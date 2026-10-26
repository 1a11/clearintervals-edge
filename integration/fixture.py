#!/usr/bin/env python3
"""Disposable real-core acceptance fixture; never connects to an existing application database.

Run with clearintervals-core's virtualenv, CORE_SOURCE pointing to its repository,
and GATEWAY_TEST_ADMIN_DSN pointing to the loopback-only disposable test server.
Only the uniquely created gateway_acceptance_* database is seeded or dropped.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--waveform-preflight', action='store_true', help='Verify the multi-replica fixture with one waveform; not a load measurement')
    parser.add_argument('--waveform-streams', action='store_true', help='Qualify simultaneous native waveform window streams through two cloud/ingest replicas and two compute containers')
    parser.add_argument('--rounds', type=int, default=3, help='Sensor burst rounds (0..10; 0 only with --stress)')
    parser.add_argument('--sensors-per-gateway', type=int, default=100, help='Production mappings per edge (1..100)')
    parser.add_argument('--admission-capacity', action='store_true', help='Verify the per-organization 256-session bound, then retire drained edges and verify recovery')
    parser.add_argument('--admission-seconds', type=int, default=180, help='Authenticated fleet warm-up deadline (1..900 seconds)')
    parser.add_argument('--gateway-start-gap-ms', type=int, default=0, help='Pace initial edge starts (0..1000 ms)')
    parser.add_argument('--stress', action='store_true', help='After the fleet burst, ramp sustained record rates to saturation')
    parser.add_argument('--observe-seconds', type=int, default=0, help='Hold the fleet for live admin observation (0..300 seconds)')
    parser.add_argument('--load-seconds', type=int, default=0)
    parser.add_argument('--drain-seconds', type=int, default=300, help='Maximum fleet durable-delivery wait (1..600 seconds)')
    parser.add_argument('--sensors', type=int, default=0, help='Run the production-binary fleet test (1..50000 sensors)')
    parser.add_argument('--output', default='build/acceptance.json')
    parser.add_argument('--image', help='Run the gateway image with one CPU, 512 MiB and a read-only root')
    args = parser.parse_args()
    if not 1 <= args.admission_seconds <= 900:
        parser.error('--admission-seconds must be between 1 and 900')
    if not 0 <= args.rounds <= 10 or not 1 <= args.sensors_per_gateway <= 100 or not 0 <= args.gateway_start_gap_ms <= 1000:
        parser.error('invalid rounds, mappings or start pacing')
    if args.rounds == 0 and (not args.stress or not args.sensors or args.admission_capacity):
        parser.error('--rounds 0 requires a sensor stress run without admission-capacity mode')
    if args.admission_capacity and (args.sensors_per_gateway != 1 or not 256 < args.sensors <= 400):
        parser.error('admission capacity requires 257..400 sensors, one per edge')
    if not 0 <= args.observe_seconds <= 300:
        parser.error('--observe-seconds must be between 0 and 300')
    if not 1 <= args.drain_seconds <= 600:
        parser.error('--drain-seconds must be between 1 and 600')
    if not 0 <= args.sensors <= 50000:
        parser.error('--sensors must be between 0 and 50000')
    if args.waveform_streams and (not 1 <= args.sensors <= 1000 or not 180 <= args.load_seconds <= 600 or args.image):
        parser.error('waveform qualification requires 1..1000 sensors, 180..600 load seconds and native gateway binaries')
    if args.waveform_preflight:
        args.sensors = 1
    root = Path(__file__).resolve().parents[1]
    core_source = Path(os.environ['CORE_SOURCE']).resolve() / 'infra/core'
    sys.path.insert(0, str(core_source))
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo, conninfo_to_dict
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    admin_dsn = os.environ['GATEWAY_TEST_ADMIN_DSN']
    if conninfo_to_dict(admin_dsn).get('host') not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('acceptance requires a disposable loopback database server')
    with psycopg.connect(admin_dsn, autocommit=True) as owner:
        if owner.execute('SHOW cluster_name').fetchone()[0] != 'clearintervals-gateway-tests-only':
            raise SystemExit('refusing unmarked server: start a disposable PostgreSQL cluster with '
                             '-c cluster_name=clearintervals-gateway-tests-only; this test rotates global test roles')
    database = 'gateway_acceptance_' + secrets.token_hex(8)
    owner_dsn = make_conninfo(admin_dsn, dbname=database)
    processes = []
    logs = []
    public_port, ingest_port, gateway_port = port(), port(), port()
    ingest_ports = [port(),port()] if args.waveform_streams else [ingest_port]
    cloud_ports = [port(),port()] if args.waveform_streams else [gateway_port]
    with psycopg.connect(admin_dsn, autocommit=True) as owner:
        owner.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(database)))
    (root / 'build').mkdir(exist_ok=True)
    scratch = tempfile.TemporaryDirectory(prefix='gateway-acceptance-', dir=root / 'build')
    work = Path(scratch.name)
    os.chmod(work, 0o700)
    os.environ.update({
        'CORE_DATABASE_URL': owner_dsn, 'CORE_ENV': 'test', 'CORE_DEV_TOKENS': '1',
        'CORE_AUTO_MIGRATE': '1', 'CORE_RUNTIME_DB_PASSWORD': 'web-acceptance-only',
        'CORE_GATEWAY_DB_PASSWORD': 'ingest-acceptance-only',
        'CORE_PII_KEYS': 'v1:' + 'A' * 43, 'CORE_BLIND_INDEX_KEY': 'B' * 43,
        'CORE_PREONB_HMAC_KEY': 'C' * 43, 'CORE_PREONB_WORKER': '0', 'CORE_ACCESS_WORKER': '0',
        'CORE_NOTIFY_WORKER': '0', 'CORE_VIBRATION_SESSIONS': '0', 'CORE_TELEMETRY_FLUSH_S': '0',
        'CORE_GATEWAY_INGEST_URL': f'https://localhost:{gateway_port}',
    })
    for key in ('CORE_ZITADEL_ISSUER', 'CORE_SMTP_HOST'):
        os.environ.pop(key, None)

    def write(name, value):
        path = work / name
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        path.chmod(0o600)
        return str(path)

    def pem(cert):
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def ca(name, parent=None, until=None):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.now(UTC)
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(parent[1].subject if parent else subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=10))
                   .not_valid_after(until or now + timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0 if parent else 1), True)
                   .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))
        return key, builder.sign(parent[0] if parent else key, hashes.SHA256())

    def identity(name, authority, *, uri=None, dns=None, start=None, end=None):
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        names = [x509.UniformResourceIdentifier(uri)] if uri else [x509.DNSName(dns)]
        cert = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(authority[1].subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(start or now - timedelta(seconds=30)).not_valid_after(end or now + timedelta(hours=23))
                .add_extension(x509.SubjectAlternativeName(names), False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if uri else
                                                    ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(authority[0], hashes.SHA256()))
        cp = write(name + '.pem', pem(cert) + pem(authority[1]))
        kp = write(name + '.key', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
        return key, cert, cp, kp

    def launch(name, command, env=None, cwd=None):
        out = open(work / (name + '.log'), 'ab')
        logs.append(out)
        child = subprocess.Popen(command, cwd=cwd or core_source, env=env or dict(os.environ),
                                 stdout=out, stderr=subprocess.STDOUT)
        processes.append(child)
        return child

    def ready(child, target):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError('test subprocess exited before readiness')
            try:
                with socket.create_connection(('127.0.0.1', target), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)
        raise RuntimeError('test subprocess readiness timeout')

    server = None

    docker_environment = {key: value for key, value in os.environ.items()
                          if key not in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}

    def docker(*arguments, check=True):
        return subprocess.run(['docker', '--host=unix:///var/run/docker.sock', *arguments],
                              env=docker_environment, capture_output=True, text=True, check=check, timeout=30)

    class Container:
        def __init__(self, child, name):
            self.child, self.name = child, name
            self.pid = child.pid

        def poll(self):
            return self.child.poll()

        def wait(self, timeout=None):
            return self.child.wait(timeout=timeout)

        def terminate(self):
            docker('kill', '--signal=TERM', self.name, check=False)

        def kill(self):
            docker('kill', '--signal=KILL', self.name, check=False)

        def memory_kib(self):
            usage = docker('stats', '--no-stream', '--format', '{{.MemUsage}}', self.name).stdout.split('/')[0].strip()
            for suffix, factor in (('GiB', 1024**2), ('MiB', 1024), ('KiB', 1), ('B', 1/1024)):
                if usage.endswith(suffix):
                    return int(float(usage[:-len(suffix)]) * factor)
            raise ValueError('unrecognized container memory measurement')

    def launch_cloud():
        if not args.image:
            return launch('cloud', cloud_args, cwd=root)
        # Only ephemeral test PKI is made readable by the image's unprivileged UID.
        # The controller token/manifest remain 0600 and are never mounted separately.
        work.chmod(0o755)
        for path in work.iterdir():
            if path.suffix in ('.pem', '.key'):
                path.chmod(0o644)
        name = database.replace('_', '-')
        out = open(work / 'cloud.log', 'ab')
        logs.append(out)
        child = subprocess.Popen(['docker', '--host=unix:///var/run/docker.sock', 'run', '--rm', '--name', name,
                    '--network=host', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                    '--memory=512m', '--cpus=1', '--pids-limit=64',
                    '--tmpfs=/run/cloudgateway:rw,noexec,nosuid,size=1m,uid=65532,gid=65532,mode=0700',
                    '-e', 'GOMEMLIMIT=384MiB', '-e', 'GOMAXPROCS=1', '-v', f'{work}:{work}:ro', args.image,
                    *cloud_args[1:], '-status-socket', '/run/cloudgateway/status.sock'],
                    env=docker_environment, stdout=out, stderr=subprocess.STDOUT)
        managed = Container(child, name)
        processes.append(managed)
        return managed

    try:
        root_ca = ca('Offline regional root')
        retired = ca('Retiring issuer', root_ca, until=datetime.now(UTC) - timedelta(days=1))
        current = ca('Current issuer', root_ca)
        roots = write('roots.pem', pem(root_ca[1]))
        os.environ['CORE_GATEWAY_TRUST_ANCHORS'] = pem(root_ca[1])
        from core import db, migrate
        from core.gateways import registry as R, lifecycle as L
        from core.vibration import service
        from tests.seed import seed
        migrate.main()
        db.pool()
        seed()
        if args.observe_seconds:
            db.run("INSERT INTO operators(user_id,granted_by) VALUES ('u-robin','local-verification')")
        R.set_entitlement('org-northwind', 'active', 10, 'u-robin')
        R.set_entitlement('org-kestrel', 'active', 10, 'u-dana')
        service.save_profile(db.one("SELECT * FROM assets WHERE id='asset-cwp'"),
                             ({'machine': 'rotodynamic_pump', 'power_kw': 55, 'rpm': 1800, 'pump_category': 'II',
                              'components':[{'kind':'bearing','name':'drive end','n':9,'ball_diameter':.3126,'pitch_diameter':1.537}]}
                             if args.waveform_streams else {'machine': 'rotodynamic_pump', 'power_kw': 55, 'rpm': 1480, 'pump_category': 'II'}), 'u-robin')
        db.run("INSERT INTO sensors(id,org_id,asset_id,type_id,name,state) VALUES "
               "('mounted','org-northwind','asset-cwp','accelerometer','Mounted','declared')")
        L.approve_issuer('current', pem(current[1]), 'ru', 'active')
        L.approve_issuer('retired', pem(retired[1]), 'ru', 'active')

        licences = {name: R.create(org, {'name': name}, user) for name, org, user in
                    [('primary', 'org-northwind', 'u-robin'), ('redundant', 'org-northwind', 'u-robin'),
                     ('foreign', 'org-kestrel', 'u-dana'), ('native', 'org-northwind', 'u-robin'), ('legacy', 'org-northwind', 'u-robin'),
                     ('rootLegacy', 'org-northwind', 'u-robin'), ('compromised', 'org-northwind', 'u-robin')]}
        binding = R.bind(licences['primary']['gatewayId'], {'kind': 'captures', 'sensorId': 'mounted'}, 'u-robin')
        R.authorize_redundancy(licences['redundant']['gatewayId'], binding['deviceId'], 'u-robin')
        redundant = R.bind(licences['redundant']['gatewayId'],
                           {'kind': 'captures', 'sensorId': 'mounted', 'deviceId': binding['deviceId']}, 'u-robin')
        bindings = {'primary': binding, 'redundant': redundant}
        db.run("INSERT INTO sensors(id,org_id,asset_id,type_id,name,state) VALUES "
               "('native-mounted','org-northwind','asset-cwp','accelerometer','Native','declared')")
        bindings['native'] = R.bind(licences['native']['gatewayId'],
                                    {'kind': 'captures', 'sensorId': 'native-mounted'}, 'u-robin')
        point_binding = R.bind(licences['primary']['gatewayId'],
                               {'kind': 'series', 'assetId': 'asset-cwp', 'metric': 'rpm'}, 'u-robin')
        R.authorize_redundancy(licences['redundant']['gatewayId'], point_binding['deviceId'], 'u-robin')
        bindings['pointPrimary'] = point_binding
        bindings['pointRedundant'] = R.bind(licences['redundant']['gatewayId'],
            {'kind': 'series', 'assetId': 'asset-cwp', 'metric': 'rpm', 'deviceId': point_binding['deviceId']}, 'u-robin')
        db.run("INSERT INTO sites(id,org_id,name,timezone) VALUES ('foreign-site','org-kestrel','Foreign','UTC')")
        db.run("INSERT INTO assets(id,org_id,site_id,type_id,name) VALUES "
               "('foreign-asset','org-kestrel','foreign-site','other','Foreign')")
        bindings['foreign'] = R.bind(licences['foreign']['gatewayId'],
                                     {'kind': 'series', 'assetId': 'foreign-asset', 'metric': 'temperature'}, 'u-dana')
        fleet = []
        if args.sensors:
            R.set_entitlement('org-northwind', 'active', args.sensors + 10, 'u-robin')
            db.run("UPDATE organizations SET sensor_limit=? WHERE id='org-northwind'", args.sensors + 10)
            with db.tx():
                for start in range(0, args.sensors, args.sensors_per_gateway):
                    licence = R.create('org-northwind', {'name': f'fleet-{start // args.sensors_per_gateway}'}, 'u-robin')
                    entries = []
                    for index in range(start, min(start + args.sensors_per_gateway, args.sensors)):
                        sensor = f'fleet-sensor-{index}'
                        db.run("INSERT INTO sensors(id,org_id,asset_id,type_id,name,state) VALUES "
                               "(?,'org-northwind','asset-cwp','accelerometer',?,'declared')", sensor, sensor)
                        entry = R.bind(licence['gatewayId'],
                                       ({'kind':'captures','sensorId':sensor} if args.waveform_streams else
                                        {'kind': 'series', 'sensorId': sensor, 'metric': 'temperature'}), 'u-robin')
                        entry['index'] = index
                        entries.append(entry)
                    fleet.append({'licence': licence, 'bindings': entries})
                    print(f'Fleet seeded: {min(start + args.sensors_per_gateway, args.sensors)}/{args.sensors}', flush=True)
        for name, licence in licences.items():
            licence['generation'] = db.one('SELECT generation FROM gateways WHERE id=?', licence['gatewayId'])['generation']
            if name not in ('legacy', 'rootLegacy', 'compromised'):
                continue
            gid = licence['gatewayId']
            old_now = R.now
            at = datetime.now(UTC) - timedelta(days=2)
            R.now = lambda: at
            try:
                key, cert, cp, kp = identity(name, retired, uri=f'spiffe://clearintervals/ru/gateway/{gid}',
                                             start=at - timedelta(seconds=30),
                                             end=retired[1].not_valid_after_utc - timedelta(minutes=1))
                csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
                       .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(L.uri({'id': gid, 'region': 'ru'}))]), False)
                       .sign(key, hashes.SHA256()))
                body = {'kind': 'enroll', 'operationId': 'legacy-' + name, 'generation': licence['generation'],
                        'csr': csr.public_bytes(serialization.Encoding.PEM).decode(), 'issuerId': 'retired',
                        'token': licence['enrollmentToken']}
                L.reserve(gid, body)
                result = L.finalize(gid, body['operationId'], pem(cert))
                licence['generation'] = result['generation']
                licence['certificateFile'], licence['keyFile'] = cp, kp
            finally:
                R.now = old_now
        L.approve_issuer('retired', pem(retired[1]), 'ru', 'retiring')

        _, _, core_cert, core_key = identity('core-server', current, dns='localhost')
        _, _, service_cert, service_key = identity('cloud-service', current, uri='spiffe://clearintervals/service/cloudgateway')
        _, _, wrong_cert, wrong_key = identity('wrong-service', current, uri='spiffe://clearintervals/service/foreign')
        _, _, public_cert, public_key = identity('ingest-server', current, dns='localhost')
        issuer_cert = write('current-issuer.pem', pem(current[1]))
        issuer_key = write('current-issuer.key', current[0].private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        client_issuers = write('client-issuers.pem', pem(current[1]) + pem(retired[1]))
        ingest_env = dict(os.environ, CORE_AUTO_MIGRATE='0', CI_ACCEPTANCE_FAULT_DIR=str(work))
        ingest_dsn = make_conninfo(owner_dsn, user='core_gateway_ingest', password='ingest-acceptance-only')
        ingest = launch('core-ingest', [sys.executable, str(root / 'integration/core_server.py'),
                        '--host', '127.0.0.1', '--port', str(ingest_ports[0]), '--cert', core_cert, '--key', core_key,
                        '--client-ca', roots, '--database-url', ingest_dsn], ingest_env)
        ready(ingest, ingest_ports[0])
        if args.waveform_streams:
            second = launch('core-ingest-b', [sys.executable, str(root/'integration/core_server.py'),
                '--host','127.0.0.1','--port',str(ingest_ports[1]),'--cert',core_cert,'--key',core_key,
                '--client-ca',roots,'--database-url',ingest_dsn], ingest_env)
            ready(second,ingest_ports[1])
        web_env = dict(os.environ, CORE_AUTO_MIGRATE='0', CORE_DATABASE_URL=make_conninfo(
                       owner_dsn, user='core_runtime', password='web-acceptance-only'), CORE_DATABASE_POOL_SIZE='4')
        web = launch('core-web', [sys.executable, '-m', 'uvicorn', 'core.main:app', '--host', '127.0.0.1',
                     '--port', str(public_port), '--no-access-log', '--limit-concurrency', '128'], web_env)
        ready(web, public_port)

        if args.waveform_streams:
            config = ['global','  nbthread 1','  maxconn 2048','defaults','  mode tcp',
                      '  timeout connect 2s','  timeout client 4m','  timeout server 4m']
            for label,front,backends,proxy in [('cloud',gateway_port,cloud_ports,True),('ingest',ingest_port,ingest_ports,False)]:
                config += [f'frontend {label}',f'  bind 127.0.0.1:{front}',f'  default_backend {label}_workers',
                           f'backend {label}_workers','  balance leastconn']
                config += [f'  server node{i} 127.0.0.1:{number} check inter 1s'+(' send-proxy-v2' if proxy else '')
                           for i,number in enumerate(backends)]
            config_path = write('qualification.haproxy','\n'.join(config)+'\n')
            os.chmod(config_path,0o644)
            name=database.replace('_','-')+'-lb'
            process=launch('balancers',['docker','--host=unix:///var/run/docker.sock','run','--rm','--name',name,
                '--network=host','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--user','99:99',
                '-v',f'{config_path}:/config:ro',
                'haproxy:3.4-alpine@sha256:3c8c1df0ae3bea8834b3890fa6fa3b1653b4d6d9c44aecefba46428bfcfde2c0',
                'haproxy','-W','-db','-f','/config'],env=docker_environment)
            managed=Container(process,name)
            processes[-1]=managed
            ready(managed,ingest_port)
        cloud_args = [str(Path(os.environ['CLOUD_SOURCE']).resolve() / 'bin/cloudgateway'), '-listen', f'127.0.0.1:{cloud_ports[0]}', '-server-name', 'localhost',
                      '-region', 'ru', '-cert', public_cert, '-key', public_key, '-client-issuers', client_issuers,
                      '-issuer-id', 'current', '-issuer-cert', issuer_cert, '-issuer-key', issuer_key,
                      '-core-url', f'https://localhost:{ingest_port}', '-core-ca', roots,
                      '-service-cert', service_cert, '-service-key', service_key]
        if args.waveform_streams:
            cloud_args += ['-trusted-proxy-cidr','127.0.0.1/32']
        cloud = launch_cloud()
        ready(cloud,cloud_ports[0])
        if args.waveform_streams:
            second_args = list(cloud_args)
            second_args[second_args.index('-listen')+1] = f'127.0.0.1:{cloud_ports[1]}'
            cloud_b = launch('cloud-b',second_args,cwd=root)
            ready(cloud_b,cloud_ports[1])
            runtime_dsn = make_conninfo(owner_dsn,user='core_runtime',password='web-acceptance-only')
            env_path = write('compute.env','\n'.join(['CORE_DATABASE_URL='+runtime_dsn,'CORE_ENV=production',
                'CORE_AUTO_MIGRATE=0','CORE_COMPUTE_MIN_WORKERS=10','CORE_COMPUTE_MAX_WORKERS=25',
                'CORE_DB_POOL_SIZE=2','PYTHONPATH=/app:/opt/site-packages','PYTHONDONTWRITEBYTECODE=1'])+'\n')
            for index in range(2):
                status_dir=work/f'compute-status-{index}'
                status_dir.mkdir(mode=0o700)
                name=database.replace('_','-')+f'-compute-{index}'
                process=launch(f'compute-{index}',['docker','--host=unix:///var/run/docker.sock','run','--rm','--name',name,
                    '--network=host','--read-only','--user',f'{os.getuid()}:{os.getgid()}',
                    '--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','4g','--cpus','1',
                    '--cpu-shares','128','--pids-limit','256','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
                    '--env-file',env_path,'-v',f'{status_dir}:/run/qualification:rw','-v',f'{core_source}/core:/app/core:ro',
                    '-v',f'{core_source}/config:/app/config:ro',
                    '-v',f'{core_source}/.venv/lib/python3.12/site-packages:/opt/site-packages:ro',
                    '-w','/app','python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70',
                    'python','-m','core.compute','--status-file','/run/qualification/status.json'],env=docker_environment)
                processes[-1]=Container(process,name)
        controller_token = secrets.token_urlsafe(32)
        class Controller(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                nonlocal cloud
                if self.headers.get('Authorization') != 'Bearer ' + controller_token:
                    self.send_error(403)
                    return
                n = int(self.headers.get('Content-Length', '0'))
                if n > 4096:
                    self.send_error(413)
                    return
                body = json.loads(self.rfile.read(n) or b'{}') or {}
                try:
                    out = {}
                    if self.path == '/process':
                        status = Path(f'/proc/{cloud.pid}/status').read_text() if cloud.poll() is None else ''
                        rss = next((int(line.split()[1]) for line in status.splitlines() if line.startswith('VmRSS:')), 0)
                        out = {'alive': cloud.poll() is None, 'memoryKiB': cloud.memory_kib() if args.image else rss}
                        if args.image:
                            check = docker('exec', cloud.name, '/cloudgateway', '-check', '-status-socket',
                                           '/run/cloudgateway/status.sock', check=False)
                            out['privateHealthy'] = check.returncode == 0
                    elif self.path == '/retire-drained-fleet':
                        retired = []
                        retired_indexes = []
                        eligible = set(body.get('eligibleIndexes', []))
                        with db.tx():
                            for index, gateway in enumerate(fleet):
                                if index not in eligible:
                                    continue
                                gid = gateway['licence']['gatewayId']
                                if len(retired) >= 64:
                                    break
                                if not db.one("SELECT 1 FROM gateways WHERE id=? AND state<>'revoked'", gid):
                                    continue
                                devices = [entry['deviceId'] for entry in gateway['bindings']]
                                count = db.one("SELECT count(*) AS n FROM gateway_series WHERE device_id=ANY(?)", devices)['n']
                                if count == len(devices) * args.rounds:
                                    R.revoke(gid, 'u-robin')
                                    retired.append(gid)
                                    retired_indexes.append(index)
                        out = {'retiredCount': len(retired), 'retiredIndexes': retired_indexes}
                    elif self.path == '/cloud-metrics':
                        from core.gateways.metrics import insights
                        out = insights()
                    elif self.path == '/native-capture':
                        from core.vibration.da.capture import decode_samples
                        import hashlib
                        if body.get('process'):
                            service.run_pending()
                        row = db.one("SELECT * FROM vib_captures WHERE device_id=? ORDER BY t DESC LIMIT 1",
                                     bindings['native']['deviceId'])
                        out = {'stored': row is not None}
                        if row:
                            timestamps, samples = decode_samples(bytes(row['samples']))
                            out.update({'n': len(timestamps), 'axes': samples.shape[1], 'state': row['state'],
                                        'accepted': row['accepted'],
                                        'sampleHash': hashlib.sha256(samples.T.astype('<f4').tobytes()).hexdigest(),
                                        'receipts': db.one("SELECT count(*) AS n FROM gateway_receipts WHERE device_id=?",
                                                           bindings['native']['deviceId'])['n']})
                    elif self.path == '/stats':
                        out = {table: db.one(f'SELECT count(*) AS n FROM {table}')["n"] for table in
                               ('gateway_receipts', 'vib_captures', 'gateway_series', 'gateway_sessions')}
                        out['firstData'] = db.one("SELECT count(*) AS n FROM updates WHERE kind='first_data'")['n']
                        out['queued'] = db.one("SELECT count(*) AS n FROM vib_captures WHERE state='queued'")['n']
                        out['faultReady'] = (work / 'fault.ready').exists()
                        if args.sensors:
                            out['fleet'] = db.one("SELECT count(*) AS points, count(DISTINCT sensor_id) AS sensors, "
                                                 "sum(value) AS total FROM gateway_series WHERE sensor_id LIKE 'fleet-sensor-%'")
                    elif self.path == '/crash':
                        cloud.kill()
                        cloud.wait(timeout=5)
                        (work / 'fault.release').touch()
                        cloud = launch_cloud()
                        ready(cloud, gateway_port)
                    elif self.path == '/suspend':
                        db.run("UPDATE organizations SET status=? WHERE id='org-northwind'",
                               'suspended' if body['suspended'] else 'active')
                        out['at'] = R.now().isoformat()
                    elif self.path == '/rotate':
                        rotated = R.rotate_binding(licences['primary']['gatewayId'], binding['id'], 'u-robin', True)
                        bindings['rotated'] = rotated
                        out = rotated
                    elif self.path == '/move':
                        db.run("UPDATE sensors SET asset_id='asset-lab1' WHERE id='mounted'")
                    elif self.path == '/compromise':
                        L.approve_issuer('retired', pem(retired[1]), 'ru', 'compromised')
                    elif self.path == '/rollover':
                        # Simulate the verified offline configuration update, not
                        # a trust anchor sent in an uplink reply.
                        cloud.terminate()
                        cloud.wait(timeout=20)
                        next_root = ca('Replacement offline root')
                        replacement = ca('Replacement root issuer', next_root)
                        L.approve_issuer('root-next', pem(replacement[1]), 'ru', 'active')
                        L.approve_issuer('current', pem(current[1]), 'ru', 'retiring')
                        write('roots.pem', pem(root_ca[1]) + pem(next_root[1]))
                        write('current-issuer.pem', pem(replacement[1]))
                        write('current-issuer.key', replacement[0].private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                        write('client-issuers.pem', pem(current[1]) + pem(retired[1]) + pem(replacement[1]))
                        cloud_args[cloud_args.index('-issuer-id') + 1] = 'root-next'
                        cloud = launch_cloud()
                        ready(cloud, gateway_port)
                        out['newRoot'] = pem(next_root[1])
                    elif self.path == '/queue':
                        if body['full']:
                            with db.tx():
                                for i in range(1000):
                                    db.run("INSERT INTO vib_captures(id,org_id,asset_id,sensor_id,device_id,session_id,t,"
                                           "tier,meta,samples,n,accepted,state) VALUES (?,?,'asset-cwp','mounted',?,"
                                           "'capacity-test',now(),'M','{}',?,2,NULL,'queued') ON CONFLICT DO NOTHING",
                                           f'capacity-{i}', 'org-northwind', binding['deviceId'], b'')
                        else:
                            db.run("DELETE FROM vib_captures WHERE session_id='capacity-test'")
                    elif self.path == '/revoke':
                        R.revoke(licences[body.get('name', 'foreign')]['gatewayId'],
                                 'u-dana' if body.get('name', 'foreign') == 'foreign' else 'u-robin')
                    else:
                        self.send_error(404)
                        return
                    raw = json.dumps(out).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except Exception as exc:
                    # Fixture errors are local test failures, not public cloud endpoints.
                    self.send_error(500, type(exc).__name__)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Controller)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        manifest = {'url': f'https://localhost:{gateway_port}', 'coreURL': f'https://localhost:{ingest_port}',
                    'webURL': f'http://127.0.0.1:{public_port}', 'rootsFile': roots, 'licences': licences,
                    'bindings': bindings, 'controller': f'http://127.0.0.1:{server.server_port}',
                    'controllerToken': controller_token, 'wrongCert': wrong_cert, 'wrongKey': wrong_key,
                    'loadSeconds': args.load_seconds, 'image': args.image or '', 'output': str(Path(args.output).resolve()),
                    'fleet': fleet, 'sensors': args.sensors, 'drainSeconds': args.drain_seconds, 'observeSeconds': args.observe_seconds, 'stress': args.stress, 'rounds': args.rounds, 'admissionCapacity': args.admission_capacity,
                    'admissionSeconds': args.admission_seconds, 'startGapMillis': args.gateway_start_gap_ms, 'waveformStreams':args.waveform_streams, 'waveformPreflight':args.waveform_preflight,
                    'cloudPids':[cloud.pid]+([cloud_b.pid] if args.waveform_streams else []),
                    'ingestPids':[ingest.pid]+([second.pid] if args.waveform_streams else []),
                    'computeStatusFiles':[str(work/f'compute-status-{index}'/'status.json') for index in range(2)] if args.waveform_streams else [],
                    'computeContainers':[database.replace('_','-')+f'-compute-{index}' for index in range(2)] if args.waveform_streams else []}
        manifest_path = write('manifest.json', json.dumps(manifest))
        if args.observe_seconds:
            (root / 'build/performance-target.json').write_text(json.dumps({'webURL': manifest['webURL']}))
        driver_env = dict(os.environ, CI_GATEWAY_FIXTURE=manifest_path)
        selection = ['-run', '^TestSensorFleet$'] if args.sensors else []
        if args.waveform_streams:
            result = subprocess.run([sys.executable,str(root/'integration/waveform_load.py')],cwd=root,env=driver_env)
        else:
            result = subprocess.run(['go', 'test', '-tags=integration', '-v', '-timeout', f'{max(args.load_seconds + 240, 3600 if args.stress else max(1200, args.admission_seconds + args.drain_seconds + 300) if args.sensors else 0)}s',
                                     *selection, './integration'], cwd=root, env=driver_env)
        if result.returncode:
            destination = root / 'build/acceptance-logs'
            destination.mkdir(parents=True, exist_ok=True)
            for path in work.glob('*.log'):
                (destination / path.name).write_bytes(path.read_bytes())
        if args.observe_seconds and not args.sensors:
            time.sleep(args.observe_seconds)
        return result.returncode
    except Exception:
        destination = root/'build/acceptance-logs'
        destination.mkdir(parents=True,exist_ok=True)
        for path in work.glob('*.log'):
            (destination/path.name).write_bytes(path.read_bytes())
        raise
    finally:
        if server:
            server.shutdown()
            server.server_close()
        for child in reversed(processes):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=45 if isinstance(child, Container) else 20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for out in logs:
            out.close()
        if args.waveform_streams:
            destination = Path(args.output).with_suffix('')
            destination = destination.with_name(destination.name+'-logs')
            destination.mkdir(parents=True,exist_ok=True)
            for path in work.glob('*.log'):
                (destination/path.name).write_bytes(path.read_bytes())
        if 'db' in locals():
            db.close()
        with psycopg.connect(admin_dsn, autocommit=True) as owner:
            owner.execute('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s', (database,))
            owner.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(database)))
        scratch.cleanup()


if __name__ == '__main__':
    raise SystemExit(main())
