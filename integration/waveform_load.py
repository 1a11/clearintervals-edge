"""Sustained native-window qualification. Run only via fixture.py --waveform-streams.

One independent producer clock schedules each sensor every ten seconds; ACK waits
cannot slow the offered schedule. Test-owned database and source files disappear
with the fixture. No production quota, raw retention or DSP setting is relaxed.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import queue
import secrets
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(os.environ['CORE_SOURCE'])/'infra/core'))
import numpy as np
import yaml
from core import db
from core.vibration import synthetic
from core.vibration.da.capture import decode_samples
from core.vibration.dm.bearings import Geometry, defect_frequencies


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def stamp(at):
    dt = datetime.fromtimestamp(at, UTC)
    fraction = f'.{dt.microsecond:06d}'.rstrip('0') if dt.microsecond else ''
    return dt.strftime('%Y-%m-%dT%H:%M:%S')+fraction+'Z'


def proc(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        rss = next(int(row.split()[1])*1024 for row in Path(f'/proc/{pid}/status').read_text().splitlines()
                   if row.startswith('VmRSS:'))
        return {'rssBytes': rss, 'cpuSeconds': (int(raw[11])+int(raw[12]))/os.sysconf('SC_CLK_TCK')}
    except (OSError, StopIteration):
        return None


def main():
    fixture = json.loads(Path(os.environ['CI_GATEWAY_FIXTURE']).read_text())
    if not fixture.get('waveformStreams') or not db.one('SELECT current_database() AS name')['name'].startswith('gateway_acceptance_'):
        raise SystemExit('refusing anything other than the disposable waveform fixture')
    if db.one('SHOW cluster_name')['cluster_name'] != 'clearintervals-gateway-tests-only':
        raise SystemExit('unmarked verification database server')
    if fixture.get('waveformPreflight'):
        fixture['loadSeconds'] = 2
    work = Path(os.environ['CI_GATEWAY_FIXTURE']).parent
    output = Path(fixture['output'])
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'scope': 'Full native window stream -> durable edge -> two cloud replicas -> two mTLS ingest replicas -> TimescaleDB -> two compute containers; all test processes share this two-CPU workspace',
              'streams': fixture['sensors'], 'windowSeconds': 10, 'sampleRateHz': 25600, 'axes': 3,
              'sampleBytesPerWindow': 3072000, 'requestedSeconds': fixture['loadSeconds'],
              'computeMinWorkers': 10, 'computeMaxWorkers': 25,
              'cpuMax': Path('/sys/fs/cgroup/cpu.max').read_text().strip(),
              'packaging': 'Native gateway binaries; non-root read-only Python3.12 compute containers with matching source/dependencies. Production Python3.13 bytecode images build separately in CI.',
              'snapshots': [], 'passed': False}
    processes, logs, writers = [], [], []
    stop_producing, stop_writers = threading.Event(), threading.Event()
    lock = threading.Lock()
    offered = {}
    seen_sessions = set()
    initial_oom_kills = int(dict(row.split() for row in Path('/sys/fs/cgroup/memory.events').read_text().splitlines())['oom_kill'])
    stats = {'offered': 0, 'edgeAcknowledged': 0, 'reconnects': 0, 'rateLimited': 0, 'bufferUnavailable': 0,
             'connected': 0, 'incompleteWindows':0, 'producerQueueFull': 0, 'producerLateOver100ms': 0, 'permanentWriterErrors': 0}
    errors, producer_lags = [], []
    latest = {}
    phase = "warmup"
    # A deterministic bearing waveform whose full three-axis DSP contract was
    # already verified. Every source gets independent identity and timing.
    geometry = Geometry(9, .3126, 1.537, 0)
    frequency = defect_frequencies(30., geometry)
    x = synthetic.bearing(frequency.bpfo, 30., fs=25600., duration_s=10., seed=11, snr_db=-10.)
    samples = np.asarray(np.column_stack([x, .5*x, .3*x+9.80665]).T, '<f4').tobytes()
    expected_hash = hashlib.sha256(samples).hexdigest()
    report['sampleHash'] = expected_hash

    def connect(writer):
        connection = http.client.HTTPConnection('127.0.0.1', writer['port'], timeout=8)
        connection.putrequest('POST', '/api/v1/streams/captures/'+writer['binding']['id'])
        connection.putheader('Authorization', 'Bearer '+writer['token'])
        connection.putheader('Content-Type', 'application/vnd.clearintervals.waveforms.v1')
        connection.putheader('Transfer-Encoding', 'chunked')
        connection.endheaders()
        response = connection.getresponse()
        if response.status != 200:
            connection.close()
            raise OSError('stream admission refused')
        return connection, response

    def sender(writer):
        connection = response = None
        counted = False
        try:
            while not stop_writers.is_set():
                if connection is None:
                    try:
                        connection, response = connect(writer)
                        if not counted:
                            with lock:
                                stats['connected'] += 1
                            counted = True
                    except (OSError, http.client.HTTPException):
                        stop_writers.wait(.2)
                        continue
                try:
                    window = writer['pending'].get(timeout=.1)
                except queue.Empty:
                    if stop_producing.is_set():
                        return
                    continue
                while not stop_writers.is_set():
                    try:
                        if connection is None:
                            connection, response = connect(writer)
                        header = window['header']
                        # Chunk framing does not concatenate or duplicate the waveform.
                        for body in (struct.pack('<I', len(header)), header, samples):
                            connection.send(f'{len(body):x}\r\n'.encode())
                            connection.send(body)
                            connection.send(b'\r\n')
                        raw = response.readline(4097)
                        if not raw or len(raw) > 4096:
                            raise OSError('lost or oversized window acknowledgement')
                        ack = json.loads(raw)
                        if ack.get('status') == 'queued' and ack.get('captureId') == window['id']:
                            with lock:
                                stats['edgeAcknowledged'] += 1
                            break
                        with lock:
                            if ack.get('code') == 'rate_limited':
                                stats['rateLimited'] += 1
                            elif ack.get('code') == 'buffer_unavailable':
                                stats['bufferUnavailable'] += 1
                            elif ack.get('code') == 'incomplete_window':
                                stats['incompleteWindows'] += 1
                            else:
                                stats['permanentWriterErrors'] += 1
                                errors.append({'stage': 'writer', 'code': str(ack.get('code', 'invalid_ack'))})
                        raise OSError('window unacknowledged')
                    except (OSError, ValueError, http.client.HTTPException):
                        if connection:
                            connection.close()
                        connection = response = None
                        with lock:
                            stats['reconnects'] += 1
                        stop_writers.wait(1)
                writer['pending'].task_done()
        finally:
            if connection:
                try:
                    connection.send(b'0\r\n\r\n')
                except OSError:
                    pass
                connection.close()

    def snapshot():
        seen_sessions.update(row['id'] for row in db.rows('SELECT id FROM gateway_sessions'))
        states = {r['state']: r['n'] for r in db.rows('SELECT state,count(*) AS n FROM vib_captures GROUP BY state')}
        done = db.one("SELECT count(*) AS n,count(*) FILTER (WHERE accepted) AS accepted FROM vib_captures WHERE state='done'")
        pool = db.one("SELECT (SELECT target FROM compute_pool) AS target,"
                      "(SELECT count(*) FROM compute_slots WHERE lease_until>clock_timestamp()) AS leased,"
                      "(SELECT count(*) FROM compute_workers WHERE seen_at>clock_timestamp()-interval '15 seconds') AS ready")
        cpu = dict(row.split() for row in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
        with lock:
            local = dict(stats)
        memory_stat = dict(row.split() for row in Path('/sys/fs/cgroup/memory.stat').read_text().splitlines())
        memory_current = int(Path('/sys/fs/cgroup/memory.current').read_text())
        manager_status = []
        for filename in fixture.get('computeStatusFiles',[]):
            try:
                state = json.loads(Path(filename).read_text())
                manager_status.append({k:state.get(k) for k in ('ready','starting','startupBlocked','cpuPressurePercent','minimum','maximum','target')})
            except (OSError,ValueError):
                manager_status.append(None)
        snap = {'at': time.time(), 'phase':phase, 'computeManagers':manager_status, **local, 'states': states, 'done': done['n'], 'accepted': done['accepted'],
                'pending': sum(n for state,n in states.items() if state not in ('done', 'failed')),
                'pool': pool, 'uniqueGatewaySessions':len(seen_sessions),
                'oomKills':int(dict(row.split() for row in Path('/sys/fs/cgroup/memory.events').read_text().splitlines())['oom_kill'])-initial_oom_kills,
                'memoryBytes': memory_current,
                'memoryWorkingSetBytes': memory_current-int(memory_stat['inactive_file']),
                'memoryAnonBytes':int(memory_stat['anon']),
                'cpuUsec': int(cpu['usage_usec']), 'diskFreeBytes': os.statvfs(ROOT).f_bavail*os.statvfs(ROOT).f_frsize,
                'cloud': [proc(pid) for pid in fixture['cloudPids']],
                'ingest': [proc(pid) for pid in fixture['ingestPids']],
                'edges': [proc(process.pid) for process in processes]}
        report['snapshots'].append(snap)
        output.with_suffix('.progress.json').write_text(json.dumps(snap, default=str))
        return snap

    def produce(start):
        next_at = [start+10*i/len(writers) for i in range(len(writers))]
        sequences = [0]*len(writers)
        while not stop_producing.is_set():
            now = time.time()
            index = min(range(len(writers)), key=next_at.__getitem__)
            due = next_at[index]
            if due >= start+fixture['loadSeconds']:
                return
            if now < due:
                stop_producing.wait(min(.02, due-now))
                continue
            producer_lags.append(max(0, now-due))
            record_id = f'waveform-{index}-{sequences[index]}'
            metadata = {'captureId': record_id, 'tier': 'I', 'axes': ['x','y','z'],
                        'fsNominalHz': 25600, 'startTimeUtc': stamp(due-10), 'mount': 'stud',
                        'continuous': True, 'rpmDeclared': 1800, 'flatBandHz': [1.,10000.],
                        'operatingStateDeclared': 'running_steady'}
            window = {'id': record_id, 'due': due,
                      'header': json.dumps({'metadata': metadata, 'count': 256000}, separators=(',', ':')).encode()}
            with lock:
                offered[record_id] = due
                stats['offered'] += 1
                if now-due > .1:
                    stats['producerLateOver100ms'] += 1
            try:
                writers[index]['pending'].put_nowait(window)
            except queue.Full:
                with lock:
                    stats['producerQueueFull'] += 1
                stop_producing.set()
                return
            next_at[index] += 10
            sequences[index] += 1

    try:
        warm_until = time.monotonic()+120
        while time.monotonic() < warm_until:
            initial = snapshot()
            if initial['pool']['ready'] == 10 and initial['pool']['leased'] == 10:
                break
            time.sleep(1)
        else:
            raise RuntimeError('ten global warm workers not ready')
        for group_index, group in enumerate(fixture['fleet']):
            token = secrets.token_urlsafe(48)
            native_port, status_port = port(), port()
            license_path = work/f'load-license-{group_index}.json'
            license_path.write_text(json.dumps(group['licence']))
            config = {'stateDir': str(work/f'edge-{group_index}'), 'deploymentLicensePath': str(license_path),
                      'statusListen': f'127.0.0.1:{status_port}',
                      'buffer': {'maxBytes': 256*1024**2, 'maxAgeDays': 7, 'maxSegments': 100000},
                      'modules': {'captures': {'enabled': True, 'listen': f'127.0.0.1:{native_port}',
                          'principals': [{'id': 'writer', 'tokenSha256': hashlib.sha256(token.encode()).hexdigest()}]}},
                      'uplink': {'forceTcp': True, 'proxy': ''},
                      'bindings': [{'id': b['id'], 'streamKey': b['streamKey'], 'sourceId': b['deviceId'],
                                    'kind': 'captures', 'principals': ['writer']} for b in group['bindings']]}
            config_path = work/f'edge-{group_index}.yaml'
            config_path.write_text(yaml.safe_dump(config))
            config_path.chmod(0o600)
            log = (work/f'edge-{group_index}.log').open('wb');logs.append(log)
            env = dict(os.environ, HTTPS_PROXY='', EDGE_STATE_DIR='', EDGE_LICENSE_PATH='')
            child = subprocess.Popen([str(ROOT/'bin/edgegateway'), '-config', str(config_path)], env=env,
                                     stdout=log, stderr=subprocess.STDOUT)
            processes.append(child)
            until = time.monotonic()+20
            while time.monotonic() < until:
                if child.poll() is not None:
                    raise RuntimeError('edge process exited during startup')
                try:
                    with socket.create_connection(('127.0.0.1', native_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('edge listener not ready')
            for binding in group['bindings']:
                writer = {'port': native_port, 'token': token, 'binding': binding, 'pending': queue.Queue(4)}
                thread = threading.Thread(target=sender, args=(writer,), daemon=True)
                writer['thread'] = thread;writers.append(writer);thread.start()
        until = time.monotonic()+60
        while time.monotonic() < until:
            with lock:
                connected = stats['connected']
            if connected == len(writers):
                break
            time.sleep(.1)
        else:
            raise RuntimeError('not all simultaneous producer streams connected')
        # Let edge enrollment finish before timing; no captures have been offered.
        until = time.monotonic()+90
        while time.monotonic() < until:
            sessions = db.one('SELECT count(*) AS n FROM gateway_sessions')['n']
            if sessions == len(processes):
                break
            time.sleep(.2)
        else:
            raise RuntimeError('gateway session warmup failed')
        start = time.time()+1
        report['startedAt'] = start
        phase = 'load'
        producer = threading.Thread(target=produce, args=(start,), daemon=True);producer.start()
        next_sample = start
        guard = None
        while time.time() < start+fixture['loadSeconds'] and not stop_producing.is_set():
            now = time.time()
            if now >= next_sample:
                latest = snapshot();next_sample += 5
                if latest['diskFreeBytes'] < 1024**3:
                    guard = 'disk_free_below_1GiB'
                elif latest['memoryWorkingSetBytes'] > 7*1024**3:
                    guard = 'workspace_memory_above_7GiB'
                elif latest['pending'] > 80:
                    guard = 'more_than_80_pending_captures'
                elif latest['pool']['leased'] > 25:
                    guard = 'global_worker_cap_exceeded'
                elif latest['oomKills']:
                    guard = 'workspace_oom_kill'
                elif latest['permanentWriterErrors']:
                    guard = 'permanent_writer_error'
                if guard:
                    break
            time.sleep(.1)
        load_end = time.time()
        stop_producing.set();producer.join(3)
        report['loadSeconds'] = max(0, load_end-start)
        report['guard'] = guard
        report['atLoadEnd'] = snapshot()
        phase = 'drain'
        if guard == 'workspace_memory_above_7GiB':
            stop_writers.set()
            for name in fixture['computeContainers']:
                subprocess.run(['docker','--host=unix:///var/run/docker.sock','kill','--signal=TERM',name],capture_output=True,check=False)
        # Completion after this bound is separately labelled drain, never counted
        # as work sustained during the offered interval.
        until = time.monotonic()+(0 if guard == 'workspace_memory_above_7GiB' else fixture['drainSeconds'])
        while time.monotonic() < until:
            final = snapshot()
            if final['memoryWorkingSetBytes'] > 7*1024**3:
                report['drainGuard'] = 'workspace_memory_above_7GiB'
                for name in fixture['computeContainers']:
                    subprocess.run(['docker','--host=unix:///var/run/docker.sock','kill','--signal=TERM',name],capture_output=True,check=False)
                break
            if final['done']+final['states'].get('failed', 0) >= stats['offered']:
                break
            time.sleep(1)
        report['afterDrain'] = snapshot()
        stop_writers.set()
        for writer in writers:
            writer['thread'].join(10)
        rows = db.rows('SELECT meta,state,accepted,error,processed_at FROM vib_captures')
        completed = {row['meta']['capture_id']: row for row in rows if row['processed_at'] is not None and row['state'] == 'done'}
        eligible = {key:due for key,due in offered.items() if due <= load_end-10}
        timely = sum(key in completed and completed[key]['processed_at'].timestamp() <= due+10
                     for key,due in eligible.items())
        lags = [completed[key]['processed_at'].timestamp()-due for key,due in offered.items() if key in completed]
        raw_ok = 0
        # Stream one stored waveform at a time after measurement. No raw rows
        # are deleted to make storage appear faster or bypass product quotas.
        with db.pool().connection() as connection, connection.transaction(), connection.cursor(name='verify_waveform_samples') as cursor:
            cursor.execute('SELECT samples,n,meta FROM vib_captures ORDER BY created_at')
            for row in cursor:
                _, array = decode_samples(bytes(row['samples']))
                if row['n'] != 256000 or row['meta']['axes'] != ['x','y','z'] or hashlib.sha256(array.T.astype('<f4').tobytes()).hexdigest() != expected_hash:
                    raise RuntimeError('stored waveform correctness mismatch')
                raw_ok += 1
        report['cloudTelemetry'] = [row['data'] for row in db.rows('SELECT DISTINCT ON (instance_id) data FROM cloud_gateway_metrics ORDER BY instance_id,at DESC')]
        report['gatewaySessionRotations'] = max(0,len(seen_sessions)-len(processes))
        report['publishedMeasurements'] = db.one('SELECT count(*) AS n FROM vib_measurements m JOIN vib_captures c ON c.id=m.capture_id')['n']
        report.update({'offered': len(offered), 'uniqueStored': len(rows), 'rawSamplesVerified': raw_ok,
                       'done': len(completed), 'qualityAccepted': sum(row['accepted'] is True for row in rows),
                       'failed': sum(row['state'] == 'failed' for row in rows),
                       'deadlineEligible': len(eligible), 'completedWithin10s': timely,
                       'timelyFraction': timely/len(eligible) if eligible else None,
                       'completionLagP95sCompletedOnly': float(np.percentile(lags,95)) if lags else None,
                       'producerLagP99ms': float(np.percentile(producer_lags,99)*1000) if producer_lags else None,
                       'writerErrors': errors})
        report['passed'] = (report['loadSeconds'] >= fixture['loadSeconds']-.5 and guard is None
                            and not stats['producerQueueFull'] and not stats['permanentWriterErrors']
                            and report['producerLagP99ms'] <= 100 and bool(eligible) and timely/len(eligible) >= .95
                            and len(rows) == len(offered) and raw_ok == len(rows)
                            and report['qualityAccepted'] == len(rows)
                            and report['publishedMeasurements'] == len(rows) and not report['afterDrain']['oomKills'])
        if fixture.get('waveformPreflight'):
            report['preflightPassed'] = raw_ok == 1 and len(completed) == 1 and report['qualityAccepted'] == 1
            if not report['preflightPassed']:
                raise RuntimeError('single waveform correctness preflight failed')
        print(json.dumps({k:v for k,v in report.items() if k not in ('snapshots','writerErrors','cloudTelemetry')}, default=str), flush=True)
        output.write_text(json.dumps(report,indent=2,default=str)+'\n')
        if fixture['observeSeconds'] >= 15:
            print('Measurement finished; separate live dashboard observation interval',flush=True)
            time.sleep(fixture['observeSeconds'])
        return 0  # A measured capacity failure is a valid report, not a fixture failure.
    except Exception as exc:
        report['fixtureError'] = type(exc).__name__+': '+str(exc)
        raise
    finally:
        stop_producing.set();stop_writers.set()
        for child in processes:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
        for child in processes:
            try:
                child.wait(10)
            except subprocess.TimeoutExpired:
                child.kill();child.wait()
        for log in logs:
            log.close()
        output.write_text(json.dumps(report, indent=2, default=str)+'\n')
        db.close()


if __name__ == '__main__':
    raise SystemExit(main())
