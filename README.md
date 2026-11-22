# Clear Intervals edge gateway

The edge gateway runs on your network and forwards machine data to Clear Intervals. Your existing agents
(vmagent, Prometheus, Grafana Alloy, OpenTelemetry Collector, or a DAQ that posts captures) write to it as if it
were their usual endpoint. It keeps everything on local disk until the cloud confirms receipt, and it only ever
connects outwards.

```
 your network                                                    Clear Intervals
┌────────────────────────────────────────────────┐           ┌──────────────────┐
│ vmagent / Prometheus ──remote write──┐         │           │                  │
│ DAQ / capture writer ──HTTP POST─────┤         │  mTLS     │                  │
│                                      ▼         │  443      │                  │
│     edge gateway: modules → disk buffer → uplink ════════▶ │  cloud gateway   │
│                   (state volume: key, cert, buffer)        │                  │
└────────────────────────────────────────────────┘ outbound  └──────────────────┘
                                                     only
```

- **Outbound only.** HTTP/3 over UDP 443, falling back to HTTP/2 over TCP 443 or an HTTP CONNECT proxy. Nothing
  listens towards the internet, and the cloud never sends commands or data back, only replies.
- **Only bound data leaves the site.** Series and channels that match no binding in your configuration are dropped
  at the door and counted.
- **Durable.** A writer gets success only after its data is fsynced to the buffer. Outages are bridged from disk
  (10 GiB and 7 days by default).
- **Own identity.** The gateway generates its private key locally and enrolls once with a single-use licence. Its
  certificate lasts 24 hours and renews itself. Keys never leave the state volume.

## Requirements

- Linux with Docker (or any OCI runtime), or Go 1.27.3 to build from source.
- Outbound UDP 443 and/or TCP 443 to your region's ingest host, directly or through an HTTP proxy. Proxies that
  inspect TLS must exempt the ingest host.
- NTP on the host. Captures are refused if the clock is more than 30 s off.
- An enrollment licence for this gateway, downloaded from the product, and a stream key for each sensor you bind.

## Quick start

These steps use Docker and the remote-write module. Paths on the host are examples.

**1. Prepare the host directories.** The image runs as UID/GID 65532 with no shell.

```sh
sudo mkdir -p /srv/edgegateway/config /srv/edgegateway/state/enrollment
sudo cp license.json /srv/edgegateway/state/enrollment/license.json
sudo chown -R 65532:65532 /srv/edgegateway/state
sudo chmod 700 /srv/edgegateway/state && sudo chmod 600 /srv/edgegateway/state/enrollment/license.json
```

The licence is deleted automatically once enrollment completes, which is why it lives in the writable state
volume. A licence may also carry a `streamBindings` roster: when present, the gateway refuses to start if a
configured binding is missing from it and warns when a stream key no longer matches the roster.

**2. Create a writer credential.** Each writer gets its own token. The gateway stores only the token's SHA-256.

```sh
TOKEN=$(openssl rand -base64 48)
printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1   # goes into tokenSha256
```

Keep `$TOKEN` in the writer's secret store, not in the gateway configuration.

**3. Write the configuration.** Start from [`config.example.yaml`](config.example.yaml) and save it as
`/srv/edgegateway/config/config.yaml`. A non-loopback listener requires a TLS certificate and key, which go in
the same directory.

```yaml
stateDir: /var/lib/edgegateway
deploymentLicensePath: /var/lib/edgegateway/enrollment/license.json
modules:
  remoteWrite:
    enabled: true
    listen: 0.0.0.0:8429
    certificate: /etc/edgegateway/lan-server.pem
    key: /etc/edgegateway/lan-server.key
    principals:
      - id: vmagent
        tokenSha256: <output of step 2>
bindings:
  - id: <binding version from the product>
    streamKey: <stream key from the product>
    sourceId: <canonical source ID from the product>
    kind: series
    selector:
      __name__: machine_speed_rpm
      machine: pump-1
    scale: 1
    principals: [vmagent]
```

**4. Check it.** `-check` validates the file without opening ports or contacting the cloud.

```sh
docker run --rm -v /srv/edgegateway/config:/etc/edgegateway:ro \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest> -check
```

A problem is reported with the field it concerns:

```json
{"level":"ERROR","event":"configuration_invalid","field":"bindings[0].streamKey","problem":"must be the 40-100 character stream key copied from the product"}
```

**5. Run it.**

```sh
docker run -d --name edgegateway --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=512m --cpus=1 \
  -v /srv/edgegateway/config:/etc/edgegateway:ro \
  -v /srv/edgegateway/state:/var/lib/edgegateway \
  -p 10.0.0.5:8429:8429 \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest>
```

Publish the port only on the LAN interface your writers use. Deploy by digest, never by tag: see
[Verifying a release](#verifying-a-release).

**6. Point a writer at it.** For Prometheus:

```yaml
remote_write:
  - url: https://edgegateway.lan:8429/api/v1/write
    authorization:
      credentials_file: /etc/prometheus/edgegateway.token
    tls_config:
      ca_file: /etc/prometheus/edgegateway-ca.pem
    queue_config:
      max_samples_per_send: 1000
```

For vmagent, add `-remoteWrite.url=https://edgegateway.lan:8429/api/v1/write`, `-remoteWrite.bearerToken=...`
and `-remoteWrite.tlsCAFile=...`. Your existing remote-write targets stay as they are.

**7. Watch the logs.** `docker logs -f edgegateway` should show `identity_loaded`, `listener_started`,
`gateway_ready`, then `credential_activated` and `uplink_connected` once enrollment succeeds.

## Configuration

The file is strict YAML: unknown keys, wrong types and extra documents are errors. The main keys:

| Key | Purpose |
| --- | --- |
| `stateDir` | State volume: key, certificate, buffer. Must persist and must not be shared or copied. |
| `deploymentLicensePath` | Enrollment licence. Needed only until enrollment succeeds. |
| `statusListen` | `/healthz` and `/metrics`. Loopback only (default `127.0.0.1:9081`). |
| `buffer.maxBytes`, `buffer.maxAgeDays`, `buffer.maxSegments` | Buffer limits (10 GiB, 7 days, 100,000). |
| `modules.remoteWrite`, `modules.captures` | Listener, TLS, optional writer CA and writer principals per module. |
| `uplink.proxy`, `uplink.forceTcp` | HTTP CONNECT proxy (or `HTTPS_PROXY`); skip the QUIC attempt. |
| `bindings` | Source selector → binding version, stream key, source ID and allowed principals. |

`EDGE_STATE_DIR` and `EDGE_LICENSE_PATH` override the two paths. `SIGHUP` reloads principals and bindings
atomically; other changes need a restart. Writers can authenticate with a bearer token, an Argon2id password
(`echo -n "$PASSWORD" | edgegateway -hash-password`) or a client certificate.

[`docs/operations.md`](docs/operations.md) has the full reference: request limits, status codes returned to
writers, buffer behaviour, reloads and root rollover. [`docs/waveform-ingest.md`](docs/waveform-ingest.md)
describes the capture module.

## Logs and troubleshooting

Logs are JSON lines on stdout. Every line has an `event` name, and problems carry a `reason` and usually a `hint`
saying what to check. Logs never contain measurements, labels, tokens, stream keys or key material, so they are
safe to forward to a log system or attach to a support request. The event reference is in
[`docs/operations.md`](docs/operations.md#logs).

| You see | Likely cause |
| --- | --- |
| `configuration_invalid` | The named `field` is wrong. Fix it and re-run `-check`. |
| `gateway_stopped`, reason `identity_invalid` | The licence is missing, expired or belongs to another gateway's state directory. The `problem` says which. |
| `gateway_stopped`, reason `permission_denied` | The state volume is not writable by UID 65532. |
| `gateway_stopped`, reason `state_directory_locked` | Another gateway process uses the same state directory. |
| `uplink_retry`, stage `server_certificate_untrusted` | A proxy or firewall is intercepting TLS. Exempt the ingest host. |
| `uplink_retry`, stage `connect_timeout` or `connection_refused` | Outbound TCP 443 is blocked. Open it or set `uplink.proxy`. |
| `uplink_retry`, stage `proxy_connect_http_407` | The proxy needs credentials in `uplink.proxy`. |
| `quic_unavailable` | UDP 443 is blocked. The gateway works over TCP; set `uplink.forceTcp: true` to skip the attempt. |
| `gateway_stopped`, reason `clock_skew` | First start only: the host clock is more than 60 s off, so enrollment cannot proceed. Enable NTP and restart. |
| `uplink_retry`, code `clock_skew` | The host clock is off. Enable NTP. |
| `uplink_retry`, code `entitlement_inactive` | The add-on is not active for your organization. Data stays buffered. |
| `ntp_drift`, `clock_skew` | The host clock differs from the cloud (warn past 2 s, error past 30 s). Enable NTP. |
| `stream_keys_rejected` | The cloud does not know a configured binding's stream key. Copy the current binding from the product. |
| `stream_key_digest_mismatch` | The configured stream key does not match the licence roster: it was rotated or the wrong key was copied. |
| `records_dropped`, `dropReason` `unmapped` | Incoming series match no binding selector. Check labels in `bindings[].selector`. |
| Writer gets `401` / `403` | Wrong token, or the series belongs to a binding that does not list this principal. |
| `buffer_integrity_alarm` | Disk error or corrupt segment. Check the disk; the segment is quarantined as `.bad`. |

`/healthz` (200 or 503) and `/metrics` (Prometheus text) are served on `statusListen`. A 200 can carry a
`degraded:` body when the clock drifts or stream keys are rejected; that is a warning, not a failed check. Inside a
container that is the container's loopback, so scrape it from a sidecar in the same network namespace.

## Building from source

```sh
make verify build        # gofmt, vet, race tests, then bin/edgegateway
bin/edgegateway -version
docker build --build-arg VERSION=$(git describe --always) -t edgegateway .
```

Other targets: `make fuzz`, `make scan` (govulncheck), and `make generate vectors`, which regenerates the protobuf
code and checks the canonical encoding vectors (needs Python with `grpcio-tools`). The `integration/` tests run
against the cloud gateway and core, which are not part of this repository; see
[`docs/verification.md`](docs/verification.md).

## Verifying a release

Images are built by [`.github/workflows/release.yaml`](.github/workflows/release.yaml) on `main`, scanned, and
signed with Sigstore keyless signing, with an SBOM and provenance attached. Check the signature against that exact
workflow, not just any valid signature:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/1a11/clearintervals-edge/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest>
```

To mirror into an internal registry, use `cosign copy` so signatures and attestations travel with the image.
There are no automatic updates.

## Security

- The image contains no secrets, keys or customer configuration. This repository contains none either; the test
  suites generate their own throwaway PKI and credentials at run time.
- Having the source or the image grants no access. A gateway can send only after enrolling with a single-use
  licence issued for it in the product, and the cloud decides the organization, sites and sensors from its own
  registry, never from anything the gateway claims.
- Revocation in the product closes live sessions within 30 seconds. A copied state volume is a copied identity:
  revoke and re-license if one leaks.
- Writer credentials are stored as SHA-256 digests or Argon2id hashes and compared in constant time.

Design details are in [`docs/design.md`](docs/design.md) and the wire protocol in
[`docs/protocol-v1.md`](docs/protocol-v1.md). To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/edgegateway` | Entry point, uplink loop, logging. |
| `internal/remotewrite`, `internal/captures` | Sink modules. |
| `internal/buffer`, `internal/durable` | Disk buffer and crash-safe files. |
| `internal/identity` | Enrollment, renewal, recovery. |
| `internal/uplink`, `internal/wire`, `protocol/v1` | Transport, framing, protobuf schema and vectors. |
| `internal/config`, `internal/auth`, `internal/httpauth` | Configuration and writer authentication. |
| `integration/` | System tests against real cloud gateway and core processes. |
| `docs/` | Design, operations, protocol, waveform ingest, verification. |
