# Clear Intervals Edge Gateway

The edge gateway runs on your local network and forwards machine telemetry to Clear Intervals. Local agents (`vmagent`, Prometheus, Grafana Alloy, OpenTelemetry Collector, or HTTP capture writers) push data to the gateway. The gateway persists data to local disk before transmission and opens only outbound connections.

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

- **Outbound only:** Connects over HTTP/3 (UDP 443), falling back to HTTP/2 (TCP 443) or an HTTP CONNECT proxy. Opens no external ports and accepts no inbound commands.
- **Explicit allowlisting:** Drops and counts any series or channel that does not match a configured binding. Until the first descriptor sync completes, an unmatched series receives `503` with `Retry-After: 15` so the writer keeps its first batch.
- **Disk-backed durability:** Returns success to writers only after `fsync` completes. Buffers data during outages (default: 10 GiB or 7 days).
- **Managed identity:** Generates its private key locally and enrolls once with a single-use license. Certificates expire after 24 hours and renew automatically. Private keys remain inside the state volume.

## Requirements

- Linux with Docker (or an OCI runtime), or Go 1.27.3 to build from source.
- Outbound UDP 443 and/or TCP 443 to your region's ingest host (direct or via HTTP proxy). Exempt the ingest host from TLS inspection.
- Active NTP on the host. Captures fail if clock drift exceeds 30 s.
- The prefilled `config.yaml`, one-time enrollment `license.json`, and writer bearer token from the Gateway Setup
  Wizard in Clear Intervals.

## Quick start

The Gateway Setup Wizard in Clear Intervals generates the configuration. Its first three steps run on the gateway host, and Step 4 defines the streams.

### 1. Download configuration and license (Step 1 of wizard)

Step 1 downloads two files and shows the writer token:

- `config.yaml`, prefilled with the `vmagent` principal (`tokenSha256`) and `bindings: []`.
- `license.json`, the one-time enrollment license.

Choose one listener mode in the wizard:

- `TLS (Recommended)`: `listen: 0.0.0.0:2948` with `certificate: /etc/ssl/certs/own/tls.crt` and `key: /etc/ssl/certs/own/tls.key`.
- `Loopback HTTP`: `listen: 127.0.0.1:2948`, for a writer that shares the gateway's network namespace.

Place both files on the host, owned by the container's UID/GID `65532:65532`:

```sh
sudo install -d -o 65532 -g 65532 -m 0700 \
  /srv/edgegateway/config /srv/edgegateway/state /srv/edgegateway/state/enrollment
sudo install -o 65532 -g 65532 -m 0600 config.yaml /srv/edgegateway/config/config.yaml
sudo install -o 65532 -g 65532 -m 0600 license.json /srv/edgegateway/state/enrollment/license.json
```

With `TLS (Recommended)`, also install the gateway's certificate and key at the paths the prefilled file names, readable by UID 65532 inside the container. The example paths are `/etc/ssl/certs/own/tls.crt` and `/etc/ssl/certs/own/tls.key`, and the examples below mount `/srv/edgegateway/tls` there.

`license.json` is single use. The gateway deletes it after enrollment, so do not restore it on later starts.

### 2. Connect vmagent (Step 2 of wizard)

Step 2 shows the remote-write endpoint and the pre-generated one-time bearer token, which starts with `ci_ingest_`. Copy the `docker-compose.yml` or the Docker or Kubernetes command for your writer and send samples to:

- `https://edgegateway:2948/api/v1/write` with `TLS (Recommended)`.
- `http://127.0.0.1:2948/api/v1/write` with `Loopback HTTP` in a shared network namespace.

Keep the token in the writer's secret store. The gateway stores only its SHA-256 digest (`tokenSha256`). Your existing remote-write destinations stay as they are; add this endpoint next to them.

### 3. Start the gateway (Step 3 of wizard)

```yaml
# docker-compose.yml
services:
  edgegateway:
    image: ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest>
    container_name: edgegateway
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 512m
    cpus: 1
    volumes:
      - /srv/edgegateway/config:/etc/edgegateway:ro
      - /srv/edgegateway/state:/var/lib/edgegateway
      - /srv/edgegateway/tls:/etc/ssl/certs/own:ro
    ports:
      - "10.0.0.5:2948:2948"
```

```sh
docker run -d --name edgegateway --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=512m --cpus=1 \
  -v /srv/edgegateway/config:/etc/edgegateway:ro \
  -v /srv/edgegateway/state:/var/lib/edgegateway \
  -v /srv/edgegateway/tls:/etc/ssl/certs/own:ro \
  -p 10.0.0.5:2948:2948 \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest>
```

Publish the port on the LAN interface your writers use. The `/srv/edgegateway/tls` mount is needed only with `TLS (Recommended)`; with `Loopback HTTP`, skip it and the port mapping. Deploy by digest, never by tag: see [Verifying a release](#verifying-a-release).

Optionally validate the file first. `-check` reads it without opening ports or contacting the cloud:

```sh
docker run --rm -v /srv/edgegateway/config:/etc/edgegateway:ro \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest> -check
```

On first start the gateway enrolls with `license.json`, deletes the file, and sends its first heartbeat. `docker logs -f edgegateway` shows `credential_activated` and `uplink_connected`, and Step 3 in the wizard turns green (`Reporting`).

### 4. Add streams in Clear Intervals (Step 4 of wizard or Gateway overview)

Add a stream in Step 4, or later from the gateway overview page. Pick the target sensor or machine and enter a PromQL series selector with one or more exact label matchers:

```
vm_motor_temp_celsius{site="north",asset="comp_a",sensor="de_bearing"}
```

Each stream uses one gateway sensor slot. The gateway polls `POST /uplink/v1/descriptors` when it connects and every 15 seconds, logs `descriptors_synced`, caches the descriptors in `<stateDir>/descriptors.json`, and begins forwarding matching series. You do not download stream key files or edit `config.yaml`.

While the first descriptor sync is pending, `remoteWrite` answers `503` with `Retry-After: 15` for a series that matches no binding yet, so `vmagent` keeps that batch in its WAL.

## Configuration

The gateway enforces strict YAML. Unknown keys, invalid types, and multiple documents fail validation.

| Key | Purpose |
| --- | --- |
| `stateDir` | Persistent state volume for key, certificate, and buffer. Do not share or copy. |
| `deploymentLicensePath` | Enrollment license path. Required only until enrollment succeeds. |
| `statusListen` | Loopback address for `/healthz` and `/metrics` (default: `127.0.0.1:9081`). |
| `buffer.maxBytes`, `buffer.maxAgeDays`, `buffer.maxSegments` | Disk buffer limits (defaults: 10 GiB, 7 days, 100,000 segments). |
| `modules.remoteWrite`, `modules.captures` | Per-module listener, TLS, optional writer CA, and writer principals. |
| `uplink.proxy`, `uplink.forceTcp` | HTTP CONNECT proxy (or `HTTPS_PROXY`); set `forceTcp: true` to skip QUIC. |
| `bindings` | Optional local override for a fixed source set. Empty in the prefilled file; normally filled from cloud stream descriptors. |

- **Environment overrides:** `EDGE_STATE_DIR` overrides `stateDir`. `EDGE_LICENSE_PATH` overrides `deploymentLicensePath`.
- **Reloads:** Send `SIGHUP` to reload `principals` and `bindings` atomically. All other changes require a restart.
- **Writer authentication:** Supports bearer tokens (SHA-256), Argon2id passwords (`echo -n "$PASSWORD" | edgegateway -hash-password`), or client certificates.
- **Local writers:** The prefilled `config.yaml` already carries the `vmagent` principal. To add another writer locally, generate a token with `openssl rand -base64 48`, keep it in that writer's secret store, and put only its SHA-256 hex digest in `tokenSha256`. Alternatively use an Argon2id password or a client certificate with `certificateSha256` and `writerCa`.
- **Static bindings:** A local `bindings` list is optional. The gateway fills `bindings: []` from the cloud stream descriptors, and a local binding overrides a descriptor with the same ID. Each entry needs `id`, `streamKey`, `sourceId`, `kind` and, for `series`, an exact-label `selector` and a nonzero `scale`.
- **Full reference:** See [`docs/operations.md`](docs/operations.md) for limits, status codes, buffer behavior, reloads, and root rollover. See [`docs/waveform-ingest.md`](docs/waveform-ingest.md) for the capture module.

## Logs, health, and troubleshooting

The gateway writes JSON lines to `stdout`. Every log line includes `event`; errors include `reason` and usually `hint`. Logs exclude measurements, labels, tokens, stream keys, and cryptographic keys. See [`docs/operations.md`](docs/operations.md#logs) for the event reference.

`statusListen` serves `/healthz` (`200` or `503`) and `/metrics` (Prometheus text). A `200` response with a `degraded:` body indicates a warning (clock drift or rejected stream keys), not a health failure. In containers, scrape from a sidecar in the same network namespace.

| Log event or symptom | Cause and action |
| --- | --- |
| `configuration_invalid` | Invalid `field`. Fix the configuration and run `-check`. |
| `gateway_stopped`, reason `identity_invalid` | License is missing, expired, or mismatched with the state directory. Check `problem`. |
| `gateway_stopped`, reason `permission_denied` | UID `65532` cannot write to `stateDir`. Fix volume ownership and permissions. |
| `gateway_stopped`, reason `state_directory_locked` | Another gateway process holds the lock on `stateDir`. Stop the duplicate process. |
| `uplink_retry`, stage `server_certificate_untrusted` | A proxy or firewall intercepts TLS. Exempt the ingest host. |
| `uplink_retry`, stage `connect_timeout` or `connection_refused` | Outbound TCP 443 is blocked. Open TCP 443 or configure `uplink.proxy`. |
| `uplink_retry`, stage `proxy_connect_http_407` | Proxy requires authentication. Add credentials to `uplink.proxy`. |
| `quic_unavailable` | Outbound UDP 443 is blocked. Gateway falls back to TCP; set `uplink.forceTcp: true` to skip QUIC. |
| `gateway_stopped`, reason `clock_skew` | First start only: host clock drift exceeds 60 s. Enable NTP and restart. |
| `uplink_retry`, code `clock_skew` | Host clock is out of sync. Enable NTP. |
| `uplink_retry`, code `entitlement_inactive` | Add-on is inactive for your organization. Gateway keeps buffering data locally. |
| `ntp_drift`, `clock_skew` | Clock differs from cloud (warns above 2 s, errors above 30 s). Enable NTP. |
| `stream_keys_rejected` | Cloud does not recognize a configured stream key. Copy the current binding from Clear Intervals. |
| `stream_key_digest_mismatch` | Configured stream key does not match the license roster. Update the rotated or mistyped key. |
| `descriptors_synced`, `descriptors_unavailable`, `descriptors_cache_failed` | Stream descriptors were applied from the cloud (`cloud`) or the startup cache; a failed fetch holds remote write at `503` with `Retry-After: 15`; the cache could not be written but the descriptors are active. |
| `records_dropped`, `dropReason` `unmapped` | Incoming series match no binding. Check the stream's PromQL selector in Clear Intervals, or a static `bindings[].selector`. |
| Writer receives `401` or `403` | Invalid token, or the writer principal is not listed on the matched binding. |
| `buffer_integrity_alarm` | Disk error or corrupt segment. Inspect the disk; corrupt segments move to `.bad`. |

## Verbose debugging

Normal logs are bounded and redacted. When a writer reaches the gateway but its samples do not appear in Clear Intervals, verbose mode shows every step: the listener connection, the TLS handshake, the request, the payload, each series with its labels, the match against a binding or a cloud descriptor, the buffered item, the uplink frames and the cloud's per-item answer.

Turn it on in any of three ways:

- CLI: `edgegateway -config /etc/edgegateway/config.yaml -verbose`
- Container environment: `-e EDGE_VERBOSE=1` (or `true`) in `docker run`, or `environment: [EDGE_VERBOSE=1]` in `docker-compose.yml`
- Configuration: `verbose: true` in `config.yaml`, then restart the gateway

| Event | What it shows |
| --- | --- |
| `verbose_config_loaded` | The whole effective configuration: paths, listeners, writer principals with their `tokenSha256`, uplink settings and static bindings. |
| `verbose_listener_conn`, `verbose_listener_error` | Raw writer connections (`accepted`, `active`, `closed`, peer address) and the HTTP or TLS handshake error the normal server log discards, for example a writer with the wrong CA. |
| `verbose_remotewrite_request`, `verbose_remotewrite_auth` | Every POST: URI, protocol, full headers including `Authorization`, and the bearer digest compared with each principal's `tokenSha256`. |
| `verbose_remotewrite_payload` | Compressed and decoded byte counts, series and sample counts, or the exact read, decompression or protobuf error. |
| `verbose_remotewrite_series`, `verbose_remotewrite_rejected` | Each series with all labels and samples: matched (`bindingId`, `sourceId`, `streamKey`, scaled value), unmapped with a per-binding label diff, held at `503` until descriptors arrive, or rejected with the status and reason. |
| `verbose_descriptor_poll`, `verbose_descriptor_response`, `verbose_active_selectors` | The descriptor request, the cloud's full answer or error, and every selector the gateway matches against. |
| `verbose_uplink_dial` | The QUIC `h3` attempt and the TCP `h2` fallback or proxy `CONNECT`, with the TLS version, ALPN and the server certificate subject and SHA-256. |
| `verbose_uplink_welcome`, `verbose_uplink_heartbeat` | Session open (session id, transport, capabilities, clock offset) and each heartbeat with buffer and counter totals. |
| `verbose_uplink_frame_send`, `verbose_uplink_frame_recv` | Every uplink frame: path, frame type, item count, and the cloud's failure code, reason and reference. |
| `verbose_uplink_batch_send`, `verbose_uplink_batch_ack` | The items sent (id, binding, source, stream key, timestamp, value) and the cloud's per-item outcome, code and retry time. |

Verbose output is deliberately unredacted. It writes bearer tokens, Argon2id hashes, stream keys, labels, sample values and certificates. Enable it for a short session, keep the output on the gateway host or a private log store, and turn it off afterwards.

## Building from source

```sh
make verify build        # runs gofmt, vet, race tests, then builds bin/edgegateway
bin/edgegateway -version
docker build --build-arg VERSION=$(git describe --always) -t edgegateway .
```

- `make fuzz`: Runs fuzz tests.
- `make scan`: Runs `govulncheck`.
- `make generate vectors`: Regenerates protobuf code and verifies canonical encoding vectors (requires Python with `grpcio-tools`).
- `integration/`: Runs system tests against the cloud gateway and core (external to this repository). See [`docs/verification.md`](docs/verification.md).

## Verifying a release

Release images are built by [`.github/workflows/release.yaml`](.github/workflows/release.yaml) on `main`, vulnerability-scanned, and signed with Sigstore keyless signing, an SBOM, and provenance attestations. Verify against the exact workflow identity:

```sh
cosign verify \
  --certificate-oidc-issuer [https://token.actions.githubusercontent.com](https://token.actions.githubusercontent.com) \
  --certificate-identity [https://github.com/1a11/clearintervals-edge/.github/workflows/release.yaml@refs/heads/main](https://github.com/1a11/clearintervals-edge/.github/workflows/release.yaml@refs/heads/main) \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest>
```

Use `cosign copy` when mirroring to an internal registry so signatures and attestations remain attached. Automatic updates are not supported.

## Security

- **No embedded secrets:** Images and source contain no secrets, keys, or customer configuration. Test suites generate ephemeral PKI and credentials at runtime.
- **Server-side authority:** Possession of the source or image grants no access. A gateway transmits only after enrolling with a single-use license. The cloud registry controls organization, site, and sensor mapping.
- **Revocation:** Revoking a gateway closes live sessions within 30 seconds. A copied state volume copies the identity; revoke and re-license if a volume leaks.
- **Credential hashing:** Writer credentials are stored as SHA-256 digests or Argon2id hashes and compared in constant time.

See [`docs/design.md`](docs/design.md) for architecture, [`docs/protocol-v1.md`](docs/protocol-v1.md) for the wire protocol, and [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/edgegateway` | Entry point, uplink loop, logging. |
| `internal/remotewrite`, `internal/captures` | Ingest modules. |
| `internal/buffer`, `internal/durable` | Disk buffer and crash-safe storage. |
| `internal/identity` | Enrollment, certificate renewal, recovery. |
| `internal/uplink`, `internal/wire`, `protocol/v1` | Transport, framing, protobuf schema, encoding vectors. |
| `internal/config`, `internal/auth`, `internal/httpauth` | Configuration parsing and writer authentication. |
| `integration/` | System tests against cloud gateway and core. |
| `docs/` | Design, operations, protocol, waveform ingest, verification. |
