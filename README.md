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
- **Explicit allowlisting:** Drops and counts any series or channel that does not match a configured binding.
- **Disk-backed durability:** Returns success to writers only after `fsync` completes. Buffers data during outages (default: 10 GiB or 7 days).
- **Managed identity:** Generates its private key locally and enrolls once with a single-use license. Certificates expire after 24 hours and renew automatically. Private keys remain inside the state volume.

## Requirements

- Linux with Docker (or an OCI runtime), or Go 1.27.3 to build from source.
- Outbound UDP 443 and/or TCP 443 to your region's ingest host (direct or via HTTP proxy). Exempt the ingest host from TLS inspection.
- Active NTP on the host. Captures fail if clock drift exceeds 30 s.
- One enrollment license for the gateway and one stream key per bound sensor (from Clear Intervals).

## Quick start

These steps deploy the `remoteWrite` module with Docker. Replace example paths to match your host.

### 1. Prepare host directories

The container runs as UID/GID `65532` with no shell.

```sh
sudo mkdir -p /srv/edgegateway/config /srv/edgegateway/state/enrollment
sudo cp license.json /srv/edgegateway/state/enrollment/license.json
sudo chown -R 65532:65532 /srv/edgegateway/state
sudo chmod 700 /srv/edgegateway/state && sudo chmod 600 /srv/edgegateway/state/enrollment/license.json
```

The gateway deletes `license.json` after enrollment succeeds. If the license includes a `streamBindings` roster, startup fails when a configured binding is missing and warns when a stream key does not match.

### 2. Create a writer token

Generate one token per writer. The gateway stores only the SHA-256 hash.

```sh
TOKEN=$(openssl rand -base64 48)
printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1   # copy to tokenSha256
```

Store `$TOKEN` in the writer's secret store, not in `config.yaml`.

### 3. Write the configuration

Copy [`config.example.yaml`](config.example.yaml) to `/srv/edgegateway/config/config.yaml`. Non-loopback listeners require a TLS certificate and key in the same directory.

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
  - id: <binding version from Clear Intervals>
    streamKey: <stream key from Clear Intervals>
    sourceId: <canonical source ID from Clear Intervals>
    kind: series
    selector:
      __name__: machine_speed_rpm
      machine: pump-1
    scale: 1
    principals: [vmagent]
```

### 4. Validate the configuration

Run `-check` to validate the file without opening ports or contacting the cloud:

```sh
docker run --rm -v /srv/edgegateway/config:/etc/edgegateway:ro \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest> -check
```

Validation errors identify the failing field:

```json
{"level":"ERROR","event":"configuration_invalid","field":"bindings[0].streamKey","problem":"must be the 40-100 character stream key copied from the product"}
```

### 5. Start the gateway

```sh
docker run -d --name edgegateway --restart unless-stopped \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=512m --cpus=1 \
  -v /srv/edgegateway/config:/etc/edgegateway:ro \
  -v /srv/edgegateway/state:/var/lib/edgegateway \
  -p 10.0.0.5:8429:8429 \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<digest>
```

Bind the port to the LAN interface only. Deploy by image digest, not by tag. See [Verifying a release](#verifying-a-release).

### 6. Configure a writer

**Prometheus:**

```yaml
remote_write:
  - url: [https://edgegateway.lan:8429/api/v1/write](https://edgegateway.lan:8429/api/v1/write)
    authorization:
      credentials_file: /etc/prometheus/edgegateway.token
    tls_config:
      ca_file: /etc/prometheus/edgegateway-ca.pem
    queue_config:
      max_samples_per_send: 1000
```

**vmagent:** Add `-remoteWrite.url=https://edgegateway.lan:8429/api/v1/write`, `-remoteWrite.bearerToken=...`, and `-remoteWrite.tlsCAFile=...`. Existing remote-write targets do not change.

### 7. Verify startup

Run `docker logs -f edgegateway`. Confirm these events appear in order: `identity_loaded`, `listener_started`, `gateway_ready`, `credential_activated`, `uplink_connected`.

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
| `bindings` | Maps source selectors to binding version, stream key, source ID, and allowed principals. |

- **Environment overrides:** `EDGE_STATE_DIR` overrides `stateDir`. `EDGE_LICENSE_PATH` overrides `deploymentLicensePath`.
- **Reloads:** Send `SIGHUP` to reload `principals` and `bindings` atomically. All other changes require a restart.
- **Writer authentication:** Supports bearer tokens (SHA-256), Argon2id passwords (`echo -n "$PASSWORD" | edgegateway -hash-password`), or client certificates.
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
| `records_dropped`, `dropReason` `unmapped` | Incoming series match no binding selector. Check `bindings[].selector` labels. |
| Writer receives `401` or `403` | Invalid token, or the writer principal is not listed on the matched binding. |
| `buffer_integrity_alarm` | Disk error or corrupt segment. Inspect the disk; corrupt segments move to `.bad`. |

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
