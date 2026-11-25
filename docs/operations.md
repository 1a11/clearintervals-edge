# Running the edge gateway

This is the customer-side sink. The cloud gateway and core are operated by Clear Intervals. The wire contract in `protocol/v1` and its canonical vectors are shared with the cloud gateway; `make generate vectors` regenerates the Go code and checks the vectors. No cloud or core code is linked into the customer image.

Build with `make verify build`. Copy `config.example.yaml` to a private configuration directory and run `bin/edgegateway -config /path/config.yaml -check` before starting it. YAML is strict; unknown fields and extra documents fail. `EDGE_STATE_DIR` and `EDGE_LICENSE_PATH` override only the corresponding local paths. Module listeners start disabled. Status binds only to a literal loopback IP; use a local authenticated monitoring forwarder for remote access.

Licences without a `credentialGeneration` field are from an older format and are refused; download a fresh one. The gateway pins the bundle's region, gateway, host and roots. It generates P-256 keys locally, journals the exact operation/key/CSR before sending anything, retrieves lost results with the pending key, and renews at half-life. Expired leaves are sent only in the recovery body; the bootstrap TLS connection does not present them. Keys and manifests are private 0600 files inside a 0700 state directory. An OS lock refuses concurrent processes sharing that directory.

Mount the whole enrollment directory writable so the one-time bundle can be removed after durable credential activation; mounting the license as a read-only standalone file prevents cleanup. Never clone the state volume. One identity belongs to one customer gateway; authorized redundant gateways require distinct bundles and product-approved canonical source identities.

## Configure remote write

Generate a random 32-byte-or-longer token on the customer host. Put only its SHA-256 hex digest in a principal's `tokenSha256`; put the token in the writer's own secret store. Authentication compares digests in constant time. Alternatively pin a writer leaf's SHA-256 DER fingerprint with `certificateSha256` and configure `writerCa` for client-chain validation. Each principal uses one method. Basic authentication uses the principal ID as username and a generated high-entropy password. Generate its salted PHC hash locally with `edgegateway -hash-password` reading stdin and place the result in `passwordHash`; never pass the password as a command-line argument. The only accepted Argon2id profile is 64 MiB, three passes and one lane with a 16-byte random salt and 32-byte digest. Two password workers bound memory to 128 MiB; saturation returns 429. Arbitrary PHC cost parameters are rejected before hashing.

For every source, copy its immutable binding ID, stream key and canonical device ID from the product. Configure an exact-label selector, source-to-core unit scale, and allowed principals:

```yaml
modules:
  remoteWrite:
    enabled: true
    listen: 0.0.0.0:8429
    certificate: /etc/edgegateway/lan-server.pem
    key: /etc/edgegateway/lan-server.key
    writerCa: ""
    principals:
      - id: vmagent
        tokenSha256: <64-lowercase-hex-characters>
bindings:
  - id: <immutable-binding-version>
    streamKey: <gateway-specific-stream-key>
    sourceId: <canonical-source-id>
    kind: series
    selector:
      __name__: machine_speed_rpm
      machine: pump-1
    scale: 1
    principals: [vmagent]
```

Configure Prometheus `remote_write.url` or vmagent `-remoteWrite.url` as `https://customer-gateway:8429/api/v1/write`, configure its bearer token and customer CA, and keep certificate verification enabled. Use remote write 1.0 (`application/x-protobuf`, version header `0.1.0`, snappy; negotiated `Content-Encoding: zstd` also works). Set batches to at most 1,000 total samples/series per request. Each series has at most 64 distinct labels, names at most 128 bytes and values at most 1,024 bytes. Remote write 2.0, exemplars, native histograms and metadata extensions are refused. Non-finite values and negative zero are invalid. Labels are used only for filtering and never leave the module.

Only one binding may match a series. An otherwise valid series matching a binding outside the authenticated writer's allowlist returns 403 for the whole request; it is never reclassified as unmapped. A gateway started from the product's downloaded configuration has no bindings of its own: it receives them from the cloud after enrollment (see `descriptors_synced` below). Until the first descriptor sync completes, a request whose series match no binding yet returns `503 Service Unavailable` with `Retry-After: 15` instead of being discarded, so the writer keeps that first batch in its WAL. The same hold applies after a restart until the cached `descriptors.json` in the state directory or the cloud supplies the bindings. Once a binding set is known (from the file, or from a completed sync even when it returned no streams) unmapped or expired input is deliberately discarded with durable aggregate counters. During a known authenticated suspension, valid authorized input is deliberately dropped with a durable suspended counter; eligible old backlog remains on disk. An explicit authenticated active heartbeat is required to resume it.

Success is 204 after one atomic segment transaction is fsynced. Temporary capacity, reload or disk errors return 429/503 with Retry-After; writer retry policy must preserve input on those responses. Invalid input returns 400, oversized input 413, unsupported formats 415 and missing/invalid credentials 401. Prometheus/vmagent may discard a request after a terminal 4xx; size their batches before enabling the sink. A disk or receipt write failure stops further durable admissions until restart, preventing false success after an unresolved write.

Compressed requests are at most 4 MiB, decoded at most 16 MiB, with expansion at most 20:1. Sixteen concurrent requests share the decoding/ingest budget; excess requests get 429 without queueing. At most 80 raw connections per listener, 8 KiB headers, 10-second header/no-progress and 30-second total request deadlines bound slow clients. Authentication failures are limited to 10/minute/source and 100/minute globally. Forwarded headers never change source attribution. TLS 1.3 is mandatory outside loopback. Go's bounded goroutines replace the draft's language-specific process-pool suggestion.

## Buffer, transport and reload

Default limits are 10 GiB, 7 days, 100,000 segments, further bounded by core's acceptance policy. Logical accounting includes 8 KiB per segment for filesystem allocation and its receipt sidecar. Series use at most 75% of the total budget, events at most 1%, preserving capacity for captures and identity outside the configured buffer. Leave at least 16 MiB of free filesystem space beyond the buffer limit for identity operations; filesystem exhaustion is handled as a temporary failure, not successful enqueue. Checksummed segment bodies retain the exact binding/key, source time, stable ID and payload hash. Partial receipts are checksummed and fsynced before reclamation; unknown and retryable results survive restart. Corrupt segments are quarantined as `.bad`, consume quota and raise an integrity alarm; investigate and restore from the source or a verified backup. Do not edit a segment or its receipt.

Context overflow evicts the oldest series transactions and persists drop counters; capture overflow refuses new captures. Expired records are durably counted before removal. Each enqueue transaction contains at most 1,000 items. Live and backlog lanes alternate. A network loss or HTTP status never authorizes deletion: session, epoch, sequence, index, stable ID and hash must match every explicit terminal result.

HTTP/3 is tried first with a three-second handshake budget, then HTTP/2 on TCP. Both multiplex control and data on one physical TLS connection. `uplink.forceTcp` bypasses QUIC. `uplink.proxy` or `HTTPS_PROXY` selects an HTTP CONNECT proxy and forces TCP; TLS remains end to end against pinned ingest roots. Proxy TLS interception is unsupported. No TLS session resumption or QUIC 0-RTT is used. All connections are outbound; the cloud replies only to requests.

At zero byte/item credit, the client polls control at most every five seconds. Grants are cumulative ceilings scoped to the session/epoch, never additive tokens. Every retry consumes credit. Reconnect resets transport counters while keeping item identities. Batches are limited to 128 items so bounded per-item acknowledgements fit the control response budget. Retries back off with jitter to at most 15 minutes; status control continues during idle data periods. Revocation persists a terminal state and retains the buffer; restart exits nonzero. A plain network/TLS failure cannot suspend, revoke, resume or delete data.

SIGHUP atomically replaces principals and binding snapshots for future input. It refuses modification of an existing binding version or restart-only settings. A removed version cannot be reused within the process lifetime. Queued records use their persisted original target/key. Changed module addresses, CA/server certificates, quotas or trust roots require a controlled restart. For root rollover, stop the process, install the verified overlapping anchors in `identity/trust.json`, and restart; never install roots from a server reply. Remove retired roots only after your offline-gateway recovery window has been handled.

`/healthz` reports local buffer integrity/revocation health; it is not a promise of cloud connectivity. A 200 body names non-fatal findings (`degraded: clock_skew,stream_keys_rejected`) without failing the check. `/metrics` exposes bounded counts, buffer bytes/segments, suspension and integrity state, the clock offset (`edgegateway_clock_offset_seconds`), the >30 s alarm (`edgegateway_clock_skew_alarm`) and the rejected stream-key count (`edgegateway_stream_keys_rejected`). Logs are described below. The minute heartbeat carries the buffer and delivery/drop totals used by the product.

The first release provides the remote-write module and a typed core queue for series/captures/events. A vendor-specific waveform source and local capture scheduler remain the later product decision stated in the accepted plan. No fabricated waveform or scalar-to-waveform conversion is provided.

## Logs

Logs go to stdout, one JSON object per line:

```json
{"time":"2026-10-25T13:48:31Z","level":"WARN","event":"uplink_retry","reason":"transport","stage":"server_certificate_untrusted","retryAfterSeconds":5.4,"hint":"..."}
```

`event` is a fixed name and safe to alert on. `hint`, where present, is a fixed sentence telling the operator what
to check. Lines carry bounded values: reason codes, counts, local paths and listen addresses, the gateway ID and
region, and the cloud's own refusal `code`, `serverReason` and `ref` (truncated to 256 bytes). They never contain
labels, measurements, stream keys, tokens, digests, private keys or proxy credentials. A configuration error names
the field (`bindings[2].streamKey`, `line 14`), never its value.

| Event | Level | Meaning |
| --- | --- | --- |
| `gateway_starting`, `buffer_opened`, `identity_loaded`, `listener_started`, `gateway_ready` | info | Startup sequence. `identity_loaded.state` is `enrolled`, `not_enrolled` or `operation_pending`. |
| `credential_operation_started`, `credential_activated` | info | Enrollment, renewal (every ~12 h) or recovery, with the new certificate's expiry. |
| `credential_operation_refused` | info | An enroll, renew or recover attempt was refused; `operation` and `code`, plus `reason` and `ref` when supplied. |
| `uplink_connected` | info | Connected to the cloud; `transport` is `h3` (QUIC) or `h2` (TCP). |
| `descriptors_synced` | info | The cloud's stream descriptors were applied; `bindings` counts them and `source` is `cloud` or `cache` (the startup copy). |
| `descriptors_unavailable` | warn | The descriptor request failed, so remote write answers 503 with `Retry-After: 15` until it succeeds. Logged once per failure streak, not every poll. |
| `descriptors_cache_failed` | warn | The descriptors are active but `<stateDir>/descriptors.json` could not be written; they are fetched again after a restart. |
| `quic_unavailable` | warn | QUIC failed; the gateway uses TCP and retries QUIC after 30 minutes. |
| `uplink_retry` | warn | The uplink failed and will be retried. `reason` is the category (`server_refusal`, `transport`, `eof` or `internal`); a refusal adds the cloud's `code` verbatim, plus `serverReason` and `ref` when supplied. Transport failures add `stage`. |
| `ntp_drift`, `clock_skew` | warn, error | The host clock differs from the cloud by more than 2 s or 30 s (`offsetSeconds`, `source`). Captures are refused past 30 s. |
| `clock_probe_failed` | warn | The clock could not be compared with the ingest origin; the gateway keeps running. |
| `stream_keys_rejected` | error | The cloud does not recognize a configured binding's stream key (`bindingId`, `kind`, `sourceId`). Repeated every 15 min while unresolved. |
| `stream_key_digest_mismatch` | error | A configured stream key no longer matches the licence roster: it was rotated or the wrong key was copied. Repeated every 15 min while unresolved. |
| `records_dropped` | warn | Input was discarded since the last minute, with `dropReason` and `count`. |
| `organization_suspended`, `organization_active` | warn, info | Suspension state learned from the cloud. |
| `buffer_status` | info | Every 15 minutes: buffered bytes, segments and totals. |
| `buffer_integrity_alarm` | error | A segment failed its checksum or a write failed; `/healthz` returns 503. |
| `configuration_valid`, `configuration_invalid` | info, error | Result of `-check`. |
| `configuration_reloaded`, `configuration_rejected` | info, error | Result of SIGHUP. A rejected reload keeps the previous configuration. |
| `no_modules_enabled` | warn | No listener accepts data. |
| `gateway_stopping`, `gateway_stopped` | info, error | Shutdown. `gateway_stopped.reason` says why the process exits non-zero. |

`uplink_retry.stage` values: `dns_lookup_failed`, `connection_refused`, `connect_timeout`, `network_unreachable`,
`connect_failed`, `proxy_*` (the same, for the proxy), `proxy_connect_http_<status>`, `server_certificate_untrusted`,
`server_name_mismatch`, `server_certificate_invalid`, `tls_rejected_by_server`, `tls_handshake_failed`,
`http2_not_negotiated`, `http2_setup_failed`, `http_status_<status>`, `request_failed`,
`invalid_response_frame`, `trailing_response`, `stream_read_failed`, `stream_write_failed`, `invalid_ingest_url` and
`invalid_proxy_url`.

`gateway_stopped.reason` values: `configuration_invalid` (with `field` and `problem`), `identity_invalid` (with
`problem`), `clock_skew` (with `offsetSeconds`), `revoked`, `state_directory_locked`, `buffer_integrity`,
`permission_denied` (with `path`), `listen_failed` (with `address`), `file_error` and `internal`.

## Container and release verification

The scratch image runs as UID/GID 65532 with no shell. Provision a state directory owned by that user, mount configuration and customer TLS files read-only, and run with a read-only root filesystem, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, a memory/CPU limit and one writable state volume. Bind the module port only on the intended LAN interface; status is local. Do not expose a listener to the internet. For containers, bind the module inside the container to a non-loopback address and configure TLS; publishing a loopback-only container listener does not make it reachable through Docker port mapping.

GitHub Actions builds, scans, signs and publishes the immutable GHCR image with SBOM and provenance. Deploy a digest after verifying it against the exact authorized release identity:

```sh
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/1a11/clearintervals-edge/.github/workflows/release.yaml@refs/heads/main \
  ghcr.io/1a11/clearintervals-edgegateway@sha256:<approved-digest>
```

Check the image's revision label/provenance against the reviewed commit and inspect the scan and SBOM artifacts. Copy images together with signatures/attestations using `cosign copy` when mirroring internally. No automatic updates or mutable-tag deployment.
