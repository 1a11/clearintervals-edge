# Edge gateway design

The design contract for the edge gateway: what it accepts, how it holds data and
identity, and what it promises about the uplink. The cloud side of the protocol
is summarised in [`protocol-v1.md`](protocol-v1.md). How to run the gateway is in
[`operations.md`](operations.md), and the executed checks are in
[`verification.md`](verification.md).

Terms: **core** is the Clear Intervals analysis platform behind the cloud gateway; the **product** is its web
application, where admins issue licences and create bindings.

## What it is

A Docker container the customer runs on their own infrastructure. It receives data from the customer's own systems
on the LAN, keeps it on local disk until the cloud has it, and streams it out to the Clear Intervals cloud gateway.
It opens no port to the internet. The cloud only replies to what the edge gateway sends: it never sends data and
never sends commands.

It is an extendable sink: a small core plus **sink modules**. Each module speaks the native write protocol of one
kind of customer system, so integrating is "point your existing agent at this address". The first module is
VictoriaMetrics (Prometheus remote write).

The edge gateway needs an active entitlement for the organization. Without it, it enrolls nothing and the cloud
accepts nothing from it.

```
 customer LAN                                       internet               Clear Intervals (one region)
┌───────────────────────────────────────────┐                        ┌───────────────────────────────┐
│ vmagent / Prometheus ─remote write─┐      │                        │                               │
│ vibration DAQ ───────(module)──────┤      │  HTTP/3 (UDP 443)      │  cloud gateway ──internal──▶  │
│                                    ▼      │  or HTTP/2 (TCP 443),  │       │           ingest API  │
│              edge gateway: modules → buffer → uplink ═══ mTLS ═══▶ │       │              core     │
│              (state volume: key, cert, buffer)    outbound only    │  ◀── replies only (acks/errors) │
└───────────────────────────────────────────┘                        └───────────────────────────────┘
```


## What data it carries, and what core does with it

Core has one analysis today: vibration monitoring of **raw waveform captures** (`POST /v1/sensors/{id}/captures`,
tiers M and I for mounted accelerometers, 3 × 30 s per measuring session, every 6 h by default). Everything the edge
gateway forwards falls into one of two kinds, and only the first feeds that analysis:

| Kind | Example sources | Rate | What core does with it |
|---|---|---|---|
| **Captures** (waveforms) | Mounted IEPE/MEMS accelerometers through a DAQ or a vendor gateway | 10–50 kHz per channel, cut into bounded captures | Analysed today (quality, features, health, RUL, diagnoses, alerts). |
| **Context series** (scalars) | VictoriaMetrics/Prometheus: speed, load, running state, run-hours, temperatures, overall velocity RMS from transmitters | Every 1–60 s | Stored as bound operating context; can fill missing speed/load/running declarations when core accepts a capture. Scalars alone do not invoke waveform DSP. |

Why the difference matters. Vibration diagnosis needs a waveform; scalar measurements alone cannot supply a spectrum. Core stores bound context series and can use values at capture time to fill missing `rpmDeclared`, `loadPct` and `operatingStateDeclared` fields.

Continuous waveform capability is currently limited to a persistent upload of completed captures. One triaxial channel at 25.6 kHz in float32 produces 307.2 KB/s, or 3.072 MB per ten-second window. The native module reads that entire window before enqueueing it. A chunked HTTP request and a QUIC connection do not remove this application boundary. Core's daily-byte, pending-capture and raw-storage limits still apply. Forwarding small sample blocks immediately and assembling DSP windows asynchronously requires a separate protocol/storage extension; vendor DAQ adapters and automatic ADC window cutting remain future work.

Only bound data leaves the site. A customer's VictoriaMetrics holds far more than machine data (hostnames, users,
business metrics). The edge gateway forwards only series and channels listed in its local bindings. Everything else
is dropped at the module and counted, never buffered or sent. The cloud rejects any binding the product does not
know.


## Sink modules

A module is the receiving end of a customer system's write path. Every module:

- Implements only the **write API** of its source, never its query API or storage engine. A module is not a
  database: it accepts, validates, filters, maps and hands over to the buffer, nothing more.
- For accepted mapped records, answers the writer only after data and its binding version are durable in the
  buffer: success after fsync, `429`/`503` with `Retry-After` for temporary capacity/draining errors, `400` for
  invalid input. Deliberately filtered records and suspension drops are explicit exceptions: success means
  discarded under the configured policy, with durable aggregate drop counters, never durable record storage.
  Authenticate and validate bounded input before applying either exception. Document each writer protocol's
  retry behavior and do not return a terminal response for a temporary failure.
- Authenticates every writer and authorizes its binding/source allowlist before buffering (see "Local API security").
- Drops unmapped data at the door and keeps per-reason counters: unmapped, invalid, too old, too large.
- Converts to core's units and identifiers (m/s² and UTC; the binding's stream key) and stamps each record with the
  source's own timestamp, never the arrival time.
- Has bounded memory: a fixed request size, a fixed number of concurrent writers, a fixed queue.

### v1: VictoriaMetrics / Prometheus remote write

- A VictoriaMetrics database does not push. `vmagent` does, and so do Prometheus, Grafana Alloy and the
  OpenTelemetry Collector. All of them speak **Prometheus remote write 1.0** (protobuf, snappy). One module covers
  all of them; there is no separate Prometheus module.
- Accept remote write 1.0. Accept VictoriaMetrics' zstd variant where vmagent negotiates it. Remote write 2.0 later.
- Customer setup: one extra `remoteWrite.url` in vmagent (or `remote_write` in Prometheus) pointing at the edge
  gateway, with the credentials below. Their existing pipeline is untouched.
- Later, for customers who cannot touch their agents: a pull mode reading VictoriaMetrics' export API on a
  schedule. Not in v1.

### Native captures and future vendor adapters

The native HTTP capture source is implemented; see `docs/operations.md`. Vendor-specific DAQ adapters remain future work. The edge gateway is a **universal
platform**: no vendor or protocol is built into its core, and the module contract is the only interface a source
gets. Which capture module ships first (a DAQ file drop such as WAV/UFF/CSV, a vendor gateway, OPC UA, ...) is
decided later. Every capture module meets the contract above, plus:

- The module cuts captures that meet core's limits: at most 1,000,000 samples per axis and 120 s
  (`MAX_CAPTURE_SAMPLES`, `MAX_CAPTURE_SECONDS`). That is ~39 s at 25.6 kHz, ~19 s at 51.2 kHz.
- It reports the instrument per capture: tier, range, flat band, nominal rate, noise floor, mount.
- Captures get a **deterministic `captureId`** derived from the canonical device/channel identity, acquisition
  identity and capture start time, never the gateway identity. Persist it with the immutable binding version.
  Authorized redundant gateways use the same canonical source identity and acquisition boundaries (see
  "Configuration" and [`protocol-v1.md`](protocol-v1.md)). Conflicting content is rejected, never silently overwritten.

### How modules are built

One image per release contains the core and every module that passed review; configuration turns modules on. This
replaces "a build per combination of modules", which multiplies images to sign, scan and support, and makes adding
a source a re-pull instead of a config change. If the image grows too large, split it into a few flavours, not one
build per combination. Modules are never loaded at runtime from disk or the network.


## Identity, licence and credentials

### What the licence is

The licence file is a **one-time enrollment bundle**, created in the product by an admin for one gateway. It holds:

| Field | |
|---|---|
| `formatVersion` | Licence format. |
| `gatewayId`, `credentialGeneration` | The gateway record and expected pending credential generation in core. |
| `region`, `ingestUrl` | The deployment it belongs to (e.g. `ru`, `https://ingest.clearintervals.com`). A gateway works only with its own region (data residency). |
| `trustAnchors` | The Clear Intervals ingest root CA certificate(s). The edge gateway trusts only these for the cloud, never the system store. |
| `enrollmentToken` | 256 random bits, single use. Core stores only its hash. |
| `expiresAt` | When the token stops working (default 7 days after issue). |
| `streamBindings` | Optional roster of authorized bindings: `id`, `kind`, `deviceId`, `sensorId`, `assetId` and `keyDigest` (hex SHA-256 of the stream key). When present and non-empty, a configured binding outside the roster is fatal and a digest mismatch is a loud warning; a rotated licence refreshes the roster. Older licences omit it. A download configuration starts with no bindings and an empty roster: after enrollment the gateway requests the stream descriptors for its promql from the cloud and installs them itself. |

It is not "Application Default Credentials": that is Google Cloud's way of finding credentials and has nothing to
do with this system. From the NHI Management Group's guidance on non-human identities we take the principles: one
identity per workload, with an owner; short-lived credentials and no shared long-lived secret; automatic rotation;
immediate revocation; an inventory; every lifecycle event in the audit log.

The licence is **not** the tenant boundary. Tenant isolation is enforced in the cloud: the authenticated certificate
names a gateway, and the cloud derives the organization, sites and sensors from core's registry. It never takes them
from anything the edge gateway sends.

### Enrollment and crash-safe credential operations (G01, G03)

1. With a licence and empty state, generate a new ECDSA P-256 key. Persist and fsync the pending key, operation ID,
   gateway/region, expected credential generation and CSR SHA-256 hash **before** sending an enrollment request.
2. Verify the cloud hostname and licence trust anchors. Submit token, operation ID and signed CSR. The cloud
   constructs identity and extensions from its registry, never arbitrary CSR fields.
3. Issuance atomically consumes the token, activates one credential generation and records a replayable result in
   core. The cloud gateway owns locking, proof and result retention.
4. Validate the returned chain, identity, key and lifetime. Fsync a generation-specific key/certificate bundle,
   atomically switch the active manifest, and fsync its parent directory before clearing pending state. A restart
   resumes the pending operation; it never generates a replacement CSR for a committed operation.
5. If the response is lost, retrieve the **same** operation result using a fresh cloud challenge signed by the
   persisted new key. A spent token is never reused to issue another certificate. Delete the licence after the
   active bundle is durable. Redact the token throughout.

### Rotation

- Renew at half the 24 h certificate lifetime, with a new key and the same pending-operation journal procedure.
- The previous serial may carry data for at most a 5 min overlap. It cannot start another credential operation
  after the new generation commits. At overlap end the cloud closes all connections authenticated by the old
  serial, including existing sessions. The edge reconnects with the new key; normal idempotency covers retries.
- Lost renewal/recovery responses use result retrieval, not a new issuance attempt using the old credential.

### Outages longer than the certificate

Recovery is available only for the **current, unsuperseded** certificate/generation, expired by no more than the
organization's grace window (default 7 days), using server time. Revocation, re-licensing or replacement prevents
old credentials from recovering. The endpoint verifies the issuing chain, client profile, exact regional identity,
current registry generation and registered certificate fingerprint/public key, organization state and entitlement. Only this verifier may relax leaf expiry; ordinary
TLS validation never accepts expired certificates.

The edge requests a one-use challenge and signs the bound recovery transcript with its old key; the new CSR proves
possession of the new key. The transcript is defined in [`protocol-v1.md`](protocol-v1.md). Beyond grace, an admin issues a new
licence for the same gateway ID. Buffered records retain their original identities and binding versions.

### Revocation and admission (G02)

- Operators and customer admins may revoke. New authenticated admissions use a fresh core check; a revocation
  committed before that check is refused. A check already in flight does not authorize future writes: core checks
  current policy transactionally at each commit. If core cannot answer within 2 s, admission fails closed.
- Core's change feed is polled every 5 s. Within 30 s of revocation all live sessions close. Missing feed progress
  beyond 30 s closes affected sessions; startup and feed gaps require a fresh snapshot. TLS resumption is disabled
  in v1 so it cannot bypass admission checks. Old-serial sessions close at the rotation overlap deadline.
- `revoked` is terminal: retain the customer's buffer and stop sending; exit non-zero on restart. A TLS/network
  failure alone is not evidence of revocation or suspension. Do not change collection policy on unauthenticated
  error text. Lifecycle replies and data results must come over the verified cloud TLS connection.

### Frozen organization (G04)

Freezing immediately stops **cloud acceptance** through core's transactional checks. An online edge stops local
collection after receiving an authenticated `organization_suspended` reply (normally by its next 60 s heartbeat,
subject to connectivity). A disconnected customer-controlled host cannot be made to stop collecting remotely.
Offline buffering remains supported; there is no promise of an offline one-minute collection stop.

- Persist the known suspended state before acknowledging new policy-dropped input. While known suspended, modules
  discard authenticated input and return success with reason `suspended`, keeping durable aggregate counters. This
  is the explicit deliberate-drop exception to the module durability contract.
- Keep eligible pre-freeze backlog within age/size limits. During current suspension, cloud refusal is `retry_later`:
  it does not acknowledge or delete backlog. Recheck status with jittered backoff capped at 15 min; resume only on
  an authenticated active-state reply. Control/status replies remain available to an otherwise valid suspended
  identity without authorizing data or issuance; if its certificate expired, recovery can return the authenticated
  suspension refusal. Do not infer unfreezing merely from transport success or the absence of an error.
- Core retains suspension intervals and rejects record event times in those intervals even after unfreezing.
  Captures overlapping an interval are terminally rejected as `suspended_period`; discard only after the matching
  per-item terminal result. Buffered records from outside the interval remain eligible under current policy.
- This is event-time enforcement using customer-supplied timestamps, not proof of physical collection time. A
  malicious source can falsify timestamps; this design does not claim to stop collection on a compromised host.
  A future bounded collection lease would change offline availability and requires a separate product decision.

### Key storage

Keys, pending-operation journal and active manifest are mode 0600; their directory is mode 0700, owned by the
container user. Keys never leave the customer's state volume. Keep keys and tokens out of crash dumps and logs.
Reserve disk capacity for renewal even when data quotas are exhausted. TPM 2.0 / PKCS#11 is a later option.

### Clones

A copied state volume shares an identity. Core grants one session lease per gateway ID regardless of source address;
a second control session is refused and audited. HTTP/3 NAT migration preserves the same session. Rotation removes
the losing old credential at overlap end, but does not identify which copy is legitimate: an attacker possessing
the current key can race the legitimate edge. Investigate duplicate-session alerts and re-license or revoke when
compromise is suspected. Superseded credentials cannot use recovery to return.

### Trust maintenance

Persist trusted ingest roots independently of the disposable enrollment licence. Normal intermediate rollover
uses cloud's approved current/retiring issuer overlap and does not change this root trust. Root changes require a
customer-installed, verified configuration/image update with an overlap period; never accept a replacement root
from an arbitrary TLS reply. CA compromise is handled by the operator's PKI incident procedure.

### Entitlement

Identity and entitlement are separate. A valid certificate proves which gateway it is; the entitlement decides
whether it may send. The cloud checks the entitlement when a licence is issued, at enrollment, at renewal, when a
session opens and for every stream key. When it lapses the cloud refuses with `entitlement_inactive`. The edge
gateway keeps buffering, shows the reason, and retries with backoff (at most every 15 min).

The gateway is not offered for sites in jurisdictions that require certified (national-standard) cryptography;
bindings to such sites are refused in the product.

## Uplink

The wire protocol is specified in [`protocol-v1.md`](protocol-v1.md). On this side:

- **Outbound only**: UDP 443 and TCP 443 to `ingestUrl`. Nothing listens towards the internet.
- **HTTP/3 over QUIC first, HTTP/2 over TLS/TCP as automatic fallback.** OT and corporate networks often block
  outbound UDP, and HTTP proxies cannot carry QUIC. QUIC-only would make the product unusable for many customers.
  Fallback is automatic (QUIC handshake fails or stalls → TCP) and is retried towards QUIC every 30 min. The
  messages are the same on both.
- `HTTPS_PROXY` (CONNECT) is supported, TCP only. The proxy sees only the TLS stream; mTLS stays end to end. Proxies
  that intercept TLS break mTLS and are not supported: the customer must exempt `ingestUrl`.
- **Mutual TLS**: TLS 1.3 only. The client certificate from enrollment; the server verified against the licence's
  trust anchors and its host name. No QUIC 0-RTT (it is replayable).
- **Streamed**: one control stream and multiplexed data requests on the same authenticated connection. Every data
  request carries the control session ID and credential generation. Batches have stable item IDs, payload hashes,
  stream epochs and sequence numbers. Terminal outcomes are `accepted`, `duplicate` or `rejected_permanent`;
  `retry_later` and unknown outcomes stay in the buffer. A cumulative acknowledgment never deletes unresolved items.
  [`protocol-v1.md`](protocol-v1.md) defines persistence, acknowledgment scope and retry behavior. Local buffer
  eviction/expiry and explicit suspension drops remain counted exceptions; delivery is not an unlimited lossless guarantee.
- **Backpressure**: open each stream with a zero-payload `OpenStream` request to obtain initial credit. At zero
  credit send bounded `CreditRequest` control messages, answered even when data capacity is zero. Control has its
  own budget. Grants are cumulative per session/stream epoch; reconnect invalidates them. Never send data without
  byte and item credit; see [`protocol-v1.md`](protocol-v1.md) for accounting. A stalled stream retains its records on disk.
- **Replies only.** The cloud never starts a message and never sends a command or any data. Everything that comes
  back answers something the edge gateway sent:
  - results and credits for batches, `OpenStream` and client-originated `CreditRequest`;
  - per-item results and error codes;
  - the answer to `Hello`: protocol version, limits, clock offset.

  Bindings and capture schedules are local configuration, never pushed. Revocation, lapsed entitlement or a draining
  server reach the edge gateway as error codes on its next request, or as a stream aborted with that code. Customer
  data never flows back (core's rule: no raw-data export).
- **Clock**: the host must run NTP. The answer to `Hello` gives the clock offset, lifecycle requests carry the
  sender clock, and the edge compares the ingest `Date` header at startup and hourly. Past 2 s the edge gateway
  logs `ntp_drift`; past 30 s it logs `clock_skew` and raises an alarm, and the cloud refuses captures (timestamps
  are the analysis). A first start more than 60 s off stops with `gateway_stopped reason=clock_skew` before
  enrolling.


## Local buffer (store and forward)

- On disk in the state volume: append-only segments per stream, fsync before a writer is answered. It survives
  restarts and crashes.
- Bounded by size (default 10 GiB) and age (default 7 days). Both are configurable, but the age cannot exceed
  core's authorized maximum record age. Recovery grace and record retention are independently enforced policies.
- When full: context series drop the oldest first; captures refuse new ones (the source keeps them and retries).
  Every drop is counted and reported to the cloud, and the product shows it.
- Records retain source event time, immutable binding version, canonical ID, payload hash and stable delivery ID.
  SIGHUP never rewrites queued targets. Schedule separate live/backlog lanes with a bounded fair share; oldest first
  within each lane, transport order per stream. Deduplication and analysis must tolerate out-of-event-time arrival.
- Segments have checksums and explicit lengths; recover only complete fsynced records, quarantine corrupt segments
  and surface an integrity alarm. Fsync file creation/rename parent directories. Persist terminal results and
  cursor changes before segment reclamation. Unknown outcomes survive restart for retry.
- Give captures, context, events and identity metadata separate quotas within the total disk budget; reserve
  identity/journal space and a minimum capture share. ENOSPC returns a temporary writer error for otherwise
  acceptable records, never a false durable success. Explicit eviction/age expiry is counted and reported.
- Not encrypted at rest by default: the key would sit on the same volume. It holds the customer's own data on the
  customer's own disk; protect it like the source database.


## Concurrency and resources

Unbounded workers are a denial-of-service vector: a writer that opens many streams must not make the gateway grow
until the host runs out of memory. The work is mostly I/O, which a small fixed set of workers handles well into
thousands of connections. The rules:

- A **fixed** number of workers (default: the CPU count, configurable), each an async event loop.
- CPU-heavy steps (decompression, protobuf decoding, cutting captures, compression for the uplink) go to a
  **bounded** process pool. Never one process per stream.
- Many logical streams share **one** uplink connection (QUIC and HTTP/2 multiplex). A cap on concurrent streams per
  connection; past it streams queue in the buffer.
- Every queue, request size, writer count and stream count has a limit with a documented default.
- Targets (to be measured, not promised): idle under 100 MB RSS; 1 vCPU sustains 100k samples/s of context series.


## Local API security (G05)

- Module listeners default to disabled. TLS 1.2 or newer (prefer 1.3) is required on every non-loopback listener;
  reject non-loopback plaintext configuration in v1. Loopback is for same-host trusted writers only. Customer LAN
  mTLS is supported against an explicitly configured writer CA with client-auth profiles.
- Each writer has a distinct local principal. It authenticates with a customer-generated 256-bit bearer token,
  basic auth using a generated high-entropy password, or LAN mTLS. Store token digests; hash passwords with a
  salted Argon2id profile benchmarked to a bounded authentication worker pool. Verify secrets in constant time.
  Certificate writer identities map to explicit principals, not arbitrary certificate subjects from another CA.
- Give each principal an allowlist of source selectors and immutable binding versions; reject submissions outside
  it before buffering even if their labels match another writer's valid source. Rotate/revoke credentials by
  atomic configuration reload; any optional overlap is explicit and bounded, and sessions are rechecked on reload.
- Defaults per module: 4 MiB compressed request, 16 MiB decoded, expansion ratio <=20, 16 concurrent writers,
  64 queued requests, 30 s total request deadline and 10 s no-progress deadline. Bound protobuf nesting, series,
  labels and string lengths in the module schema before implementation. Streaming decompression enforces limits
  while decoding snappy or zstd. Reject declared oversized bodies before allocation; authenticate before decoding.
- Defaults: 10 failed auth attempts/minute per source and 100/minute globally per module, bounded auth workers,
  capped metric cardinality and rate-limited audit events. Capacity is also global across enabled modules.
- `/healthz` and `/metrics` bind to 127.0.0.1 by default and expose bounded counters only. Any non-loopback status
  listener requires TLS and a separate read-only monitoring principal. No admin API; configuration is local.
- Logs, metrics, errors and dumps never contain sample/label values, authorization headers, tokens, stream keys,
  private keys or proxy credentials. Use stable reason enums and bounded field lengths, not client values as labels.

## Configuration

File (YAML) with environment overrides. The keys that matter:

| Key | |
|---|---|
| `deploymentLicensePath` | Licence file, needed only until enrollment succeeds. |
| `stateDir` | The state volume: key, certificate, buffer, cursor. Must persist. |
| `buffer.maxBytes`, `buffer.maxAgeDays` | Buffer limits. |
| `modules.<name>.*` | Enable, listen address, writer credentials, TLS. |
| `uplink.proxy` | Or `HTTPS_PROXY`. |
| `uplink.forceTcp` | Skip QUIC (for networks known to block UDP). |
| `bindings` | Source selector → immutable binding ID/version, gateway-specific stream key, canonical source/channel ID and kind; writer principal allowlist. |
| `captures.schedule` | Per bound channel: how often and how many (default every 6 h, 3 × 30 s, core's session model). Optionally only while a bound running-state series says the machine runs. |

Bindings and schedules are set on the edge gateway because the cloud never pushes anything. The admin makes the
binding in the product. The product creates a **stream key** for the sensor or asset and shows it once; the
customer puts it in `bindings`. The binding key file also carries the `gatewayId` it was issued for, so a file
copied between gateways is caught at production time. The cloud accepts a stream key only from the gateway it was
made for and rejects any other. This prevents foreign-gateway and cross-tenant routing. Selecting another valid
key on the same gateway can still map the wrong physical source: provide a local dry-run preview of selector,
principal, units and target references without exposing measurement values. Changing a target creates a new
binding version/key; versions are never repointed or reused. Editing and reloading (`SIGHUP`) applies atomically
only to future records.

Authorized redundancy uses a product-managed group of distinct gateways and a canonical device/channel identity.
Each gateway has its own certificate, session and binding key; shared identity/key configuration is rejected.
Acquisition IDs and capture boundaries must match across the group. Core resolves each key to the same canonical
source and deduplicates independently of gateway and stream key. Key rotation for the same immutable target may
drain old versions for at most the authorized buffer age; explicit deletion/compromise revokes immediately.
Current site scope/eligibility is always checked, including device moves.

Consequence: the product's "measure now" and its scheduled sessions (`autoSessionHours`) do not reach sensors behind
an edge gateway. Their schedule lives in `captures.schedule`, and the product says so on those sensors.


## Container and supply chain

- Runs as a non-root user with a read-only root filesystem; one writable volume (`stateDir`); no capabilities; a
  minimal base image without a shell.
- Images are built in GitHub Actions, scanned, signed (Sigstore cosign) with an SBOM attached, and published
  **publicly on GitHub's container registry** (ghcr.io), by digest. The customer docs show how to verify the
  signature against the documented release workflow identity, OIDC issuer and repository, not just any valid
  signature. Pin build actions/dependencies, attach provenance and an SBOM, and publish a vulnerability response
  policy with supported versions and security advisories. The image holds no secrets or customer configuration.
- Customers may copy the image into their internal registry. They copy it by digest together with its signature and
  SBOM (`cosign copy`), so verification still works there, and deploy the digest, never a mutable tag.
- **No automatic updates.** OT sites run change control. The cloud's answer to `Hello` says which protocol versions
  it accepts. It supports the previous one for at least 6 months. An outdated edge gateway shows "update required" before it is
  cut off. A critical security advisory may require an earlier cutoff: publish the affected versions, reason,
  patched digest and deadline through the product and release channel, and record the operator decision. Do not
  silently weaken authentication to keep an unsafe version online.
- Logs are structured JSON on stdout with bounded IDs, counts and reason enums, with the redaction rules above.
- Redundancy requires distinct gateways in an authorized redundancy group, as defined in "Configuration"; retries
  and group members deduplicate by canonical source identity, never by sharing a gateway's credentials.


## Status in the product

Every session sends a heartbeat (each minute) the product shows per gateway: connected or last seen, version,
transport (QUIC or TCP), certificate expiry, buffer depth and age, drops by reason (including `suspended`),
mapping errors, clock offset.
Core raises updates when a gateway is offline, near the end of its recovery window, or dropping data. Core's update
texts already end with "Check the sensor's gateway and its network".


## Security acceptance gates

These requirements answer the design review findings G01–G10. They state what must be demonstrated; executed
results are recorded in [`verification.md`](verification.md).

| Finding | Required acceptance evidence |
|---|---|
| G01 recovery | Superseded/re-licensed/foreign/compromised certificates cannot recover; reject replay, CSR substitution, CA/foreign SAN and wrong-region proofs; unchanged registry on failure. |
| G02 revocation | Revoke immediately after a feed refresh; fresh admissions refuse, live sessions close <=30 s; empty/stale/gapped caches fail closed; old connections close at overlap; resumption is off. |
| G03 lifecycle durability | Inject crashes and lost replies at reservation/signing/commit/local-key/manifest boundaries; exact retries retrieve one result; mismatched CSR and concurrent issuance fail; revoke/re-licence cancels outstanding operations. |
| G04 suspension | Offline freeze/unfreeze, persisted suspended restart, spanning capture and core outage preserve eligible backlog, reject suspended event times and expose deliberate drop counters; no unauthenticated policy transitions. |
| G05 local security | Reject non-loopback plaintext and unauthorized writer bindings; enforce rotation, token/password handling, snappy/zstd limits and bounded authentication work. |
| G06 isolation | Exercise slow pre-SNI TCP, distributed pre-auth attempts, QUIC validation, proxy-source spoofing, slow partial frames and authenticated over-credit input; satisfy recorded web/DB/memory/fairness budgets. |
| G07 delivery | Partial commit plus lost Ack/restart has one durable effect; retryable failures retain data; stale/mismatched Acks cannot reclaim it; changed hashes conflict; atomic enqueue has no duplicate side effects. |
| G08 credit progress | Zero initial/exhausted credit resumes after capacity returns through client polling; lost/repeated grants cannot double allowance; reconnect isolates epochs; control remains available. |
| G09 redundancy | Distinct authorized identities/keys for one canonical source deduplicate captures and points, differing content conflicts, unauthorized identity fails before duplicate lookup. |
| G10 binding history | Queue then retarget/rotate/move/delete/change scope/site eligibility; old records never silently change destination; current commit-time policy wins races. |

Additional gates: normal/emergency issuer and root rollover with offline gateways; torn/corrupt segments and ENOSPC
during renewal; signature/provenance verification against the authorized release workflow; bounded redacted logs;
public internal-ingest reachability rejection and wrong-service mTLS rejection. Add normative protobuf schemas,
canonical encoding/hash vectors and an error/outcome matrix before implementing the protocol. Record measured
limits, dependency scans and failure-injection results; unresolved failures block a production release.
