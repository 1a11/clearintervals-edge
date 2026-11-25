# Public uplink v1

The normative schema is [`protocol/v1/uplink.proto`](../protocol/v1/uplink.proto).
This document defines bounds and encodings that protobuf alone cannot express.
The checked-in Go package is generated with protoc 7.35.1 and protoc-gen-go 1.36.12.
`make generate vectors` reproduces it using grpcio-tools 1.84.0. Vectors are verified
independently with Python protobuf, including the exact canonical bytes and SHA-256.

## Transport and identity

HTTP/2 on TCP and HTTP/3 on UDP use identical POST paths and semantics. TLS 1.3,
exact configured SNI, regional approved client issuers, P-256, digital-signature
key usage and the sole client-auth EKU are required. Session tickets, resumption
and 0-RTT are disabled. The client URI is exactly
`spiffe://clearintervals/{region}/gateway/{gatewayId}`, matching implemented core.
Region is configuration, never a caller-selected routing destination.

An absent client certificate is permitted only on `/challenge`, `/enroll`,
`/recover` and `/operations/result` below `/uplink/v1`. A presented certificate
must be currently valid even on those endpoints. Recovery supplies its expired
certificate in the message body. Renew, control, descriptors and data require the
actual TLS identity; headers and payload gateway IDs never substitute for it.

Before accepting a client identity at the handshake, cloud calls core `/admit`
with a two-second deadline and no positive fallback. Control calls admit again
and acquires a lease bound to a random physical-connection ID. All data calls use
that stored identity tuple. TCP source attribution is direct by default;
optional PROXY v2 accepts only a configured trusted internal peer CIDR.

## Frame bytes

Content type: `application/x-clearintervals-protobuf`. HTTP content encoding is
not supported. No query strings, escaped alternate paths or HTTP/1 application
requests are accepted. Every frame has this 13-byte header, followed by a
serialized `Frame`:

| Offset | Width | Meaning |
| --- | --- | --- |
| 0 | 1 | Flags: 0 raw protobuf, 1 zstd payload |
| 1 | 4 | Big-endian wire byte length |
| 5 | 4 | Big-endian decoded byte length |
| 9 | 4 | Big-endian item count; zero for non-batch frames |

Raw frames are at most 16 MiB. Zstd wire bytes are at most 4 MiB, decoded bytes
at most 16 MiB, expansion at most 20:1. Control and lifecycle frames are at most
32 KiB. Lengths and credit are checked before body allocation; zstd enforces
output capacity, window and memory limits during decoding. Declared lengths
and item count must exactly match the decoded message. Recursion is bounded
at 16; unknown protobuf fields at any nesting level, unsupported versions and
unknown request alternatives are refused. Frame version is always 1.

Once a frame starts, no-progress time is 10 seconds and total time is 30 seconds.
Initial Hello/OpenStream waits are 10 seconds; control idle waits are 180 seconds.
Unary lifecycle requests contain exactly one frame and end the HTTP request body.

IDs are 1–100 ASCII letters, digits, `_` or `-`. Session IDs come only from core;
epochs and request IDs are random client values. Generations and counters must
fit their stated bounds. At most 1,000 items occur in one batch. Hello carries
at most 8 protocols, 32 module names (100 bytes each), and 100 stream keys
(40–100 bytes each); version is 1–100 bytes.

## Conversations

Control starts with Hello, then receives Welcome or Failure. Hello must match the
TLS gateway and registered generation. Protocol 1 must appear in `protocols`.
Clock offset is measured at Hello; offset beyond one day is refused; core refuses
captures beyond 30 seconds. Times are never rewritten. Welcome only reports
unknown keys from the caller's own submitted list.

Control subsequently accepts Heartbeat or CreditRequest and replies once to each.
Heartbeat counters are bounded at 2^50 and rate-limited to 12/minute/gateway.
Heartbeats preserve the core version, transport, buffer/drop and ingest telemetry
contract. Lease refresh is independent, every 10 seconds, with a two-second
deadline; failure closes the connection. Three missed minute heartbeats end it.

Each data HTTP request starts with OpenStream. It names the control session,
generation, a never-reused epoch, and a kind matching the URL: captures, series or
events. Its first reply is Credit, representing StreamReady. Sixteen stream epochs
are allowed per session lifetime, including closed epochs; reconnect to reset.
Clients close drained data streams promptly to return their reserved cloud window,
while keeping control alive. Polling a closed epoch returns `invalid_session`;
reconnect with fresh epochs instead of waiting on zero credit forever. Bounded
server retry timing applies to capacity refusals and session recovery.

Closed control ends every data stream on that physical connection. The same source
address on another connection grants no access.

Credit fields are cumulative ceilings, never additive tokens. Debit decoded
protobuf bytes (excluding the 13-byte header) and item count before reading the
body. Every application retry consumes credit. OpenStream can receive zero;
CreditRequest on control can obtain capacity without sending data. Poll each epoch
at most every five seconds; earlier polls repeat its current ceiling. `last_grant`
cannot exceed the server's grant. A reply echoes request ID, session and epoch.
Processing never automatically increases the ceiling: poll to replenish it.
Polling a closed epoch grants nothing. Reconnect resets transport counters only.

Batch sequence starts at 1 and strictly increases by 1. Reusing a sequence aborts
the request without acknowledging any buffered data. Retry unresolved items with
the next sequence or a new connection, preserving item IDs/hashes and bindings.
Item index is its zero-based position. Validate the entire envelope before any
item is forwarded. Per-item core commits may partially succeed. An Ack echoes
session, epoch, sequence, index, stable ID and hash for every item. Its terminal
frontier advances only through contiguous fully terminal batches; after a gap it
stays conservative for the remainder of that stream. Explicit item outcomes are
authoritative; sequence alone never authorizes edge buffer deletion.

The cloud sends no application frame before an edge frame. It never pushes
bindings, source configuration, commands, raw data or unsolicited credit: the
stream descriptors in the next section are returned only as the reply to the
gateway's own `/uplink/v1/descriptors` request.

## Stream descriptors

A gateway enrolled from the product's download configuration starts with no
bindings. It learns the streams behind the configured PromQL by asking, and the
cloud answers only that request: `POST /uplink/v1/descriptors` carries one
`Lifecycle{gatewayId, operationId, generation, purpose: "descriptors"}` frame.
The body only proposes the gateway and generation; the certificate is the
identity, and a body naming another gateway or generation is refused.

The reply is a `Challenge` frame with `challenge: "descriptors-v1"`, `expiresAt`
set to core's confirmation time, and `signingPayload` holding a JSON object of at
most 65536 bytes:

```json
{"items": [{"id": "binding-…", "streamKey": "…", "sourceId": "dev-…",
            "kind": "series", "metric": "Temperature, °C",
            "selector": {"__name__": "vm_motor_temperature_celsius", "site": "north"},
            "scale": 1}]}
```

Each item describes one active binding: its immutable binding version, the
gateway-specific stream key, the canonical source, the kind, the reading name,
the exact-label selector it matches and the unit scale. Core decides what the
gateway may receive; the cloud never invents a descriptor. Requests are limited
to 30 per minute per gateway and refusals use the `session` lane. A gateway asks
once per connection and every 15 seconds while its session is open, so a stream
added in the product starts flowing without a restart.

## Record content and canonical hashes

`Item.hash` is SHA-256 of the deterministic protobuf encoding of `Record`:
domain `clearintervals-uplink-record-v1`, source ID, acquisition/delivery ID and
the exact typed capture/point/event payload. Emit fields in numeric order, no
unknown fields, omit default-valued scalar fields, use standard packed encoding
where applicable. This schema has no protobuf maps. Canonical vectors are in
[`vectors.json`](../protocol/v1/vectors.json). Keys, binding versions, credential,
session, index and retry fields are excluded. Hashes are checked before forwarding.

Source ID is the configured canonical device/channel ID; it must match the
gateway's immutable binding snapshot. For events it is the authenticated gateway
ID. Records contain no caller-selected organization, sensor, site or asset target.
Only core resolves that target and authorizes it at commit.

This public delivery hash and core's storage hash have different domains and
purposes. Core independently normalizes CaptureMeta and includes the resolved
target in its own hash, using `clearintervals-core-ingest-v1`. It alone determines
canonical duplicates and content conflicts, including across redundant gateways.
The adapter never treats the public hash as proof of a durable commit or overrides
core's hash. Ack echoes the public hash so the edge can match its buffered item.

Capture metadata is a JSON object using core's public CaptureMeta camelCase names.
It is at most 16,384 bytes and uses the exact compact sorted-key encoding produced
by Go `encoding/json.Marshal` on the decoded object: UTF-8, no whitespace, finite
numbers, shortest Go float64 representation, Go JSON string/HTML escaping.
Cross-language clients must reproduce this encoding; the capture vector is a
normative example. The capture ID equals the stable item ID. `axes` is a nonempty
unique ordered subset of x/y/z, tier M/I, count 2–1,000,000, positive fsNominalHz,
duration at most 120 seconds. Samples are finite IEEE-754 float32 little-endian,
axis-major, exactly `4 * count * len(axes)` bytes. Missing axes are never fabricated.
Core receives uint32-LE header length, its exact JSON header, then those bytes.

Series Point timestamps and capture start times use canonical UTC RFC3339Nano
(`Z`, no redundant trailing fractional zeroes); values are finite float64 and
negative zero is refused for points. Core supplies metric bounds and age policy
and returns one result for each independently submitted point.

Event kinds are source_unreachable, buffer_full, module_error, clock_skew and
update_required; count is at most 2^50. Event IDs are stable. Events carry no
stream key or binding ID. Core enforces its persisted per-gateway event rate.

## Lifecycle and signing transcript

Lifecycle carries gateway ID, operation ID, expected generation and a signed
P-256 CSR. Enroll adds the one-time token; renew uses the actual TLS fingerprint;
recover includes the expired leaf and old-key signature; result retrieval includes
the new-key signature. The active issuer is selected only from server configuration.
Cloud reserves the exact operation in core, verifies the returned identity, signs
that CSR, and commits the signed certificate to core before replying. A lost commit
reply is unresolved. Replaying a spent token returns result_proof_required; it
does not disclose a certificate. Result retrieval performs no signing.

Challenge returns a 60-second one-use core challenge and exact signing bytes.
The normative signing bytes are the compact ASCII JSON array:

`["clearintervals-core-proof-v1", challenge, gatewayId, region, purpose, operationId, expectedGeneration, csrHashHex, oldFingerprintOrNull]`

The protobuf Challenge encloses these bytes without re-encoding. Purpose is
`recover` or `result`, selecting the endpoint; result uses null fingerprint.
Verify the array's tuple against local intent before signing with ECDSA P-256/
SHA-256, DER signature. Core receives base64 of the DER signature. CSR hash is
SHA-256 of DER CSR bytes. This explicitly adopts implemented core's proof format
in place of the earlier proposed protobuf signing transcript; signatures cannot
be translated between formats by the cloud without the edge's private key.
Core atomically verifies/consumes challenges with operation admission and binds
proofs to current registered keys/generations. Never log these payloads or tokens.

## Outcomes

| Result/code | Outcome and edge action |
| --- | --- |
| Explicit core accepted | ACCEPTED; persist matched result, reclaim item |
| Explicit core duplicate | DUPLICATE; persist matched result, reclaim item |
| content_conflict, suspended_period, binding_revoked, unknown_stream_key, site_not_eligible, timestamp_out_of_range, invalid_value, invalid_timestamp, invalid_metadata, invalid_samples, invalid_batch, profile_required, invalid_binding, invalid_frame | REJECTED_PERMANENT only after explicit validation/core result; persist matched result, reclaim item |
| Current suspension/inactive entitlement, clock_skew, stale_policy, rate_limited, core outage/timeout, invalid/expired session, revoked, server_draining | RETRY_LATER or stream Failure; retain item |
| Unknown core code/outcome, malformed response, transport failure, missing result | RETRY_LATER or no Ack; retain item |
| credit_exceeded, protocol abort, update_required, lifecycle errors | Failure; no item acknowledged |

Retry delay defaults to five seconds. A binding absent from a potentially stale
snapshot is retryable; a known gateway/key/source mismatch is refused before any
duplicate lookup. HTTP status alone never establishes an item outcome.

## Fleet acceptance

`integration/fixture.py --sensors 5000 --drain-seconds 600` drives 5,000 barrier-released sensor clients in three
rounds through 50 production edge processes, one production cloud process and real core services/TimescaleDB.
Distinct local CONNECT egress addresses preserve production enrollment limits. Values are valid 20–30 °C points;
acceptance checks 15,000 durable points, 5,000 source identities, an independent value checksum, empty edge queues,
zero permanent rejection/integrity alarms, and cloud process telemetry reflecting committed outcomes. Local
backpressure retries are counted. `--observe-seconds 45` additionally grants the disposable fixture's Robin account
operator access and holds the fleet for admin screenshots; `build/performance-target.json` contains only its local
web URL. All fixture processes, test PKI and its uniquely named database are removed afterward.

For higher stress, `--sensors 10000 --stress` starts 100 real edge gateways, shards sensor writers into processes
of at most 5,000 clients behind a shared burst barrier, then offers sustained plateaus at 16, 32, 64, … records/s.
A plateau keeps up only if at least 95% of offered points are durably committed by its end and no ingress fails.
The first backlog-growing plateau bounds the measured throughput; the last passing rate is repeated for three
minutes. Each stage records ingress latency, backlog, cloud telemetry and resource use in `<output>.stress.json`.
The test waits for recovery rather than interpreting a durable local queue's 204 response as a core commit.
The optional sensor bound is 50,000; larger counts require sufficient runner resources and multiple generators.
Production limits remain: 100 mappings per edge, 256 concurrent controls per organization, 1,024 connections per
cloud instance. Those are configured connection ceilings, not sustainable record rates.

### Capability negotiation

`Hello.modules` may include `flow-control-v1`. Only when advertised does a new
server send `Welcome.capabilities` (field 7). `frame-budget-v1` means idle credit
reserves no frame memory, so the edge keeps data streams open when the queue
empties. Without this capability, drained streams close to return older servers'
reservations. Strict unknown-field rejection remains enabled and older clients
receive no new fields. `stream-reopen-v1` permits `stream_closed` for a known
closed epoch; the edge reopens data while retaining control. Unknown epochs still
return `invalid_session`. All replay keeps original semantic identities.
