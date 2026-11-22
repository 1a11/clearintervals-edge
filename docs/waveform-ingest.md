# Native waveform ingest

Enable `modules.captures` with a dedicated listener (default
`127.0.0.1:8430`) and writer principals. Its TLS and bearer, mTLS or Argon2id
password authentication rules match remote write. Public listeners require TLS.
Both sinks share a two-worker password verification limit and bounded failed-auth
rate limits. Bindings have `kind: captures`, a canonical source ID, immutable
binding ID, stream key and authorized principal IDs. Captures do not accept
remote-write selectors or a scale factor.

POST `/api/v1/captures/{bindingId}` with `Content-Type: application/octet-stream`
and authenticated writer credentials. The body is:

1. Four bytes, unsigned little-endian metadata header length (1–16,384).
2. That many UTF-8 JSON bytes: `{"metadata":{...},"count":256000}`.
3. Exactly `count * axes.length * 4` axis-major little-endian float32 bytes.

Metadata uses the existing capture contract, including `captureId`, `tier` M or I,
`axes`, `fsNominalHz`, and canonical UTC `startTimeUtc`, with other product context
as applicable. The ID must stay identical on retries of the same acquisition.
The edge supplies source, stream key and binding from trusted configuration;
writers cannot replace them in the request header. NaN, infinity, incorrect
lengths, invalid metadata and unsupported content encodings are rejected.
Samples are never rescaled or downsampled. A finite capture supports at most
1,000,000 samples per axis, three axes, 12,000,000 sample bytes and 120 seconds.

A `202 {"captureId":"...","status":"queued"}` means the capture has been
fsync'd to the edge's durable queue. It does not mean cloud storage, DSP or fault
assessment has completed. A retry after a lost response uses the same ID and
payload; core idempotency prevents duplicate measurements. A full, suspended or
revoked edge returns a retryable failure instead of acknowledging discarded data.
There are two active upload slots, acquired before reading or allocating bodies.
A rejected writer consumes no waveform memory. Reads have a 10-second progress
and 30-second whole-request deadline. These bounds are deliberate backpressure;
clients must honor `Retry-After` and retain unacknowledged acquisitions.

The uplink shares immutable sample payloads instead of cloning them, and a bounded
16 MiB/eight-segment cache avoids repeated payload decoding during credit waits.
Every cache hit still streams and verifies the complete on-disk checksum.
`NextBatch` combines independent queue segments up to an 8 MiB target / 128 items
while retaining each segment's original receipt identity. A larger legal first
capture travels alone. This amortizes WAN round trips without changing record
hashes, quota policies or durable replay semantics.

The finite endpoint accepts completed waveform windows. The persistent endpoint
below adds window framing, progress timeouts, per-window durable acknowledgments
and reconnect/replay semantics. Direct interleaved ADC chunks require a separate
assembler; an unbounded HTTP body alone is not a durable stream.

## Persistent window streams

POST `/api/v1/streams/captures/{bindingId}` using
`Content-Type: application/vnd.clearintervals.waveforms.v1`. Keep the HTTP/1.1
chunked or HTTP/2 request open and write consecutive windows in exactly the same
length/header/sample format as a finite capture. Each completed window has its
own stable `captureId` and acquisition start timestamp. There is no enclosing
unbounded array and no whole-stream content length or end marker requirement.

The server responds immediately with HTTP 200 and `application/x-ndjson`, then
flushes `{"captureId":"...","status":"queued"}` **after each window is fsync'd**.
Read responses while the request remains open; an HTTP proxy must support full
duplex forwarding. Retain each source window until its matching acknowledgement.
After disconnect, reconnect and replay every unacknowledged window with the
original ID, metadata and samples. Core receipt identity handles lost ACKs and
prevents duplicate measurements. Source files/data must survive a producer crash.
An HTTP 200 header alone acknowledges no waveform.

Temporary refusal emits `{"status":"retry","code":"rate_limited",...}` or
`buffer_unavailable`, including a one-second retry floor, then closes the stream.
The refused window remains unacknowledged. An idle timeout before any prefix
closes the connection without rejecting a record. Malformed windows emit `rejected` /
`invalid_frame` and require corrected input rather than unchanged automatic retry.
EOF before the next prefix cleanly ends a stream. EOF inside a window reports retry / `incomplete_window` and stores
none of that window; earlier acknowledged windows remain durable. Policy/config
reload is checked at each durable window boundary; reconnect to authenticate
against the replacement configuration.

At most 128 streams are connected per edge module, and the native listener allows
128 TCP connections. Idle streams read only a four-byte prefix and hold neither
of the two full-waveform slots. Each active window has a 30-second total and
10-second progress deadline; an idle stream may wait up to 60 seconds for its
next prefix. Finite uploads and stream windows share the same two active buffer
slots. A burst that cannot acquire one gets explicit backpressure before allocating
waveform memory. No unbounded application queue is created by stream admission.

This is continuous **completed-window streaming** through the existing DSP capture
contract. DSP publishes after a finite window, rather than after each sample.
The sender forms the DSP windows and sends axis-major samples; direct interleaved
ADC chunks, a rolling preview and incremental per-sample feature updates are
separate extensions. Raw samples, product quotas and storage bandwidth are
unchanged. Long-term large fleets still need an explicit raw retention/object
storage policy; persistence is not silently removed to make a benchmark pass.
