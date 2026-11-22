# Verification and acceptance evidence

Executed on 2026-10-21 in an isolated development environment with Go 1.27.3. Core's fixture uses a uniquely named throwaway database on a TimescaleDB 2.17.2/PostgreSQL 16 container marked `clearintervals-gateway-tests-only`; it refuses any unmarked or non-loopback database server. The fixtures never use a production application database. The cloud gateway and core were the versions current on that date.

## Executed checks

| Check | Result |
| --- | --- |
| `make verify build` | Formatting, vet, race-enabled package tests and static production build passed. |
| `make generate vectors` | Reproducible schema generation; three independently decoded Python/Go canonical byte/hash vectors passed. |
| `make fuzz` | Wire framing: 135,154 executions in the recorded 20-second run; remote-write decoding: 237,410 executions in 20 seconds; no failures. |
| `make scan` | No vulnerable called symbols or imported packages. The x/crypto module contains advisory GO-2026-5932 for unmaintained OpenPGP; this application does not import or call OpenPGP. |
| Core gateway suite | 38 passed against real TimescaleDB, including the initial/replacement bundle generation assertions. |
| Real-service integration fixture | All three tests passed: production executable remote-write delivery; lost enrollment response, renewal, zero credit, H2/H3, authorized redundant point deduplication and revoked backlog; expired identity recovery. |
| Container | Scratch image built; configuration validation passed as UID 65532 with read-only root, no capabilities, no-new-privileges, one CPU and 512 MiB limit. |
| Real disk exhaustion | Passed on an actual 1 MiB tmpfs in the restricted non-root container; accepted transactions survived ENOSPC and restart. |
| Argon2id benchmark | Three verifications averaged 201 ms on a shared cloud VM; 64 MiB/profile, maximum two password workers. This is a bounded-cost measurement, not a production throughput promise. |

Package failure tests cover checksum corruption/torn segments and quarantine, partial receipts and restart, unknown outcomes/frontiers, mismatched session/epoch/sequence/index/ID/hash, receipt-write failure, immutable bindings, quota/expiry eviction, durable suspension and explicit active resume, wrong returned credential key/identity/generation/operation/expiry, pending-operation and activation-manifest restarts, local writer authorization, malformed and over-expanding snappy/zstd, password work limits and zero-credit progress. H2 tests verify server trust, client certificates and reuse of the same physical connection.

Real-service tests initially caught a test point older than its binding validity window. Core correctly rejected it as terminal. The corrected fixture timestamps acquisitions after binding creation and confirms the durable core effect. It also waits for the cloud's bounded change-feed poll before testing a newly committed credential on a new TLS connection; a transient TLS failure does not alter local collection policy.

## Reproduce the service integration

This needs the cloud gateway and core sources, which are not published with this repository. The unit, race, fuzz, vector and container checks above need only this repository.

Build the companion cloud gateway with its own `make build`. Install core's pyproject dependencies, pytest and grpcio-tools in an isolated Python environment. Start a disposable TimescaleDB container with `cluster_name=clearintervals-gateway-tests-only`, an explicit test password, and a port published on loopback only. Then:

```sh
make verify build
CORE_SOURCE=/path/to/clearintervals-core \
CLOUD_SOURCE=/path/to/clearintervals-cloudgateway \
GATEWAY_TEST_ADMIN_DSN=postgresql://core:<test-password>@127.0.0.1:<test-port>/core \
python integration/fixture.py
```

The fixture creates and deletes its own database, PKI, gateways, bindings and service processes. It does not publish images or send messages. The normal CI workflow compiles the integration driver and runs unit/race/fuzz/vector/scanning and image checks. Real core/cloud tests require the explicit isolated fixture above; a compile-only integration check is not reported as executed end-to-end acceptance.

For actual disk exhaustion, compile `CGO_ENABLED=0 go test -c -o bin/buffer-tests ./internal/buffer`, make that test binary executable by UID 65532, and run only `TestRealENOSPC` in the scratch image with a 1 MiB writable tmpfs, `EDGE_TEST_ENOSPC_ROOT=/tmp/queue`, read-only root and no capabilities. This test requires an actual ENOSPC, refuses success on subsequent admissions, restarts the queue and verifies every previously acknowledged enqueue transaction remains recoverable.

## Scope of the evidence

These results establish the current remote-write consumer against the implemented core/cloud protocol. Core owns current-generation admission, entitlement/site/binding/suspension-time enforcement and canonical cross-gateway deduplication; its tests and the companion cloud's recorded G01–G10 acceptance evidence remain part of the combined system assessment. This repository does not duplicate the cloud listener, PKI issuer or internal core service.

The later waveform-source selection, source-specific acquisition/scheduling integration, site-specific operational qualification, and the 100k-samples/s performance target are not claimed as executed here. The first released sink is remote write. Production rollout still requires operator approval of the exact main-branch signed image digest, public GHCR package visibility, installed regional roots and customer-specific writer/binding configuration. Candidate workflow artifacts prove the release path; they are not an automatic customer deployment.

## System fleet verification (2026-10-22)

The reproducible `integration/fixture.py` now supports simultaneous sensor fleets, sharded client processes, configured admission-ceiling recovery and open-loop sustained load. Values stay within the real binding range; the driver checks distinct delivered sensor identities, an independent value checksum, empty durable queues, zero terminal rejection/drop counters and live cloud telemetry through core. Proxy source addresses are distinct per real edge; production admission protections are unchanged. Failed delivery retains its JSON evidence even if telemetry is incomplete.

Two 5,000-source / 50-edge runs delivered all 15,000 readings each. A 10,000-source / 100-edge run delivered all 30,000 readings. These are burst-delivery results, not a sustained per-sensor sampling guarantee. The refined stress harness distributes traffic round-robin across edge processes, samples backlog growth, continues until two consecutive ramp tiers fail, then refines above the highest passing rate and confirms the candidate for three minutes. Earlier short plateaus do not establish sustainable throughput.

Edge recovery now clears an old outage penalty after an authenticated welcome. A data-stream capacity refusal retains healthy control and heartbeats and retries only the data stream after the bounded server floor. Repeated admission refusals use independent bounded backoff. A regression verifies that a refused data open and subsequent credit polling complete on one control session. Retry diagnostics expose only a whitelisted reason and delay, never credentials or payloads.

Example isolated burst/stress run (same companion build/database prerequisites as above):

```sh
python integration/fixture.py --sensors 25600 --rounds 1 --stress \
  --gateway-start-gap-ms 500 --admission-seconds 600 \
  --drain-seconds 600 --output build/fleet.json
```

For the 256-session per-organization ceiling and recovery, use `--sensors 300 --sensors-per-gateway 1 --rounds 1 --admission-capacity`. The fixture retires already fully delivered gateways before checking queued gateways recover. That optional mode requires 257–400 gateways and never changes the server limit. Use a dedicated marked database server: fixtures rotate shared gateway roles and must not run concurrently.

No universal maximum or 100k-samples/s claim is implied by these measurements.

Fleet warm-up is explicit: `--admission-seconds` defaults to 180 and is bounded at 900 seconds. Large cold starts may spend time in the production exponential retry schedule. The report records the configured warm-up and actual admission elapsed time separately from burst delivery. A longer warm-up does not convert an earlier failed run into a pass.

For sustained-only verification after a separately validated burst, use `--rounds 0 --stress`. The report explicitly marks the burst as skipped. The stability criterion retains 95% durable completion and zero ingress failures; its growth comparison allows two records of resolution between independently sampled ingress/core counters. A one-record in-flight difference must not be reported as overload. The candidate is still confirmed for three minutes.
