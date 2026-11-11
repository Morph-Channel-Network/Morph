# Scoped service readiness and bounded metrics

This covers the current Hub, Payment Gateway, signer-context supervisor, event
consumer and watch configuration service observations, including exact-source
Sponsor publication quotes. The participant key-process probe independently
reports loaded-policy responsiveness; combined channel mutation readiness and
complete payment reconciliation readiness remain incomplete. Consumer readiness is local dispatch health, not remote
receiver availability or chain finality. Gateway readiness reports the named
prerequisites below, not guaranteed route liquidity or successful settlement.

## Interfaces and access

| Endpoint | Meaning | HTTP/body |
| --- | --- | --- |
| `GET /api/health` | The Hub can authenticate and dispatch this request | 200, typed `Liveness`; no store lock, database or RPC probe |
| `GET /api/readiness` | Current observation of explicitly configured scopes | 200 when those scopes are ready; otherwise 503 with the same typed `Readiness` body |
| `GET /api/metrics` | Fixed-label process counters, latency and scope gauges | 200, Prometheus text, bounded below 64 KiB |

All three retain the Hub's **read** permission, existing listener/authentication,
connection and request limits. They are not anonymous monitoring bypasses.
Explicit unauthenticated loopback remains a development configuration. Responses
dispatched through these routes carry `Cache-Control: no-store`. Authentication
failures still use `ApiErrorBody`, not a readiness body. The Rust SDK exposes
`liveness()` and `readiness()`; it decodes a 503 readiness report and rejects
contradictory HTTP status, service or summary/check fields.

The endpoint registry generates the OpenAPI and schemas. There is one current
unpublished shape: `/api/health` no longer returns the full `HubView`. Use
`/api/state` for that projection. No old-shape fallback is provided.

## Exactly what the Hub claims

| Scope | Configured now | Checks |
| --- | --- | --- |
| `local_registry` | Yes | Current runtime database integrity/schema, valid Hub projection and exact in-memory/durable revision agreement |
| `invoice_issuance` | Only with the startup-validated invoice key | Same store checks plus that loaded invoice signing policy |
| `channel_signing` | No | Explicitly unsupported by this Hub service |
| `payment_submission` | No | Explicitly unsupported by this Hub service |
| `chain_publication` | No | Explicitly unsupported by this Hub service |
| `event_dispatch` | No | Checked by the separate event-consumer process, not the Hub |

The top-level `ready` summarizes **configured scopes only**. A Hub without an
invoice key can be ready for local registry work while invoice issuance is not
configured. A caller that needs a particular capability must inspect that exact
scope's `configured` and `ready` fields. Unsupported scopes always have
`ready=false`; they are not silently promoted by a healthy database or reachable
CKB endpoint.

Local registry actions update Hub coordination records. Their readiness does not
claim that a corresponding funding, splice or finalisation transaction happened
on CKB. The current Hub model already marks chain actions disabled. Loaded invoice
authority is distinct from the seven-role participant signer and its journal.

No readiness report is a signing request, monotonic authority, recovery package,
admission decision or mutation permit. Existing request validation, signer guards,
durable reservations and transaction CAS remain the actual execution boundaries.
Likewise, a stale observational summary does not block independent keyless recovery.

## Freshness and concurrency

The Hub uses an on-demand background store probe. At most **one probe** is in
flight. Requests do not wait for database validation or hold the Hub store mutex
while it runs. A request encountering the store mutex reports `busy`; a poisoned
mutex reports `store_inconsistent`. Startup is `unverified` until a real probe
completes.

The development cache horizon is **5 seconds from probe start**, not completion.
An I/O call that stalls beyond that horizon cannot manufacture a fresh result
when it eventually returns. Expiry is checked against both wall time and elapsed
monotonic time. A changed Hub revision invalidates the cached observation and
requests a new probe. Missing/unreadable files, unsupported current schema or
invalid persisted state remain not ready until they can actually be checked again.

`generated_at_ms` is the report's creation time. Each check separately carries
`checked_at_ms` and `valid_until_ms`, or explicit nulls when no observation exists.
These fields are canonical decimal strings; the report timestamp must not be
mistaken for the age of the underlying evidence.

The filesystem operation itself is not forcibly cancelled. A stalled call occupies
the sole probe worker, and subsequent observations expire instead of spawning more
workers. This is bounded worker ownership and fail-closed freshness, not a claim
of a hard operating-system I/O deadline. The existing connection cap still applies
to liveness; it is not a separate reserved listener.

Five seconds is an explicit local cache policy, **not** a measured production
service objective or a challenge-window budget. Those thresholds require the
actual watcher/publication scheduling and deployment measurements.

## Metrics

One Hub exporter has **133 fixed series**:

- `morph_runtime_operations_total`: 7 operation categories × 5 outcomes.
- `morph_runtime_inflight`: 7 categories.
- `morph_runtime_duration_milliseconds`: 7 histograms, each with nine finite
  buckets, `+Inf`, count and sum.
- `morph_runtime_scope_ready`: 7 capability scopes (including unready event-dispatch and authority-supervision scopes in Hub).

Categories are `read`, `registry`, `invoice`, `recovery`, `restore`, `observe` and
`unknown`. Outcomes are `success` (HTTP 2xx/3xx), `rejected` (4xx except 429),
`busy` (429), `failure` (other statuses) and `aborted` (dispatch guard dropped).
The histogram boundaries in milliseconds are 1, 5, 10, 50, 100, 500, 1000, 5000
and 30000. They are measurement buckets, not alert thresholds.

These are **dispatched HTTP-operation measurements**, not settled-payment or
on-chain lifecycle counters. They exclude transport parsing, early authentication
rejection before dispatch, and SSE streaming lifetime. Observation requests
themselves are counted, including readiness failures. The scrape being rendered
finishes after its response is assembled, so its completion appears on a later
scrape.

Labels cannot contain a channel/payment ID, OutPoint, token, URL, peer, path,
request ID, raw error or arbitrary caller string. The API accepts fixed Rust enums
only. Unknown request paths share one category. Counters saturate instead of
wrapping and reset on process restart. Concurrent scrapes are approximate atomic
measurements, not a transaction ledger or independent rollback-freshness source.

## Responding to failures

| Signal | Operator action |
| --- | --- |
| Alive, initially unverified | Allow the bounded probe to finish; inspect continued failure rather than assuming protection |
| Busy | Find the active local operation; repeated busy does not count as verified coverage |
| Revision changed | Refresh/reconcile against the current runtime revision; do not replay a different mutation under an old identity |
| Stale or clock invalid | Check process/worker progress and clock behavior; do not extend the timestamp by editing files |
| Store unavailable/inconsistent/schema unsupported | Preserve the directory and logs, check permissions, I/O and the exact current build; use the incident/storage runbooks |
| Capability not configured/implemented | Use its actual implementation and required evidence; a green local registry scope does not enable it |

Never delete a payment ledger or restore an old signer journal to make a probe
green. No automatic repair/reset occurs here.

## #35 completion scope

The sections below describe implemented signer/supervision, Gateway, watcher,
consumer and operation observers, their fixed diagnoses, durable business counts,
fee/time margins and operator actions. The final W1 profile joins their actual
fault tests and native watch/Sponsor/reorg evidence under one candidate identity.
The [W1 scope](../w1-acceptance.md) qualifies these explicitly configured scopes.

A new general mutation coordinator, routed payments and RPC failover are later
features. Their absence must continue to report unsupported/unready; they are not
new #35 completion prerequisites. Saved operation history does not become live
mutation authority. The admitted no-value experiment uses declared local budgets;
production percentile/SLO calibration and public-network measurements remain
separate. The owner's cancelled independent gate is not reinstated here.

## Watch configuration service: expiring scan and publication observations

The current health format is `morph.watchtower_health.v3`; the public assessment
is `morph.watchtower_readiness.v3`, including fixed reasons and remaining margins.
Old health files are
rejected, not upgraded. Inspect it without keys or RPC:

```sh
morph-cli watch-config-health --config /private/watch.json --health /private/health.json
morph-cli watch-config-health --config /private/watch.json --health /private/health.json --metrics
```

The report separates **scan coverage** from **prepared publication readiness**.
`scan_coverage_ready` requires every configured resource's pass to complete and
report caught-up scanning, a running service, matching current config/policy/location
and unexpired per-resource evidence. `publication_ready` additionally requires
fresh exact-source Sponsor quotes for every resource. The JSON probe returns
nonzero unless publication readiness is verified; it still prints each scope.
This replaces the earlier permanently-false `protection_ready` placeholder.

A quote uses the existing publication builder, canonical dependencies and VM
preflight without submitting. It validates the exact State/Vault source, live
Sponsor identity/range/change lock, initial fee and current fee market. It reports
remaining Sponsor total and per-transaction budgets, operator fee cap, capacity
after the actual change-output floor, and the configured full fee ceiling. Merely
being able to pay the first fee does not satisfy full replacement headroom.
Replacements compete for the same input; their mutually exclusive fees are not
summed. Time headroom subtracts observed Settling confirmations and configured
reorg/failover/safety/confirmation reserves from the signed challenge window.

Budget observations expire after 30 seconds on both wall and boot clocks, or
sooner when their execution window runs out. They are observations, not input
reservations or broadcast authority; publication reconstructs and verifies again.
The quote rejects a tip change during evaluation. It uses supplied policy block
timing, not a newly measured public-network guarantee. Amounts/time budgets are
canonical decimal strings; no transaction body, key or private package is placed
in health output. The existing dry-run path can persist the already-held immutable
recovery package, but does not append broadcast attempts or submit a transaction.

`funding_not_prepared` means automatic funding has not yet produced a concrete
Sponsor cell. `source_not_observed` and `recovery_not_available` require restoring
coverage/evidence. `preflight_unavailable` includes spent/mismatched inputs, fee
or policy limits and unavailable RPC; rerun the explicit dry-run to diagnose it.
After actual publication, `source_consumed` prevents the old Sponsor quote from
being treated as available funding. No higher saved state means there is no
prepared superseding operation to quote. None of these states authorizes a fresh
signature, a journal reset, automatic funding from a readiness read, or a claim
that a saved package is the latest privately signed allocation.

Each observation expires ten minutes after its own pass starts, using both wall
time and Linux boot time/identity. This is a diagnostic upper bound, **not an
admitted dispute-response SLO**. Restart/clock rollback/config or policy change,
missing/old health and stopped service cannot become ready from cached evidence.
The service takes a stable, nonblocking health-writer lock and saves owner-only,
fsynced atomic health. It does not accept health as mutation authority.

There are at most 32 channels and a five-minute configured timeout per channel,
with one total RPC budget of that timeout plus five seconds. A busy cursor fails
promptly. Per-resource failures are retained and subsequent resources still run;
fully failed consecutive passes hit the configured stop limit. Initial invalid
global configuration or a mid-pass config/policy change invalidates the whole
pass. Scanning remains sequential: a slow earlier channel can delay later ones,
and earlier evidence may expire before a large pass ends. This is visible as
unready; parallel scheduling/failover is not claimed here.

The watcher checks the saved package's network against genesis and its StateType,
StateLock and VaultLock against the supplied current artifacts before scanning.
An unavailable/mismatched source cannot be hidden as an idle success. Once/loop
CLI commands print the full report and return failure if any resource failed;
the continuous service keeps healthy peers running. Raw RPC errors are replaced
by a fixed aggregate error code. Private service reports retain paths; the health
probe emits bounded resource indices only, mapped to configuration order.

Twenty-six fixed series have no user-controlled labels. The original nine gauges are `morph_watch_scan_coverage_ready`,
`morph_watch_publication_ready`, `morph_watch_publication_ready_resources`, `morph_watch_resources`, `morph_watch_evidence_fresh`,
`morph_watch_scan_completed`, `morph_watch_caught_up`, `morph_watch_reorg_reset`,
`morph_watch_publication_confirmed`. The last two count fresh pass observations,
not lifetime counters or current-chain proof. The additional series are:

| Metric | Meaning |
| --- | --- |
| `morph_watch_readiness_reason_resources{reason}` | Twelve fixed reason labels; each configured resource contributes exactly once |
| `morph_watch_budget_quoted_resources` | Resources with completed/caught-up scans and fresh internally consistent numerical quotes, including valid insufficient-fee quotes |
| `morph_watch_min_fee_headroom_shannons` | Smallest excess above the configured full fee ceiling among those quotes |
| `morph_watch_max_fee_shortfall_shannons` | Largest missing amount below the configured full fee ceiling among those quotes |
| `morph_watch_min_execution_remaining_ms` | Smallest remaining execution time under the quoted timing profile |
| `morph_watch_min_observation_ttl_ms` | Smallest remaining quote validity, bounded by both 30 seconds and execution time |

Fee availability is the minimum of operator cap, Sponsor remaining total,
Sponsor per-transaction cap and capacity after the actual change floor. These
fees compete for the same input; replacement fees are not summed. Exactly meeting
the full ceiling gives zero excess and zero shortfall and can be ready. A positive
shortfall cannot be hidden by another channel's ample budget. If there are no
valid numerical quotes, all four margin gauges are NaN. With partial coverage,
min/max describe only the quoted subset: always inspect coverage and reason counts
alongside them, never read a positive minimum as universal protection.

Remaining time subtracts the greater of wall elapsed time and boot elapsed time
plus the quote's age when captured. Thus a slow wall clock cannot restore budget;
quote creation/capture inconsistencies fail closed. No estimate of subsequently
elapsed blocks is presented as a new chain observation. These numbers inherit the
supplied timing profile, not a claim of measured public-network performance.

| Fixed reason | Operator action |
| --- | --- |
| `ready` | Retain monitoring; a fresh quote reserves no inputs or future fees |
| `evidence_unavailable` | Check service status, config binding and scan expiry; unavailable evidence is not coverage |
| `scan_failed` / `scan_behind` | Inspect that resource's scan, RPC and cursor; healthy resources continue independently |
| `budget_expired` | Refresh actual quote/clock evidence before relying on its margins |
| `funding_not_prepared` | Complete configured funding and obtain a fresh quote; an unfunded wallet balance is not a Sponsor |
| `source_not_observed` / `recovery_not_available` | Restore canonical source observation or exact retained recovery evidence; never reset signing authority |
| `preflight_unavailable` | Inspect pinned inputs, scripts, current fee profile and VM preflight |
| `source_consumed` | Reconcile the consumed source and any successor before preparing new publication funding |
| `budget_invalid` | Preserve evidence and inspect inconsistent quote fields; do not edit the ready flag |
| `fee_headroom_insufficient` | Inspect per-resource limiting caps and shortfall, then adjust approved funding/policy and requote |

Any unready resource is an actionable coverage loss. Positive fee shortfall and
quote expiry are exact configured-policy boundaries, not arbitrary production
warning percentages. Configure early-warning lead time from measured polling,
rebuild and failover behavior for the admitted deployment; that calibration remains
open. Existing alert and publication-attempt records remain the sources of publication/RBF outcome history;
these reason gauges are current assessment categories, not lifetime failures.
A health probe failure must itself
alert the operator; do not treat missing output as zero failures. Check failed
resource paths/policies and available packages, then reconcile/restart the real
service; never repair readiness by editing its health file.

The native watch acceptance now prepends a deliberately unavailable source and
requires the genuine peer to complete sponsored canonical correction. Evidence:
[watch checkpoint](../evidence/watch-readiness-2026-11-10/README.md). Publication/RBF business metrics, calibrated margin alerts and full #35 qualification remain.
The subsequent [budget checkpoint](../evidence/watch-budget-2026-11-10/README.md)
adds live Sponsor quotes and the short budget lifetime described above.


## Event consumer: actual local dispatch readiness

The consumer uses the same typed `Readiness`, with `service=event_consumer` and
exactly `scope=event_dispatch`. Invoke it with the same source, store, URL and
protected key-file configuration as the worker:

```sh
morph-cli event-delivery \
  --source /private/watch/channel.db \
  --store /private/events/generation-002.db \
  --url https://receiver.example/morph-events \
  --hmac-key-file /private/events/webhook.key \
  readiness --max-pending-age-ms 300000 --max-critical-age-ms 30000
```

For encrypted sources, also specify `--source-storage-key-file`. The probe is
read-only, takes no consumer-worker lock, and performs no HTTP request. It prints
scoped JSON and exits nonzero when unready. `metrics` accepts the same age budgets
and emits Prometheus text suitable for a local textfile collector. It exits
successfully with readiness 0 when the observation shows a fault; unavailable
backlog values are `NaN`, never invented zeros. Invalid command budgets fail.
These commands require trusted local access to the configured key files; this is
not an anonymous network monitoring endpoint.

| Dependency | Required evidence |
| --- | --- |
| Store | Full source/consumer schema and payload validation; consistent source and consumer revisions around the backlog observation |
| Outbox | Active generation, no archive requirement, no dead letters, no unread source page, and pending/critical age within the selected budgets |
| Worker | Fresh heartbeat bound to the same source, consumer generation and receiver/key policy; matching boot identity, valid wall and boot-time horizons, running state |
| Delivery policy | Current committed watch-source egress permission, where applicable |

A readable empty queue without a running worker is not ready. Any dead letter is
unready, not merely critical dead letters. Unread source events are conservatively
unready until enrolled rather than treating unseen critical work as healthy. The
critical age covers pending/in-flight critical events already enrolled. The age
origin is enrollment or explicit dead-letter replay; these budgets are not chain
challenge deadlines and do not authorize resetting those deadlines.

`serve` writes a private heartbeat at `STORE.health.json`, or `--health-file`.
The heartbeat is stamped **before each tick** and lasts `interval_ms + 15000` ms
(maximum 75000). A normal fatal tick writes `running=false`; process termination
leaves a lease that expires. On Linux, verification uses both the wall clock and
`CLOCK_BOOTTIME` plus `/proc/sys/kernel/random/boot_id`. A wall-clock rollback cannot
extend the boot-time horizon; a reboot or another generation invalidates the old
lease. A stopped worker can appear fresh only until its already-issued heartbeat
expires. `run-once` does not claim a continuously running worker or renew this lease.

A health file belonging to another subscription/generation is rejected by the
writer instead of overwritten; use the new default path after archival. Corrupt
health projections may be recreated locally after stopping the worker; they are
not signing or delivery authority. Do not use a source/consumer database as the
health-file path. Store/key inputs retain their private ownership/permission rules.

Each CLI probe owns one background task with a 2000 ms observation budget. A slow
or expired result cannot become green after completion, and the worker check's
validity is capped by the heartbeat's remaining wall/boot horizon. The command
returns an unready report on timeout; it does not promise cancellation of a stuck
kernel I/O call. Process scheduling/termination still obeys the operating system.
No readiness command is used to bypass validation or to block unrelated keyless
recovery.

The consumer exporter emits **17 fixed gauges**: observation availability, scoped
readiness, retained/pending/in-flight/acknowledged/dead-letter counts, critical
pending/dead-letter counts, two oldest-age values, source pending/blocked, archive
required, sealed, worker freshness and delivery-policy allowance. It emits no
source IDs, consumer IDs, event/channel IDs, endpoint URLs, filesystem paths or raw
errors. These are current observations, not cumulative settled-payment counters.
Defaults (300 s ordinary, 30 s critical) are explicit local no-value budgets;
measured deployment thresholds and the other #35 service integrations remain open.


## Payment Gateway

The actual Axum router exposes public `GET /health` liveness and operator-bearer
protected `GET /ready` and `GET /metrics`. Existing explicit local-development
configurations may omit the bearer. Readiness returns 200/503 with the same shared
`Readiness` DTO; authentication failures retain `GatewayErrorBody`. Both observation
routes set `Cache-Control: no-store`. The Rust Gateway SDK provides `readiness()`
(including structured 503) and bounded `metrics()` text. Its readiness decoder
checks service identity, status and internal report consistency.

Append both identity flags to the existing `morph-payment-gateway serve` command:

```sh
--fiber-pubkey "$EXPECTED_FIBER_PUBKEY" \
--fiber-chain-hash "$EXPECTED_FIBER_CHAIN_HASH"
```

Choose expectations from the intended node/network configuration; do not learn
and silently accept replacements from each health response. Public key is exactly
66 lowercase hex digits **without** `0x`, matching current Fiber `node_info`;
chain hash is 32 nonzero bytes in lowercase `0x`-prefixed hex. Both flags are
required together. They are observation configuration, not new payment authority.
Without pins, local store observations can be healthy but Fiber-dependent scopes
remain `not_configured` and aggregate readiness is false. Existing payment
request validation is unchanged: no health result bypasses signed terms, stored
submission identity, expiry, payer policy or per-request limits.

| Gateway scope | Required observations |
| --- | --- |
| `local_registry` | Matching encrypted store identity, valid current schema/history/projection and observed capacity |
| `invoice_issuance` | Store plus live outstanding challenge/receipt room and exact provider-reported identity match |
| `payment_submission` | Only configured with `outgoing_payer`; store, non-evicting outgoing-attempt room and provider identity |
| `channel_signing`, `chain_publication`, `event_dispatch` | Explicitly unsupported here; their real services own those checks |

The sole RPC probe is read-only `node_info` with **empty positional parameters**.
It compares both node public key and chain hash, distinguishing malformed data,
wrong network, wrong provider, unavailable RPC and absent configuration. This is
an observation of what the configured RPC reports. It does not independently
verify the CKB tip, deployment scripts, token admission, writable RPC permissions,
route liquidity, recipient availability or paid upstream availability. The
current named scopes do not claim those capabilities; per-operation validation
and failure handling remain necessary. A matching RPC identity does not solve
provider-loss recovery or qualify the full #37 integration.

Each service instance permits one observation in flight. It opens an independent
**read-only** encrypted store connection, validates history and checks the source
identity and unchanged revision around projection reads; it does not lock the
business `DurableStore` connection or prune records. Replacing the file with a
different otherwise-valid encrypted database fails identity matching. A single
2000 ms budget covers the store and RPC probes, running concurrently. Evidence
expires from probe start; elapsed monotonic time and wall-clock rollback cannot
turn a late result green. Concurrent scrapes return `busy` instead of queueing.
A timed-out/cancelled blocking disk task retains the single permit until it
actually exits, so repeated scrapes cannot accumulate stuck threads. The HTTP
request can finish on timeout; this is not cancellation of kernel I/O.

Capacity is an observation, not a reservation: it checks history-row ceilings,
room for a bounded transaction under the stored-byte limit, the transient
projection ceiling, current challenge/receipt bounds and the 256 non-evicting
outgoing identities. Expired unreceipted challenges count as reclaimable without
being removed by the probe. Request-size validation and write-time CAS still
apply. Unknown outgoing results remain retained and are never resubmitted by a
probe. Safe producer history archival is still required for long-running service.

Metrics contain **147 fixed series**: 133 shared process operation/outcome,
latency and scope series plus ten Gateway gauges (revision, challenges, receipts,
offers, outgoing identities, unresolved outgoing count and oldest age, history
rows, stored payload bytes and overdue unresolved outgoing count), and four
durable business counters described below. Missing or expired store data is `NaN`; it is
never represented as zero backlog. Route categories are closed and no captured
path, key, payment hash, node key, URL or raw RPC error becomes a label. Process
HTTP process counters reset on restart and are not durable payment totals. Latency ends when
the handler produces a response, not when downstream streaming finishes.

Business counters come from non-evicting records in the same observed encrypted
projection, not from the bounded payment display or an independently updated
metrics ledger:

| Metric | Meaning |
| --- | --- |
| `morph_gateway_outgoing_reserved_total` | Distinct durable outgoing identities, each permitting at most one initial send call; not evidence that a call or payment completed |
| `morph_gateway_outgoing_succeeded_total` | Retained immutable terminal responses with matching payment identity, `Success` and `completed=true` |
| `morph_gateway_outgoing_failed_total` | Retained immutable terminal responses with matching payment identity, `Failed` and `completed=false` |
| `morph_gateway_receipts_issued_total` | Distinct locally persisted incoming receipts; duplicate settles return the existing receipt |

These counts survive restart and display eviction. Exact retries and repeated
terminal observations add no identity/result. Unknown outcomes remain in the
existing unresolved gauge and are neither successes nor failures. Contradictory
saved terminal identity/status makes the store observation inconsistent rather
than silently counting it. Provider terminal results are saved provider evidence,
not a new independent chain-finality proof. Counts are per retained store; resetting
the store is not an acceptable way to recover quota or sending permission.

`morph_gateway_overdue_unresolved_outgoing` counts unresolved identities whose
elapsed wall time reaches their **own recorded payment-wait timeout**. Any positive
value calls for exact-request reconciliation and inspection of the provider; it
does not prove failure, authorize a refund, cancel an approval or permit resubmission.
The boundary is the actual request's waiting budget, not an invented production
SLO. It does not block unrelated healthy payment work. Deployment-wide failure-rate
and capacity alert thresholds still require measured admitted profiles.

Current tests exercise real encrypted databases, actual HTTP/router/SDK paths,
exact provider wire shape against a controlled HTTP peer, provider timeout,
authentication, database replacement, quota exhaustion/expiry, and cancellation
of a running blocking probe. They are host regression evidence, not a new native
Fiber/CKB acceptance run or production qualification.


## Signer context supervisor

`multi-asset-supervision-readiness` (RPC-enabled/devnet build) reads current v2
supervision evidence under a 2-second observation budget and emits the shared
report. `--metrics` exports eight fixed series. See the
[supervision runbook](signer-supervision.md#redacted-scoped-observations).
The scope is `authority_supervision`, not `channel_signing`: it says whether the
registered contexts recently passed their canonical guards. It does not contact
or grant authority to an external key process. Snapshot validity is bounded by
cycle-start wall time, Linux boot time and boot identity; stale readings cannot
be renewed by a scrape. The shared scope addition makes the current generic
Hub exporter 133 series and Gateway exporter 147; older checkpoint counts are
historical. External signer liveness/policy has its own live probe below. Watch scan and
publication observations are implemented separately in the section above; they
do not turn supervision evidence into signing authority.

## Participant key-process policy

`participant-signer-readiness --config PATH` probes the actual private signing
listener under a two-second total budget. It reports only `key_process_policy`,
with separate `responsive` and `policy_ready` booleans and short-lived timestamps.
The configured key is checked on service startup; the probe compares loaded and
current configuration without signing or touching the authority journal. Busy
queues, changed policy, stopped services and expired/invalid clocks cannot appear
ready. `--metrics` exposes two fixed gauges with no variable labels. See the
[signer runbook](external-participant-signer.md#read-only-key-process-policy-readiness)
for semantics, access, restart and operator actions. This does not add a ready
`channel_signing` scope to Hub or turn policy observations into mutation permits.

## Exact-operation lifecycle history

`operation-observability --store PATH` reads the current v2 operation records
without RPC or mutation. Its `saved_operation_history` scope and 225 fixed metrics
cover persisted status entries, registered replacements, pre-send intents and
unresolved age. They are historical business measurements, not current chain or
mutation readiness. Missing/invalid/old-schema/expired snapshots expose availability
zero and `NaN` values, not fabricated zero activity. The five-second observation
budget and revision/store-identity checks bound this local scrape. See the
[operation runbook](ckb-operations.md#saved-lifecycle-metrics) for exact semantics,
reset boundaries, operator actions and unimplemented adapters.
