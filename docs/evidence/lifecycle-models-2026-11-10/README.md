# Payment, delivery and operation lifecycle models — 2026-11-10

Issue #43 now has bounded sequential models for all five named current runtime
areas: the prior runtime-replay/edge checkpoint plus the three models here.
This does not complete the decoder/fault inventory or final candidate qualification.

| Model | Deterministic program | Production boundary checked |
| --- | --- | --- |
| Payment attempts | Seeds 1, 17, 332043276360; 160 steps each | Real encrypted Gateway SQLite; eight request identities, unique send grants, first terminal result, immutable submission, projection/event/metric agreement and reopen |
| Outbox delivery | Same seeds; 256 steps each | One real SQLite delivery job per trace; lease/reclaim, old worker rejection, retry/backoff, age/dead-letter/replay, acknowledgement, exact event bytes and separate source revision |
| Exact CKB operation | Same seeds; 64 steps each | Actual tracker/persistent outbox and bounded HTTP mock RPC; one exact cooperative-close transaction, one ambiguous broadcast, canonical depths, reorg, dead input, wrong network, above-tip rejection, duplicate observations and reopen |

The 1,440 main-loop steps include deterministic coverage prefixes and repeated
operations; they are not 1,440 distinct states or exhaustive schedules. Tests
include extra setup/final replays. The delivery model asserts that claim,
completion, dead-letter replay, stale completion and acknowledgement all actually
occur. The payment model preserves one send grant per identity; expiry is only
observed through the existing readiness assessment and never grants a second send.
The operation model preserves inclusion history while requiring fresh observation;
its reference state/class counters do not call the production observer or lifecycle
counter implementation. Restart removes volatile broadcast permission.

## Actual defect found and fixed

The payment model originally failed at a reused requirement ID with a different
payment hash. The store correctly rejected it, but its generic CAS-conflict recovery
returned `Busy` when no row existed under the new hash. That mislabeled a permanent
identity conflict as transient unavailability. The fallback now reloads and checks
whether the requirement ID is already reserved before choosing `Conflict` or `Busy`.
Matching concurrent reservations still return `Existing`, never a new send grant.
There is no double-payment finding or changed authorization boundary.

`reused_requirement_with_different_payment_hash_is_conflict_not_retryable_busy`
is the minimal regression: no revision changes, no new reservation, and a genuinely
new request can still reserve normally. The original model failure is retained.
Public DTOs, schema, wire encodings and encryption formats are unchanged. Existing
service error mapping converts the preserved Conflict into RequestConflict.

## Reproduce and results

```sh
cargo test -p morph-payment-gateway -p morph-events --all-features
cargo test -p morph-cli --all-features operation_runtime
cargo clippy -p morph-payment-gateway -p morph-events --all-features --all-targets -- -D warnings
cargo clippy -p morph-cli --all-features --all-targets -- -D warnings
```

- Gateway: 57 library + 3 binary + 2 protected-input integration tests pass.
- Events: 22 tests pass, including existing real-process kill/HTTP/archive tests.
- Operation runtime: 22 tests pass; the rest of CLI tests are filtered, not rerun.
- Total: **106 tests pass**. Both Clippy invocations pass.
- Formatting, whitespace and saved evidence checksums pass.

The scheduled campaign now runs the Gateway suite as well as its existing event
and operation suites. PR workspace tests already include these models. Fixed
command counts and the enclosing CI timeout bound these ordinary Rust tests;
they are not new isolated mutation-fuzz workers. No scheduled GitHub execution
is claimed for this unpushed worktree.

Before/after hashes cover the explicit source sets used for final validation and
are equal. They are not a whole-tree/clean-source freeze. A first operation-model
run exposed a test setup error: a prior explicit dead-cell mock response overrode
the helper's restored live-cell map. Each model observation now resets the explicit
RPC response. This was not a production tracker failure.

## Limits and next evidence

These are sequential models, complemented by existing independent-connection,
real-process kill, HTTP and native-chain scenarios. They do not explore every
thread schedule, filesystem power loss, complete authority rollback, routed MPP,
provider-independent fulfillment or all operation adapters. The operation model
uses controlled RPC, not a new CKB-node run; replacement winners retain their
separate existing scenario tests. Delivery uses one job; competing worker/global
in-flight tests remain separate. Payment fixtures exercise persistence after the
service authorization boundary; existing HTTP tests own proof authentication.

Next #43 work is a complete current decoder and declared fault-family coverage
inventory, fixing actual holes and binding evidence to the final candidate. #44,
#28 and #55 still require their respective final qualification. No issue is closed,
no release is published, and real-asset permission is unchanged.
