# Durable exact-operation lifecycle metrics — 2026-11-10

The sole current operation record is `morph.ckb_operation.v2`, with required
registration/state-entry times and twelve status-entry counts. Counts are part of
the same record/status/intent/outbox transaction, not asynchronously reconstructed
from a potentially unbounded event scan. Existing registration and unchanged
observation retries are idempotent. Changing inclusion depth inside one state
class does not add another class entry. A failed CAS commits neither state nor
counts. Historical finalised counts survive later RPC-failure/reorg observations;
the current saved-state gauge changes separately.

`operation-observability --store PATH` is available in the default CLI build and
uses the actual read-only runtime store. Global revision, reopened store identity,
strict current schema, operation identity/preflight and lifecycle counts are
validated. It takes no operation lock and performs no RPC or transaction submission.
Its named scope is `saved_operation_history`, never current chain/mutation
readiness. Only the existing cooperative-close adapter is claimed; enum slots for
other kinds do not implement those transaction adapters.

Metrics have exactly 225 fixed series, using eight kinds and twelve status
classes. They cover retained records, pre-send intents, linked replacement
registrations, historical state entries, current saved states and oldest unresolved
age. Unavailable evidence produces availability zero and 224 NaN values. JSON
returns nonzero with a null snapshot. No paths, endpoints, IDs, raw errors,
transaction bytes or signatures become labels or output fields. The five-second
wall/boot observation budget is a local scrape horizon, not a deployment SLO.

| Verification | Result |
| --- | --- |
| Final CLI all-features | 352 unit + 4 integration tests pass; native-event readback remains explicitly ignored without separate devnet input |
| Operation subset within that run | 21 tests, including existing process-kill, canonical replacement and recovery tests |
| New producer checks | Duplicate registration/polls, same-state depth increase, restart, wrong-genesis failure, reorg and linked replacement registration |
| Atomic count check | Failed CAS leaves no pending-state count; successful exact retry commits once |
| Negative records | Missing store, old v1, missing lifecycle, inconsistent counts, future timestamps and overflowing counts reject without application mutation |
| Separate observation process | Writer lock stays held and RPC is shut down; historical read succeeds with the same database revision |
| Actual CLI unavailable path | JSON nonzero/null snapshot; metrics exit zero with 225 series and 224 NaNs; no database created |
| Clippy/format | All-features/all-targets and default all-targets pass; formatting/diff checks pass |

The first broad run exposed a default-build module gate and a transient test
reopen lock during concurrent fork/exec. The default command now uses the same
shared module; mutation adapters retain their existing CLI gates. The restart
test retries only the explicitly classified Busy condition within two seconds;
production lock rules were not changed. Final verification passed after both
corrections. Five relevant implementation/test files have identical before/after
hashes. This is not a whole-worktree clean-source or final committed-candidate claim.

`verification.json` records the built CLI hash. Public unavailable-report/metrics
artifacts contain no private store data. No new native CKB run, contract/ELF rebuild,
public-network measurement, release, commit, push or issue closure occurred.
Earlier operation evidence retains its original v1 scope; current development
acceptance must be regenerated with v2, without an old-reader/migration fallback.
Preserve recovery files and signer journals rather than resetting authority to
make metrics appear healthy.

Remaining #35 scope includes actual dependency aggregation, other business/payment/
publication/Sponsor metrics and deployment-calibrated alerts; full W1 qualification
remains open. [Operational semantics and actions](../../runbooks/ckb-operations.md#saved-lifecycle-metrics).
