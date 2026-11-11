# Runtime replay and edge revision models — 2026-11-10

Issue #43 gains two bounded sequential models against actual SQLite-backed APIs.
No consensus, production runtime, schema, authority or admission behavior changes.

| Check | Result |
| --- | --- |
| Fourteen-target mutation smoke, seed 17, 1,000 inputs each | 14,000 pass, 11.026 s |
| Fourteen-target longer campaign, seed 332043276360, 10,000 inputs each | 140,000 pass, 94.728 s |
| `store-replay` short / long | 207 / 2,153 accepted; 793 / 7,847 rejected |
| Tool unit/integration tests | 11 pass |
| Fiber adapter tests | 38 pass |
| Both affected crates, all-target Clippy | Pass |

`store-replay` uses two synthetic `MTR1` test programs (included here), with at
most 16 commands. Eight commands cover writes, deletes, stale CAS, exact historical
retry, changed effect under unchanged intent/operation ID, duplicate immutable
outbox/attempt IDs, forbidden `commit_new` replay and reads. An independent set of
maps tracks expected live rows, original receipts and immutable history after
every step. Queries check absent as well as present keys and two-row pagination,
including reversed insertion order within the same revision. A rejection may not
leave a partial write, advance revision or modify history. Historical replay may
not resurrect a deleted projection or grant permission for a new external effect.
The test grammar is not an application format or compatibility path.

The edge model runs seeds **1, 17, 332043276360**, each for **128 commands**, with
the first eleven commands explicitly covering every command family. It exercises
new state updates, drain, disable, old exact replies, stale/future revisions,
same-state changed contents, state regression, database reopen, unknown edges and
modified historical requests. An independent expected projection and receipt log
are compared after every command. Every historical request is replayed again in
reverse order after reopening. The production API must retain the final mirror,
revision, non-forwarding status and immutable transaction count. This model covers
one funding context per run; existing separate tests cover multi-asset successor
handoff and provider-process faults. It is not live routed-payment evidence.

## Reproduction

```sh
cargo test -p morph-xtask
cargo test -p morph-fiber-adapter
cargo clippy -p morph-xtask --all-targets -- -D warnings
cargo clippy -p morph-fiber-adapter --all-targets -- -D warnings
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/replay-model-new-smoke \
  --seed 17 --cases 1000 --seconds 30
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/replay-model-new-long \
  --seed 332043276360 --cases 10000 --seconds 180
# Inspect a saved model input; output is the existing campaign parent directory.
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --worker store-replay --output target/fuzz-campaigns/replay-model-new-smoke \
  --replay docs/evidence/runtime-replay-model-2026-11-10/store-replay-seed-0.bin
```

Each mutation target has a separate child process with 1 MiB input, 1 GiB address
space, 8 MiB output-file and explicit CPU/wall limits. Unchanged positive seeds are
included in counts; accepted inputs are not claimed as distinct traces. This is
not coverage-guided or exhaustive model checking. The normal Rust edge test is
bounded by fixed steps and the enclosing CI job timeout, not the fuzz worker's
resource limits. Both PR workspace tests and the scheduled adapter test command
include it. The scheduled fuzz runner automatically includes the fourteenth target.
No GitHub workflow execution is claimed for this unpushed worktree.

Reports bind executable/lockfile/toolchain/corpus hashes and budgets. Saved
campaign source hashes are equal before/after the two campaigns; the adapter
source hashes are equal before/after its final full tests and Clippy. These are
explicit file scopes, not a clean-source/whole-worktree freeze. The campaign
scope was captured after the tool unit tests. The initial tool integration run
failed because its expected target count was still thirteen; it was updated to
fourteen and the complete tool suite rerun successfully. Saved final test logs
include intentional child failures for timeout and output-overwrite regressions.

Remaining #43 work includes the current payment-attempt, operation-lifecycle and
outbox-delivery models and a complete current decoder inventory. Future
re-establishment integrations should gain tests as #30 lands; they do not turn
this checkpoint into a claim that those features already exist. Existing process
kill/I/O tests remain separate from these sequential models. No disk/power-loss,
whole-authority rollback, real-node, final W1 or release approval follows.
