# Exact-operation runtime checkpoint

This dirty-worktree checkpoint implements the first #41 adapter (cooperative
close) over the existing #29 transaction store and #34 typed outbox. It adds no
contract encoding and does not complete #41, #51 or W1.

## Executed validation

| Check | Observed result |
| --- | --- |
| CLI unit suite, all features | 324 passed |
| Operation-runtime tests within that suite | 11 passed, including one subprocess entrypoint |
| CLI integration tests | 3 passed: Gateway event delivery, native SDK/Hub, supervision readiness |
| Event library | 21 passed |
| Hub API unit / public-number tests | 5 + 4 passed; generated schema drift checks included |
| Shared packages | 4 passed |
| Gateway library / binary / protected-key process | 54 + 3 + 2 passed |
| Targeted multi-package command total | **420 passed, 0 failed, 1 ignored** |
| Ignored test | Existing native watch-event integration; not rerun in this command |
| Clippy | CLI/events/Hub API/packages/Gateway all features/all targets and CLI default features/all targets passed |
| Formatting / whitespace | Passed |
| Native close runner | Passed for two and eight devnet token Types |
| Source identity | 4,116 entries unchanged during native run; eight captured ELFs match manifest |
| Post-run recovery | Both stores validated; offline exported bytes match original transactions, with unchanged database hashes |

The 11 operation tests cover registration conflicts, single operation ownership,
restart without cached send permission, retry cadence, committed/finalised depth,
reorg/live-input and consumed-source handling, forged/missing canonical inclusion,
wrong genesis, independent depth subscribers, pending/proposed/rejected states,
offline exact export and typed/redacted/deduplicated events. One real child process
is killed **after durable broadcast intent and before RPC**; restart retains the
exact bytes, attempt count and corresponding outbox event, then reconciles instead
of immediately resending. These counts are not 11 additional tests beyond 324.

Lost send-response reconciliation uses a controlled RPC fixture returning an
error while canonical transaction data is separately available. This is not a
native TCP proxy dropping a successful node acknowledgement. Existing store I/O
fault tests and previous close-signing crash tests are separate evidence; this
checkpoint does not relabel them as new runtime fault executions.

Commands:

```sh
cargo test --locked -p morph-cli -p morph-events -p morph-hub-api \
  -p morph-payment-gateway -p morph-packages --all-features
cargo clippy --locked -p morph-cli -p morph-events -p morph-hub-api \
  -p morph-packages -p morph-payment-gateway --all-features --all-targets -- -D warnings
cargo clippy --locked -p morph-cli --all-targets -- -D warnings
cargo fmt --all --check
SCENARIO=close CKB_BIN=/path/to/ckb \
  bash scripts/devnet-external-signer-e2e.sh
```

## Native observations

The runner records 16 role attempts, 48 isolated signing-service processes and
32 distinct verified caller processes. Those are the existing signer-loss/retry
scenarios repeated against this candidate, not 48 close transactions.

| Shape | Signed bytes | Node VM cycles | First close depth | Broadcast count after orphan replay |
| --- | ---: | ---: | ---: | ---: |
| Two devnet token Types | 3,548 | 12,263,518 | 4 | 2 |
| Eight devnet token Types | 8,294 | 13,875,104 | 4 | 2 |

Both exact bodies pay 200,000 shannons from a real secp fee wallet. These are
measurements of these particular transactions, not a fixed cost for arbitrary
scripts or a new maximum-resource qualification. The asset script is devnet xUDT.

For each shape, an already canonical repeat preserves operation identity,
transaction/recovery artifact paths and broadcast count. A controlled rollback
makes the saved exact body replayable; it again reaches depth four. On a second
rollback an ordinary publication consumes the source first. The close runtime
reports `operator_action`, depth zero; the unchanged retained unilateral package
then finalises normally. Both participant journals remain byte-identical.
**The final canonical branch is the unilateral fallback**, not the two earlier
intentionally orphaned close inclusions.

Each operation store finishes with one projection and 22 immutable intents,
22 attempts and **22 typed outbox events**, at revision 22. After the harness's
node shuts down, the captured CLI exports each exact signed transaction offline.
The export reports `canonical_confirmation_checked=false`, matches the original
bytes and leaves the database hash unchanged. No raw database, key or signed
transaction is copied into this public evidence directory.

Full private run artifacts: `target/close-native-evidence/runtime-outbox-qualified/`.
`native-results.json` contains allowlisted IDs, statuses, resource values and
checks; `native-verification.json` retains harness output hashes. `verification.json`
binds code/generated-schema hashes and before/after source fingerprints. Evidence
documentation was written after the stable-source run. This is not a clean
committed candidate, full CI, a contract rebuild or a release.

## Intermediate runs and remaining scope

- `runtime-initial` stopped because an operation store inherited a writable
  repository ancestor. The implementation now requires an explicit separate private
  store; directory checks were not weakened and repository permissions were not changed.
- `runtime-private` stopped at the enforced retry cadence during very fast local
  block generation. The harness now honors the one-second delay.
- `runtime-qualified` passed the preceding runtime-only checkpoint (322 CLI tests,
  no operation outbox). It is superseded by this 324-test outbox/export checkpoint.
- An earlier full test invocation overlapped a build of its own test executable
  and reported a child-process executable lookup failure. The final integrated
  run above completed serially and passed; no production guard was bypassed.

The shared runtime currently receives fully signed bodies; Built/AwaitingSignature
and other adapters remain separate. No autonomous scheduler, generic replacement
builder, operation API/SDK/desktop integration, producer rotation or full native
lost-ACK campaign is claimed. Close replacement links still register null; old
approvals remain valid until source consumption. Native conditional-Batch and
Factory-child close cases remain open. Whole-store freshness is still the explicit
#55 assumption. No issue was closed, no commit/push/release performed, and no
real-asset scope was widened.

Design: [ADR 006](../../adr/006-exact-ckb-operations.md).
Operations: [runbook](../../runbooks/ckb-operations.md).
