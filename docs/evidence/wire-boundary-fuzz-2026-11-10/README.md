# Splice, conditional resolution and argument mutation checkpoint — 2026-11-10

Four bounded targets extend #43's existing runner to twenty targets. No contract,
wire encoding, authority or production argument parser changed.

| Target | Corpus and acceptance invariant |
| --- | --- |
| `splice-frame` | Three current synthetic signed splice fixtures; test-only old State header prefix followed by `MORPHMS!`. Validate old context/OutPoints, per-asset conservation and actual bridge signatures, then reconstruct the frame canonically |
| `splice-flows` | Three corresponding flow tables, mutated independently of signatures; host re-encoding and host/script commitment must agree |
| `batch-resolution` | Six witnesses: 1/8 transfers, both hash algorithms, all fulfill/all refund/mixed. Test-only input_since prefix. Re-encode through the host codec, compare semantic outcome and check an independent recipient/capacity sum |
| `script-args` | Four cases selected by a test-only tag: direct StateType, Factory-child StateType, Vault and Sponsor. Parse current shape and reconstruct exact fields |

Regressions explicitly reject a changed splice transaction hash, modified bridge
signature, nonzero reserved flow bytes, wrong Batch preimage, immature refund,
relative since substituted for absolute refund and zero Factory origin. The
splice seed builder sorts detached public receipts into canonical wire key order;
its first unsorted assembly failed the existing parser and was corrected without
changing production code or accepting unsorted witnesses.

## Scope distinctions

The splice old header is normally authenticated by the actual State input. A fuzz
prefix is not a live-cell proof. This frame target does not execute the old-phase
retirement guard, input_type new-creation signatures, exact physical transaction
inputs/outputs or new recovery delivery. Those remain VM/native/ceremony tests.
Its component reconstruction preserves existing evidence bytes while rebuilding
header, manifest, signatures, flow table and framing; separate State-witness
mutation owns the inner witness roundtrip.

The Batch host resolve path delegates to shared script code, so parity alone is
not an independent calculation. The target additionally computes recipients and
checked payout sums from the decoded host batch, and has known wrong-preimage /
refund-since negatives. Acceptance is semantic resolution, not mere shape parse.
A valid resolution does not prove the transaction has the required unique outputs.

Sponsor argument parse validates the fixed layout only. This target does not
invent range constraints or equate parse success with valid fees, budgets,
capacity, change or authenticated State consumption. StateType/Vault args retain
their actual canonical origin/since/identity parser checks. Factory args and inline
Batch-lock argument validation still require explicit inventory treatment.

## Reproduce

```sh
cargo test -p morph-xtask
cargo clippy -p morph-xtask --all-targets -- -D warnings
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/wire-new-smoke --seed 17 --cases 1000 --seconds 30
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/wire-new-long --seed 332043276360 --cases 10000 --seconds 180
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --worker splice-frame --output target/fuzz-campaigns/wire-new-smoke \
  --replay docs/evidence/wire-boundary-fuzz-2026-11-10/splice-frame/seed-0.bin
```

Each target is a separate synchronous child with 1 MiB input, 1 GiB address space,
8 MiB output files, explicit CPU/wall budgets and parent kill/reap. Every tenth
input retains a valid seed. Counts are attempted inputs, not distinct mutations
or exhaustive state coverage. Seed builders use existing canonical fixture/Core
constructors; test prefixes/tags are never application formats.

Reports bind commands, executable/lockfile/toolchain/corpus hashes and budgets.
The explicit fuzz/Core/shared-script/package/fixture scope was captured before
the campaigns and compared afterward. It does not establish a clean worktree,
whole-source freeze or a new VM/CKB-node qualification. The saved public seeds
are synthetic, with no actual user keys, journals or private child exits.

The [boundary matrix](../../verification-boundary-matrix.md) retains remaining
HTTP DTO, external signer Request/Response and private-record/service-kill tasks.
No issue is closed or real-asset/release permission expanded by this checkpoint.


## Actual results

| Verification | Result |
| --- | --- |
| Twenty-target smoke, 1,000 inputs each | 20,000 pass; 22.196 s overall |
| Twenty-target long, 10,000 inputs each | 200,000 pass; 194.259 s overall |
| Splice frame long | 1,062 accepted / 8,938 rejected; 3.857 s |
| Splice flows long | 3,224 accepted / 6,776 rejected; 1.578 s |
| Batch resolution long | 2,052 accepted / 7,948 rejected; 1.888 s |
| Script args long | 3,726 accepted / 6,274 rejected; 1.520 s |
| Tool unit/integration suite | 14 pass, including deadline/replay/overwrite checks |
| Scoped all-target Clippy, formatting and whitespace | Pass |

All saved source-scope hashes agree before/after the campaigns, and both report
executable hashes match the tested binary. The unit tests were started before
that snapshot; no full unit-test source-freeze assertion is made. Existing PR and
scheduled campaign commands automatically include the new target names. No new
GitHub run, full workspace or VM test run is claimed.
