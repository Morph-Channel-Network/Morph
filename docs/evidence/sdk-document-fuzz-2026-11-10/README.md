# Public SDK document and receipt mutation checkpoint — 2026-11-10

Issue #43 adds two targets to the existing resource-bounded runner, now sixteen
targets. `sdk-document` uses 22 canonical public fixture cases covering all ten
current `inspection::inspect` schemas: recovery, conditional batch, root draft /
collection / funding, proposal, splice draft / funding, Factory request / transition.
`sdk-receipt` uses four detached proposal/Factory receipt fixtures through
`inspection::inspect_signature`. Other external-signer roles are not implied.

Every accepted input is decoded/re-encoded through the actual public DTO, reviewed
again and required to produce the same result. Encoding must stabilize. The
production SDK's signature/domain/context checks are used, not an alternate parser.
Unit regressions require each canonical sample to pass, missing proposal context
to fail and every zeroed detached signature to fail. Optional context ignored by
a standalone SDK review remains ignored by the harness; a stricter test-only rule
would create false positives.

| Verification | Actual result |
| --- | --- |
| Sixteen-target smoke: seed 17, 1,000 inputs/target, 30 s/target | 16,000 inputs pass; 20.609 s overall |
| Sixteen-target long: seed 332043276360, 10,000 inputs/target, 180 s/target | 160,000 inputs pass; 184.473 s overall |
| SDK document long target | 1,020 accepted / 8,980 rejected; 35.699 s |
| SDK receipt long target | 1,009 accepted / 8,991 rejected; 52.698 s |
| SDK tests + xtask tests | 23 pass |
| Scoped all-target Clippy, formatting and whitespace | Pass |

Limits are per child target, so the overall long campaign may exceed 180 seconds.
Input maximum is 1 MiB, address space 1 GiB, output file 8 MiB, CPU wall budget +
one second, with parent timeout/kill/reap. Fixed positive seeds occur every tenth
input. Counts include those seeds and do not represent unique mutations or
exhaustive protocol state coverage.

## Reproduction

```sh
cargo test -p morph-xtask -p morph-sdk
cargo clippy -p morph-xtask -p morph-sdk --all-targets -- -D warnings
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/sdk-new-smoke --seed 17 --cases 1000 --seconds 30
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/sdk-new-long --seed 332043276360 --cases 10000 --seconds 180
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --worker sdk-receipt --output target/fuzz-campaigns/sdk-new-smoke \
  --replay docs/evidence/sdk-document-fuzz-2026-11-10/sdk-receipt/seed-0.bin
```

The `sdk-document/` and `sdk-receipt/` directories preserve the exact synthetic
public corpus used. There are no user keys/journals/private child exits. Case
wrapping (`document`, `base`, `receipt`) is test-only; application formats are
unchanged. Fixture constructors and ordinary SDK tests already validate these
public samples independently of the new campaign.

Reports bind command, executable/lockfile/toolchain/corpus hashes and budgets.
The explicit SDK/package/fuzz/fixture source scope is equal before/after both
campaigns. It was captured after the scoped unit/integration tests; this is not a
whole-tree freeze or clean-source assertion. No VM, real-chain, full workspace,
release qualification or GitHub execution is newly claimed. The existing PR and
scheduled runner automatically includes the two target names.

The reconciled [boundary matrix](../../verification-boundary-matrix.md) records
remaining current API DTO, binary splice/argument and signer request/response
mutation gaps, plus private-record and service-kill coverage that still needs
qualification. The new SDK targets do not silently cover those boundaries. No
issue is closed, and real-asset permissions are unchanged.
