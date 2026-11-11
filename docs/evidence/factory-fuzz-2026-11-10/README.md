# Factory FS/FM bounded-fuzz checkpoint — 2026-11-10

Issue #43 now includes current public FS and FM frames in the existing bounded
mutation runner. No consensus code, wire format, authority or production admission
limit changes. The existing Core constructors generate the checked-in public
corpus; ordinary tests detect drift. Private child exit signatures are excluded.

| Verification | Result |
| --- | --- |
| Thirteen-target smoke, seed 17, 1,000 inputs/target | 13,000 inputs pass, 7.414 s overall |
| Thirteen-target longer run, seed 332043276360, 10,000 inputs/target | 130,000 inputs pass, 56.556 s overall |
| Core multi-asset tests | 76 pass |
| Tool unit/integration tests | 10 pass, including real worker deadline failure/replay |
| Exact-operation regressions | 15 pass |
| Shadow adapter regressions | 37 pass |
| Scoped all-target Clippy, formatting, whitespace | Pass |

FS covers all three kinds at 2/8 assets and 2/16 members. Accepted frames must
survive script parsing, reconstruction through Core and exact re-encoding. Its
sample signatures are FM-domain signatures: structural acceptance grants no FS
authority. FM includes retained 2/1/2 and 8/4/16 asset/child/member shapes, plus
terminal 8/1/16. Complete parsing must agree with both delegated views on source,
transaction and every child. Acceptance additionally requires public key
commitments and synthetic parent signatures. A zero-signature regression proves
that a parseable delegated view is not an authority verifier.

The FM long target accepted 1,006 and rejected 8,994 inputs in 17.085 seconds.
Periodic unchanged seeds are included, not counted as distinct mutations. Neither
campaign is coverage-guided, exhaustive, VM execution or a real-node experiment.
No intended-mainnet-script or maximum proof-topology resource claim follows.

Reproduce with the commands in each report and
[the campaign runbook](../../runbooks/verification-campaigns.md). The scheduled
workflow now also invokes existing operation-runtime and adapter fault tests.
The workflow has not run on GitHub for this dirty, unpushed worktree.

`smoke.json` and `long.json` bind compiled executable, lockfile, toolchain, input
corpus hashes, budgets and outcomes. Both executable hashes match the local binary.
`source-scope.json` records relevant file hashes **after** validation; it is not a
before/after whole-source freeze or clean-candidate assertion. Logs include the
intentional failed child campaigns required by the deadline/overwrite tests;
the parent integration tests passed. `SHA256SUMS` protects these saved artifacts.

Remaining #43 work includes complete public DTO/record decoding and deterministic
payment/edge/operation/re-establishment models. Existing scenario regressions are
not a replacement for those models. Whole-authority rollback and independent or
public-network qualification remain separate. This checkpoint closes no issue,
publishes no release and expands no real-asset permission.
