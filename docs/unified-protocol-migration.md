# Unified protocol migration

Status: Option C implemented, 2026-11-05. Historical baseline:
`24484e72a20edf0fbe0344d59afdcd9af1fe9b29`.

Morph has one current custody, asset, provenance, signing and recovery family.
Bilateral channels and Factories remain distinct authority types. Ordinary
settlement, CKB conditions and reduced Factory operations are explicit
capabilities. A one-asset channel is a restricted instance of the same current
Vault-set model.

The selected scope preserves the existing business capabilities. Obsolete
State/Factory/Vault/splice codecs, public packages, backend implementations and
CLI workflows have been removed. There are no historical aliases, migration
readers, funding-anchor fallbacks or recovery-only old implementations. Reset
no-value development state after an incompatible change. The decision and its
tradeoffs are recorded in [the architecture analysis](architecture-profile-strategy.md).

## Capability and retirement record

| Boundary | Result | Verification |
| --- | --- | --- |
| Persistence | One stable sidecar lock and private fsynced atomic/event implementation | Lock contention, incomplete history and immutable-artifact tests |
| Bilateral custody | State 318, descriptor 5; CKB and one or several tokens share complete-set custody and settlement | Host/SDK parity, authentic-State/OutPoint negatives, real-node lifecycle |
| Conditional CKB | Explicit descriptor capability; shared 828-byte terms and 104-byte funding-context-bound Batch identity | Fulfill/refund exclusivity, preimages, maturity, occupied reserve and mixed-asset VM cases |
| Payments | Prepare/commit/cancel and idempotent payment metadata use the sole signing backend | Current payment, cancellation, provider-loss and settlement-evidence tests |
| Full-consent Factory | State 306; exact-body root, metadata, custody and materialisation; independent participant journals | Native root/wallet/activation/replay and child/terminal lifecycle; VM authority/conservation negatives |
| Reduced Factory | Sole current rights/release/deposit/child frame; one touched member and localized compact proofs | Host/proof/VM negatives, native withheld-consent escape and public peer-proof refresh |
| Initial recovery | Independent exact-transaction exits precede root/child approval; private child exits stay with their parties | Partial-delivery/export poisoning, restart, same-path handoff and unilateral child finalisation |
| Splice recovery | One exact-body bridge; offline future-exit export and public reconciliation of withheld receipts | Real removal/admission, asymmetric receipt, canonical handoff and terminal settlement |
| Agent/Fiber semantics | Current custody, selected asset, liquidity and context evidence | Workspace provider/bridge/adapter tests; cross-stack scripts use the same native matrix |
| Public consumers | CLI, Hub, SDK, policy and continuous watch use current packages and wire helpers | Fixtures, SDK/UI, watch configuration/service and real reorg correction |
| Retirement | Old State 346, Factory 302, physical Vault/splice and envelope-kind dispatch are not executable | Explicit old-format VM rejection and source/entrypoint inventory in the coverage ledger |
| Release | Current eight-ELF manifest, one envelope, portable watch/profile samples and deterministic bundle | Full local CI, manifest/readiness checks and independent extracted-bundle verification |

The detailed property-to-test mapping and dimensional measurements are in
[the coverage ledger](current-protocol-coverage.md). Shared cryptographic,
compact-proof and Batch-terms primitives remain because current capabilities
use them; retaining those algorithms does not retain an old physical protocol.

## Performed local verification

The [public checkpoint evidence](evidence/unified-protocol-9202e34/README.md)
contains allowlisted results, transaction measurements and the eight-ELF
manifest for the original `9202e341` run. Publication and CI follow-up commits
do not relabel that historical evidence as a different source revision.

At checkpoint `9202e341`, `make ci` passed with workspace tests, five Python
evidence-boundary tests,
current fixture generation/inspection, SDK checks, 13 UI tests, all 77 then-current
CKB-VM cases, source hygiene, lint, supply-chain checks under the existing
explicit waivers, and rebuilt manifest/envelope/runbook checks.

The development run
`target/current-protocol-e2e/current-five-case-validation-5/` completed all
five native cases on one actual node and captured the CLI and eight ELFs:

| Native case | Demonstrated behavior |
| --- | --- |
| Shared bilateral | Three independent wallet groups, retained initial exit, activation, signed progression and finalisation |
| Splice | Asset removal/admission, withheld bridge receipt reconciliation, same-path journals and unilateral closure |
| Factory | Native root and activation, retained failed/full-consent vote, reduced escape/deposit, peer proof refresh, reduced and terminal children, private exit delivery and independent child finalisation |
| Watch/reorg | Continuous service auto-funds Sponsor, corrects stale State, retains health, rescans a real truncated branch and republishes canonically |
| Eight assets | Independent funding and complete-set activation/publication/finalisation at the supported Vault-count bound |

The derived ledger contains nine scenarios, 65 exact artifact assertions and
11 audit families with no evidence errors. It records 74 distinct committed
transactions: 344,414,193 total measured cycles, 29,156,228 maximum cycles,
1,091,034 total bytes and 280,956 maximum bytes. The eight deployment
transactions account for 951,608 bytes; the five native cases account for
139,426 bytes with a 7,730-byte maximum. Deployment and operating transaction
budgets are therefore declared separately rather than treating ELF deployment
as an ordinary channel operation.

That development run truthfully records a dirty/changing tree. It is useful
native and report-integration evidence, and cannot be relabelled as clean
release acceptance. The source-freshness guard deliberately rejects it.

The independent watch-window rehearsal in
`target/current-watch-window-validation/` also passed. The native matrix uses
100,000-shannon fixed wallet fees and a 64-block test challenge window to cover
its deliberately mined stale checks and automatic Sponsor funding. Publication
still uses the unchanged dynamic estimator and 200,000,000-shannon cap; the
15 reserved reorg/failover/safety blocks and four canonical confirmations are
preserved. These are controlled test parameters, not a production window
measurement or an increase to release admission.

Two pre-alpha local package builds produced the identical historical archive hash recorded in
[the coverage ledger](current-protocol-coverage.md#independent-release-bundle-verification).
The extracted archive passed all checksums, eight ELF hashes, envelope and
relative watch/profile validation. The current publication-reliability run
also exercises real eviction/retry/reorg and service-health behavior; see
[the runbook](runbooks/current-publication-reliability.md).

## Audit closeout regressions

The `4ae2d47` closeout has 82 registered VM tests: the original 77 plus three
Factory and two Batch regressions. Reduced source replay/stale-header cases,
retained reserve below its occupied floor, and token/CKB claim substitution
have valid baselines and fresh signatures before asserting the intended VM
error. Batch tests cover incorrect state/channel/context lock identities and
six payout-shape mutations with exact errors; the earlier capacity-mismatch
case is strengthened rather than counted as previously absent coverage.

Hub model metadata and the UI fallback now use `morph-current-custody`; the
Rust response uses the release profile constant. Documentation distinguishes
new signing expiry from reconciliation of already issued authorization, and
qualified reduced exits from complete Factory liquidation. Eleven unissued
script-error variants and their CLI name mappings are retired with numeric
slots reserved; all active error numbers are unchanged. The rebuilt eight ELF
hashes still match the existing release manifest. Wire formats and active
consensus rules are unchanged. The original checkpoint evidence remains
historical; new-head validation is reported by the PR's exact-head checks.

## Alpha recovery closeout

Version 4.0.0-alpha.1 adds private Unix directory/file permission enforcement,
N=2/3/16 independent Factory journal and real process-exit tests, exact private
child delivery checks, and offline root recovery despite a withheld creation
receipt. Canonical confirmation supplies the authentic missing peer approval
without cloning or resetting the participant journal.

The current native matrix explicitly orphans and replays signed root and
Factory transactions without new participant votes, publishes one/four/ten-right
updates, and exercises all-member retained materialisation before terminal
parent retirement. It derives ten stateful scenarios. Two additional VM
negatives isolate false Factory Type/StateLock authority and checked u128
group overflow, bringing the registered VM count to 84. No contract implementation
or wire format changes accompany these host/recovery/test fixes.

The issue/acceptance map, reproduction steps and release boundaries are recorded
in [the alpha release record](releases/v4.0.0-alpha.1.md). Current source-bound
CI/native artifacts and fresh package digests are published with that prerelease;
the `9202e341` checkpoint and its reports remain unchanged historical evidence.

## Clean candidate acceptance

Run the complete matrix from a clean committed tree with no fixture-writing
flag and a fresh directory:

```sh
CKB_BIN=/path/to/ckb \
  OUT_DIR=target/current-protocol-e2e/candidate \
  scripts/devnet-current-e2e.sh
```

Before building, the runner immutably records HEAD, tracked/untracked
implementation state and a source digest. It freezes its CLI and ELFs, retains
actual native reports, derives the ten current evidence scenarios, then checks the
finite deployment/operation/proof budgets, audit families and source freshness.
Post-run captures, changed source, dirty authority implementations and old
artifacts cannot be restamped as clean. Only a completely successful run updates
`target/current-protocol-e2e/latest`; default report/assert commands use that
single location. All earlier smoke/e2e/stateful script entrypoints delegate to
this one implementation.

## Remaining boundaries

A Factory member needs current rights/proof data and an executable admitted
claim/payout geometry. Physical reduced operations consume ReserveClaim rights;
metadata balances do not implicitly become withdrawal claims. Reduced operations
retain the occupied Vault floor and collective State carrier. Full-consent
materialisation can retire that remainder while creating independent children.
Do not claim that a member can unilaterally withdraw every last shannon.

No fresh complete external Fiber/Bruno stack was run in this migration. The
adapter/provider tests and current cross-stack scripts are migrated; real shared
RPC, Fiber receipts and routing acceptance remain a separate integration gate.
Independent operators/RPC failover, production timing and fees, arbitrary asset
scripts, trusted rollback resistance and external review remain readiness work.

Bilateral cooperative terminal close and Factory membership changes were
unimplemented design candidates before migration and remain separate decisions.
This migration does not turn them into implemented capabilities. Real assets
remain prohibited under [mainnet readiness](mainnet-readiness.md) and the sole
current controlled-devnet envelope.
