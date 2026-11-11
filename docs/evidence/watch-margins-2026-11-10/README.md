# Watch publication margin observations — 2026-11-10

The current public assessment is `morph.watchtower_readiness.v3`; the underlying
private health remains v3. Each resource has exactly one fixed diagnosis plus an
optional canonical-decimal margin summary. Existing nine scan/publication gauges
are joined by twelve fixed reason series, quote coverage, minimum fee excess,
maximum fee deficit, minimum remaining execution time and minimum quote validity:
26 fixed series in total, no channel/OutPoint/token/path labels.

The numerical quote is accepted only after a fresh completed/caught-up scan,
consistent quote flag/limits and valid timestamps. Insufficient but coherent fee
quotes retain their positive shortfall. Missing/stopped/stale/invalid resources
have no numerical summary; an empty quoted set exports four NaNs. Minima over a
partial set never imply universal coverage, which remains independently false.

Time consumption now uses the maximum of wall elapsed time and boot elapsed plus
the quote age at capture. This preserves time already spent before the health
snapshot and prevents a slow wall clock from overstating remaining execution.
Clock/config/source changes still require re-observation. No new chain observation,
input reservation or measured public-network performance claim is made.

| Verification | Result |
| --- | --- |
| Targeted watch-config suite | 23 tests pass; final full CLI/workspace gates were not rerun for this scoped assessment change |
| Margin/coverage regressions | Healthy plus unfunded channel; mixed healthy/insufficient quote; inconsistent flag; stopped service; fixed distinct series and one diagnosis per resource |
| Clock regression | Original quote age plus boot progress consumes execution budget even when wall time barely advances; expired quote disappears |
| Existing coverage | Full-fee enforcement, schema/config/order/boot/stop expiry, independent resource failure/recovery remain passing |
| Actual keyless CLI | Retained stopped native-run health yields v3 JSON/nonzero readiness; metrics return 26 series with four NaNs; source config/health hashes unchanged |
| Static checks | Default and all-features/all-targets CLI Clippy, formatting and diff checks pass |

The CLI readback used files retained from
`/tmp/morph-watch-budget-native-20261110/scenarios/smoke/watch-service-packages`.
It did not restart that node/service, rewrite health or submit transactions.
`stopped.json`/`stopped.prom` are redacted outputs from this read, not a new native
CKB acceptance. Source hash was recorded after verification; no before/after
whole-worktree claim is made. The built CLI hash is recorded separately.

Actions and exact policy-boundary alerts are documented in the
[readiness runbook](../../runbooks/service-readiness.md). Early-warning thresholds
still need measured admitted-profile lead time; fixed reason gauges are not RBF
lifetime counters. #35 and remaining W1 qualification are not closed. No contract
rebuild, commit, push, release or real-asset approval occurred.
