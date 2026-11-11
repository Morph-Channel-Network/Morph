# Exact-source publication-budget checkpoint — 2026-11-10

The existing sponsored publication dry-run now returns a bounded quote after
canonical source/dependency checks and VM preflight. It includes current initial
fee, complete configured fee ceiling, operator cap, remaining Sponsor total and
per-transaction limits, and capacity after the real change-output floor. Time
headroom excludes observed confirmations and configured reorg/failover/safety/
canonical-confirmation reserves. This is a checked observation, not an input
reservation or a measured public-network guarantee.

Passive watch scanning uses this same path for an explicitly funded Sponsor.
Automatic funding not yet performed stays `funding_not_prepared`; successful
publication invalidates the consumed-source quote. The current health schema is
v3 and readiness report v2. `publication_ready` requires complete scan coverage,
full fee-ceiling support and quotes less than 30 seconds old on both clocks (or
less than the remaining execution interval). A separate scan scope is retained.
The earlier always-false `protection_ready` field is retired, with no old reader.

| Verification | Result |
| --- | --- |
| CLI all-features | 344 unit + 3 integration tests pass; one native-event test remains explicitly ignored without its separate evidence input |
| Final watcher subset | 20 pass, including short expiry, boot changes and rejecting each insufficient fee bound even with an inconsistent ready flag |
| Clippy | All-features/all-targets and default CLI pass |
| Native CKB | Two exact sponsored quotes cover the full ceiling; two initial-fee-only operator caps correctly fail full-headroom readiness |
| Passive watcher | Live Active source produces a valid quote, catches up and does not submit a publication |
| Existing correction path | Unavailable first configured source does not stop real peer sponsored canonical correction/reorg acceptance |
| Keyless probe | Stopped service remains unready; nine distinct fixed gauges, no variable labels |

The recorded initial fees were 374,537 and 413,966 shannons, versus a configured
200,000,000-shannon ceiling. Reported execution headroom was 45 and 36 blocks under
the supplied development timing policy. These fixture values are not production
thresholds. Replacement candidates consume the same input, so their mutually
exclusive fees are not added together. Canonical consumption, failed preflight
or a changed tip requires fresh evaluation.

The exact local subset runner is retained as `native-runner.sh`; use a fresh
directory and adjust its repository path on another machine. It was invoked with
`CKB_BIN=/home/arthur/RustRoverProjects/ckb/target/debug/ckb`, RPC/P2P ports
19794/19795 and `OUT_DIR=/tmp/morph-watch-budget-native-20261110`.
Source provenance was captured before build and unchanged afterward; existing
eight ELF hashes matched the release manifest. Only the owned temporary CKB node
was stopped. Original wallet nodes and target files were preserved.

The full native report remains private. `public-budgets.json` contains allowlisted
budget fields only, not signing material or transaction bodies. `verification.json`
binds the actual executable and subset runner. The helper's provenance also
records the general native runner; it does not misidentify that larger matrix as
executed here. Post-native, only the `BudgetReason` import was gated on devnet/test
to fix the default-build unused-import lint; final default Clippy and watch tests
passed. The tree is dirty and no clean committed-candidate qualification is claimed.

Remaining #35 scope includes actual signer-policy readiness, complete business/
RBF/Sponsor metrics and calibrated operator alerts. Other W1 acceptance and exact
candidate evidence remain open. These observations do not replace intact signer
authority, latest retained recovery evidence or runtime validation. No release,
real-asset admission, independent review or issue closure occurred.
