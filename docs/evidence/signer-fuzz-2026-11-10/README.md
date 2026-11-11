# Seven-role external signer mutation checkpoint — 2026-11-10

Issue #43 now includes three bounded targets for the current external signer
contract. They supplement the existing seven-role subprocess/IPC/journal tests;
they do not replace them or close the whole issue. The current remote #43 scope
was reread when adding this checkpoint: parser/state-machine fuzzing, actual
durability/effect faults, retained corpus and bounded CI remain its requirements.

| Target | Accepted input must establish |
| --- | --- |
| `signer-request` | Production bounded Request decode, original public request ID, complete validation under fixed external policy/resolver; stable encoding, correct role/domain and expiry rejection |
| `signer-review` | Same checks after the harness recomputes the public request ID, so mutations reach canonical payload review rather than always stopping at the outer hash |
| `signer-response` | Production bounded Response decode, valid receipt bound to the exact original request/key/digest; stable verified signature and rejection against every other corpus role/context |

Each target has seven seeds: Root exit, Root creation, Update, Splice creation,
Splice recovery, Splice bridge and cooperative close. A one-byte harness selector
chooses the fixed case; it is not a protocol format. Existing public root/update/
splice fixtures supply original receipts. Close builds a current exact settlement
transaction and signs its close digest using the known public `[1; 32]` fixture
key. No user keys or active signing authority are read or created.

Policy is constructed from the unmutated fixture: key, chain, deployment, single
allowed target, maximum 60-second request lifetime. Time is fixed at 100 and seed
expiry at 150. Physical input resolution accepts only the fixture's exact ordered
OutPoints and returns predetermined synthetic capacities and genesis. It never
uses caller-supplied resolved values. This isolates review binding, not actual
canonical-chain availability or realistic input-cell geometry.

Request IDs are public commitments, not authentication. The attacker-side ID
recomputation is intentionally local to the harness; no alternate production
decoder or relaxed validation is introduced. The deterministic regression changes
the review digest, funding context, chain or carrier refund lock, recomputes the ID,
asserts cheap envelope validation succeeds, then asserts full canonical review
rejects. Zero receipts and cross-role/context receipt reuse are rejected.

## Reproduction

```sh
cargo test --locked -p morph-xtask
cargo clippy --locked -p morph-xtask --all-targets -- -D warnings
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/signer-boundaries-smoke-20261110 \
  --seed 17 --cases 1000 --seconds 30
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/signer-boundaries-long-20261110 \
  --seed 332043276360 --cases 10000 --seconds 180
```

Use fresh output paths on repeat runs. Every target gets its own child, 1 MiB
input, 1 GiB address space and the declared wall/CPU/file budgets. Counts include
periodic unchanged positive seeds. These deterministic mutations are not
coverage-guided fuzzing or exhaustive adversarial schedules. Production request
and response limits still apply inside their own decoders (1 MiB and 4096 bytes).

`tests.log`, `clippy.log`, campaign reports and seven seeds per new target are
retained here. Explicit source/config/corpus hashes bracket the two campaigns;
that is not a clean-source freeze of the whole repository. The reports bind the
actual executable, lockfile, toolchain, seed, command and resource limits. The
existing PR smoke and scheduled workflow discover the three added targets via
the canonical target registry; no remote workflow execution is claimed.

The only dependency addition is a direct host-tool edge to the already-used
workspace `ckb-types`, for canonical fixture transaction construction. No contract
code, signing role/domain, public encoding or production parser is changed.
Remaining #43 work includes other registered HTTP DTOs, administrative archives,
private-record rejection reconciliation and the final exact-candidate evidence
join. Whole-authority rollback remains a separate #55 assumption.


## Verified results

- Tool tests: **15 pass** (8 fuzz-binary unit, 5 runner unit, 2 real campaign integration).
- Scoped all-target Clippy, formatting and whitespace checks pass.
- Short campaign: **23,000 inputs**, all targets pass, 34.973 seconds overall.
- Long campaign: **230,000 inputs**, all targets pass, 302.229 seconds overall.
- 120 explicitly inventoried source/config/corpus entries match before/after the campaigns.
- Both report executable/lockfile hashes match the actual tested binary/lockfile.

| New long-campaign target | Accepted | Rejected | Seconds |
| --- | --- | --- | --- |
| `signer-request` | 1,003 | 8,997 | 43.946 |
| `signer-review` | 1,031 | 8,969 | 57.095 |
| `signer-response` | 1,006 | 8,994 | 6.920 |


The integration suite intentionally launches a separate forced-timeout campaign
and expects every worker to fail within its one-second budget. Its printed FAIL
lines are negative-test evidence; the enclosing test result is pass. The two
qualification campaigns above completed their full budgets. No protocol defect
was discovered by this checkpoint. W1 remains active and no issue is closed here.
