# W1 local acceptance and issue completion boundary

This is the closing scope for #28/#29/#31/#32/#35/#37/#43/#44/#51/#55,
under the owner's 2026-11-11 instruction. It qualifies controlled devnet with no
real assets. Independent review and public-network measurements were excluded by
the owner. Live forwarding, new GUI workflows, HSM vendors and unexposed future
endpoints are not completion prerequisites for these issues.

The candidate must pass `make qualify-local-candidate`: complete CI, the sole
native matrix, independent participant-signing lifecycle faults, two/eight-Type
cooperative close, three fixed long fuzz seeds, pinned Fiber hook tests and an
actual nonforwarding shadow service, followed by exact contract/desktop packaging
and candidate-bound evidence validation. A historical checkpoint alone cannot pass.

| Issue | Required current boundary | Executable evidence | Separate future work |
| --- | --- | --- | --- |
| #28 | Joint signability, independent exit geometry and retained floor for the **admitted** shapes | `admission.rs`, `admission_channel.rs`, `preproduction.rs` tests; full VM suite; native Factory release/deposit/children, canonical proof refresh and replays | Larger counts, real-asset scripts, arbitrary proof topology and general production admission |
| #29 | State/CAS, immutable intent and outbox in one transaction; encrypted Gateway bodies; read-only validation | `morph-runtime-store` memory/native parity, independent connections, real kills, page-full, fsync EIO/ENOSPC, schema/corruption tests; Hub/Gateway recovery tests | Migrating every future consumer or signer authority into SQLite |
| #31 | Bounded purpose-bound IPC with independent review, seven current roles, monotonic host reservations | `morph-signer` transport tests; CLI host/key process and I/O cuts; native lifecycle and close signer gates | Hardware/vendor adapters and hostile same-UID isolation |
| #32 | All **exposed** routes have canonical public DTO/error/decimal/hex contracts, checked generated schemas and Rust SDK; durable retry/revision rules | Hub/Gateway generated registry/schema drift tests; SDK transport and real Hub client tests; public DTO mutation targets | TypeScript outputs are superseded by the owner's Rust-only decision; nonexistent endpoints are not required |
| #35 | Process liveness separate from explicitly configured readiness; bounded labels, failures, age/fee/time headroom and operator responses | Hub/Gateway health tests, actual supervisor/signer probes, watcher per-resource failure tests, operation/outbox observers; native watch/reorg/Sponsor run | Generic lifecycle orchestration, RPC failover and production percentile/SLO calibration |
| #37 | Pinned hook, persistent exact-custody canonical observer/coordinator and real shadow process recovery, always nonforwarding | Fiber hook tests plus `devnet-shadow-service-e2e.sh`; Factory/splice observer and source-authenticity tests in full CI | Routed payments and provider-loss automation (#38/#40) |
| #43 | Current parser/model inventories, bounded resources, deterministic regressions and actual process durability cuts in PR/scheduled tiers | Full CI, 26 targets × 10,000 cases × 3 seeds; existing process fault/model suites; checked campaign workflow | Remote scheduled execution is not fabricated; new future consumers need their own tests when introduced |
| #44 | One source/artifact/schema identity; required gate receipts; actual report hashes, semantics and replay references; private-data-safe bundle | Current integration tools and negative tests, then a fresh complete candidate run | External attestations and deployment authorization |
| #51 | Accepted design plus explicit two-party complete terminal close, monotonic freeze, replacement/source races and preserved pending claims | ADR 005; Core and VM positives/negatives; native 2/8-Type replacements and unilateral fallback; all three Factory-child closes and Batch fulfill/refund forks | Autonomous close scheduling and a new Hub/desktop close workflow are product work, not a new prerequisite for this design issue |
| #55 | Current custody/role/conservation matrix plus executed intact-restart, corruption and whole-authority rollback dispositions | Current VM tests; Core rollback limitation tests; actual signers, native replay/watch/close and canonical shadow evidence, all bound by #44 | An external trusted freshness protocol is explicitly not claimed |

## #28: why the admitted allocation can exit

The envelope deliberately admits a smaller Factory shape than the parser ceilings:
two members, one plain-CKB Vault and one child per materialisation. Bilateral
custody uses the same current implementation, with bounded devnet token identities.
Parser maxima do not override this envelope. Maximum-dimensional VM tests remain
research evidence, not admission of their joint maxima.

For admitted Factory claims, let `C` be total Vault capacity, `F` the occupied
retained floor, and `q_i` the positive CKB ReserveClaims. Admission requires each
`q_i` to fund its actual standard-wallet output and `sum(q_i) <= C - F`.
After an authorized release `q_j`, conservation leaves `C' = C - q_j` and
`sum(remaining q_i) <= C' - F`. Thus releasing one member's committed claim cannot
spend another claim's backing or the last collective floor. The shared State
carrier is separately conserved. Actual fee inputs/child carriers are independently
funded; they are not silently taken from another member's claim.

This argument relies on the admitted fixed script/payout geometry, the saved full
rights snapshot and canonical refresh. Root commitments cannot reconstruct lost
rights data. Nonadmitted token-only/suboccupied cases have dedicated VM coverage
but do not broaden current Factory admission. Concurrent approvals remain competing
exact-source operations: the first canonical consumption wins, and survivors must
refresh against the new root. Restart/reorg cannot reset lifetime child accounting.

## #35: supported scopes and operational thresholds

The implemented observers are the protected scopes: local registry/store, Gateway
issuance/submission, signer policy, authority supervision, watch scan/publication,
outbox delivery and saved-operation history. Each reports configured/available/
fresh/ready separately. A missing coordinator capability stays unsupported or
unready; it cannot be inferred from process liveness or another green scope.
Per-operation canonical checks remain mandatory after a readiness observation.

The local experiment uses declared finite block/fee/replacement budgets rather
than invented mainnet P99 estimates. Watch readiness compares the complete fee
sequence with operator/Sponsor/capacity limits, and compares remaining challenge
time with the configured execution profile. Expired quotes, busy resources and
missing margins cannot become a positive guarantee. `service-readiness.md` defines
the fixed diagnoses and responses: restore actual signer/RPC/worker service,
fund the exact policy, reduce load or preserve the saved unilateral exit; never
reset a journal, erase an outbox or edit timestamps to make a probe green.

## #55: current capability matrix and retained assumptions

| Property | Current execution paths | Required defense/evidence |
| --- | --- | --- |
| Authentic complete custody | Ordinary/conditional finalise, splice, cooperative close, FS/FM/FR | Exact StateType/StateLock and OutPoints, complete unique Vault set; clone/missing/duplicate/wrong-source VM negatives |
| Allocation freshness | Ordinary/conditional supersession, watch correction | Higher signed state within fixed context; confirmed correction before maturity; native stale-publication correction |
| Independent asset equations | Ordinary/conditional payouts, splice, FM and physical FR | Global CKB business/reserve and per-Type quantities; no cross-Type compensation, carrier/fee claim or unlisted mutation |
| Pending claim uniqueness | Conditional settlement/close → CKB Batch | Whole-Batch fulfill/refund and absolute maturity; actual mutually exclusive canonical forks, not simultaneous double claims |
| Role/context separation | Root, update, three splice roles, Factory and close | Exact role domains/context/body; independent signer review and wrong-role/body negatives |
| Monotonic intact authority | Funding/update/splice/Factory/close journals | Reserve/fsync before key use, verified record/fsync before release; actual response loss/kill/I/O tests; no unfreeze from an empty receipt list |
| Whole consistent rollback/clone | All signing authority | Explicit unsupported threat under the selected intact, non-cloned authority assumption; executable tests demonstrate why internal consistency cannot detect it |
| Sponsor protection | Keyless watch publication | Exact fee attribution and checked per-cell bounds; actual Sponsor/reorg native run |

The corrected historical dispositions are retained: no ordinary reachable
self-referential Sponsor reset was established; high-s is rejected on the
participant verifier path; extra nonmatching funded outputs and scan-loop counts
alone did not demonstrate exploitable duplicate payouts or service DoS. No new
Critical/High absence theorem or independent audit is claimed by this test matrix.
Cooperative-close signatures remain authority after replacement/reorg; only exact
canonical source consumption settles which competing transaction won.

## Candidate and publication order

Freeze one candidate source tree and its commit, build eight scripts, capture the
manifest and schemas, then run every declared gate without source changes. Bind
node/Fiber/patch identity, actual commands, execution times, fault labels and
checksums; package the same contract and native-client outputs. Failure or changed
bytes abort qualification. A failed run is retained and a corrected source needs
a new candidate. Public evidence is reconstructed from fixed fields; keys, tokens,
preimages, private exits and active journal snapshots stay in private run storage.

Only after complete acceptance may that candidate advance to `dev` and be pushed,
with each issue linked to its actual completion record. Publishing a release/tag,
mainnet or real-asset deployment remains separate from this task.
