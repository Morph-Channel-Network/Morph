# Bounded verification campaigns

The Linux `morph-fuzz` tool runs deterministic mutation fuzzing against current
codecs. It is a second binary in `morph-xtask`; existing `cargo run -p morph-xtask`
commands still select `morph-xtask`. There is no JS runtime, alternate protocol
parser, coverage-guided engine or claim of full #43 completion.

## Run and reproduce

```sh
make fuzz-smoke
# A longer campaign, with a fresh output directory:
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/manual-17 --seed 17 --cases 10000 --seconds 180
# Replay the bytes retained for one target:
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --worker settlement --output target/fuzz-campaigns/manual-17 \
  --replay target/fuzz-campaigns/manual-17/settlement/current.bin
```

Output paths must be new; the runner refuses to overwrite an earlier campaign.
Replay prints whether the input was accepted. An ordinary parser rejection is a
successful replay, while a panic/invariant failure exits unsuccessfully. For a
hang or resource exhaustion, rerun the campaign with the same seed/case budget
under the parent wall-time supervisor; direct replay retains CPU/address-space
limits but does not start a second wall-time supervisor.

The algorithm is `xorshift64-mutation-v1` with explicit nonzero seed. It applies
bit/byte edits, truncation, insertion, deletion, trailing bytes, fixed-width
`0xff`, reversal and periodic maximum-size inputs. Every tenth case retains its
seed to guarantee positive coverage; those cases are not described as mutations.
Each corpus seed receives every mutation family. Counts include retained seeds.

| Target | Seed / invariant |
| --- | --- |
| `manifest` | Ordinary and conditional current manifests; host/script parse acceptance equality and exact encoding roundtrip |
| `settlement` | Ordinary and CKB conditional descriptors; host/script acceptance equality and exact encoding roundtrip |
| `state-witness` | Carrier (8-byte test prefix), current State and witness; accepted host contents must also satisfy script header/witness checks and roundtrip exactly |
| `close-frame` | Bounded current `MORPHMC!` parse, target/evidence commitments and canonical roundtrip; corpus signatures are ordinary votes, so this target does not claim close authorization or VM validation |
| `recovery-json` | Signed current ordinary/conditional packages; SDK inspection acceptance and summary match package validation for the recovery schema |
| `factory-frame` | Five current FR operation fixtures; bounded parse and transition/paired compact-proof validation; no physical transaction/VM certification |
| `factory-state` | FS root/activate/update at 2/8 assets and 2/16 members; script parse → host reconstruction → exact canonical encoding. Structural signatures are from the FM domain and do not authorize FS transitions |
| `factory-materialisation` | Signed synthetic FM at 2 assets/1 child/2 members and 8 assets/4 children/16 members with retained custody, plus 8 assets/1 child/16 members with terminal custody; full/delegated view agreement, parent signatures, public child keys, partition and exact host frame reconstruction |
| `event-json` | Current public event; accepted semantic roundtrip and stable canonical JSON encoding |
| `hub-mutation` | Current idempotency/revision context; bounded semantic validation, canonical decimal and exact roundtrip |
| `gateway-authorization` | Current public signed requirements/payload fixture; requirements at fixed time 100 and payer signature validate before/after roundtrip |
| `callback-auth` | Test framing of ID64 + request-MAC64 + event bytes; exact body/ID authentication, wrong-key and acknowledgement/request domain separation |
| `store-commit` | Current private transaction JSON; actual in-memory SQLite atomicity, exact retry, changed-intent conflict, new-effect rejection and complete projections/history |
| `store-replay` | Bounded test programs (up to 16 commands); independent reference maps versus real SQLite after every commit/delete/stale request/exact retry/conflict/read, including two-row pagination |
| `sdk-document` | 22 canonical public documents over all ten current SDK review schemas; typed re-encoding preserves review and is stable |
| `sdk-receipt` | Four canonical detached proposal/Factory receipts; SDK authorization and review remain identical after typed roundtrip; zero signatures rejected |
| `splice-frame` | Three signed fixture frames with test-only old State header prefix; per-asset conservation, context/OutPoints, bridge signatures and full canonical reconstruction |
| `splice-flows` | Same three flow tables independently mutated; host re-encoding and host/script flow commitments agree |
| `batch-resolution` | Six canonical 1/8-transfer fulfill/refund/mixed witnesses with test-only since prefix; exact host re-encoding, semantic outcome parity and independent payout accounting |
| `script-args` | Test tag selects direct/Factory-child StateType, Vault, Sponsor or Factory Type args; bounded parse and exact field reconstruction, not transaction authority or Sponsor spend validation |
| `signer-request` | Seven roles, bounded Request decode and complete validation against pinned policy/controlled input resolver; stable encoding, expiry and role/domain checks |
| `signer-review` | Same corpus; recompute the public request ID after mutation to exercise deeper review/payload checks. External policy/resolver are never taken from mutated bytes |
| `signer-response` | Seven valid role receipts; bounded Response decode, exact request/key/digest verification, stable signature roundtrip and rejection against every other role/context |
| `hub-api` | 31 structural seeds covering all endpoint JSON/SSE body roots plus public errors, tied to the closed registry; raw typed decoding (including duplicate keys), stable re-encoding, current readiness/page consistency |
| `gateway-api` | 27 structural seeds over every current registered JSON/query root plus errors; raw concrete decoding, stable encoding, query bounds, readiness/page consistency |
| `gateway-receipt` | Deterministic signed terminal receipt from a public fixture key; actual signer/intent/outer-field binding, roundtrip and wrong-signer rejection; not Biscuit access authorization |


State/witness host validation has extra semantic checks; rejecting something the
structural script parser accepts is not automatically a parity bug. Factory
samples are extracted through the current exact-transaction package validator,
then mutations exercise the frame/proof boundary. They do not replace VM or
canonical source checks. Event samples contain synthetic public identifiers only.

## Budgets and evidence

Each target runs in its own synchronous child process. Limits: 1 MiB input,
1 GiB address space, 8 MiB per output file, no core dump, requested wall time and
CPU limit one second beyond it. The parent kills and reaps a timed-out worker.
The case budget must finish; running out of time is failure, not partial success.
Limits are process limits, not performance SLOs for the deployed application.

The parent saves `report.json` with command, algorithm, seed, toolchain output,
compiled lockfile hash, executable hash, budgets, timings and per-target results.
Each successful target lists seed hashes, accepted/rejected counts and copies of
the actual corpus. Failed workers retain logs plus the last input/metadata written
before checking. Timeout during debug-file writing can leave a partial checkpoint;
retain the seed/config too, and verify its input hash before treating bytes as a
parser reproducer. There is no promise that an arbitrary failing input is minimal.
Minimize confirmed failures and add a deterministic regression with its invariant
before changing code. Do not merely add the failure to an ignored corpus.

PR CI and `make ci` run `make fuzz-smoke`: twenty-six targets, 1000 cases per target, 30 seconds each.
The scheduled workflow runs 10000 per target, 180 seconds each, with seeds 1, 17
and 332043276360. It also executes existing signer subprocess fault matrices,
exact-operation crash/reorg regressions, persistent shadow coordinator/provider
faults and runtime-store/event tests. The workflow has a 60-minute job ceiling and retains
artifacts for 30 days, including failures. Workflow authorship/local testing is
not evidence that GitHub has executed the unpushed changes.

Failures belong to the owner of the affected codec/runtime. Start from the exact
job SHA, lockfile and executable/corpus hashes. A timeout needs resource analysis;
it is not by itself a security severity. Never upload real signing journals,
private exits, keys or preimages as fuzz corpus.

## Remaining #43 scope

The twenty-target campaign covers selected API/authentication/store boundaries, not
every public DTO or persistent record schema. The complete current decoder and
declared fault-family coverage inventory still needs final qualification. Future
re-establishment integrations receive coverage as #30 lands. The store targets
use actual in-memory SQLite but do not simulate disk failure. `store-replay` is a
sequential runtime replay model, not a concurrent scheduler or a business-payment
state machine. Its `MTR1` prefix and command bytes are a private test grammar,
never an accepted application schema. Two fixed programs cover all eight commands;
mutation changes/rejects their bounded sequences. Independent maps track live
projections and all immutable rows, checking both absent and present keys after
every step. Two-entry pages check revision/ID ordering, including multiple events
in one revision. Duplicate event and attempt IDs must roll back the whole request.
Same-operation/different-effect requests must conflict even if the intent is unchanged.
Exact old requests return the original receipt without acquiring `commit_new` authority.

The FS/FM corpus is regenerated by the existing Core Factory constructors:
`MORPH_UPDATE_FIXTURES=1 cargo test --locked -p morph-core --test multi_asset factory_public_fuzz_corpus_matches_current_encoders`.
The ordinary test checks drift without rewriting files. Frames contain synthetic
public parent authorization and child public keys, never private child exit signatures.
FS mutation acceptance means structural encoding only; FM acceptance additionally
requires parent signature verification. Neither replaces exact physical-body
consensus, VM execution, private delivery or canonical-chain validation. The
delegated FM view intentionally accepts less-validated structure: only complete
parser success implies matching delegated reads, not vice versa.

Separate existing runtime-store tests inject fsync EIO and database-write ENOSPC
in real child processes. The Root and session fault modules now also inject four
I/O failures at reservation and receipt persistence: temporary-file write ENOSPC,
file fsync EIO, rename EIO and post-rename directory fsync EIO. They use a small C
interposer compiled by `cc` and loaded only into owned test callers. Every case
requires an injection-hit marker; before-reservation failure must make no external
signer connection. Recovery uses the canonical journal, including already renamed
bytes after directory-sync failure; it never restores a prior snapshot. These
application syscall failures are not power-loss or filesystem durability proofs.
Existing signer SIGKILL and runtime tests retain their own documented scope. Kernel power loss, whole
consistent authority rollback and real-node reorg qualification are distinct.
No issue, real-asset gate or release is approved by this campaign alone.

The adapter also runs a deterministic single-context edge revision model: seeds
1, 17 and 332043276360, 128 commands each, with every command family forced once.
It compares the real persistent mirror and immutable transaction counts with an
independent expected state and receipt log after each update, drain, disable,
rejection, retry or reopen. Reverse replay of all old replies must leave the
final state unchanged. It runs in the ordinary/scheduled adapter test suite,
not as a resource-limited fuzz worker. Multi-asset successor handoff and actual
process faults remain separate scenario tests. See the
[runtime/edge model checkpoint](../evidence/runtime-replay-model-2026-11-10/README.md).


## Deterministic runtime models

| Current boundary | Model execution |
| --- | --- |
| Transaction replay | `store-replay` in the twenty-target bounded mutation campaign |
| Edge revisions | Adapter tests: three seeds × 128 commands, current projection and historical reply checks |
| Payment attempts | Gateway tests: three seeds × 160 commands, eight identities, unique submit permission and immutable terminal evidence |
| Outbox delivery | Events tests: three seeds × 256 commands, lease/generation/ack, exact bytes and separate business revision |
| CKB operation lifecycle | CLI `operation_runtime` tests: three seeds × 64 observations, canonical depth/reorg, RPC failure and restart |

The latter four use seeds 1, 17 and 332043276360. Fixed prefixes force relevant
command coverage; xorshift64 then orders bounded commands. Normal PR workspace
tests include them; the scheduled workflow explicitly runs their crates/modules.
They exercise real persistence with independent expected state, not an alternate
product implementation. The operation model uses controlled HTTP RPC and one
exact cooperative-close body. One-job delivery and single-context edge models
are complemented by separate contention/handoff tests. No exhaustive scheduler,
new native chain result or whole-authority freshness guarantee is claimed.
See [lifecycle model evidence](../evidence/lifecycle-models-2026-11-10/README.md),
including the permanent payment-ID conflict found and fixed by the model.


## Boundary inventory

The [current boundary matrix](../verification-boundary-matrix.md) maps registered
HTTP types, SDK documents, binary codecs, private records and durability cut
points to their actual evidence tiers. In particular, document review coverage
does not stand in for binary splice mutation, every HTTP DTO, signer-service
Request/Response fuzzing or whole-service kill experiments.

SDK document/receipt inputs use a test wrapper containing `document`, optional
`base` and optional `receipt`. This wrapper is not an application schema.
Production review validates the actual typed payload. Only roles that consume a
base validate/re-encode it; standalone SDK reviews intentionally ignore unused
context, and the harness preserves that behavior. Samples come from checked-in
synthetic public fixtures and the canonical conditional package constructor.
No real key, private user journal or private child exit is copied into the corpus.


Splice and settlement binary samples exercise the existing shared parsers.
`splice-frame` validates bridge authority against the supplied old header; that
header is normally authenticated by the VM's actual State input. It does not
prove that a supplied prefix is a live cell, that the old phase may retire, that
new-creation signatures were executed in input_type, or that real transaction
inputs/outputs match. Those remain separate VM/native checks. The flow-only
target avoids relying on a surviving signature to exercise flow parser variations.

Batch resolution prefixes eight bytes of test input_since, covering 1/8 transfers,
both hash algorithms and mixed outcomes. An accepted semantic resolution must
preserve the original descriptor/resolution bytes and agree with independent
recipient sums. Wrong preimages and immature/noncanonical refund since are rejected.
State/Vault args enforce their canonical parsers; Sponsor parsing is only fixed
layout. A structurally accepted Sponsor argument is not evidence that a fee,
channel, state or capacity satisfies the transaction-level Sponsor policy.


## External signer mutation scope

The three signer targets select a pinned fixture case using a one-byte harness
prefix (not part of the production protocol). Each has seven canonical inputs:
Root exit/creation, Update, Splice creation/recovery/bridge and cooperative close.
The request targets use fixed time 100, expiry 150, a single permitted role and
pinned key/network/deployment. Physical inputs resolve only for the exact fixture
OutPoint sequence; synthetic capacities/genesis are independent of caller JSON.
This is controlled canonical evidence, not a new live-chain observation.

Request IDs are public hashes, not signatures. `signer-review` intentionally
recomputes them after mutation, while `signer-request` checks the raw ID. The
regression proves substituted digest/context/chain/carrier review fields pass
cheap envelope validation after rehashing but fail canonical payload review.
Responses use existing signed fixtures; close uses a documented public fixture
key. No user keys, journal authority, external signing process or network are
involved. IPC deadline/partial-frame/process-crash and authority rollback tests
remain separate. See the [signer checkpoint](../evidence/signer-fuzz-2026-11-10/README.md).


## Hub HTTP and administrative DTO boundary

The Hub target's one-byte case selector is harness framing only. It feeds raw JSON
bytes to the actual concrete Rust DTO decoder, not through `Value` first, preserving
rejection of duplicate keys in strict request/archive structures. It includes
explicit nullable fields, full-width decimal numbers, Chinese text, empty and
nested archives, current signed recovery/root/batch packages and pagination.
The corpus constructor compares covered type names with every JSON/SSE body in
`morph_hub_api::endpoints`; missing new endpoint types fail seed construction.
Text metrics and HTTP/SSE framing are separate transport tests.

Most checks here are structural: idempotent typed re-encoding and known strict
field/number rejection. `Readiness::consistent` and `EventPage::valid_for` add actual
semantic checks for those responses. The page query is fixed outside mutations
(`after: None`, limit 64). This does not validate arbitrary server requests or
replace existing authoritative package/signature/HTTP tests. Some deliberately
synthetic archive/invoice/Factory entries are decodable but not valid operations;
parsing one never authorizes restore, creates a channel or pays an invoice.
Current server archive conversion, confirmation hash, network/key and empty-state
restore policy have separate named tests in the boundary matrix.

For a scoped long run of only this new target, retain the wall-time supervisor:

```sh
mkdir target/fuzz-campaigns/hub-api-long-fresh
# Nonzero exit (including timeout) is failure; keep worker files/log.
timeout --signal=KILL 180s target/debug/morph-fuzz --worker hub-api \
  --output target/fuzz-campaigns/hub-api-long-fresh \
  --seed 332043276360 --cases 10000 --seconds 180
```

This creates a worker `result.json`, not a full campaign `report.json`. Bind it to
the executable/toolchain/lockfile from the same build's full smoke report and save
the exact command and exit status. Never report the scoped run as a new full-target
long campaign. See [Hub DTO evidence](../evidence/hub-api-fuzz-2026-11-10/README.md).


## Gateway DTO and terminal-receipt scope

Gateway corpus construction checks every JSON/query type in the actual endpoint
registry. Proxy bytes/upstream responses and metrics text are not JSON contracts.
A one-byte selector chooses the API decoder; `gateway-receipt` is raw receipt JSON
without a prefix. Query DTOs use their actual Deserialize implementation with a
small harness encoder for the current optional string limit. This checks decoded
query values, not URI percent decoding or HTTP framework extraction.

The API target is structural except for the existing readiness/page consistency
validators. Its arbitrary provider result is deliberately opaque. `PayRequest`
authorization is separately exercised by `gateway-authorization`; typed parsing
alone does not grant spend permission. Fair-exchange ciphertext, returned preimage
and access-token fields use synthetic non-operational values, not a live exchange.

The receipt target constructs a deterministic current intent and terminal receipt,
signed by a documented public fixture key. The expected signer stays outside
mutation. It runs `PaymentReceipt::validate_for_signer`, binding the signed intent,
provider evidence and receipt identity/amount/payer/resource/time fields. Changing
outer JSON fields can remain structurally valid but must fail this validator.
Credential strings in this corpus are explicitly not access tokens; signature
validation does not validate Biscuit policy or confer access. The existing
credential/service tests exercise that separate boundary.

The Gateway store also has nine consumer-codec negatives: validly encrypted
transactions containing malformed/missing/unknown/future projection data must
fail to reopen without rewriting records, revision or database bytes. This does
not simulate whole-store rollback or prove every semantic record relationship.
See [Gateway API evidence](../evidence/gateway-api-fuzz-2026-11-10/README.md).
