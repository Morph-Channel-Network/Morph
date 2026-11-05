# Controlled-devnet experiment envelope: phase A

Effective: 2026-11-05. Mandatory review by: 2026-12-04.

Phase A defines the experiment shapes and admission obligations for
`morph-current-custody`. Final release admission is pending #22, #28, #27 and
#44. Real assets, mainnet, public-value testnet trials, externally issued xUDTs
and production traffic remain prohibited. Completing A does not close #21.

| Operating boundary | Status |
| --- | --- |
| Real assets | Prohibited |
| Production release admission | Pending phase B evidence and approval |

The canonical policy is
[`release/factory-preproduction/envelope.json`](../release/factory-preproduction/envelope.json),
schema `morph.preproduction_envelope.v2`. The validator requires explicit
protocol limits, experiment shapes, identity rules, operator obligations and
pending qualification. Missing declarations, unknown fields, the earlier policy
shape and unsupported scope are rejected; there is no migration fallback.

`morph-cli validate-preproduction-envelope --json` reports
`policy_verified: true` and `release_admitted: false` for the checked-in A policy.
This validates the policy declaration and its date window. It does not verify
the referenced ELFs, asset instances, native reports or operator records.
`make release-readiness` continues to check the policy alongside its separate
manifest and runbook checks; successful local checks do not grant final B
admission.

## Protocol limits and declared experiment shapes

`protocol_limits` mirrors the executable parsers and consensus checks. The
`factory` and `channel` sections define narrower experiment shapes, pending
final B qualification. A protocol maximum is not an admitted experiment shape.

| Dimension | Parser/consensus boundary | Phase-A experiment rule |
| --- | --- | --- |
| Factory members | 2–16; full paths require N-of-N | Exactly 2 |
| Children in one Factory transaction | Up to 4 | At most 1 |
| Factory custody | Up to 8 Vaults with independent per-Type values | One plain-CKB Vault; no token rights |
| Reduced metadata | Up to 10 touched value rights | The declared 1, 4 and 10-right cases only |
| Reduced physical changes | Up to 9 physical claims | Plain-CKB operation within the declared geometry |
| Compact proofs | Depth 256; at most 64 siblings per individual proof | The declared native profile and its aggregate proof/byte budgets |
| Bilateral custody | Up to 8 Vaults | Up to 8 Vaults; CKB and identity-pinned `morph-devnet-xudt` test instances only |

The native Factory harness uses two members, one plain-CKB Vault and one child
per transaction. It exercises 1/4/10-right updates, public proof refresh,
retained/full materialisation and child recovery. The separate native bilateral
maximum-asset lifecycle exercises eight Vaults with the devnet issuer. These
are distinct measurements. The joint **16-member / four-child / eight-asset
Factory** profile has VM fixture evidence; it has not received native
qualification or experiment admission. These distinctions are also recorded
in the policy's `joint_protocol_maxima_native_qualified: false` and
`exact_release_evidence_status: "pending"`.

The existing reports establish historical dimensions only. Dependency,
toolchain or script changes require new exact-artifact native acceptance and
budget results before B approval. A does not relabel an earlier report as
evidence for the newly rebuilt release. See
[the coverage ledger](current-protocol-coverage.md) and
[the native budget profile](devnet-smoke-budget.example.json).

## Value limits and asset identities

| Boundary | Experiment ceiling or requirement |
| --- | --- |
| Network | Controlled no-value CKB devnet |
| Concurrent active factories | 4, operator admission limit |
| Lifetime materialised children per Factory | 10, operator admission limit; no on-chain cumulative counter |
| Capacity per Factory | 1,000,000,000,000 shannons (10,000 CKB) |
| Capacity per child/bilateral channel | 100,000,000,000 shannons (1,000 CKB) |
| Total pilot capacity | 4,000,000,000,000 shannons (40,000 CKB) |
| Factory token identities/units | 0; this experiment is plain CKB |
| Bilateral test-token types | Up to 8 within the total Vault bound |
| Raw test-token units per Type per bilateral channel | 1,000,000,000,000 |
| Conditional transfers | At most 8; CKB business value only |
| Conditional algorithms/refund horizon | CKB Blake2b or SHA-256; at most 2,016 blocks |
| SponsorCell capacity / sponsored transaction fee | 50,000,000,000 / 200,000,000 shannons |
| Watchtower detection depth | At least 3 blocks; separate operator required |

A script name is not asset identity. An operator must check the exact Type
Script hash against its explicit `ValueLimitPolicy` allowlist and check that
the code identity matches the reviewed manifest's devnet issuer. Altered args
create another Type identity requiring explicit admission. External code with
the same name is not admitted. Every committed token right requires admission,
including quantity zero: zero future claims cannot bypass the identity policy.
Consequently even a zero-quantity token right is outside this plain-CKB Factory
experiment.

The policy validator checks these declared identity obligations. It does not
resolve a live token's code or certify an instance from the string
`morph-devnet-xudt`. Exact contract hashes are checked separately against the
reviewed manifest, and the live asset/dependency checks remain the native
operator's responsibility. Devnet CKB and test-token units have no permitted
monetary value. Operators must stop if an identity, cap or no-value condition
cannot be established.

## Authority, proof data, retained floor and fees

The protocol has one 318-byte descriptor-5 bilateral State and a distinct
306-byte Factory State. Custody commits complete content and exact OutPoint
sets. Full-consent paths require every member; reduced paths require the
touched member and localized proofs. Broader supported protocol capabilities
do not widen the experiment's declared shapes.

Initial allocation must precommit the intended `ReserveClaim` identities and
any zero future claims. Backing alone does not establish that each allocation
can independently fund its intended payout. Before signing, operators must
check occupied capacity, recipient payout geometry, the retained Factory floor,
the shared carrier and operating reserve. Reduced operations cannot consume
the last collective reserve/carrier; terminal materialisation requires full
consent. Child carriers and transaction fees require independent funding and
cannot be charged to another member's rights or conserved custody lanes.

Each member must retain the complete initial rights snapshot. Public localized
changes permit proof refresh from that saved data; the chain root cannot
reconstruct missing rights. Every full-consent replacement requires delivery
of a complete new snapshot before signing. Child parties persist complete
private initial exits before issuing public possession receipts. A receipt
does not prove that private data remains durably available thereafter.

The native budget profile defines named cycle, signed transaction-byte,
witness-byte and aggregate sibling ceilings, including the 1/4/10-right cases.
An individual proof's consensus sibling maximum does not bound the sum of all
proof pairs. #22 must supply fresh fee/cost evidence for the exact release
and declared geometry; A's reference to that profile does not assert that the
new artifacts have passed it. Real-asset or production approval remains closed.

## Enforcement responsibilities and remaining work

The current prepare/sign/submit paths execute `ValueLimitPolicy`, exact-request
verification and their existing chain/VM checks. They do **not** load this
envelope or automatically enforce its experiment cardinalities. The policy
therefore requires `request_shape_enforcement: "pending_exact_request_integration"`.
A verified envelope must not be presented as a runtime admission guard.

| Responsibility | Owner and current boundary |
| --- | --- |
| Parser and conservation limits | Consensus scripts; unchanged by A |
| Per-Type amount/identity allowlist, including zero quantities | Existing `ValueLimitPolicy` at native operator entry points |
| Exact request versus declared experiment shape | Native operator integration follow-up: connect the envelope to prepare/sign/submit and inspect the exact request, source/target assets, member/child counts and proof geometry before signing or submission |
| Lifetime child cap 10, active Factory and total capacity caps | Pilot operator's admission ledger; reconcile canonical creations, retries and reorgs; a single local counter or transaction limit is not a lifetime guarantee |
| Durable automatic lifetime accounting | Follow-up operator integration; not implemented by A, not an on-chain counter, and not a claim to solve #29's general persistence scope |
| Full proof/snapshot delivery and feasible reserve/carrier/fee geometry | Every signer and pilot operator before approval; policy validation alone is insufficient |
| Exact ELF hashes, toolchain and source freshness | Release rebuild/manifest and fresh acceptance workflow; A supplies no replacement hash evidence |
| Final B admission | Release owner after reviewing #22/#28/#27/#44 evidence and the remaining enforcement/operator obligations |

Morph Hub remains a local projection; `hub_chain_actions_allowed` remains
false. Old wire/JSON shapes, arbitrary descriptor runtimes, conditional xUDT,
unconfirmed concurrent splice chains, membership rotation and cooperative
terminal close remain outside the current profile. Unknown shapes fail closed.

## Reorg, reset and expiry

Every watch cursor records the canonical hash of its last scanned block. A
missing/uninitialised hash, missing canonical block or changed hash emits a
critical reorg alert, clears orphanable context and rescans from the configured
`from_block` floor. Operators must retain a floor covering the complete channel
history and retain recovery packages across funding contexts.

The format is unpublished. After an incompatible change, discard no-value
devnet state, deploy reviewed hashes and create a new Factory; see
[upgrade and migration](runbooks/upgrade-and-migration.md). The envelope expires
without release-owner review by 2026-12-04. Increasing a limit, widening a shape
or changing qualification status requires a reviewed policy change and matching
evidence. A is complete only as a declaration/validator phase; final B approval
and #21 remain open.
