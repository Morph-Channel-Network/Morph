# Factory Pre-production Envelope

Effective: 2026-11-05. Mandatory review by: 2026-12-04.

This envelope authorises only a controlled, no-real-assets CKB devnet pilot of
the `morph-current-custody` profile. It does not authorise mainnet,
public-value testnet trials, externally issued xUDTs, production traffic, or a
claim that Morph is production-ready.

The canonical machine-readable policy is
[`release/factory-preproduction/envelope.json`](../release/factory-preproduction/envelope.json).
`morph-cli validate-preproduction-envelope` rejects a wider network, real
assets, unsupported Factory shapes, excessive caps, missing independent
watchtower operation, weaker reorg handling, or a policy used outside its
effective/review window.

## Approved Limits

| Boundary | Limit |
| --- | ---: |
| Network | Controlled CKB devnet only |
| Real assets | Prohibited |
| Factory signing participants | 2–16; full paths require N-of-N |
| Concurrent active factories | 4 |
| Lifetime materialised children per Factory | 10, operator-maintained admission cap |
| Children per materialisation transaction | 4, protocol bound |
| Vaults per bilateral/Factory State | 8 total |
| Capacity per Factory | 1,000,000,000,000 shannons (10,000 CKB) |
| Capacity per child/bilateral channel | 100,000,000,000 shannons (1,000 CKB) |
| Conditional transfers per batch | 8, CKB-only |
| Conditional hash algorithms | CKB Blake2b and SHA-256 |
| Maximum conditional refund horizon | 2,016 blocks |
| Total pilot capacity | 4,000,000,000,000 shannons (40,000 CKB) |
| Capacity per SponsorCell | 50,000,000,000 shannons (500 CKB) |
| Fee per sponsored transaction | 200,000,000 shannons (2 CKB) |
| xUDT scripts | `morph-devnet-xudt` only |
| xUDT types per Factory | Up to 8 within the total Vault bound |
| Raw xUDT units per Factory | 1,000,000,000,000 |
| Watchtower detection depth | At least 3 blocks |

Devnet CKB and `morph-devnet-xudt` units have no permitted monetary value.
Operators must stop the pilot if a user attempts to introduce an external
asset, exceeds any cap, or cannot establish the exact contract hashes from the
reviewed manifest.

## Factory Feature Boundary

The current family has one asset/Vault-set implementation with typed bilateral
and Factory authority. Bilateral State is 318 bytes with descriptor 5. Factory
State is 306 bytes. Full-consent Factory paths require all two to sixteen
members. Reduced rights, release, funded deposit and child materialisation use
one touched member and localized compact proofs, with global CKB reserve/business
lanes and separate per-Type token conservation. Fees and child carriers require
independent funding. All custody is bound by content and exact OutPoints.

CKB conditions are an explicit descriptor capability. Only pending CKB business
value enters the bounded Batch executor; other assets and the State carrier keep
their own settlement lanes. Its 104-byte lock identity includes channel, exact
funding context, state number and the Batch terms commitment. Each leaf chooses
one preimage or absolute-height refund resolution; conditional xUDT is excluded.

A reduced physical operation redeems committed `ReserveClaim` rights. Initial
allocation must include the intended right identities, including explicit zero
future claims, and leave enough operating reserve for every intended payout and
the retained Factory floor. The root constructor checks backing; that check alone
does not prove every arbitrary allocation is independently withdrawable. The
last retained reserve/carrier requires full-consent terminal materialisation.
Members retain complete rights data; full-consent replacements require a delivered
new snapshot. Child parties retain complete private initial exits before issuing
public possession receipts. The parent request contains no private exit signatures.

The profile excludes old wire/JSON formats, arbitrary descriptor runtimes,
conditional xUDT, unconfirmed concurrent splice chains, membership rotation and
cooperative terminal close. The latter two remain separate design work.

Those exclusions are protocol boundaries, not bugs to bypass. Unknown shapes
must continue to fail closed. Raising the participant bound or changing proof
shape requires a deliberate wire redesign, updated limits, fixtures, contract
tests, hash manifest, and independent review.

Morph Hub remains a local operator projection. Its Factory actions do not
submit CKB transactions, and `hub_chain_actions_allowed` therefore remains
false. Chain evidence comes from the devnet CLI reports and watchtower output.

## Reorg and Reset Policy

Every persisted watch cursor records the canonical hash of its last scanned
block. An uninitialised cursor hash, a missing block, or a changed hash causes a
critical `chain_reorg_detected` alert, clears orphanable observation
context, and restarts the scan from the configured channel `from_block` floor.
Operators must retain a floor old enough to cover the complete live channel
history.

Morph has no released wire to migrate. When this unpublished shape changes,
discard no-value devnet state, deploy the reviewed hashes, and create a new
Factory. See
[`runbooks/upgrade-and-migration.md`](runbooks/upgrade-and-migration.md).

## Approval and Expiry

The envelope expires unless a release owner reviews it by 2026-12-04. Any
increase requires fresh acceptance evidence and a reviewed change to both the
JSON policy and this document. CI validation is necessary but is not release
owner approval for higher limits.
