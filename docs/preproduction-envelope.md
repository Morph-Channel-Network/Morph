# Factory Pre-production Envelope

Effective: 2026-11-04. Mandatory review by: 2026-12-04.

This envelope authorises only a controlled, no-real-assets CKB devnet pilot of
the `morph-v3-conditional-batch` profile. It does not authorise mainnet,
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
| Materialised child channels per factory | 10 |
| Capacity per Factory | 1,000,000,000,000 shannons (10,000 CKB) |
| Capacity per child/bilateral channel | 100,000,000,000 shannons (1,000 CKB) |
| Conditional transfers per batch | 8, CKB-only |
| Conditional hash algorithms | CKB Blake2b and SHA-256 |
| Maximum conditional refund horizon | 2,016 blocks |
| Total pilot capacity | 4,000,000,000,000 shannons (40,000 CKB) |
| Capacity per SponsorCell | 50,000,000,000 shannons (500 CKB) |
| Fee per sponsored transaction | 200,000,000 shannons (2 CKB) |
| xUDT scripts | `morph-devnet-xudt` only |
| xUDT types per Factory | 1 |
| Raw xUDT units per Factory | 1,000,000,000,000 |
| Watchtower detection depth | At least 3 blocks |

Devnet CKB and `morph-devnet-xudt` units have no permitted monetary value.
Operators must stop the pilot if a user attempts to introduce an external
asset, exceeds any cap, or cannot establish the exact contract hashes from the
reviewed manifest.

## Factory Feature Boundary

This release profile includes conservative updates, local exits,
reduced-rights updates, one-right depth-256 sparse-Merkle updates, reduced
exits, CKB/xUDT Factory Vault conservation, and conservative/reduced splice
paths. Factory membership is dynamic from 2–16 participants; reduced paths
commit the complete membership and admit exactly one touched participant's
signature. Resize witness bodies use version 2: splice-out headers sign the
participant withdrawal lock and the Vault scripts enforce the exact CKB/xUDT
payout output. The profile also binds every live bilateral and Factory Vault by
content and exact OutPoint. Descriptor version 3 additionally admits up to
eight CKB-only conditional transfers. Vault finalisation materialises the whole
Vault into the code-hash-pinned Batch Cell; each leaf is fulfilled by an exact
preimage or refunded only after its absolute block timeout. It intentionally
excludes membership outside the Factory bound, more than four multi-right
updates, conditional xUDT, arbitrary descriptor runtimes, and concurrent
unconfirmed splice chains.

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
