# Multi-Asset Channels

Status: proposed production implementation direction, 2026-11-02. This document
records the paper-to-code gap and recommended implementation sequence. It does
not define an accepted wire encoding or claim that current scripts support
multiple xUDT types in one channel.

## Decision

Remove the architectural restriction to one xUDT type per channel. Use one
signed State track to control a bounded set of physical Vault Cells, with
canonical settlement outputs and independent accounting for each asset.
Asset-count, Vault-count, output-count, witness-byte, and execution limits must
remain explicit and measured. The protocol should support multiple registered
xUDT types; operators may admit a smaller set through value-limit policy.

## Paper and Current Implementation

The [paper source](https://github.com/a19q3/Research/blob/3c202ea30ad88c145dbcdba2513363cf09c81923/morph_channel/paper.tex)
defines a funding bundle containing a channel identity Cell and a Vault set
(section 5, Stable Funding Bundle). Vault validation checks membership and
complete-set consumption/evidence before finalisation (section 6, Vault Lock
Semantics). Partition conservation treats each xUDT type separately, identified
by its canonical full Type Script identity (section 9).

These rules support a multi-asset construction. They are not a byte-level
implementation or a ready-made production asset profile.

| Layer | Current code | Gap |
| --- | --- | --- |
| Host registry and accounting | `AssetRegistry.xudt_types` is a set; `PartitionTotals` uses maps keyed by Type hash. | Reuse the model, but make its accepted shape agree with the new script profile. |
| Factory rights | `FactoryRightId.asset_type` identifies the asset; kind 8 checks non-increase separately for each asset. | Rights express multiple assets, but do not establish custody or multi-asset child settlement. |
| Bilateral settlement | `BilateralCkbXudtSettlementDescriptor` v2 has one `xudt_type_hash` and two participant outputs. | Add a canonical multi-asset output descriptor. |
| Vault authority | `validate_current_vault_commitment` rejects a second group input and binds one content hash and exact OutPoint; State retirement finds one matching Vault. | Bind and verify the entire Vault set in both Vault and State scripts. |
| Splice and Factory reserve | Fixed descriptors have two asset slots; physical Vault paths admit CKB plus at most one xUDT type. | Version the descriptor, delta, reserve, and materialisation paths together. |
| Conditional settlement | Descriptor v3 and Batch Lock settle only CKB. | Add typed conditions after ordinary multi-asset settlement has complete recovery evidence. |

The decisive restriction is physical custody and settlement. An ordinary xUDT
Cell has one Type Script; putting more Type hashes into a registry or increasing
an array bound does not let that Cell hold several independent xUDT types.

## Proposed Construction

### Vault Set and Provenance

Start with one Vault per admitted xUDT type and, if needed, a plain CKB Vault.
A typed Vault also holds CKB capacity, which must be accounted for separately
from its token quantity. Keep one authentic live State Cell for the channel.

Commit a canonical bounded manifest of Vault contents at funding time. Every
entry binds its asset identity, lock hash, optional Type hash, capacity, and
data commitment. Define a strict order and reject duplicate assets or entries.
After funding commits, activate against the complete canonical set of direct
CellDeps and bind the exact OutPoint of every Vault. Preserve the two-stage
activation rule: funding cannot sign its own final transaction hash.

Keep content identity and exact provenance as distinct commitments. Define new
domain-separated set commitments and a versioned State representation; do not
reinterpret the existing single-Vault `vault_materialisation_root` or
`vault_outpoint_commitment` in place. Existing profiles retain their encodings.

### Settlement and Capacity

A multi-asset descriptor derives outputs by participant, asset identity, role,
capacity, and amount. It must bind exact lock and Type Script identities and
canonical output placement, reject duplicate output attribution, and define
zero-balance handling. Each typed payout needs its own sufficient capacity.

Check the following lanes independently:

- business CKB;
- each registered xUDT Type's quantity, using checked arithmetic;
- channel reserve and explicitly authorised reserve refunds;
- State carrier capacity and its refund;
- sponsor capacity, whose deficit alone pays publication fees.

Splitting one typed Vault into two participant payouts can require more
occupied capacity. Allocate that reserve in the signed funding/settlement
configuration. Reject underfunded configurations before participants accept a
state. Any later reserve increase needs explicit funding authorisation; it
cannot silently consume business balances or sponsor change.

For the first profile, finalisation consumes the entire committed Vault set
atomically, checks the challenge delay and authentic StateType/StateLock, and
retires the State only after every Vault and every expected payout is
accounted for. A partial-set exit must fail. Staged exits would need a separate
remaining-value authority and are outside this first profile.

### Updates, Splice, and Factory

Ordinary updates preserve the registered asset set, Vault content set, and
exact provenance. Adding/removing an asset or changing funded quantities needs
an explicit signed re-anchor/splice with a new funding context. The new bridge
must verify old-set consumption, signed per-asset deltas, new-set creation,
withdrawal locks, and subsequent whole-set activation.

Factory reserve custody and child materialisation need the same set semantics.
Begin with all-participant authorisation. Extend reduced exits/splices only
when proofs cover every touched asset/right and establish non-interference
for untouched rights and reserve. Existing kind-8 quantity non-increase is
per asset and single participant; it does not authorise arbitrary cross-party
trades or mint one asset by burning another.

### Versions and Recovery

Introduce explicit descriptor, State-layout, Vault-args, and witness versions
where interpretation changes. Freeze their exact bytes only after the design
and budget review. Update matching host/script domains, parity tests, fixtures,
schemas, deployment hashes, and release manifests together. Keep old packages
decodable under their original profile; fail closed on unsupported new shapes.
Moving an existing channel requires an authorised migration/re-anchor or a
close and reopen, not a parser upgrade alone.

CLI, SDK, Hub, and watchtower packages must retain the full asset registry,
Vault manifest, exact OutPoints, descriptor, signatures, dependencies, and
funding context needed to reconstruct unilateral settlement. Test recovery
after restart and canonical-chain reorganisation for the entire set.

## Delivery Sequence and Acceptance

| Step | Deliverable | Acceptance evidence |
| --- | --- | --- |
| 1 | Wire proposal and executable host invariants. | Canonical encoding, host/script hash parity, bounded sizes, and explicit capacity allocation. Choose numeric profile limits from measured worst-case budgets. |
| 2 | Directly funded bilateral multi-asset channels. | CKB plus at least two distinct xUDT types through fund, activate, publish, supersede, and unilateral full-set finalise; balanced and one-sided payouts for every asset. |
| 3 | Multi-asset splice and Factory custody/materialisation. | Signed asset admission/removal and deltas, full-authority Factory exits, then separately evidenced reduced paths. Unsupported combinations remain rejected. |
| 4 | Recovery tooling and release candidate. | CLI/SDK/Hub/watchtower round trips, durable packages, restart/reorg recovery, devnet/stateful reports, reviewed ELFs, and independent review. |
| 5 | Conditional xUDT extension. | Asset-bound preimage/refund leaves, typed Batch custody and payouts, capacity budgets, and independent force-resolution evidence. |

Required negative cases include missing or extra Vaults; substituted
byte-identical Vaults with different OutPoints; duplicate manifest entries;
mixed channels or funding epochs; partial State retirement; unregistered or
wrong Type Scripts; swapped asset amounts; per-type minting masked by burning
another type; overflow; insufficient payout capacity; duplicate output use;
reserve/carrier leakage into fees or sponsor change; stale pre-splice
packages; malformed set proofs; and missing recovery data.

Before fixing limits, record transaction bytes, witnesses, CellDeps, CKB-VM
cycles, occupied capacity, and fee-bump headroom for the largest accepted set
and its worst-case payout shape. Run the existing local gates plus the new
contract and devnet/stateful scenarios. Production approval also requires the
evidence in [mainnet readiness](mainnet-readiness.md).
