# Implementation Notes

These notes describe the current Morph Channel implementation: protocol
objects, script boundary, factory witness envelope, and invariant coverage.

The important point is that the repository has one protocol story expressed in
three places:

```mermaid
flowchart LR
    P["Protocol model<br/>morph-core"] --> C["Package tooling<br/>morph-cli"]
    P --> S["CKB scripts<br/>contracts/*"]
    C --> S
    S --> R["Devnet reports<br/>smoke + stateful evidence"]
    P --> T["Invariant tests"]
```

`morph-core` defines the executable model. `morph-cli` turns model objects into
reviewable packages and devnet transactions. The CKB scripts enforce the narrow
on-chain boundary. Reports prove that those layers agree on real local
transactions.

## Security Boundaries

Morph Channel splits authority into three boundaries:

| Boundary | Owner | What it protects |
| --- | --- | --- |
| State authority | Participant signatures | Which state number and settlement descriptor are current. |
| Value authority | Vault scripts | Whether channel-owned CKB/xUDT can be released. |
| Fee authority | Sponsor scripts and operator policy | Whether sponsor capacity may pay publication costs. |

```mermaid
flowchart TB
    A["Participants sign StateHeader"] --> B["State Cell"]
    B --> C["Vault lock checks current settling state"]
    D["Sponsor Cell"] --> E["Sponsor lock pays bounded fee"]
    E --> B
    C --> F["Settlement outputs"]
```

Sponsor capacity is not channel value. Sponsor scripts can help publish a
state, but they cannot rewrite vault settlement or drain participant assets.

## Protocol Objects

| Object | Where it lives | Role |
| --- | --- | --- |
| `StateHeader` | script-common, CLI, core | Signed channel state header with funding epoch, funding anchor, vault-set/content and exact-OutPoint commitments, state number, phase, and settlement descriptor commitment. |
| `BilateralSignatureWitness` | script-common | Two sorted participant public keys and signatures over the state digest. |
| `SpliceStateTransitionWitness` | script-common, CLI | Bounded resize/re-anchor body proving an old funding context can move to a new one. |
| `FactoryStateHeader` | script-common, CLI | Factory state pointer: factory id, update number, state root, participant commitment, access-manifest root, non-interference digest, challenge policy, and exact FactoryVault content/OutPoint commitments. |
| `FactorySpliceHeader` | core, script-common, CLI | Signed Factory resize bridge binding state/access-root progress, reserve deltas, non-interference, and the old/new materialised FactoryVault Cells. |
| `FactoryRight` | script-common, core, CLI | Fixed-layout representation of a participant right such as balance or reserve claim. |
| `WitnessEnvelope` | script-common, CLI, factory scripts | Factory authorisation envelope: kind, flags, body length, and body digest. |
| `SponsorPolicy` | script-common, CLI | Script-level sponsor fee policy. |

Names ending in `current` usually identify a fixed-layout body schema. They are not
a claim that the current factory witness boundary is the old current boundary.

In the current devnet profile, `funding_anchor` means the signed funding anchor
identity. It is derived in a Type-ID-style way from the first funding input and
the State Cell output index, and it is not a live output locator. This is the
devnet funding-anchor profile; a mainnet-track profile should add live Fund Cell
uniqueness checking before treating the anchor as deployment-grade identity.

Tooling derives `funding_context_id = H("CKB_MORPH_FUNDING_CONTEXT",
chain_id, channel_id, funding_anchor, vault_set_commitment,
vault_outpoint_commitment)` from the signed State Header context. This
identifier is an integration and audit key for one exact materialised funding
context. It is not an additional consensus field. It deliberately omits
`funding_epoch`: exact-context uniqueness rests on the OutPoint commitment,
while the signed epoch remains a monotonic engineering namespace for logs,
package construction, recovery, SDKs, and indexers. The epoch is therefore not
the minimal anti-replay primitive, but it remains consensus-checked in the
current wire profile.

The stable user/integration identity is `channel_id`. The current funding
object is identified by `funding_context_id`, and `funding_epoch` is its signed
generation label. A user-facing resize or re-anchor changes the latter two
while preserving `channel_id`. Source code, packages, CLI commands, and witness
kinds retain the historical `splice` name; changing those identifiers would be
a separate wire/API migration rather than a documentation synonym.

The current public mode surface is intentionally narrow. Host code names the
implemented modes `BilateralPlain` and `FactoryProof`; the signing and fixed
wire profile uses mode bytes `1` and `2`. These correspond to the paper's
current `bilateral_plaintext` profile and the implemented factory
commitment/proof profile. Directly funded initial states use mode `1` and must
carry bilateral consent. Child states materialised by a Factory exit use mode
`2` and must carry an exact local/reduced-exit envelope; the mode is preserved
when the child later advances under its bilateral participant signatures.
Bilateral commitment mode is reserved and is not emitted by current package or
devnet flows.

The host `Phase` enum is wider than the on-chain State type phase byte. Current
State scripts accept only `Active` and `Settling`; `Funding` and `Closed` are
local lifecycle labels used by the host node and Hub after opening and after
finalisation. Factory progression is tracked by `FactoryStateHeader.update_number`,
not by a `Phase::FactoryActive` value.

Initial funding approval is enforced on chain. In addition to canonical anchor
derivation, active phase, state number zero, lock/type binding, and capacity
shape, the funding input carries a bilateral signature witness over the complete
initial `StateHeader`. This binds the descriptor, asset registry, challenge
policy, participants, and materialised Vault before the channel exists. The
State type also requires exactly one transaction output whose lock, type,
capacity, and data hash to `vault_materialisation_root`; missing or ambiguous
Vault materialisation is rejected. Creation leaves
`vault_outpoint_commitment` zero because the funding transaction hash is not
known until the transaction is committed.

Initial Factory creation follows the same rule: the canonical factory-id input
carries a full Factory signature envelope over update zero. Reduced or local
proof kinds cannot be used to authorise creation. The signed
`FactoryStateHeader.vault_materialisation_root` commits the unique FactoryVault
output's lock hash, capacity, optional type hash, and data. Ordinary Factory
updates must preserve this root; local/reduced exits and full/reduced splices
must materialise old and new FactoryVault Cells matching the signed roots. The
Factory type and Factory vault lock enforce the binding independently.
Splice-created successor channels continue to use the separately signed splice
bridge instead of a second redundant initial-state signature.

The content root is paired with an exact provenance locator. After funding or
any reserve-changing transition, an activation transaction consumes only the
unbound State/Factory Cell, preserves every other header field and its lock,
and sets:

```text
vault_outpoint_commitment =
  H("CKB_MORPH_VAULT_OUTPOINT_V1", vault_tx_hash, u32_le(vault_index))
```

The referenced Vault must be the first raw/direct CellDep and its resolved
content must match `vault_materialisation_root`. Requiring a direct canonical
position avoids confusing a DepGroup member with the named Vault. Later
updates preserve the locator; finalise, splice and Factory exits must consume
that exact OutPoint. Reserve-changing successors return to the unbound state
and must be activated before further use. Byte-identical clone Cells therefore
cannot substitute for the committed bilateral or Factory Vault.

## Script Boundary

### Current Asset Boundary

The host model represents multiple xUDT types through `AssetRegistry`,
per-type conservation maps, and asset-qualified Factory rights. The legacy
script profile is narrower: descriptor v2 names one xUDT type, and bilateral
and Factory provenance bind one physical Vault Cell. Splice and Factory Vault
descriptors have two asset slots, with physical paths limited to CKB plus one
xUDT type. Descriptor v3 conditional batches are CKB-only.

The [candidate multi-asset profile](multi-asset-wire.md) now implements a
separate 318-byte State layout, 1–8 Vaults, whole-set activation and retirement,
per-asset settlement, occupied-capacity evidence, CLI/SDK recovery, durable
bilateral signing sessions, Hub import/export, and canonical dispute-watch
passes with reorg recovery. Multi-asset splice, Factory custody, conditional
xUDT, and multi-channel watch service orchestration remain work tracked by the
[multi-asset channel design](multi-asset-channels.md).

```mermaid
flowchart LR
    subgraph State["Channel scripts"]
      SL["morph-state-lock"]
      ST["morph-state-type"]
      VL["morph-vault-lock"]
      BL["morph-batch-lock"]
      SP["morph-sponsor-lock"]
    end
    subgraph Factory["Factory scripts"]
      FT["morph-factory-type"]
      FVL["morph-factory-vault-lock"]
    end
    X["morph-devnet-xudt"] --> VL
    ST --> VL
    VL --> BL
    SP --> ST
    FT --> FVL
```

### Channel Scripts

`morph-state-type` owns State Cell progression. It accepts canonical initial
state creation, newer signed state publication, settling progression, and the
State Cell side of splice transitions.

`morph-state-lock` keeps State Cell spending tied to the expected state type
script. Transition rules remain in the type script.

`morph-vault-lock` owns channel value. It finalises only against an authentic
current settling State Cell with a matching descriptor commitment and matured
relative `since`. It also verifies the vault side of splice transitions.
Vault Cells remain unchanged during ordinary off-chain state exchange and
ordinary State Cell publication/supersession. They are consumed at explicit
value boundaries: finalisation, resize/re-anchor, and Factory
exit/materialisation paths. A resize successor is a newly committed Vault, not
the same Vault left untouched for the full logical channel lifetime.
The v1/v2 bilateral finalisation profiles are atomic. Descriptor v3 instead
materialises the whole CKB Vault into one code-hash-pinned Batch Cell when any
condition remains; `morph-batch-lock` later verifies every preimage/refund and
the exact two participant outputs.
Cooperative close is not part of the current State type, vault contract, CLI,
host operation taxonomy, or devnet execution profile.

`morph-sponsor-lock` pays only bounded publication fees for admitted channel
state numbers and clean sponsor change.
It does not sponsor funding, finalisation, splice, materialisation, or
cooperative close transactions in the current profile.
The v1 devnet operator default is `min_state_number=1` and
`max_state_number=2^20`; stateful reports flag sponsor policies wider than that
audited default window.
Sponsor policies do not carry a script-level expiry field in the current wire
profile. Finite sponsor windows are operator/watchtower policy, not a
sponsor-lock consensus rule.

### Factory Scripts

`morph-factory-type` owns one-live-FactoryStateCell progression. It verifies
conservative full-participant signatures, local-exit evidence, reduced-rights
proofs, sparse-Merkle updates, reduced exits, factory splices, and
reduced-splice bodies.
New FactoryStateCells use `morph-state-lock` bound to the exact FactoryType
script hash. The operator key funds fees through an independent secp input; it
does not control or co-authorise the FactoryStateCell. Reduced reserve-claim
exit construction needs the exiting participant's private key and every other
participant's compressed public key, not their secrets.
Value-bearing factory materialisation consumes and recreates the parent Factory
State Cell with updated roots; read-only `unchanged_reference` materialisation
is not part of the current conservative contract profile.

State and FactoryState carrier capacity is a protocol boundary. Ordinary
updates preserve it exactly. An unbound carrier reserves 10,000 shannons for
the deterministic Vault-OutPoint activation transaction; activation consumes
exactly that reserve, while splice and Factory exit create the next unbound
carrier with exactly the same reserve added. This prevents a valid state proof
from being reused as authority to drain unrelated carrier capacity.

`morph-factory-vault-lock` owns factory reserve conservation. It ensures a
factory exit or splice changes the FactoryVaultCell exactly as the factory
evidence permits.

The current executable Factory signature profile supports 2–16 sorted,
commitment-bound participant identifiers/public keys. Conservative creation,
updates, local exits, and full splices require N-of-N signatures. Reduced
rights, sparse-Merkle, reduced-exit, and reduced-splice paths still commit the
complete participant set but require exactly one signature from the touched
participant. Counts outside 2–16, threshold subsets on full paths, duplicate or
unsorted identifiers, duplicate public keys, and unknown witness shapes fail
closed. The sparse-Merkle depth and reduced right-count limits remain fixed.

### Factory Liquidity Movement

Factory liquidity has two distinct kinds of change:

- a **rights delta** changes who can claim value inside the Factory while the
  FactoryVault assets remain unchanged;
- a **vault delta** changes the assets held at the Factory boundary.

Cooperative rights deltas can remain off chain as signed Factory state. The
current conservative update requires N-of-N signatures. Bounded reduced-rights
and sparse-Merkle paths admit only the implemented local proof shapes; locality
alone is not economic authority. General multi-right rebalancing therefore
falls back to full signatures and remains a future reduced-proof family.

Vault deltas are on-chain. Adding/removing Factory funds uses full or reduced
Factory resize (`factory splice`) evidence. Materialising a child and local or
reduced exit also consume/recreate the parent Factory state and bind the exact
FactoryVault/child-vault changes. Cooperation may keep internal accounting off
chain, but crossing the Factory boundary, materialising a child, or enforcing
an exit/dispute requires a CKB transaction.

### Factory Local Exit Lifecycle

Factory local-exit evidence is one-shot evidence for materialising a child
channel from factory reserve rights. The embedded child State header must be
`state_number=0` and `Active`: the factory transition creates the child channel's
initial enforceable state, after which ordinary child-channel publish,
supersede, splice, and finalise rules take over. Later child states are not
authorised through another local-exit proof; they are authorised by the child
channel's own participant signatures and state-number progression.

The factory type script does not reconstruct the child participants from the
materialised output. The binding is indirect and signed: the local-exit or
reduced-exit evidence commits the exact child State header, including its
`participants_commitment`, settlement descriptor commitment, descriptor version,
lock hash, and vault shape. `morph-factory-type` then requires the output State
Cell bytes to equal that committed header, while the child State type enforces
the participant signature set for later state progression.

Ordinary supersede may advance state number, phase, and the participant-signed
settlement descriptor commitment, but preserves the descriptor version and
materialised Vault root as funding context. Splice has a separate
`state_context_matches_splice_next` rule for the old/new funding-anchor bridge
and is the only transition that may replace the materialised Vault root, while
additionally binding the successor payload to the signed splice header.

## Resolution And Packages

The paper's `ResolvedStateContext` is an audit abstraction. The implementation
does not allocate one shared Rust struct with that name; it resolves commitments
at the boundary that needs them:

- fixed-layout State Header and witness parsers live in `morph-script-common`;
- `morph-state-type` verifies the State Cell progression context and
  participant signatures;
- `morph-vault-lock` parses descriptor witnesses and checks settlement outputs
  against the committed descriptor;
- `morph-batch-lock` resolves bounded descriptor-v3 leaves against preimages
  and canonical absolute-block refunds;
- `morph-sponsor-lock` checks the publication State type hash and bounded
  sponsor policy;
- `morph-factory-type` and `morph-factory-vault-lock` resolve factory envelopes,
  local-exit descriptors, rights proofs, and vault descriptors for the admitted
  factory branch.

The bilateral `StoredStatePackage` used by the CLI stores the signed State
Header bytes, bilateral signature witness bytes, channel id, funding anchor,
derived funding context id, state number, signing digest, source State
outpoint, and descriptor commitment/version metadata. It validates signatures
and metadata before write and read. Latest-package selection is by channel id
and state number. Watchtower re-anchor handling requires the exact derived
funding context id; funding-anchor-only matching is rejected. The broader paper `StatePackage`
object is the protocol requirement for
arbitrary representation profiles; the current bilateral devnet package is the
implemented plaintext profile.

`StoredConditionalBatchPackage` additionally stores the channel/funding/state
binding, canonical descriptor, force-resolution witness, input `since`, and
expected capacities. CLI and Hub revalidate the package from semantic fields;
Hub will not import it for a stale or unknown live channel context.

## Factory Witness Envelope

Factory authorisation uses `WitnessEnvelope`.

```mermaid
flowchart LR
    V["version"] --> K["kind"]
    K --> F["flags"]
    F --> L["body_len"]
    L --> D["body_digest"]
    D --> R["reserved"]
    R --> B["body bytes"]
```

The scripts verify the envelope first, then dispatch by `kind`.

```mermaid
flowchart TB
    E["WitnessEnvelope"] --> H["Check version, flags, length, digest"]
    H --> K{"kind"}
    K --> A["all-participant signature body"]
    K --> B["reduced-rights body"]
    K --> C["sparse-Merkle update body"]
    K --> D["reduced-exit body"]
    K --> F["local-exit body"]
    K --> G["factory-splice body"]
    K --> I["reduced-splice body"]
```

This design separates the public authorisation surface from body schemas. The
body may remain fixed-layout while the outer witness explicitly states which
factory path is being authorised.

## Channel Business Flow In Code

```mermaid
sequenceDiagram
    participant A as Alice
    participant B as Bob
    participant CLI as morph-cli
    participant CKB as CKB devnet
    A->>B: exchange signed state updates
    B->>CLI: save latest state package
    CLI->>CKB: publish StateCell with sponsor capacity
    CKB->>CKB: state-type verifies signatures
    CLI->>CKB: finalise VaultCell after since
    CKB->>CKB: vault-lock checks current settling state
```

The same pattern appears in tests and devnet smokes: construct evidence,
publish evidence, assert that scripts accept the valid shape and reject the
attack-shaped variants.

## Invariant Coverage

| Risk | Representative coverage |
| --- | --- |
| Stale state publication | `rejects_stale_or_equal_state_number`, state type negative tests. |
| Signature forgery | host invariant tests, script-common signature tests, state/factory script tests. |
| Vault settlement drift | vault-lock tests and devnet finalisation smokes. |
| State carrier capacity leakage | `rejects_state_carrier_capacity_leakage`. |
| Sponsor fee drain | sponsor-lock budget and clean-change tests. |
| Fake StateHeader bytes | script tests require authentic State Cell type identity. |
| Splice value loss | splice invariant tests, script bridge tests, devnet splice negative smokes. |
| Factory right interference | reduced-rights and sparse-Merkle update tests. |
| Reserve release mismatch | reduced-exit host, script, and devnet smoke coverage. |
| Witness envelope tamper | `WitnessEnvelope` parser and factory script negative tests. |

The latest security baseline is the
[2026-08-15 swarm audit](swarm-audit-glm-2026-08-15.md); current remediation
status and negative-path evidence are recorded in
[SECURITY-FIXES.md](../SECURITY-FIXES.md). Devnet assertion gates are described
in [devnet.md](devnet.md).

## Where To Inspect The Code

```text
crates/morph-core/src/types.rs          protocol structs
crates/morph-core/src/hash.rs           signing and commitment domains
crates/morph-core/src/validation.rs     host-side invariants
crates/morph-core/src/conditional.rs    bounded conditional batch model
contracts/morph-script-common/src/lib.rs fixed-layout parsers and verifiers
contracts/morph-state-type/src/main.rs  State Cell rules
contracts/morph-vault-lock/src/main.rs  Vault rules
contracts/morph-batch-lock/src/main.rs  conditional CKB resolution rules
contracts/morph-factory-type/src/main.rs Factory State rules
contracts/morph-factory-vault-lock/src/main.rs Factory reserve rules
crates/morph-cli/src/devnet.rs          local devnet transaction paths
crates/morph-cli/src/*packages.rs       reusable package encoders/validators
```

## Design Posture

The implementation is deliberately conservative:

- fixed-layout bodies are used where CKB scripts need simple bounded parsing;
- `WitnessEnvelope` provides the current factory authorisation boundary;
- reduced factory paths prove one narrow local change, not arbitrary global
  mutation;
- devnet evidence is local and executable, but not a mainnet readiness claim.

The production-readiness gap is tracked in
[mainnet-readiness.md](mainnet-readiness.md).
