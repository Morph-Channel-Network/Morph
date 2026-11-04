# Roadmap

This roadmap tracks Morph Channel's production implementation, protocol
extensions, and release evidence.

## Maturity Picture

```mermaid
flowchart LR
    M0["M0<br/>Protocol model"] --> M1["M1<br/>State/Vault/Sponsor"]
    M1 --> M2["M2<br/>Devnet vertical slice"]
    M2 --> M3["M3<br/>CKB+xUDT + splice"]
    M3 --> M4["M4<br/>Factory reduced proofs"]
    M4 --> M5["M5<br/>Watchtower + stateful audit"]
    M5 --> M6["M6<br/>External readiness work"]
    M5 --> M8["M8<br/>Conditional batches"]
    M8 --> M9["M9<br/>Multi-asset channels"]
```

The repository is entering production implementation work. Protocol objects,
package tooling, CKB scripts, smoke tests, and stateful acceptance gates exist
locally. The next asset extension is multiple xUDT types in one channel;
external review and operational release evidence remain open.

## Milestone Status

| Milestone | Status | What exists |
| --- | --- | --- |
| M0: Protocol semantics | Implemented | `morph-core` types, signing digests, validation invariants, and executable tests. |
| M1: Bilateral channel | Implemented | State Cell progression, Vault Cell settlement, sponsor fee boundary, and participant signatures. |
| M2: Devnet vertical slice | Implemented | Local CKB node flow, script deployment, channel open, state publication, vault finalisation, negative smokes, and reports. |
| M3: Assets and splice | Implemented locally | CKB+xUDT settlement, splice-in/out, funding epoch, vault-set commitment, package validation, and devnet smokes. |
| M4: Factory mode | Implemented narrowly | Conservative factory updates, local exits, reduced-rights proof, sparse-Merkle update, reduced exit, factory splice, and reduced splice through `WitnessEnvelope`. |
| M5: Watchtower and audit gates | Implemented locally | Watch config, policy checks, JSONL/webhook alerts, stale-package guard, smoke assertions, stateful assertions, and budget profiles. |
| M6: Production readiness | Controlled-devnet candidate; production open | Factory has a checked manifest/envelope and runbooks. Publication now has bounded node-informed fees, CKB RBF, least-privilege two-operator local evidence, and induced-reorg recovery. External review, independent rebuild/operators, and repeated public-network measurements remain open. |
| M7: Factory 2.0 surface (v2.0) | Implemented locally | Multi-right reduced updates (envelope kind 8), compact variable-depth sparse-Merkle proofs, and the operator value-limit policy with runbook; see `docs/factory-multi-right.md`. Devnet save/publication plumbing for kind 8 packages is the remaining follow-up. |
| M8: Conditional batch surface (v3.0) | Implemented locally | Descriptor v3, bounded preimage/absolute-refund leaves, cooperative consolidation, Vault-to-Batch materialisation, Batch CKB-VM enforcement, canonical CLI package, and durable Hub import; see `docs/conditional-batches.md`. |
| M9: Multi-asset channels | Implementation in progress | Bilateral layout 2 / descriptor 4 supports 1–8 Vaults with host, CKB-VM, CLI/SDK, durable Hub recovery, and real-node two/eight-xUDT lifecycle evidence. Bilateral splice has native construction, durable signing and SDK verification. Factory custody, typed conditions, full publication/reorg orchestration and release qualification remain open; see [candidate profile](multi-asset-wire.md). |

## Current Factory Witness Baseline

Factory authorisation uses `WitnessEnvelope`.

```mermaid
flowchart TB
    E["Envelope kind + digest"] --> B["bounded body schema"]
    B --> S["factory scripts"]
    S --> R["state/root/vault checks"]
```

The remaining `*current` names in package or body schemas identify fixed-layout
schemas and historical evidence labels. They are not the current public factory
authorisation boundary.

## Deferred Work

| Area | Deferred item | Why it is deferred |
| --- | --- | --- |
| Multi-asset channels | Multiple xUDT types in one physical channel funding context. | Next protocol extension (M9): host/right models already represent multiple assets; single-Vault provenance and fixed settlement/splice paths need a versioned replacement. |
| Factory proofs | ~~Multi-right reduced updates.~~ | Delivered in 2.0 as envelope kind 8; see `docs/factory-multi-right.md`. |
| Factory proofs | ~~Variable-depth or dynamic proof profiles.~~ | Delivered in 2.0 as compact bounded sparse-Merkle proofs on kind 8. |
| Factory 2.0 tooling | Devnet save/publication command for kind 8 state-cell packages. | Host validation, fixtures, and on-chain evidence exist; the live-node publication flow mirrors `save-factory-merkle-update-package` and needs a devnet rehearsal. |
| Factory membership | Larger participant sets with production ergonomics. | The wire supports 2-16 participants; production ergonomics still need proof-size, fee, and UX evidence. |
| Watchtower | Independent multi-operator deployment evidence. | Two isolated local operator scopes pass; distinct hosts, administrators, RPC providers, and alert paths still require rehearsal. |
| Conditional batches | xUDT leaves, cross-channel routing, and production auto-broadcast. | v3 deliberately ships a bounded CKB-only primitive first; broader assets and routing need separate wire and operational evidence. |
| Network conditions | Repeated public-network reorg, delay, and fee-pressure runs. | A deterministic local fault-injection gate passes, but one devnet sample is not a production measurement. |
| Release process | Independent reproduction and release-owner sign-off. | Deterministic bundles, reviewed ELF hashes, successful main-branch CI upload/attestation, and staging cleanup exist; a successful independent external rebuild and release-owner sign-off remain open. |
| Policy | Value-limit policy and operator runbooks. | Delivered in 2.0 (`morph-core::policy`, `value-limit-check`, `docs/runbooks/value-limits.md`); enforcing it in live publication automation remains operator process work. |

## Next Engineering Slice

```mermaid
flowchart LR
    A["Multi-Vault wire + invariants"] --> B["Bilateral multi-asset settlement"]
    B --> C["Splice + Factory materialisation"]
    C --> D["Recovery + release evidence"]
```

The next protocol slice closes the single-xUDT limitation:

1. specify bounded multi-Vault commitments, exact provenance, canonical
   settlement outputs, and capacity lanes;
2. implement bilateral multi-xUDT funding, activation, publication, supersede,
   and full-set finalisation, with negative CKB-VM tests;
3. extend signed splice and Factory materialisation without weakening
   non-interference or leaving reserve value behind;
4. carry complete recovery packages through CLI, SDK, Hub, and watchtower
   persistence, including restart and reorg recovery;
5. measure transaction bytes, cycles, occupied capacity, and publication costs
   at the chosen limits before freezing the profile.

The detailed sequence is in [multi-asset channels](multi-asset-channels.md).
Independent review, clean release artefacts, repeated public-network fee/reorg
measurements, independent operators, runbook rehearsals, and conservative
value limits continue as production release requirements. Conditional xUDT
batches follow ordinary multi-asset settlement as a separate extension.

## How To Read Older Milestone Documents

Some closeout documents remain in this repository as historical evidence. They
are useful for understanding what was proved at a prior milestone, but current
design should be read from:

- [README.md](../README.md) for the human overview;
- [implementation.md](implementation.md) for protocol and script boundaries;
- [devnet.md](devnet.md) for executable local evidence;
- [mainnet-readiness.md](mainnet-readiness.md) for release gates.
