# Morph current custody — 4.0.0-alpha.1

`morph-current-custody` is the sole current protocol family. This is a
controlled-devnet candidate with no real assets. Selecting the shared-foundation
architecture does not approve a mainnet release.

Bilateral custody and Factory custody use distinct authority objects on the same
bounded asset, Vault-set, persistence, signing and recovery foundation:

| Boundary | Current implementation |
| --- | --- |
| Bilateral State | 318 bytes; descriptor 5; one to eight Vaults |
| Factory State | 306 bytes; two to sixteen committed members |
| Full Factory authorization | Exact-transaction N-of-N root, update, custody and materialisation |
| Reduced Factory authorization | One touched member; localized compact proofs; independent asset conservation |
| CKB conditions | At most eight preimage/refund transfers; separate Batch executor |
| Batch identity | 104 bytes, including the exact funding context |
| Child recovery | Independent initial-exit journals and public possession receipts; private exits stay with child parties |
| Operational recovery | Stable journals, canonical reconciliation, same-path handoff, reorg-aware watch service |

Single-asset channels use a one-entry current manifest. Retired single-Vault
State/Factory/splice formats, old JSON schemas and old signing backends are not
supported. Reset no-value development state after an incompatible change.

A physical reduced Factory operation spends `ReserveClaim` rights. Precommit the
rights identities and zero-valued future rights needed by the intended workflow;
metadata `Balance` or sponsor rights do not implicitly create a withdrawal claim.
Every member must retain the complete initial rights snapshot and apply public
reduced changes. A full-consent root replacement requires delivery of its complete
new snapshot before signing. Retained Factory custody keeps an occupied-capacity
floor and the shared State carrier; single-member escape does not retire that
collectively owned remainder. Fund child carriers and transaction fees separately.

`contracts.json` pins all eight deterministic ELFs built with Rust 1.95.0.
The phase-A `envelope.json` separates those protocol maxima from declared
experiments: Factory is two members, one plain-CKB Vault, one child at a time
and one/four/ten-right updates; bilateral experiments have at most eight total
Vaults and only the manifest-pinned devnet issuer. Zero-quantity token rights
still require asset admission. Real assets remain prohibited, and local Hub
projections are not chain actions.

Policy verification returns `policy_verified=true`, `release_admitted=false`.
Exact-request shape integration, durable operator lifetime accounting and final
phase-B evidence/approval remain outstanding. Current native commands execute
ValueLimitPolicy and their exact-source/VM checks, not an implicit full envelope
admission service. Its lifetime child cap of ten is operator bookkeeping; the
independent per-transaction child bound is enforced by the protocol. Eight
Vaults means eight total entries, including a separate plain CKB Vault when
present. See `docs/preproduction-envelope.md` for #22/#28/#27/#44 evidence gates.

```sh
make ci
make devnet-current-e2e
make release-readiness
make package-contract-release
```

The actual-node runner captures the exact ELF snapshot and transaction evidence.
Its evidence is development acceptance, not independent release approval.
A hash change needs a rebuilt manifest and the complete applicable gates; changing
metadata alone cannot establish the protocol's behavior.
