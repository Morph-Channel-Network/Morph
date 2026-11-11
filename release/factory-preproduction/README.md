# Morph current custody — 4.0.0-alpha.1

`morph-current-custody` is the sole current protocol family. This is a
controlled-devnet candidate with no real assets. Selecting the shared-foundation
architecture does not approve a mainnet release.

The November 11 implementation includes exact-transaction cooperative close
(`MORPHMC!`), durable close signing/operation tracking and asset-bound conditional
settlement. `contracts.json` pins the corresponding eight ELF identities. The
signed implementation `bc4be3ff` completed the ten local no-value gates; see
`docs/evidence/typed-conditions-bc4be3ff/README.md` for exact source/artifact
identities, outcomes and the original descriptor-label erratum. Later reporting
corrections are not another full executed candidate or deployment approval.

Bilateral custody and Factory custody use distinct authority objects on the same
bounded asset, Vault-set, persistence, signing and recovery foundation:

| Boundary | Current implementation |
| --- | --- |
| Bilateral State | 318 bytes; descriptor 7; one to eight Vaults |
| Factory State | 306 bytes; two to sixteen committed members |
| Full Factory authorization | Exact-transaction N-of-N root, update, custody and materialisation |
| Reduced Factory authorization | One touched member; localized compact proofs; independent asset conservation |
| CKB/UDT conditions | One to eight asset-sorted Batches, each with at most eight preimage/refund transfers; each Batch resolves at transaction input 0 |
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
The local controlled-devnet `envelope.json` separates those protocol maxima from declared
experiments: Factory is two members, one plain-CKB Vault, one child at a time
and one/four/ten-right updates; bilateral experiments have at most eight total
Vaults and only the manifest-pinned devnet issuer. Zero-quantity token rights
still require asset admission. Real assets remain prohibited, and local Hub
projections are not chain actions.

Policy verification returns `policy_verified=true`, `release_admitted=false`.
Schema v3 requires exact-request admission before value-creating signatures,
wallet signing and submission. One private OS-locked/fsynced operator ledger
tracks active Factories, lifetime child reservations and bilateral capacity
peaks, including retained batches and canonical closure/reorg reconciliation.
It is not a consensus lifetime counter. Existing complete private exits and
keyless finalisation remain recovery authority.

The owner removed #27 independent-operator measurements and #44 external
records as prerequisites for #21 on 2026-11-06. Exact local CI/native/source/
ELF/policy/bundle verification is required instead. `make qualify-local-candidate`
produces only a local qualification receipt and archive; it does not publish a
release or authorize production. No real assets are allowed. Eight Vaults means
eight total entries; the 4,000 CKB channel experiment ceiling covers the
measured 3,536 CKB eight-token shape, including its State carrier. The larger
joint Factory maxima remain outside the experiment. See
`docs/preproduction-envelope.md` and `docs/runbooks/experiment-admission.md`.

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
