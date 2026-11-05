# CKB Contracts

This directory contains the CKB script boundary for Morph Channel.

Host-side protocol semantics live in `morph-core`. The no-std scripts use one
current State/Vault-set family with typed authority and bounded parsers in
`morph-script-common`. Bilateral State is 318 bytes (layout 2, descriptor 5);
Factory State is 306 bytes (layout 2). Ordinary CKB, one token and several
tokens use the same custody model.

Factory authorisation is dispatched by the current `MORPHFS!`, `MORPHFM!` and
`MORPHFR!` frames. FS format 2 handles exact-transaction root/metadata approval
and permissionless activation; FM handles full-consent child materialisation;
FR handles reduced rights/custody operations and full-consent custody changes.
Unknown frames and retired State/Vault/splice or envelope-kind formats are
rejected. The scripts are:

- `morph-state-type`: owns State Cell progression, state-number monotonicity,
  and bilateral participant signature verification.
- `morph-state-lock`: ensures a State Cell can only be spent when it carries
  the expected state type script, leaving transition rules to the type script.
- `morph-vault-lock`: authenticates the current State and complete exact
  Vault set, then enforces descriptor-bound settlement or splice outputs.
- `morph-batch-lock`: resolves a bounded conditional CKB batch to exactly two
  aggregate participant outputs using preimages or mature absolute-block
  refunds.
- `morph-sponsor-lock`: authenticates a matching settling-state publication
  and enforces per-cell budget, exact fee attribution and clean change.
- `morph-factory-type`: authenticates Factory identity, source State,
  monotonic progress, exact transaction and the appropriate all-member or
  single-touched-member authority.
- `morph-factory-vault-lock`: enforces complete source/retained custody,
  independent asset conservation, payouts, external funding/fees and canonical
  child materialisation under the same Factory authority.
- `morph-devnet-xudt`: provides the devnet-only xUDT issuer and conservation
  script used by CKB+xUDT smoke paths.

Descriptor 5 makes ordinary versus conditional CKB settlement explicit. Batch
terms remain 828 bytes; its 104-byte lock args bind the channel, funding
context, state number and terms commitment. A Factory child becomes an
independently enforceable bilateral channel after creation.

Reduced physical operations spend the touched member's proven `ReserveClaim`
rights and retain the shared carrier and occupied Vault floor. All-member
`FullCustody` can redistribute rights without the single-member claim-delta
predicate; actual custody, per-Type value and external fee/funding checks still
apply. See [the current wire](../docs/multi-asset-wire.md) and
[Factory permissions](../docs/factory-multi-right.md).

Build the current scripts with:

```sh
make build-contracts
```

The output ELFs are under
`target/riscv64imac-unknown-none-elf/release/`.
