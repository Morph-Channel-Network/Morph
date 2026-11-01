# CKB Contracts

This directory contains the CKB script boundary for Morph Channel.

The repository implements host-side protocol semantics in `morph-core` and the
current no-std CKB script boundary: fixed-layout body parsers where schemas are
intentionally fixed, plus `WitnessEnvelope` authorisation dispatch by kind,
body, and digest for factory flows:

- `morph-state-type`: owns State Cell progression, state-number monotonicity,
  and bilateral participant signature verification.
- `morph-state-lock`: ensures a State Cell can only be spent when it carries
  the expected state type script, leaving transition rules to the type script.
- `morph-vault-lock`: owns vault settlement, current-state authorisation, and
  descriptor-bound settlement output checks.
- `morph-batch-lock`: resolves a bounded conditional CKB batch to exactly two
  aggregate participant outputs using preimages or mature absolute-block
  refunds.
- `morph-sponsor-lock`: owns bounded sponsor budget spending and requires a
  matching settling StateHeader output.
- `morph-factory-type`: owns conservative FactoryStateCell creation,
  monotonic updates, full-participant signatures, bounded reduced-rights
  updates, bounded reserve-claim reduced exits, local-exit evidence checks, and
  `WitnessEnvelope` factory authorisation dispatch.
- `morph-factory-vault-lock`: owns factory reserve conservation while a
  conservative or reduced exit materialises a child channel, including
  envelope-carried factory splice and reduced-splice bodies.
- `morph-devnet-xudt`: provides the devnet-only xUDT issuer and conservation
  script used by CKB+xUDT smoke paths.

Build the current scripts with:

```sh
make build-contracts
```

The output ELFs are under
`target/riscv64imac-unknown-none-elf/release/`.
