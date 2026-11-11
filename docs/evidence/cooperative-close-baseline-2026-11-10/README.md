# Current close geometry: 2026-11-10

This is the current-contract baseline for [ADR 005](../../adr/005-bilateral-cooperative-terminal-close.md).
It is not cooperative-close implementation or final candidate qualification.

`measurements.json` contains 14 actual VM transaction measurements, the eight
verified ELF identities, the test binary SHA-256, toolchain and relevant source
hashes captured after execution. Existing ELF files match
`release/factory-preproduction/contracts.json`; they were not rebuilt in this
checkpoint. The working tree is dirty. File hashes captured afterward do not
constitute clean-source build provenance or prove source stability during a run.

Reproduce after building the current ELFs:

```sh
cargo test --locked -p morph-core --test contract_scripts current_close_geometry -- --ignored --nocapture --test-threads=1
cargo test --locked -p morph-core --test multi_asset conditional_service_cooperative_consolidation_returns_to_ordinary_same_custody
cargo clippy --locked -p morph-core --test contract_scripts -- -D warnings
```

Two VM tests pass, including four negative variants proving valid ordinary state
votes cannot bypass the current finalisation delay. One existing host consolidation
test passes. Scoped Clippy passes. Full logs are retained here. These counts are
new targeted evidence, not a claim that all current VM cases or W1 gates ran.

The ordinary measurement builds the latest valid publication directly from a
bound Active source; its corresponding finalisation consumes that publication.
The splice measurement uses the existing replace-all fixture and retains a
successor. The conditional measurement creates a Batch and executes fulfillment.
These three flows are not economically identical transactions. Consolidation is
an off-chain state change and has no on-chain transaction to measure.

Participant locks are simplified, token scripts are development fixtures, and
the relative delay is six blocks. Transaction size is serialized packed size,
not an assertion about a node's charged-size policy. Actual capacity difference
is recorded as fee: zero for ordinary/conditional and 10,000 shannons for splice.
Occupied capacity is the sum of output capacity minima, not burned capacity.
Random fixture deployment identities/signatures can affect cycle samples.
Neither real-asset resource limits nor the new close's bytes/cycles were tested.
