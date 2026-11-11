# Inline script arguments and integration-index foundation — 2026-11-10

This scoped checkpoint advances #43 and the first #44 implementation. It is not
whole-W1 qualification, a clean candidate, a publication or an issue closure.

## #43 arguments

`script-args` now has five canonical seeds: direct/Factory-child StateType,
Vault, Sponsor and Factory Type. Factory Type calls the actual shared 44-byte
parser/encoder; its exact roundtrip is checked, with deterministic malformed
magic/version/reserved/zero-ID/short/long negatives. No production codec or
contract bytecode was changed here.

The Factory reserve64 and Batch104 parsers are inline in their script entry
points. Instead of inventing a host parser, the new real-VM test
`current_inline_factory_and_batch_args_reject_malformed_shapes_before_witness_access`
checks four bad lengths per script, both zero Batch namespace lanes and zero
Batch state number: **11 variants** with exact expected script errors.
Existing valid-length Factory authority and conditional commitment/spend tests
remain separate; this run does not claim they all executed again.

Executed:

```sh
cargo test --locked -p morph-xtask current_batch_fulfill_refund_and_argument_corpus_rejects_semantic_tampering
cargo test --locked -p morph-core --test contract_scripts \
  current_inline_factory_and_batch_args_reject_malformed_shapes_before_witness_access \
  -- --ignored --test-threads=1
cargo clippy --locked -p morph-xtask --all-targets -- -D warnings
cargo clippy --locked -p morph-core --test contract_scripts -- -D warnings
cargo build --locked -p morph-xtask --bin morph-fuzz
mkdir target/fuzz-campaigns/inline-args-long-20261110
timeout --signal=KILL 60s target/debug/morph-fuzz --worker script-args \
  --output target/fuzz-campaigns/inline-args-long-20261110 \
  --seed 332043276360 --cases 10000 --seconds 60
```

The scoped worker finished **10,000 inputs**, 3,637 accepted and 6,363 rejected,
in 1.417 seconds, enclosing exit 0. Counts include periodic unchanged seeds.
This is one target, not a fresh 26-target campaign. Worker bounds remain 1 MiB
input / 1 GiB address space / 8 MiB output files / CPU and enclosing wall limits.
The existing built ELFs were used; their post-run hashes are retained, with no
fresh ELF/source equivalence claim or rebuild implied.

## #44 initial implementation

[The runbook](../../runbooks/integration-evidence.md) describes the strict
plan/candidate/index formats and `capture`, `run`, `validate` commands. Identity
checks bind current source, lockfile, toolchain, all eight actual ELFs and their
deployment manifest, plus declared configuration/schema files. Required gates
cannot disappear, be skipped or have their command/config/fault/replay bindings
changed. The execution wrapper records actual exit/timeout/source outcomes;
rehashing a failed receipt does not promote it to a passing one.

Evidence validation rejects duplicate/unknown fields, changed/missing/linked/
oversized artifacts, unsafe paths, stale campaign times and missing replay
locations. Its output is allowlisted metadata, not arbitrary log export. Raw
execution logs remain in a fresh 0700 directory as 0600 files. No private exit,
key, token, preimage or active journal is copied into this checkpoint.

`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_*.py'`
passes **33 tests**, including **11 new integration-evidence tests**. These use
a temporary Git repository and synthetic files, plus real child commands for
success, exit7, source change and timeout. The actual CLI capture/run/validate
path succeeds on that synthetic clean candidate and rejects dirty capture.
This is testing evidence machinery, not running Morph native qualification.

Together with the two Rust entries, **35 test entries pass**. Scoped Clippy,
format and diff checks pass. `post-run-identities.json` is exactly that: an
inventory after execution, **not** a before/after source freeze. No remote CI
run or cryptographic attestation is claimed. Final W1 gate mapping, per-runner
semantic report integration, clean candidate execution, and public bundle/CI
upload integration remain open; #44 is not closed by this foundation.
