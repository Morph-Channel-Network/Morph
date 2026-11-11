# Gateway endpoint, receipt and projection-codec checkpoint — 2026-11-10

Two new #43 targets supplement existing payer-proof and HTTP/process tests.
`gateway-api` has 27 seeds spanning 22 root types: every JSON/query
body in the current endpoint registry plus public errors. Corpus construction
fails if a registered type lacks a seed. `gateway-receipt` separately checks one
deterministic, cryptographically valid terminal receipt with an externally fixed
expected signer.

## Actual boundaries

API inputs have a one-byte harness selector, then raw JSON passed directly to the
actual concrete Rust type decoder. This retains duplicate-field rejection. Typed
re-encoding must be stable. Every nonempty corpus root has a duplicate-field
negative; all roots reject extra fields. The Deserialize-only payment-list query
uses the actual decoder and a harness encoder for its current optional string
limit. Negatives cover null, JSON numbers, zero, >1000, leading zero, plus sign
and integer overflow. These are decoded query values, not URI/HTTP extraction.

Readiness and event pages additionally use the existing semantic consistency
validators. Other API roots test structure, not operation authorization. Provider
result Value, proxy bytes/upstream responses and metrics text retain their actual
boundaries; the latter are not represented as fictitious JSON APIs. Some offer,
credential, nonce/ciphertext and preimage fields deliberately contain synthetic
non-operational values. A successful DTO parse is not a completed exchange.

The receipt fixture builds the current PaymentIntent from existing public payer
terms, derives its ID, signs TerminalSettlementReceipt with public fixture key
`[8; 32]`, and binds the Gateway's exact provider-evidence commitment. The expected
signer is fixed outside mutation. Actual `PaymentReceipt::validate_for_signer`
checks terminal authority, intent and outer identity/amount/payer/resource/time
bindings; wrong signer and structurally valid outer substitutions are rejected.
The receipt uses `synthetic-not-an-access-token`: this target deliberately makes
**no Biscuit credential or resource-access authorization claim**. Existing
credential/service tests cover those separate checks. No user key/network/store
is used by the mutation targets and no production parser is replaced.

## Private projection rejection

`malformed_missing_unknown_and_future_projection_records_fail_without_reinitialization`
adds nine actual encrypted SQLite consumer-codec cases: truncated JSON, null,
array root, schema 0/current+1/u32::MAX, missing outgoing, unknown authority field,
and an outgoing array instead of map. Tests commit those bytes through the generic
encrypted transaction layer so failures reach Gateway decoding, not just cipher
MAC checking. Reopening must fail with Corrupt/UnsupportedVersion. Exact database
bytes, persisted projection bytes and revision remain unchanged. No initialization,
migration, new event or reservation reset is permitted.

This supplements generic store encryption/schema/I/O tests and payment models.
It does not model whole-authority rollback, all syntactically valid but inconsistent
record relationships, or every filesystem failure. Production Gateway behavior
and schema are unchanged; this checkpoint adds tests only.

## Executed checks

```sh
cargo test --locked -p morph-payment-gateway -p morph-xtask --all-features -- --nocapture
cargo clippy --locked -p morph-payment-gateway -p morph-xtask --all-features --all-targets -- -D warnings
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/gateway-api-smoke-20261110 \
  --seed 17 --cases 1000 --seconds 30
# Separately for gateway-api and gateway-receipt, with a fresh directory:
mkdir target/fuzz-campaigns/gateway-api-long-20261110
timeout --signal=KILL 180s target/debug/morph-fuzz --worker gateway-api \
  --output target/fuzz-campaigns/gateway-api-long-20261110 \
  --seed 332043276360 --cases 10000 --seconds 180
```

- **82 test entries pass**: Gateway 60 library + 3 binary + 2 integration;
  tools 10 fuzz unit + 5 runner unit + 2 campaign integration. The Gateway child
  helper is one counted entry; its parent also passes all six SIGKILL scenarios.
- Scoped all-target Clippy, formatting and whitespace checks pass.
- **26,000 full-smoke inputs pass**, 37.710 seconds overall.
- **20,000 scoped long inputs pass** (10,000 per new target); no new full-target
  long run is claimed. The enclosing timeout exits are both 0.

| Scoped long target | Accepted | Rejected | Seconds |
| --- | --- | --- | --- |
| `gateway-api` | 2,020 | 7,980 | 1.896 |
| `gateway-receipt` | 1,126 | 8,874 | 6.650 |


Counts include periodic unchanged positive seeds, not exhaustive attack traces.
The ordinary integration suite intentionally forces timeouts in a separate run;
those FAIL log lines are expected negatives. The qualification runs above finish
the complete input counts. Each scoped worker retains 1 MiB input, 1 GiB address
space and CPU/file bounds, with GNU timeout enforcing the 180-second wall limit.
`scoped-long-executions.json` records exact commands and exit status. The smoke
report binds binary/toolchain/lockfile; actual binary and lockfile hashes match.

162 explicitly inventoried source/config/corpus files match before/after the
campaigns; this is not a whole-repository or clean-candidate freeze. All 27 API
seeds and the receipt seed are identical across short/long runs and retained here.
No protocol defect was found. No remote CI execution, issue closure or W1
completion is claimed. Remaining verification work includes other private record
families, inline script-argument inventory and final candidate evidence.
