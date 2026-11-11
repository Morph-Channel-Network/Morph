# Hub endpoint DTO mutation checkpoint — 2026-11-10

The new `hub-api` #43 target contains **31 seeds over 28 root DTO types**:
every current registered JSON/SSE body plus the public error body. Corpus
construction checks names against `morph_hub_api::endpoints::Endpoint::ALL`;
missing new endpoint types fail immediately. This is a coverage inventory, not
an assertion that every nested variant, HTTP action or authorization is tested.

## Properties exercised

- A one-byte harness selector chooses a fixed concrete production Rust decoder.
  Raw JSON reaches that decoder directly; it is not first collapsed into `Value`,
  so duplicate request/archive fields retain their rejection behavior.
- Accepted typed encoding must decode and re-encode identically. Optional-field
  normalization uses the existing DTO behavior; no second schema/compatibility
  parser is maintained. Read-only DTOs retain their existing field policy.
- Seed data includes full-width decimals (above 2^53 and u64::MAX), explicit null,
  Chinese/English text, empty and nested public archives, current signed root/
  recovery/conditional packages, event pages, errors and readiness.
- Named regressions reject unknown/retired and duplicate fields in four strict
  request/archive roots; numeric JSON, leading zero and u64 overflow are rejected
  for the state-number codec.
- Actual `Readiness::consistent` and `EventPage::valid_for` run for those response
  roots. The page query is fixed outside mutation (no cursor, limit 64); a false
  ready summary or a mismatched final cursor revision is rejected.

The nested archive includes deliberately synthetic invoice/one-member Factory
entries: they are **structural DTO inputs, not valid/restorable operations**.
Other request roots likewise test decoding, not funding, payment or permission.
Current package semantic/signature tests are separate SDK targets. The actual
server checks archive conversion, resource values, key/network binding, current
confirmation and empty-bootstrap policy; its named tests are listed in
[the boundary matrix](../../verification-boundary-matrix.md). Their source was
inspected, but the CLI suite was not rerun for this tool-only change.

The first semantic seed check correctly rejected a test page that used its event
ID directly as the outbox ID. The fixture now derives the event ID from the
source/outbox pair as the current API requires. `initial-harness-failure.log`
retains that development failure. No production protocol defect was found or
production parser/format changed.

## Executed checks

```sh
cargo test --locked -p morph-hub-api -p morph-xtask -- --nocapture
cargo clippy --locked -p morph-hub-api -p morph-xtask --all-targets -- -D warnings
cargo run --locked -p morph-xtask --bin morph-fuzz -- \
  --output target/fuzz-campaigns/hub-api-smoke-20261110 \
  --seed 17 --cases 1000 --seconds 30
# Use a fresh directory; retain nonzero exits as failures.
mkdir target/fuzz-campaigns/hub-api-long-20261110
timeout --signal=KILL 180s target/debug/morph-fuzz --worker hub-api \
  --output target/fuzz-campaigns/hub-api-long-20261110 \
  --seed 332043276360 --cases 10000 --seconds 180
```

| Check | Actual result |
| --- | --- |
| Hub API unit/integration | 5 + 4 pass |
| Fuzz/runner unit + campaign integration | 9 + 5 + 2 pass |
| Total test entries | **25 pass** |
| Full 24-target smoke | **24,000 pass**, 35.432 seconds |
| Scoped Hub long campaign | **10,000 pass**, 2.642 seconds |
| Scoped accepted/rejected | 2,295 / 7,705 |
| Scoped Clippy, formatting, whitespace | Pass |

The existing integration test also intentionally forces timeouts; its FAIL log
lines are expected negative-test outcomes. The qualification runs above completed
all inputs. Counts include periodically unchanged positive seeds, not distinct
attack traces. The scoped long run is **not** another full-target long run: GNU
`timeout` provides its 180-second wall supervisor; the worker keeps the same
1 MiB input/1 GiB address-space/CPU/file limits. The saved command and exit code
are in `scoped-long-execution.json`; `long-result.json` is a worker result.

Both campaigns use the binary whose hash is in `smoke-report.json`; actual binary
and Cargo.lock hashes were checked. 132 explicit source/config/corpus entries
match before/after the campaigns. This is not a whole-tree clean candidate freeze.
The 31 saved seeds match across both runs; `corpus-index.json` maps selectors to
types. SHA256SUMS protects saved checkpoint files. No remote CI execution is claimed.

The existing CI registry now runs 24 targets. Remaining #43 work still includes
Gateway's other endpoint DTOs and private-record corruption reconciliation,
followed by final candidate verification. This checkpoint closes neither #43 nor W1.
