# Gateway HTTP service kill/restart checkpoint — 2026-11-10

This #43 checkpoint closes the dedicated outgoing-payment service-process kill
row. It does not complete W1 or qualify live Fiber forwarding. The parent holds a
controlled Fiber RPC server; a separate Rust test process runs the production
Gateway router, payment handler and encrypted SQLite store. Every restart uses
the same database, storage key, provider endpoint and exact signed request.

| Kill point | Provider status on reconciliation | Total sends across restart |
| --- | --- | --- |
| Reservation committed; before sending | No provider record | 0; both retries return `503 payment_outcome_unknown` |
| Provider accepted; RPC reply deliberately withheld | Success | 1; reconcile and then return cached success |
| Send reply received; before terminal observation/storage | Success | 1 |
| Send reply received; before terminal observation/storage | Failed | 1; return `completed: false`, never resubmit |
| Terminal result committed; before HTTP response | Success | 1; exact saved response despite unavailable provider |
| Terminal result committed; before HTTP response | Failed | 1; exact saved failure despite unavailable provider |

The parent waits for each actual cut point, sends SIGKILL and reaps the child
(signal 9 asserted). The interrupted HTTP request must fail without a response.
It opens the database independently to check whether terminal evidence exists,
then starts another HTTP service process. Two identical POSTs must preserve the
send count; changing the request timeout must return `409 request_conflict`.
After the second process is stopped, a fresh database connection checks immutable
submission body, timeout and creation time, plus terminal presence/absence.
Saved-terminal retries must not query the provider. The test owns and reaps only
its children; no running user's service or node is touched.

Three deterministic wait hooks compile only under `cfg(test)` and have no
production environment-variable switch. The lost-provider-reply case instead
blocks the controlled RPC response after recording acceptance. The service is
real Rust HTTP/SQLite code, but its test-executable entry point is not the CLI
bootstrap. This does not emulate kernel power loss, provider data rollback,
whole Gateway database rollback, cross-provider retry, or routed MPP. It proves
at-most-one local send authorization for an intact persisted identity, not
guaranteed completion or exactly-once delivery. The pre-send crash intentionally
retains an unresolved identity; safe new attempts belong to #36.

## Commands and evidence

```sh
cargo test --locked -p morph-payment-gateway --all-features -- --nocapture
cargo clippy --locked -p morph-payment-gateway --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Results: **59 library tests, 3 binary tests and 2 protected-key integration tests
pass** (64 test-harness entries; one library entry is the subprocess helper).
All six kill scenarios pass within the single parent regression. Clippy,
formatting and whitespace checks pass. The existing scheduled campaign already
runs this crate's suite, so no new CI duplication is needed. No remote workflow
run is claimed.

`tests.log` and `clippy.log` retain actual output. `source.sha256` identifies the
explicit source/config set after verification, not a whole-tree freeze or final
committed candidate. `SHA256SUMS` covers the saved checkpoint files. The initial
test-development failure is preserved as `initial-harness-failure.log`: its
assertion incorrectly used `paymentHash` instead of the existing `payment_hash`
response field. Correcting that assertion changed no public format or runtime
payment behavior.
