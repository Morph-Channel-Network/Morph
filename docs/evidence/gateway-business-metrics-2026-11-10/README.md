# Gateway durable business measurements — 2026-11-10

The existing authenticated `/metrics` endpoint now exports four durable business
counters from the same read-only encrypted projection used by readiness:
registered outgoing identities, retained successful terminal results, retained
failed terminal results, and issued incoming receipts. These records are
non-evicting. The bounded payment display is deliberately not their source, and
no second statistical ledger or persistence schema is introduced.

An additional gauge identifies unresolved outgoing records whose own recorded
payment-wait timeout has elapsed. This is an exact-reconciliation signal, not a
failure verdict, refund trigger or fresh submission authority. Unknown outcomes
remain unresolved; the original one-send authorization is unchanged. Persisted
terminal identity/status/completed mismatches fail the store observation instead
of producing success counts. Provider results remain provider evidence, not an
independent chain-finality proof.

The exporter now has 147 fixed series: 133 process/scope series, ten store gauges
and four durable counters. The fourteen store values are NaN on unavailable or
stale observations; authentication, existing two-second budget, retained single
probe permit and response bounds are unchanged. No provider string, payment hash,
path, key, signature or raw error becomes a metric label.

| Verification | Result |
| --- | --- |
| Gateway + Hub API + Rust SDK + observability | 84 tests pass across unit/integration targets; Gateway library has 55 |
| Exact concurrent HTTP requests | One Fiber send, cached terminal result, both service instances export identical one-attempt/one-success counts |
| Durable store | Success/failure/unresolved separation survives exact retries, display eviction and reopening; probe leaves revision unchanged |
| Wait-budget boundary | Before the recorded timeout no overdue identity; at the boundary exactly the unresolved identity is overdue |
| Contradictory terminal evidence | Stored completed/status mismatch returns store-inconsistent, not success |
| API generated artifacts | Regenerated from current canonical Hub/Gateway types; both checked-schema/OpenAPI suites pass |
| Static checks | Scoped all-features/all-targets Clippy, workspace formatting and diff whitespace checks pass |

The first Gateway run found an existing stale EventPage schema following earlier
event-type additions. Both authoritative generators were rerun; no handwritten
alternative schema or compatibility alias was added. Source/generated-artifact
hashes were captured before final verification and match afterward. This is
worktree evidence, not final committed-candidate qualification.

Commands:

```sh
cargo run -p morph-payment-gateway --example export_api
cargo run -p morph-hub-api --example export_schemas
cargo test -p morph-payment-gateway -p morph-hub-api -p morph-sdk -p morph-observability --all-features
cargo clippy -p morph-payment-gateway -p morph-hub-api -p morph-sdk -p morph-observability --all-features --all-targets -- -D warnings
```

No new native Fiber/CKB campaign, contract rebuild, real-asset admission, release,
commit, push or issue closure is claimed. #35 still requires remaining actual
readiness dependencies, publication/Sponsor/RPC measurements and deployment
alert calibration; the other W1 acceptance and exact candidate join remain open.
See [service readiness](../../runbooks/service-readiness.md) for metric semantics
and operator actions. Runtime data and private key material are not included.
