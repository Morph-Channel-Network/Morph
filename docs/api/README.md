# Current public API contracts

The Rust definitions in `morph-hub-api` and public package definitions in
`morph-packages` are authoritative. `hub-types/` contains independent JSON
Schema 2020-12 documents generated from these definitions. Each file includes
its own local `$defs`; use the individual file as the validation root.

Regenerate from the repository root:

```sh
cargo run -p morph-hub-api --example export_schemas
cargo test -p morph-hub-api
```

`schema::tests::checked_schemas_match_authoritative_types_without_stale_files`
compares every generated file byte for byte and rejects missing/obsolete files.
It runs through normal workspace CI and `make rust-client-check`. Schema keys
are recursively sorted so GPUI's transitive `serde_json/preserve_order` feature
does not change the output. The Schemars version is pinned to 1.2.1: generation
behavior can change between versions, so dependency upgrades must regenerate
and review these files. See [Schemars documentation](https://docs.rs/crate/schemars/1.2.1).

These files cover current Hub request/view/error/event types, funding receipts,
and public root/recovery packages. They are structural contracts, not a proof
that a package's signatures, scripts, conservation or lineage are valid. Those
checks remain in the sole canonical package/Core validators before mutation.
The public summaries of conditional capabilities and payouts are concrete Rust
types; their schema no longer uses an unrestricted JSON object.

## Numeric units and encodings

| Field family | Public JSON representation | Units / meaning |
| --- | --- | --- |
| revision, expected revision | Decimal string | Durable Hub projection version |
| state/update number, funding epoch | Decimal string | Protocol counter |
| sponsor budget, CKB balances/reserves/capacities | Decimal string | Shannon (100,000,000 per CKB) |
| xUDT amount | Decimal string | Integer base units of its exact Type |
| `*_unix`, `expiry_secs` | Decimal string | Seconds |
| `created_unix_ms` | Decimal string | Milliseconds |
| block heights | Decimal string | Absolute CKB block height |
| small counts, indices, script hash-type tag | JSON integer | Bounded count/index/tag, not value |
| nullable u64 observations | Decimal string or explicit `null` | Missing observation is not zero |

Every u64 field owned by `morph-hub-api` now serializes as a canonical decimal
string. Its Rust representation remains u64. Numbers, signs, whitespace,
leading zeroes, fractional notation and overflow are rejected on input; the
schema includes the full u64 upper bound. A separate non-digit exclusion avoids
ECMAScript end-anchor acceptance of trailing newlines. Tests compare range
boundaries against runtime decoding, including values above 2^53.

The native form builder validates u64 ranges and emits the same strings as the
Rust SDK. The server's private storage structs retain their internal Rust
encodings; they are not silently converted into public protocol DTOs. No old
number/string dual reader or alias is supported.

## HTTP binding and administrative archives

[hub-endpoints.md](hub-endpoints.md) and [hub-openapi.json](hub-openapi.json)
are generated from the same closed `Endpoint` registry that dispatches Hub
requests and supplies SDK scope/mutation classification. They bind all 26
current Hub routes to request/result types, authentication scope and retry
requirements. SSE carries `EventView` JSON; health still returns `HubView`, not
the #35 readiness contract. The OpenAPI 3.1 document references the adjacent
2020-12 schemas, so distribute it together with `hub-types/`. Both generated
outputs have byte-for-byte drift checks in normal API crate tests.

`GET /api/state-file` returns `StateArchive`; preview consumes it and restore
consumes `RestoreArchiveRequest`. These are public transport types, **not** the
private `PersistedHubState` serialization. Archive amounts/counters are decimal
strings; subject IDs and asset Type hashes are canonical hex. Network, phase,
invoice status and completed-flow variants are closed snake-case enums. Signed
invoices appear once as their canonical encoded invoice plus status/timestamps;
the decoder validates the invoice rather than accepting another editable copy
of its signed fields. Conversion also checks full-width quantities, per-asset
bounds and summed balances before any restoration. Packages still pass the
existing canonical signature/lineage validators.

SDK export/preview/restore use these concrete types. Old internal snapshot JSON
is rejected at the API boundary; no compatibility reader is provided. Private
storage and backups keep their private encoding. Exported data is administrative
material, not an authorization to restore operational state: restore scope,
server enablement, preview confirmation, expected revision, identity/network
checks and the **empty-bootstrap-only** restriction remain enforced. No signer
journal or signing authority is imported.

## Remaining #32 work

Gateway now has its own [generated endpoints](gateway-endpoints.md),
[OpenAPI](gateway-openapi.json) and 19 type schemas, with decimal/hex transport
adapters for signed Core objects. Its durable exact-request retry contract and
payment-attempt integration remain unfinished; Hub OpenAPI does not document
that separate service. Gateway DTOs, typed errors, numeric boundaries and retry
limits are documented in [gateway-errors.md](gateway-errors.md). Dynamic inspection
reports outside these registered public roots also remain distinct from the
Hub API. Do not infer complete endpoint coverage from a green type-schema
snapshot test.

[Mutation, retry and revision contract](../hub-api-mutations.md) documents
version headers, authorization, historical response replay and exact-request
retry rules. There are no JavaScript/TypeScript generated clients; the supported
SDK is Rust and directly consumes the authoritative DTO crate.
