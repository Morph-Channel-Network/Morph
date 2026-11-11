# Payment Gateway public errors and DTOs

`morph-payment-gateway::api` owns the current request/response types and stable
error codes. It imports public protocol objects, not a private store or an HTTP
framework. The service and Rust SDK consume these same definitions. Public
challenge, payment, verification, settlement and fair-exchange request objects
reject unknown fields, including their nested protocol objects.

Every response from the Gateway router includes `X-Morph-Api-Version: 1` and a
server-generated `X-Morph-Request-Id`. A caller-supplied request ID is ignored.
The ID is diagnostic only: it is not a durable idempotency key or signing
identity. A Gateway-owned error has this shape:

```json
{
  "api_version": "1",
  "code": "invalid_query",
  "request_id": "gateway-1234-17",
  "error": "query does not match the current bounded contract"
}
```

The `request_id` matches the response header. Error messages do not include raw
parser output, malformed fields, request bodies, authorization headers or private
storage errors. Clients branch on `GatewayErrorCode`, never on the text.

| Code family | HTTP status | Meaning |
| --- | --- | --- |
| `invalid_json` | 400 syntax / 422 data shape | JSON cannot decode into the current request type |
| `unsupported_content_type` | 415 | JSON endpoint requires application/json |
| `body_too_large` | 413 | Existing request body limit exceeded |
| `invalid_query` | 400 | Unknown, repeated, noncanonical or out-of-range query field |
| `route_not_found`, `method_not_allowed` | 404, 405 | No matching route/method |
| `invalid_request`, `unknown_challenge`, `unknown_offer` | 400 | Domain validation rejected the operation |
| `unauthorized` | 401 | Required bearer or payer authorization missing/mismatched |
| `payment_required` | 402 | Payment has not reached the required paid state |
| `payment_timeout` | 504 | Outgoing payment did not reach terminal state within the deadline |
| `unsupported_asset` | 422 | Asset is not configured |
| `rate_limited` | 429 | Durable creation rate bound reached |
| `fiber_unavailable`, `gateway_unavailable` | 502 | Required upstream is unavailable |
| `store_capacity_exceeded` | 503 | Runtime storage capacity exhausted |
| `store_unavailable`, `credential_failure`, `crypto_failure` | 500 | Internal dependency failed; no raw detail is exposed |

JSON, query, proxy-body and proxy-path extractor failures use the same envelope
as service errors.
Framework fallbacks are covered as well. The x402 challenge's normal 402 response
is deliberately **not** an error envelope: it retains the canonical requirement
body and PAYMENT-REQUIRED header. Successful or failed responses forwarded from
the configured paid upstream retain the upstream's own body/status; the router
does not reinterpret arbitrary upstream data as a Gateway error.

`GET /v1/payments` accepts only `limit`, an optional canonical integer from 1 to
1000, defaulting to 100. It rejects zero, overflow, leading zeros, repeated
parameters and unknown fields instead of silently clamping them. `PaymentListItem`
is an explicit projection and never contains the raw Fiber result. Supported
capabilities and payment lists also have owned response types consumed directly
by the Rust SDK.

The SDK preserves typed service errors and request IDs for ordinary JSON and
x402 challenge calls. An unrecognized/intermediary response has no typed code;
it must not be reclassified by parsing its human message. The Fiber acceptance
runner retries settlement/claims only on the typed `payment_required` code.
Neither a timeout nor a generic HTTP error proves that an outgoing payment was
not submitted. This change does not introduce automatic payment retries or claim
that Gateway mutation idempotency is complete.

## Verification and remaining work

The native HTTP test covers 19 rejected request shapes, checks unique IDs and
version headers, verifies no input marker leaks into the response, exercises the
SDK's typed errors and valid typed reads, and compares the encrypted database
before/after to prove rejected operations did not change durable state. Existing
payer, fee, receipt, credential and fair-exchange tests remain in place.

#32 is not complete: Gateway still needs the durable exact-request retry and
conflict contract, coordinated with payment attempt recovery (#36). Typed HTTP
contracts are not live Fiber integration qualification (#37/#40).

## Generated endpoints and transport types

[The 13-route inventory](gateway-endpoints.md) and [OpenAPI 3.1](gateway-openapi.json)
are generated from the registry that builds the actual Axum router. The adjacent
`gateway-types/` directory contains 19 standalone JSON Schema 2020-12 documents;
ship it together with OpenAPI. Regenerate with:

```sh
cargo run -p morph-payment-gateway --example export_api
```

Normal Gateway tests compare these files byte for byte and reject missing/stale
schema files. Shared schema generation sorts object keys and uses the pinned
Schemars dependency, so enabling GPUI's `serde_json/preserve_order` does not alter
generated contracts. Health and credential verification responses are concrete
DTOs. The provider-specific `PayResponse.fiber_result` remains explicitly opaque
JSON for diagnostic/route evidence; it is not a Morph payment receipt.

| Public fields | Encoding |
| --- | --- |
| Durations, Unix seconds, state numbers, block heights/confirmations | Canonical decimal u64 strings |
| Core intent amounts | Canonical decimal u128 strings |
| Requirement/receipt display amounts | Canonical decimal strings checked by domain validators |
| Intent/receipt byte32 IDs and commitments | Lowercase `0x` plus 64 hexadecimal digits |
| Public receipt signer key / signature | Lowercase fixed-length `0x` hex, 33 / 64 bytes |
| Optional Core binding/anchor/proof fields with custom adapters | Required field, explicit null when absent |
| Optional request durations | Omit or null for configured default; otherwise decimal string |
| Small tags, asset decimals, output index | JSON integers |

`wire` provides explicit public serde adapters for Core intents, assets, evidence
and terminal receipts. Core structs keep their own private serde format, binary
IDs, signing digests and validation methods. No JSON-array/number compatibility
reader is supported. Runtime tests round-trip all three Core asset kinds with
maximum quantities and anchored/channel evidence, compare objects/IDs/digests,
and revalidate signatures; missing fields, old byte arrays/numbers, extra keys,
uppercase hex and overflow are rejected. Public deserialization does not itself
prove signature validity; handlers still run the original authority validators.

Script JSON uses a closed `code_hash/hash_type/args` shape. It reuses the pinned
CKB RPC hash-type decoder, including data1..data127, and canonical lowercase hex
for args. No capability is dropped just to simplify the schema. Tests check the
generated hash-type enum against that decoder. Requirement commitments sort
Script object keys before hashing, avoiding insertion-order dependence. Their
private commitment keeps its original integer expiry representation; the public
expiry string is a transport change. The independent authorization fixture's
requirement ID and signature remain unchanged; only its public expiry field and
transport annotation changed.

## Retry limits remain explicit

The endpoint inventory documents each route separately. Reads can be repeated;
verification persists a fresh observation but initiates no payment. Settlement
and fair claims return an existing stored receipt subject to the existing terms,
payer and expiry checks. New challenge/offer calls create fresh identities, and
outgoing pay can already have reached Fiber when the response disappears.
There is **no generic Gateway idempotency key or reviewed-revision contract yet**.
Do not send Hub mutation headers and assume they protect these calls; do not
turn a network error into an automatic new payment. Paid proxy retry safety also
depends on the upstream operation, including after a lost response.

