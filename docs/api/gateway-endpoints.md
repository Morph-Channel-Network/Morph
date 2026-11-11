# Current Payment Gateway endpoints

Generated from `morph_payment_gateway::endpoints`; do not edit the table by hand.
Regenerate with `cargo run -p morph-payment-gateway --example export_api`.

Readiness HTTP 503 returns the same Readiness body as HTTP 200. Other API failures use [GatewayErrorBody](gateway-types/GatewayErrorBody.json).
The normal x402 challenge uses HTTP 402 with PaymentRequirements, not the error
envelope. A proxied upstream error remains the upstream response. Diagnostic
request IDs and API version headers do not grant idempotency or prove payment
non-submission. See [transport and retry rules](gateway-errors.md).

Operator bearer may be omitted only in explicitly allowed local development.
Payer-signature endpoints still validate exact terms and configured outgoing
policy; stored-credential endpoints require the stored receipt and resource.
The operator-only `/v1/events` endpoint pages immutable, redacted local records
with source-bound cursors; it is not a chain-finality or signing interface.
See [event delivery](../runbooks/event-delivery.md). Public liveness is not full readiness. Raw Fiber evidence in PayResponse is an
explicit provider-specific diagnostic object; it is not a signed Morph receipt.

| Method | Path | Authority | Request | Success | Body | Retry semantics |
| --- | --- | --- | --- | --- | --- | --- |
| POST | `/v1/events` | operator_bearer | [EventPageRequest](gateway-types/EventPageRequest.json) | 200 | [EventPage](gateway-types/EventPage.json) | Read-only durable source-bound pagination. Resume with the exact next cursor; never use these local records as independent chain confirmation. |
| GET | `/ready` | operator_bearer | None | 200 | [Readiness](gateway-types/Readiness.json) | Read-only expiring prerequisites. HTTP 503 carries the same Readiness body. No payment authorization, route liquidity or independent chain confirmation is implied. |
| GET | `/metrics` | operator_bearer | None | 200 | Prometheus text | Fixed bounded Prometheus series. Unobserved store values are NaN. Read-only; never retries payments. |
| GET | `/health` | public | None | 200 | [HealthResponse](gateway-types/HealthResponse.json) | Read-only liveness; not readiness. |
| GET | `/v1/supported` | public | None | 200 | [SupportedResponse](gateway-types/SupportedResponse.json) | Read-only. |
| POST | `/v1/challenges` | operator_bearer | [CreateChallengeRequest](gateway-types/CreateChallengeRequest.json) | 200 | [PaymentRequirements](gateway-types/PaymentRequirements.json) | Creates a fresh challenge. Lost response is ambiguous; no idempotency-key replay contract yet. |
| POST | `/v1/x402/challenge` | operator_bearer | [CreateChallengeRequest](gateway-types/CreateChallengeRequest.json) | 402 | [PaymentRequirements](gateway-types/PaymentRequirements.json) | 402 is the successful challenge, also encoded in PAYMENT-REQUIRED. Creates fresh state; no automatic retry. |
| POST | `/v1/pay` | signed_payer_terms | [PayRequest](gateway-types/PayRequest.json) | 200 | [PayResponse](gateway-types/PayResponse.json) | Payment hash binds the exact typed request and configured Fiber endpoint. Only the first durable reservation sends; exact retries query that payment or return its immutable terminal result, including after expiry. Conflicting contents return 409 request_conflict. Unknown outcomes never authorize resubmission. Full provider-neutral/MPP orchestration remains #36. |
| POST | `/v1/x402/verify` | signed_payer_terms | [VerifyRequest](gateway-types/VerifyRequest.json) | 200 | [VerifyResponse](gateway-types/VerifyResponse.json) | Queries Fiber and persists an observation. Does not initiate an outgoing payment. |
| POST | `/v1/x402/settle` | signed_payer_terms | [SettleRequest](gateway-types/SettleRequest.json) | 200 | [SettleResponse](gateway-types/SettleResponse.json) | Validates exact stored terms/payer proof and returns the stored receipt when present. No new outgoing payment; this is not a generic key/body replay contract. |
| POST | `/v1/payment-gateway/authorize` | signed_payer_terms | [SettleRequest](gateway-types/SettleRequest.json) | 200 | [SettleResponse](gateway-types/SettleResponse.json) | Same settlement authority and stored-receipt rules as x402 settle. |
| POST | `/v1/credentials/verify` | stored_credential_and_receipt | [CredentialVerifyRequest](gateway-types/CredentialVerifyRequest.json) | 200 | [CredentialVerifyResponse](gateway-types/CredentialVerifyResponse.json) | Read-only validation of the stored receipt, credential and exact resource. |
| POST | `/v1/fair-exchange/offers` | operator_bearer | [FairExchangeOfferRequest](gateway-types/FairExchangeOfferRequest.json) | 200 | [FairExchangeEnvelope](gateway-types/FairExchangeEnvelope.json) | Creates a fresh encrypted offer and challenge; lost response is ambiguous. No automatic retry. |
| POST | `/v1/fair-exchange/claims` | signed_payer_terms | [FairExchangeClaimRequest](gateway-types/FairExchangeClaimRequest.json) | 200 | [FairExchangeClaim](gateway-types/FairExchangeClaim.json) | Requires the offer's payer authorization and paid settlement before returning the key. Stored-receipt rules apply. |
| GET | `/v1/payments` | operator_bearer | Query: [PaymentListQuery](gateway-types/PaymentListQuery.json) | 200 | [PaymentListResponse](gateway-types/PaymentListResponse.json) | Read-only bounded latest entries; not a cursor or complete historical pagination. |
| GET, HEAD, POST, PUT, PATCH, DELETE | `/gateway/{*path}` | paid_credential_or_payment_signature | Bounded opaque upstream body | upstream | Upstream status/body/selected headers | Exact resource and method authorization. Upstream may mutate even if its response is lost; never infer retry safety from a Gateway timeout. |
