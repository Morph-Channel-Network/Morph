//! Owned public request/response types; no HTTP framework or store state.
use crate::protocol::{PaymentPayload, PaymentReceipt, PaymentRequirements, RgbppAsset};
pub use morph_observability::Readiness;
pub use morph_packages::events::{EventPage, EventPageRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const API_VERSION: &str = "1";
pub const MAX_LIST_PAYMENTS: usize = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateChallengeRequest {
    pub asset: RgbppAsset,
    pub amount: String,
    /// Morph account allowed to sign and claim this challenge.
    pub payer: String,
    pub resource: String,
    pub operation: String,
    pub description: Option<String>,
    #[serde(default, with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub expires_in_seconds: Option<u64>,
    pub rgbpp_proof_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PayRequest {
    pub requirements: PaymentRequirements,
    pub payload: PaymentPayload,
    #[serde(default, with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub timeout_seconds: Option<u64>,
    pub max_fee_amount: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PayResponse {
    pub completed: bool,
    pub payment_hash: String,
    pub fiber_result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub requirements: PaymentRequirements,
    pub payload: PaymentPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyResponse {
    pub valid: bool,
    pub payment_hash: String,
    pub fiber_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettleRequest {
    pub requirements: PaymentRequirements,
    pub payload: PaymentPayload,
    #[serde(default, with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub credential_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettleResponse {
    pub receipt: PaymentReceipt,
    pub payment_preimage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialVerifyRequest {
    pub credential: String,
    pub receipt: PaymentReceipt,
    pub resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FairExchangeOfferRequest {
    pub asset: RgbppAsset,
    pub amount: String,
    /// Morph account allowed to pay for and decrypt this offer.
    pub payer: String,
    pub resource: String,
    pub operation: String,
    pub plaintext_base64: String,
    pub description: Option<String>,
    #[serde(default, with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub expires_in_seconds: Option<u64>,
    pub rgbpp_proof_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FairExchangeClaimRequest {
    pub offer_id: String,
    pub payload: PaymentPayload,
    #[serde(default, with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub credential_ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentListQuery {
    #[serde(default, deserialize_with = "page_limit")]
    #[schemars(schema_with = "page_limit_schema")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportedResponse {
    pub scheme: String,
    pub network: String,
    pub assets: Vec<RgbppAsset>,
    pub payee: String,
    pub capabilities: Vec<String>,
    pub credential_public_key: String,
    pub terminal_receipt_public_key: String,
}

fn page_limit<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<usize>, D::Error> {
    let raw = String::deserialize(d)?;
    let value = raw
        .parse::<usize>()
        .map_err(|_| serde::de::Error::custom("invalid page limit"))?;
    if value == 0 || value > MAX_LIST_PAYMENTS || value.to_string() != raw {
        return Err(serde::de::Error::custom(
            "page limit must be canonical and within bounds",
        ));
    }
    Ok(Some(value))
}

/// Stable machine-readable errors. Human text is not a branching contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GatewayErrorCode {
    InvalidRequest,
    UnknownChallenge,
    PaymentRequired,
    PaymentTimeout,
    PaymentOutcomeUnknown,
    RequestConflict,
    UnsupportedAsset,
    Unauthorized,
    UnknownOffer,
    FiberUnavailable,
    GatewayUnavailable,
    StoreUnavailable,
    StoreCapacityExceeded,
    RateLimited,
    CredentialFailure,
    CryptoFailure,
    InvalidJson,
    InvalidQuery,
    UnsupportedContentType,
    BodyTooLarge,
    RouteNotFound,
    MethodNotAllowed,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatewayErrorBody {
    pub api_version: String,
    pub code: GatewayErrorCode,
    pub request_id: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PaymentDirection {
    Incoming,
    Outgoing,
}

/// Public index entry: deliberately excludes the raw Fiber result and secrets.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentListItem {
    pub payment_hash: String,
    pub requirement_id: String,
    pub direction: PaymentDirection,
    pub status: String,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::decimal::schema")]
    pub updated_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentListResponse {
    pub payments: Vec<PaymentListItem>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialVerifyResponse {
    pub authorized: bool,
}

fn page_limit_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type":"string","minLength":1,"maxLength":4,"pattern":"^([1-9][0-9]{0,2}|1000)$","not":{"pattern":"[^0-9]"}})
}
