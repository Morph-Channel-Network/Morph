use std::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path as AxumPath, Query, RawQuery, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
};
use ckb_types::prelude::Entity;
use k256::ecdsa::{SigningKey, VerifyingKey};
use morph_core::{
    BackendSettlementEvidence, HttpOperation, PaymentHashAlgorithm, PaymentIntent,
    TerminalPaymentStatus, TerminalSettlementReceipt, blake2b256,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    credential::{CredentialClaims, CredentialError, CredentialService},
    crypto::{CryptoError, encrypt, random_byte32, sha256_bytes, sha256_hex, verify_preimage},
    fiber_rpc::{
        FiberRpcClient, FiberRpcError, extract_invoice_address, extract_invoice_payment_hash,
        invoice_is_paid, payment_is_success,
    },
    http_safety::{is_secure_service_url, read_response_limited},
    protocol::{
        AssetKind, FairExchangeClaim, FairExchangeEnvelope, MORPH_PAYER_RECORD_KEY,
        MORPH_REQUIREMENT_RECORD_KEY, PAYMENT_RAIL_FIBER, PAYMENT_REQUIRED_HEADER,
        PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER, PaymentPayload, PaymentReceipt,
        PaymentRequirements, ProtocolError, RgbppAsset, X402_NETWORK, X402_SCHEME, decode_byte32,
        hex32, now_seconds, parse_amount, validate_nonzero_byte32,
    },
    store::{
        ChallengeRecord, DurableStore, PaymentDirection, StoreError, StoredOffer, TrackedPayment,
    },
};

pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024 + 64 * 1024;
pub const MAX_CHALLENGE_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_CHALLENGE_TTL_SECONDS: u64 = 30;
pub const MAX_CREDENTIAL_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_CREDENTIAL_TTL_SECONDS: u64 = 60 * 60;
pub const MAX_LIST_PAYMENTS: usize = 1_000;
pub const MAX_UPSTREAM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_X402_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_OUTGOING_PAYMENT_TIMEOUT_SECONDS: u64 = 10 * 60;
pub const MAX_RESOURCE_BYTES: usize = 2 * 1024;
pub const MAX_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_DURABLE_CREATIONS_PER_MINUTE: usize = 120;
pub const MAX_API_BEARER_TOKEN_BYTES: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unknown or mismatched payment challenge")]
    UnknownChallenge,
    #[error("payment has not reached Fiber's Paid state")]
    PaymentRequired,
    #[error("outgoing Fiber payment did not reach a terminal state before the deadline")]
    PaymentTimeout,
    #[error("requested asset is not configured by this Morph Payment Gateway")]
    UnsupportedAsset,
    #[error("a valid paid Biscuit credential is required")]
    Unauthorized,
    #[error("fair-exchange offer does not exist")]
    UnknownOffer,
    #[error("Fiber RPC is unavailable")]
    FiberUnavailable,
    #[error("configured Gateway upstream is unavailable")]
    GatewayUnavailable,
    #[error("durable gateway state is unavailable")]
    StoreUnavailable,
    #[error("durable gateway capacity is temporarily exhausted")]
    StoreCapacityExceeded,
    #[error("durable creation rate limit exceeded")]
    RateLimited,
    #[error("credential operation failed")]
    CredentialFailure,
    #[error("cryptographic operation failed")]
    CryptoFailure,
}

impl From<ProtocolError> for ServiceError {
    fn from(error: ProtocolError) -> Self {
        Self::InvalidRequest(error.to_string())
    }
}

impl From<FiberRpcError> for ServiceError {
    fn from(_: FiberRpcError) -> Self {
        Self::FiberUnavailable
    }
}

impl From<StoreError> for ServiceError {
    fn from(error: StoreError) -> Self {
        if matches!(error, StoreError::CapacityExceeded) {
            Self::StoreCapacityExceeded
        } else {
            Self::StoreUnavailable
        }
    }
}

impl From<CredentialError> for ServiceError {
    fn from(_: CredentialError) -> Self {
        Self::CredentialFailure
    }
}

impl From<CryptoError> for ServiceError {
    fn from(_: CryptoError) -> Self {
        Self::CryptoFailure
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::InvalidRequest(_) | Self::UnknownChallenge | Self::UnknownOffer => {
                StatusCode::BAD_REQUEST
            }
            Self::PaymentRequired => StatusCode::PAYMENT_REQUIRED,
            Self::PaymentTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::UnsupportedAsset => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::FiberUnavailable | Self::GatewayUnavailable => StatusCode::BAD_GATEWAY,
            Self::StoreCapacityExceeded => StatusCode::SERVICE_UNAVAILABLE,
            Self::StoreUnavailable | Self::CredentialFailure | Self::CryptoFailure => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}

#[derive(Clone)]
pub struct PaymentGatewayConfig {
    pub payee: String,
    /// Morph identity allowed to authorize outgoing Fiber wallet spends.
    /// When absent, the public `/v1/pay` endpoint is disabled.
    pub outgoing_payer: Option<String>,
    /// Deployment cap for one outgoing Fiber routing fee. Required whenever
    /// `outgoing_payer` enables the wallet-spending endpoint.
    pub outgoing_max_fee_amount: Option<u128>,
    /// Deployment cap for an outgoing payment RPC timeout.
    pub outgoing_payment_timeout_seconds: u64,
    /// One of Fiber's `Fibb`, `Fibt`, or `Fibd` currency names.
    pub currency: String,
    pub supported_assets: Vec<RgbppAsset>,
    /// Proof commitments admitted by an operator-controlled RGB++ verifier.
    pub verified_rgbpp_proof_commitments: BTreeSet<String>,
    pub default_credential_ttl_seconds: u64,
    /// Fixed HTTP(S) origin used by `/gateway/*`. It is never chosen by a request.
    pub upstream_base_url: Option<String>,
    /// Bearer required for durable creation and operator-observability routes.
    /// It may be omitted only for a loopback-only development listener.
    pub api_bearer_token: Option<String>,
}

#[derive(Clone)]
struct GatewayUpstream {
    base_url: reqwest::Url,
    client: reqwest::Client,
}

impl GatewayUpstream {
    fn new(value: &str) -> Result<Self, ServiceError> {
        let mut base_url = reqwest::Url::parse(value).map_err(|_| {
            ServiceError::InvalidRequest("invalid Gateway upstream URL".to_string())
        })?;
        if !is_secure_service_url(&base_url)
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(ServiceError::InvalidRequest(
                "Gateway upstream must be a fixed HTTP(S) origin/path without query or fragment"
                    .to_string(),
            ));
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ServiceError::GatewayUnavailable)?;
        Ok(Self { base_url, client })
    }
}

pub struct PaymentGatewayService {
    config: PaymentGatewayConfig,
    api_bearer_token_hash: Option<[u8; 32]>,
    fiber: FiberRpcClient,
    store: Arc<DurableStore>,
    credentials: CredentialService,
    receipt_signing_key: SigningKey,
    upstream: Option<GatewayUpstream>,
    creation_limiter: Mutex<CreationRateLimiter>,
}

struct CreationRateLimiter {
    accepted: VecDeque<Instant>,
}

impl CreationRateLimiter {
    fn new() -> Self {
        Self {
            accepted: VecDeque::new(),
        }
    }

    fn check(&mut self, now: Instant) -> bool {
        let window = Duration::from_secs(60);
        while self
            .accepted
            .front()
            .is_some_and(|accepted| now.saturating_duration_since(*accepted) >= window)
        {
            self.accepted.pop_front();
        }
        if self.accepted.len() >= MAX_DURABLE_CREATIONS_PER_MINUTE {
            return false;
        }
        self.accepted.push_back(now);
        true
    }
}

impl PaymentGatewayService {
    pub fn new(
        config: PaymentGatewayConfig,
        fiber: FiberRpcClient,
        store: Arc<DurableStore>,
        credentials: CredentialService,
        receipt_signing_key: SigningKey,
    ) -> Result<Self, ServiceError> {
        if !matches!(config.currency.as_str(), "Fibb" | "Fibt" | "Fibd")
            || config.supported_assets.is_empty()
            || config.default_credential_ttl_seconds == 0
            || config.default_credential_ttl_seconds > MAX_CREDENTIAL_TTL_SECONDS
        {
            return Err(ServiceError::InvalidRequest(
                "invalid payee, Fiber currency, asset catalog, or credential TTL".to_string(),
            ));
        }
        validate_nonzero_byte32(&config.payee)?;
        match (&config.outgoing_payer, config.outgoing_max_fee_amount) {
            (Some(payer), Some(_)) => {
                validate_nonzero_byte32(payer)?;
                if payer == &config.payee {
                    return Err(ServiceError::InvalidRequest(
                        "outgoing payer and incoming payee must differ".to_string(),
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ServiceError::InvalidRequest(
                    "outgoing payer and maximum fee must be configured together".to_string(),
                ));
            }
        }
        if config.outgoing_payment_timeout_seconds == 0
            || config.outgoing_payment_timeout_seconds > MAX_OUTGOING_PAYMENT_TIMEOUT_SECONDS
        {
            return Err(ServiceError::InvalidRequest(
                "outgoing payment timeout is outside the allowed range".to_string(),
            ));
        }
        for commitment in &config.verified_rgbpp_proof_commitments {
            validate_nonzero_byte32(commitment)?;
        }
        for asset in &config.supported_assets {
            asset.validate()?;
        }
        if config
            .api_bearer_token
            .as_ref()
            .is_some_and(|token| !(32..=MAX_API_BEARER_TOKEN_BYTES).contains(&token.len()))
        {
            return Err(ServiceError::InvalidRequest(format!(
                "Payment Gateway API bearer token must contain 32 to {MAX_API_BEARER_TOKEN_BYTES} bytes"
            )));
        }
        let upstream = config
            .upstream_base_url
            .as_deref()
            .map(GatewayUpstream::new)
            .transpose()?;
        let api_bearer_token_hash = config
            .api_bearer_token
            .as_deref()
            .map(|token| blake2b256(token.as_bytes()));
        Ok(Self {
            config,
            api_bearer_token_hash,
            fiber,
            store,
            credentials,
            receipt_signing_key,
            upstream,
            creation_limiter: Mutex::new(CreationRateLimiter::new()),
        })
    }

    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/health", get(health))
            .route("/v1/supported", get(supported))
            .route("/v1/challenges", post(create_challenge))
            .route("/v1/x402/challenge", post(create_x402_challenge))
            .route("/v1/pay", post(pay))
            .route("/v1/x402/verify", post(verify))
            .route("/v1/x402/settle", post(settle))
            .route("/v1/payment-gateway/authorize", post(settle))
            .route("/v1/credentials/verify", post(verify_credential))
            .route("/v1/fair-exchange/offers", post(create_fair_offer))
            .route("/v1/fair-exchange/claims", post(claim_fair_offer))
            .route("/v1/payments", get(list_payments))
            .route("/gateway/{*path}", any(gateway_proxy))
            .layer(DefaultBodyLimit::max(DEFAULT_MAX_BODY_BYTES))
            .with_state(self)
    }

    fn require_api_bearer(&self, headers: &HeaderMap) -> Result<(), ServiceError> {
        let Some(expected_hash) = self.api_bearer_token_hash.as_ref() else {
            return Ok(());
        };
        let supplied = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        if supplied.len() > MAX_API_BEARER_TOKEN_BYTES {
            return Err(ServiceError::Unauthorized);
        }
        let supplied_hash = blake2b256(supplied.as_bytes());
        if constant_time_equal(&supplied_hash, expected_hash) {
            Ok(())
        } else {
            Err(ServiceError::Unauthorized)
        }
    }

    async fn make_challenge(
        &self,
        request: &CreateChallengeRequest,
        payment_preimage: [u8; 32],
    ) -> Result<PaymentRequirements, ServiceError> {
        if !self
            .creation_limiter
            .lock()
            .map_err(|_| ServiceError::StoreUnavailable)?
            .check(Instant::now())
        {
            return Err(ServiceError::RateLimited);
        }
        self.require_supported_asset(&request.asset)?;
        match (&request.asset.kind, &request.rgbpp_proof_commitment) {
            (AssetKind::Rgbpp, Some(commitment))
                if self
                    .config
                    .verified_rgbpp_proof_commitments
                    .contains(commitment) => {}
            (AssetKind::Rgbpp, _) => return Err(ServiceError::UnsupportedAsset),
            (AssetKind::Ckb, None) => {}
            (AssetKind::Ckb, Some(_)) => {
                return Err(ServiceError::InvalidRequest(
                    "ordinary CKB must not carry RGB++ proof evidence".to_string(),
                ));
            }
        }
        let amount = parse_amount(&request.amount)?;
        validate_nonzero_byte32(&request.payer)?;
        if request.payer == self.config.payee {
            return Err(ServiceError::InvalidRequest(
                "challenge payer and payee must differ".to_string(),
            ));
        }
        validate_resource(&request.resource)?;
        if request.resource.len() > MAX_RESOURCE_BYTES {
            return Err(ServiceError::InvalidRequest(
                "resource exceeds the safety limit".to_string(),
            ));
        }
        validate_operation(&request.operation)?;
        if request
            .description
            .as_ref()
            .is_some_and(|description| description.len() > MAX_DESCRIPTION_BYTES)
        {
            return Err(ServiceError::InvalidRequest(
                "description exceeds the safety limit".to_string(),
            ));
        }
        let ttl = request.expires_in_seconds.unwrap_or(300);
        if !(MIN_CHALLENGE_TTL_SECONDS..=MAX_CHALLENGE_TTL_SECONDS).contains(&ttl) {
            return Err(ServiceError::InvalidRequest(
                "challenge TTL is outside the allowed range".to_string(),
            ));
        }
        let now = now_seconds();
        let expires_at = now
            .checked_add(ttl)
            .ok_or_else(|| ServiceError::InvalidRequest("challenge expiry overflow".to_string()))?;
        let preimage = hex32(&payment_preimage);
        let expected_payment_hash = sha256_hex(&payment_preimage);
        let invoice_result = self
            .fiber
            .new_invoice(json!({
                "amount": format!("0x{amount:x}"),
                "description": request.description,
                "currency": self.config.currency,
                "payment_preimage": preimage,
                "payment_hash": null,
                "expiry": format!("0x{ttl:x}"),
                "fallback_address": null,
                "final_expiry_delta": null,
                "udt_type_script": match request.asset.kind {
                    AssetKind::Ckb => None,
                    AssetKind::Rgbpp => request.asset.type_script.clone(),
                },
                "hash_algorithm": "sha256",
                "allow_mpp": true,
                "allow_trampoline_routing": true,
            }))
            .await?;
        let invoice = extract_invoice_address(&invoice_result)?.to_string();
        let payment_hash = extract_invoice_payment_hash(&invoice_result)?.to_string();
        if payment_hash != expected_payment_hash {
            return Err(ServiceError::FiberUnavailable);
        }
        let mut requirement = PaymentRequirements {
            requirement_id: hex32(&[0_u8; 32]),
            scheme: X402_SCHEME.to_string(),
            network: X402_NETWORK.to_string(),
            payment_rail: PAYMENT_RAIL_FIBER.to_string(),
            asset: request.asset.clone(),
            amount: request.amount.clone(),
            payer: request.payer.clone(),
            payee: self.config.payee.clone(),
            invoice,
            payment_hash,
            hash_algorithm: "sha256".to_string(),
            resource: request.resource.clone(),
            operation: request.operation.clone(),
            nonce: hex32(&random_byte32()),
            rgbpp_proof_commitment: request.rgbpp_proof_commitment.clone(),
            expires_at,
        };
        requirement.requirement_id = requirement.expected_id()?;
        requirement.validate(now)?;
        validate_fiber_invoice(&invoice_result, &requirement, &self.config.currency)?;
        self.store.insert_challenge(ChallengeRecord {
            requirement: requirement.clone(),
            payment_preimage: preimage,
            created_at: now,
        })?;
        Ok(requirement)
    }

    fn require_supported_asset(&self, requested: &RgbppAsset) -> Result<(), ServiceError> {
        let requested_id = requested.canonical_id()?;
        let exact = self.config.supported_assets.iter().any(|configured| {
            configured.canonical_id().ok().as_ref() == Some(&requested_id)
                && configured.type_script == requested.type_script
        });
        if exact {
            Ok(())
        } else {
            Err(ServiceError::UnsupportedAsset)
        }
    }

    async fn verify_payment(
        &self,
        requirements: &PaymentRequirements,
        payload: &PaymentPayload,
    ) -> Result<String, ServiceError> {
        let now = now_seconds();
        requirements.validate(now)?;
        let stored = self
            .store
            .challenge(&requirements.requirement_id)?
            .filter(|record| record.requirement == *requirements)
            .ok_or(ServiceError::UnknownChallenge)?;
        payload.validate(requirements)?;
        if let Some(preimage) = &payload.payment_preimage {
            verify_preimage(&requirements.payment_hash, preimage)?;
            return Ok("preimage_verified".to_string());
        }
        // `stored` proves the request was generated locally. Do not expose its
        // preimage until Fiber independently reports the incoming invoice Paid.
        let _secret_kept_out_of_rpc = &stored.payment_preimage;
        let invoice = self.fiber.get_invoice(&requirements.payment_hash).await?;
        let status = invoice
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string();
        self.store.record_payment(TrackedPayment {
            payment_hash: requirements.payment_hash.clone(),
            requirement_id: requirements.requirement_id.clone(),
            direction: PaymentDirection::Incoming,
            status: status.clone(),
            updated_at: now,
            fiber_result: invoice.clone(),
        })?;
        if !invoice_is_paid(&invoice) {
            return Err(ServiceError::PaymentRequired);
        }
        Ok(status)
    }

    async fn settle_requirement(
        &self,
        requirements: &PaymentRequirements,
        payload: &PaymentPayload,
        credential_ttl_seconds: Option<u64>,
    ) -> Result<(PaymentReceipt, String), ServiceError> {
        let challenge = self
            .store
            .challenge(&requirements.requirement_id)?
            .filter(|record| record.requirement == *requirements)
            .ok_or(ServiceError::UnknownChallenge)?;
        payload.validate(requirements)?;
        if let Some(receipt) = self.store.receipt(&requirements.requirement_id)? {
            if receipt.payer != payload.payer {
                return Err(ServiceError::UnknownChallenge);
            }
            return Ok((receipt, challenge.payment_preimage));
        }
        let fiber_status = self.verify_payment(requirements, payload).await?;
        let now = now_seconds();
        let ttl = credential_ttl_seconds.unwrap_or(self.config.default_credential_ttl_seconds);
        if ttl == 0 || ttl > MAX_CREDENTIAL_TTL_SECONDS {
            return Err(ServiceError::InvalidRequest(
                "credential TTL is outside the allowed range".to_string(),
            ));
        }
        let credential_expires_at = now.checked_add(ttl).ok_or_else(|| {
            ServiceError::InvalidRequest("credential expiry overflow".to_string())
        })?;
        let claims = CredentialClaims {
            credential_id: hex32(&random_byte32()),
            payment_hash: requirements.payment_hash.clone(),
            asset_id: requirements.asset.canonical_id()?,
            amount: requirements.amount.clone(),
            resource: requirements.resource.clone(),
            operation: requirements.operation.clone(),
            expires_at: credential_expires_at,
        };
        let credential = self.credentials.mint(claims.clone(), now)?;
        let mut intent = PaymentIntent {
            intent_id: [0; 32],
            payer: decode_byte32(&payload.payer)?,
            payee: decode_byte32(&requirements.payee)?,
            asset: requirements.asset.to_gateway_asset()?,
            amount: requirements.amount_u128()?,
            payment_hash: decode_byte32(&requirements.payment_hash)?,
            hash_algorithm: PaymentHashAlgorithm::Sha256,
            resource: requirements.resource.clone(),
            operation: core_http_operation(&requirements.operation)?,
            nonce: decode_byte32(&requirements.nonce)?,
            idempotency_key: decode_byte32(&requirements.requirement_id)?,
            created_at_unix: challenge.created_at,
            expires_at_unix: requirements.expires_at,
            required_rgbpp_proof_commitment: requirements
                .rgbpp_proof_commitment
                .as_deref()
                .map(decode_byte32)
                .transpose()?,
            channel_binding: None,
        };
        intent.intent_id = intent.derive_id().map_err(|error| {
            ServiceError::InvalidRequest(format!("invalid canonical payment intent: {error}"))
        })?;
        let opaque_commitment = sha256_bytes(
            format!(
                "morph-fiber-settlement-v1\0{}\0{}\0{}",
                requirements.requirement_id, requirements.payment_hash, fiber_status
            )
            .as_bytes(),
        );
        let terminal_receipt = TerminalSettlementReceipt::new_signed(
            &intent,
            TerminalPaymentStatus::Settled,
            BackendSettlementEvidence {
                provider_id: "fiber-json-rpc".to_string(),
                settlement_id: decode_byte32(&requirements.payment_hash)?,
                opaque_commitment,
                morph_state: None,
                ckb_anchor: None,
                rgbpp_proof_commitment: intent.required_rgbpp_proof_commitment,
                failure_code: None,
            },
            now,
            &self.receipt_signing_key,
        )
        .map_err(|_| ServiceError::CredentialFailure)?;
        let receipt_id = hex32(&terminal_receipt.receipt_id);
        let receipt = self.store.settle_once(PaymentReceipt {
            receipt_id,
            credential_id: claims.credential_id,
            requirement_id: requirements.requirement_id.clone(),
            payment_hash: requirements.payment_hash.clone(),
            payer: payload.payer.clone(),
            asset_id: claims.asset_id,
            amount: requirements.amount.clone(),
            resource: requirements.resource.clone(),
            operation: requirements.operation.clone(),
            paid_at: now,
            fiber_status,
            credential,
            credential_expires_at,
            intent,
            terminal_receipt,
        })?;
        // Another request can win `settle_once` after the lookup above. Do not
        // release its bearer credential or preimage across payer identities.
        if receipt.payer != payload.payer {
            return Err(ServiceError::UnknownChallenge);
        }
        Ok((receipt, challenge.payment_preimage))
    }
}

fn core_http_operation(operation: &str) -> Result<HttpOperation, ServiceError> {
    match operation {
        "GET" => Ok(HttpOperation::Get),
        "HEAD" => Ok(HttpOperation::Head),
        "POST" => Ok(HttpOperation::Post),
        "PUT" => Ok(HttpOperation::Put),
        "PATCH" => Ok(HttpOperation::Patch),
        "DELETE" => Ok(HttpOperation::Delete),
        _ => Err(ServiceError::InvalidRequest(
            "operation is not a supported upper-case HTTP method".to_string(),
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChallengeRequest {
    pub asset: RgbppAsset,
    pub amount: String,
    /// Morph account allowed to sign and claim this challenge.
    pub payer: String,
    pub resource: String,
    pub operation: String,
    pub description: Option<String>,
    pub expires_in_seconds: Option<u64>,
    pub rgbpp_proof_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayRequest {
    pub requirements: PaymentRequirements,
    pub payload: PaymentPayload,
    pub timeout_seconds: Option<u64>,
    pub max_fee_amount: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayResponse {
    pub completed: bool,
    pub payment_hash: String,
    pub fiber_result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub requirements: PaymentRequirements,
    pub payload: PaymentPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub payment_hash: String,
    pub fiber_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleRequest {
    pub requirements: PaymentRequirements,
    pub payload: PaymentPayload,
    pub credential_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleResponse {
    pub receipt: PaymentReceipt,
    pub payment_preimage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVerifyRequest {
    pub credential: String,
    pub receipt: PaymentReceipt,
    pub resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairExchangeOfferRequest {
    pub asset: RgbppAsset,
    pub amount: String,
    /// Morph account allowed to pay for and decrypt this offer.
    pub payer: String,
    pub resource: String,
    pub operation: String,
    pub plaintext_base64: String,
    pub description: Option<String>,
    pub expires_in_seconds: Option<u64>,
    pub rgbpp_proof_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairExchangeClaimRequest {
    pub offer_id: String,
    pub payload: PaymentPayload,
    pub credential_ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PaymentListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SupportedResponse {
    scheme: &'static str,
    network: &'static str,
    assets: Vec<RgbppAsset>,
    payee: String,
    capabilities: Vec<&'static str>,
    credential_public_key: String,
    terminal_receipt_public_key: String,
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn supported(State(service): State<Arc<PaymentGatewayService>>) -> Json<SupportedResponse> {
    let mut capabilities = vec![
        "x402_exact",
        "fiber_json_rpc",
        "biscuit_credentials",
        "fair_exchange_aes_256_gcm",
        "durable_payment_index",
    ];
    if service.upstream.is_some() {
        capabilities.push("fixed_upstream_gateway");
    }
    Json(SupportedResponse {
        scheme: X402_SCHEME,
        network: X402_NETWORK,
        assets: service.config.supported_assets.clone(),
        payee: service.config.payee.clone(),
        capabilities,
        credential_public_key: service.credentials.public_key(),
        terminal_receipt_public_key: hex::encode(
            service
                .receipt_signing_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes(),
        ),
    })
}

async fn create_challenge(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<CreateChallengeRequest>,
) -> Result<Json<PaymentRequirements>, ServiceError> {
    service.require_api_bearer(&headers)?;
    let requirement = service.make_challenge(&request, random_byte32()).await?;
    Ok(Json(requirement))
}

/// HTTP-native x402 challenge endpoint. The same canonical requirement is
/// returned in the body and in the `PAYMENT-REQUIRED` header.
async fn create_x402_challenge(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<CreateChallengeRequest>,
) -> Result<Response, ServiceError> {
    service.require_api_bearer(&headers)?;
    let requirement = service.make_challenge(&request, random_byte32()).await?;
    let encoded = encode_x402_header(&requirement)?;
    let mut response = (StatusCode::PAYMENT_REQUIRED, Json(requirement)).into_response();
    response.headers_mut().insert(
        PAYMENT_REQUIRED_HEADER,
        encoded
            .parse()
            .map_err(|_| ServiceError::InvalidRequest("x402 header is invalid".to_string()))?,
    );
    Ok(response)
}

async fn pay(
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<PayRequest>,
) -> Result<Json<PayResponse>, ServiceError> {
    let now = now_seconds();
    request.requirements.validate(now)?;
    request.payload.validate(&request.requirements)?;
    if service.config.outgoing_payer.as_deref() != Some(request.payload.payer.as_str()) {
        return Err(ServiceError::Unauthorized);
    }
    let parsed = service
        .fiber
        .parse_invoice(&request.requirements.invoice)
        .await?;
    validate_fiber_invoice(&parsed, &request.requirements, &service.config.currency)?;
    let max_fee = request
        .max_fee_amount
        .as_deref()
        .map(parse_amount)
        .transpose()?;
    let configured_max_fee = service
        .config
        .outgoing_max_fee_amount
        .ok_or(ServiceError::Unauthorized)?;
    let max_fee = max_fee.unwrap_or(configured_max_fee);
    if max_fee > configured_max_fee {
        return Err(ServiceError::Unauthorized);
    }
    let timeout = request
        .timeout_seconds
        .unwrap_or(service.config.outgoing_payment_timeout_seconds);
    if timeout == 0 || timeout > service.config.outgoing_payment_timeout_seconds {
        return Err(ServiceError::Unauthorized);
    }
    let payment_hash = request.requirements.payment_hash.clone();
    service.store.record_payment(TrackedPayment {
        payment_hash: payment_hash.clone(),
        requirement_id: request.requirements.requirement_id.clone(),
        direction: PaymentDirection::Outgoing,
        status: "PendingSubmission".to_string(),
        updated_at: now,
        fiber_result: json!({ "status": "PendingSubmission" }),
    })?;
    let initial_result = service
        .fiber
        .send_payment(json!({
            "invoice": request.requirements.invoice,
            "timeout": format!("0x{timeout:x}"),
            "max_fee_amount": format!("0x{max_fee:x}"),
            "custom_records": {
                format!("0x{MORPH_REQUIREMENT_RECORD_KEY:x}"):
                    request.requirements.requirement_id,
                format!("0x{MORPH_PAYER_RECORD_KEY:x}"): request.payload.payer,
            },
        }))
        .await?;
    let reported_payment_hash = initial_result
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or(ServiceError::FiberUnavailable)?;
    if reported_payment_hash != payment_hash {
        return Err(ServiceError::FiberUnavailable);
    }
    let initial_status = initial_result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();
    service.store.record_payment(TrackedPayment {
        payment_hash: payment_hash.clone(),
        requirement_id: request.requirements.requirement_id.clone(),
        direction: PaymentDirection::Outgoing,
        status: initial_status,
        updated_at: now_seconds(),
        fiber_result: initial_result.clone(),
    })?;
    let result = if payment_is_terminal(&initial_result) {
        initial_result
    } else {
        wait_for_payment(&service.fiber, &payment_hash, Duration::from_secs(timeout)).await?
    };
    if result
        .get("payment_hash")
        .and_then(Value::as_str)
        .is_some_and(|reported| reported != payment_hash)
    {
        return Err(ServiceError::FiberUnavailable);
    }
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();
    let completed = payment_is_success(&result);
    service.store.record_payment(TrackedPayment {
        payment_hash: payment_hash.clone(),
        requirement_id: request.requirements.requirement_id,
        direction: PaymentDirection::Outgoing,
        status,
        updated_at: now_seconds(),
        fiber_result: result.clone(),
    })?;
    Ok(Json(PayResponse {
        completed,
        payment_hash,
        fiber_result: result,
    }))
}

async fn verify(
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ServiceError> {
    let fiber_status = service
        .verify_payment(&request.requirements, &request.payload)
        .await?;
    Ok(Json(VerifyResponse {
        valid: true,
        payment_hash: request.requirements.payment_hash,
        fiber_status,
    }))
}

async fn settle(
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, ServiceError> {
    let (receipt, payment_preimage) = service
        .settle_requirement(
            &request.requirements,
            &request.payload,
            request.credential_ttl_seconds,
        )
        .await?;
    Ok(Json(SettleResponse {
        receipt,
        payment_preimage,
    }))
}

async fn verify_credential(
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<CredentialVerifyRequest>,
) -> Result<Json<Value>, ServiceError> {
    if request.credential != request.receipt.credential
        || service
            .store
            .receipt_for_credential(&request.credential)?
            .as_ref()
            != Some(&request.receipt)
    {
        return Err(ServiceError::Unauthorized);
    }
    request
        .receipt
        .validate_for_signer(
            service
                .receipt_signing_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes(),
        )
        .map_err(|_| ServiceError::Unauthorized)?;
    if request.resource != request.receipt.resource {
        return Err(ServiceError::CredentialFailure);
    }
    service.credentials.verify(
        &request.credential,
        &CredentialClaims {
            credential_id: request.receipt.credential_id,
            payment_hash: request.receipt.payment_hash,
            asset_id: request.receipt.asset_id,
            amount: request.receipt.amount,
            resource: request.resource,
            operation: request.receipt.operation,
            expires_at: request.receipt.credential_expires_at,
        },
        now_seconds(),
    )?;
    Ok(Json(json!({ "authorized": true })))
}

async fn create_fair_offer(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<FairExchangeOfferRequest>,
) -> Result<Json<FairExchangeEnvelope>, ServiceError> {
    service.require_api_bearer(&headers)?;
    let plaintext = BASE64.decode(&request.plaintext_base64).map_err(|_| {
        ServiceError::InvalidRequest("plaintext_base64 is not valid base64".to_string())
    })?;
    if plaintext.is_empty() || plaintext.len() > 1024 * 1024 {
        return Err(ServiceError::InvalidRequest(
            "fair-exchange plaintext must contain 1 byte to 1 MiB".to_string(),
        ));
    }
    let offer_id = hex32(&random_byte32());
    let key = random_byte32();
    let challenge_request = CreateChallengeRequest {
        asset: request.asset,
        amount: request.amount,
        payer: request.payer,
        resource: request.resource,
        operation: request.operation,
        description: request.description,
        expires_in_seconds: request.expires_in_seconds,
        rgbpp_proof_commitment: request.rgbpp_proof_commitment,
    };
    let requirement = service.make_challenge(&challenge_request, key).await?;
    let associated_data = format!(
        "morph-fair-exchange-v1\0{}\0{}",
        offer_id, requirement.requirement_id
    );
    let encrypted = encrypt(&key, &plaintext, associated_data.as_bytes())?;
    let envelope = FairExchangeEnvelope {
        offer_id: offer_id.clone(),
        requirement,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
        result_hash: encrypted.plaintext_hash,
    };
    service.store.insert_offer(StoredOffer {
        envelope: envelope.clone(),
        decryption_key: hex32(&key),
        associated_data,
    })?;
    Ok(Json(envelope))
}

async fn claim_fair_offer(
    State(service): State<Arc<PaymentGatewayService>>,
    Json(request): Json<FairExchangeClaimRequest>,
) -> Result<Json<FairExchangeClaim>, ServiceError> {
    let offer = service
        .store
        .offer(&request.offer_id)?
        .ok_or(ServiceError::UnknownOffer)?;
    if request.payload.requirement_id != offer.envelope.requirement.requirement_id
        || request.payload.payment_hash != offer.envelope.requirement.payment_hash
    {
        return Err(ServiceError::UnknownOffer);
    }
    let (receipt, payment_preimage) = service
        .settle_requirement(
            &offer.envelope.requirement,
            &request.payload,
            request.credential_ttl_seconds,
        )
        .await?;
    if payment_preimage != offer.decryption_key {
        return Err(ServiceError::CryptoFailure);
    }
    Ok(Json(FairExchangeClaim {
        offer_id: request.offer_id,
        decryption_key: offer.decryption_key,
        receipt,
    }))
}

async fn list_payments(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    Query(query): Query<PaymentListQuery>,
) -> Result<Json<Value>, ServiceError> {
    service.require_api_bearer(&headers)?;
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_LIST_PAYMENTS);
    let payments = service
        .store
        .payments(limit)?
        .into_iter()
        .map(|payment| {
            json!({
                "payment_hash": payment.payment_hash,
                "requirement_id": payment.requirement_id,
                "direction": payment.direction,
                "status": payment.status,
                "updated_at": payment.updated_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "payments": payments,
        "source": "morph_payment_gateway_durable_index",
    })))
}

async fn gateway_proxy(
    State(service): State<Arc<PaymentGatewayService>>,
    AxumPath(path): AxumPath<String>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ServiceError> {
    let upstream = service
        .upstream
        .as_ref()
        .ok_or(ServiceError::GatewayUnavailable)?;
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(':')
        || path.contains('\\')
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return Err(ServiceError::InvalidRequest(
            "invalid Gateway path".to_string(),
        ));
    }
    validate_operation(method.as_str())?;
    let resource = match query.as_deref() {
        Some(query) if !query.is_empty() => format!("/{path}?{query}"),
        _ => format!("/{path}"),
    };
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty());
    let payment_signature = headers
        .get(PAYMENT_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty());
    let payment_response = match (bearer, payment_signature) {
        (Some(authorization), None) => {
            let receipt = service
                .store
                .receipt_for_credential(authorization)?
                .ok_or(ServiceError::Unauthorized)?;
            receipt
                .validate_for_signer(
                    service
                        .receipt_signing_key
                        .verifying_key()
                        .to_sec1_point(true)
                        .as_bytes(),
                )
                .map_err(|_| ServiceError::Unauthorized)?;
            if receipt.resource != resource || receipt.operation != method.as_str() {
                return Err(ServiceError::Unauthorized);
            }
            service.credentials.verify(
                authorization,
                &CredentialClaims {
                    credential_id: receipt.credential_id,
                    payment_hash: receipt.payment_hash,
                    asset_id: receipt.asset_id,
                    amount: receipt.amount,
                    resource: resource.clone(),
                    operation: method.as_str().to_string(),
                    expires_at: receipt.credential_expires_at,
                },
                now_seconds(),
            )?;
            None
        }
        (None, Some(encoded)) => {
            let request: SettleRequest = decode_x402_header(encoded)?;
            if request.requirements.resource != resource
                || request.requirements.operation != method.as_str()
            {
                return Err(ServiceError::Unauthorized);
            }
            let (receipt, _) = service
                .settle_requirement(
                    &request.requirements,
                    &request.payload,
                    request.credential_ttl_seconds,
                )
                .await?;
            Some(encode_x402_header(&receipt)?)
        }
        (Some(_), Some(_)) => {
            return Err(ServiceError::InvalidRequest(
                "send either a paid credential or PAYMENT-SIGNATURE, not both".to_string(),
            ));
        }
        (None, None) => return Err(ServiceError::PaymentRequired),
    };

    let mut url = upstream
        .base_url
        .join(&path)
        .map_err(|_| ServiceError::InvalidRequest("invalid Gateway path".to_string()))?;
    url.set_query(query.as_deref());
    let mut request = upstream.client.request(method, url).body(body);
    for name in [
        header::ACCEPT,
        header::CONTENT_TYPE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_UNMODIFIED_SINCE,
        header::RANGE,
    ] {
        if let Some(value) = headers.get(&name) {
            request = request.header(name, value);
        }
    }
    let response = request
        .send()
        .await
        .map_err(|_| ServiceError::GatewayUnavailable)?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let response_body = read_response_limited(response, MAX_UPSTREAM_RESPONSE_BYTES)
        .await
        .map_err(|_| ServiceError::GatewayUnavailable)?
        .ok_or(ServiceError::GatewayUnavailable)?;
    let mut builder = Response::builder().status(status);
    for name in [
        header::CONTENT_TYPE,
        header::CACHE_CONTROL,
        header::ETAG,
        header::LAST_MODIFIED,
        header::CONTENT_RANGE,
    ] {
        if let Some(value) = response_headers.get(&name) {
            builder = builder.header(name, value);
        }
    }
    if let Some(encoded) = payment_response {
        builder = builder.header(PAYMENT_RESPONSE_HEADER, encoded);
    }
    builder
        .body(Body::from(response_body))
        .map_err(|_| ServiceError::GatewayUnavailable)
}

fn encode_x402_header(value: &impl Serialize) -> Result<String, ServiceError> {
    let raw = serde_json::to_vec(value)
        .map_err(|_| ServiceError::InvalidRequest("x402 payload is invalid".to_string()))?;
    let encoded = BASE64URL.encode(raw);
    if encoded.len() > MAX_X402_HEADER_BYTES {
        return Err(ServiceError::InvalidRequest(
            "x402 header exceeds the safety limit".to_string(),
        ));
    }
    Ok(encoded)
}

fn decode_x402_header<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, ServiceError> {
    if value.len() > MAX_X402_HEADER_BYTES {
        return Err(ServiceError::InvalidRequest(
            "x402 header exceeds the safety limit".to_string(),
        ));
    }
    let raw = BASE64URL
        .decode(value)
        .map_err(|_| ServiceError::InvalidRequest("x402 header is not base64url".to_string()))?;
    serde_json::from_slice(&raw)
        .map_err(|_| ServiceError::InvalidRequest("x402 header payload is invalid".to_string()))
}

fn validate_resource(resource: &str) -> Result<(), ServiceError> {
    if !resource.starts_with('/') || resource.starts_with("//") || resource.contains("://") {
        return Err(ServiceError::InvalidRequest(
            "resource must be an absolute path without a URL authority".to_string(),
        ));
    }
    Ok(())
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_operation(operation: &str) -> Result<(), ServiceError> {
    if matches!(
        operation,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
    ) {
        Ok(())
    } else {
        Err(ServiceError::InvalidRequest(
            "operation is not a supported upper-case HTTP method".to_string(),
        ))
    }
}

fn parse_fiber_amount(value: Option<&Value>) -> Result<u128, ServiceError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(ServiceError::FiberUnavailable)?;
    let raw = value
        .strip_prefix("0x")
        .ok_or(ServiceError::FiberUnavailable)?;
    u128::from_str_radix(raw, 16).map_err(|_| ServiceError::FiberUnavailable)
}

fn validate_fiber_invoice(
    value: &Value,
    requirements: &PaymentRequirements,
    expected_currency: &str,
) -> Result<(), ServiceError> {
    let invoice = value.get("invoice").ok_or(ServiceError::FiberUnavailable)?;
    if invoice.get("currency").and_then(Value::as_str) != Some(expected_currency)
        || invoice
            .get("signature")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || extract_invoice_payment_hash(value)? != requirements.payment_hash
        || parse_fiber_amount(invoice.get("amount"))? != requirements.amount_u128()?
    {
        return Err(ServiceError::InvalidRequest(
            "Fiber invoice does not match the committed payment requirement".to_string(),
        ));
    }
    let attrs = invoice
        .pointer("/data/attrs")
        .and_then(Value::as_array)
        .ok_or(ServiceError::FiberUnavailable)?;
    let hash_algorithm = unique_invoice_attribute(attrs, "hash_algorithm")?
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServiceError::InvalidRequest("Fiber invoice does not commit SHA-256".to_string())
        })?;
    if hash_algorithm != "sha256" {
        return Err(ServiceError::InvalidRequest(
            "Fiber invoice does not commit SHA-256".to_string(),
        ));
    }
    let payee_pubkey = unique_invoice_attribute(attrs, "payee_public_key")?
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServiceError::InvalidRequest("Fiber invoice does not identify its payee".to_string())
        })?;
    let payee_pubkey = hex::decode(payee_pubkey.strip_prefix("0x").unwrap_or(payee_pubkey))
        .map_err(|_| ServiceError::InvalidRequest("Fiber payee key is invalid".to_string()))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&payee_pubkey)
        .map_err(|_| ServiceError::InvalidRequest("Fiber payee key is invalid".to_string()))?;
    if verifying_key.to_sec1_point(true).as_bytes() != payee_pubkey
        || hex32(&blake2b256(&payee_pubkey)) != requirements.payee
    {
        return Err(ServiceError::InvalidRequest(
            "Fiber invoice payee does not match the Morph payee".to_string(),
        ));
    }
    let actual_udt_script = unique_invoice_attribute(attrs, "udt_script")?.and_then(Value::as_str);
    match (&requirements.asset.kind, actual_udt_script) {
        (AssetKind::Ckb, None) => {}
        (AssetKind::Rgbpp, Some(actual)) => {
            let json_script: ckb_jsonrpc_types::Script = serde_json::from_value(
                requirements
                    .asset
                    .type_script
                    .clone()
                    .ok_or(ServiceError::UnsupportedAsset)?,
            )
            .map_err(|_| ServiceError::UnsupportedAsset)?;
            let packed_script: ckb_types::packed::Script = json_script.into();
            if format!("0x{}", hex::encode(packed_script.as_slice())) != actual {
                return Err(ServiceError::InvalidRequest(
                    "Fiber invoice UDT does not match the RGB++ Type Script".to_string(),
                ));
            }
        }
        _ => {
            return Err(ServiceError::InvalidRequest(
                "Fiber invoice asset does not match the Morph asset".to_string(),
            ));
        }
    }
    Ok(())
}

fn unique_invoice_attribute<'a>(
    attrs: &'a [Value],
    name: &str,
) -> Result<Option<&'a Value>, ServiceError> {
    let mut values = attrs.iter().filter_map(|attribute| attribute.get(name));
    let first = values.next();
    if values.next().is_some() {
        return Err(ServiceError::InvalidRequest(format!(
            "Fiber invoice contains duplicate {name} attributes"
        )));
    }
    Ok(first)
}

pub async fn serve(
    service: Arc<PaymentGatewayService>,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let listen_address = listener.local_addr()?;
    anyhow::ensure!(
        listener_auth_is_valid(
            listen_address.ip(),
            service.config.api_bearer_token.as_deref()
        ),
        "Payment Gateway API bearer token is required for a non-loopback listener"
    );
    axum::serve(listener, service.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn listener_auth_is_valid(address: std::net::IpAddr, token: Option<&str>) -> bool {
    address.is_loopback() || token.is_some_and(|token| token.len() >= 32)
}

pub async fn wait_for_payment(
    fiber: &FiberRpcClient,
    payment_hash: &str,
    timeout: Duration,
) -> Result<Value, ServiceError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ServiceError::PaymentTimeout);
        }
        let payment = tokio::time::timeout(remaining, fiber.get_payment(payment_hash))
            .await
            .map_err(|_| ServiceError::PaymentTimeout)??;
        if payment_is_terminal(&payment) {
            return Ok(payment);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ServiceError::PaymentTimeout);
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(250))).await;
    }
}

fn payment_is_terminal(payment: &Value) -> bool {
    payment_is_success(payment) || payment.get("status").and_then(Value::as_str) == Some("Failed")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::routing::post;

    use super::*;
    use crate::{EncryptedPayload, crypto::decrypt, protocol::decode_byte32};

    #[derive(Default)]
    struct MockFiberState {
        invoice: Option<Value>,
        invoice_address: Option<String>,
        payment_poll_count: usize,
        omit_send_payment_hash: bool,
    }

    fn payer_id(seed: u8) -> String {
        hex32(&blake2b256(
            SigningKey::from_slice(&[seed; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes(),
        ))
    }

    #[test]
    fn durable_creation_limiter_is_bounded_and_recovers() {
        let start = Instant::now();
        let mut limiter = CreationRateLimiter::new();
        for _ in 0..MAX_DURABLE_CREATIONS_PER_MINUTE {
            assert!(limiter.check(start));
        }
        assert!(!limiter.check(start));
        assert!(limiter.check(start + Duration::from_secs(60)));
    }

    #[test]
    fn remote_listener_requires_a_strong_api_token() {
        assert!(listener_auth_is_valid("127.0.0.1".parse().unwrap(), None));
        assert!(!listener_auth_is_valid("0.0.0.0".parse().unwrap(), None));
        assert!(!listener_auth_is_valid(
            "10.0.0.8".parse().unwrap(),
            Some("short")
        ));
        assert!(listener_auth_is_valid(
            "10.0.0.8".parse().unwrap(),
            Some(&"m".repeat(32))
        ));
    }

    #[test]
    fn bearer_comparison_covers_unequal_lengths_without_accepting_prefixes() {
        let expected = blake2b256(b"same-token");
        assert!(constant_time_equal(&expected, &blake2b256(b"same-token")));
        assert!(!constant_time_equal(&expected, &blake2b256(b"same-toke")));
        assert!(!constant_time_equal(
            &expected,
            &blake2b256(b"same-token-longer")
        ));
        assert!(!constant_time_equal(&expected, &blake2b256(b"different!")));
    }

    #[test]
    fn gateway_requires_tls_off_loopback() {
        assert!(GatewayUpstream::new("http://127.0.0.1:8080").is_ok());
        assert!(GatewayUpstream::new("https://gateway.example.com").is_ok());
        assert!(matches!(
            GatewayUpstream::new("http://10.0.0.8:8080"),
            Err(ServiceError::InvalidRequest(_))
        ));
    }

    async fn mock_fiber_rpc(
        State(state): State<Arc<Mutex<MockFiberState>>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.pointer("/params/0").cloned().unwrap_or(Value::Null);
        let result = match method {
            "new_invoice" => {
                let preimage = params
                    .get("payment_preimage")
                    .and_then(Value::as_str)
                    .and_then(|value| decode_byte32(value).ok())
                    .unwrap();
                let payment_hash = sha256_hex(&preimage);
                let invoice_address = format!("fibd1mock{}", &payment_hash[2..18]);
                let payee_pubkey = SigningKey::from_slice(&[5; 32])
                    .unwrap()
                    .verifying_key()
                    .to_sec1_point(true);
                let invoice = json!({
                    "currency": "Fibd",
                    "amount": params.get("amount").cloned().unwrap(),
                    "signature": "mock",
                    "data": {
                        "timestamp": "0x1",
                        "payment_hash": payment_hash,
                        "attrs": [
                            {"hash_algorithm": "sha256"},
                            {"payee_public_key": hex::encode(payee_pubkey.as_bytes())},
                        ],
                    }
                });
                let mut state = state.lock().unwrap();
                state.invoice = Some(invoice.clone());
                state.invoice_address = Some(invoice_address.clone());
                json!({ "invoice_address": invoice_address, "invoice": invoice })
            }
            "get_invoice" => {
                let state = state.lock().unwrap();
                json!({
                    "invoice_address": state.invoice_address.clone().unwrap(),
                    "invoice": state.invoice.clone().unwrap(),
                    "status": "Paid",
                })
            }
            "parse_invoice" => {
                let state = state.lock().unwrap();
                json!({ "invoice": state.invoice.clone().unwrap() })
            }
            "send_payment" => {
                let state = state.lock().unwrap();
                let payment_hash = state
                    .invoice
                    .as_ref()
                    .and_then(|invoice| invoice.pointer("/data/payment_hash"))
                    .cloned()
                    .unwrap();
                if state.omit_send_payment_hash {
                    json!({ "status": "Created" })
                } else {
                    json!({ "payment_hash": payment_hash, "status": "Created" })
                }
            }
            "get_payment" => {
                let mut state = state.lock().unwrap();
                state.payment_poll_count += 1;
                let payment_hash = state
                    .invoice
                    .as_ref()
                    .and_then(|invoice| invoice.pointer("/data/payment_hash"))
                    .cloned()
                    .unwrap();
                let status = if state.payment_poll_count < 2 {
                    "Inflight"
                } else {
                    "Success"
                };
                json!({ "payment_hash": payment_hash, "status": status })
            }
            _ => Value::Null,
        };
        Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    async fn test_service(
        upstream_base_url: Option<String>,
    ) -> (Arc<PaymentGatewayService>, tempfile::TempDir) {
        let (service, dir, _) = test_service_with_fiber_state(upstream_base_url).await;
        (service, dir)
    }

    async fn test_service_with_fiber_state(
        upstream_base_url: Option<String>,
    ) -> (
        Arc<PaymentGatewayService>,
        tempfile::TempDir,
        Arc<Mutex<MockFiberState>>,
    ) {
        let fiber_state = Arc::new(Mutex::new(MockFiberState::default()));
        let fiber_app = Router::new()
            .route("/", post(mock_fiber_rpc))
            .with_state(fiber_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, fiber_app).await.unwrap();
        });

        let credentials = CredentialService::generate();
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            DurableStore::open(
                dir.path().join("payment-gateway.db"),
                credentials.store_key(),
            )
            .unwrap(),
        );
        let asset = RgbppAsset {
            kind: AssetKind::Ckb,
            ckb_network_id: format!("0x{}", "01".repeat(32)),
            type_script_hash: None,
            type_script: None,
            bitcoin_network: None,
            binding_code_hash: None,
            symbol: "CKB".to_string(),
            decimals: 8,
        };
        let service = PaymentGatewayService::new(
            PaymentGatewayConfig {
                payee: hex32(&blake2b256(
                    SigningKey::from_slice(&[5; 32])
                        .unwrap()
                        .verifying_key()
                        .to_sec1_point(true)
                        .as_bytes(),
                )),
                outgoing_payer: None,
                outgoing_max_fee_amount: None,
                outgoing_payment_timeout_seconds: 60,
                currency: "Fibd".to_string(),
                supported_assets: vec![asset],
                verified_rgbpp_proof_commitments: BTreeSet::new(),
                default_credential_ttl_seconds: 600,
                upstream_base_url,
                api_bearer_token: None,
            },
            FiberRpcClient::new(&format!("http://{address}"), None).unwrap(),
            store,
            credentials,
            SigningKey::from_slice(&[3; 32]).unwrap(),
        )
        .unwrap();
        (Arc::new(service), dir, fiber_state)
    }

    #[tokio::test]
    async fn fair_exchange_releases_a_verifiable_key_only_after_paid() {
        let (service, _dir) = test_service(None).await;
        let plaintext = b"RGB++ paid computation result";
        let asset = service.config.supported_assets[0].clone();
        let envelope = create_fair_offer(
            HeaderMap::new(),
            State(service.clone()),
            Json(FairExchangeOfferRequest {
                asset,
                amount: "42".to_string(),
                payer: payer_id(4),
                resource: "/payment-gateway/result".to_string(),
                operation: "GET".to_string(),
                plaintext_base64: BASE64.encode(plaintext),
                description: None,
                expires_in_seconds: Some(300),
                rgbpp_proof_commitment: None,
            }),
        )
        .await
        .unwrap()
        .0;
        let payer_key = SigningKey::from_slice(&[4; 32]).unwrap();
        let payload = PaymentPayload::new_signed(&envelope.requirement, None, &payer_key).unwrap();
        let claim = claim_fair_offer(
            State(service.clone()),
            Json(FairExchangeClaimRequest {
                offer_id: envelope.offer_id.clone(),
                payload,
                credential_ttl_seconds: Some(300),
            }),
        )
        .await
        .unwrap()
        .0;
        verify_preimage(&envelope.requirement.payment_hash, &claim.decryption_key).unwrap();
        let key = decode_byte32(&claim.decryption_key).unwrap();
        let associated_data = format!(
            "morph-fair-exchange-v1\0{}\0{}",
            envelope.offer_id, envelope.requirement.requirement_id
        );
        let decrypted = decrypt(
            &key,
            &EncryptedPayload {
                nonce: envelope.nonce,
                ciphertext: envelope.ciphertext,
                plaintext_hash: envelope.result_hash,
            },
            associated_data.as_bytes(),
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);

        let receipt = claim.receipt;
        service
            .credentials
            .verify(
                &receipt.credential,
                &CredentialClaims {
                    credential_id: receipt.credential_id,
                    payment_hash: receipt.payment_hash,
                    asset_id: receipt.asset_id,
                    amount: receipt.amount,
                    resource: receipt.resource,
                    operation: receipt.operation,
                    expires_at: receipt.credential_expires_at,
                },
                receipt.paid_at,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn payment_index_requires_auth_and_redacts_raw_fiber_metadata() {
        let (mut service, _dir) = test_service(None).await;
        let configured = Arc::get_mut(&mut service).unwrap();
        configured.config.api_bearer_token = Some("m".repeat(32));
        configured.api_bearer_token_hash = Some(blake2b256("m".repeat(32).as_bytes()));
        service
            .store
            .record_payment(TrackedPayment {
                payment_hash: format!("0x{}", "12".repeat(32)),
                requirement_id: format!("0x{}", "13".repeat(32)),
                direction: PaymentDirection::Incoming,
                status: "Paid".to_string(),
                updated_at: 1,
                fiber_result: json!({"private_route": "raw-secret-marker"}),
            })
            .unwrap();

        assert!(matches!(
            list_payments(
                HeaderMap::new(),
                State(service.clone()),
                Query(PaymentListQuery { limit: Some(10) })
            )
            .await,
            Err(ServiceError::Unauthorized)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "m".repeat(32)).parse().unwrap(),
        );
        let Json(value) = list_payments(
            headers,
            State(service),
            Query(PaymentListQuery { limit: Some(10) }),
        )
        .await
        .unwrap();
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("raw-secret-marker"));
        assert!(encoded.contains("payment_hash"));
    }

    #[tokio::test]
    async fn outgoing_wallet_requires_payer_and_enforces_policy_caps() {
        let (mut service, _dir) = test_service(None).await;
        let requirement = service
            .make_challenge(
                &CreateChallengeRequest {
                    asset: service.config.supported_assets[0].clone(),
                    amount: "7".to_string(),
                    payer: payer_id(4),
                    resource: "/outgoing".to_string(),
                    operation: "GET".to_string(),
                    description: None,
                    expires_in_seconds: Some(300),
                    rgbpp_proof_commitment: None,
                },
                random_byte32(),
            )
            .await
            .unwrap();
        let payload = PaymentPayload::new_signed(
            &requirement,
            None,
            &SigningKey::from_slice(&[4; 32]).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            pay(
                State(service.clone()),
                Json(PayRequest {
                    requirements: requirement.clone(),
                    payload: payload.clone(),
                    timeout_seconds: None,
                    max_fee_amount: None,
                }),
            )
            .await,
            Err(ServiceError::Unauthorized)
        ));

        let configured = Arc::get_mut(&mut service).unwrap();
        configured.config.outgoing_payer = Some(payer_id(4));
        configured.config.outgoing_max_fee_amount = Some(5);
        assert!(matches!(
            pay(
                State(service),
                Json(PayRequest {
                    requirements: requirement,
                    payload,
                    timeout_seconds: Some(60),
                    max_fee_amount: Some("6".to_string()),
                }),
            )
            .await,
            Err(ServiceError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn outgoing_wallet_waits_for_fiber_terminal_success() {
        let (mut service, _dir) = test_service(None).await;
        let requirement = service
            .make_challenge(
                &CreateChallengeRequest {
                    asset: service.config.supported_assets[0].clone(),
                    amount: "7".to_string(),
                    payer: payer_id(4),
                    resource: "/outgoing-terminal".to_string(),
                    operation: "GET".to_string(),
                    description: None,
                    expires_in_seconds: Some(300),
                    rgbpp_proof_commitment: None,
                },
                random_byte32(),
            )
            .await
            .unwrap();
        let payload = PaymentPayload::new_signed(
            &requirement,
            None,
            &SigningKey::from_slice(&[4; 32]).unwrap(),
        )
        .unwrap();
        let configured = Arc::get_mut(&mut service).unwrap();
        configured.config.outgoing_payer = Some(payer_id(4));
        configured.config.outgoing_max_fee_amount = Some(5);

        let Json(response) = pay(
            State(service.clone()),
            Json(PayRequest {
                requirements: requirement.clone(),
                payload,
                timeout_seconds: Some(2),
                max_fee_amount: Some("5".to_string()),
            }),
        )
        .await
        .unwrap();

        assert!(response.completed);
        assert_eq!(response.payment_hash, requirement.payment_hash);
        assert_eq!(response.fiber_result["status"], "Success");
        let payments = service.store.payments(10).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].status, "Success");
    }

    #[tokio::test]
    async fn outgoing_wallet_persists_intent_before_fiber_submission() {
        let (mut service, _dir, fiber_state) = test_service_with_fiber_state(None).await;
        let requirement = service
            .make_challenge(
                &CreateChallengeRequest {
                    asset: service.config.supported_assets[0].clone(),
                    amount: "7".to_string(),
                    payer: payer_id(4),
                    resource: "/outgoing-pending".to_string(),
                    operation: "GET".to_string(),
                    description: None,
                    expires_in_seconds: Some(300),
                    rgbpp_proof_commitment: None,
                },
                random_byte32(),
            )
            .await
            .unwrap();
        let payload = PaymentPayload::new_signed(
            &requirement,
            None,
            &SigningKey::from_slice(&[4; 32]).unwrap(),
        )
        .unwrap();
        let configured = Arc::get_mut(&mut service).unwrap();
        configured.config.outgoing_payer = Some(payer_id(4));
        configured.config.outgoing_max_fee_amount = Some(5);
        fiber_state.lock().unwrap().omit_send_payment_hash = true;

        assert!(matches!(
            pay(
                State(service.clone()),
                Json(PayRequest {
                    requirements: requirement.clone(),
                    payload,
                    timeout_seconds: Some(2),
                    max_fee_amount: Some("5".to_string()),
                }),
            )
            .await,
            Err(ServiceError::FiberUnavailable)
        ));
        let payments = service.store.payments(10).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].payment_hash, requirement.payment_hash);
        assert_eq!(payments[0].status, "PendingSubmission");
    }

    #[tokio::test]
    async fn gateway_requires_a_resource_and_method_bound_paid_credential() {
        let upstream_app =
            Router::new().route("/protected/data", get(|| async { "paid upstream result" }));
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(upstream_listener, upstream_app).await.unwrap();
        });
        let (service, _dir) = test_service(Some(format!("http://{upstream_address}/"))).await;
        let asset = service.config.supported_assets[0].clone();
        let requirement = service
            .make_challenge(
                &CreateChallengeRequest {
                    asset,
                    amount: "7".to_string(),
                    payer: payer_id(4),
                    resource: "/protected/data".to_string(),
                    operation: "GET".to_string(),
                    description: None,
                    expires_in_seconds: Some(300),
                    rgbpp_proof_commitment: None,
                },
                random_byte32(),
            )
            .await
            .unwrap();

        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gateway_listener, service.router())
                .await
                .unwrap();
        });
        let client = reqwest::Client::new();
        let url = format!("http://{gateway_address}/gateway/protected/data");
        assert_eq!(
            client.get(&url).send().await.unwrap().status(),
            StatusCode::PAYMENT_REQUIRED
        );
        let payer_key = SigningKey::from_slice(&[4; 32]).unwrap();
        let payload = PaymentPayload::new_signed(&requirement, None, &payer_key).unwrap();
        let payer = payload.payer.clone();
        let payment_signature = encode_x402_header(&SettleRequest {
            requirements: requirement.clone(),
            payload: payload.clone(),
            credential_ttl_seconds: Some(300),
        })
        .unwrap();
        let paid_response = client
            .get(&url)
            .header(PAYMENT_SIGNATURE_HEADER, payment_signature)
            .send()
            .await
            .unwrap();
        assert_eq!(paid_response.status(), StatusCode::OK);
        let receipt: PaymentReceipt = decode_x402_header(
            paid_response
                .headers()
                .get(PAYMENT_RESPONSE_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        receipt
            .validate_for_signer(
                SigningKey::from_slice(&[3; 32])
                    .unwrap()
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes(),
            )
            .unwrap();
        let mut tampered_status = receipt.clone();
        tampered_status.fiber_status = "Failed".to_string();
        assert!(
            tampered_status
                .validate_for_signer(
                    SigningKey::from_slice(&[3; 32])
                        .unwrap()
                        .verifying_key()
                        .to_sec1_point(true)
                        .as_bytes(),
                )
                .is_err()
        );
        assert_eq!(receipt.payer, payer);
        assert_eq!(paid_response.text().await.unwrap(), "paid upstream result");

        let mut forged_retry = payload;
        forged_retry.payer_signature = format!("0x{}", "00".repeat(64));
        let forged_header = encode_x402_header(&SettleRequest {
            requirements: requirement,
            payload: forged_retry,
            credential_ttl_seconds: Some(300),
        })
        .unwrap();
        assert_eq!(
            client
                .get(&url)
                .header(PAYMENT_SIGNATURE_HEADER, forged_header)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );

        let response = client
            .get(&url)
            .bearer_auth(receipt.credential)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "paid upstream result");
    }
}
