mod health;
#[cfg(test)]
use axum::routing::get;
pub use health::FiberIdentity;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::api::*;
use crate::http_api::{ApiBytes, ApiJson, ApiPath, ApiQuery, HttpFailure};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, RawQuery, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
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
    store::{ChallengeRecord, DurableStore, StoreError, StoredOffer, TrackedPayment},
};

pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024 + 64 * 1024;
pub const MAX_CHALLENGE_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_CHALLENGE_TTL_SECONDS: u64 = 30;
pub const MAX_CREDENTIAL_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_CREDENTIAL_TTL_SECONDS: u64 = 60 * 60;
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
    #[error("payment submission outcome is unknown; retry only the exact request to reconcile")]
    PaymentOutcomeUnknown,
    #[error("request conflicts with a durable identity, provider binding or revision")]
    RequestConflict,
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
        if matches!(error, StoreError::Conflict) {
            Self::RequestConflict
        } else if matches!(error, StoreError::CapacityExceeded) {
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
            Self::PaymentOutcomeUnknown => StatusCode::SERVICE_UNAVAILABLE,
            Self::RequestConflict => StatusCode::CONFLICT,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::UnsupportedAsset => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::FiberUnavailable | Self::GatewayUnavailable => StatusCode::BAD_GATEWAY,
            Self::StoreCapacityExceeded => StatusCode::SERVICE_UNAVAILABLE,
            Self::StoreUnavailable | Self::CredentialFailure | Self::CryptoFailure => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let code = match &self {
            Self::InvalidRequest(_) => GatewayErrorCode::InvalidRequest,
            Self::UnknownChallenge => GatewayErrorCode::UnknownChallenge,
            Self::PaymentRequired => GatewayErrorCode::PaymentRequired,
            Self::PaymentTimeout => GatewayErrorCode::PaymentTimeout,
            Self::PaymentOutcomeUnknown => GatewayErrorCode::PaymentOutcomeUnknown,
            Self::RequestConflict => GatewayErrorCode::RequestConflict,
            Self::UnsupportedAsset => GatewayErrorCode::UnsupportedAsset,
            Self::Unauthorized => GatewayErrorCode::Unauthorized,
            Self::UnknownOffer => GatewayErrorCode::UnknownOffer,
            Self::FiberUnavailable => GatewayErrorCode::FiberUnavailable,
            Self::GatewayUnavailable => GatewayErrorCode::GatewayUnavailable,
            Self::StoreUnavailable => GatewayErrorCode::StoreUnavailable,
            Self::StoreCapacityExceeded => GatewayErrorCode::StoreCapacityExceeded,
            Self::RateLimited => GatewayErrorCode::RateLimited,
            Self::CredentialFailure => GatewayErrorCode::CredentialFailure,
            Self::CryptoFailure => GatewayErrorCode::CryptoFailure,
        };
        // Never reflect request-derived parser/validation text or credentials.
        let message = match self {
            Self::InvalidRequest(_) => "invalid request".to_string(),
            _ => self.to_string(),
        };
        HttpFailure::new(status, code, message).into_response()
    }
}

#[derive(Clone)]
pub struct PaymentGatewayConfig {
    /// Explicit node_info identity expectation for observations, not payment authority.
    pub fiber_identity: Option<FiberIdentity>,
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
    health_permit: Arc<tokio::sync::Semaphore>,
    metrics: Arc<morph_observability::metrics::Metrics>,
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
            health_permit: Arc::new(tokio::sync::Semaphore::new(1)),
            metrics: Arc::new(morph_observability::metrics::Metrics::new(
                morph_observability::Service::Gateway,
            )),
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
        use crate::endpoints::{Endpoint, Method as RouteMethod};
        let mut router = Router::new();
        for endpoint in Endpoint::ALL {
            let spec = endpoint.spec();
            let filter = match spec.method {
                RouteMethod::Get => axum::routing::MethodFilter::GET,
                RouteMethod::Post => axum::routing::MethodFilter::POST,
                RouteMethod::Proxy => axum::routing::MethodFilter::GET
                    .or(axum::routing::MethodFilter::HEAD)
                    .or(axum::routing::MethodFilter::POST)
                    .or(axum::routing::MethodFilter::PUT)
                    .or(axum::routing::MethodFilter::PATCH)
                    .or(axum::routing::MethodFilter::DELETE),
            };
            let handler = match endpoint {
                Endpoint::Readiness => axum::routing::on(filter, health::readiness),
                Endpoint::Metrics => axum::routing::on(filter, health::metrics),
                Endpoint::Events => axum::routing::on(filter, event_log),
                Endpoint::Health => axum::routing::on(filter, health),
                Endpoint::Supported => axum::routing::on(filter, supported),
                Endpoint::Challenge => axum::routing::on(filter, create_challenge),
                Endpoint::X402Challenge => axum::routing::on(filter, create_x402_challenge),
                Endpoint::Pay => axum::routing::on(filter, pay),
                Endpoint::Verify => axum::routing::on(filter, verify),
                Endpoint::Settle | Endpoint::Authorize => axum::routing::on(filter, settle),
                Endpoint::CredentialVerify => axum::routing::on(filter, verify_credential),
                Endpoint::FairOffer => axum::routing::on(filter, create_fair_offer),
                Endpoint::FairClaim => axum::routing::on(filter, claim_fair_offer),
                Endpoint::Payments => axum::routing::on(filter, list_payments),
                Endpoint::Proxy => axum::routing::on(filter, gateway_proxy),
            };
            router = router.route(spec.path, handler);
        }
        router
            .fallback(crate::http_api::not_found)
            .method_not_allowed_fallback(crate::http_api::method_not_allowed)
            .layer(DefaultBodyLimit::max(DEFAULT_MAX_BODY_BYTES))
            .layer(axum::middleware::from_fn(
                crate::http_api::response_contract,
            ))
            .layer(axum::middleware::from_fn_with_state(
                self.metrics.clone(),
                health::measure,
            ))
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

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
    })
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
        scheme: X402_SCHEME.into(),
        network: X402_NETWORK.into(),
        assets: service.config.supported_assets.clone(),
        payee: service.config.payee.clone(),
        capabilities: capabilities.into_iter().map(str::to_owned).collect(),
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
    ApiJson(request): ApiJson<CreateChallengeRequest>,
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
    ApiJson(request): ApiJson<CreateChallengeRequest>,
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
    ApiJson(request): ApiJson<PayRequest>,
) -> Result<Json<PayResponse>, ServiceError> {
    // Validate signatures and current payer authority even for cached delivery.
    // Expiry gates a NEW submission, not observation of an existing spend.
    request.requirements.validate(0)?;
    request.payload.validate(&request.requirements)?;
    if service.config.outgoing_payer.as_deref() != Some(request.payload.payer.as_str()) {
        return Err(ServiceError::Unauthorized);
    }
    let provider = service.fiber.endpoint();
    if let Some(attempt) = service.store.outgoing(&request, provider)? {
        return reconcile_outgoing(&service, &request, attempt)
            .await
            .map(Json);
    }
    request.requirements.validate(now_seconds())?;
    let parsed = service
        .fiber
        .parse_invoice(&request.requirements.invoice)
        .await?;
    validate_fiber_invoice(&parsed, &request.requirements, &service.config.currency)?;
    let configured_max_fee = service
        .config
        .outgoing_max_fee_amount
        .ok_or(ServiceError::Unauthorized)?;
    let max_fee = request
        .max_fee_amount
        .as_deref()
        .map(parse_amount)
        .transpose()?
        .unwrap_or(configured_max_fee);
    if max_fee > configured_max_fee {
        return Err(ServiceError::Unauthorized);
    }
    let timeout = request
        .timeout_seconds
        .unwrap_or(service.config.outgoing_payment_timeout_seconds);
    if timeout == 0 || timeout > service.config.outgoing_payment_timeout_seconds {
        return Err(ServiceError::Unauthorized);
    }
    // Recheck expiry after invoice RPC and before persisting send authority.
    let now = now_seconds();
    request.requirements.validate(now)?;
    let submission = json!({
        "invoice": request.requirements.invoice,
        "timeout": format!("0x{timeout:x}"),
        "max_fee_amount": format!("0x{max_fee:x}"),
        "custom_records": {
            format!("0x{MORPH_REQUIREMENT_RECORD_KEY:x}"): request.requirements.requirement_id,
            format!("0x{MORPH_PAYER_RECORD_KEY:x}"): request.payload.payer,
        },
    });
    match service
        .store
        .reserve_outgoing(&request, provider, submission.clone(), timeout, now)?
    {
        crate::store::OutgoingReservation::Existing(attempt) => {
            return reconcile_outgoing(&service, &request, *attempt)
                .await
                .map(Json);
        }
        crate::store::OutgoingReservation::New => {}
    }
    // Only this successfully committed NEW branch sends. A disconnect, process
    // exit or uncertain storage result never grants another send on restart.
    #[cfg(test)]
    tests::process_faults::checkpoint("reserved").await;
    request.requirements.validate(now_seconds())?;
    let initial = service
        .fiber
        .send_payment(submission)
        .await
        .map_err(|_| ServiceError::PaymentOutcomeUnknown)?;
    #[cfg(test)]
    tests::process_faults::checkpoint("provider-accepted").await;
    require_payment_identity(&initial, &request.requirements.payment_hash)?;
    let result = if payment_is_terminal(&initial) {
        initial
    } else {
        wait_for_payment(
            &service.fiber,
            &request.requirements.payment_hash,
            Duration::from_secs(timeout),
        )
        .await
        .map_err(payment_reconcile_error)?
    };
    let response = finish_outgoing(&service, &request, result)?;
    #[cfg(test)]
    tests::process_faults::checkpoint("terminal-persisted").await;
    Ok(Json(response))
}

fn payment_reconcile_error(error: ServiceError) -> ServiceError {
    if matches!(error, ServiceError::PaymentTimeout) {
        error
    } else {
        ServiceError::PaymentOutcomeUnknown
    }
}
fn require_payment_identity(result: &Value, hash: &str) -> Result<(), ServiceError> {
    if result.get("payment_hash").and_then(Value::as_str) != Some(hash) {
        return Err(ServiceError::PaymentOutcomeUnknown);
    }
    Ok(())
}
async fn reconcile_outgoing(
    service: &PaymentGatewayService,
    request: &PayRequest,
    attempt: crate::store::OutgoingAttempt,
) -> Result<PayResponse, ServiceError> {
    if let Some(response) = attempt.response {
        return Ok(response);
    }
    let timeout = attempt
        .timeout_seconds
        .min(service.config.outgoing_payment_timeout_seconds);
    let result = wait_for_payment(
        &service.fiber,
        &request.requirements.payment_hash,
        Duration::from_secs(timeout),
    )
    .await
    .map_err(payment_reconcile_error)?;
    finish_outgoing(service, request, result)
}
fn finish_outgoing(
    service: &PaymentGatewayService,
    request: &PayRequest,
    result: Value,
) -> Result<PayResponse, ServiceError> {
    require_payment_identity(&result, &request.requirements.payment_hash)?;
    service
        .store
        .finish_outgoing(
            request,
            service.fiber.endpoint(),
            PayResponse {
                completed: payment_is_success(&result),
                payment_hash: request.requirements.payment_hash.clone(),
                fiber_result: result,
            },
            now_seconds(),
        )
        .map_err(Into::into)
}

async fn verify(
    State(service): State<Arc<PaymentGatewayService>>,
    ApiJson(request): ApiJson<VerifyRequest>,
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
    ApiJson(request): ApiJson<SettleRequest>,
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
    ApiJson(request): ApiJson<CredentialVerifyRequest>,
) -> Result<Json<CredentialVerifyResponse>, ServiceError> {
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
    Ok(Json(CredentialVerifyResponse { authorized: true }))
}

async fn create_fair_offer(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    ApiJson(request): ApiJson<FairExchangeOfferRequest>,
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
    ApiJson(request): ApiJson<FairExchangeClaimRequest>,
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

async fn event_log(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    ApiJson(query): ApiJson<EventPageRequest>,
) -> Result<Json<EventPage>, ServiceError> {
    service.require_api_bearer(&headers)?;
    service
        .store
        .events(&query)
        .map(Json)
        .map_err(|error| match error {
            morph_events::Error::Invalid | morph_events::Error::Policy => {
                ServiceError::InvalidRequest("invalid event page or source cursor".into())
            }
            _ => ServiceError::StoreUnavailable,
        })
}

async fn list_payments(
    headers: HeaderMap,
    State(service): State<Arc<PaymentGatewayService>>,
    ApiQuery(query): ApiQuery<PaymentListQuery>,
) -> Result<Json<PaymentListResponse>, ServiceError> {
    service.require_api_bearer(&headers)?;
    let limit = query.limit.unwrap_or(100);
    if limit == 0 || limit > MAX_LIST_PAYMENTS {
        return Err(ServiceError::InvalidRequest(
            "page limit is outside bounds".into(),
        ));
    }
    let payments = service
        .store
        .payments(limit)?
        .into_iter()
        .map(|payment| PaymentListItem {
            payment_hash: payment.payment_hash,
            requirement_id: payment.requirement_id,
            direction: payment.direction,
            status: payment.status,
            updated_at: payment.updated_at,
        })
        .collect::<Vec<_>>();
    Ok(Json(PaymentListResponse {
        payments,
        source: "morph_payment_gateway_durable_index".into(),
    }))
}

async fn gateway_proxy(
    State(service): State<Arc<PaymentGatewayService>>,
    ApiPath(path): ApiPath<String>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
    ApiBytes(body): ApiBytes,
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

pub fn encode_x402_header(value: &impl Serialize) -> Result<String, ServiceError> {
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

pub fn decode_x402_header<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T, ServiceError> {
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
        require_payment_identity(&payment, payment_hash)?;
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
    pub(super) mod process_faults;
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
        send_count: usize,
        get_payment_error: bool,
        wrong_payment_hash: bool,
        hold_send_reply: bool,
        fail_payment: bool,
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
                let mut state = state.lock().unwrap();
                state.send_count += 1;
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
                if state.get_payment_error || state.send_count == 0 {
                    return Json(
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-1,"message":"provider-private-marker"}}),
                    );
                }
                state.payment_poll_count += 1;
                let payment_hash = state
                    .invoice
                    .as_ref()
                    .and_then(|invoice| invoice.pointer("/data/payment_hash"))
                    .cloned()
                    .unwrap();
                let payment_hash = if state.wrong_payment_hash {
                    json!(hex32(&[77; 32]))
                } else {
                    payment_hash
                };
                let status = if state.fail_payment {
                    "Failed"
                } else if state.payment_poll_count < 2 {
                    "Inflight"
                } else {
                    "Success"
                };
                json!({ "payment_hash": payment_hash, "status": status })
            }
            _ => Value::Null,
        };
        let hold_reply = method == "send_payment" && state.lock().unwrap().hold_send_reply;
        if hold_reply {
            std::future::pending::<()>().await;
        }
        Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    pub(super) async fn test_service(
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
                dir.path().join("private/payment-gateway.db"),
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
                fiber_identity: None,
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
    async fn public_http_errors_are_typed_bounded_and_do_not_reflect_input() {
        let (mut service, dir) = test_service(None).await;
        Arc::get_mut(&mut service).unwrap().api_bearer_token_hash =
            Some(blake2b256("a".repeat(32).as_bytes()));
        let asset = service.config.supported_assets[0].clone();
        let request = CreateChallengeRequest {
            asset,
            amount: "1".into(),
            payer: payer_id(4),
            resource: "/test".into(),
            operation: "GET".into(),
            description: None,
            expires_in_seconds: Some(60),
            rgbpp_proof_commitment: None,
        };
        let path = dir.path().join("private/payment-gateway.db");
        let before = std::fs::read(&path).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, service.router()).await.unwrap();
        });
        let client = reqwest::Client::new();
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["raw-secret-marker"] = json!(true);
        let mut nested = serde_json::to_value(&request).unwrap();
        nested["asset"]["raw-secret-marker"] = json!(true);
        let cases = [
            (
                "POST",
                "/health",
                "application/json",
                "{}".into(),
                405,
                GatewayErrorCode::MethodNotAllowed,
            ),
            (
                "GET",
                "/v1/missing",
                "application/json",
                String::new(),
                404,
                GatewayErrorCode::RouteNotFound,
            ),
            (
                "POST",
                "/v1/challenges",
                "text/plain",
                "raw-secret-marker".into(),
                415,
                GatewayErrorCode::UnsupportedContentType,
            ),
            (
                "POST",
                "/v1/challenges",
                "application/json",
                "raw-secret-marker".into(),
                400,
                GatewayErrorCode::InvalidJson,
            ),
            (
                "POST",
                "/v1/challenges",
                "application/json",
                unknown.to_string(),
                422,
                GatewayErrorCode::InvalidJson,
            ),
            (
                "POST",
                "/v1/challenges",
                "application/json",
                nested.to_string(),
                422,
                GatewayErrorCode::InvalidJson,
            ),
            (
                "POST",
                "/v1/challenges",
                "application/json",
                "x".repeat(DEFAULT_MAX_BODY_BYTES + 1),
                413,
                GatewayErrorCode::BodyTooLarge,
            ),
            (
                "POST",
                "/v1/challenges",
                "application/json",
                serde_json::to_string(&request).unwrap(),
                401,
                GatewayErrorCode::Unauthorized,
            ),
            (
                "GET",
                "/v1/payments?limit=0",
                "application/json",
                String::new(),
                400,
                GatewayErrorCode::InvalidQuery,
            ),
            (
                "GET",
                "/v1/payments?limit=1001",
                "application/json",
                String::new(),
                400,
                GatewayErrorCode::InvalidQuery,
            ),
            (
                "GET",
                "/v1/payments?limit=01",
                "application/json",
                String::new(),
                400,
                GatewayErrorCode::InvalidQuery,
            ),
            (
                "GET",
                "/v1/payments?limit=1&limit=2",
                "application/json",
                String::new(),
                400,
                GatewayErrorCode::InvalidQuery,
            ),
            (
                "GET",
                "/v1/payments?unknown=raw-secret-marker",
                "application/json",
                String::new(),
                400,
                GatewayErrorCode::InvalidQuery,
            ),
        ];
        let malformed_numbers = [
            json!(60),
            json!("01"),
            json!("18446744073709551616"),
            json!(" 60"),
        ]
        .into_iter()
        .map(|value| {
            let mut bad = serde_json::to_value(&request).unwrap();
            bad["expires_in_seconds"] = value;
            (
                "POST",
                "/v1/challenges",
                "application/json",
                bad.to_string(),
                422,
                GatewayErrorCode::InvalidJson,
            )
        });
        let cases = cases.into_iter().chain(malformed_numbers).chain([
            (
                "POST",
                "/gateway/test",
                "application/octet-stream",
                "x".repeat(DEFAULT_MAX_BODY_BYTES + 1),
                413,
                GatewayErrorCode::BodyTooLarge,
            ),
            (
                "GET",
                "/gateway/%FF",
                "application/json",
                String::new(),
                400,
                GatewayErrorCode::InvalidRequest,
            ),
        ]);
        let mut ids = BTreeSet::new();
        for (method, path, content, body, status, code) in cases {
            let response = client
                .request(method.parse().unwrap(), format!("{base}{path}"))
                .header("content-type", content)
                .header("x-morph-request-id", "raw-secret-marker")
                .header("authorization", "Bearer raw-secret-marker")
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status, "{path}");
            assert_eq!(response.headers()["x-morph-api-version"], "1");
            let id = response.headers()["x-morph-request-id"]
                .to_str()
                .unwrap()
                .to_owned();
            assert!(ids.insert(id.clone()));
            let text = response.text().await.unwrap();
            assert!(!text.contains("raw-secret-marker"));
            let error: GatewayErrorBody = serde_json::from_str(&text).unwrap();
            assert_eq!(error.code, code);
            assert_eq!(error.request_id, id);
            assert_eq!(error.api_version, "1");
        }
        let unauthorized = crate::PaymentGatewayClient::new(&base).unwrap();
        assert!(matches!(
            unauthorized.create_x402_challenge(&request).await,
            Err(crate::PaymentGatewayClientError::Http {
                code: Some(GatewayErrorCode::Unauthorized),
                status: 401,
                request_id: Some(_),
                ..
            })
        ));
        let sdk = crate::PaymentGatewayClient::new(&base)
            .unwrap()
            .with_bearer_token("a".repeat(32))
            .unwrap();
        assert!(matches!(
            sdk.payments(0).await,
            Err(crate::PaymentGatewayClientError::Http {
                code: Some(GatewayErrorCode::InvalidQuery),
                request_id: Some(_),
                status: 400,
                ..
            })
        ));
        assert!(sdk.payments(1000).await.unwrap().payments.is_empty());
        assert!(
            sdk.supported()
                .await
                .unwrap()
                .capabilities
                .iter()
                .any(|v| v == "x402_exact")
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
        server.abort();
    }

    #[tokio::test]
    async fn fair_exchange_releases_a_verifiable_key_only_after_paid() {
        let (service, _dir) = test_service(None).await;
        let plaintext = b"RGB++ paid computation result";
        let asset = service.config.supported_assets[0].clone();
        let envelope = create_fair_offer(
            HeaderMap::new(),
            State(service.clone()),
            ApiJson(FairExchangeOfferRequest {
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
            ApiJson(FairExchangeClaimRequest {
                offer_id: envelope.offer_id.clone(),
                payload,
                credential_ttl_seconds: Some(300),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            crate::decrypt_fair_exchange(&envelope, &claim).unwrap(),
            plaintext
        );
        let mut wrong_claim = claim.clone();
        wrong_claim.offer_id.push('x');
        assert!(crate::decrypt_fair_exchange(&envelope, &wrong_claim).is_err());
        wrong_claim = claim.clone();
        wrong_claim.decryption_key = hex32(&[0; 32]);
        assert!(crate::decrypt_fair_exchange(&envelope, &wrong_claim).is_err());
        let mut wrong_envelope = envelope.clone();
        wrong_envelope.requirement.requirement_id = hex32(&[0; 32]);
        assert!(crate::decrypt_fair_exchange(&wrong_envelope, &claim).is_err());
        wrong_envelope = envelope.clone();
        wrong_envelope.result_hash = hex32(&[0; 32]);
        assert!(crate::decrypt_fair_exchange(&wrong_envelope, &claim).is_err());
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
                ApiQuery(PaymentListQuery { limit: Some(10) })
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
            ApiQuery(PaymentListQuery { limit: Some(10) }),
        )
        .await
        .unwrap();
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("raw-secret-marker"));
        assert!(encoded.contains("payment_hash"));
    }

    #[tokio::test]
    async fn durable_event_http_pages_require_operator_and_redact_private_state() {
        let (mut service, _dir) = test_service(None).await;
        Arc::get_mut(&mut service).unwrap().api_bearer_token_hash =
            Some(blake2b256("e".repeat(32).as_bytes()));
        service.store.record_payment(TrackedPayment {
            payment_hash: format!("0x{}", "12".repeat(32)), requirement_id: format!("0x{}", "13".repeat(32)),
            direction: PaymentDirection::Incoming, status: "Paid".into(), updated_at: 1,
            fiber_result: json!({"private_proof":"must-not-leave-store","url":"https://provider.invalid/?token=private"}),
        }).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, service.router()).await.unwrap();
        });
        let client = reqwest::Client::new();
        let query = EventPageRequest {
            after: None,
            limit: 1,
        };
        let denied = client
            .post(format!("{base}/v1/events"))
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let sdk = crate::client::PaymentGatewayClient::new(&base)
            .unwrap()
            .with_bearer_token("e".repeat(32))
            .unwrap();
        let first = sdk.events(&query).await.unwrap();
        assert!(first.has_more);
        let second = sdk
            .events(&EventPageRequest {
                after: Some(first.next),
                limit: 1,
            })
            .await
            .unwrap();
        assert!(!second.has_more);
        assert_eq!(
            second.events[0].kind,
            morph_packages::events::Kind::GatewayPaymentRecorded
        );
        let text = serde_json::to_string(&second).unwrap();
        assert!(!text.contains("must-not-leave-store"));
        assert!(!text.contains("provider.invalid"));
        let end = sdk
            .events(&EventPageRequest {
                after: Some(second.next.clone()),
                limit: 1,
            })
            .await
            .unwrap();
        assert!(end.events.is_empty());
        let mut wrong = second.next;
        wrong.source_id = "ab".repeat(32);
        let bad = client
            .post(format!("{base}/v1/events"))
            .bearer_auth("e".repeat(32))
            .json(&EventPageRequest {
                after: Some(wrong),
                limit: 1,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        task.abort();
    }

    async fn outgoing_retry_fixture() -> (
        Arc<PaymentGatewayService>,
        tempfile::TempDir,
        Arc<Mutex<MockFiberState>>,
        PayRequest,
    ) {
        let (mut service, dir, state) = test_service_with_fiber_state(None).await;
        let requirements = service
            .make_challenge(
                &CreateChallengeRequest {
                    asset: service.config.supported_assets[0].clone(),
                    amount: "7".into(),
                    payer: payer_id(4),
                    resource: "/retry".into(),
                    operation: "GET".into(),
                    description: None,
                    expires_in_seconds: Some(300),
                    rgbpp_proof_commitment: None,
                },
                random_byte32(),
            )
            .await
            .unwrap();
        let payload = PaymentPayload::new_signed(
            &requirements,
            None,
            &SigningKey::from_slice(&[4; 32]).unwrap(),
        )
        .unwrap();
        let config = &mut Arc::get_mut(&mut service).unwrap().config;
        config.outgoing_payer = Some(payer_id(4));
        config.outgoing_max_fee_amount = Some(5);
        (
            service,
            dir,
            state,
            PayRequest {
                requirements,
                payload,
                timeout_seconds: Some(2),
                max_fee_amount: Some("5".into()),
            },
        )
    }

    #[tokio::test]
    async fn outgoing_http_concurrent_retries_send_once_and_conflicts_have_stable_code() {
        let (service, dir, state, request) = outgoing_retry_fixture().await;
        let peer = Arc::new(
            PaymentGatewayService::new(
                service.config.clone(),
                service.fiber.clone(),
                Arc::new(
                    DurableStore::open(
                        dir.path().join("private/payment-gateway.db"),
                        service.credentials.store_key(),
                    )
                    .unwrap(),
                ),
                service.credentials.clone(),
                service.receipt_signing_key.clone(),
            )
            .unwrap(),
        );
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_url = format!("http://{}/v1/pay", second.local_addr().unwrap());
        let peer_server = tokio::spawn(async move {
            axum::serve(second, peer.router()).await.unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/pay", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, service.router()).await.unwrap();
        });
        let client = reqwest::Client::new();
        let (a, b) = tokio::join!(
            client.post(&url).json(&request).send(),
            client.post(&peer_url).json(&request).send()
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let mut terminal = None;
        for response in [a, b] {
            if response.status() == StatusCode::OK {
                let value = response.json::<Value>().await.unwrap();
                if let Some(saved) = &terminal {
                    assert_eq!(saved, &value);
                }
                terminal = Some(value);
            } else {
                // The winner may not yet have reached Fiber when a racing
                // observer queries. Missing evidence must not grant a send.
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response.json::<GatewayErrorBody>().await.unwrap().code,
                    GatewayErrorCode::PaymentOutcomeUnknown
                );
            }
        }
        let original = terminal.expect("the winning submitter must complete");
        assert_eq!(state.lock().unwrap().send_count, 1);
        let mut changed = request.clone();
        changed.timeout_seconds = Some(1);
        let response = client.post(&url).json(&changed).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.json::<GatewayErrorBody>().await.unwrap().code,
            GatewayErrorCode::RequestConflict
        );
        assert_eq!(state.lock().unwrap().send_count, 1);
        let cached = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(cached, original);
        for payment_url in [&url, &peer_url] {
            let metrics_url = payment_url.replace("/v1/pay", "/metrics");
            let metrics = client.get(metrics_url).send().await.unwrap();
            assert_eq!(metrics.status(), StatusCode::OK);
            let metrics = metrics.text().await.unwrap();
            assert!(metrics.contains("morph_gateway_outgoing_reserved_total 1\n"));
            assert!(metrics.contains("morph_gateway_outgoing_succeeded_total 1\n"));
            assert!(metrics.contains("morph_gateway_outgoing_failed_total 0\n"));
            assert!(!metrics.contains(&request.requirements.payment_hash));
            assert!(!metrics.contains(&request.payload.payer_signature));
        }
        server.abort();
        peer_server.abort();
    }

    #[tokio::test]
    async fn outgoing_unknown_submission_reopens_and_reconciles_without_resubmitting() {
        let (service, dir, state, request) = outgoing_retry_fixture().await;
        state.lock().unwrap().omit_send_payment_hash = true;
        assert!(matches!(
            pay(State(service.clone()), ApiJson(request.clone())).await,
            Err(ServiceError::PaymentOutcomeUnknown)
        ));
        assert_eq!(state.lock().unwrap().send_count, 1);
        let config = service.config.clone();
        let fiber = service.fiber.clone();
        let credentials = service.credentials.clone();
        let key = service.receipt_signing_key.clone();
        drop(service);
        let store = Arc::new(
            DurableStore::open(
                dir.path().join("private/payment-gateway.db"),
                credentials.store_key(),
            )
            .unwrap(),
        );
        let reopened =
            Arc::new(PaymentGatewayService::new(config, fiber, store, credentials, key).unwrap());
        state.lock().unwrap().get_payment_error = true;
        assert!(matches!(
            pay(State(reopened.clone()), ApiJson(request.clone())).await,
            Err(ServiceError::PaymentOutcomeUnknown)
        ));
        assert_eq!(state.lock().unwrap().send_count, 1);
        state.lock().unwrap().get_payment_error = false;
        let Json(result) = pay(State(reopened.clone()), ApiJson(request.clone()))
            .await
            .unwrap();
        assert!(result.completed);
        assert_eq!(state.lock().unwrap().send_count, 1);
        let polls = state.lock().unwrap().payment_poll_count;
        state.lock().unwrap().get_payment_error = true;
        assert!(
            pay(State(reopened), ApiJson(request))
                .await
                .unwrap()
                .0
                .completed
        );
        assert_eq!(state.lock().unwrap().payment_poll_count, polls);
    }

    #[tokio::test]
    async fn outgoing_pre_send_reservation_never_guesses_non_submission_from_missing_provider_record()
     {
        let (service, _dir, state, request) = outgoing_retry_fixture().await;
        service
            .store
            .reserve_outgoing(
                &request,
                service.fiber.endpoint(),
                json!({"invoice":request.requirements.invoice}),
                2,
                now_seconds(),
            )
            .unwrap();
        assert!(matches!(
            pay(State(service.clone()), ApiJson(request.clone())).await,
            Err(ServiceError::PaymentOutcomeUnknown)
        ));
        assert_eq!(state.lock().unwrap().send_count, 0);
        assert!(
            service
                .store
                .outgoing(&request, service.fiber.endpoint())
                .unwrap()
                .unwrap()
                .response
                .is_none()
        );
    }

    #[tokio::test]
    async fn outgoing_wrong_poll_identity_cannot_finish_original_attempt() {
        let (service, _dir, state, request) = outgoing_retry_fixture().await;
        state.lock().unwrap().wrong_payment_hash = true;
        assert!(matches!(
            pay(State(service.clone()), ApiJson(request.clone())).await,
            Err(ServiceError::PaymentOutcomeUnknown)
        ));
        assert!(
            service
                .store
                .outgoing(&request, service.fiber.endpoint())
                .unwrap()
                .unwrap()
                .response
                .is_none()
        );
        state.lock().unwrap().wrong_payment_hash = false;
        assert!(
            pay(State(service), ApiJson(request))
                .await
                .unwrap()
                .0
                .completed
        );
        assert_eq!(state.lock().unwrap().send_count, 1);
    }

    #[tokio::test]
    async fn outgoing_expired_cached_result_is_delivered_but_new_expired_spend_is_rejected() {
        let (service, _dir, state, mut request) = outgoing_retry_fixture().await;
        request.requirements.expires_at = now_seconds() - 1;
        request.requirements.requirement_id = request.requirements.expected_id().unwrap();
        request.payload = PaymentPayload::new_signed(
            &request.requirements,
            None,
            &SigningKey::from_slice(&[4; 32]).unwrap(),
        )
        .unwrap();
        assert!(
            pay(State(service.clone()), ApiJson(request.clone()))
                .await
                .is_err()
        );
        service
            .store
            .reserve_outgoing(
                &request,
                service.fiber.endpoint(),
                json!({}),
                2,
                now_seconds() - 10,
            )
            .unwrap();
        service.store.finish_outgoing(&request,service.fiber.endpoint(),PayResponse { completed:true,payment_hash:request.requirements.payment_hash.clone(),fiber_result:json!({"payment_hash":request.requirements.payment_hash,"status":"Success"})},now_seconds()).unwrap();
        assert!(
            pay(State(service), ApiJson(request))
                .await
                .unwrap()
                .0
                .completed
        );
        assert_eq!(state.lock().unwrap().send_count, 0);
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
                ApiJson(PayRequest {
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
                ApiJson(PayRequest {
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
            ApiJson(PayRequest {
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
                ApiJson(PayRequest {
                    requirements: requirement.clone(),
                    payload,
                    timeout_seconds: Some(2),
                    max_fee_amount: Some("5".to_string()),
                }),
            )
            .await,
            Err(ServiceError::PaymentOutcomeUnknown)
        ));
        let payments = service.store.payments(10).unwrap();
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].payment_hash, requirement.payment_hash);
        assert_eq!(payments[0].status, "PendingSubmission");
    }

    #[tokio::test]
    async fn native_client_challenge_paid_get_and_post_preserve_auth_and_receipt_boundaries() {
        let upstream = Router::new().route(
            "/paid",
            get(|| async { "native GET" }).post(|body: String| async move { body }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, upstream).await.unwrap();
        });
        let (service, _dir) = test_service(Some(upstream_url)).await;
        let asset = service.config.supported_assets[0].clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, service.router()).await.unwrap();
        });
        // A configured gateway token must never appear on its separate paid resource request:
        // that endpoint rejects combined Authorization and PAYMENT-SIGNATURE.
        let client = crate::PaymentGatewayClient::new(&url)
            .unwrap()
            .with_bearer_token("test-only-gateway-token".repeat(3))
            .unwrap();
        let signer = SigningKey::from_slice(&[3; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(true);
        let key = SigningKey::from_slice(&[4; 32]).unwrap();
        for method in [reqwest::Method::GET, reqwest::Method::POST] {
            let requirement = client
                .create_x402_challenge(&CreateChallengeRequest {
                    asset: asset.clone(),
                    amount: "17".into(),
                    payer: payer_id(4),
                    resource: "/paid".into(),
                    operation: method.as_str().into(),
                    description: None,
                    expires_in_seconds: Some(300),
                    rgbpp_proof_commitment: None,
                })
                .await
                .unwrap();
            let settlement = SettleRequest {
                payload: PaymentPayload::new_signed(&requirement, None, &key).unwrap(),
                requirements: requirement,
                credential_ttl_seconds: Some(300),
            };
            let resource = format!("{url}/gateway/paid");
            let (body, receipt) = if method == reqwest::Method::GET {
                client
                    .x402_get(&resource, &settlement, signer.as_bytes())
                    .await
                    .unwrap()
            } else {
                client
                    .x402_request(
                        method.clone(),
                        &resource,
                        HeaderMap::new(),
                        b"native POST".to_vec(),
                        &settlement,
                        signer.as_bytes(),
                    )
                    .await
                    .unwrap()
            };
            assert_eq!(
                body,
                if method == reqwest::Method::GET {
                    b"native GET".to_vec()
                } else {
                    b"native POST".to_vec()
                }
            );
            assert_eq!(
                receipt.requirement_id,
                settlement.requirements.requirement_id
            );
            let wrong_signer = key.verifying_key().to_sec1_point(true);
            assert!(matches!(
                client
                    .x402_request(
                        method.clone(),
                        &resource,
                        HeaderMap::new(),
                        Vec::new(),
                        &settlement,
                        wrong_signer.as_bytes()
                    )
                    .await,
                Err(crate::PaymentGatewayClientError::InvalidResponse)
            ));
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                "Bearer must-not-leak".parse().unwrap(),
            );
            assert!(matches!(
                client
                    .x402_request(
                        method.clone(),
                        &resource,
                        headers,
                        Vec::new(),
                        &settlement,
                        signer.as_bytes()
                    )
                    .await,
                Err(crate::PaymentGatewayClientError::InvalidResponse)
            ));
            let wrong_method = if method == reqwest::Method::GET {
                reqwest::Method::POST
            } else {
                reqwest::Method::GET
            };
            assert!(matches!(
                client
                    .x402_request(
                        wrong_method,
                        &resource,
                        HeaderMap::new(),
                        Vec::new(),
                        &settlement,
                        signer.as_bytes()
                    )
                    .await,
                Err(crate::PaymentGatewayClientError::InvalidResponse)
            ));
        }
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
