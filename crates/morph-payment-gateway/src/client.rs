use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

use crate::http_safety::{is_secure_service_url, read_response_limited};
use crate::{
    CredentialVerifyRequest, CredentialVerifyResponse, FairExchangeClaim, FairExchangeClaimRequest,
    FairExchangeEnvelope, FairExchangeOfferRequest, PayRequest, PayResponse, PaymentRequirements,
    SettleRequest, SettleResponse, VerifyRequest, VerifyResponse,
};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum PaymentGatewayClientError {
    #[error("invalid Morph Payment Gateway URL")]
    InvalidUrl,
    #[error("invalid Morph Payment Gateway API bearer token")]
    InvalidBearerToken,
    #[error("Morph Payment Gateway transport failed: {0}")]
    Transport(String),
    #[error("Morph Payment Gateway returned HTTP {status}: {message}")]
    Http {
        status: u16,
        message: String,
        code: Option<crate::api::GatewayErrorCode>,
        request_id: Option<String>,
    },
    #[error("Morph Payment Gateway returned an invalid or oversized response")]
    InvalidResponse,
}

/// Native Rust SDK for an independent Morph Payment Gateway sidecar. It contains no
/// Fiber internals and therefore works with an unmodified Fiber RPC server.
#[derive(Clone)]
pub struct PaymentGatewayClient {
    base_url: Url,
    client: Client,
    bearer_token: Option<String>,
}

impl PaymentGatewayClient {
    pub fn new(base_url: &str) -> Result<Self, PaymentGatewayClientError> {
        let mut base_url =
            Url::parse(base_url).map_err(|_| PaymentGatewayClientError::InvalidUrl)?;
        if !is_secure_service_url(&base_url)
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(PaymentGatewayClientError::InvalidUrl);
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| PaymentGatewayClientError::Transport(error.to_string()))?;
        Ok(Self {
            base_url,
            client,
            bearer_token: None,
        })
    }

    pub fn with_bearer_token(
        mut self,
        token: impl Into<String>,
    ) -> Result<Self, PaymentGatewayClientError> {
        let token = token.into();
        if token.len() < 32 {
            return Err(PaymentGatewayClientError::InvalidBearerToken);
        }
        self.bearer_token = Some(token);
        Ok(self)
    }

    /// HTTP 503 is a valid negative observation, not an opaque transport error.
    pub async fn readiness(&self) -> Result<crate::Readiness, PaymentGatewayClientError> {
        let response = self.observation_request("ready").await?;
        let status = response.status();
        if status != reqwest::StatusCode::OK && status != reqwest::StatusCode::SERVICE_UNAVAILABLE {
            let _: Value = decode_response(response).await?;
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        let bytes = read_response_limited(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?
            .ok_or(PaymentGatewayClientError::InvalidResponse)?;
        let report: crate::Readiness = serde_json::from_slice(&bytes)
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        if !report.consistent()
            || report.service != morph_observability::Service::Gateway
            || report.ready != (status == reqwest::StatusCode::OK)
        {
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        Ok(report)
    }

    pub async fn metrics(&self) -> Result<String, PaymentGatewayClientError> {
        let response = self.observation_request("metrics").await?;
        if response.status() != reqwest::StatusCode::OK {
            let _: Value = decode_response(response).await?;
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        if !response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.starts_with("text/plain"))
        {
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        let bytes = read_response_limited(response, morph_observability::metrics::MAX_EXPORT_BYTES)
            .await
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?
            .ok_or(PaymentGatewayClientError::InvalidResponse)?;
        String::from_utf8(bytes).map_err(|_| PaymentGatewayClientError::InvalidResponse)
    }

    async fn observation_request(
        &self,
        path: &str,
    ) -> Result<reqwest::Response, PaymentGatewayClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| PaymentGatewayClientError::InvalidUrl)?;
        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .map_err(|_| PaymentGatewayClientError::Transport("observation request failed".into()))
    }

    pub async fn supported(
        &self,
    ) -> Result<crate::api::SupportedResponse, PaymentGatewayClientError> {
        self.get("v1/supported").await
    }

    pub async fn create_challenge(
        &self,
        request: &crate::api::CreateChallengeRequest,
    ) -> Result<PaymentRequirements, PaymentGatewayClientError> {
        self.post("v1/challenges", request).await
    }

    pub async fn pay(
        &self,
        request: &PayRequest,
    ) -> Result<PayResponse, PaymentGatewayClientError> {
        self.post("v1/pay", request).await
    }

    pub async fn verify(
        &self,
        request: &VerifyRequest,
    ) -> Result<VerifyResponse, PaymentGatewayClientError> {
        self.post("v1/x402/verify", request).await
    }

    pub async fn settle(
        &self,
        request: &SettleRequest,
    ) -> Result<SettleResponse, PaymentGatewayClientError> {
        self.post("v1/x402/settle", request).await
    }

    pub async fn verify_credential(
        &self,
        request: &CredentialVerifyRequest,
    ) -> Result<CredentialVerifyResponse, PaymentGatewayClientError> {
        self.post("v1/credentials/verify", request).await
    }

    pub async fn create_fair_offer(
        &self,
        request: &FairExchangeOfferRequest,
    ) -> Result<FairExchangeEnvelope, PaymentGatewayClientError> {
        self.post("v1/fair-exchange/offers", request).await
    }

    pub async fn claim_fair_offer(
        &self,
        request: &FairExchangeClaimRequest,
    ) -> Result<FairExchangeClaim, PaymentGatewayClientError> {
        self.post("v1/fair-exchange/claims", request).await
    }

    pub async fn events(
        &self,
        query: &crate::api::EventPageRequest,
    ) -> Result<crate::api::EventPage, PaymentGatewayClientError> {
        let page: crate::api::EventPage = self.post("v1/events", query).await?;
        if !page.valid_for(query) {
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        Ok(page)
    }

    pub async fn payments(
        &self,
        limit: usize,
    ) -> Result<crate::api::PaymentListResponse, PaymentGatewayClientError> {
        self.get(&format!("v1/payments?limit={limit}")).await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, PaymentGatewayClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| PaymentGatewayClientError::InvalidUrl)?;
        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| PaymentGatewayClientError::Transport(error.to_string()))?;
        decode_response(response).await
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, PaymentGatewayClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| PaymentGatewayClientError::InvalidUrl)?;
        let mut request = self.client.post(url).json(body);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| PaymentGatewayClientError::Transport(error.to_string()))?;
        decode_response(response).await
    }
}

async fn decode_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, PaymentGatewayClientError> {
    let status = response.status();
    let bytes = read_response_limited(response, MAX_RESPONSE_BYTES)
        .await
        .map_err(|error| PaymentGatewayClientError::Transport(error.to_string()))?
        .ok_or(PaymentGatewayClientError::InvalidResponse)?;
    if !status.is_success() {
        let error = serde_json::from_slice::<crate::api::GatewayErrorBody>(&bytes)
            .ok()
            .filter(|e| e.api_version == crate::api::API_VERSION);
        return Err(PaymentGatewayClientError::Http {
            status: status.as_u16(),
            message: error
                .as_ref()
                .map(|e| e.error.clone())
                .unwrap_or_else(|| "request failed".into()),
            code: error.as_ref().map(|e| e.code),
            request_id: error.map(|e| e.request_id),
        });
    }
    serde_json::from_slice(&bytes).map_err(|_| PaymentGatewayClientError::InvalidResponse)
}

impl PaymentGatewayClient {
    /// Read the HTTP 402 challenge without treating its intentional status as a
    /// generic transport failure. The bounded body and header must agree.
    pub async fn create_x402_challenge(
        &self,
        request: &crate::CreateChallengeRequest,
    ) -> Result<PaymentRequirements, PaymentGatewayClientError> {
        let url = self
            .base_url
            .join("v1/x402/challenge")
            .map_err(|_| PaymentGatewayClientError::InvalidUrl)?;
        let mut request = self.client.post(url).json(request);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|_| PaymentGatewayClientError::Transport("challenge request failed".into()))?;
        if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            let status = response.status().as_u16();
            // Preserve the same typed service error as the normal JSON API.
            // A successful response is still invalid for the x402 challenge flow.
            let _: Value = decode_response(response).await?;
            return Err(PaymentGatewayClientError::Http {
                status,
                message: "expected x402 challenge".into(),
                code: None,
                request_id: None,
            });
        }
        let header = response
            .headers()
            .get("payment-required")
            .and_then(|h| h.to_str().ok())
            .ok_or(PaymentGatewayClientError::InvalidResponse)?
            .to_owned();
        let requirement: PaymentRequirements = crate::decode_x402_header(&header)
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        let body = read_response_limited(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?
            .ok_or(PaymentGatewayClientError::InvalidResponse)?;
        let echoed: PaymentRequirements = serde_json::from_slice(&body)
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        if echoed != requirement {
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        requirement
            .validate(crate::now_seconds())
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        Ok(requirement)
    }
    /// A paid GET carries no gateway bearer token to the resource. Redirections
    /// remain disabled, and the caller pins the receipt signer independently.
    pub async fn x402_get(
        &self,
        resource_url: &str,
        settlement: &SettleRequest,
        receipt_signer: &[u8],
    ) -> Result<(Vec<u8>, crate::PaymentReceipt), PaymentGatewayClientError> {
        self.x402_request(
            reqwest::Method::GET,
            resource_url,
            reqwest::header::HeaderMap::new(),
            Vec::new(),
            settlement,
            receipt_signer,
        )
        .await
    }

    /// Native replacement for a paid fetch, including POST/PUT payloads. The
    /// signed operation must match. API credentials are never inherited by the
    /// separate resource request, and caller Authorization is rejected.
    pub async fn x402_request(
        &self,
        method: reqwest::Method,
        resource_url: &str,
        mut headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
        settlement: &SettleRequest,
        receipt_signer: &[u8],
    ) -> Result<(Vec<u8>, crate::PaymentReceipt), PaymentGatewayClientError> {
        let url = Url::parse(resource_url).map_err(|_| PaymentGatewayClientError::InvalidUrl)?;
        if !is_secure_service_url(&url)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(PaymentGatewayClientError::InvalidUrl);
        }
        if body.len() > MAX_RESPONSE_BYTES
            || headers.contains_key(reqwest::header::AUTHORIZATION)
            || method.as_str() != settlement.requirements.operation
        {
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        settlement
            .payload
            .validate(&settlement.requirements)
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        let signature = crate::encode_x402_header(settlement)
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        headers.insert(
            "payment-signature",
            reqwest::header::HeaderValue::from_str(&signature)
                .map_err(|_| PaymentGatewayClientError::InvalidResponse)?,
        );
        let response = self
            .client
            .request(method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|_| {
                PaymentGatewayClientError::Transport("paid resource request failed".into())
            })?;
        if !response.status().is_success() {
            return Err(PaymentGatewayClientError::Http {
                status: response.status().as_u16(),
                message: "paid resource rejected request".into(),
                code: None,
                request_id: None,
            });
        }
        let receipt: crate::PaymentReceipt = crate::decode_x402_header(
            response
                .headers()
                .get("payment-response")
                .and_then(|v| v.to_str().ok())
                .ok_or(PaymentGatewayClientError::InvalidResponse)?,
        )
        .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        receipt
            .validate_for_signer(receipt_signer)
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?;
        if receipt.requirement_id != settlement.requirements.requirement_id
            || receipt.payment_hash != settlement.requirements.payment_hash
            || receipt.payer != settlement.requirements.payer
        {
            return Err(PaymentGatewayClientError::InvalidResponse);
        }
        let body = read_response_limited(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| PaymentGatewayClientError::InvalidResponse)?
            .ok_or(PaymentGatewayClientError::InvalidResponse)?;
        Ok((body, receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_requires_tls_for_non_loopback_gateways() {
        for accepted in [
            "http://localhost:4617",
            "http://127.0.0.1:4617",
            "http://[::1]:4617",
            "https://gateway.example.com",
        ] {
            assert!(PaymentGatewayClient::new(accepted).is_ok(), "{accepted}");
        }
        for rejected in ["http://example.com", "http://10.0.0.8:4617"] {
            assert!(
                matches!(
                    PaymentGatewayClient::new(rejected),
                    Err(PaymentGatewayClientError::InvalidUrl)
                ),
                "{rejected}"
            );
        }
    }

    #[test]
    fn client_rejects_short_api_tokens() {
        assert!(matches!(
            PaymentGatewayClient::new("http://127.0.0.1:4617")
                .unwrap()
                .with_bearer_token("short"),
            Err(PaymentGatewayClientError::InvalidBearerToken)
        ));
    }
}
