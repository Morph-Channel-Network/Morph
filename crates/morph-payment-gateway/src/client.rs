use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

use crate::http_safety::{is_secure_service_url, read_response_limited};
use crate::{
    CredentialVerifyRequest, FairExchangeClaim, FairExchangeClaimRequest, FairExchangeEnvelope,
    FairExchangeOfferRequest, PayRequest, PayResponse, PaymentRequirements, SettleRequest,
    SettleResponse, VerifyRequest, VerifyResponse,
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
    Http { status: u16, message: String },
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
        if !is_secure_service_url(&base_url) {
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

    pub async fn supported(&self) -> Result<Value, PaymentGatewayClientError> {
        self.get("v1/supported").await
    }

    pub async fn create_challenge<T: Serialize + ?Sized>(
        &self,
        request: &T,
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
    ) -> Result<Value, PaymentGatewayClientError> {
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

    pub async fn payments(&self, limit: usize) -> Result<Value, PaymentGatewayClientError> {
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
        let message = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "request failed".to_string());
        return Err(PaymentGatewayClientError::Http {
            status: status.as_u16(),
            message,
        });
    }
    serde_json::from_slice(&bytes).map_err(|_| PaymentGatewayClientError::InvalidResponse)
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
