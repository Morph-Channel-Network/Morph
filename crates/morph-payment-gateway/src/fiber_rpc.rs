use std::{
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use reqwest::{Client, Url, header};
use serde_json::{Value, json};
use thiserror::Error;

use crate::http_safety::{is_secure_service_url, read_response_limited};

const MAX_RPC_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FiberRpcError {
    #[error("invalid Fiber JSON-RPC URL")]
    InvalidUrl,
    #[error("Fiber RPC transport failed: {0}")]
    Transport(String),
    #[error("Fiber RPC returned HTTP {0}")]
    Http(u16),
    #[error("Fiber RPC response exceeded the 2 MiB safety limit")]
    ResponseTooLarge,
    #[error("Fiber RPC returned malformed JSON")]
    MalformedResponse,
    #[error("Fiber RPC {method} failed with code {code}: {message}")]
    Rpc {
        method: String,
        code: i64,
        message: String,
    },
}

#[derive(Clone)]
pub struct FiberRpcClient {
    url: Url,
    bearer_token: Option<String>,
    client: Client,
    next_id: Arc<AtomicU64>,
}

impl FiberRpcClient {
    pub fn new(url: &str, bearer_token: Option<String>) -> Result<Self, FiberRpcError> {
        let url = Url::parse(url).map_err(|_| FiberRpcError::InvalidUrl)?;
        if !is_secure_service_url(&url) {
            return Err(FiberRpcError::InvalidUrl);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| FiberRpcError::Transport(error.to_string()))?;
        Ok(Self {
            url,
            bearer_token,
            client,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, FiberRpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            // jsonrpsee positional RPCs take one typed parameter.
            "params": [params],
        });
        let mut request = self.client.post(self.url.clone()).json(&body);
        if let Some(token) = &self.bearer_token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|error| FiberRpcError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(FiberRpcError::Http(response.status().as_u16()));
        }
        let bytes = read_response_limited(response, MAX_RPC_RESPONSE_BYTES)
            .await
            .map_err(|error| FiberRpcError::Transport(error.to_string()))?
            .ok_or(FiberRpcError::ResponseTooLarge)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| FiberRpcError::MalformedResponse)?;
        if value.get("id") != Some(&json!(id)) || value.get("jsonrpc") != Some(&json!("2.0")) {
            return Err(FiberRpcError::MalformedResponse);
        }
        if let Some(error) = value.get("error") {
            return Err(FiberRpcError::Rpc {
                method: method.to_string(),
                code: error.get("code").and_then(Value::as_i64).unwrap_or(-1),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown Fiber error")
                    .to_string(),
            });
        }
        value
            .get("result")
            .cloned()
            .ok_or(FiberRpcError::MalformedResponse)
    }

    pub async fn new_invoice(&self, params: Value) -> Result<Value, FiberRpcError> {
        self.call("new_invoice", params).await
    }

    pub async fn parse_invoice(&self, invoice: &str) -> Result<Value, FiberRpcError> {
        self.call("parse_invoice", json!({ "invoice": invoice }))
            .await
    }

    pub async fn get_invoice(&self, payment_hash: &str) -> Result<Value, FiberRpcError> {
        self.call("get_invoice", json!({ "payment_hash": payment_hash }))
            .await
    }

    pub async fn send_payment(&self, params: Value) -> Result<Value, FiberRpcError> {
        self.call("send_payment", params).await
    }

    pub async fn get_payment(&self, payment_hash: &str) -> Result<Value, FiberRpcError> {
        self.call("get_payment", json!({ "payment_hash": payment_hash }))
            .await
    }

    pub async fn list_payments(
        &self,
        status: Option<&str>,
        limit: u64,
        after: Option<&str>,
    ) -> Result<Value, FiberRpcError> {
        self.call(
            "list_payments",
            json!({
                "status": status,
                "limit": format!("0x{limit:x}"),
                "after": after,
            }),
        )
        .await
    }
}

pub fn extract_invoice_address(result: &Value) -> Result<&str, FiberRpcError> {
    result
        .get("invoice_address")
        .and_then(Value::as_str)
        .ok_or(FiberRpcError::MalformedResponse)
}

pub fn extract_invoice_payment_hash(result: &Value) -> Result<&str, FiberRpcError> {
    result
        .pointer("/invoice/data/payment_hash")
        .and_then(Value::as_str)
        .ok_or(FiberRpcError::MalformedResponse)
}

pub fn invoice_is_paid(result: &Value) -> bool {
    result.get("status").and_then(Value::as_str) == Some("Paid")
}

pub fn payment_is_success(result: &Value) -> bool {
    result.get("status").and_then(Value::as_str) == Some("Success")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_status_parsing_does_not_accept_inflight() {
        assert!(invoice_is_paid(&json!({"status": "Paid"})));
        assert!(!invoice_is_paid(&json!({"status": "Received"})));
        assert!(payment_is_success(&json!({"status": "Success"})));
        assert!(!payment_is_success(&json!({"status": "Inflight"})));
    }

    #[test]
    fn client_requires_tls_for_non_loopback_fiber_rpc() {
        for accepted in [
            "http://localhost:8227",
            "http://127.0.0.1:8227",
            "http://[::1]:8227",
            "https://fiber.example.com",
        ] {
            assert!(FiberRpcClient::new(accepted, None).is_ok(), "{accepted}");
        }
        for rejected in ["http://example.com", "http://10.0.0.8:8227"] {
            assert!(
                matches!(
                    FiberRpcClient::new(rejected, None),
                    Err(FiberRpcError::InvalidUrl)
                ),
                "{rejected}"
            );
        }
    }
}
