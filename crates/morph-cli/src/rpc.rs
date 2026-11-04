use std::fmt;
use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ckb_jsonrpc_types::{
    BlockView, CellWithStatus, EstimateCycles, FeeRateStatistics, OutPoint as JsonOutPoint,
    Transaction, TransactionWithStatusResponse, TxPoolInfo, Uint64,
};
use ckb_types::H256;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const CKB_RPC_REQUEST_TIMEOUT_SECS: u64 = 90;
const CKB_RPC_CONNECT_TIMEOUT_SECS: u64 = 10;
const CKB_RPC_TRANSPORT_MAX_ATTEMPTS: usize = 4;
// Keep transport retries short because a request timeout is already expensive.
// Fiber-backed local devnets can surface longer 502 windows while CKB remains live.
const CKB_RPC_RETRYABLE_STATUS_MAX_ATTEMPTS: usize = 32;
const CKB_RPC_RETRY_BASE_DELAY_MS: u64 = 250;
const CKB_RPC_RETRY_MAX_DELAY_MS: u64 = 2_000;
const MAX_CKB_RPC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RPC_ERROR_DIAGNOSTIC_CHARS: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct CkbRpcClient {
    url: String,
    client: Client,
    transport_max_attempts: usize,
    retryable_status_max_attempts: usize,
    max_attempts: usize,
    deadline: Option<Instant>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug)]
pub struct RpcMethodError {
    method: String,
    code: i64,
    message: String,
}

impl RpcMethodError {
    pub fn code(&self) -> i64 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RpcMethodError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CKB RPC error {} on {}: {}",
            self.code, self.method, self.message
        )
    }
}

impl std::error::Error for RpcMethodError {}

pub fn rpc_method_error(error: &anyhow::Error) -> Option<&RpcMethodError> {
    error.downcast_ref::<RpcMethodError>()
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderView {
    pub hash: String,
    pub number: String,
    pub parent_hash: String,
    pub timestamp: String,
    pub epoch: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainInfo {
    pub chain: String,
    pub median_time: String,
    pub epoch: String,
    pub is_initial_block_download: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalNodeInfo {
    pub active: bool,
    pub node_id: String,
    pub connections: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct DevnetStatus {
    pub tip: HeaderView,
    pub chain: ChainInfo,
    pub node: LocalNodeInfo,
}

impl CkbRpcClient {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Self::with_options(
            url,
            Duration::from_secs(CKB_RPC_REQUEST_TIMEOUT_SECS),
            Duration::from_secs(CKB_RPC_CONNECT_TIMEOUT_SECS),
            CKB_RPC_TRANSPORT_MAX_ATTEMPTS,
            CKB_RPC_RETRYABLE_STATUS_MAX_ATTEMPTS,
        )
    }

    pub fn new_health_check(url: impl Into<String>) -> Result<Self> {
        Self::with_options(url, Duration::from_secs(2), Duration::from_secs(1), 1, 1)
    }

    pub fn new_supervision(url: impl Into<String>, budget: Duration) -> Result<Self> {
        anyhow::ensure!(!budget.is_zero(), "supervision RPC budget must be positive");
        let mut client = Self::with_options(url, budget, budget.min(Duration::from_secs(1)), 1, 1)?;
        client.deadline = Some(
            Instant::now()
                .checked_add(budget)
                .ok_or_else(|| anyhow!("RPC deadline overflow"))?,
        );
        Ok(client)
    }

    pub fn ensure_deadline(&self) -> Result<()> {
        let _ = self.remaining_budget()?;
        Ok(())
    }

    fn remaining_budget(&self) -> Result<Option<Duration>> {
        self.deadline
            .map(|deadline| {
                deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(|| anyhow!("supervision RPC deadline exhausted"))
            })
            .transpose()
    }

    fn with_options(
        url: impl Into<String>,
        request_timeout: Duration,
        connect_timeout: Duration,
        transport_max_attempts: usize,
        retryable_status_max_attempts: usize,
    ) -> Result<Self> {
        let url = url.into();
        let client = Client::builder()
            .timeout(request_timeout)
            .connect_timeout(connect_timeout)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            url,
            client,
            transport_max_attempts,
            retryable_status_max_attempts,
            max_attempts: transport_max_attempts.max(retryable_status_max_attempts),
            deadline: None,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.url
    }

    pub fn tip_header(&self) -> Result<HeaderView> {
        self.call("get_tip_header", json!([]))
    }

    pub fn chain_info(&self) -> Result<ChainInfo> {
        self.call("get_blockchain_info", json!([]))
    }

    pub fn local_node_info(&self) -> Result<LocalNodeInfo> {
        self.call("local_node_info", json!([]))
    }

    pub fn status(&self) -> Result<DevnetStatus> {
        Ok(DevnetStatus {
            tip: self.tip_header()?,
            chain: self.chain_info()?,
            node: self.local_node_info()?,
        })
    }

    pub fn generate_block(&self) -> Result<String> {
        self.call("generate_block", json!([])).with_context(
            || "generate_block failed; ensure the node exposes CKB integration-test RPC methods",
        )
    }

    pub fn truncate(&self, target_tip_hash: H256) -> Result<()> {
        self.call_null("truncate", json!([target_tip_hash]))
            .with_context(
                || "truncate failed; ensure the node exposes CKB integration-test RPC methods",
            )
    }

    pub fn genesis_block_hash(&self) -> Result<Option<H256>> {
        self.call_nullable("get_block_hash", json!(["0x0"]))
    }

    pub fn block_by_number(&self, number: u64) -> Result<Option<BlockView>> {
        self.call_nullable(
            "get_block_by_number",
            json!([format_quantity(number), format_quantity(2), false]),
        )
    }

    pub fn live_cell(&self, out_point: JsonOutPoint, with_data: bool) -> Result<CellWithStatus> {
        self.call("get_live_cell", json!([out_point, with_data, true]))
    }

    pub fn canonical_live_cell(
        &self,
        out_point: JsonOutPoint,
        with_data: bool,
    ) -> Result<CellWithStatus> {
        self.call("get_live_cell", json!([out_point, with_data, false]))
    }

    pub fn send_transaction(&self, transaction: Transaction) -> Result<H256> {
        self.call("send_transaction", json!([transaction, "passthrough"]))
    }

    pub fn estimate_cycles(&self, transaction: Transaction) -> Result<EstimateCycles> {
        self.call("estimate_cycles", json!([transaction]))
    }

    pub fn transaction(&self, tx_hash: H256) -> Result<TransactionWithStatusResponse> {
        self.call(
            "get_transaction",
            json!([tx_hash, format_quantity(2), null]),
        )
    }

    pub fn estimate_fee_rate(&self) -> Result<u64> {
        let rate: Uint64 = self.call("estimate_fee_rate", json!(["no_priority", true]))?;
        Ok(rate.value())
    }

    pub fn fee_rate_statistics(&self, target: Option<u64>) -> Result<Option<FeeRateStatistics>> {
        let params = target
            .map(|value| json!([format_quantity(value)]))
            .unwrap_or_else(|| json!([]));
        self.call_nullable("get_fee_rate_statistics", params)
    }

    pub fn tx_pool_info(&self) -> Result<TxPoolInfo> {
        self.call("tx_pool_info", json!([]))
    }

    pub fn wait_for_tip(
        &self,
        min_number: u64,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<HeaderView> {
        let started = Instant::now();
        loop {
            let tip = self.tip_header()?;
            if tip.number_value()? >= min_number {
                return Ok(tip);
            }
            if started.elapsed() >= timeout {
                bail!(
                    "timed out waiting for tip >= {min_number}; current tip is {}",
                    tip.number_value()?
                );
            }
            std::thread::sleep(poll_interval);
        }
    }

    fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        self.call_nullable(method, params)?
            .ok_or_else(|| anyhow!("CKB RPC response for {method} has no result"))
    }

    fn call_nullable<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<Option<T>> {
        let value = self.call_value(method, params)?;
        value
            .map(|value| {
                serde_json::from_value(value)
                    .with_context(|| format!("invalid JSON-RPC result for method {method}"))
            })
            .transpose()
    }

    fn call_null(&self, method: &str, params: Value) -> Result<()> {
        let result = self.call_value(method, params)?;
        if result.is_some() {
            bail!("CKB RPC response for {method} should be null");
        }
        Ok(())
    }

    fn call_value(&self, method: &str, params: Value) -> Result<Option<Value>> {
        let request = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });

        for attempt in 1..=self.max_attempts {
            let mut builder = self.client.post(&self.url).json(&request);
            if let Some(remaining) = self.remaining_budget()? {
                builder = builder.timeout(remaining);
            }
            let response = match builder.send() {
                Ok(response) => response,
                Err(err) => {
                    if is_retryable_rpc_transport_error(&err)
                        && attempt < self.transport_max_attempts
                    {
                        sleep_before_rpc_retry(attempt);
                        continue;
                    }
                    return Err(err)
                        .with_context(|| format!("failed to call CKB RPC at {}", self.url));
                }
            };
            let status = response.status();
            if response
                .content_length()
                .is_some_and(|length| length > MAX_CKB_RPC_RESPONSE_BYTES as u64)
            {
                bail!(
                    "CKB RPC response for {method} exceeds the {MAX_CKB_RPC_RESPONSE_BYTES}-byte limit"
                );
            }
            let body = read_bounded_rpc_body(response, MAX_CKB_RPC_RESPONSE_BYTES)
                .context("failed to read CKB RPC response body")?;
            if !status.is_success() {
                if is_retryable_rpc_status(status) && attempt < self.retryable_status_max_attempts {
                    sleep_before_rpc_retry(attempt);
                    continue;
                }
                bail!(
                    "CKB RPC HTTP error {status}: {}",
                    bounded_rpc_diagnostic(&body)
                );
            }
            let response: RpcResponse<Value> = serde_json::from_str(&body).with_context(|| {
                format!(
                    "invalid JSON-RPC response for method {method}: {}",
                    bounded_rpc_diagnostic(&body)
                )
            })?;
            if let Some(error) = response.error {
                return Err(RpcMethodError {
                    method: method.to_string(),
                    code: error.code,
                    message: error.message,
                }
                .into());
            }
            self.remaining_budget()?;
            return Ok(response.result);
        }

        anyhow::bail!(
            "CKB RPC retry loop exhausted for {method} after {attempts} attempts (this is a bug; \
             the loop should always return inside the iteration body)",
            attempts = self.max_attempts
        )
    }
}

fn read_bounded_rpc_body<R: Read>(reader: R, limit: usize) -> Result<String> {
    let read_limit = u64::try_from(limit)
        .context("CKB RPC response limit exceeds u64")?
        .checked_add(1)
        .context("CKB RPC response limit overflow")?;
    let mut bytes = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .context("failed to stream CKB RPC response body")?;
    if bytes.len() > limit {
        bail!("CKB RPC response exceeds the {limit}-byte limit");
    }
    String::from_utf8(bytes).context("CKB RPC response body is not UTF-8")
}

fn bounded_rpc_diagnostic(body: &str) -> String {
    body.chars().take(MAX_RPC_ERROR_DIAGNOSTIC_CHARS).collect()
}

fn is_retryable_rpc_transport_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout()
}

fn is_retryable_rpc_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT
    )
}

fn sleep_before_rpc_retry(attempt: usize) {
    let retry_index = attempt.saturating_sub(1).min(8);
    let delay_ms = CKB_RPC_RETRY_BASE_DELAY_MS
        .saturating_mul(1u64 << retry_index)
        .min(CKB_RPC_RETRY_MAX_DELAY_MS);
    std::thread::sleep(Duration::from_millis(delay_ms));
}

impl HeaderView {
    pub fn number_value(&self) -> Result<u64> {
        parse_quantity(&self.number)
    }

    pub fn timestamp_value(&self) -> Result<u64> {
        parse_quantity(&self.timestamp)
    }
}

impl ChainInfo {
    pub fn median_time_value(&self) -> Result<u64> {
        parse_quantity(&self.median_time)
    }
}

impl LocalNodeInfo {
    pub fn connection_count(&self) -> Result<u64> {
        parse_quantity(&self.connections)
    }
}

fn parse_quantity(value: &str) -> Result<u64> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("quantity is not 0x-prefixed: {value}"))?;
    u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex quantity: {value}"))
}

fn format_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn supervision_deadline_covers_the_whole_client_without_transport_retry() {
        let mut rpc =
            CkbRpcClient::new_supervision("http://127.0.0.1:1", Duration::from_secs(1)).unwrap();
        rpc.deadline = Some(Instant::now());
        assert!(rpc.ensure_deadline().is_err());
        assert!(
            rpc.tip_header()
                .unwrap_err()
                .to_string()
                .contains("supervision RPC deadline exhausted")
        );
        assert!(CkbRpcClient::new_supervision("http://127.0.0.1:1", Duration::ZERO).is_err());
    }

    #[test]
    fn bounded_rpc_body_accepts_body_at_limit() {
        let body = read_bounded_rpc_body(Cursor::new(b"1234"), 4).unwrap();
        assert_eq!(body, "1234");
    }

    #[test]
    fn bounded_rpc_body_rejects_body_over_limit() {
        let error = read_bounded_rpc_body(Cursor::new(b"12345"), 4).unwrap_err();
        assert!(error.to_string().contains("exceeds the 4-byte limit"));
    }
}
