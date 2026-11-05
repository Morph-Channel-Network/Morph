#![forbid(unsafe_code)]

//! Isolated Morph -> Fiber adapter and minimal external-edge hook contract.
//!
//! Fiber's current `graph_channels` RPC is read-only and external funding still
//! creates a native Fiber channel state machine. This crate therefore refuses
//! to fake a graph edge through those APIs. It targets an explicit, minimal
//! hook that Fiber can implement or Morph can carry in an isolated patch.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use morph_core::{AgentAsset, Bytes32, ProviderEdgeDescriptor};
use reqwest::{Client, Url, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const MAX_RPC_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const REGISTER_EXTERNAL_EDGE_METHOD: &str = "morph_register_external_edge";
pub const UPDATE_EXTERNAL_EDGE_METHOD: &str = "morph_update_external_edge";
pub const DISABLE_EXTERNAL_EDGE_METHOD: &str = "morph_disable_external_edge";
pub const LIST_EXTERNAL_EDGES_METHOD: &str = "morph_list_external_edges";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiberExternalEdge {
    pub morph_edge_id: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub funding_epoch: u64,
    pub state_number: u64,
    /// Fiber graph endpoints: compressed secp256k1 public keys.
    pub node_ids: [String; 2],
    /// Provider-neutral Morph account IDs derived from the same keys.
    pub morph_participant_ids: [String; 2],
    pub asset: FiberEdgeAsset,
    pub directional_liquidity: [String; 2],
    pub deployment_id: String,
    pub factory_id: Option<String>,
    pub factory_update_number: Option<u64>,
    pub evidence_block_hash: String,
    pub evidence_block_number: u64,
    pub opaque_morph_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FiberEdgeAsset {
    Ckb {
        ckb_genesis_hash: String,
    },
    Xudt {
        ckb_genesis_hash: String,
        type_script_hash: String,
    },
    Rgbpp {
        ckb_genesis_hash: String,
        type_script_hash: String,
        bitcoin_network: String,
        binding_code_hash: String,
    },
}

impl TryFrom<&ProviderEdgeDescriptor> for FiberExternalEdge {
    type Error = AdapterError;

    fn try_from(edge: &ProviderEdgeDescriptor) -> AdapterResult<Self> {
        if edge.edge_id
            != edge
                .derive_id()
                .map_err(|_| AdapterError::InvalidMorphEdge)?
            || edge.directional_liquidity.iter().all(|amount| *amount == 0)
        {
            return Err(AdapterError::InvalidMorphEdge);
        }
        let asset = match &edge.asset {
            AgentAsset::Ckb { ckb_genesis_hash } => FiberEdgeAsset::Ckb {
                ckb_genesis_hash: hex32(ckb_genesis_hash),
            },
            AgentAsset::Xudt {
                ckb_genesis_hash,
                type_script_hash,
            } => FiberEdgeAsset::Xudt {
                ckb_genesis_hash: hex32(ckb_genesis_hash),
                type_script_hash: hex32(type_script_hash),
            },
            AgentAsset::Rgbpp(asset) => FiberEdgeAsset::Rgbpp {
                ckb_genesis_hash: hex32(&asset.ckb_genesis_hash),
                type_script_hash: hex32(&asset.xudt_type_script_hash),
                bitcoin_network: format!("{:?}", asset.bitcoin_network).to_ascii_lowercase(),
                binding_code_hash: hex32(&asset.binding_code_hash),
            },
        };
        Ok(Self {
            morph_edge_id: hex32(&edge.edge_id),
            channel_id: hex32(&edge.channel_id),
            funding_context_id: hex32(&edge.funding_context_id),
            funding_epoch: edge.funding_epoch,
            state_number: edge.state_number,
            node_ids: [
                hex_bytes(&edge.participant_pubkeys_sec1[0]),
                hex_bytes(&edge.participant_pubkeys_sec1[1]),
            ],
            morph_participant_ids: [hex32(&edge.participants[0]), hex32(&edge.participants[1])],
            asset,
            directional_liquidity: [
                edge.directional_liquidity[0].to_string(),
                edge.directional_liquidity[1].to_string(),
            ],
            deployment_id: hex32(&edge.deployment_id),
            factory_id: edge.factory_id.map(|value| hex32(&value)),
            factory_update_number: edge.factory_update_number,
            evidence_block_hash: hex32(&edge.evidence_block_hash),
            evidence_block_number: edge.evidence_block_number,
            opaque_morph_commitment: hex32(&edge.opaque_morph_commitment),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterExternalEdgeRequest {
    pub edge: FiberExternalEdge,
    /// Reject registration if Fiber already mirrors a different generation for
    /// this channel. Splice replacement is always explicit.
    pub expected_previous_edge_id: Option<String>,
    pub callback_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateExternalEdgeRequest {
    pub edge: FiberExternalEdge,
    pub expected_provider_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisableExternalEdgeRequest {
    pub morph_edge_id: String,
    pub expected_provider_revision: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiberHookAck {
    pub morph_edge_id: String,
    pub provider_revision: u64,
    pub enabled: bool,
    pub opaque_morph_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirroredFiberEdge {
    pub channel_id: String,
    pub morph_edge_id: String,
    pub funding_context_id: String,
    pub provider_revision: u64,
    pub enabled: bool,
    pub opaque_morph_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPaymentDirection {
    FirstToSecond,
    SecondToFirst,
}

/// Fiber -> Morph callback used while forwarding a TLC over a Morph-backed
/// edge. `prepare` reserves a descriptor transition; `commit` is accepted only
/// after Morph obtains the required bilateral signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPaymentPrepare {
    pub morph_edge_id: String,
    pub provider_revision: u64,
    pub payment_id: String,
    pub direction: ExternalPaymentDirection,
    pub amount: String,
    pub payment_hash: String,
    pub expiry_unix_millis: u64,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPaymentPrepared {
    pub payment_id: String,
    pub morph_prepared_id: String,
    pub expected_state_number: u64,
    pub opaque_proposal_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPaymentResolution {
    Fulfill { preimage: String },
    Fail { failure_code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPaymentResolve {
    pub morph_edge_id: String,
    pub provider_revision: u64,
    pub payment_id: String,
    pub morph_prepared_id: String,
    pub resolution: ExternalPaymentResolution,
}

#[derive(Clone)]
pub struct FiberHookClient {
    url: Url,
    bearer_token: Option<String>,
    callback_endpoint: Url,
    client: Client,
    next_id: Arc<AtomicU64>,
}

impl FiberHookClient {
    pub fn new(
        rpc_url: &str,
        bearer_token: Option<String>,
        callback_endpoint: &str,
    ) -> AdapterResult<Self> {
        let url = parse_http_url(rpc_url)?;
        let callback_endpoint = parse_http_url(callback_endpoint)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| AdapterError::Transport(error.to_string()))?;
        Ok(Self {
            url,
            bearer_token,
            callback_endpoint,
            client,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub async fn register_edge(
        &self,
        edge: &ProviderEdgeDescriptor,
        expected_previous_edge_id: Option<Bytes32>,
    ) -> AdapterResult<FiberHookAck> {
        let ack: FiberHookAck = self
            .call(
                REGISTER_EXTERNAL_EDGE_METHOD,
                RegisterExternalEdgeRequest {
                    edge: FiberExternalEdge::try_from(edge)?,
                    expected_previous_edge_id: expected_previous_edge_id.map(|value| hex32(&value)),
                    callback_endpoint: self.callback_endpoint.to_string(),
                },
            )
            .await?;
        validate_enabled_ack(&ack, edge, 0)?;
        Ok(ack)
    }

    pub async fn update_edge(
        &self,
        edge: &ProviderEdgeDescriptor,
        expected_provider_revision: u64,
    ) -> AdapterResult<FiberHookAck> {
        let ack: FiberHookAck = self
            .call(
                UPDATE_EXTERNAL_EDGE_METHOD,
                UpdateExternalEdgeRequest {
                    edge: FiberExternalEdge::try_from(edge)?,
                    expected_provider_revision,
                },
            )
            .await?;
        validate_enabled_ack(&ack, edge, expected_provider_revision)?;
        Ok(ack)
    }

    pub async fn disable_edge(
        &self,
        edge_id: Bytes32,
        expected_provider_revision: u64,
        reason: String,
    ) -> AdapterResult<FiberHookAck> {
        if reason.trim().is_empty() || reason.len() > 256 {
            return Err(AdapterError::InvalidRequest);
        }
        let ack: FiberHookAck = self
            .call(
                DISABLE_EXTERNAL_EDGE_METHOD,
                DisableExternalEdgeRequest {
                    morph_edge_id: hex32(&edge_id),
                    expected_provider_revision,
                    reason,
                },
            )
            .await?;
        if ack.morph_edge_id != hex32(&edge_id)
            || ack.enabled
            || expected_provider_revision.checked_add(1) != Some(ack.provider_revision)
        {
            return Err(AdapterError::ProviderAckMismatch);
        }
        Ok(ack)
    }

    pub async fn list_edges(&self) -> AdapterResult<Vec<MirroredFiberEdge>> {
        self.call(LIST_EXTERNAL_EDGES_METHOD, json!({})).await
    }

    async fn call<P: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> AdapterResult<T> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": [params],
        });
        let mut request = self.client.post(self.url.clone()).json(&body);
        if let Some(token) = &self.bearer_token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|error| AdapterError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(AdapterError::Http(response.status().as_u16()));
        }
        let bytes = read_response_limited(response, MAX_RPC_RESPONSE_BYTES)
            .await?
            .ok_or(AdapterError::ResponseTooLarge)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| AdapterError::MalformedResponse)?;
        if value.get("jsonrpc") != Some(&json!("2.0")) || value.get("id") != Some(&json!(id)) {
            return Err(AdapterError::MalformedResponse);
        }
        if let Some(error) = value.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(-1);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown Fiber hook error")
                .to_string();
            if code == -32601 {
                return Err(AdapterError::HookUnavailable);
            }
            return Err(AdapterError::Rpc {
                method: method.to_string(),
                code,
                message,
            });
        }
        serde_json::from_value(
            value
                .get("result")
                .cloned()
                .ok_or(AdapterError::MalformedResponse)?,
        )
        .map_err(|_| AdapterError::MalformedResponse)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    Register {
        edge_id: Bytes32,
    },
    Update {
        edge_id: Bytes32,
        expected_provider_revision: u64,
    },
    DisableUnknown {
        edge_id: Bytes32,
        expected_provider_revision: u64,
    },
}

/// Compare provider state with verified Morph state after restart. Morph wins:
/// unknown Fiber mirrors are disabled, and changed Morph commitments are
/// updated using optimistic provider revisions.
pub fn reconciliation_plan(
    local_edges: &[ProviderEdgeDescriptor],
    mirrored_edges: &[MirroredFiberEdge],
) -> AdapterResult<Vec<ReconcileAction>> {
    morph_core::validate_provider_edge_set(local_edges)
        .map_err(|_| AdapterError::InvalidMorphEdge)?;
    let mut local = BTreeMap::new();
    for edge in local_edges {
        if edge.edge_id
            != edge
                .derive_id()
                .map_err(|_| AdapterError::InvalidMorphEdge)?
            || local.insert(edge.edge_id, edge).is_some()
        {
            return Err(AdapterError::InvalidMorphEdge);
        }
    }
    let mut mirrored = BTreeMap::new();
    for edge in mirrored_edges {
        let edge_id = decode_byte32(&edge.morph_edge_id)?;
        decode_byte32(&edge.channel_id)?;
        decode_byte32(&edge.funding_context_id)?;
        decode_byte32(&edge.opaque_morph_commitment)?;
        if mirrored.insert(edge_id, edge).is_some() {
            return Err(AdapterError::DuplicateProviderEdge);
        }
    }
    let mut actions = Vec::new();
    for (edge_id, edge) in &local {
        match mirrored.get(edge_id) {
            None => actions.push(ReconcileAction::Register { edge_id: *edge_id }),
            Some(remote)
                if remote.channel_id != hex32(&edge.channel_id)
                    || remote.funding_context_id != hex32(&edge.funding_context_id)
                    || remote.opaque_morph_commitment != hex32(&edge.opaque_morph_commitment)
                    || !remote.enabled =>
            {
                actions.push(ReconcileAction::Update {
                    edge_id: *edge_id,
                    expected_provider_revision: remote.provider_revision,
                });
            }
            Some(_) => {}
        }
    }
    let local_ids = local.keys().copied().collect::<BTreeSet<_>>();
    for (edge_id, remote) in mirrored {
        if remote.enabled && !local_ids.contains(&edge_id) {
            actions.push(ReconcileAction::DisableUnknown {
                edge_id,
                expected_provider_revision: remote.provider_revision,
            });
        }
    }
    actions.sort_by_key(|action| match action {
        ReconcileAction::Register { edge_id }
        | ReconcileAction::Update { edge_id, .. }
        | ReconcileAction::DisableUnknown { edge_id, .. } => *edge_id,
    });
    Ok(actions)
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Morph edge descriptor is invalid")]
    InvalidMorphEdge,
    #[error("Fiber hook URL or callback URL is invalid")]
    InvalidUrl,
    #[error("Fiber hook request is invalid")]
    InvalidRequest,
    #[error("Fiber hook transport failed: {0}")]
    Transport(String),
    #[error("Fiber hook returned HTTP {0}")]
    Http(u16),
    #[error("Fiber hook response exceeded the safety limit")]
    ResponseTooLarge,
    #[error("Fiber hook returned malformed JSON-RPC")]
    MalformedResponse,
    #[error("the connected Fiber node does not implement the Morph external-edge hook")]
    HookUnavailable,
    #[error("Fiber hook {method} failed with code {code}: {message}")]
    Rpc {
        method: String,
        code: i64,
        message: String,
    },
    #[error("Fiber returned duplicate mirrored edge identifiers")]
    DuplicateProviderEdge,
    #[error("Fiber hook acknowledgement does not match the requested Morph edge or revision")]
    ProviderAckMismatch,
    #[error("hex identifier is malformed")]
    InvalidIdentifier,
}

pub type AdapterResult<T> = Result<T, AdapterError>;

fn parse_http_url(value: &str) -> AdapterResult<Url> {
    let url = Url::parse(value).map_err(|_| AdapterError::InvalidUrl)?;
    let is_loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) {
        return Err(AdapterError::InvalidUrl);
    }
    Ok(url)
}

async fn read_response_limited(
    mut response: reqwest::Response,
    maximum: usize,
) -> AdapterResult<Option<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Ok(None);
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(maximum),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| AdapterError::Transport(error.to_string()))?
    {
        if chunk.len() > maximum.saturating_sub(body.len()) {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

fn validate_enabled_ack(
    ack: &FiberHookAck,
    edge: &ProviderEdgeDescriptor,
    expected_provider_revision: u64,
) -> AdapterResult<()> {
    if ack.morph_edge_id != hex32(&edge.edge_id)
        || ack.opaque_morph_commitment != hex32(&edge.opaque_morph_commitment)
        || !ack.enabled
        || expected_provider_revision.checked_add(1) != Some(ack.provider_revision)
    {
        return Err(AdapterError::ProviderAckMismatch);
    }
    Ok(())
}

fn hex32(value: &Bytes32) -> String {
    format!("0x{}", hex::encode(value))
}

fn hex_bytes(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}

fn decode_byte32(value: &str) -> AdapterResult<Bytes32> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(AdapterError::InvalidIdentifier)?;
    let raw = hex::decode(raw).map_err(|_| AdapterError::InvalidIdentifier)?;
    let decoded = raw
        .try_into()
        .map_err(|_| AdapterError::InvalidIdentifier)?;
    if hex32(&decoded) != value {
        return Err(AdapterError::InvalidIdentifier);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::{Json, Router, extract::State, routing::post};
    use k256::ecdsa::SigningKey;
    use morph_core::blake2b256;

    use super::*;

    fn edge(tag: u8) -> ProviderEdgeDescriptor {
        let participant_pubkeys_sec1 = [1_u8, 2_u8].map(|seed| {
            SigningKey::from_slice(&[seed; 32])
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
        });
        let mut edge = ProviderEdgeDescriptor {
            edge_id: [0; 32],
            channel_id: [tag; 32],
            funding_context_id: [tag + 1; 32],
            funding_epoch: 0,
            state_number: 1,
            participants: [
                blake2b256(&participant_pubkeys_sec1[0]),
                blake2b256(&participant_pubkeys_sec1[1]),
            ],
            participant_pubkeys_sec1,
            asset: AgentAsset::Ckb {
                ckb_genesis_hash: [tag + 4; 32],
            },
            directional_liquidity: [60, 40],
            deployment_id: [tag + 5; 32],
            factory_id: Some([tag + 6; 32]),
            factory_update_number: Some(7),
            factory_reservation_id: Some([tag + 7; 32]),
            evidence_block_hash: [tag + 8; 32],
            evidence_block_number: 100,
            opaque_morph_commitment: [tag + 9; 32],
        };
        edge.edge_id = edge.derive_id().unwrap();
        edge
    }

    #[test]
    fn edge_projection_never_invents_a_fiber_funding_outpoint() {
        let projection = FiberExternalEdge::try_from(&edge(1)).unwrap();
        let json = serde_json::to_value(projection).unwrap();
        assert!(json.get("funding_outpoint").is_none());
        assert!(json.get("morph_edge_id").is_some());
        assert!(json.get("funding_context_id").is_some());
        assert_eq!(
            json.pointer("/node_ids/0")
                .and_then(Value::as_str)
                .unwrap()
                .len(),
            68
        );
        assert_eq!(
            json.pointer("/morph_participant_ids/0")
                .and_then(Value::as_str)
                .unwrap()
                .len(),
            66
        );
    }

    #[test]
    fn reconciliation_accepts_distinct_assets_only_at_one_current_channel_snapshot() {
        let ckb = edge(1);
        let mut token = ckb.clone();
        token.asset = AgentAsset::Xudt {
            ckb_genesis_hash: [5; 32],
            type_script_hash: [81; 32],
        };
        token.edge_id = token.derive_id().unwrap();
        assert_eq!(
            reconciliation_plan(&[ckb.clone(), token.clone()], &[])
                .unwrap()
                .len(),
            2
        );
        let mut stale = token.clone();
        stale.state_number += 1;
        stale.opaque_morph_commitment = [82; 32];
        assert!(matches!(
            reconciliation_plan(&[ckb.clone(), stale], &[]),
            Err(AdapterError::InvalidMorphEdge)
        ));
        let mut equivocation = token;
        equivocation.opaque_morph_commitment = [83; 32];
        assert!(matches!(
            reconciliation_plan(&[ckb, equivocation], &[]),
            Err(AdapterError::InvalidMorphEdge)
        ));
    }

    #[test]
    fn reconciliation_rejects_double_counting_one_type_under_native_and_rgbpp_aliases() {
        let mut native = edge(1);
        native.asset = AgentAsset::Xudt {
            ckb_genesis_hash: [5; 32],
            type_script_hash: [81; 32],
        };
        native.edge_id = native.derive_id().unwrap();
        let mut rgbpp = native.clone();
        rgbpp.asset = AgentAsset::Rgbpp(morph_core::RgbppAssetId {
            ckb_genesis_hash: [5; 32],
            xudt_type_script_hash: [81; 32],
            bitcoin_network: morph_core::BitcoinNetwork::Regtest,
            binding_code_hash: [82; 32],
        });
        rgbpp.edge_id = rgbpp.derive_id().unwrap();
        assert_ne!(native.edge_id, rgbpp.edge_id);
        assert!(matches!(
            reconciliation_plan(&[native, rgbpp], &[]),
            Err(AdapterError::InvalidMorphEdge)
        ));
    }

    #[test]
    fn hook_and_callback_require_tls_off_loopback() {
        for accepted in [
            "http://localhost:8227",
            "http://127.0.0.1:8227",
            "http://[::1]:8227",
            "https://fiber.example.com",
        ] {
            assert!(parse_http_url(accepted).is_ok(), "{accepted}");
        }
        for rejected in ["http://example.com", "http://10.0.0.8:8227"] {
            assert!(
                matches!(parse_http_url(rejected), Err(AdapterError::InvalidUrl)),
                "{rejected}"
            );
        }
        assert!(matches!(
            FiberHookClient::new(
                "https://fiber.example.com",
                None,
                "http://10.0.0.9:4621/callback"
            ),
            Err(AdapterError::InvalidUrl)
        ));
    }

    #[test]
    fn restart_reconciliation_treats_morph_as_source_of_truth() {
        let current = edge(1);
        let unknown = edge(20);
        let remote = vec![
            MirroredFiberEdge {
                channel_id: hex32(&current.channel_id),
                morph_edge_id: hex32(&current.edge_id),
                funding_context_id: hex32(&current.funding_context_id),
                provider_revision: 3,
                enabled: true,
                opaque_morph_commitment: hex32(&[99; 32]),
            },
            MirroredFiberEdge {
                channel_id: hex32(&unknown.channel_id),
                morph_edge_id: hex32(&unknown.edge_id),
                funding_context_id: hex32(&unknown.funding_context_id),
                provider_revision: 4,
                enabled: true,
                opaque_morph_commitment: hex32(&unknown.opaque_morph_commitment),
            },
        ];
        let plan = reconciliation_plan(std::slice::from_ref(&current), &remote).unwrap();
        assert_eq!(plan.len(), 2);
        assert!(plan.contains(&ReconcileAction::Update {
            edge_id: current.edge_id,
            expected_provider_revision: 3,
        }));
        assert!(plan.contains(&ReconcileAction::DisableUnknown {
            edge_id: unknown.edge_id,
            expected_provider_revision: 4,
        }));
    }

    #[test]
    fn liquidity_updates_keep_the_registered_edge_id() {
        let current = edge(1);
        let mut updated = current.clone();
        updated.state_number += 1;
        updated.directional_liquidity = [55, 45];
        updated.opaque_morph_commitment = [42; 32];
        updated.evidence_block_number += 1;
        updated.evidence_block_hash = [43; 32];
        assert_eq!(updated.derive_id().unwrap(), current.edge_id);

        let mirrored = MirroredFiberEdge {
            channel_id: hex32(&current.channel_id),
            morph_edge_id: hex32(&current.edge_id),
            funding_context_id: hex32(&current.funding_context_id),
            provider_revision: 7,
            enabled: true,
            opaque_morph_commitment: hex32(&current.opaque_morph_commitment),
        };
        assert_eq!(
            reconciliation_plan(&[updated], &[mirrored]).unwrap(),
            vec![ReconcileAction::Update {
                edge_id: current.edge_id,
                expected_provider_revision: 7,
            }]
        );
    }

    #[test]
    fn reconciliation_repairs_a_wrong_provider_channel_binding() {
        let current = edge(1);
        let mirrored = MirroredFiberEdge {
            channel_id: hex32(&[99; 32]),
            morph_edge_id: hex32(&current.edge_id),
            funding_context_id: hex32(&current.funding_context_id),
            provider_revision: 2,
            enabled: true,
            opaque_morph_commitment: hex32(&current.opaque_morph_commitment),
        };
        assert_eq!(
            reconciliation_plan(std::slice::from_ref(&current), &[mirrored]).unwrap(),
            vec![ReconcileAction::Update {
                edge_id: current.edge_id,
                expected_provider_revision: 2,
            }]
        );
    }

    #[derive(Default)]
    struct MockState {
        methods: Vec<String>,
    }

    async fn mock_hook(
        State(state): State<Arc<Mutex<MockState>>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let id = request.get("id").cloned().unwrap();
        let method = request.get("method").and_then(Value::as_str).unwrap();
        state.lock().unwrap().methods.push(method.to_string());
        let edge = request.pointer("/params/0/edge");
        let result = json!({
            "morph_edge_id": edge
                .and_then(|edge| edge.get("morph_edge_id"))
                .and_then(Value::as_str)
                .unwrap_or(&format!("0x{}", "01".repeat(32))),
            "provider_revision": 1,
            "enabled": true,
            "opaque_morph_commitment": edge
                .and_then(|edge| edge.get("opaque_morph_commitment"))
                .and_then(Value::as_str)
                .unwrap_or(&format!("0x{}", "02".repeat(32))),
        });
        Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    #[tokio::test]
    async fn client_calls_only_the_explicit_external_edge_hook() {
        let state = Arc::new(Mutex::new(MockState::default()));
        let app = Router::new()
            .route("/", post(mock_hook))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = FiberHookClient::new(
            &format!("http://{address}"),
            None,
            "http://127.0.0.1:4621/callback",
        )
        .unwrap();
        let edge = edge(1);
        let ack = client.register_edge(&edge, None).await.unwrap();
        assert_eq!(ack.morph_edge_id, hex32(&edge.edge_id));
        assert_eq!(
            state.lock().unwrap().methods,
            vec![REGISTER_EXTERNAL_EDGE_METHOD]
        );
    }
}
