//! Shared public Hub projection and transport DTOs. No signer authority or GUI dependencies.

use morph_packages::{
    conditional_packages::StoredConditionalBatchPackage,
    multi_asset_funding::RootCollectionSummary, multi_asset_packages::MultiAssetPackageSummary,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScope {
    Read,
    Write,
    Restore,
    Sign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub code: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePreview {
    pub confirmation_hash: String,
    pub allowed: bool,
    pub current: RestoreStateSummary,
    pub candidate: RestoreStateSummary,
    pub ignored_completed_flows: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreStateSummary {
    pub peers: usize,
    pub channels: usize,
    pub factories: usize,
    pub conditional_batches: usize,
    pub multi_asset_packages: usize,
    pub root_fundings: usize,
    pub invoices: usize,
    pub completed_flows: usize,
    pub events: usize,
    pub settling_channels: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubView {
    pub pubkey: String,
    pub node_id: String,
    pub network: String,
    pub state_path: String,
    pub rpc: RpcView,
    pub security: HubSecurityView,
    pub model: HubModelView,
    pub provenance: RecordProvenanceView,
    pub watchtower: WatchtowerView,
    pub peers: Vec<PeerView>,
    pub channels: Vec<ChannelView>,
    pub invoices: Vec<InvoiceView>,
    pub factories: Vec<FactoryView>,
    pub conditional_batches: Vec<StoredConditionalBatchPackage>,
    pub multi_asset_packages: Vec<MultiAssetPackageSummary>,
    pub multi_asset_package_count: usize,
    pub root_fundings: Vec<RootCollectionSummary>,
    pub events: Vec<EventView>,
    pub required_flows: Vec<String>,
    pub completed_flows: Vec<String>,
    pub missing_flows: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubModelView {
    pub profile: String,
    pub hub_role: String,
    pub factory_authority: String,
    pub channel_authority: String,
    pub routing_role: String,
    pub payment_gateway_role: String,
    pub factory_min_participants: usize,
    pub factory_max_participants: usize,
    pub chain_actions_enabled: bool,
    pub factory_rights_exposed: bool,
    pub provider_edges_exposed: bool,
    pub rgbpp_evidence_exposed: bool,
    pub payment_gateway_receipts_exposed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubSecurityView {
    pub auth_required: bool,
    pub auth_mode: String,
    pub auth_scopes: Vec<AuthScope>,
    pub single_operator: bool,
    pub state_restore_enabled: bool,
    pub invoice_signing_enabled: bool,
    pub cors_origin: Option<String>,
    pub max_concurrent_connections: usize,
    pub max_concurrent_mutations: usize,
    pub max_concurrent_event_streams: usize,
    pub mutation_rate_limit_per_minute: u32,
    pub max_invoice_expiry_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordProvenanceView {
    pub source: String,
    pub chain_status: String,
    pub label: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchtowerView {
    pub configured: bool,
    pub alert_file: Option<String>,
    pub file_exists: bool,
    pub alerts: Vec<WatchtowerAlertView>,
    pub last_error: Option<String>,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchtowerAlertView {
    pub schema: String,
    pub created_unix_ms: u64,
    pub channel_id: String,
    pub severity: WatchAlertSeverity,
    pub event: WatchAlertEvent,
    pub message: String,
    pub selected_state_number: u64,
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    pub selected_funding_anchor: Option<String>,
    pub observed_funding_anchor: Option<String>,
    pub selected_funding_context_id: Option<String>,
    pub observed_funding_context_id: Option<String>,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcView {
    pub status: String,
    pub url: Option<String>,
    pub tip_height: Option<u64>,
    pub chain: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    pub pubkey: String,
    pub node_id: String,
    pub alias: String,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelView {
    pub channel_id: String,
    pub factory_id: Option<String>,
    pub counterparty_pubkey: String,
    pub counterparty_node_id: String,
    pub funding_epoch: u64,
    pub funding_context_id: String,
    pub state_number: u64,
    pub phase: String,
    pub balances: Vec<BalanceView>,
    pub sponsor_budget: u64,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceView {
    pub asset: AssetView,
    pub local: String,
    pub remote: String,
    pub pending: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceView {
    pub invoice_id: String,
    pub encoded_invoice: String,
    pub status: String,
    pub network: String,
    pub payee_pubkey: Option<String>,
    pub payee_node_id: String,
    pub channel_id: Option<String>,
    pub asset: AssetView,
    pub amount: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub payment_hash: String,
    pub description: String,
    pub received_at_unix: Option<u64>,
    pub paid_at_unix: Option<u64>,
    pub cancelled_at_unix: Option<u64>,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryView {
    pub factory_id: String,
    pub participant_pubkeys: Vec<String>,
    pub participant_node_ids: Vec<String>,
    pub update_number: u64,
    pub reserve_balances: Vec<BalanceView>,
    pub materialised_child_channels: Vec<String>,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventView {
    pub id: u64,
    pub severity: EventSeverity,
    pub event: String,
    pub subject_id: Option<String>,
    pub message: String,
    pub created_at_unix: u64,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AssetView {
    Ckb,
    Xudt { type_hash: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAlertEvent {
    ChainReorgDetected,
    RecoveryDataInvalid,
    PublicationFailed,
    OlderStateDetected,
    PublicationSubmitted,
    SpliceDetected,
    SplicePackageStale,
    SplicePublicationSubmitted,
    ScanIdle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvoiceRequest {
    pub amount: String,
    pub description: String,
    pub payment_preimage: Option<String>,
    pub payment_hash: Option<String>,
    pub expiry_secs: u64,
    pub channel_id: Option<String>,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeInvoiceRequest {
    pub encoded_invoice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleInvoiceRequest {
    pub payment_preimage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPeerRequest {
    pub pubkey: String,
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannelRequest {
    pub channel_id: String,
    pub counterparty_pubkey: String,
    pub counterparty_alias: Option<String>,
    pub funding_context_id: String,
    pub local: String,
    pub remote: String,
    pub pending: Option<String>,
    pub sponsor_budget: u64,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpliceChannelRequest {
    pub new_funding_epoch: u64,
    pub new_funding_context_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishStateRequest {
    pub funding_context_id: String,
    pub state_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFactoryRequest {
    pub factory_id: String,
    pub participant_pubkeys: Vec<String>,
    pub reserve: String,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceFactoryRequest {
    pub new_update_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterialiseChildRequest {
    pub child_channel_id: String,
    pub counterparty_pubkey: String,
    pub counterparty_alias: Option<String>,
    pub funding_context_id: String,
    pub local: String,
    pub remote: String,
    pub pending: Option<String>,
    pub sponsor_budget: u64,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AssetRequest {
    Ckb,
    Xudt { type_hash: String },
}
