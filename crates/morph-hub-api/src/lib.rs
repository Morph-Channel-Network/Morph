//! Shared public Hub projection and transport DTOs. No signer authority or GUI dependencies.

pub use morph_observability::{Liveness, Readiness};

pub mod admin;
pub use admin::{RestoreArchiveRequest, StateArchive};
pub mod endpoints;
pub mod error;
pub mod openapi;
pub mod schema;
pub use error::ApiErrorCode;
pub mod mutation;
pub use mutation::{ApiInfo, MutationContext};

pub use morph_packages::events::{EventCursor, EventEnvelope, EventPage, EventPageRequest};

use morph_packages::{
    conditional_packages::StoredConditionalBatchPackage,
    multi_asset_funding::RootCollectionSummary, multi_asset_packages::MultiAssetPackageSummary,
};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthScope {
    Read,
    Write,
    Restore,
    Sign,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApiErrorBody {
    pub error: String,
    pub code: ApiErrorCode,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestorePreview {
    pub confirmation_hash: String,
    pub allowed: bool,
    pub current: RestoreStateSummary,
    pub candidate: RestoreStateSummary,
    pub ignored_completed_flows: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HubView {
    /// Durable revision of this exact projection, for review/confirm CAS.
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub revision: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub max_invoice_expiry_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordProvenanceView {
    pub source: String,
    pub chain_status: String,
    pub label: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WatchtowerView {
    pub configured: bool,
    pub alert_file: Option<String>,
    pub file_exists: bool,
    pub alerts: Vec<WatchtowerAlertView>,
    pub last_error: Option<String>,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WatchtowerAlertView {
    pub schema: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub created_unix_ms: u64,
    pub channel_id: String,
    pub severity: WatchAlertSeverity,
    pub event: WatchAlertEvent,
    pub message: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub selected_state_number: u64,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    pub selected_funding_anchor: Option<String>,
    pub observed_funding_anchor: Option<String>,
    pub selected_funding_context_id: Option<String>,
    pub observed_funding_context_id: Option<String>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub scanned_to_block: u64,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub next_from_block: u64,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RpcView {
    pub status: String,
    pub url: Option<String>,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub tip_height: Option<u64>,
    pub chain: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeerView {
    pub pubkey: String,
    pub node_id: String,
    pub alias: String,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChannelView {
    pub channel_id: String,
    pub factory_id: Option<String>,
    pub counterparty_pubkey: String,
    pub counterparty_node_id: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub funding_epoch: u64,
    pub funding_context_id: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub state_number: u64,
    pub phase: String,
    pub balances: Vec<BalanceView>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub sponsor_budget: u64,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BalanceView {
    pub asset: AssetView,
    pub local: String,
    pub remote: String,
    pub pending: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
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
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub created_at_unix: u64,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub expires_at_unix: u64,
    pub payment_hash: String,
    pub description: String,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub received_at_unix: Option<u64>,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub paid_at_unix: Option<u64>,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub cancelled_at_unix: Option<u64>,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FactoryView {
    pub factory_id: String,
    pub participant_pubkeys: Vec<String>,
    pub participant_node_ids: Vec<String>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub update_number: u64,
    pub reserve_balances: Vec<BalanceView>,
    pub materialised_child_channels: Vec<String>,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EventView {
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub id: u64,
    pub severity: EventSeverity,
    pub event: String,
    pub subject_id: Option<String>,
    pub message: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub created_at_unix: u64,
    pub provenance: RecordProvenanceView,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AssetView {
    Ckb,
    Xudt { type_hash: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WatchAlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateInvoiceRequest {
    pub amount: String,
    pub description: String,
    pub payment_preimage: Option<String>,
    pub payment_hash: Option<String>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub expiry_secs: u64,
    pub channel_id: Option<String>,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeInvoiceRequest {
    pub encoded_invoice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettleInvoiceRequest {
    pub payment_preimage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectPeerRequest {
    pub pubkey: String,
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenChannelRequest {
    pub channel_id: String,
    pub counterparty_pubkey: String,
    pub counterparty_alias: Option<String>,
    pub funding_context_id: String,
    pub local: String,
    pub remote: String,
    pub pending: Option<String>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub sponsor_budget: u64,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpliceChannelRequest {
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub new_funding_epoch: u64,
    pub new_funding_context_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishStateRequest {
    pub funding_context_id: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub state_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenFactoryRequest {
    pub factory_id: String,
    pub participant_pubkeys: Vec<String>,
    pub reserve: String,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdvanceFactoryRequest {
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub new_update_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialiseChildRequest {
    pub child_channel_id: String,
    pub counterparty_pubkey: String,
    pub counterparty_alias: Option<String>,
    pub funding_context_id: String,
    pub local: String,
    pub remote: String,
    pub pending: Option<String>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub sponsor_budget: u64,
    pub asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum AssetRequest {
    Ckb {},
    Xudt { type_hash: String },
}

/// Body for actions without parameters: the sole encoding is an empty object.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

/// Public participant receipt; this DTO never carries a private signing key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootReceiptRequest {
    pub target: morph_packages::multi_asset_funding::RootFundingTarget,
    pub receipt: morph_packages::multi_asset_signatures::SignatureMessage,
}
