//! Public administrative archive, distinct from the private runtime snapshot.
//! It contains no signer journal or signing permission. Import remains subject
//! to the server's empty-bootstrap-only restore policy and confirmation.
use crate::{AssetRequest, EventSeverity, mutation};
use morph_packages::{
    conditional_packages::StoredConditionalBatchPackage,
    multi_asset_funding::RootFundingCollection, multi_asset_packages::StoredMultiAssetPackage,
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveNetwork {
    Devnet,
    Testnet,
    Mainnet,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArchivePhase {
    Funding,
    Active,
    Settling,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveInvoiceStatus {
    Open,
    Received,
    Paid,
    Cancelled,
    Expired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFlow {
    PeerConnected,
    InvoiceCreated,
    InvoiceReceived,
    InvoiceSettled,
    ChannelOpened,
    StatePublished,
    ChannelFinalised,
    ChannelSpliced,
    FactoryOpened,
    FactoryAdvanced,
    FactoryChildMaterialised,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateArchive {
    pub pubkey: String,
    pub network: ArchiveNetwork,
    pub peers: Vec<ArchivePeer>,
    pub channels: Vec<ArchiveChannel>,
    pub factories: Vec<ArchiveFactory>,
    pub conditional_batches: Vec<StoredConditionalBatchPackage>,
    pub multi_asset_packages: Vec<StoredMultiAssetPackage>,
    pub root_fundings: Vec<RootFundingCollection>,
    pub invoices: Vec<ArchiveInvoice>,
    pub completed_flows: Vec<ArchiveFlow>,
    pub events: Vec<ArchiveEvent>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreArchiveRequest {
    pub state: StateArchive,
    pub confirmation_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchivePeer {
    pub pubkey: String,
    pub alias: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveBalance {
    pub asset: AssetRequest,
    pub local: String,
    pub remote: String,
    pub pending: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveChannel {
    pub channel_id: String,
    pub counterparty_pubkey: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub funding_epoch: u64,
    pub funding_context_id: String,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub state_number: u64,
    pub phase: ArchivePhase,
    pub balances: Vec<ArchiveBalance>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub sponsor_budget: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveFactory {
    pub factory_id: String,
    pub participant_pubkeys: Vec<String>,
    #[serde(with = "mutation::decimal")]
    #[schemars(schema_with = "mutation::decimal::schema")]
    pub update_number: u64,
    pub reserve_balances: Vec<ArchiveBalance>,
    pub materialised_child_channels: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInvoice {
    pub encoded_invoice: String,
    pub status: ArchiveInvoiceStatus,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub received_at_unix: Option<u64>,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub paid_at_unix: Option<u64>,
    #[serde(with = "mutation::optional_decimal")]
    #[schemars(schema_with = "mutation::optional_decimal::schema")]
    pub cancelled_at_unix: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveEvent {
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
}
