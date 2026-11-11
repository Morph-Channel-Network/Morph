//! Public review of a validated capability. Exact evidence remains in its signed package.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilitySummary {
    Ordinary {},
    CkbConditional(Box<ConditionalCapabilitySummary>),
}
impl CapabilitySummary {
    pub fn conditional(&self) -> Option<&ConditionalCapabilitySummary> {
        match self {
            Self::Ordinary {} => None,
            Self::CkbConditional(value) => Some(value),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalCapabilitySummary {
    pub batch_code_hash: String,
    pub batch_hash_type: u8,
    pub batch_id: String,
    pub application_context_commitment: String,
    /// CKB shannons, canonical decimal.
    pub pending_ckb: String,
    pub batch_lock_hash: String,
    /// CKB shannons for participants 0 and 1.
    pub settled_capacities: [String; 2],
    pub transfers: Vec<ConditionalTransferSummary>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalTransferSummary {
    pub transfer_id: String,
    pub payer_lock_hash: String,
    pub payee_lock_hash: String,
    pub hash_algorithm: HashAlgorithmSummary,
    pub payment_hash: String,
    /// CKB shannons, canonical decimal.
    pub amount: String,
    /// Canonical decimal absolute block height.
    pub refund_after_block: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithmSummary {
    CkbBlake2b,
    Sha256,
}
