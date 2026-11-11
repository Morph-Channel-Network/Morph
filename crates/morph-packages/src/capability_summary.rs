//! Public review of a validated capability. Exact evidence remains in its signed package.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilitySummary {
    Ordinary {},
    Conditional(Box<ConditionalCapabilitySummary>),
}
impl CapabilitySummary {
    pub fn conditional(&self) -> Option<&ConditionalCapabilitySummary> {
        match self {
            Self::Ordinary {} => None,
            Self::Conditional(value) => Some(value),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalCapabilitySummary {
    pub batch_code_hash: String,
    pub batch_hash_type: u8,
    pub batches: Vec<ConditionalBatchSummary>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionalAssetSummary {
    Ckb {},
    Xudt { type_hash: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalBatchSummary {
    pub asset: ConditionalAssetSummary,
    pub batch_id: String,
    pub application_context_commitment: String,
    /// Shannons for CKB, base token units for UDT, canonical unsigned decimal.
    pub pending_amount: String,
    pub batch_lock_hash: String,
    pub settled_capacities: [String; 2],
    pub settled_amounts: [String; 2],
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
    /// Units of this Batch's exact asset, canonical unsigned decimal.
    pub amount: String,
    pub refund_after_block: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithmSummary {
    CkbBlake2b,
    Sha256,
}
