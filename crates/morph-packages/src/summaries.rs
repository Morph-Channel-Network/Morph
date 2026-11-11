use crate::multi_asset_packages::canonical_hex;
use morph_core::{MultiAssetSettlement, MultiAssetValue, VaultAsset};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValueSummary {
    /// Reserved CKB shannons, canonical decimal.
    pub reserve: String,
    /// Business CKB shannons, canonical decimal.
    pub business_ckb: String,
    /// Token base units, canonical decimal; zero for CKB.
    pub amount: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PayoutSummary {
    pub type_hash: Option<String>,
    pub allocations: [ValueSummary; 2],
}
pub fn asset_summary(asset: &VaultAsset) -> Option<String> {
    match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(hash) => Some(canonical_hex(hash)),
    }
}
pub fn value_summary(value: MultiAssetValue) -> ValueSummary {
    ValueSummary {
        reserve: value.reserve.to_string(),
        business_ckb: value.business_ckb.to_string(),
        amount: value.amount.to_string(),
    }
}
pub fn payout_summary(settlement: &MultiAssetSettlement) -> Vec<PayoutSummary> {
    settlement
        .payouts
        .iter()
        .map(|payout| PayoutSummary {
            type_hash: asset_summary(&payout.asset),
            allocations: payout.values.map(value_summary),
        })
        .collect()
}
