use crate::multi_asset_packages::canonical_hex;
use morph_core::{MultiAssetSettlement, MultiAssetValue, VaultAsset};
use serde_json::{Value, json};

pub fn asset_summary(asset: &VaultAsset) -> Option<String> {
    match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(hash) => Some(canonical_hex(hash)),
    }
}
pub fn value_summary(value: MultiAssetValue) -> Value {
    json!({"reserve":value.reserve.to_string(), "business_ckb":value.business_ckb.to_string(), "amount":value.amount.to_string()})
}
pub fn payout_summary(settlement: &MultiAssetSettlement) -> Vec<Value> {
    settlement.payouts.iter().map(|payout| json!({"type_hash":asset_summary(&payout.asset), "allocations":payout.values.map(value_summary)})).collect()
}
