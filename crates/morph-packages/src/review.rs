//! Public formatting of validated unsigned terms. These reviews never assert publishable authority.
use crate::{
    multi_asset_packages::{
        MultiAssetPackageBalance, MultiAssetPackageSummary, canonical_hex, capability_summary,
    },
    summaries::{asset_summary, payout_summary},
};
use anyhow::Result;
use morph_core::*;
use serde_json::{Value, json};

pub fn contents_summary(
    package: &MultiAssetRecoveryPackage,
    dependency_count: usize,
    participants: &[String; 2],
) -> Result<MultiAssetPackageSummary> {
    package.validate_contents()?;
    Ok(MultiAssetPackageSummary {
        package_id: canonical_hex(&package.state.signing_digest()?),
        channel_id: canonical_hex(&package.state.header.channel_id),
        funding_context_id: canonical_hex(&package.state.funding_context_id()?),
        state_number: package.state.header.state_number.to_string(),
        phase: if package.state.header.phase == Phase::Active {
            "active"
        } else {
            "settling"
        }
        .into(),
        vaults_bound: package.state.vault_outpoint_set_root != [0; 32],
        vault_count: package.manifest.vaults.len(),
        witness_bytes: encode_multi_asset_witness(
            &package.manifest,
            &package.settlement,
            &package.outpoints,
            &package.scripts,
        )?
        .len(),
        dependency_count,
        state_carrier_capacity: package.state_carrier_capacity.to_string(),
        signer_pubkeys: participants.clone(),
        capability: capability_summary(&package.settlement, &package.state)?,
        assets: package
            .manifest
            .vaults
            .iter()
            .map(|v| MultiAssetPackageBalance {
                type_hash: asset_summary(&v.asset),
                reserve: v.value.reserve.to_string(),
                business_ckb: v.value.business_ckb.to_string(),
                amount: v.value.amount.to_string(),
            })
            .collect(),
    })
}
pub fn contents_review(
    package: &MultiAssetRecoveryPackage,
    dependency_count: usize,
    participants: &[String; 2],
) -> Result<Value> {
    Ok(
        json!({"summary":contents_summary(package,dependency_count,participants)?,"participant_lock_hashes":package.settlement.participant_lock_hashes.map(|h|canonical_hex(&h)),"capability":capability_summary(&package.settlement,&package.state)?,"payouts":payout_summary(&package.settlement)}),
    )
}
