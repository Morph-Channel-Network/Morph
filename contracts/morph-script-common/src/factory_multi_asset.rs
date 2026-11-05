//! Complete Factory reserve partitioning. This module does not dispatch a
//! spending witness; Factory execution must additionally authenticate the
//! source State, consume its complete custody set and verify actual outputs.
use crate::multi_asset::{MultiAssetAllocation, MultiAssetId, MultiAssetVaultManifest};
use crate::{Result, ScriptError};

pub const FACTORY_MULTI_ASSET_MAX_CHILDREN: usize = 4;
pub const FACTORY_MULTI_ASSET_MAX_OUTPUTS: usize = 64;

fn mismatch<T>() -> Result<T> {
    Err(ScriptError::FactoryMultiAssetPartitionMismatch)
}

/// CKB lanes are global across physical Vault types. Token quantities never
/// enter this aggregate: Type identity is a token domain, not a CKB domain.
fn factory_manifest_ckb(manifest: &MultiAssetVaultManifest) -> Result<MultiAssetAllocation> {
    let mut sum = MultiAssetAllocation::default();
    for i in 0..manifest.count() {
        sum = factory_add_ckb(sum, manifest.entry(i)?.allocation)?;
    }
    Ok(sum)
}
fn factory_add_ckb(
    left: MultiAssetAllocation,
    right: MultiAssetAllocation,
) -> Result<MultiAssetAllocation> {
    let value = MultiAssetAllocation {
        reserve: left
            .reserve
            .checked_add(right.reserve)
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?,
        business_ckb: left
            .business_ckb
            .checked_add(right.business_ckb)
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?,
        amount: 0,
    };
    value.capacity()?;
    Ok(value)
}

fn value_for(
    manifest: &MultiAssetVaultManifest,
    asset: MultiAssetId,
) -> Result<MultiAssetAllocation> {
    for i in 0..manifest.count() {
        let entry = manifest.entry(i)?;
        if entry.asset == asset {
            return Ok(entry.allocation);
        }
    }
    Ok(MultiAssetAllocation::default())
}

/// Preserve global reserve/business CKB lanes and each Type token quantity.
/// CKB can move between typed and plain Vaults without becoming a new asset. No external deposit or reserve subsidy is implicit here.
/// A missing retained manifest means the entire reserve is materialised.
/// Canonical manifest parsing has already bounded every set to 1..=8 Vaults.
pub fn validate_materialisation_partition(
    source: &MultiAssetVaultManifest,
    retained: Option<&MultiAssetVaultManifest>,
    children: &[MultiAssetVaultManifest],
) -> Result<()> {
    if !(1..=FACTORY_MULTI_ASSET_MAX_CHILDREN).contains(&children.len()) {
        return mismatch();
    }
    let source_lock = source.entry(0)?.lock_hash;
    let mut outputs = 0usize;
    if let Some(retained) = retained {
        if retained.entry(0)?.lock_hash != source_lock {
            return mismatch();
        }
        outputs += 1 + retained.count(); // Factory State and retained Vaults.
    }
    for (index, child) in children.iter().enumerate() {
        let lock = child.entry(0)?.lock_hash;
        if lock == source_lock {
            return mismatch();
        }
        for previous in &children[..index] {
            if previous.entry(0)?.lock_hash == lock {
                return mismatch();
            }
        }
        outputs += 1 + child.count(); // Child State and its complete Vault set.
    }
    if outputs > FACTORY_MULTI_ASSET_MAX_OUTPUTS {
        return mismatch();
    }
    let mut output_ckb = MultiAssetAllocation::default();
    for manifest in retained.into_iter().chain(children.iter()) {
        output_ckb = factory_add_ckb(output_ckb, factory_manifest_ckb(manifest)?)?;
        for i in 0..manifest.count() {
            let entry = manifest.entry(i)?;
            if entry.asset.kind == 1 && value_for(source, entry.asset)?.amount == 0 {
                return mismatch();
            }
        }
    }
    if output_ckb != factory_manifest_ckb(source)? {
        return mismatch();
    }
    for i in 0..source.count() {
        let entry = source.entry(i)?;
        if entry.asset.kind == 0 {
            continue;
        }
        let mut amount = 0u128;
        for manifest in retained.into_iter().chain(children.iter()) {
            amount = amount
                .checked_add(value_for(manifest, entry.asset)?.amount)
                .ok_or(ScriptError::MultiAssetConservationMismatch)?;
        }
        if amount != entry.allocation.amount {
            return mismatch();
        }
    }
    Ok(())
}

pub const FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN: &[u8] =
    b"CKB_MORPH_FACTORY_MULTI_ASSET_MATERIALISATION_V1";

pub fn materialisation_commitment(intent: &[u8]) -> [u8; 32] {
    crate::blake2b256(&[FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN, intent])
}

mod materialisation;
mod reduced;
mod state;
pub use materialisation::*;
pub use reduced::*;
pub use state::*;
