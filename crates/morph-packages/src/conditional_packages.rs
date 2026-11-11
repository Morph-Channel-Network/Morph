//! Recovery for the current State/Vault-set conditional capability. The signed
//! source package is the sole authority for Batch terms, custody and identity;
//! this package adds only a complete deterministic fulfillment/refund witness.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{
    bytes::Bytes,
    packed::{CellOutput, Script},
    prelude::*,
};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::{
    Bytes32, ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant,
    ConditionalResolution, ConditionalTransferSpec, MultiAssetSettlementCapability,
    ParticipantSignature, StateAuthorization, VaultAsset, asset_registry_commitment,
    derive_conditional_payment_hash, multi_asset_outpoint_commitment,
};
use morph_script_common::CONDITIONAL_BATCH_RESOLUTION_WITNESS_MAX_LEN;
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::{
    MultiAssetPackageSummary, StoredMultiAssetPackage, canonical_hex, decode_hex, read_bounded_json,
};

pub const CONDITIONAL_BATCH_PACKAGE_SCHEMA: &str = "morph.conditional_batch_package.v3";
pub const MAX_PACKAGE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoredConditionalBatchPackage {
    pub schema: String,
    pub source_package: StoredMultiAssetPackage,
    pub batch_id: String,
    pub resolutions: Vec<StoredConditionalResolution>,
    pub input_since: String,
    pub resolution_witness_hex: String,
    pub resolved_values: [StoredConditionalValue; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoredConditionalResolution {
    Fulfill {
        transfer_id: String,
        preimage: String,
    },
    Refund {
        transfer_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ConditionalBatchPackageSummary {
    pub schema: String,
    pub source: MultiAssetPackageSummary,
    pub batch_id: String,
    pub batch_lock_hash: String,
    pub transfer_count: usize,
    pub asset: crate::capability_summary::ConditionalAssetSummary,
    pub total_capacity: String,
    pub total_amount: String,
    pub descriptor_commitment: String,
    pub input_since: String,
    pub resolved_values: [StoredConditionalValue; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoredConditionalValue {
    pub capacity: String,
    pub amount: String,
}

pub struct BatchSettlementCells {
    pub input: (CellOutput, Bytes),
    pub outputs: Vec<(CellOutput, Bytes)>,
}
impl From<morph_core::ConditionalValue> for StoredConditionalValue {
    fn from(value: morph_core::ConditionalValue) -> Self {
        Self {
            capacity: value.capacity.to_string(),
            amount: value.amount.to_string(),
        }
    }
}

pub fn decimal_u128(label: &str, raw: &str) -> Result<u128> {
    let number = raw
        .parse::<u128>()
        .with_context(|| format!("invalid {label}"))?;
    ensure!(
        number.to_string() == raw,
        "{label} must be canonical unsigned decimal"
    );
    Ok(number)
}

pub fn decimal_u64(label: &str, raw: &str) -> Result<u64> {
    let number = raw
        .parse::<u64>()
        .with_context(|| format!("invalid {label}"))?;
    ensure!(
        number.to_string() == raw,
        "{label} must be canonical unsigned decimal"
    );
    Ok(number)
}

impl StoredConditionalBatchPackage {
    /// Exact expected Batch and payout cells, reconstructed from authenticated
    /// source terms. No live-cell, signing or publication claim is made here.
    pub fn cells(&self) -> Result<BatchSettlementCells> {
        self.validate()?;
        let recovery = self.source_package.recovery()?;
        let id = parse_hex32(&self.batch_id)?;
        let MultiAssetSettlementCapability::Conditional { batches, .. } =
            &recovery.settlement.capability
        else {
            return Err(anyhow!("source has no conditional capability"));
        };
        let batch = batches
            .iter()
            .find(|batch| batch.batch_id == id)
            .context("unknown signed Batch")?;
        let encoded = recovery.settlement.encode()?;
        let descriptor =
            morph_script_common::multi_asset::MultiAssetSettlementDescriptor::parse(&encoded)
                .map_err(|error| anyhow!("invalid descriptor: {error:?}"))?;
        let conditional = descriptor
            .conditional()
            .map_err(|error| anyhow!("invalid capability: {error:?}"))?
            .context("missing signed conditional capability")?;
        let asset = match batch.asset {
            VaultAsset::Ckb => morph_script_common::multi_asset::MultiAssetId::CKB,
            VaultAsset::Xudt(hash) => morph_script_common::multi_asset::MultiAssetId::xudt(hash),
        };
        let index = conditional
            .index_of(asset)
            .map_err(|error| anyhow!("invalid Batch asset: {error:?}"))?
            .context("Batch asset absent")?;
        let lock = Script::from_slice(
            &conditional
                .batch_script(
                    index,
                    &recovery.state.header.channel_id,
                    &recovery.state.funding_context_id()?,
                    recovery.state.header.state_number,
                )
                .map_err(|error| anyhow!("invalid Batch identity: {error:?}"))?,
        )?;
        let ty = match batch.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(Script::from_slice(
                &recovery
                    .scripts
                    .type_scripts
                    .iter()
                    .find(|script| script.type_hash == hash)
                    .context("missing exact Batch Type")?
                    .script,
            )?),
        };
        let total_amount = batch.total_amount()?;
        let data = if ty.is_some() {
            Bytes::from(total_amount.to_le_bytes().to_vec())
        } else {
            Bytes::new()
        };
        let input = (
            CellOutput::new_builder()
                .capacity(batch.total_capacity()?)
                .lock(lock)
                .type_(ty.clone().pack())
                .build(),
            data,
        );
        let values = batch.resolve(
            &parse_resolutions(&self.resolutions)?,
            decimal_u64("input_since", &self.input_since)?,
        )?;
        let mut outputs = Vec::new();
        for (participant, value) in values.iter().enumerate() {
            let output_type = if value.amount == 0 { None } else { ty.clone() };
            let data = if output_type.is_some() {
                Bytes::from(value.amount.to_le_bytes().to_vec())
            } else {
                Bytes::new()
            };
            outputs.push((
                CellOutput::new_builder()
                    .capacity(value.capacity)
                    .lock(Script::from_slice(
                        &recovery.scripts.participant_locks[participant],
                    )?)
                    .type_(output_type.pack())
                    .build(),
                data,
            ));
        }
        Ok(BatchSettlementCells { input, outputs })
    }

    pub fn from_source(
        source_package: StoredMultiAssetPackage,
        batch_id: Bytes32,
        resolutions: Vec<StoredConditionalResolution>,
        input_since: u64,
    ) -> Result<Self> {
        let recovery = source_package.recovery()?;
        let MultiAssetSettlementCapability::Conditional { batches, .. } =
            &recovery.settlement.capability
        else {
            return Err(anyhow!("source package has no conditional capability"));
        };
        let batch = batches
            .iter()
            .find(|batch| batch.batch_id == batch_id)
            .ok_or_else(|| anyhow!("batch_id does not select a signed Batch in this source"))?;
        let parsed = parse_resolutions(&resolutions)?;
        let package = Self {
            schema: CONDITIONAL_BATCH_PACKAGE_SCHEMA.to_string(),
            batch_id: canonical_hex(&batch_id),
            source_package,
            resolutions,
            input_since: input_since.to_string(),
            resolution_witness_hex: canonical_hex(&batch.encode_resolution_witness(&parsed)?),
            resolved_values: batch
                .resolve(&parsed, input_since)?
                .map(StoredConditionalValue::from),
        };
        package.validate()?;
        Ok(package)
    }
    pub fn validate(&self) -> Result<ConditionalBatchPackageSummary> {
        ensure!(
            self.schema == CONDITIONAL_BATCH_PACKAGE_SCHEMA,
            "unsupported conditional package schema"
        );
        let source = self.source_package.validate()?;
        ensure!(
            source.vaults_bound && source.phase == "settling",
            "conditional resolution requires a bound settling source package"
        );
        let recovery = self.source_package.recovery()?;
        let MultiAssetSettlementCapability::Conditional { batches, .. } =
            &recovery.settlement.capability
        else {
            return Err(anyhow!("source package has no conditional capability"));
        };
        let batch_id = parse_hex32(&self.batch_id)?;
        let batch = batches
            .iter()
            .find(|batch| batch.batch_id == batch_id)
            .ok_or_else(|| anyhow!("batch_id does not select a signed Batch in this source"))?;
        let resolutions = parse_resolutions(&self.resolutions)?;
        let since = decimal_u64("input_since", &self.input_since)?;
        let witness = batch.encode_resolution_witness(&resolutions)?;
        ensure!(
            decode_hex(
                &self.resolution_witness_hex,
                CONDITIONAL_BATCH_RESOLUTION_WITNESS_MAX_LEN
            )? == witness,
            "resolution_witness_hex does not match the complete canonical resolutions"
        );
        let values = batch.resolve(&resolutions, since)?;
        for (supplied, actual) in self.resolved_values.iter().zip(values) {
            ensure!(
                decimal_u64("resolved capacity", &supplied.capacity)? == actual.capacity
                    && decimal_u128("resolved token amount", &supplied.amount)? == actual.amount,
                "resolved_values do not match enforced resolution"
            );
        }
        let descriptor = batch.encode_descriptor()?;
        let descriptor_commitment =
            morph_script_common::ConditionalBatchDescriptor::parse(&descriptor)
                .map_err(|error| anyhow!("invalid Batch descriptor: {error:?}"))?
                .commitment();
        let batch_lock_hash = source
            .capability
            .conditional()
            .and_then(|value| {
                value
                    .batches
                    .iter()
                    .find(|value| value.batch_id == self.batch_id)
            })
            .map(|value| &value.batch_lock_hash)
            .ok_or_else(|| anyhow!("missing validated Batch lock identity"))?
            .to_string();
        Ok(ConditionalBatchPackageSummary {
            schema: self.schema.clone(),
            batch_id: canonical_hex(&batch.batch_id),
            batch_lock_hash,
            transfer_count: batch.transfers.len(),
            asset: match batch.asset {
                VaultAsset::Ckb => crate::capability_summary::ConditionalAssetSummary::Ckb {},
                VaultAsset::Xudt(hash) => {
                    crate::capability_summary::ConditionalAssetSummary::Xudt {
                        type_hash: canonical_hex(&hash),
                    }
                }
            },
            total_capacity: batch.total_capacity()?.to_string(),
            total_amount: batch.total_amount()?.to_string(),
            descriptor_commitment: canonical_hex(&descriptor_commitment),
            input_since: self.input_since.clone(),
            resolved_values: values.map(StoredConditionalValue::from),
            source,
        })
    }
}

pub fn read_package(path: &Path) -> Result<StoredConditionalBatchPackage> {
    let package: StoredConditionalBatchPackage = read_bounded_json(path, MAX_PACKAGE_BYTES)?;
    package.validate()?;
    Ok(package)
}

pub fn fixture_source_package() -> Result<StoredMultiAssetPackage> {
    fixture_source(false)
}

pub fn fixture_typed_source_package() -> Result<StoredMultiAssetPackage> {
    fixture_source(true)
}

fn fixture_source(typed: bool) -> Result<StoredMultiAssetPackage> {
    let original = crate::multi_asset_packages::fixture_package()?;
    let mut recovery = original.recovery()?;
    let pending = if typed {
        let large = u64::MAX as u128 + 123;
        recovery.settlement.payouts[0].values[0].amount = 2 * large;
        recovery.manifest.vaults[0].value.amount =
            2 * large + recovery.settlement.payouts[0].values[1].amount;
        recovery.settlement.payouts[0].values[0].amount -= large;
        large
    } else {
        recovery.manifest.vaults[0].asset = VaultAsset::Ckb;
        recovery.manifest.vaults[0].value.amount = 0;
        recovery.settlement.payouts[0].asset = VaultAsset::Ckb;
        for value in &mut recovery.settlement.payouts[0].values {
            value.amount = 0;
        }
        recovery.scripts.type_scripts.remove(0);
        recovery.settlement.payouts[0].values[0].business_ckb -= 2_000_000_000;
        2_000_000_000
    };
    let values = recovery.settlement.payouts[0].values;
    let batch = ConditionalBatch {
        asset: recovery.settlement.payouts[0].asset.clone(),
        batch_id: [31; 32],
        application_context_commitment: [32; 32],
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: recovery.settlement.participant_lock_hashes[0],
                settled_capacity: values[0].capacity()?,
                settled_amount: values[0].amount,
            },
            ConditionalParticipant {
                settlement_lock_hash: recovery.settlement.participant_lock_hashes[1],
                settled_capacity: values[1].capacity()?,
                settled_amount: values[1].amount,
            },
        ],
        transfers: vec![ConditionalTransferSpec {
            transfer_id: [33; 32],
            payer_lock_hash: recovery.settlement.participant_lock_hashes[0],
            hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
            payment_hash: derive_conditional_payment_hash(
                ConditionalHashAlgorithm::CkbBlake2b,
                &[34; 32],
            )?,
            amount: pending,
            refund_after_block: 500,
        }],
    };
    recovery.settlement.capability = MultiAssetSettlementCapability::Conditional {
        batch_code_hash: [35; 32],
        batch_hash_type: 2,
        batches: vec![batch],
    };
    recovery.state.header.asset_registry_commitment =
        asset_registry_commitment(&recovery.manifest.registry()?);
    recovery.state.vault_content_set_root = recovery.manifest.commitment()?;
    recovery.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints)?;
    recovery.state.header.settlement_descriptor_commitment = recovery.settlement.commitment()?;
    let digest = recovery.state.signing_digest()?;
    let mut keys = [
        SigningKey::from_slice(&[1; 32]).map_err(|_| anyhow!("invalid fixture signer"))?,
        SigningKey::from_slice(&[2; 32]).map_err(|_| anyhow!("invalid fixture signer"))?,
    ];
    keys.sort_by_key(|key| key.verifying_key().to_sec1_point(true).as_bytes().to_vec());
    recovery.authorization = StateAuthorization {
        threshold: 2,
        signatures: keys
            .iter()
            .map(|key| {
                let signature: Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| anyhow!("fixture state signing failed"))?;
                Ok(ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: signature.to_bytes().to_vec(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    recovery.validate()?;
    StoredMultiAssetPackage::from_recovery(&recovery, &original.decode()?.cell_deps)
}

pub fn fixture_package() -> Result<StoredConditionalBatchPackage> {
    fixture_resolution(fixture_source_package()?)
}

pub fn fixture_typed_package() -> Result<StoredConditionalBatchPackage> {
    fixture_resolution(fixture_typed_source_package()?)
}

fn fixture_resolution(source: StoredMultiAssetPackage) -> Result<StoredConditionalBatchPackage> {
    StoredConditionalBatchPackage::from_source(
        source,
        [31; 32],
        vec![StoredConditionalResolution::Fulfill {
            transfer_id: canonical_hex(&[33; 32]),
            preimage: canonical_hex(&[34; 32]),
        }],
        0,
    )
}

pub fn parse_resolutions(
    values: &[StoredConditionalResolution],
) -> Result<BTreeMap<Bytes32, ConditionalResolution>> {
    ensure!(
        values.len() <= morph_script_common::CONDITIONAL_TRANSFER_MAX_COUNT as usize,
        "too many conditional resolutions"
    );
    let mut resolutions = BTreeMap::new();
    let mut previous = None;
    for value in values {
        let (id, resolution) = match value {
            StoredConditionalResolution::Fulfill {
                transfer_id,
                preimage,
            } => (
                parse_hex32(transfer_id)?,
                ConditionalResolution::Fulfill {
                    preimage: parse_hex32(preimage)?,
                },
            ),
            StoredConditionalResolution::Refund { transfer_id } => {
                (parse_hex32(transfer_id)?, ConditionalResolution::Refund)
            }
        };
        ensure!(
            previous.is_none_or(|before| before < id),
            "conditional resolutions must be unique and ordered"
        );
        resolutions.insert(id, resolution);
        previous = Some(id);
    }
    Ok(resolutions)
}
pub fn parse_hex32(value: &str) -> Result<Bytes32> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("conditional identifier must contain exactly 32 bytes"))
}
