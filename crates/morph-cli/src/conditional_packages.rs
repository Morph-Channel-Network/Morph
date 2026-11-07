//! Recovery for the current State/Vault-set conditional capability. The signed
//! source package is the sole authority for Batch terms, custody and identity;
//! this package adds only a complete deterministic fulfillment/refund witness.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::{
    Bytes32, ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant,
    ConditionalResolution, ConditionalTransferSpec, MultiAssetSettlementCapability,
    ParticipantSignature, StateAuthorization, VaultAsset, asset_registry_commitment,
    derive_conditional_payment_hash, multi_asset_outpoint_commitment,
};
use morph_script_common::CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN;
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::{
    MultiAssetPackageSummary, StoredMultiAssetPackage, canonical_hex, decode_hex, read_bounded_json,
};

const CONDITIONAL_BATCH_PACKAGE_SCHEMA: &str = "morph.conditional_batch_package.v1";
const MAX_PACKAGE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredConditionalBatchPackage {
    pub schema: String,
    pub source_package: StoredMultiAssetPackage,
    pub resolutions: Vec<StoredConditionalResolution>,
    pub input_since: String,
    pub resolution_witness_hex: String,
    pub resolved_capacities: [String; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConditionalBatchPackageSummary {
    pub schema: String,
    pub source: MultiAssetPackageSummary,
    pub batch_id: String,
    pub batch_lock_hash: String,
    pub transfer_count: usize,
    pub total_capacity: String,
    pub descriptor_commitment: String,
    pub input_since: String,
    pub resolved_capacities: [String; 2],
}

fn decimal_u64(label: &str, raw: &str) -> Result<u64> {
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
    pub fn from_source(
        source_package: StoredMultiAssetPackage,
        resolutions: Vec<StoredConditionalResolution>,
        input_since: u64,
    ) -> Result<Self> {
        let recovery = source_package.recovery()?;
        let MultiAssetSettlementCapability::CkbConditional { batch, .. } =
            &recovery.settlement.capability
        else {
            return Err(anyhow!("source package has no CKB conditional capability"));
        };
        let parsed = parse_resolutions(&resolutions)?;
        let package = Self {
            schema: CONDITIONAL_BATCH_PACKAGE_SCHEMA.to_string(),
            source_package,
            resolutions,
            input_since: input_since.to_string(),
            resolution_witness_hex: canonical_hex(&batch.encode_resolution_witness(&parsed)?),
            resolved_capacities: batch
                .resolve(&parsed, input_since)?
                .map(|capacity| capacity.to_string()),
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
        let MultiAssetSettlementCapability::CkbConditional { batch, .. } =
            &recovery.settlement.capability
        else {
            return Err(anyhow!("source package has no CKB conditional capability"));
        };
        let resolutions = parse_resolutions(&self.resolutions)?;
        let since = decimal_u64("input_since", &self.input_since)?;
        let witness = batch.encode_resolution_witness(&resolutions)?;
        ensure!(
            decode_hex(
                &self.resolution_witness_hex,
                CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN
            )? == witness,
            "resolution_witness_hex does not match the complete canonical resolutions"
        );
        let capacities = batch.resolve(&resolutions, since)?;
        let supplied = [
            decimal_u64("resolved_capacities[0]", &self.resolved_capacities[0])?,
            decimal_u64("resolved_capacities[1]", &self.resolved_capacities[1])?,
        ];
        ensure!(
            supplied == capacities,
            "resolved_capacities do not match enforced resolution"
        );
        let descriptor = batch.encode_descriptor()?;
        let descriptor_commitment =
            morph_script_common::BilateralCkbConditionalDescriptor::parse(&descriptor)
                .map_err(|error| anyhow!("invalid Batch descriptor: {error:?}"))?
                .commitment();
        let batch_lock_hash = source.capability["batch_lock_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("missing validated Batch lock identity"))?
            .to_string();
        Ok(ConditionalBatchPackageSummary {
            schema: self.schema.clone(),
            batch_id: canonical_hex(&batch.batch_id),
            batch_lock_hash,
            transfer_count: batch.transfers.len(),
            total_capacity: batch.total_capacity()?.to_string(),
            descriptor_commitment: canonical_hex(&descriptor_commitment),
            input_since: self.input_since.clone(),
            resolved_capacities: capacities.map(|capacity| capacity.to_string()),
            source,
        })
    }
}

pub fn read_package(path: &Path) -> Result<StoredConditionalBatchPackage> {
    let package: StoredConditionalBatchPackage = read_bounded_json(path, MAX_PACKAGE_BYTES)?;
    package.validate()?;
    Ok(package)
}

pub(crate) fn fixture_source_package() -> Result<StoredMultiAssetPackage> {
    let original = crate::multi_asset_packages::fixture_package()?;
    let mut recovery = original.recovery()?;
    recovery.manifest.vaults[0].asset = VaultAsset::Ckb;
    recovery.manifest.vaults[0].value.amount = 0;
    recovery.settlement.payouts[0].asset = VaultAsset::Ckb;
    for value in &mut recovery.settlement.payouts[0].values {
        value.amount = 0;
    }
    recovery.scripts.type_scripts.remove(0);
    recovery.settlement.payouts[0].values[0].business_ckb -= 2_000_000_000;
    let values = recovery.settlement.payouts[0].values;
    let batch = ConditionalBatch {
        batch_id: [31; 32],
        application_context_commitment: [32; 32],
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: recovery.settlement.participant_lock_hashes[0],
                settled_capacity: values[0].capacity()?,
            },
            ConditionalParticipant {
                settlement_lock_hash: recovery.settlement.participant_lock_hashes[1],
                settled_capacity: values[1].capacity()?,
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
            amount: 2_000_000_000,
            refund_after_block: 500,
        }],
    };
    recovery.settlement.capability = MultiAssetSettlementCapability::CkbConditional {
        batch_code_hash: [35; 32],
        batch_hash_type: 2,
        batch: Box::new(batch),
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
    StoredConditionalBatchPackage::from_source(
        fixture_source_package()?,
        vec![StoredConditionalResolution::Fulfill {
            transfer_id: canonical_hex(&[33; 32]),
            preimage: canonical_hex(&[34; 32]),
        }],
        0,
    )
}

fn parse_resolutions(
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
fn parse_hex32(value: &str) -> Result<Bytes32> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("conditional identifier must contain exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_is_linked_to_complete_signed_current_custody() {
        let package = fixture_package().unwrap();
        let summary = package.validate().unwrap();
        assert_eq!(summary.source.capability["kind"], "ckb_conditional");
        assert_eq!(summary.transfer_count, 1);
        assert_eq!(summary.total_capacity, "50000000000");
        assert_eq!(summary.resolved_capacities, ["24000000000", "26000000000"]);
        assert_eq!(
            summary.batch_lock_hash,
            summary.source.capability["batch_lock_hash"]
        );
    }
    #[test]
    fn standalone_resolution_checks_preimages_refund_clock_and_complete_witness() {
        let source = fixture_source_package().unwrap();
        let refund = vec![StoredConditionalResolution::Refund {
            transfer_id: canonical_hex(&[33; 32]),
        }];
        assert!(
            StoredConditionalBatchPackage::from_source(source.clone(), refund.clone(), 499)
                .is_err()
        );
        let package = StoredConditionalBatchPackage::from_source(source, refund, 500).unwrap();
        assert_eq!(
            package.validate().unwrap().resolved_capacities,
            ["26000000000", "24000000000"]
        );
        let mut tampered = fixture_package().unwrap();
        tampered.resolution_witness_hex.replace_range(2..4, "ff");
        assert!(tampered.validate().is_err());
        assert!(
            StoredConditionalBatchPackage::from_source(
                fixture_source_package().unwrap(),
                vec![],
                0
            )
            .is_err()
        );
        let bad = vec![StoredConditionalResolution::Fulfill {
            transfer_id: canonical_hex(&[33; 32]),
            preimage: canonical_hex(&[36; 32]),
        }];
        assert!(
            StoredConditionalBatchPackage::from_source(fixture_source_package().unwrap(), bad, 0)
                .is_err()
        );
    }
    #[test]
    fn standalone_package_rejects_unsigned_detached_or_noncanonical_shapes() {
        let mut package = fixture_package().unwrap();
        package.source_package = crate::multi_asset_packages::fixture_package().unwrap();
        assert!(package.validate().is_err());
        let mut json = serde_json::to_value(fixture_package().unwrap()).unwrap();
        json["state_number"] = serde_json::json!(9);
        assert!(serde_json::from_value::<StoredConditionalBatchPackage>(json).is_err());
        let mut package = fixture_package().unwrap();
        package.input_since = "00".into();
        assert!(package.validate().is_err());
        let mut json = serde_json::to_value(fixture_package().unwrap()).unwrap();
        json["input_since"] = serde_json::json!(0);
        assert!(serde_json::from_value::<StoredConditionalBatchPackage>(json).is_err());
    }
}
