//! Lossless public Factory planning packages. No signer keys, journal mutation,
//! RPC calls or transaction submission are part of this verifier.
use anyhow::{Result, ensure};
use morph_core::*;
use morph_script_common::{FactorySignatureWitness, multi_asset as wire};
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::{
    StoredMultiAssetPackage, canonical_hex, decode_hex, read_bounded_json,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPoint {
    tx_hash: String,
    index: u32,
}
impl StoredPoint {
    fn decode(&self) -> Result<MultiAssetOutPoint> {
        Ok(MultiAssetOutPoint {
            tx_hash: bytes32(&self.tx_hash)?,
            index: self.index,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredChild {
    state_output_index: u32,
    recovery_package: StoredMultiAssetPackage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMaterialisation {
    schema: String,
    chain_id: String,
    factory_id: String,
    old_state: StoredPoint,
    transaction_hash: String,
    source_manifest_hex: String,
    source_outpoints: Vec<StoredPoint>,
    factory_vault_lock_hex: String,
    type_scripts_hex: Vec<String>,
    retained_manifest_hex: String,
    factory_carrier_capacity: String,
    external_carrier_contribution: String,
    carrier_refund_lock_hex: String,
    children: Vec<StoredChild>,
    factory_participants_commitment: String,
    factory_signature_witness_hex: String,
}
fn bytes32(raw: &str) -> Result<Bytes32> {
    let bytes = decode_hex(raw, 32)?;
    ensure!(bytes.len() == 32, "expected bytes32");
    let mut value = [0; 32];
    value.copy_from_slice(&bytes);
    Ok(value)
}
fn decimal(raw: &str) -> Result<u64> {
    let value = raw.parse::<u64>()?;
    ensure!(
        value.to_string() == raw,
        "capacity must be canonical decimal"
    );
    Ok(value)
}
impl StoredMaterialisation {
    fn decode(&self) -> Result<FactoryMultiAssetMaterialisation> {
        ensure!(
            self.schema == "morph.factory_multi_asset_materialisation.v1",
            "unsupported Factory materialisation schema"
        );
        ensure!(
            self.source_outpoints.len() <= 8
                && self.type_scripts_hex.len() <= 8
                && (1..=4).contains(&self.children.len()),
            "Factory plan exceeds count bounds"
        );
        let decode_manifest = |raw: &str| -> Result<MultiAssetManifest> {
            Ok(MultiAssetManifest::decode(&decode_hex(raw, 4 + 8 * 97)?)?)
        };
        let retained = if self.retained_manifest_hex == "0x" {
            None
        } else {
            Some(decode_manifest(&self.retained_manifest_hex)?)
        };
        let plan = FactoryMultiAssetMaterialisation {
            chain_id: bytes32(&self.chain_id)?,
            factory_id: bytes32(&self.factory_id)?,
            participants_commitment: bytes32(&self.factory_participants_commitment)?,
            old_state: self.old_state.decode()?,
            transaction_hash: bytes32(&self.transaction_hash)?,
            source: decode_manifest(&self.source_manifest_hex)?,
            source_outpoints: self
                .source_outpoints
                .iter()
                .map(StoredPoint::decode)
                .collect::<Result<_>>()?,
            factory_vault_lock: decode_hex(
                &self.factory_vault_lock_hex,
                wire::MULTI_ASSET_MAX_SCRIPT_LEN,
            )?,
            type_scripts: self
                .type_scripts_hex
                .iter()
                .map(|raw| -> Result<_> {
                    let script = decode_hex(raw, wire::MULTI_ASSET_MAX_SCRIPT_LEN)?;
                    Ok(MultiAssetTypeScript {
                        type_hash: blake2b256(&script),
                        script,
                    })
                })
                .collect::<Result<_>>()?,
            retained,
            factory_carrier_capacity: decimal(&self.factory_carrier_capacity)?,
            external_carrier_contribution: decimal(&self.external_carrier_contribution)?,
            carrier_refund_lock: decode_hex(
                &self.carrier_refund_lock_hex,
                wire::MULTI_ASSET_MAX_SCRIPT_LEN,
            )?,
            children: self
                .children
                .iter()
                .map(|child| -> Result<_> {
                    Ok(FactoryMultiAssetChild {
                        state_output_index: child.state_output_index,
                        recovery: child.recovery_package.recovery()?,
                    })
                })
                .collect::<Result<_>>()?,
        };
        plan.validate_contents()?;
        Ok(plan)
    }
    fn summary(&self) -> Result<serde_json::Value> {
        let plan = self.decode()?;
        let raw = decode_hex(&self.factory_signature_witness_hex, 4 + 16 * 129)?;
        let witness = FactorySignatureWitness::parse(&raw)
            .map_err(|error| anyhow::anyhow!("invalid Factory signatures: {error:?}"))?;
        let authorization = (0..witness.count() as usize)
            .map(|i| {
                let mut participant = [0; 32];
                participant.copy_from_slice(witness.participant(i));
                FactoryParticipantSignature {
                    participant,
                    pubkey_sec1: witness.pubkey(i).to_vec(),
                    signature: witness.signature(i).to_vec(),
                }
            })
            .collect::<Vec<_>>();
        plan.verify_authorization(
            &bytes32(&self.factory_participants_commitment)?,
            &authorization,
        )?;
        let children=self.children.iter().zip(&plan.children).map(|(stored,child)|->Result<_>{Ok(serde_json::json!({"state_output_index":child.state_output_index,"recovery":stored.recovery_package.validate()?,"payouts":crate::multi_asset_session::payout_summary(&child.recovery.settlement)}))}).collect::<Result<Vec<_>>>()?;
        let assets = |manifest: &MultiAssetManifest| {
            manifest.vaults.iter().map(|vault|serde_json::json!({"type_hash":match vault.asset{VaultAsset::Ckb=>None,VaultAsset::Xudt(hash)=>Some(canonical_hex(&hash))},"reserve":vault.value.reserve.to_string(),"business_ckb":vault.value.business_ckb.to_string(),"amount":vault.value.amount.to_string()})).collect::<Vec<_>>()
        };
        Ok(
            serde_json::json!({"schema":"morph.factory_multi_asset_materialisation_summary.v1","stage":"offline_plan","chain_id":self.chain_id,"factory_id":self.factory_id,"old_state":self.old_state,"transaction_hash":self.transaction_hash,"signing_digest":canonical_hex(&plan.signing_digest()?),"source_content_root":canonical_hex(&plan.source.commitment()?),"source_outpoint_root":canonical_hex(&multi_asset_outpoint_commitment(&plan.source,&plan.source_outpoints)?),"retained_content_root":plan.retained.as_ref().map(MultiAssetManifest::commitment).transpose()?.map(|hash|canonical_hex(&hash)),"source_assets":assets(&plan.source),"retained_assets":plan.retained.as_ref().map(assets).unwrap_or_default(),"factory_carrier_capacity":self.factory_carrier_capacity,"external_carrier_contribution":self.external_carrier_contribution,"factory_participants_commitment":self.factory_participants_commitment,"factory_participant_count":witness.count(),"children":children}),
        )
    }
}
pub fn validate(path: &std::path::Path) -> Result<serde_json::Value> {
    let stored: StoredMaterialisation = read_bounded_json(path, 512 * 1024)?;
    stored.summary()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_types::{packed, prelude::*};
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    fn fixture() -> StoredMaterialisation {
        let root = crate::multi_asset_funding::root_collection_tests::fixture();
        let recovery_package: StoredMultiAssetPackage =
            serde_json::from_value(root["funding"]["recovery_package"].clone()).unwrap();
        let mut recovery = recovery_package.recovery().unwrap();
        let old_type = packed::Script::from_slice(&recovery.scripts.state_type).unwrap();
        let old_args = old_type.args().raw_data();
        let mut args = old_args[..32].to_vec();
        args.extend_from_slice(&[99; 32]);
        args.extend_from_slice(&old_args[32..]);
        let ty = old_type
            .as_builder()
            .args(ckb_types::bytes::Bytes::from(args).pack())
            .build();
        let lock = packed::Script::from_slice(&recovery.scripts.state_lock)
            .unwrap()
            .as_builder()
            .args(ckb_types::bytes::Bytes::from(ty.calc_script_hash().as_slice().to_vec()).pack())
            .build();
        let since = u64::from_le_bytes(old_args[32..].try_into().unwrap());
        let vault_args = wire::encode_multi_asset_vault_args(
            &recovery.state.header.funding_anchor,
            since,
            &ty.calc_script_hash().unpack(),
            &lock.calc_script_hash().unpack(),
        )
        .unwrap();
        let vault = packed::Script::from_slice(&recovery.scripts.vault_lock)
            .unwrap()
            .as_builder()
            .args(ckb_types::bytes::Bytes::from(vault_args.to_vec()).pack())
            .build();
        recovery.scripts.state_type = ty.as_slice().to_vec();
        recovery.scripts.state_lock = lock.as_slice().to_vec();
        recovery.scripts.vault_lock = vault.as_slice().to_vec();
        for entry in &mut recovery.manifest.vaults {
            entry.lock_hash = blake2b256(vault.as_slice());
        }
        recovery.state.vault_content_set_root = recovery.manifest.commitment().unwrap();
        recovery.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
        let digest = recovery.state.signing_digest().unwrap();
        let participants = root["draft"]["participants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        recovery.authorization = StateAuthorization {
            threshold: 2,
            signatures: crate::multi_asset_funding::root_collection_tests::signed_receipts(&digest)
                .iter()
                .map(|receipt| {
                    receipt
                        .verify(&digest, &[participants[0].clone(), participants[1].clone()])
                        .unwrap()
                })
                .collect(),
        };
        let recovery_package = StoredMultiAssetPackage::from_recovery(
            &recovery,
            &crate::multi_asset_packages::decode_dependency_records(&recovery_package.cell_deps)
                .unwrap(),
        )
        .unwrap();
        let transaction = packed::Transaction::from_slice(
            &decode_hex(
                root["draft"]["transaction_hex"].as_str().unwrap(),
                256 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let input = transaction.raw().inputs().get(0).unwrap().previous_output();
        let state_index = transaction
            .raw()
            .outputs_data()
            .into_iter()
            .position(|data| data.raw_data().len() == 318)
            .unwrap() as u32;
        let factory_id = [51u8; 32];
        let mut args = factory_id.to_vec();
        args.extend_from_slice(&[99; 32]);
        let factory_lock = packed::Script::new_builder()
            .code_hash([6u8; 32].pack())
            .hash_type(ckb_types::core::ScriptHashType::Data1)
            .args(ckb_types::bytes::Bytes::from(args).pack())
            .build();
        let mut source = recovery.manifest.clone();
        for vault in &mut source.vaults {
            vault.lock_hash = blake2b256(factory_lock.as_slice());
        }
        let mut stored = StoredMaterialisation {
            schema: "morph.factory_multi_asset_materialisation.v1".to_string(),
            chain_id: canonical_hex(&recovery.state.header.chain_id),
            factory_id: canonical_hex(&factory_id),
            old_state: StoredPoint {
                tx_hash: canonical_hex(input.tx_hash().as_slice()),
                index: input.index().unpack(),
            },
            transaction_hash: root["inspection"]["transaction_hash"]
                .as_str()
                .unwrap()
                .to_string(),
            source_manifest_hex: canonical_hex(&source.encode().unwrap()),
            source_outpoints: (0..source.vaults.len())
                .map(|i| StoredPoint {
                    tx_hash: canonical_hex(&[40; 32]),
                    index: i as u32 + 1,
                })
                .collect(),
            factory_vault_lock_hex: canonical_hex(factory_lock.as_slice()),
            type_scripts_hex: recovery
                .scripts
                .type_scripts
                .iter()
                .map(|entry| canonical_hex(&entry.script))
                .collect(),
            retained_manifest_hex: "0x".to_string(),
            factory_carrier_capacity: recovery.state_carrier_capacity.to_string(),
            external_carrier_contribution: recovery.state_carrier_capacity.to_string(),
            carrier_refund_lock_hex: canonical_hex(&recovery.scripts.carrier_refund_lock),
            children: vec![StoredChild {
                state_output_index: state_index,
                recovery_package,
            }],
            factory_participants_commitment: String::new(),
            factory_signature_witness_hex: String::new(),
        };
        let mut raw = vec![1, 0, 2, 2];
        for seed in [1u8, 2] {
            let key = SigningKey::from_slice(&[seed; 32]).unwrap();
            raw.extend_from_slice(&[seed; 32]);
            raw.extend_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
            raw.extend_from_slice(&[0; 64]);
        }
        stored.factory_participants_commitment = canonical_hex(
            &FactorySignatureWitness::parse(&raw)
                .unwrap()
                .participants_commitment(),
        );
        let digest = stored.decode().unwrap().signing_digest().unwrap();
        for (i, seed) in [1u8, 2].into_iter().enumerate() {
            let key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let signature: Signature = key.sign_prehash(&digest).unwrap();
            raw[4 + i * 129 + 65..4 + (i + 1) * 129].copy_from_slice(&signature.to_bytes());
        }
        stored.factory_signature_witness_hex = canonical_hex(&raw);
        stored
    }
    #[test]
    fn public_factory_plan_checks_complete_authorisations_and_lossless_summary() {
        let stored = fixture();
        let summary = stored.summary().unwrap();
        assert_eq!(summary["stage"], "offline_plan");
        assert_eq!(summary["factory_participant_count"], 2);
        assert_eq!(
            summary["source_assets"][0]["amount"],
            (u128::MAX / 2).to_string()
        );
        let restored: StoredMaterialisation =
            serde_json::from_slice(&serde_json::to_vec(&stored).unwrap()).unwrap();
        assert_eq!(restored.summary().unwrap(), summary);
        let mut bad = stored.clone();
        bad.factory_id = canonical_hex(&[52; 32]);
        assert!(bad.summary().is_err());
        let mut bad = stored.clone();
        bad.source_outpoints[0].index += 100;
        assert!(bad.summary().is_err());
        let mut bad = stored.clone();
        bad.external_carrier_contribution = "0".to_string();
        assert!(bad.summary().is_err());
        let mut bad = stored.clone();
        bad.factory_carrier_capacity = "0100000000000".to_string();
        assert!(bad.summary().is_err());
        let mut bad = stored.clone();
        bad.factory_signature_witness_hex = "0x".to_string();
        assert!(bad.summary().is_err());
        for field in [
            "retained_manifest_hex",
            "factory_signature_witness_hex",
            "type_scripts_hex",
        ] {
            let mut value = serde_json::to_value(&stored).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<StoredMaterialisation>(value).is_err());
        }
        let mut value = serde_json::to_value(&stored).unwrap();
        value["backward_format"] = serde_json::json!(true);
        assert!(serde_json::from_value::<StoredMaterialisation>(value).is_err());
    }
}
