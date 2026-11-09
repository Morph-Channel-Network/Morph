//! CLI entry points and baseline regression tests reuse the sole public Rust package implementation.
#[allow(unused_imports)]
pub use morph_packages::multi_asset_packages::*;

#[cfg(test)]
#[allow(unused_imports)]
use crate::persistence::sync_recovery_directories;

#[cfg(test)]
#[allow(unused_imports)]
use std::fs::File;

#[cfg(test)]
#[allow(unused_imports)]
use std::io::Read;

#[cfg(test)]
#[allow(unused_imports)]
use std::path::Path;

#[cfg(test)]
#[allow(unused_imports)]
use anyhow::{Context, Result, anyhow, ensure};

#[cfg(test)]
#[allow(unused_imports)]
use ckb_types::{
    core::{DepType, ScriptHashType},
    packed::{CellDep, OutPoint, Script},
    prelude::*,
};

#[cfg(test)]
#[allow(unused_imports)]
use k256::ecdsa::signature::hazmat::PrehashSigner;

#[cfg(test)]
#[allow(unused_imports)]
use k256::ecdsa::{Signature, SigningKey};

#[cfg(test)]
#[allow(unused_imports)]
use morph_core::*;

#[cfg(test)]
#[allow(unused_imports)]
use morph_script_common::multi_asset as wire;

#[cfg(test)]
#[allow(unused_imports)]
use morph_script_common::{BILATERAL_SIGNATURE_WITNESS_LEN, BilateralSignatureWitness};

#[cfg(test)]
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_json_cannot_admit_settling_zero_or_plain_vote_root_creation() {
        let original = fixture_package().unwrap();
        for root in [false, true] {
            let mut recovery = original.recovery().unwrap();
            recovery.state.header.state_number = 0;
            if root {
                recovery.state.header.phase = Phase::Active;
                recovery.state.vault_outpoint_set_root = [0; 32];
                recovery.outpoints.clear();
            }
            let digest = recovery.state.signing_digest().unwrap();
            recovery.authorization.signatures = [1u8, 2]
                .into_iter()
                .map(|seed| {
                    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                    let signature: Signature = key.sign_prehash(&digest).unwrap();
                    ParticipantSignature {
                        pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                        signature: signature.to_bytes().to_vec(),
                    }
                })
                .collect();
            recovery
                .authorization
                .signatures
                .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
            let mut encoded = original.clone();
            encoded.header_hex = canonical_hex(&recovery.state.encode().unwrap());
            encoded.witness_hex = canonical_hex(
                &encode_multi_asset_witness(
                    &recovery.manifest,
                    &recovery.settlement,
                    &recovery.outpoints,
                    &recovery.scripts,
                )
                .unwrap(),
            );
            encoded.signature_witness_hex =
                canonical_hex(&encode_multi_asset_signatures(&recovery.authorization).unwrap());
            let raw_header = decode_hex(&encoded.header_hex, 318).unwrap();
            let header = wire::MultiAssetStateHeader::parse(&raw_header).unwrap();
            // These are genuine normal-domain signatures. Their mathematical
            // validity cannot substitute for the required lifecycle/domain.
            header
                .verify_signatures(
                    &BilateralSignatureWitness::parse(
                        &decode_hex(&encoded.signature_witness_hex, 198).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
            let error = encoded.validate().unwrap_err().to_string();
            assert!(
                error.contains(if root {
                    "transaction-bound"
                } else {
                    "positive state number"
                }),
                "{error}"
            );
            assert!(encoded.recovery().is_err());
        }
    }
    #[test]
    fn multi_asset_package_keeps_u128_values_lossless() {
        let package = fixture_package().unwrap();
        let summary = package.validate().unwrap();
        assert_eq!(summary.assets[0].amount, (u128::MAX / 2).to_string());
        let raw = serde_json::to_string(&package).unwrap();
        let restored: StoredMultiAssetPackage = serde_json::from_str(&raw).unwrap();
        assert_eq!(restored.validate().unwrap(), summary);
        let shared: StoredMultiAssetPackage =
            serde_json::from_str(include_str!("../../../fixtures/protocol/multi-asset.json"))
                .unwrap();
        assert_eq!(
            shared, package,
            "Rust and TypeScript must share the canonical signed fixture"
        );
        assert_eq!(
            serde_json::to_value(summary).unwrap(),
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../fixtures/protocol/multi-asset-summary.json"
            ))
            .unwrap()
        );
    }
    #[test]
    fn multi_asset_package_rejects_noncanonical_and_unsupported_evidence() {
        let package = fixture_package().unwrap();
        for mutation in 0..9 {
            let mut package = package.clone();
            match mutation {
                0 => package.schema.push('x'),
                1 => package.state_carrier_capacity.insert(0, '0'),
                2 => package.signature_witness_hex.push_str("00"),
                3 => package.witness_hex.replace_range(12..14, "FF"),
                4 => package.state_carrier_capacity = "1".to_string(),
                5 => package.cell_deps.clear(),
                6 => package.cell_deps.push(package.cell_deps[0].clone()),
                7 => package.cell_deps[0].dep_type = "unknown".to_string(),
                _ => package.cell_deps[0].tx_hash = format!("0x{}", "00".repeat(32)),
            }
            assert!(package.validate().is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn multi_asset_recovery_store_is_durable_idempotent_and_private() {
        let dir = std::env::temp_dir().join(format!(
            "morph-multi-asset-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let package = fixture_package().unwrap();
        let path = write_package(&dir, &package).unwrap();
        assert_eq!(read_package(&path).unwrap(), package);
        assert_eq!(write_package(&dir, &package).unwrap(), path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            for parent in path.parent().unwrap().ancestors() {
                assert_eq!(
                    std::fs::metadata(parent).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                if parent == dir {
                    break;
                }
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(write_package(&dir, &package).is_err());
            assert_eq!(read_package(&path).unwrap(), package);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(write_package(&dir, &package).unwrap(), path);
        }
        let mut changed = package.clone();
        changed.state_carrier_capacity = "200000000000".to_string();
        changed.validate().unwrap();
        assert!(write_package(&dir, &changed).is_err());
        assert_eq!(read_package(&path).unwrap(), package);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
