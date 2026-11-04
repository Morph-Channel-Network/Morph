//! Immutable local provenance for a child created by current Factory authority.
//! The public parent proof never contains a child's publishable exit signatures.
use crate::factory_packets::StoredFactoryRequest;
use crate::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex, decode_hex};
use anyhow::{Result, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::{FactorySigningRequest, MultiAssetRecoveryPackage, blake2b256};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(crate) const MAX_ORIGIN_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const SCHEMA: &str = "morph.factory_child_origin.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryChildOrigin {
    pub schema: String,
    pub request: StoredFactoryRequest,
    pub transaction_hex: String,
    pub child_index: u16,
    pub initial_recovery: StoredMultiAssetPackage,
}

impl FactoryChildOrigin {
    pub(crate) fn decode(
        &self,
    ) -> Result<(
        FactorySigningRequest,
        packed::Transaction,
        MultiAssetRecoveryPackage,
    )> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported Factory child origin schema"
        );
        let request = self.request.decode()?;
        let transaction = packed::Transaction::from_slice(&decode_hex(
            &self.transaction_hex,
            morph_core::FACTORY_MAX_TRANSACTION_BYTES,
        )?)?;
        request.verify_authorized_transaction(&transaction)?;
        let initial = self.initial_recovery.recovery()?;
        request.verify_child_recovery(self.child_index, &initial)?;
        ensure!(
            StoredMultiAssetPackage::from_recovery(
                &initial,
                &transaction
                    .raw()
                    .cell_deps()
                    .into_iter()
                    .collect::<Vec<_>>()
            )? == self.initial_recovery,
            "child recovery dependencies differ from its exact parent transaction"
        );
        Ok((request, transaction, initial))
    }
    pub(crate) fn verify_current(&self, current: &MultiAssetRecoveryPackage) -> Result<()> {
        let (_, _, initial) = self.decode()?;
        let initial_header = initial.state.encode()?;
        let current_header = current.state.encode()?;
        let initial_header =
            morph_script_common::multi_asset::MultiAssetStateHeader::parse(&initial_header)
                .map_err(|error| anyhow::anyhow!("invalid initial child State: {error:?}"))?;
        let current_header =
            morph_script_common::multi_asset::MultiAssetStateHeader::parse(&current_header)
                .map_err(|error| anyhow::anyhow!("invalid current child State: {error:?}"))?;
        ensure!(
            initial_header.same_context_except_progress(&current_header)
                && current_header.state_number() >= initial_header.state_number()
                && initial.manifest == current.manifest
                && initial.outpoints == current.outpoints
                && initial.state_carrier_capacity == current.state_carrier_capacity
                && initial.scripts.state_type == current.scripts.state_type
                && initial.scripts.state_lock == current.scripts.state_lock
                && initial.scripts.vault_lock == current.scripts.vault_lock,
            "Factory origin differs from active child custody"
        );
        Ok(())
    }
}

pub(crate) fn read(path: &Path, expected_hash: &str) -> Result<FactoryChildOrigin> {
    use std::io::Read;
    ensure!(
        path.is_absolute(),
        "Factory child origin path must be absolute"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_ORIGIN_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_ORIGIN_BYTES,
        "Factory child origin exceeds byte bound"
    );
    ensure!(
        canonical_hex(&blake2b256(&bytes)) == expected_hash,
        "Factory child origin content hash mismatch"
    );
    let origin: FactoryChildOrigin = serde_json::from_slice(&bytes)?;
    origin.decode()?;
    Ok(origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use morph_core::FactoryChildDeliveryReceipt;

    fn fixture() -> FactoryChildOrigin {
        let (mut request, _, _, children) = crate::factory_journal_fixture::reduced_child_request();
        for (index, child) in children.iter().enumerate() {
            for seed in 1u8..=2 {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                request.deliveries.push(
                    FactoryChildDeliveryReceipt::new_signed(&request, index as u16, child, &key)
                        .unwrap(),
                );
            }
        }
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/factory-transitions.json"
        ))
        .unwrap();
        let case = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["operation"] == "ReducedChild")
            .unwrap();
        let transaction_hex = case["package"]["transaction_hex"]
            .as_str()
            .unwrap()
            .to_string();
        let tx = packed::Transaction::from_slice(
            &decode_hex(&transaction_hex, morph_core::FACTORY_MAX_TRANSACTION_BYTES).unwrap(),
        )
        .unwrap();
        FactoryChildOrigin {
            schema: SCHEMA.to_string(),
            request: StoredFactoryRequest::from_core(&request).unwrap(),
            transaction_hex,
            child_index: 0,
            initial_recovery: StoredMultiAssetPackage::from_recovery(
                &children[0],
                &tx.raw().cell_deps().into_iter().collect::<Vec<_>>(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn child_origin_binds_private_exit_to_exact_authorized_parent_and_context() {
        let origin = fixture();
        let (_, _, initial) = origin.decode().unwrap();
        origin.verify_current(&initial).unwrap();
        let mut wrong = initial.clone();
        wrong.state.header.funding_epoch += 1;
        assert!(origin.verify_current(&wrong).is_err());
        let mut value = serde_json::to_value(&origin).unwrap();
        value["child_index"] = serde_json::json!(4);
        assert!(
            serde_json::from_value::<FactoryChildOrigin>(value)
                .unwrap()
                .decode()
                .is_err()
        );
        let mut value = serde_json::to_value(&origin).unwrap();
        value["request"]["deliveries"] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<FactoryChildOrigin>(value)
                .unwrap()
                .decode()
                .is_err()
        );
        let mut value = serde_json::to_value(&origin).unwrap();
        value["transaction_hex"] =
            serde_json::json!(canonical_hex(packed::Transaction::default().as_slice()));
        assert!(
            serde_json::from_value::<FactoryChildOrigin>(value)
                .unwrap()
                .decode()
                .is_err()
        );
        let mut value = serde_json::to_value(&origin).unwrap();
        value["initial_recovery"]
            .as_object_mut()
            .unwrap()
            .remove("signature_witness_hex");
        assert!(serde_json::from_value::<FactoryChildOrigin>(value).is_err());
    }

    #[test]
    fn child_origin_archive_rejects_tampering_and_cannot_replace_active_authority() {
        let origin = fixture();
        let bytes = serde_json::to_vec(&origin).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "morph-child-origin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("origin.json");
        crate::persistence::write_private_immutable(&path, &bytes).unwrap();
        let hash = canonical_hex(&blake2b256(&bytes));
        read(&path, &hash).unwrap();
        assert!(read(&path, &canonical_hex(&[0; 32])).is_err());
        assert!(crate::persistence::write_private_immutable(&path, b"{}").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
