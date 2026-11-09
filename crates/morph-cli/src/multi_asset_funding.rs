//! CLI entry points and baseline regression tests reuse the sole public Rust package implementation.
#[allow(unused_imports)]
pub use morph_packages::multi_asset_funding::*;

#[cfg(test)]
#[allow(unused_imports)]
use std::collections::BTreeSet;

#[cfg(test)]
#[allow(unused_imports)]
use anyhow::{Result, anyhow, ensure};

#[cfg(test)]
#[allow(unused_imports)]
use ckb_types::{bytes::Bytes, packed, prelude::*};

#[cfg(test)]
#[allow(unused_imports)]
use morph_core::*;

#[cfg(test)]
#[allow(unused_imports)]
use morph_script_common::multi_asset as wire;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ckb_types::{bytes::Bytes, core::TransactionBuilder};
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

    fn authorize(package: &mut MultiAssetRecoveryPackage) {
        let digest = package.state.signing_digest().unwrap();
        let mut signatures = [1u8, 2]
            .into_iter()
            .map(|seed| {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                let signature: Signature = key.sign_prehash(&digest).unwrap();
                ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        package.authorization = StateAuthorization {
            threshold: 2,
            signatures,
        };
    }
    fn bind_hash(package: &mut MultiAssetRecoveryPackage, transaction: &packed::Transaction) {
        let hash = transaction.calc_tx_hash().unpack();
        for point in &mut package.outpoints {
            point.tx_hash = hash;
        }
        package.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
        authorize(package);
    }
    fn fixture() -> (MultiAssetRecoveryPackage, packed::Transaction) {
        fixture_with_admission(false)
    }
    fn fixture_with_admission(admitted: bool) -> (MultiAssetRecoveryPackage, packed::Transaction) {
        let stored = crate::multi_asset_packages::fixture_package().unwrap();
        let mut current = stored.recovery().unwrap();
        if admitted {
            current = crate::admission_channel::tests::recovery(current);
        }
        for (raw, binary) in [
            (
                &mut current.scripts.state_type,
                b"root-test-state-type".as_slice(),
            ),
            (
                &mut current.scripts.state_lock,
                b"root-test-state-lock".as_slice(),
            ),
            (
                &mut current.scripts.vault_lock,
                b"root-test-vault-lock".as_slice(),
            ),
        ] {
            *raw = script(raw)
                .unwrap()
                .as_builder()
                .code_hash(blake2b256(binary).pack())
                .hash_type(2u8)
                .build()
                .as_slice()
                .to_vec();
        }
        let input = packed::CellInput::new_builder()
            .previous_output(
                packed::OutPoint::new_builder()
                    .tx_hash([42u8; 32].pack())
                    .build(),
            )
            .build();
        let mut anchor = input.as_slice().to_vec();
        anchor.extend_from_slice(&1u64.to_le_bytes());
        let anchor = blake2b256(&anchor);
        let since = wire::MultiAssetVaultArgs::parse(&current.scripts.vault_lock[53..])
            .unwrap()
            .finalise_since();
        let mut args = anchor.to_vec();
        args.extend_from_slice(&since.to_le_bytes());
        current.scripts.state_type = script(&current.scripts.state_type)
            .unwrap()
            .as_builder()
            .args(Bytes::from(args).pack())
            .build()
            .as_slice()
            .to_vec();
        current.scripts.state_lock = script(&current.scripts.state_lock)
            .unwrap()
            .as_builder()
            .args(Bytes::from(blake2b256(&current.scripts.state_type).to_vec()).pack())
            .build()
            .as_slice()
            .to_vec();
        current.scripts.vault_lock = script(&current.scripts.vault_lock)
            .unwrap()
            .as_builder()
            .args(
                Bytes::from(
                    wire::encode_multi_asset_vault_args(
                        &anchor,
                        since,
                        &blake2b256(&current.scripts.state_type),
                        &blake2b256(&current.scripts.state_lock),
                    )
                    .unwrap()
                    .to_vec(),
                )
                .pack(),
            )
            .build()
            .as_slice()
            .to_vec();
        for vault in &mut current.manifest.vaults {
            vault.lock_hash = blake2b256(&current.scripts.vault_lock);
        }
        current.state.header.funding_anchor = anchor;
        current.state.vault_content_set_root = current.manifest.commitment().unwrap();
        let mut creation = current.clone();
        creation.state.header.phase = Phase::Active;
        creation.state.header.state_number = 0;
        creation.state.vault_outpoint_set_root = [0; 32];
        creation.outpoints.clear();
        authorize(&mut creation);
        let evidence = encode_multi_asset_witness(
            &creation.manifest,
            &creation.settlement,
            &[],
            &creation.scripts,
        )
        .unwrap();
        let witness = packed::WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&creation.authorization)
                        .unwrap()
                        .to_vec(),
                ))
                .pack(),
            )
            .output_type(Some(Bytes::from(evidence)).pack())
            .build();
        let mut tx = TransactionBuilder::default()
            .input(input)
            .set_cell_deps(stored.decode().unwrap().cell_deps)
            .output(
                packed::CellOutput::new_builder()
                    .capacity(10_000_000_000u64)
                    .lock(script(&current.scripts.participant_locks[0]).unwrap())
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .output(
                packed::CellOutput::new_builder()
                    .capacity(current.state_carrier_capacity)
                    .lock(script(&current.scripts.state_lock).unwrap())
                    .type_(Some(script(&current.scripts.state_type).unwrap()).pack())
                    .build(),
            )
            .output_data(Bytes::from(creation.state.encode().unwrap().to_vec()).pack())
            .witness(witness.as_bytes());
        // Manifest asset order intentionally differs from physical output order.
        current.outpoints.clear();
        for (index, vault) in current.manifest.vaults.iter().rev().enumerate() {
            let ty = match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => Some(
                    script(
                        &current
                            .scripts
                            .type_scripts
                            .iter()
                            .find(|entry| entry.type_hash == hash)
                            .unwrap()
                            .script,
                    )
                    .unwrap(),
                ),
            };
            let data = if ty.is_some() {
                vault.value.amount.to_le_bytes().to_vec()
            } else {
                vec![]
            };
            tx = tx
                .output(
                    packed::CellOutput::new_builder()
                        .capacity(vault.value.capacity().unwrap())
                        .lock(script(&current.scripts.vault_lock).unwrap())
                        .type_(ty.pack())
                        .build(),
                )
                .output_data(Bytes::from(data).pack());
            current.outpoints.push(MultiAssetOutPoint {
                tx_hash: [1; 32],
                index: index as u32 + 2,
            });
        }
        current.outpoints.reverse();
        // The retained exit is newer and has different payouts from creation.
        current.settlement.payouts[0].values[0].amount -= 1;
        current.settlement.payouts[0].values[1].amount += 1;
        current.state.header.settlement_descriptor_commitment =
            current.settlement.commitment().unwrap();
        let transaction = authorize_transaction(tx.build().data(), current.state_carrier_capacity);
        bind_hash(&mut current, &transaction);
        (current, transaction)
    }
    pub(crate) fn draft_fixture() -> RootFundingDraft {
        draft_fixture_with_admission(false)
    }
    pub(crate) fn admitted_draft_fixture() -> RootFundingDraft {
        draft_fixture_with_admission(true)
    }
    fn draft_fixture_with_admission(admitted: bool) -> RootFundingDraft {
        let (current, tx) = fixture_with_admission(admitted);
        let raw = tx.witnesses().get(0).unwrap().raw_data();
        let witness = packed::WitnessArgs::from_slice(&raw)
            .unwrap()
            .as_builder()
            .input_type(None::<Bytes>.pack())
            .lock(None::<Bytes>.pack())
            .build();
        let tx = tx
            .as_builder()
            .witnesses(vec![witness.as_bytes().pack()].pack())
            .build();
        RootFundingDraft {
            schema: "morph.multi_asset_root_draft.v1".to_string(),
            transaction_hex: crate::multi_asset_packages::canonical_hex(tx.as_slice()),
            participants: current
                .authorization
                .signatures
                .iter()
                .map(|signature| crate::multi_asset_packages::canonical_hex(&signature.pubkey_sec1))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        }
    }
    fn authorize_transaction(
        transaction: packed::Transaction,
        carrier: u64,
    ) -> packed::Transaction {
        let raw = transaction.witnesses().get(0).unwrap().raw_data();
        let witness = packed::WitnessArgs::from_slice(&raw).unwrap();
        let header = transaction.raw().outputs_data().get(1).unwrap().raw_data();
        let evidence = witness.output_type().to_opt().unwrap().raw_data();
        let mut creation =
            MultiAssetRecoveryPackage::decode_contents(&header, &evidence, carrier).unwrap();
        let digest = creation
            .state
            .root_funding_signing_digest(&transaction.calc_tx_hash().unpack())
            .unwrap();
        creation.authorization = StateAuthorization {
            threshold: 2,
            signatures: [1u8, 2]
                .into_iter()
                .map(|seed| {
                    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                    let signature: Signature = key.sign_prehash(&digest).unwrap();
                    ParticipantSignature {
                        pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                        signature: signature.to_bytes().to_vec(),
                    }
                })
                .collect(),
        };
        creation
            .authorization
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        let witness = witness
            .as_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&creation.authorization)
                        .unwrap()
                        .to_vec(),
                ))
                .pack(),
            )
            .build();
        transaction
            .as_builder()
            .witnesses(vec![witness.as_bytes().pack()].pack())
            .build()
    }
    #[test]
    fn root_authorization_rejects_replaced_raw_body_even_with_fresh_exit_signatures() {
        let (mut current, transaction) = fixture();
        let raw = transaction
            .raw()
            .as_builder()
            .header_deps(vec![[77u8; 32].pack()].pack())
            .build();
        let transaction = transaction.as_builder().raw(raw).build();
        bind_hash(&mut current, &transaction);
        assert!(
            validate_root_funding(&current, &transaction)
                .unwrap_err()
                .to_string()
                .contains("root funding authorization")
        );
        let transaction = authorize_transaction(transaction, current.state_carrier_capacity);
        validate_root_funding(&current, &transaction).unwrap();
    }
    #[test]
    fn root_proof_preserves_later_payouts_and_actual_state_and_vault_indices() {
        let (current, transaction) = fixture();
        assert_eq!(current.state.header.state_number, 9);
        validate_root_funding(&current, &transaction).unwrap();
        let raw = transaction.witnesses().get(0).unwrap().raw_data();
        let witness = packed::WitnessArgs::from_slice(&raw).unwrap();
        for present in [false, true] {
            let signatures = if present {
                let mut signatures = witness.input_type().to_opt().unwrap().raw_data().to_vec();
                let last = signatures.len() - 1;
                signatures[last] ^= 1;
                Some(Bytes::from(signatures))
            } else {
                None
            };
            let changed = witness
                .clone()
                .as_builder()
                .input_type(signatures.pack())
                .build();
            let tx = transaction
                .clone()
                .as_builder()
                .witnesses(vec![changed.as_bytes().pack()].pack())
                .build();
            assert!(validate_root_funding(&current, &tx).is_err());
        }
        let mut epoch = current;
        epoch.state.header.funding_epoch = 1;
        authorize(&mut epoch);
        assert!(validate_root_funding(&epoch, &transaction).is_err());
    }
    #[test]
    fn root_proof_rejects_validly_authorized_references_to_wrong_physical_custody() {
        let (current, transaction) = fixture();
        for mutation in 0..7 {
            let mut outputs = transaction.raw().outputs().into_iter().collect::<Vec<_>>();
            let mut data = transaction
                .raw()
                .outputs_data()
                .into_iter()
                .collect::<Vec<_>>();
            match mutation {
                0 => {
                    outputs[2] = outputs[2]
                        .clone()
                        .as_builder()
                        .capacity(u64::from(outputs[2].capacity()) - 1)
                        .build()
                }
                1 => {
                    outputs.push(outputs[2].clone());
                    data.push(data[2].clone());
                }
                2 => {
                    outputs.push(outputs[1].clone());
                    data.push(data[1].clone());
                }
                3 => {
                    outputs[1] = outputs[1]
                        .clone()
                        .as_builder()
                        .lock(script(&current.scripts.participant_locks[0]).unwrap())
                        .build()
                }
                4 => data[2] = Bytes::from(vec![0; 16]).pack(),
                6 => {
                    outputs.push(
                        outputs[1]
                            .clone()
                            .as_builder()
                            .type_(None::<packed::Script>.pack())
                            .build(),
                    );
                    data.push(Bytes::new().pack());
                }
                _ => {}
            }
            let raw = transaction
                .raw()
                .as_builder()
                .version(if mutation == 5 { 1u32 } else { 0u32 })
                .outputs(outputs.pack())
                .outputs_data(data.pack())
                .build();
            let tx = transaction.clone().as_builder().raw(raw).build();
            let tx = authorize_transaction(tx, current.state_carrier_capacity);
            let mut signed = current.clone();
            bind_hash(&mut signed, &tx);
            signed.validate().unwrap();
            assert!(
                validate_root_funding(&signed, &tx).is_err(),
                "mutation {mutation}"
            );
        }
        let tx = transaction
            .clone()
            .as_builder()
            .raw(
                transaction
                    .raw()
                    .as_builder()
                    .header_deps(vec![[99u8; 32].pack()].pack())
                    .build(),
            )
            .build();
        assert!(validate_root_funding(&current, &tx).is_err());
    }
}

#[cfg(test)]
pub(crate) mod root_collection_tests {
    use super::*;
    use crate::multi_asset_signatures::SignatureMessage;
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    pub(crate) fn receipts(
        draft: &RootFundingDraft,
        target: RootFundingTarget,
    ) -> Vec<SignatureMessage> {
        let digest = target.digest(draft).unwrap();
        signed_receipts(&digest)
    }
    pub(crate) fn signed_receipts(digest: &Bytes32) -> Vec<SignatureMessage> {
        let mut result = [1u8, 2]
            .into_iter()
            .map(|seed| {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                let signature: Signature = key.sign_prehash(digest).unwrap();
                SignatureMessage::new(
                    digest,
                    &ParticipantSignature {
                        pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                        signature: signature.to_bytes().to_vec(),
                    },
                )
            })
            .collect::<Vec<_>>();
        result.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        result
    }
    pub(crate) fn fixture() -> serde_json::Value {
        fixture_from_draft(super::tests::draft_fixture())
    }
    pub(crate) fn fixture_from_draft(draft: RootFundingDraft) -> serde_json::Value {
        let inspection = draft.inspection().unwrap();
        let exit = receipts(&draft, RootFundingTarget::Exit);
        let creation = receipts(&draft, RootFundingTarget::Creation);
        let collection = RootFundingCollection {
            schema: "morph.multi_asset_root_collection.v1".to_string(),
            draft: draft.clone(),
            exit_signatures: exit.clone(),
            creation_signatures: creation.clone(),
        };
        serde_json::json!({"draft":draft,"inspection":inspection,"exit_receipts":exit,"creation_receipts":creation,"funding":collection.export().unwrap(),"collection":collection})
    }
    #[test]
    fn sdk_root_fixture_matches_rust_encodings_and_both_signing_domains() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/protocol/multi-asset-root.json"
        ))
        .unwrap();
        assert_eq!(
            fixture(),
            expected,
            "Rust and SDK must share exact root bytes and signing domains"
        );
    }
    #[test]
    fn imported_root_bundle_keeps_recovery_and_rejects_invalid_authorisation() {
        let dir = std::env::temp_dir().join(format!(
            "morph-root-import-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("funding.json");
        let store = dir.join("recovery");
        let fixture = fixture();
        std::fs::write(&source, serde_json::to_vec(&fixture["funding"]).unwrap()).unwrap();
        let result = import_root_funding(&source, &store).unwrap();
        let transaction = std::path::Path::new(result["transaction"].as_str().unwrap());
        let recovery = std::path::Path::new(result["recovery_package"].as_str().unwrap());
        assert!(transaction.is_file());
        assert!(recovery.is_file());
        let package: serde_json::Value =
            serde_json::from_slice(&std::fs::read(recovery).unwrap()).unwrap();
        assert_eq!(package, fixture["funding"]["recovery_package"]);
        assert_eq!(import_root_funding(&source, &store).unwrap(), result);
        let mut invalid = fixture["funding"].clone();
        invalid["transaction_hex"] = serde_json::json!("0x00");
        std::fs::write(&source, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let rejected_store = dir.join("rejected");
        assert!(import_root_funding(&source, &rejected_store).is_err());
        assert!(!rejected_store.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn public_collection_requires_complete_exit_and_rejects_cross_role_and_duplicate_receipts() {
        let draft = super::tests::draft_fixture();
        let mut collection = RootFundingCollection::new(draft.clone()).unwrap();
        let exit = receipts(&draft, RootFundingTarget::Exit);
        let creation = receipts(&draft, RootFundingTarget::Creation);
        assert!(
            collection
                .add(RootFundingTarget::Creation, creation[0].clone())
                .is_err()
        );
        assert!(collection.creation_signatures.is_empty());
        assert!(
            collection
                .add(RootFundingTarget::Exit, creation[0].clone())
                .is_err()
        );
        assert!(
            collection
                .add(RootFundingTarget::Exit, exit[0].clone())
                .unwrap()
        );
        assert!(
            !collection
                .add(RootFundingTarget::Exit, exit[0].clone())
                .unwrap()
        );
        assert!(collection.export().is_err());
        collection
            .add(RootFundingTarget::Exit, exit[1].clone())
            .unwrap();
        collection
            .add(RootFundingTarget::Creation, creation[0].clone())
            .unwrap();
        assert!(collection.export().is_err());
        collection
            .add(RootFundingTarget::Creation, creation[1].clone())
            .unwrap();
        let exported = collection.export().unwrap();
        let tx = packed::Transaction::from_slice(
            &crate::multi_asset_packages::decode_hex(&exported.transaction_hex, MAX_FUNDING_BYTES)
                .unwrap(),
        )
        .unwrap();
        validate_root_funding(&exported.recovery_package.recovery().unwrap(), &tx).unwrap();
        let restored: RootFundingCollection =
            serde_json::from_slice(&serde_json::to_vec(&collection).unwrap()).unwrap();
        assert!(restored.summary().unwrap().ready_to_export);
        let mut duplicate = collection.clone();
        duplicate.exit_signatures.push(exit[0].clone());
        assert!(duplicate.validate().is_err());
        let mut missing = serde_json::to_value(&collection).unwrap();
        missing.as_object_mut().unwrap().remove("exit_signatures");
        assert!(serde_json::from_value::<RootFundingCollection>(missing).is_err());
    }
}
