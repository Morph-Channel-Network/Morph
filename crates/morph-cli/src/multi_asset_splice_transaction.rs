//! CLI entry points and baseline regression tests reuse the sole public Rust package implementation.
#[allow(unused_imports)]
pub use morph_packages::multi_asset_splice_transaction::*;

#[cfg(test)]
#[allow(unused_imports)]
use std::collections::BTreeSet;

#[cfg(test)]
#[allow(unused_imports)]
use anyhow::{Result, anyhow, ensure};

#[cfg(test)]
#[allow(unused_imports)]
use ckb_types::{packed, prelude::*};

#[cfg(test)]
#[allow(unused_imports)]
use morph_core::*;

#[cfg(test)]
#[allow(unused_imports)]
use morph_script_common::{multi_asset as wire, multi_asset_splice as splice};

#[cfg(test)]
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[allow(unused_imports)]
use crate::multi_asset_packages::{canonical_hex, decode_hex};

#[cfg(test)]
pub(crate) fn fixture_draft(current: &MultiAssetRecoveryPackage) -> SpliceDraft {
    fixture_draft_at(
        current,
        MultiAssetOutPoint {
            tx_hash: [44; 32],
            index: 0,
        },
        vec![
            packed::CellDep::new_builder()
                .out_point(
                    packed::OutPoint::new_builder()
                        .tx_hash([77u8; 32].pack())
                        .build(),
                )
                .build(),
        ],
    )
}

#[cfg(test)]
pub(crate) fn fixture_draft_at(
    current: &MultiAssetRecoveryPackage,
    old: MultiAssetOutPoint,
    deps: Vec<packed::CellDep>,
) -> SpliceDraft {
    use ckb_types::{bytes::Bytes, core::TransactionBuilder};
    let next = SpliceTerms {
        schema: "morph.multi_asset_splice_terms.v1".to_string(),
        descriptor_hex: canonical_hex(&current.settlement.encode().unwrap()),
        flows_hex: "0x".to_string(),
        new_type_scripts_hex: current
            .scripts
            .type_scripts
            .iter()
            .map(|entry| canonical_hex(&entry.script))
            .collect(),
        withdrawal_lock_hex: "0x".to_string(),
        cell_deps: vec![],
    }
    .funding(current, &old)
    .unwrap();
    let flows = current
        .manifest
        .vaults
        .iter()
        .map(|vault| MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: MultiAssetValue::default(),
            withdrawal: MultiAssetValue::default(),
        })
        .collect::<Vec<_>>();
    let mut tx = TransactionBuilder::default().cell_deps(deps);
    for point in std::iter::once(&old).chain(&current.outpoints) {
        tx = tx.input(
            packed::CellInput::new_builder()
                .previous_output(
                    packed::OutPoint::new_builder()
                        .tx_hash(point.tx_hash.pack())
                        .index(point.index)
                        .build(),
                )
                .build(),
        );
    }
    tx = tx
        .output(
            packed::CellOutput::new_builder()
                .capacity(current.state_carrier_capacity)
                .lock(script(&next.scripts.state_lock).unwrap())
                .type_(Some(script(&next.scripts.state_type).unwrap()).pack())
                .build(),
        )
        .output_data(Bytes::from(next.state.encode().unwrap().to_vec()).pack());
    for vault in &next.manifest.vaults {
        let ty = match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(
                script(
                    &next
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
                    .lock(script(&next.scripts.vault_lock).unwrap())
                    .type_(ty.pack())
                    .build(),
            )
            .output_data(Bytes::from(data).pack());
    }
    SpliceDraft {
        schema: SCHEMA.to_string(),
        base_state_digest: canonical_hex(&current.state.signing_digest().unwrap()),
        transaction_hex: canonical_hex(tx.build().data().as_slice()),
        new_witness_hex: canonical_hex(
            &encode_multi_asset_witness(&next.manifest, &next.settlement, &[], &next.scripts)
                .unwrap(),
        ),
        flows_hex: canonical_hex(&encode_multi_asset_splice_flows(&flows).unwrap()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ckb_types::bytes::Bytes;

    #[test]
    fn conditional_splice_terms_fund_pending_business_without_touching_reserve() {
        let source = crate::conditional_packages::fixture_source_package().unwrap();
        let current = source.recovery().unwrap();
        let flows = current
            .manifest
            .vaults
            .iter()
            .map(|vault| MultiAssetSpliceFlow {
                asset: vault.asset.clone(),
                deposit: MultiAssetValue::default(),
                withdrawal: MultiAssetValue::default(),
            })
            .collect::<Vec<_>>();
        let terms = SpliceTerms {
            schema: "morph.multi_asset_splice_terms.v1".into(),
            descriptor_hex: canonical_hex(&current.settlement.encode().unwrap()),
            flows_hex: canonical_hex(&encode_multi_asset_splice_flows(&flows).unwrap()),
            new_type_scripts_hex: current
                .scripts
                .type_scripts
                .iter()
                .map(|entry| canonical_hex(&entry.script))
                .collect(),
            withdrawal_lock_hex: "0x".into(),
            cell_deps: source.cell_deps,
        };
        let next = terms
            .funding(
                &current,
                &MultiAssetOutPoint {
                    tx_hash: [40; 32],
                    index: 0,
                },
            )
            .unwrap();
        for (before, after) in current.manifest.vaults.iter().zip(&next.manifest.vaults) {
            assert_eq!(before.asset, after.asset);
            assert_eq!(before.value, after.value);
        }
        next.settlement.validate_against(&next.manifest).unwrap();
        assert_eq!(next.manifest.vaults[0].value.business_ckb, 10_000_000_000);
        assert_ne!(
            next.state.header.funding_anchor,
            current.state.header.funding_anchor
        );
    }

    pub(crate) fn splice_fixture() -> serde_json::Value {
        use crate::multi_asset_funding::root_collection_tests::signed_receipts;
        use crate::multi_asset_packages::StoredMultiAssetPackage;
        let stored = crate::multi_asset_packages::fixture_package().unwrap();
        let current = stored.recovery().unwrap();
        let draft = fixture_draft(&current);
        let mut plan = draft.proposal(&current).unwrap();
        let participants = stored.validate().unwrap().signer_pubkeys;
        let creation_digest = plan.new_state.signing_digest().unwrap();
        let creation = signed_receipts(&creation_digest);
        let authorization =
            |digest: &Bytes32, receipts: &[crate::multi_asset_signatures::SignatureMessage]| {
                StateAuthorization {
                    threshold: 2,
                    signatures: receipts
                        .iter()
                        .map(|receipt| receipt.verify(digest, &participants).unwrap())
                        .collect(),
                }
            };
        plan.new_state_authorization = authorization(&creation_digest, &creation);
        let points = (0..plan.new_manifest.vaults.len())
            .map(|i| MultiAssetOutPoint {
                tx_hash: plan.transaction_hash,
                index: i as u32 + 1,
            })
            .collect::<Vec<_>>();
        let mut state = plan.new_state.clone();
        state.header.phase = Phase::Settling;
        state.header.state_number = 1;
        state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&plan.new_manifest, &points).unwrap();
        let recovery_digest = state.signing_digest().unwrap();
        let recovery = signed_receipts(&recovery_digest);
        plan.initial_recovery_authorization = authorization(&recovery_digest, &recovery);
        let bridge_digest = plan.signing_digest(&current).unwrap();
        let bridge = signed_receipts(&bridge_digest);
        let witness = packed::WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&plan.new_state_authorization)
                        .unwrap()
                        .to_vec(),
                ))
                .pack(),
            )
            .output_type(
                Some(Bytes::from(
                    plan.encode_witness(&current, &authorization(&bridge_digest, &bridge))
                        .unwrap(),
                ))
                .pack(),
            )
            .build();
        let transaction = draft
            .transaction()
            .unwrap()
            .as_builder()
            .witnesses(vec![witness.as_bytes().pack()].pack())
            .build();
        let exit = plan.initial_recovery(&current).unwrap();
        let recovery_package = StoredMultiAssetPackage::from_recovery(
            &exit,
            &transaction
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>(),
        )
        .unwrap();
        serde_json::json!({"current":stored,"draft":draft,"creation_digest":canonical_hex(&creation_digest),"recovery_digest":canonical_hex(&recovery_digest),"bridge_digest":canonical_hex(&bridge_digest),"creation_receipts":creation,"recovery_receipts":recovery,"bridge_receipts":bridge,"funding":{"schema":"morph.multi_asset_splice_funding.v1","transaction_hex":canonical_hex(transaction.as_slice()),"recovery_package":recovery_package}})
    }

    #[test]
    fn splice_fixture_matches_all_three_domains_and_exact_transaction() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/protocol/multi-asset-splice.json"
        ))
        .unwrap();
        assert_eq!(splice_fixture(), expected);
        // Recorded node transactions cover actual asset admission/removal and
        // withdrawal custody; revalidate their public evidence without RPC.
        let transitions: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../fixtures/protocol/multi-asset-splice-transitions.json"
        ))
        .unwrap();
        for transition in transitions {
            let dir = std::env::temp_dir().join(format!(
                "morph-splice-import-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let bundle_path = dir.join("funding.json");
            let old_path = dir.join("old.json");
            std::fs::write(
                &bundle_path,
                serde_json::to_vec(&transition["funding"]).unwrap(),
            )
            .unwrap();
            std::fs::write(
                &old_path,
                serde_json::to_vec(&transition["current"]).unwrap(),
            )
            .unwrap();
            let current: crate::multi_asset_packages::StoredMultiAssetPackage =
                serde_json::from_value(transition["current"].clone()).unwrap();
            let recovery: crate::multi_asset_packages::StoredMultiAssetPackage =
                serde_json::from_value(transition["funding"]["recovery_package"].clone()).unwrap();
            let draft: SpliceDraft = serde_json::from_value(transition["draft"].clone()).unwrap();
            let tx = packed::Transaction::from_slice(
                &decode_hex(
                    transition["funding"]["transaction_hex"].as_str().unwrap(),
                    MAX_TRANSACTION_BYTES,
                )
                .unwrap(),
            )
            .unwrap();
            let current = current.recovery().unwrap();
            let recovery = recovery.recovery().unwrap();
            let (reconstructed, plan, _) =
                SpliceDraft::from_signed_transaction(&current, &recovery, &tx).unwrap();
            assert_eq!(
                reconstructed.transaction().unwrap().raw().as_slice(),
                draft.transaction().unwrap().raw().as_slice()
            );
            assert_eq!(reconstructed.new_witness_hex, draft.new_witness_hex);
            assert_eq!(reconstructed.flows_hex, draft.flows_hex);
            let participants = current
                .authorization
                .signatures
                .iter()
                .map(|signature| canonical_hex(&signature.pubkey_sec1))
                .collect::<Vec<_>>();
            let participants = [participants[0].clone(), participants[1].clone()];
            for (role, digest) in [
                ("creation", plan.new_state.signing_digest().unwrap()),
                ("recovery", recovery.state.signing_digest().unwrap()),
                ("bridge", plan.signing_digest(&current).unwrap()),
            ] {
                let receipts: Vec<crate::multi_asset_signatures::SignatureMessage> =
                    serde_json::from_value(transition[format!("{role}_receipts")].clone()).unwrap();
                assert_eq!(receipts.len(), 2);
                for receipt in receipts {
                    receipt.verify(&digest, &participants).unwrap();
                }
            }
            let store = dir.join("received");
            let imported = import_splice_funding(&bundle_path, &old_path, &store).unwrap();
            assert_eq!(
                std::fs::read(imported["transaction"].as_str().unwrap()).unwrap(),
                tx.as_slice()
            );
            assert_eq!(
                crate::multi_asset_packages::read_package(std::path::Path::new(
                    imported["recovery_package"].as_str().unwrap()
                ))
                .unwrap()
                .recovery()
                .unwrap(),
                recovery
            );
            assert_eq!(
                import_splice_funding(&bundle_path, &old_path, &store).unwrap(),
                imported
            );
            let mut invalid = transition["funding"].clone();
            invalid["recovery_package"] = transition["current"].clone();
            std::fs::write(&bundle_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            let rejected = dir.join("rejected");
            assert!(import_splice_funding(&bundle_path, &old_path, &rejected).is_err());
            assert!(!rejected.exists());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn exact_draft_rejects_authority_value_input_and_witness_tampering() {
        let current = crate::multi_asset_packages::fixture_package()
            .unwrap()
            .recovery()
            .unwrap();
        let good = fixture_draft(&current);
        let plan = good.proposal(&current).unwrap();
        for mutation in 0..8 {
            let mut draft = good.clone();
            let tx = draft.transaction().unwrap();
            let mut inputs = tx.raw().inputs().into_iter().collect::<Vec<_>>();
            let mut outputs = tx.raw().outputs().into_iter().collect::<Vec<_>>();
            let mut data = tx.raw().outputs_data().into_iter().collect::<Vec<_>>();
            match mutation {
                0 => inputs.swap(1, 2),
                1 => inputs.push(inputs[0].clone()),
                2 => {
                    outputs[0] = outputs[0]
                        .clone()
                        .as_builder()
                        .capacity(current.state_carrier_capacity - 1)
                        .build()
                }
                3 => {
                    outputs[1] = outputs[1]
                        .clone()
                        .as_builder()
                        .lock(script(&current.scripts.vault_lock).unwrap())
                        .build()
                }
                4 => {
                    outputs.push(outputs[1].clone());
                    data.push(data[1].clone());
                }
                5 => {
                    outputs[1] = outputs[1]
                        .clone()
                        .as_builder()
                        .type_(None::<packed::Script>.pack())
                        .build()
                }
                6 => {
                    outputs.pop();
                    data.pop();
                }
                _ => {}
            }
            let raw = tx
                .raw()
                .as_builder()
                .inputs(inputs.pack())
                .outputs(outputs.pack())
                .outputs_data(data.pack())
                .build();
            let mut tx = tx.as_builder().raw(raw).build();
            if mutation == 7 {
                tx = tx
                    .as_builder()
                    .witnesses(vec![Bytes::from_static(b"unreviewed").pack()].pack())
                    .build();
            }
            draft.transaction_hex = canonical_hex(tx.as_slice());
            assert!(draft.proposal(&current).is_err(), "mutation {mutation}");
        }
        let mut changed = good.clone();
        let tx = changed.transaction().unwrap();
        let mut inputs = tx.raw().inputs().into_iter().collect::<Vec<_>>();
        inputs.push(
            packed::CellInput::new_builder()
                .previous_output(
                    packed::OutPoint::new_builder()
                        .tx_hash([88u8; 32].pack())
                        .build(),
                )
                .build(),
        );
        let raw = tx.raw().as_builder().inputs(inputs.pack()).build();
        changed.transaction_hex = canonical_hex(tx.as_builder().raw(raw).build().as_slice());
        assert!(changed.proposal(&current).is_ok());
        assert!(changed.validate_plan(&current, &plan).is_err());
        let mut changed = good;
        changed.base_state_digest = canonical_hex(&[0; 32]);
        assert!(changed.validate_plan(&current, &plan).is_err());
    }
}
