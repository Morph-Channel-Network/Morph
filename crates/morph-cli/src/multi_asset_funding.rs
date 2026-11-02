//! Exact epoch-0 funding provenance. Creation signatures authenticate the
//! original unbound state; the current complete exit may have newer payouts.
use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use morph_core::*;
use morph_script_common::multi_asset as wire;

pub(crate) const SECP_TYPE_HASH: &str =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
pub(crate) fn funding_wallet_lock(pubkey: &[u8]) -> Result<packed::Script> {
    ensure!(pubkey.len() == 33, "compressed key must be 33 bytes");
    Ok(packed::Script::new_builder()
        .code_hash(
            <[u8; 32]>::try_from(crate::multi_asset_packages::decode_hex(SECP_TYPE_HASH, 32)?)
                .map_err(|_| anyhow!("invalid standard secp type hash"))?
                .pack(),
        )
        .hash_type(1u8)
        .args(Bytes::copy_from_slice(&blake2b256(pubkey)[..20]).pack())
        .build())
}
pub const MAX_FUNDING_BYTES: usize = 256 * 1024;

fn script(raw: &[u8]) -> Result<packed::Script> {
    Ok(packed::Script::from_slice(raw)?)
}

pub fn validate_root_funding(
    current: &MultiAssetRecoveryPackage,
    transaction: &packed::Transaction,
) -> Result<()> {
    current.validate()?;
    validate_root_funding_contents(current, transaction)?;
    let witness = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding witness"))?
        .raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness)?;
    let signatures = witness
        .input_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing creation signatures"))?
        .raw_data();
    let (creation, _) = creation_contents(transaction)?;
    let header = creation.state.encode()?;
    wire::MultiAssetStateHeader::parse(&header)
        .map_err(|error| anyhow!("invalid creation: {error:?}"))?
        .verify_root_funding_signatures(
            &transaction.calc_tx_hash().unpack(),
            &morph_script_common::BilateralSignatureWitness::parse(&signatures)
                .map_err(|error| anyhow!("invalid root signatures: {error:?}"))?,
        )
        .map_err(|error| anyhow!("invalid root funding authorization: {error:?}"))?;
    Ok(())
}

/// Explicit unsigned review. This does not authorise creation or broadcast.
pub fn validate_root_funding_contents(
    current: &MultiAssetRecoveryPackage,
    transaction: &packed::Transaction,
) -> Result<()> {
    current.validate_contents()?;
    ensure!(
        current.state.header.funding_epoch == 0
            && current.state.header.phase == Phase::Settling
            && !current.outpoints.is_empty(),
        "root binding requires bound epoch-0 exit evidence"
    );
    ensure!(
        transaction.as_slice().len() <= MAX_FUNDING_BYTES,
        "root funding exceeds byte limit"
    );
    let raw = transaction.raw();
    ensure!(
        u32::from(raw.version()) == 0,
        "unsupported root transaction version"
    );
    ensure!(
        (1..=64).contains(&raw.inputs().len())
            && (1..=64).contains(&raw.outputs().len())
            && raw.outputs().len() == raw.outputs_data().len(),
        "invalid root funding cell count"
    );
    ensure!(
        (1..=64).contains(&raw.cell_deps().len()) && raw.header_deps().len() <= 64,
        "invalid root funding dependency count"
    );
    let hash: [u8; 32] = transaction.calc_tx_hash().unpack();
    ensure!(
        current.outpoints.iter().all(|point| point.tx_hash == hash),
        "root Vaults are outside the funding transaction"
    );
    let state_type = script(&current.scripts.state_type)?;
    let states = raw
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, output)| output.type_().to_opt() == Some(state_type.clone()))
        .collect::<Vec<_>>();
    ensure!(
        states.len() == 1,
        "funding requires one authentic creation State"
    );
    let (index, output) = &states[0];
    ensure!(
        output.lock() == script(&current.scripts.state_lock)?
            && u64::from(output.capacity()) == current.state_carrier_capacity,
        "funding State authority or carrier mismatch"
    );
    let input = raw
        .inputs()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding anchor input"))?;
    let mut anchor = input.as_slice().to_vec();
    anchor.extend_from_slice(&(*index as u64).to_le_bytes());
    ensure!(
        blake2b256(&anchor) == current.state.header.funding_anchor,
        "funding State anchor does not derive from its actual output index"
    );
    let witness_bytes = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding witness zero"))?
        .raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness_bytes)?;
    let creation_data = raw
        .outputs_data()
        .get(*index)
        .ok_or_else(|| anyhow!("missing creation header"))?
        .raw_data();
    let evidence = witness
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing creation evidence"))?
        .raw_data();
    let mut creation = MultiAssetRecoveryPackage::decode_contents(
        &creation_data,
        &evidence,
        current.state_carrier_capacity,
    )?;
    ensure!(
        creation.state.header.funding_epoch == 0
            && creation.state.header.phase == Phase::Active
            && creation.state.header.state_number == 0
            && creation.outpoints.is_empty(),
        "funding witness is not the root unbound creation"
    );
    ensure!(
        creation.manifest == current.manifest && creation.scripts == current.scripts,
        "current recovery differs from authenticated root custody"
    );
    creation.outpoints = current.outpoints.clone();
    creation.state.vault_outpoint_set_root = current.state.vault_outpoint_set_root;
    // Never re-use the unbound creation signatures as an activation vote.
    creation.validate_contents()?;
    let before = creation.state.encode()?;
    let after = current.state.encode()?;
    ensure!(
        wire::MultiAssetStateHeader::parse(&before)
            .map_err(|error| anyhow!("invalid root header: {error:?}"))?
            .same_context_except_progress(
                &wire::MultiAssetStateHeader::parse(&after)
                    .map_err(|error| anyhow!("invalid current header: {error:?}"))?
            ),
        "root/current funding contexts differ"
    );
    let vault_lock = script(&current.scripts.vault_lock)?;
    let mut selected = BTreeSet::new();
    for (vault, point) in current.manifest.vaults.iter().zip(&current.outpoints) {
        let index = point.index as usize;
        ensure!(
            selected.insert(index) && index != states[0].0,
            "duplicate or aliased root Vault OutPoint"
        );
        let output = raw
            .outputs()
            .get(index)
            .ok_or_else(|| anyhow!("root Vault output missing"))?;
        let data = raw
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("root Vault data missing"))?
            .raw_data();
        let ty = match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(script(
                &current
                    .scripts
                    .type_scripts
                    .iter()
                    .find(|entry| entry.type_hash == hash)
                    .ok_or_else(|| anyhow!("missing root Type Script"))?
                    .script,
            )?),
        };
        let expected_data = if ty.is_some() {
            vault.value.amount.to_le_bytes().to_vec()
        } else {
            vec![]
        };
        ensure!(
            output.lock() == vault_lock
                && output.type_().to_opt() == ty
                && u64::from(output.capacity()) == vault.value.capacity()?
                && data.as_ref() == expected_data,
            "root Vault physical contents mismatch"
        );
    }
    for (index, output) in raw.outputs().into_iter().enumerate() {
        ensure!(
            output.lock() != script(&current.scripts.state_lock)? || index == states[0].0,
            "unlisted StateLock in root funding transaction"
        );
        ensure!(
            output.lock() != vault_lock || selected.contains(&index),
            "unlisted Vault in root funding transaction"
        );
    }
    Ok(())
}

fn creation_contents(
    transaction: &packed::Transaction,
) -> Result<(MultiAssetRecoveryPackage, usize)> {
    ensure!(
        transaction.as_slice().len() <= MAX_FUNDING_BYTES,
        "root funding exceeds byte limit"
    );
    let witness = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding witness zero"))?
        .raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness)?;
    let evidence = witness
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing creation evidence"))?
        .raw_data();
    let parsed = wire::MultiAssetWitness::parse(&evidence)
        .map_err(|error| anyhow!("invalid creation evidence: {error:?}"))?;
    let ty = script(
        parsed
            .scripts()
            .script(4)
            .map_err(|error| anyhow!("missing StateType: {error:?}"))?,
    )?;
    let raw = transaction.raw();
    let indices = raw
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, output)| output.type_().to_opt() == Some(ty.clone()))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        indices.len() == 1,
        "funding requires one authentic creation State"
    );
    let index = indices[0];
    let carrier = u64::from(
        raw.outputs()
            .get(index)
            .ok_or_else(|| anyhow!("missing State"))?
            .capacity(),
    );
    let header = raw
        .outputs_data()
        .get(index)
        .ok_or_else(|| anyhow!("missing creation header"))?
        .raw_data();
    Ok((
        MultiAssetRecoveryPackage::decode_contents(&header, &evidence, carrier)?,
        index,
    ))
}

/// Public immutable funding proposal. Every amount and the initial exit are
/// derived from the packed transaction; no duplicate roots or amounts exist.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootFundingDraft {
    pub schema: String,
    pub transaction_hex: String,
    pub participants: [String; 2],
}
impl RootFundingDraft {
    pub fn transaction(&self) -> Result<packed::Transaction> {
        ensure!(
            self.schema == "morph.multi_asset_root_draft.v1",
            "unsupported root draft schema"
        );
        let bytes =
            crate::multi_asset_packages::decode_hex(&self.transaction_hex, MAX_FUNDING_BYTES)?;
        let tx = packed::Transaction::from_slice(&bytes)?;
        let raw = tx
            .witnesses()
            .get(0)
            .ok_or_else(|| anyhow!("missing draft witness"))?
            .raw_data();
        let args = packed::WitnessArgs::from_slice(&raw)?;
        ensure!(
            args.input_type().to_opt().is_none() && args.lock().to_opt().is_none(),
            "root draft must contain no creation or wallet signature in witness zero"
        );
        Ok(tx)
    }
    pub fn evidence(&self) -> Result<(MultiAssetRecoveryPackage, MultiAssetRecoveryPackage)> {
        let tx = self.transaction()?;
        let (creation, _) = creation_contents(&tx)?;
        let public = self
            .participants
            .each_ref()
            .map(|key| crate::multi_asset_packages::decode_hex(key, 33));
        let public = [
            public[0].as_ref().map_err(|error| anyhow!("{error}"))?,
            public[1].as_ref().map_err(|error| anyhow!("{error}"))?,
        ];
        ensure!(
            public[0].len() == 33 && public[1].len() == 33 && public[0] < public[1],
            "root participants must be sorted distinct compressed keys"
        );
        for key in public {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .map_err(|_| anyhow!("invalid compressed participant key"))?;
        }
        ensure!(
            participants_commitment(2, &[public[0], public[1]])
                == creation.state.header.participants_commitment,
            "root participant commitment mismatch"
        );
        let mut exit = creation.clone();
        let lock = script(&creation.scripts.vault_lock)?;
        let hash = tx.calc_tx_hash().unpack();
        for vault in &creation.manifest.vaults {
            let matches = tx
                .raw()
                .outputs()
                .into_iter()
                .enumerate()
                .filter(|(_, output)| {
                    output.lock() == lock
                        && match vault.asset {
                            VaultAsset::Ckb => output.type_().to_opt().is_none(),
                            VaultAsset::Xudt(hash) => output
                                .type_()
                                .to_opt()
                                .is_some_and(|ty| ty.calc_script_hash().as_slice() == hash),
                        }
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            ensure!(matches.len() == 1, "missing or duplicated root Vault");
            exit.outpoints.push(MultiAssetOutPoint {
                tx_hash: hash,
                index: matches[0] as u32,
            });
        }
        exit.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&exit.manifest, &exit.outpoints)?;
        exit.state.header.phase = Phase::Settling;
        exit.state.header.state_number = 1;
        validate_root_funding_contents(&exit, &tx)?;
        // Validate code-dependency shape without pretending unsigned evidence
        // is a recoverable package.
        let deps = tx.raw().cell_deps();
        let mut points = BTreeSet::new();
        for dep in deps {
            ensure!(
                dep.dep_type().as_slice() == [0] || dep.dep_type().as_slice() == [1],
                "invalid dependency type"
            );
            ensure!(
                points.insert(dep.out_point().as_slice().to_vec()),
                "duplicate funding dependency"
            );
        }
        Ok((creation, exit))
    }
    pub fn digests(&self) -> Result<([u8; 32], [u8; 32])> {
        let (creation, exit) = self.evidence()?;
        Ok((
            creation
                .state
                .root_funding_signing_digest(&self.transaction()?.calc_tx_hash().unpack())?,
            exit.state.signing_digest()?,
        ))
    }
}

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
                    pubkey_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
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
        let stored = crate::multi_asset_packages::fixture_package().unwrap();
        let mut current = stored.recovery().unwrap();
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
        let (current, tx) = fixture();
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
                        pubkey_sec1: key
                            .verifying_key()
                            .to_encoded_point(true)
                            .as_bytes()
                            .to_vec(),
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
