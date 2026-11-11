use super::*;
use ckb_types::{
    core::TransactionBuilder,
    packed::{CellInput, OutPoint},
};
use morph_script_common::multi_asset_close as close;

fn proposal(current: &MultiAssetRecoveryPackage, marker: u8) -> MultiAssetCloseProposal {
    let header_raw = current.state.encode().unwrap();
    let header = wire::MultiAssetStateHeader::parse(&header_raw).unwrap();
    let witness_raw = encode_multi_asset_witness(
        &current.manifest,
        &current.settlement,
        &current.outpoints,
        &current.scripts,
    )
    .unwrap();
    let witness = wire::MultiAssetWitness::parse(&witness_raw).unwrap();
    let outputs =
        multi_asset_settlement_outputs(&witness, &header, current.state_carrier_capacity).unwrap();
    let source_outpoint = MultiAssetOutPoint {
        tx_hash: [77; 32],
        index: 0,
    };
    let mut source_state = current.state.clone();
    source_state.header.state_number = 0;
    source_state.header.phase = Phase::Active;
    let mut builder = TransactionBuilder::default()
        .header_dep([marker; 32].pack())
        .input(CellInput::new(
            OutPoint::new(source_outpoint.tx_hash.pack(), 0),
            0,
        ));
    for point in &current.outpoints {
        builder = builder.input(CellInput::new(
            OutPoint::new(point.tx_hash.pack(), point.index),
            0,
        ));
    }
    for (output, data) in outputs {
        builder = builder.output(output).output_data(data.pack());
    }
    MultiAssetCloseProposal {
        source_outpoint,
        source_state,
        transaction: builder.build().data().raw().as_slice().to_vec(),
    }
}
fn sign_close(
    proposal: &MultiAssetCloseProposal,
    package: &MultiAssetRecoveryPackage,
    key: u8,
) -> ParticipantSignature {
    let sig: Signature = participant_key(key)
        .sign_prehash(&proposal.signing_digest(package).unwrap())
        .unwrap();
    ParticipantSignature {
        pubkey_sec1: participant_pubkey(key),
        signature: sig.to_bytes().to_vec(),
    }
}
fn restored(backend: &MultiAssetChannelBackend) -> MultiAssetChannelBackend {
    serde_json::from_slice(&serde_json::to_vec(backend).unwrap()).unwrap()
}

#[test]
fn cooperative_close_reservation_survives_restart_and_never_reopens_payments() {
    let current = fixture(2);
    let plan = proposal(&current, 1);
    let hash = plan.transaction_hash().unwrap();
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_close(plan.clone()).unwrap();
    let local = sign_close(&plan, &current, 1);
    assert_eq!(
        backend
            .record_close_signature(&hash, local.clone())
            .unwrap_err(),
        MultiAssetBackendError::UnreservedSignature
    );
    backend.reserve_close_signature(&hash).unwrap();
    let mut backend = restored(&backend); // crash after reserve, before key receipt
    assert!(backend.close_signature_reserved(&hash).unwrap());
    assert_eq!(
        backend.cancel_close().unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
    assert_eq!(
        backend.propose(current.settlement.clone()).unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
    assert_eq!(
        backend
            .prepare_splice(splice_proposal(&current))
            .unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
    assert_eq!(
        backend.recover_committed(current.clone()).unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
    backend.cancel_proposal();
    backend.cancel_splice().unwrap();
    assert_eq!(
        backend.cancel_close().unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
    assert_eq!(
        backend.close_authorization(&hash).unwrap_err(),
        MultiAssetBackendError::IncompleteSignatures
    );
    backend
        .record_close_signature(&hash, local.clone())
        .unwrap();
    let mut backend = restored(&backend); // crash after record, before delivery
    backend.record_close_signature(&hash, local).unwrap();
    backend
        .record_close_signature(&hash, sign_close(&plan, &current, 2))
        .unwrap();
    assert_eq!(
        backend.close_authorization(&hash).unwrap().signatures.len(),
        2
    );
    let encoded = backend.close_witness(&hash).unwrap();
    let source = plan.source_state.encode().unwrap();
    close::MultiAssetCloseWitness::parse(&encoded)
        .unwrap()
        .validate_source(&wire::MultiAssetStateHeader::parse(&source).unwrap())
        .unwrap();
    assert_eq!(backend.current(), &current);
    backend.current().validate().unwrap(); // Saved unilateral exit remains available.
}

#[test]
fn cooperative_close_replacements_preserve_all_old_approvals_and_exact_sources() {
    let current = fixture(2);
    let first = proposal(&current, 1);
    let second = proposal(&current, 2);
    let a = first.transaction_hash().unwrap();
    let b = second.transaction_hash().unwrap();
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_close(first.clone()).unwrap();
    backend.reserve_close_signature(&a).unwrap();
    for key in [1, 2] {
        backend
            .record_close_signature(&a, sign_close(&first, &current, key))
            .unwrap();
    }
    let old = backend.close_witness(&a).unwrap();
    backend.prepare_close(second.clone()).unwrap();
    assert!(
        backend
            .record_close_signature(&b, sign_close(&first, &current, 1))
            .is_err()
    );
    backend.reserve_close_signature(&b).unwrap();
    backend
        .record_close_signature(&b, sign_close(&second, &current, 1))
        .unwrap();
    let backend = restored(&backend);
    assert_eq!(backend.close_witness(&a).unwrap(), old);
    assert_eq!(backend.close_attempts().len(), 2);
    let mut changed_source = second;
    changed_source.source_outpoint.tx_hash = [88; 32];
    let raw = changed_source.raw_transaction().unwrap();
    let mut inputs: Vec<_> = raw.inputs().into_iter().collect();
    inputs[0] = CellInput::new(OutPoint::new([88; 32].pack(), 0), 0);
    changed_source.transaction = raw
        .as_builder()
        .inputs(inputs.pack())
        .build()
        .as_slice()
        .to_vec();
    changed_source.validate(&current).unwrap();
    let mut backend = backend;
    assert_eq!(
        backend.prepare_close(changed_source).unwrap_err(),
        MultiAssetBackendError::StaleProposal
    );
    assert_eq!(backend.close_attempts().len(), 2);
}

#[test]
fn cooperative_close_preparation_cancellation_and_outstanding_votes_are_explicit() {
    let current = fixture(2);
    let plan = proposal(&current, 1);
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_close(plan.clone()).unwrap();
    backend.cancel_close().unwrap();
    backend.propose(current.settlement.clone()).unwrap();
    assert_eq!(
        backend.prepare_close(plan.clone()).unwrap_err(),
        MultiAssetBackendError::PendingProposal
    );
    backend.reserve_signature().unwrap();
    backend.cancel_proposal();
    assert_eq!(
        backend.prepare_close(plan.clone()).unwrap_err(),
        MultiAssetBackendError::UnsettledVotes
    );
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_splice(splice_proposal(&current)).unwrap();
    assert_eq!(
        backend.prepare_close(plan.clone()).unwrap_err(),
        MultiAssetBackendError::SpliceFrozen
    );
    backend.cancel_splice().unwrap();
    backend.prepare_close(plan.clone()).unwrap();
    backend
        .record_close_signature(
            &plan.transaction_hash().unwrap(),
            sign_close(&plan, &current, 2),
        )
        .unwrap();
    assert_eq!(
        backend.cancel_close().unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
}

#[test]
fn cooperative_close_snapshots_reject_missing_fields_inconsistent_votes_and_duplicate_history() {
    let current = fixture(2);
    let plan = proposal(&current, 1);
    let hash = plan.transaction_hash().unwrap();
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_close(plan.clone()).unwrap();
    backend.reserve_close_signature(&hash).unwrap();
    backend
        .record_close_signature(&hash, sign_close(&plan, &current, 1))
        .unwrap();
    for mutation in 0..6 {
        let mut value = serde_json::to_value(&backend).unwrap();
        match mutation {
            0 => {
                value.as_object_mut().unwrap().remove("close");
            }
            1 => value["close"][0]["signature_reserved"] = false.into(),
            2 => {
                let duplicate = value["close"][0].clone();
                value["close"].as_array_mut().unwrap().push(duplicate);
            }
            3 => value["close"] = serde_json::json!([]),
            4 => {
                value["close"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("signature_reserved");
            }
            _ => value["close"][0]["signatures"][0]["signature"][0] = 255.into(),
        }
        assert!(
            serde_json::from_value::<MultiAssetChannelBackend>(value).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn cooperative_close_transaction_review_rejects_changed_payouts_provenance_and_bounds() {
    let current = fixture(2);
    let good = proposal(&current, 1);
    good.validate(&current).unwrap();
    for mutation in 0..9 {
        let mut bad = good.clone();
        let raw = bad.raw_transaction().unwrap();
        let mut inputs: Vec<_> = raw.inputs().into_iter().collect();
        let mut outputs: Vec<_> = raw.outputs().into_iter().collect();
        match mutation {
            0 => {
                inputs.pop();
            }
            1 => inputs.swap(1, 2),
            2 => inputs.push(inputs[1].clone()),
            3 => outputs[0] = outputs[0].clone().as_builder().capacity(1u64).build(),
            4 => {
                outputs.pop();
            }
            5 => bad.source_state.header.funding_epoch += 1,
            6 => bad.source_state.header.state_number = current.state.header.state_number + 1,
            7 => bad.source_state.vault_outpoint_set_root = [0; 32],
            _ => bad.source_outpoint.tx_hash = [78; 32],
        }
        bad.transaction = raw
            .as_builder()
            .inputs(inputs.pack())
            .outputs(outputs.pack())
            .build()
            .as_slice()
            .to_vec();
        assert!(bad.validate(&current).is_err(), "mutation {mutation}");
    }
    let mut oversized = good;
    oversized.transaction = vec![0; MULTI_ASSET_CLOSE_MAX_TRANSACTION_BYTES + 1];
    assert!(oversized.raw_transaction().is_err());
}

#[test]
fn cooperative_close_history_limit_never_discards_reserved_authority() {
    let current = fixture(1);
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    for marker in 1..=MULTI_ASSET_CLOSE_MAX_APPROVALS {
        let plan = proposal(&current, marker as u8);
        let hash = plan.transaction_hash().unwrap();
        backend.prepare_close(plan).unwrap();
        backend.reserve_close_signature(&hash).unwrap();
    }
    let before = backend.clone();
    assert_eq!(
        backend.prepare_close(proposal(&current, 99)).unwrap_err(),
        MultiAssetBackendError::CloseHistoryFull
    );
    assert_eq!(backend, before);
    assert_eq!(
        backend.cancel_close().unwrap_err(),
        MultiAssetBackendError::CloseFrozen
    );
    assert_eq!(restored(&backend), backend);
}

#[test]
fn cooperative_close_consistent_whole_store_rollback_still_needs_external_freshness() {
    let current = fixture(1);
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    let old_snapshot = serde_json::to_vec(&backend).unwrap();
    let plan = proposal(&current, 1);
    let hash = plan.transaction_hash().unwrap();
    backend.prepare_close(plan).unwrap();
    backend.reserve_close_signature(&hash).unwrap();
    assert!(backend.propose(current.settlement.clone()).is_err());
    let mut rolled_back: MultiAssetChannelBackend = serde_json::from_slice(&old_snapshot).unwrap();
    assert!(
        rolled_back.propose(current.settlement).is_ok(),
        "local consistency cannot detect loss of the entire close history"
    );
}

fn frame() -> (MultiAssetRecoveryPackage, Vec<u8>) {
    let mut package = fixture(2);
    let raw_header = package.state.encode().unwrap();
    let header = wire::MultiAssetStateHeader::parse(&raw_header).unwrap();
    let digest = close::multi_asset_close_digest(&header, &[19; 32]).unwrap();
    let mut preimage = morph_core::hash::MULTI_ASSET_CLOSE_DOMAIN.to_vec();
    preimage.extend(package.state.signing_digest().unwrap());
    preimage.extend([19; 32]);
    assert_eq!(blake2b256(&preimage), digest);
    let mut keys = [1u8, 2].map(|byte| SigningKey::from_slice(&[byte; 32]).unwrap());
    keys.sort_by_key(|key| key.verifying_key().to_sec1_point(true).as_bytes().to_vec());
    package.authorization.signatures = keys
        .iter()
        .map(|key| {
            let sig: Signature = key.sign_prehash(&digest).unwrap();
            ParticipantSignature {
                pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                signature: sig.to_bytes().to_vec(),
            }
        })
        .collect();
    let evidence = encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )
    .unwrap();
    let sigs = encode_multi_asset_signatures(&package.authorization).unwrap();
    let mut encoded = vec![0; close::MULTI_ASSET_CLOSE_FIXED_LEN + evidence.len()];
    close::encode_multi_asset_close(&mut encoded, &[19; 32], &raw_header, &sigs, &evidence)
        .unwrap();
    (package, encoded)
}

#[test]
fn cooperative_close_encoding_digest_and_role_are_single_sourced() {
    let (package, encoded) = frame();
    let header = package.state.encode().unwrap();
    let source = wire::MultiAssetStateHeader::parse(&header).unwrap();
    let proof = close::MultiAssetCloseWitness::parse(&encoded).unwrap();
    proof.validate_source(&source).unwrap();
    assert_eq!(proof.target().as_bytes(), header);
    assert_eq!(proof.transaction_hash(), [19; 32]);
    assert!(
        package.validate().is_err(),
        "close signatures cannot authorize a recovery package"
    );
    let mut wrong_body = encoded.clone();
    wrong_body[16] ^= 1;
    assert!(
        close::MultiAssetCloseWitness::parse(&wrong_body)
            .unwrap()
            .validate_source(&source)
            .is_err()
    );
    for domain in [
        morph_core::hash::MULTI_ASSET_STATE_DOMAIN,
        morph_core::hash::MULTI_ASSET_ROOT_FUNDING_DOMAIN,
        morph_core::hash::MULTI_ASSET_SPLICE_DOMAIN,
        morph_core::hash::FACTORY_MULTI_ASSET_STATE_DOMAIN,
    ] {
        assert!(!domain.starts_with(close::MULTI_ASSET_CLOSE_DOMAIN));
        assert!(!close::MULTI_ASSET_CLOSE_DOMAIN.starts_with(domain));
    }
}

#[test]
fn cooperative_close_parser_rejects_truncation_trailing_and_noncanonical_fields() {
    let (_, encoded) = frame();
    for length in 0..encoded.len() {
        assert!(close::MultiAssetCloseWitness::parse(&encoded[..length]).is_err());
    }
    for (offset, byte) in [(0, 0), (8, 2), (10, 1), (12, 255)] {
        let mut invalid = encoded.clone();
        invalid[offset] = byte;
        assert!(close::MultiAssetCloseWitness::parse(&invalid).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(close::MultiAssetCloseWitness::parse(&trailing).is_err());
    let oversized = vec![0; close::MULTI_ASSET_CLOSE_MAX_LEN + 1];
    assert!(close::MultiAssetCloseWitness::parse(&oversized).is_err());
}

proptest! {
    #[test]
    fn cooperative_close_bounded_parser_never_panics(raw in prop::collection::vec(any::<u8>(), 0..=close::MULTI_ASSET_CLOSE_MAX_LEN + 1)) {
        let _ = close::MultiAssetCloseWitness::parse(&raw);
    }
}
