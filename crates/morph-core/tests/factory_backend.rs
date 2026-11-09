use ckb_types::{bytes::Bytes, packed, prelude::*};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::*;
use morph_script_common::{factory_multi_asset as wire, multi_asset as asset};

#[path = "support/factory_journal.rs"]
mod support;

fn fixture() -> (FactorySigningRequest, Vec<FactoryParticipantKey>) {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/factory-root.json")).unwrap();
    (
        serde_json::from_value(value["request"].clone()).unwrap(),
        serde_json::from_value(value["members"].clone()).unwrap(),
    )
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn signature(request: &FactorySigningRequest, seed: u8) -> FactoryParticipantSignature {
    let key = key(seed);
    let public = key.verifying_key().to_sec1_point(true).as_bytes().to_vec();
    let member = request
        .members()
        .unwrap()
        .into_iter()
        .find(|member| member.pubkey_sec1 == public)
        .unwrap();
    let signature: Signature = key
        .sign_prehash(&request.signing_digest().unwrap())
        .unwrap();
    FactoryParticipantSignature {
        participant: member.participant,
        pubkey_sec1: public,
        signature: signature.to_bytes().to_vec(),
    }
}
fn placeholders(members: &[FactoryParticipantKey]) -> Vec<FactoryParticipantSignature> {
    members
        .iter()
        .map(|member| FactoryParticipantSignature {
            participant: member.participant,
            pubkey_sec1: member.pubkey_sec1.clone(),
            signature: vec![0; 64],
        })
        .collect()
}
fn point(tag: u8, index: u32) -> packed::OutPoint {
    packed::OutPoint::new_builder()
        .tx_hash([tag; 32].pack())
        .index(index)
        .build()
}
fn packed_point(point: &MultiAssetOutPoint) -> packed::OutPoint {
    packed::OutPoint::new_builder()
        .tx_hash(point.tx_hash.pack())
        .index(point.index)
        .build()
}
fn root_journal() -> (
    FactorySignerJournal,
    FactorySigningRequest,
    Vec<FactoryParticipantKey>,
) {
    let (request, members) = fixture();
    let mut journal =
        FactorySignerJournal::new_root(request.clone(), members.clone(), members[0].participant)
            .unwrap();
    let id = request.request_id().unwrap();
    journal.reserve_signature(&id).unwrap();
    for seed in [1, 2] {
        journal
            .record_signature(&id, signature(&request, seed))
            .unwrap();
    }
    let mut observed = request.target.clone().unwrap();
    observed.state_out_point = MultiAssetOutPoint {
        tx_hash: [91; 32],
        index: 0,
    };
    journal.confirm_request(&id, Some(observed)).unwrap();
    (journal, request, members)
}
fn wallet_lock() -> packed::Script {
    let (request, _) = fixture();
    request
        .raw_transaction()
        .unwrap()
        .outputs()
        .get(2)
        .unwrap()
        .lock()
}
fn metadata(
    source: &FactoryCustody,
    rights: &[FactoryRight],
    members: &[FactoryParticipantKey],
    number: u64,
    tag: u8,
) -> FactorySigningRequest {
    let mut after = source.state().unwrap().fields();
    after.update_number = number;
    after.access_manifest_root = [tag; 32];
    let header = after.encode().unwrap().to_vec();
    let output = packed::CellOutput::new_builder()
        .capacity(source.state_carrier_capacity)
        .lock(packed::Script::from_slice(&source.state_lock).unwrap())
        .type_(Some(packed::Script::from_slice(&source.state_type).unwrap()).pack())
        .build();
    let raw = packed::RawTransaction::new_builder()
        .inputs(
            vec![
                packed::CellInput::new_builder()
                    .previous_output(packed_point(&source.state_out_point))
                    .build(),
                packed::CellInput::new_builder()
                    .previous_output(point(tag, 0))
                    .build(),
            ]
            .pack(),
        )
        .outputs(
            vec![
                output,
                packed::CellOutput::new_builder()
                    .capacity(10_000_000_000u64)
                    .lock(wallet_lock())
                    .build(),
            ]
            .pack(),
        )
        .outputs_data(vec![Bytes::from(header.clone()).pack(), Bytes::new().pack()].pack())
        .build();
    let mut target = source.clone();
    target.header = header;
    target.state_out_point = MultiAssetOutPoint {
        tx_hash: raw.calc_tx_hash().unpack(),
        index: 0,
    };
    FactorySigningRequest {
        role: FactorySigningRole::MetadataUpdate,
        source: Some(source.clone()),
        target: Some(target),
        transaction: raw.as_slice().to_vec(),
        witness: encode_factory_multi_asset_state_witness(
            wire::FACTORY_STATE_WITNESS_UPDATE,
            &source.manifest,
            &source.vault_outpoints,
            &placeholders(members),
        )
        .unwrap(),
        target_rights: rights.to_vec(),
        deliveries: vec![],
    }
}
fn escape(
    source: &FactoryCustody,
    before_rights: &[FactoryRight],
    members: &[FactoryParticipantKey],
) -> FactorySigningRequest {
    assert_eq!(source.manifest.vaults.len(), 1);
    let owner = members[0].participant;
    let right = before_rights
        .iter()
        .find(|right| {
            right.id.participant == owner
                && right.id.kind == FactoryRightKind::ReserveClaim
                && right.id.asset_type.is_none()
        })
        .unwrap();
    let mut rights = before_rights.to_vec();
    rights
        .iter_mut()
        .find(|entry| entry.id == right.id)
        .unwrap()
        .quantity = 0;
    let capacity = u64::try_from(right.quantity).unwrap();
    let destination = wallet_lock();
    let reserve = asset::multi_asset_occupied_capacity(destination.as_slice(), None, 0).unwrap();
    let value = MultiAssetValue {
        reserve,
        business_ckb: capacity - reserve,
        amount: 0,
    };
    let mut retained = source.manifest.clone();
    retained.vaults[0].value.reserve -= value.reserve;
    retained.vaults[0].value.business_ckb -= value.business_ckb;
    let before = source.state().unwrap().fields();
    let after = wire::FactoryMultiAssetHeaderFields {
        update_number: before.update_number + 1,
        state_root: factory_right_sparse_root(&rights).unwrap(),
        content_root: retained.commitment().unwrap(),
        outpoint_root: [0; 32],
        ..before
    };
    let mut plan = FactoryMultiAssetReducedRelease {
        operation: FactoryTransitionOperation::ReducedRelease,
        before,
        after,
        members: members.to_vec(),
        signer_index: 0,
        old_state: source.state_out_point.clone(),
        transaction_hash: [1; 32],
        carrier_capacity: source.state_carrier_capacity,
        source: source.manifest.clone(),
        source_outpoints: source.vault_outpoints.clone(),
        retained: retained.clone(),
        factory_lock_script: source.vault_lock.clone(),
        type_scripts: source.type_scripts.clone(),
        payouts: vec![FactoryReducedReleasePayout {
            asset: VaultAsset::Ckb,
            value,
            lock_script: destination.as_slice().to_vec(),
            output_index: 2,
        }],
        rights: vec![FactoryReducedReleaseRight {
            before: factory_right_sparse_proof_compact(before_rights, &right.id).unwrap(),
            after: factory_right_sparse_proof_compact(&rights, &right.id).unwrap(),
        }],
        materialisation: None,
    };
    plan.set_locality_digest().unwrap();
    let state_output = packed::CellOutput::new_builder()
        .capacity(source.state_carrier_capacity)
        .lock(packed::Script::from_slice(&source.state_lock).unwrap())
        .type_(Some(packed::Script::from_slice(&source.state_type).unwrap()).pack())
        .build();
    let retained_output = packed::CellOutput::new_builder()
        .capacity(retained.vaults[0].value.capacity().unwrap())
        .lock(packed::Script::from_slice(&source.vault_lock).unwrap())
        .build();
    let raw = packed::RawTransaction::new_builder()
        .inputs(
            vec![
                packed::CellInput::new_builder()
                    .previous_output(packed_point(&source.state_out_point))
                    .build(),
                packed::CellInput::new_builder()
                    .previous_output(packed_point(&source.vault_outpoints[0]))
                    .build(),
                packed::CellInput::new_builder()
                    .previous_output(point(92, 0))
                    .build(),
            ]
            .pack(),
        )
        .outputs(
            vec![
                state_output,
                retained_output,
                packed::CellOutput::new_builder()
                    .capacity(capacity)
                    .lock(destination.clone())
                    .build(),
                packed::CellOutput::new_builder()
                    .capacity(10_000_000_000u64)
                    .lock(destination)
                    .build(),
            ]
            .pack(),
        )
        .outputs_data(
            vec![
                Bytes::from(plan.after.encode().unwrap().to_vec()).pack(),
                Bytes::new().pack(),
                Bytes::new().pack(),
                Bytes::new().pack(),
            ]
            .pack(),
        )
        .build();
    plan.transaction_hash = raw.calc_tx_hash().unpack();
    let points = vec![MultiAssetOutPoint {
        tx_hash: plan.transaction_hash,
        index: 1,
    }];
    let mut bound = plan.after;
    bound.outpoint_root = multi_asset_outpoint_commitment(&retained, &points).unwrap();
    let target = FactoryCustody {
        header: bound.encode().unwrap().to_vec(),
        state_out_point: MultiAssetOutPoint {
            tx_hash: plan.transaction_hash,
            index: 0,
        },
        manifest: retained,
        vault_outpoints: points,
        state_type: source.state_type.clone(),
        state_lock: source.state_lock.clone(),
        vault_lock: source.vault_lock.clone(),
        type_scripts: source.type_scripts.clone(),
        state_carrier_capacity: source.state_carrier_capacity,
    };
    FactorySigningRequest {
        role: FactorySigningRole::Transition,
        source: Some(source.clone()),
        target: Some(target),
        transaction: raw.as_slice().to_vec(),
        witness: plan.encode_unsigned().unwrap(),
        target_rights: rights,
        deliveries: vec![],
    }
}
fn authorized_transaction(
    request: &FactorySigningRequest,
    authorization: &[FactoryParticipantSignature],
) -> packed::Transaction {
    let frame = request.authorized_witness(authorization).unwrap();
    let witness = match request.role {
        FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
            packed::WitnessArgs::new_builder()
                .input_type(Some(Bytes::from(frame)).pack())
                .build()
        }
        _ => packed::WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(frame)).pack())
            .build(),
    };
    packed::Transaction::new_builder()
        .raw(request.raw_transaction().unwrap())
        .witnesses(vec![witness.as_bytes().pack()].pack())
        .build()
}

#[test]
fn root_journal_reserves_before_key_and_never_resets_root_authority() {
    let (request, members) = fixture();
    request.validate(&members).unwrap();
    let mut alice =
        FactorySignerJournal::new_root(request.clone(), members.clone(), members[0].participant)
            .unwrap();
    let id = request.request_id().unwrap();
    assert_eq!(
        alice.record_signature(&id, signature(&request, 1)),
        Err(FactoryBackendError::UnreservedSignature)
    );
    let reservation = alice.reserve_signature(&id).unwrap();
    assert_eq!(reservation.sequence, 1);
    let mut alice: FactorySignerJournal =
        serde_json::from_slice(&serde_json::to_vec(&alice).unwrap()).unwrap();
    assert_eq!(alice.reserve_signature(&id).unwrap(), reservation);
    assert_eq!(
        alice.cancel_request(&id),
        Err(FactoryBackendError::ConflictingVote)
    );
    alice.record_signature(&id, signature(&request, 1)).unwrap();
    assert_eq!(
        alice.authorized_witness(&id),
        Err(FactoryBackendError::IncompleteSignatures)
    );
    alice.record_signature(&id, signature(&request, 2)).unwrap();
    let transaction = authorized_transaction(&request, alice.signatures(&id).unwrap());
    request.verify_authorized_transaction(&transaction).unwrap();
    let mut altered = request.clone();
    let raw = altered.raw_transaction().unwrap();
    altered.transaction = raw
        .as_builder()
        .header_deps(vec![[44; 32].pack()].pack())
        .build()
        .as_slice()
        .to_vec();
    assert_eq!(
        alice.prepare_replacement(&id, altered),
        Err(FactoryBackendError::WrongContext)
    );
    assert!(
        alice.current().is_none(),
        "signing or exporting is not canonical inclusion"
    );
}

#[test]
fn withheld_full_n_approval_does_not_prevent_explicit_unilateral_escape() {
    let (mut journal, _, members) = root_journal();
    let source = journal.current().unwrap().clone();
    let rights = journal.current_rights().unwrap().to_vec();
    let full = metadata(&source, &rights, &members, 1, 93);
    let id = journal.prepare_request(full.clone()).unwrap();
    journal.reserve_signature(&id).unwrap();
    journal.record_signature(&id, signature(&full, 1)).unwrap();
    assert_eq!(
        journal.authorized_witness(&id),
        Err(FactoryBackendError::IncompleteSignatures)
    );
    let reduced = escape(&source, &rights, &members);
    reduced.validate(&members).unwrap();
    assert_eq!(
        journal.prepare_request(reduced.clone()),
        Err(FactoryBackendError::ConflictingVote)
    );
    let replacement = journal.prepare_replacement(&id, reduced.clone()).unwrap();
    let escape_vote = journal.reserve_signature(&replacement).unwrap();
    assert_eq!(escape_vote.sequence, 3);
    journal
        .record_signature(&replacement, signature(&reduced, 1))
        .unwrap();
    let mut journal: FactorySignerJournal =
        serde_json::from_slice(&serde_json::to_vec(&journal).unwrap()).unwrap();
    let transaction = authorized_transaction(&reduced, journal.signatures(&replacement).unwrap());
    FactoryTransactionView::parse(transaction.as_slice())
        .unwrap()
        .validate_against(&source)
        .unwrap();
    assert_eq!(
        journal
            .source_authorizations(&source.state_out_point)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(journal.current(), Some(&source));
    // The withholding peer may still complete the original approval later.
    journal.record_signature(&id, signature(&full, 2)).unwrap();
    let competing = authorized_transaction(&full, journal.signatures(&id).unwrap());
    full.verify_authorized_transaction(&competing).unwrap();
    assert_eq!(
        transaction.raw().inputs().get(0).unwrap().previous_output(),
        competing.raw().inputs().get(0).unwrap().previous_output(),
        "the two valid alternatives spend the same exact CKB UTXO; neither revokes the other and only one can be canonical"
    );
    let mut observed = reduced.target.clone().unwrap();
    observed.state_out_point = MultiAssetOutPoint {
        tx_hash: [94; 32],
        index: 0,
    };
    journal
        .confirm_request(&replacement, Some(observed.clone()))
        .unwrap();
    assert_eq!(journal.current(), Some(&observed));
    assert!(
        journal.authorized_witness(&id).is_ok(),
        "historical evidence remains exportable after confirmation"
    );
}

#[test]
fn source_reorg_changes_context_but_reappearance_keeps_all_old_votes() {
    let (mut journal, _, members) = root_journal();
    let original = journal.current().unwrap().clone();
    let rights = journal.current_rights().unwrap().to_vec();
    let first = metadata(&original, &rights, &members, 1, 95);
    let first_id = journal.prepare_request(first.clone()).unwrap();
    journal.reserve_signature(&first_id).unwrap();
    journal
        .record_signature(&first_id, signature(&first, 1))
        .unwrap();
    let mut replacement_source = original.clone();
    replacement_source.state_out_point = MultiAssetOutPoint {
        tx_hash: [96; 32],
        index: 0,
    };
    journal
        .observe_canonical(replacement_source.clone(), rights.clone())
        .unwrap();
    let second = metadata(&replacement_source, &rights, &members, 1, 97);
    let second_id = journal.prepare_request(second).unwrap();
    assert_eq!(journal.reserve_signature(&second_id).unwrap().sequence, 3);
    journal
        .observe_canonical(original.clone(), rights.clone())
        .unwrap();
    let changed_number = metadata(&original, &rights, &members, 2, 98);
    assert_eq!(
        journal.prepare_request(changed_number),
        Err(FactoryBackendError::ConflictingVote)
    );
    assert_eq!(journal.prepare_request(first).unwrap(), first_id);
    assert_eq!(journal.reserve_signature(&first_id).unwrap().sequence, 2);
    let mut changed_cell = original;
    changed_cell.state_carrier_capacity += 1;
    assert_eq!(
        journal.observe_canonical(changed_cell, rights),
        Err(FactoryBackendError::InvalidCustody)
    );
}

#[test]
fn current_factory_view_checks_all_five_vm_exported_classes() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/factory-transitions.json"
    ))
    .unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let bytes = hex::decode(
            case["package"]["transaction_hex"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let view = FactoryTransactionView::parse(&bytes).unwrap();
        assert_eq!(
            view.witness().unwrap().transaction_hash(),
            view.transaction().calc_tx_hash().as_slice()
        );
        let raw = view.transaction().raw();
        let mut output = raw.outputs().get(0).unwrap();
        output = output
            .clone()
            .as_builder()
            .capacity(u64::from(output.capacity()) + 1)
            .build();
        let mut outputs: Vec<_> = raw.outputs().into_iter().collect();
        outputs[0] = output;
        let mutated = view
            .transaction()
            .clone()
            .as_builder()
            .raw(raw.as_builder().outputs(outputs.pack()).build())
            .build();
        assert!(
            FactoryTransactionView::parse(mutated.as_slice()).is_err(),
            "even freshly serialized bodies must match the signed exact TX"
        );
    }
}

#[test]
fn current_root_rights_budget_counts_convertible_kinds_but_excludes_carrier() {
    let (request, members) = fixture();
    let target = request.target.as_ref().unwrap();
    let mut rights = request.target_rights.clone();
    let mut duplicate = rights[0].clone();
    duplicate.id.kind = FactoryRightKind::Balance;
    rights.push(duplicate);
    rights.sort_by(|a, b| a.id.cmp(&b.id));
    assert!(validate_factory_initial_rights(&members, &target.manifest, &rights).is_ok());
    let mut over = rights.clone();
    over.iter_mut()
        .find(|entry| entry.id.kind == FactoryRightKind::Balance)
        .unwrap()
        .quantity = 100_000_000_000;
    assert_eq!(
        validate_factory_initial_rights(&members, &target.manifest, &over),
        Err(FactoryBackendError::InvalidRights)
    );
    let mut unknown = rights[0].clone();
    unknown.id.asset_type = Some([81; 32]);
    unknown.quantity = 0;
    rights.push(unknown.clone());
    rights.sort_by(|a, b| a.id.cmp(&b.id));
    validate_factory_initial_rights(&members, &target.manifest, &rights).unwrap();
    rights
        .iter_mut()
        .find(|entry| entry.id == unknown.id)
        .unwrap()
        .quantity = 1;
    assert_eq!(
        validate_factory_initial_rights(&members, &target.manifest, &rights),
        Err(FactoryBackendError::InvalidRights)
    );
}

#[test]
fn factory_snapshot_validates_members_current_custody_votes_and_exact_receipts() {
    let (mut journal, request, members) = root_journal();
    let source = journal.current().unwrap().clone();
    let rights = journal.current_rights().unwrap().to_vec();
    let pending = metadata(&source, &rights, &members, 1, 99);
    let id = journal.prepare_request(pending.clone()).unwrap();
    journal.reserve_signature(&id).unwrap();
    journal
        .record_signature(&id, signature(&pending, 1))
        .unwrap();
    let pristine = serde_json::to_value(&journal).unwrap();
    for field in ["current", "active_request"] {
        let mut missing = pristine.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<FactorySignerJournal>(missing).is_err());
    }
    let mut invalid = pristine.clone();
    invalid["requests"][1]["reservation_sequence"] = serde_json::json!(1);
    assert!(serde_json::from_value::<FactorySignerJournal>(invalid).is_err());
    let mut invalid = pristine.clone();
    invalid["requests"][1]["signatures"][0]["signature"][0] = serde_json::json!(0);
    assert!(serde_json::from_value::<FactorySignerJournal>(invalid).is_err());
    let root_id = request.request_id().unwrap();
    let transaction = authorized_transaction(&request, journal.signatures(&root_id).unwrap());
    let mut witness =
        packed::WitnessArgs::from_slice(&transaction.witnesses().get(0).unwrap().raw_data())
            .unwrap();
    witness = witness
        .as_builder()
        .output_type(Some(Bytes::from(vec![1])).pack())
        .build();
    let wrong_role = transaction
        .as_builder()
        .witnesses(vec![witness.as_bytes().pack()].pack())
        .build();
    assert_eq!(
        request.verify_authorized_transaction(&wrong_role),
        Err(FactoryBackendError::WrongRole)
    );
}

#[test]
fn child_parent_vote_requires_both_private_delivery_attestations_without_exposing_exits() {
    let (mut request, members, rights, children) = support::reduced_child_request();
    request.validate_for_review(&members).unwrap();
    assert_eq!(request.missing_delivery_receipts().unwrap().len(), 2);
    assert_eq!(
        request.validate(&members),
        Err(FactoryBackendError::InvalidDelivery)
    );
    let mut journal = FactorySignerJournal::from_confirmed(
        request.source.clone().unwrap(),
        rights,
        members.clone(),
        members[0].participant,
    )
    .unwrap();
    assert_eq!(
        journal.prepare_request(request.clone()),
        Err(FactoryBackendError::InvalidDelivery)
    );
    assert!(journal.active_request_id().is_none());
    for seed in [1, 2] {
        let receipt =
            FactoryChildDeliveryReceipt::new_signed(&request, 0, &children[0], &key(seed)).unwrap();
        receipt.verify(&request).unwrap();
        request.deliveries.push(receipt);
    }
    assert!(request.missing_delivery_receipts().unwrap().is_empty());
    request.validate(&members).unwrap();
    let public = serde_json::to_string(&request).unwrap();
    for signature in &children[0].authorization.signatures {
        assert!(
            !public.contains(&serde_json::to_string(&signature.signature).unwrap()),
            "parent packet must not disclose a publishable child exit signature"
        );
    }
    let id = journal.prepare_request(request.clone()).unwrap();
    journal.reserve_signature(&id).unwrap();
    journal
        .record_signature(&id, signature(&request, 1))
        .unwrap();
    request
        .verify_authorized_transaction(&authorized_transaction(
            &request,
            journal.signatures(&id).unwrap(),
        ))
        .unwrap();
    let duplicate = request.deliveries[0].clone();
    request.deliveries[1] = duplicate;
    assert_eq!(
        request.validate_for_review(&members),
        Err(FactoryBackendError::InvalidDelivery)
    );
}

#[test]
fn delivery_signer_rejects_missing_wrong_or_invalid_private_recovery_before_attesting() {
    let (request, _, _, children) = support::reduced_child_request();
    let mut wrong = children[0].clone();
    wrong.authorization.signatures.pop();
    assert!(FactoryChildDeliveryReceipt::new_signed(&request, 0, &wrong, &key(1)).is_err());
    let mut wrong = children[0].clone();
    wrong.authorization.signatures[0].signature[0] ^= 1;
    assert!(FactoryChildDeliveryReceipt::new_signed(&request, 0, &wrong, &key(1)).is_err());
    assert_eq!(
        FactoryChildDeliveryReceipt::new_signed(&request, 0, &children[0], &key(3)),
        Err(FactoryBackendError::InvalidDelivery)
    );
    let receipt =
        FactoryChildDeliveryReceipt::new_signed(&request, 0, &children[0], &key(1)).unwrap();
    let mut changed = request.clone();
    let raw = changed.raw_transaction().unwrap();
    changed.transaction = raw
        .as_builder()
        .header_deps(vec![[88; 32].pack()].pack())
        .build()
        .as_slice()
        .to_vec();
    assert!(
        receipt.verify(&changed).is_err(),
        "delivery cannot replay across exact transactions"
    );
}

#[test]
fn child_possession_receipts_cannot_replace_parent_votes_or_cross_child_identity() {
    let (request, members, _, children) = support::reduced_child_request();
    let receipt =
        FactoryChildDeliveryReceipt::new_signed(&request, 0, &children[0], &key(1)).unwrap();
    receipt.verify(&request).unwrap();
    request
        .verify_participant_signature(&signature(&request, 1))
        .unwrap();
    // The fixture deliberately reuses one key in the child and parent roles;
    // domain separation, rather than different keys, must reject substitution.
    let parent = members
        .iter()
        .find(|member| member.pubkey_sec1 == receipt.pubkey_sec1)
        .unwrap();
    assert_eq!(
        request.verify_participant_signature(&FactoryParticipantSignature {
            participant: parent.participant,
            pubkey_sec1: receipt.pubkey_sec1.clone(),
            signature: receipt.signature.clone(),
        }),
        Err(FactoryBackendError::InvalidSignature)
    );
    let mut wrong_child = receipt.clone();
    wrong_child.child_index = 1;
    assert!(wrong_child.verify(&request).is_err());
    let mut wrong_recipient = receipt;
    wrong_recipient.pubkey_sec1 = key(2)
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(
        wrong_recipient.verify(&request),
        Err(FactoryBackendError::InvalidSignature)
    );
}

#[test]
fn factory_child_public_fixture_matches_current_rust_vm_terms() {
    let (request, _, _, _) = support::reduced_child_request();
    let child = request.public_child(0).unwrap();
    let expected = request.expected_child_recovery(0).unwrap();
    let encode = |raw: &[u8]| format!("0x{}", hex::encode(raw));
    let value = serde_json::json!({
        "schema": "morph.factory_child_public_terms_fixture.v1",
        "provenance": "Public terms extracted with Rust current codecs from the VM-qualified ReducedChild corpus; no private child authorization.",
        "header_hex": encode(child.header.as_bytes()),
        "witness_hex": encode(child.evidence.as_bytes()),
        "state_carrier_capacity": child.carrier_capacity.to_string(),
        "participants": expected.authorization.signatures.iter().map(|member|encode(&member.pubkey_sec1)).collect::<Vec<_>>(),
        "state_type_script_hex": encode(&expected.scripts.state_type),
        "factory_origin": encode(&expected.scripts.state_type[85..117]),
        "since": morph_script_common::multi_asset::MultiAssetVaultArgs::parse(&expected.scripts.vault_lock[53..]).unwrap().finalise_since().to_string(),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/protocol/factory-child-public-exit.json");
    if std::env::var("MORPH_UPDATE_FIXTURES").as_deref() == Ok("1") {
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(saved, value);
}
