use std::collections::BTreeSet;

use super::*;

fn engine() -> MultiAssetChannelBackend {
    MultiAssetChannelBackend::new(fixture(2), participant_pubkey(1)).unwrap()
}

fn payments(backend: &MultiAssetChannelBackend) -> ChannelPayments {
    ChannelPayments::new(
        backend,
        [1, 2].map(|key| ChannelParticipant {
            node_id: blake2b256(&participant_pubkey(key)),
            settlement_lock_hash: backend.current().settlement.participant_lock_hashes
                [usize::from(key - 1)],
        }),
        BTreeSet::new(),
    )
    .unwrap()
}

fn intent(
    payments: &ChannelPayments,
    backend: &MultiAssetChannelBackend,
    ckb: bool,
    amount: u128,
) -> PaymentIntent {
    let mut intent = PaymentIntent {
        intent_id: [0; 32],
        payer: blake2b256(&participant_pubkey(1)),
        payee: blake2b256(&participant_pubkey(2)),
        asset: if ckb {
            AgentAsset::Ckb {
                ckb_genesis_hash: backend.current().state.header.chain_id,
            }
        } else {
            let VaultAsset::Xudt(type_hash) = backend.current().manifest.vaults[0].asset else {
                panic!("typed test fixture")
            };
            AgentAsset::Xudt {
                ckb_genesis_hash: backend.current().state.header.chain_id,
                type_script_hash: type_hash,
            }
        },
        amount,
        payment_hash: [8; 32],
        hash_algorithm: PaymentHashAlgorithm::CkbBlake2b,
        resource: "/content".into(),
        operation: HttpOperation::Get,
        nonce: [9; 32],
        idempotency_key: [10; 32],
        created_at_unix: 100,
        expires_at_unix: 200,
        required_rgbpp_proof_commitment: None,
        channel_binding: Some(MorphChannelPaymentBinding {
            channel_id: backend.current().state.header.channel_id,
            funding_context_id: backend.current().state.funding_context_id().unwrap(),
            expected_settlement_descriptor_commitment: [1; 32],
        }),
    };
    intent
        .channel_binding
        .as_mut()
        .unwrap()
        .expected_settlement_descriptor_commitment = payments
        .payment_settlement(backend, &intent)
        .unwrap()
        .commitment()
        .unwrap();
    intent.intent_id = intent.derive_id().unwrap();
    intent
}

fn authorize(
    payments: &ChannelPayments,
    backend: &mut MultiAssetChannelBackend,
    prepared: &PreparedChannelPayment,
) {
    payments
        .reserve_payment_signature(backend, &prepared.prepared_id, 150)
        .unwrap();
    // Exercise the caller's durable boundary without creating another signer.
    *backend = serde_json::from_slice(&serde_json::to_vec(backend).unwrap()).unwrap();
    for key in [1, 2] {
        payments
            .record_payment_signature(
                backend,
                &prepared.prepared_id,
                proposal_signature(&prepared.proposal, key),
            )
            .unwrap();
    }
}

#[test]
fn payment_moves_only_selected_type_and_commits_exact_recovery() {
    let mut backend = engine();
    let before = backend.current().clone();
    let mut book = payments(&backend);
    let intent = intent(&book, &backend, false, 20);
    let prepared = book
        .prepare_payment(&mut backend, intent.clone(), 110)
        .unwrap();
    assert_eq!(
        book.prepare_payment(&mut backend, intent, 111).unwrap(),
        prepared
    );
    let new = &prepared.proposal.settlement;
    assert_eq!(new.payouts[0].values[0].amount, 680);
    assert_eq!(new.payouts[0].values[1].amount, 320);
    assert_eq!(new.payouts[1], before.settlement.payouts[1]);
    for i in 0..2 {
        assert_eq!(
            new.payouts[0].values[i].reserve,
            before.settlement.payouts[0].values[i].reserve
        );
        assert_eq!(
            new.payouts[0].values[i].business_ckb,
            before.settlement.payouts[0].values[i].business_ckb
        );
    }
    assert_eq!(
        book.commit_payment(&mut backend, &prepared.prepared_id, 120),
        Err(PaymentError::Agreement(
            MultiAssetBackendError::IncompleteSignatures
        ))
    );
    assert_eq!(backend.current(), &before);
    authorize(&book, &mut backend, &prepared);
    let evidence = book
        .commit_payment(&mut backend, &prepared.prepared_id, 151)
        .unwrap();
    assert_eq!(backend.current().manifest, before.manifest);
    assert_eq!(backend.current().outpoints, before.outpoints);
    assert_eq!(backend.current().scripts, before.scripts);
    assert_eq!(
        backend.current().state_carrier_capacity,
        before.state_carrier_capacity
    );
    assert_eq!(backend.current().state, prepared.proposal.state);
    backend.current().validate().unwrap();
    assert_eq!(
        evidence
            .morph_state
            .as_ref()
            .unwrap()
            .state_header_commitment,
        backend.current().state.signing_digest().unwrap()
    );
    assert_eq!(
        book.commit_payment(&mut backend, &prepared.prepared_id, 999)
            .unwrap(),
        evidence
    );
    assert!(matches!(
        book.cancel_payment(&mut backend, &prepared.prepared_id, 999),
        Err(PaymentError::AlreadyTerminal)
    ));
}

#[test]
fn ckb_payment_uses_business_value_across_typed_vaults_without_touching_reserve() {
    let mut backend = engine();
    let original = backend.current().settlement.clone();
    let mut book = payments(&backend);
    let intent = intent(&book, &backend, true, 8_000_000_000);
    let prepared = book.prepare_payment(&mut backend, intent, 110).unwrap();
    let result = &prepared.proposal.settlement;
    assert_eq!(result.payouts[0].values[0].business_ckb, 0);
    assert_eq!(result.payouts[1].values[0].business_ckb, 4_000_000_000);
    assert_eq!(result.payouts[0].values[1].business_ckb, 10_000_000_000);
    assert_eq!(result.payouts[1].values[1].business_ckb, 6_000_000_000);
    for (before, after) in original.payouts.iter().zip(&result.payouts) {
        for i in 0..2 {
            assert_eq!(before.values[i].reserve, after.values[i].reserve);
            assert_eq!(before.values[i].amount, after.values[i].amount);
        }
    }
    authorize(&book, &mut backend, &prepared);
    book.commit_payment(&mut backend, &prepared.prepared_id, 160)
        .unwrap();
    backend.current().validate().unwrap();
}

#[test]
fn idempotency_binds_the_complete_intent_and_wrong_binding_has_no_side_effects() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let mut first = intent(&book, &backend, false, 20);
    first
        .channel_binding
        .as_mut()
        .unwrap()
        .expected_settlement_descriptor_commitment = [9; 32];
    first.intent_id = first.derive_id().unwrap();
    let unchanged = backend.clone();
    assert_eq!(
        book.prepare_payment(&mut backend, first, 110),
        Err(PaymentError::WrongBinding)
    );
    assert_eq!(backend, unchanged);
    let first = intent(&book, &backend, false, 20);
    book.prepare_payment(&mut backend, first, 110).unwrap();
    let different = intent(&book, &backend, false, 30);
    assert_eq!(
        book.prepare_payment(&mut backend, different, 110),
        Err(PaymentError::IdempotencyConflict)
    );
}

#[test]
fn cancellation_is_idempotent_only_before_authorization_and_never_resets_a_vote() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    let prepared = book.prepare_payment(&mut backend, payment, 110).unwrap();
    let evidence = book
        .cancel_payment(&mut backend, &prepared.prepared_id, 210)
        .unwrap();
    assert!(evidence.morph_state.is_none());
    assert!(backend.proposal().is_none());
    assert_eq!(
        book.cancel_payment(&mut backend, &prepared.prepared_id, 999)
            .unwrap(),
        evidence
    );

    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    let prepared = book.prepare_payment(&mut backend, payment, 110).unwrap();
    book.reserve_payment_signature(&mut backend, &prepared.prepared_id, 150)
        .unwrap();
    let reservation = backend.reservation().clone();
    let mut restored: ChannelPayments =
        serde_json::from_slice(&serde_json::to_vec(&book).unwrap()).unwrap();
    let mut backend: MultiAssetChannelBackend =
        serde_json::from_slice(&serde_json::to_vec(&backend).unwrap()).unwrap();
    assert_eq!(
        restored.cancel_payment(&mut backend, &prepared.prepared_id, 999),
        Err(PaymentError::AuthorizationMayExist)
    );
    assert_eq!(backend.reservation(), &reservation);
    assert_eq!(backend.proposal(), Some(&prepared.proposal));
}

#[test]
fn expiry_stops_new_authorization_but_cannot_revoke_an_issued_state_signature() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    let prepared = book.prepare_payment(&mut backend, payment, 110).unwrap();
    assert_eq!(
        book.reserve_payment_signature(&mut backend, &prepared.prepared_id, 200),
        Err(PaymentError::Agent(AgentError::Expired))
    );
    authorize(&book, &mut backend, &prepared);
    assert_eq!(
        book.cancel_payment(&mut backend, &prepared.prepared_id, 210),
        Err(PaymentError::AuthorizationMayExist)
    );
    book.commit_payment(&mut backend, &prepared.prepared_id, 210)
        .unwrap();
    assert_eq!(backend.current().state, prepared.proposal.state);
}

#[test]
fn lost_metadata_commit_recovers_exact_engine_result_without_resigning() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    let prepared = book.prepare_payment(&mut backend, payment, 110).unwrap();
    authorize(&book, &mut backend, &prepared);
    backend.commit().unwrap();
    let vote = backend.reservation().clone();
    let mut book: ChannelPayments =
        serde_json::from_slice(&serde_json::to_vec(&book).unwrap()).unwrap();
    book.commit_payment(&mut backend, &prepared.prepared_id, 210)
        .unwrap();
    assert_eq!(backend.reservation(), &vote);
    assert!(matches!(
        book.payment_state(&prepared.intent.intent_id),
        Some(ChannelPaymentState::Settled { .. })
    ));
}

#[test]
fn changed_proposal_and_peer_signature_cannot_be_cancelled_or_misreported() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    let prepared = book.prepare_payment(&mut backend, payment, 110).unwrap();
    book.record_payment_signature(
        &mut backend,
        &prepared.prepared_id,
        proposal_signature(&prepared.proposal, 2),
    )
    .unwrap();
    assert_eq!(
        book.cancel_payment(&mut backend, &prepared.prepared_id, 120),
        Err(PaymentError::AuthorizationMayExist)
    );
    backend.cancel_proposal();
    let mut other = backend.current().settlement.clone();
    other.payouts[1].values[0].amount -= 10;
    other.payouts[1].values[1].amount += 10;
    backend.propose(other).unwrap();
    assert_eq!(
        book.commit_payment(&mut backend, &prepared.prepared_id, 130),
        Err(PaymentError::StalePreparation)
    );
    assert_eq!(
        book.reserve_payment_signature(&mut backend, &prepared.prepared_id, 130),
        Err(PaymentError::StalePreparation)
    );
}

#[test]
fn payment_book_rejects_malformed_snapshot_and_wrong_funding_authority() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    book.prepare_payment(&mut backend, payment, 110).unwrap();
    let mut snapshot = serde_json::to_value(&book).unwrap();
    let payment = snapshot["payments"]
        .as_array_mut()
        .unwrap()
        .first_mut()
        .unwrap();
    payment["prepared"]["payment"]["prepared_id"][0] = serde_json::json!(99);
    assert!(serde_json::from_value::<ChannelPayments>(snapshot).is_err());
    let mut other = backend.current().clone();
    other.state.header.channel_id = [99; 32];
    sign(&mut other);
    let other = MultiAssetChannelBackend::new(other, participant_pubkey(1)).unwrap();
    assert_eq!(book.validate(&other), Err(PaymentError::WrongBinding));
}

#[test]
fn ordinary_payment_refuses_to_modify_an_armed_conditional_allocation() {
    let ordinary = engine();
    let ordinary_book = payments(&ordinary);
    let mut payment = intent(&ordinary_book, &ordinary, true, 20);
    let mut package = fixture(1);
    package.manifest.vaults[0].asset = VaultAsset::Ckb;
    package.manifest.vaults[0].value.amount = 0;
    package.settlement.payouts[0].asset = VaultAsset::Ckb;
    package.scripts.type_scripts.clear();
    for value in &mut package.settlement.payouts[0].values {
        value.amount = 0;
    }
    package.settlement.payouts[0].values[0].business_ckb -= 1_000_000_000;
    package.settlement.capability = MultiAssetSettlementCapability::CkbConditional {
        batch_code_hash: [31; 32],
        batch_hash_type: 2,
        batch: Box::new(ConditionalBatch {
            batch_id: [11; 32],
            application_context_commitment: [12; 32],
            participants: [0, 1].map(|index| ConditionalParticipant {
                settlement_lock_hash: package.settlement.participant_lock_hashes[index],
                settled_capacity: package.settlement.payouts[0].values[index]
                    .capacity()
                    .unwrap(),
            }),
            transfers: vec![ConditionalTransferSpec {
                transfer_id: [13; 32],
                payer_lock_hash: package.settlement.participant_lock_hashes[0],
                hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                payment_hash: blake2b256(&[14; 32]),
                amount: 1_000_000_000,
                refund_after_block: 500,
            }],
        }),
    };
    package.state.vault_content_set_root = package.manifest.commitment().unwrap();
    package.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
    package.state.header.asset_registry_commitment =
        asset_registry_commitment(&package.manifest.registry().unwrap());
    package.state.header.settlement_descriptor_commitment =
        package.settlement.commitment().unwrap();
    sign(&mut package);
    package.validate().unwrap();
    let mut backend = MultiAssetChannelBackend::new(package, participant_pubkey(1)).unwrap();
    let mut book = payments(&backend);
    payment.channel_binding.as_mut().unwrap().funding_context_id =
        backend.current().state.funding_context_id().unwrap();
    payment.intent_id = payment.derive_id().unwrap();
    assert_eq!(
        book.prepare_payment(&mut backend, payment, 110),
        Err(PaymentError::ConditionalLifecycleRequired)
    );
    assert!(backend.proposal().is_none());
}

#[test]
fn payment_network_identity_and_overflow_fail_before_signing() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let mut wrong_network = intent(&book, &backend, false, 20);
    match &mut wrong_network.asset {
        AgentAsset::Xudt {
            ckb_genesis_hash, ..
        } => *ckb_genesis_hash = [99; 32],
        _ => unreachable!(),
    }
    wrong_network.intent_id = wrong_network.derive_id().unwrap();
    assert_eq!(
        book.prepare_payment(&mut backend, wrong_network, 110),
        Err(PaymentError::WrongNetwork)
    );
    let mut overflow = intent(&book, &backend, false, 20);
    overflow.amount = u128::MAX;
    overflow.intent_id = overflow.derive_id().unwrap();
    assert_eq!(
        book.prepare_payment(&mut backend, overflow, 110),
        Err(PaymentError::InsufficientBalance)
    );
    assert!(backend.proposal().is_none());
    assert!(
        ChannelPayments::new(
            &backend,
            [1, 2].map(|key| ChannelParticipant {
                node_id: [key; 32],
                settlement_lock_hash: backend.current().settlement.participant_lock_hashes
                    [usize::from(key - 1)],
            }),
            BTreeSet::new()
        )
        .is_err()
    );
    let mut bad_registry = backend.current().clone();
    bad_registry.state.header.asset_registry_commitment = [99; 32];
    sign(&mut bad_registry);
    assert!(MultiAssetChannelBackend::new(bad_registry, participant_pubkey(1)).is_err());
}

#[test]
fn an_unrelated_preexisting_vote_cannot_be_relabelled_as_a_new_payment() {
    let mut backend = engine();
    let mut book = payments(&backend);
    let payment = intent(&book, &backend, false, 20);
    let settlement = book.payment_settlement(&backend, &payment).unwrap();
    backend.propose(settlement).unwrap();
    assert_eq!(
        book.prepare_payment(&mut backend, payment.clone(), 110),
        Err(PaymentError::UnresolvedAuthority)
    );
    backend.reserve_signature().unwrap();
    backend.cancel_proposal();
    assert_eq!(
        book.prepare_payment(&mut backend, payment, 110),
        Err(PaymentError::UnresolvedAuthority)
    );
}
