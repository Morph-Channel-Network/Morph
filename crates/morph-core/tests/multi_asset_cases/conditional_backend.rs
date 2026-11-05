use super::*;

pub(super) fn engine() -> MultiAssetChannelBackend {
    let mut package = fixture(2);
    let removed_type = package.manifest.vaults[0].asset.clone();
    package.manifest.vaults[0].asset = VaultAsset::Ckb;
    package.manifest.vaults[0].value.amount = 0;
    package.settlement.payouts[0].asset = VaultAsset::Ckb;
    for value in &mut package.settlement.payouts[0].values {
        value.amount = 0;
    }
    package
        .scripts
        .type_scripts
        .retain(|entry| VaultAsset::Xudt(entry.type_hash) != removed_type);
    package.state.vault_content_set_root = package.manifest.commitment().unwrap();
    package.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
    package.state.header.asset_registry_commitment =
        asset_registry_commitment(&package.manifest.registry().unwrap());
    package.state.header.settlement_descriptor_commitment =
        package.settlement.commitment().unwrap();
    sign(&mut package);
    package.validate().unwrap();
    MultiAssetChannelBackend::new(package, participant_pubkey(1)).unwrap()
}

fn batch(backend: &MultiAssetChannelBackend) -> ConditionalBatch {
    let locks = backend.current().settlement.participant_lock_hashes;
    let context = [81; 32];
    ConditionalBatch {
        batch_id: derive_conditional_batch_id(
            &backend.current().state.header.channel_id,
            &backend.current().state.funding_context_id().unwrap(),
            backend.current().state.header.state_number + 1,
            &context,
        ),
        application_context_commitment: context,
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: locks[0],
                settled_capacity: 25_000_000_000,
            },
            ConditionalParticipant {
                settlement_lock_hash: locks[1],
                settled_capacity: 23_500_000_000,
            },
        ],
        transfers: vec![
            ConditionalTransferSpec {
                transfer_id: [1; 32],
                payer_lock_hash: locks[0],
                hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                payment_hash: blake2b256(&[61; 32]),
                amount: 1_000_000_000,
                refund_after_block: 120,
            },
            ConditionalTransferSpec {
                transfer_id: [2; 32],
                payer_lock_hash: locks[1],
                hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                payment_hash: blake2b256(&[62; 32]),
                amount: 500_000_000,
                refund_after_block: 130,
            },
        ],
    }
}

fn authorize(backend: &mut MultiAssetChannelBackend, proposal: &MultiAssetProposal) {
    backend.reserve_signature().unwrap();
    for key in [1, 2] {
        backend
            .record_signature(proposal_signature(proposal, key))
            .unwrap();
    }
}

pub(super) fn arm(
    backend: &mut MultiAssetChannelBackend,
    service: &mut ChannelConditionalBatches,
) -> ConditionalBatch {
    let batch = batch(backend);
    let proposal = service
        .prepare_conditional_batch(backend, batch.clone(), [31; 32], 2, 100)
        .unwrap();
    authorize(backend, &proposal);
    service.commit_change(backend).unwrap();
    batch
}

#[test]
fn conditional_service_arms_via_shared_signer_and_preserves_unrelated_assets() {
    let mut backend = engine();
    let before = backend.current().clone();
    let mut service = ChannelConditionalBatches::new(&backend).unwrap();
    let batch = batch(&backend);
    let proposal = service
        .prepare_conditional_batch(&mut backend, batch.clone(), [31; 32], 2, 100)
        .unwrap();
    assert_eq!(
        service.commit_change(&mut backend),
        Err(ConditionalBackendError::Agreement(
            MultiAssetBackendError::IncompleteSignatures
        ))
    );
    assert_eq!(backend.current(), &before);
    authorize(&mut backend, &proposal);
    service.commit_change(&mut backend).unwrap();
    backend.current().validate().unwrap();
    assert_eq!(backend.current().manifest, before.manifest);
    assert_eq!(backend.current().outpoints, before.outpoints);
    assert_eq!(backend.current().scripts, before.scripts);
    assert_eq!(
        backend.current().settlement.payouts[1],
        before.settlement.payouts[1]
    );
    for index in 0..2 {
        assert_eq!(
            backend.current().settlement.payouts[0].values[index].reserve,
            before.settlement.payouts[0].values[index].reserve
        );
    }
    assert_eq!(
        service
            .conditional_batch(&batch.batch_id)
            .unwrap()
            .lifecycle,
        ConditionalBatchLifecycle::Armed
    );
    assert_eq!(
        service.prepare_conditional_batch(&mut backend, batch.clone(), [31; 32], 2, 100),
        Err(ConditionalBackendError::BatchActive)
    );
}

#[test]
fn conditional_service_resolves_preimages_and_mature_refunds_without_peer_signature() {
    let mut backend = engine();
    let mut service = ChannelConditionalBatches::new(&backend).unwrap();
    let batch = arm(&mut backend, &mut service);
    assert_eq!(
        service.learn_conditional_preimage(&batch.batch_id, &[1; 32], [99; 32]),
        Err(ConditionalBackendError::WrongPreimage)
    );
    service
        .learn_conditional_preimage(&batch.batch_id, &[1; 32], [61; 32])
        .unwrap();
    service
        .learn_conditional_preimage(&batch.batch_id, &[1; 32], [61; 32])
        .unwrap();
    let mut service: ChannelConditionalBatches =
        serde_json::from_slice(&serde_json::to_vec(&service).unwrap()).unwrap();
    service.validate(&backend).unwrap();
    assert_eq!(
        service.begin_conditional_force_resolution(&backend, &batch.batch_id, 129),
        Err(ConditionalBackendError::TransferPending)
    );
    let authority = backend.reservation().clone();
    let force = service
        .begin_conditional_force_resolution(&backend, &batch.batch_id, 130)
        .unwrap();
    assert_eq!(
        force.input_since,
        morph_script_common::absolute_block_since(130).unwrap()
    );
    assert_eq!(force.payout_capacities, [25_000_000_000, 25_000_000_000]);
    assert_eq!(force.descriptor, batch.encode_descriptor().unwrap());
    assert_eq!(backend.reservation(), &authority);
    assert!(backend.proposal().is_none());
    assert_eq!(
        service.confirm_conditional_force_settlement(&batch.batch_id, [0; 32]),
        Err(ConditionalBackendError::InvalidRecord)
    );
    service
        .confirm_conditional_force_settlement(&batch.batch_id, [91; 32])
        .unwrap();
    assert_eq!(
        service
            .conditional_batch(&batch.batch_id)
            .unwrap()
            .lifecycle,
        ConditionalBatchLifecycle::ForceSettled {
            settlement_tx: [91; 32]
        }
    );
}

#[test]
fn conditional_service_cooperative_consolidation_returns_to_ordinary_same_custody() {
    let mut backend = engine();
    let original = backend.current().clone();
    let mut service = ChannelConditionalBatches::new(&backend).unwrap();
    let batch = arm(&mut backend, &mut service);
    service
        .learn_conditional_preimage(&batch.batch_id, &[1; 32], [61; 32])
        .unwrap();
    let proposal = service
        .prepare_cooperative_consolidation(&mut backend, &batch.batch_id)
        .unwrap();
    authorize(&mut backend, &proposal);
    let vote = backend.reservation().clone();
    assert_eq!(
        service.cancel_pending_change(&mut backend),
        Err(ConditionalBackendError::UnresolvedAuthority)
    );
    assert_eq!(backend.reservation(), &vote);
    // A committed engine with an interrupted metadata write is recoverable.
    backend.commit().unwrap();
    let mut service: ChannelConditionalBatches =
        serde_json::from_slice(&serde_json::to_vec(&service).unwrap()).unwrap();
    service.commit_change(&mut backend).unwrap();
    assert_eq!(
        backend.current().settlement.capability,
        MultiAssetSettlementCapability::Ordinary
    );
    assert_eq!(
        backend.current().settlement.payouts[0].values[0].business_ckb,
        5_000_000_000
    );
    assert_eq!(
        backend.current().settlement.payouts[0].values[1].business_ckb,
        5_000_000_000
    );
    assert_eq!(
        backend.current().settlement.payouts[1],
        original.settlement.payouts[1]
    );
    assert_eq!(backend.current().manifest, original.manifest);
    assert_eq!(
        service
            .conditional_batch(&batch.batch_id)
            .unwrap()
            .lifecycle,
        ConditionalBatchLifecycle::CooperativeSettled {
            state_number: proposal.state.header.state_number
        }
    );
}

#[test]
fn conditional_service_rejects_wrong_context_and_reserve_spending_before_any_vote() {
    let mut backend = engine();
    let mut service = ChannelConditionalBatches::new(&backend).unwrap();
    let mut wrong_id = batch(&backend);
    wrong_id.batch_id = [99; 32];
    assert_eq!(
        service.prepare_conditional_batch(&mut backend, wrong_id, [31; 32], 2, 100),
        Err(ConditionalBackendError::BatchMismatch)
    );
    let mut too_large = batch(&backend);
    too_large.transfers[0].amount = 7_000_000_000;
    assert_eq!(
        service.prepare_conditional_batch(&mut backend, too_large, [31; 32], 2, 100),
        Err(ConditionalBackendError::InsufficientBusinessBalance)
    );
    assert!(backend.proposal().is_none());
    assert_eq!(
        backend.reservation().state_number,
        backend.current().state.header.state_number
    );
    let mut snapshot = serde_json::to_value(&service).unwrap();
    snapshot.as_object_mut().unwrap().remove("pending");
    assert!(serde_json::from_value::<ChannelConditionalBatches>(snapshot).is_err());
}
