use super::*;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use morph_core::{
    FactoryMultiAssetReducedRelease, FactoryReducedReleasePayout, FactoryReducedReleaseRight,
};

#[path = "factory_multi_asset_delegation.rs"]
mod delegation;

#[derive(Clone, Copy)]
enum ExitShape {
    Standard,
    WholeTokenToPlain,
    TokenOnlyExternalCkb,
    DustMergedWallet,
    RetainedFloor,
    CrossAssetUnitBoundary,
}
struct ReducedFixture {
    base: FactoryFixture,
    plan: FactoryMultiAssetReducedRelease,
    transaction: TransactionView,
    root: TransactionView,
    activation: TransactionView,
}
fn reserve_claim(participant: u8, asset: Option<[u8; 32]>, quantity: u128) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: [participant; 32],
            subchannel: [0; 32],
            kind: FactoryRightKind::ReserveClaim,
            asset_type: asset,
        },
        quantity,
    }
}
fn sign_release(
    plan: &FactoryMultiAssetReducedRelease,
    transaction: TransactionView,
) -> TransactionView {
    let digest = plan.signing_digest().unwrap();
    let signatures: Vec<_> = (1..=plan.signature_count() as u8)
        .map(|seed| signature(&signing_key(seed), &digest))
        .collect();
    let bytes = plan.encode_authorized(&signatures).unwrap();
    let witness = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(bytes)).pack())
        .build();
    transaction
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build()
}
fn resign(fixture: &mut ReducedFixture, transaction: TransactionView) -> TransactionView {
    fixture.plan.transaction_hash = transaction.hash().unpack();
    if let Some(materialisation) = &mut fixture.plan.materialisation {
        materialisation.transaction_hash = fixture.plan.transaction_hash;
        for child in &mut materialisation.children {
            for point in &mut child.recovery.outpoints {
                point.tx_hash = fixture.plan.transaction_hash;
            }
            child.recovery.state.vault_outpoint_set_root = multi_asset_outpoint_commitment(
                &child.recovery.manifest,
                &child.recovery.outpoints,
            )
            .unwrap();
            signed(&mut child.recovery);
        }
    }
    sign_release(&fixture.plan, transaction)
}

fn release_frame(transaction: &TransactionView) -> Vec<u8> {
    WitnessArgs::from_slice(&transaction.witnesses().get(0).unwrap().raw_data())
        .unwrap()
        .output_type()
        .to_opt()
        .unwrap()
        .raw_data()
        .to_vec()
}

// Start with a production-encoded valid frame, then bypass only the host's
// transition prevalidation. Every adversarial body still has a fresh exact-tx
// signature, checked independently below, so the VM must enforce the invariant.
fn sign_raw_release(mut transaction: TransactionView, mut frame: Vec<u8>) -> TransactionView {
    assert!(matches!(
        u16::from_le_bytes(frame[10..12].try_into().unwrap()),
        0 | 1
    ));
    let locality = factory::factory_transition_locality_digest(&frame, 788).unwrap();
    frame[590..622].copy_from_slice(&locality);
    let mut data: Vec<_> = transaction.outputs_data().into_iter().collect();
    data[0] = Bytes::copy_from_slice(&frame[418..724]).pack();
    transaction = transaction
        .as_advanced_builder()
        .set_outputs_data(data)
        .build();
    frame[72..104].copy_from_slice(transaction.hash().as_slice());
    let digest = factory::FactoryReducedReleaseWitness::parse(&frame)
        .unwrap()
        .signing_digest();
    let key = signing_key(1);
    let signed = signature(&key, &digest);
    key.verifying_key()
        .verify_prehash(
            &digest,
            &k256::ecdsa::Signature::from_slice(&signed).unwrap(),
        )
        .expect("fresh valid touched-member signature over the mutated exact body");
    frame[724..788].copy_from_slice(&signed);
    let witness = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(frame)).pack())
        .build();
    transaction
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build()
}

fn replace_release_values(
    transaction: &TransactionView,
    retained: &MultiAssetManifest,
    payouts: &[FactoryReducedReleasePayout],
) -> Vec<u8> {
    let mut frame = release_frame(transaction);
    // Locate already-encoded slices with the production parser instead of
    // maintaining a second frame encoder in these negative tests.
    let view = factory::FactoryReducedReleaseWitness::parse(&frame).unwrap();
    let start = view.retained().as_bytes().as_ptr() as usize - frame.as_ptr() as usize;
    let old_len = view.retained().as_bytes().len();
    let allocation_offsets: Vec<_> = (0..view.payout_count())
        .map(|i| {
            view.payout(i).unwrap().lock_script.as_ptr() as usize - frame.as_ptr() as usize - 69
                + 33
        })
        .collect();
    assert_eq!(allocation_offsets.len(), payouts.len());
    let encoded = retained.encode().unwrap();
    assert_eq!(encoded.len(), old_len);
    frame[start..start + old_len].copy_from_slice(&encoded);
    for (offset, payout) in allocation_offsets.into_iter().zip(payouts) {
        wire::MultiAssetAllocation {
            reserve: payout.value.reserve,
            business_ckb: payout.value.business_ckb,
            amount: payout.value.amount,
        }
        .encode(&mut frame[offset..offset + 32])
        .unwrap();
    }
    frame[656..688].copy_from_slice(&retained.commitment().unwrap());
    frame
}
fn reduced_fixture() -> ReducedFixture {
    reduced_fixture_profile(1, true, 2)
}
fn reduced_fixture_profile(typed: usize, plain: bool, n: u8) -> ReducedFixture {
    reduced_fixture_profile_with_scripts(typed, plain, n, false)
}
fn reduced_fixture_profile_with_scripts(
    typed: usize,
    plain: bool,
    n: u8,
    maximum_scripts: bool,
) -> ReducedFixture {
    reduced_fixture_operation(
        typed,
        plain,
        n,
        maximum_scripts,
        morph_core::FactoryTransitionOperation::ReducedRelease,
    )
}
fn reduced_fixture_operation(
    typed: usize,
    plain: bool,
    n: u8,
    maximum_scripts: bool,
    operation: morph_core::FactoryTransitionOperation,
) -> ReducedFixture {
    reduced_fixture_operation_children(typed, plain, n, maximum_scripts, operation, 1)
}
fn reduced_fixture_operation_children(
    typed: usize,
    plain: bool,
    n: u8,
    maximum_scripts: bool,
    operation: morph_core::FactoryTransitionOperation,
    children: usize,
) -> ReducedFixture {
    reduced_fixture_shape(
        typed,
        plain,
        n,
        maximum_scripts,
        operation,
        children,
        ExitShape::Standard,
    )
}
fn reduced_fixture_shape(
    typed: usize,
    plain: bool,
    n: u8,
    maximum_scripts: bool,
    operation: morph_core::FactoryTransitionOperation,
    children: usize,
    shape: ExitShape,
) -> ReducedFixture {
    let mut base = build_factory_profile(typed, plain, children, true, n, maximum_scripts);
    let large = base.plan.source.clone();
    let small = base.plan.retained.clone().unwrap();
    let (source, mut retained) =
        if operation == morph_core::FactoryTransitionOperation::ReducedDeposit {
            (small.clone(), large.clone())
        } else if !operation.moves_custody() {
            (large.clone(), large.clone())
        } else {
            (large.clone(), small.clone())
        };
    let whole_token_to_plain = matches!(
        shape,
        ExitShape::WholeTokenToPlain | ExitShape::TokenOnlyExternalCkb
    );
    if whole_token_to_plain {
        assert_eq!(typed, 1);
        assert!(!plain);
        assert_eq!(children, 1);
        if matches!(shape, ExitShape::TokenOnlyExternalCkb) {
            retained = source.clone();
        }
        retained.vaults[0].asset = VaultAsset::Ckb;
        retained.vaults[0].value.amount = 0;
    }
    if matches!(shape, ExitShape::DustMergedWallet) {
        assert_eq!(typed, 0);
        assert!(plain);
        retained = source.clone();
        retained.vaults[0].value.business_ckb -= 1;
    }
    if matches!(shape, ExitShape::RetainedFloor) {
        assert_eq!(typed, 0);
        assert!(plain);
        retained.vaults[0].value.reserve =
            wire::multi_asset_occupied_capacity(base.factory_vault_lock.as_slice(), None, 0)
                .unwrap();
    }
    let mut changes = Vec::new();
    let mut changed_capacity = 0u128;
    for (i, (large, small)) in large.vaults.iter().zip(&small.vaults).enumerate() {
        let value = MultiAssetValue {
            reserve: large.value.reserve - small.value.reserve,
            business_ckb: large.value.business_ckb - small.value.business_ckb,
            amount: if whole_token_to_plain {
                large.value.amount
            } else {
                large.value.amount - small.value.amount
            },
        };
        changed_capacity += value.capacity().unwrap() as u128;
        changes.push(FactoryReducedReleasePayout {
            asset: large.asset.clone(),
            value,
            lock_script: base.template.locks[0].as_slice().to_vec(),
            output_index: (1 + retained.vaults.len() + i) as u16,
        });
    }
    if matches!(shape, ExitShape::RetainedFloor) {
        changes[0].value.reserve =
            source.vaults[0].value.reserve - retained.vaults[0].value.reserve;
        changed_capacity = changes[0].value.capacity().unwrap() as u128;
    }
    if matches!(shape, ExitShape::CrossAssetUnitBoundary) {
        assert_eq!(typed, 1);
        assert!(plain);
        // A fully backed positive allocation: one fewer shannon of CKB and
        // one more token unit belong to the touched member's release.
        retained.vaults[0].value.business_ckb += 1;
        changes[0].value.business_ckb -= 1;
        retained.vaults[1].value.amount -= 1;
        changes[1].value.amount += 1;
        changed_capacity -= 1;
    }
    if matches!(
        shape,
        ExitShape::TokenOnlyExternalCkb | ExitShape::DustMergedWallet
    ) {
        let token_type = if typed == 0 {
            None
        } else {
            Some(base.template.types[0].as_slice())
        };
        let minimum = wire::multi_asset_occupied_capacity(
            base.template.locks[0].as_slice(),
            token_type,
            if typed == 0 { 0 } else { 16 },
        )
        .unwrap();
        changes[0].value.reserve = minimum;
        changes[0].value.business_ckb = if typed == 0 { 1 } else { 0 };
        changed_capacity = if typed == 0 { 1 } else { 0 };
    }
    let deposit = operation == morph_core::FactoryTransitionOperation::ReducedDeposit;
    let mut before_rights = vec![reserve_claim(
        1,
        None,
        if deposit { 0 } else { changed_capacity },
    )];
    for change in &changes {
        if let VaultAsset::Xudt(token) = change.asset {
            before_rights.push(reserve_claim(
                1,
                Some(token),
                if deposit { 0 } else { change.value.amount },
            ));
        }
    }
    let touched_count = before_rights.len();
    let other_capacity: u128 = source
        .vaults
        .iter()
        .map(|v| v.value.capacity().unwrap() as u128)
        .sum::<u128>()
        - if deposit { 0 } else { changed_capacity };
    before_rights.push(reserve_claim(2, None, other_capacity));
    for (i, vault) in source.vaults.iter().enumerate() {
        if let VaultAsset::Xudt(token) = vault.asset {
            before_rights.push(reserve_claim(
                2,
                Some(token),
                vault.value.amount - if deposit { 0 } else { changes[i].value.amount },
            ));
        }
    }
    let mut after_rights = before_rights.clone();
    after_rights[0].quantity = if deposit { changed_capacity } else { 0 };
    for (right, change) in after_rights.iter_mut().take(touched_count).skip(1).zip(
        changes
            .iter()
            .filter(|p| matches!(p.asset, VaultAsset::Xudt(_))),
    ) {
        right.quantity = if deposit { change.value.amount } else { 0 };
    }
    let rights = if operation.is_full() {
        vec![]
    } else {
        before_rights[..touched_count]
            .iter()
            .filter(|r| r.quantity != after_rights.iter().find(|a| a.id == r.id).unwrap().quantity)
            .map(|r| FactoryReducedReleaseRight {
                before: factory_right_sparse_proof_compact(&before_rights, &r.id).unwrap(),
                after: factory_right_sparse_proof_compact(&after_rights, &r.id).unwrap(),
            })
            .collect()
    };
    let payouts = if operation == morph_core::FactoryTransitionOperation::ReducedRelease
        || operation == morph_core::FactoryTransitionOperation::FullCustody
    {
        changes.clone()
    } else {
        vec![]
    };
    let mut root_header = base.header;
    root_header.state_root = factory_right_sparse_root(&before_rights).unwrap();
    root_header.content_root = source.commitment().unwrap();
    root_header.outpoint_root = [0; 32];
    let mut data: Vec<_> = base.root.outputs_data().into_iter().collect();
    data[0] = Bytes::from(root_header.encode().unwrap().to_vec()).pack();
    let mut root_outputs: Vec<_> = base.root.outputs().into_iter().collect();
    for (i, vault) in source.vaults.iter().enumerate() {
        root_outputs[i + 1] = root_outputs[i + 1]
            .clone()
            .as_builder()
            .capacity(vault.value.capacity().unwrap())
            .build();
        if matches!(vault.asset, VaultAsset::Xudt(_)) {
            data[i + 1] = xudt_amount_data(vault.value.amount).pack();
        }
    }
    let mut token_index = 0;
    for vault in &source.vaults {
        if matches!(vault.asset, VaultAsset::Xudt(_)) {
            let point = base
                .root
                .inputs()
                .get(1 + token_index)
                .unwrap()
                .previous_output();
            let (cell, _) = base.template.context.get_cell(&point).unwrap();
            base.template.context.create_cell_with_out_point(
                point,
                cell.as_builder()
                    .capacity(vault.value.capacity().unwrap())
                    .build(),
                xudt_amount_data(vault.value.amount),
            );
            token_index += 1;
        }
    }
    let root = base
        .root
        .as_advanced_builder()
        .set_outputs(root_outputs)
        .set_outputs_data(data)
        .build();
    let digest = factory::FactoryMultiAssetStateHeader::parse(&root_header.encode().unwrap())
        .unwrap()
        .root_funding_signing_digest(&root.hash().unpack())
        .unwrap();
    let root = root
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_ROOT,
                &source,
                &[],
                &factory_auth(&digest, n),
            )
            .pack(),
        ])
        .build();
    materialise(&mut base.template.context, &root);
    let source_points: Vec<_> = (1..=source.vaults.len())
        .map(|i| MultiAssetOutPoint {
            tx_hash: root.hash().unpack(),
            index: i as u32,
        })
        .collect();
    let mut before = root_header;
    before.outpoint_root = multi_asset_outpoint_commitment(&source, &source_points).unwrap();
    let mut inputs: Vec<_> = base.active.inputs().into_iter().collect();
    inputs[0] = inputs[0]
        .clone()
        .as_builder()
        .previous_output(point(&root, 0))
        .build();
    let mut data: Vec<_> = base.active.outputs_data().into_iter().collect();
    data[0] = Bytes::from(before.encode().unwrap().to_vec()).pack();
    let mut deps: Vec<_> = base.active.cell_deps().into_iter().collect();
    for (i, dep) in deps.iter_mut().take(source.vaults.len()).enumerate() {
        *dep = dep
            .clone()
            .as_builder()
            .out_point(point(&root, i + 1))
            .build();
    }
    let activation = base
        .active
        .as_advanced_builder()
        .set_inputs(inputs)
        .set_outputs_data(data)
        .set_cell_deps(deps)
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_ACTIVATE,
                &source,
                &source_points,
                &[],
            )
            .pack(),
        ])
        .build();
    materialise(&mut base.template.context, &activation);
    let after = factory::FactoryMultiAssetHeaderFields {
        update_number: 1,
        state_root: factory_right_sparse_root(&after_rights).unwrap(),
        content_root: retained.commitment().unwrap(),
        outpoint_root: if operation.moves_custody() {
            [0; 32]
        } else {
            before.outpoint_root
        },
        ..before
    };
    let mut plan = FactoryMultiAssetReducedRelease {
        operation,
        before,
        after,
        members: factory_auth(&[1; 32], n)
            .into_iter()
            .map(|p| morph_core::FactoryParticipantKey {
                participant: p.participant,
                pubkey_sec1: p.pubkey_sec1,
            })
            .collect(),
        signer_index: 0,
        old_state: MultiAssetOutPoint {
            tx_hash: activation.hash().unpack(),
            index: 0,
        },
        transaction_hash: [1; 32],
        carrier_capacity: CELL_CAPACITY,
        source,
        source_outpoints: source_points,
        retained,
        factory_lock_script: base.factory_vault_lock.as_slice().to_vec(),
        type_scripts: base.template.package.scripts.type_scripts.clone(),
        payouts,
        rights,
        materialisation: None,
    };
    if operation == morph_core::FactoryTransitionOperation::ReducedChild {
        plan.materialisation = Some(reduced_child_plan(&mut base, &plan));
    }
    plan.set_locality_digest().unwrap();
    let plain_deposit: u64 = if deposit {
        changes
            .iter()
            .filter(|p| p.asset == VaultAsset::Ckb)
            .map(|p| p.value.capacity().unwrap())
            .sum()
    } else {
        0
    };
    let payout_topup = if matches!(
        operation,
        morph_core::FactoryTransitionOperation::ReducedRelease
            | morph_core::FactoryTransitionOperation::FullCustody
    ) {
        plan.payouts
            .iter()
            .map(|p| p.value.capacity().unwrap() as u128)
            .sum::<u128>()
            .saturating_sub(changed_capacity) as u64
    } else {
        0
    };
    let fee = base.template.context.create_cell(
        CellOutput::new_builder()
            .capacity(
                CELL_CAPACITY
                    + 10_000
                    + plain_deposit
                    + payout_topup
                    + if operation == morph_core::FactoryTransitionOperation::ReducedChild {
                        children as u64 * CELL_CAPACITY
                    } else {
                        0
                    },
            )
            .lock(base.template.locks[0].clone())
            .build(),
        Bytes::new(),
    );
    let mut tx = TransactionBuilder::default().input(
        CellInput::new_builder()
            .previous_output(point(&activation, 0))
            .build(),
    );
    for i in 0..if operation.moves_custody() {
        plan.source.vaults.len()
    } else {
        0
    } {
        tx = tx.input(
            CellInput::new_builder()
                .previous_output(point(&root, i + 1))
                .build(),
        );
    }
    if deposit {
        for (change, ty) in changes.iter().zip(&base.template.vault_types) {
            if let Some(ty) = ty {
                let input = base.template.context.create_cell(
                    CellOutput::new_builder()
                        .capacity(change.value.capacity().unwrap())
                        .lock(base.template.locks[0].clone())
                        .type_(Some(ty.clone()).pack())
                        .build(),
                    xudt_amount_data(change.value.amount),
                );
                tx = tx.input(CellInput::new_builder().previous_output(input).build());
            }
        }
    }
    tx = tx
        .input(CellInput::new_builder().previous_output(fee).build())
        .output(state_cell(
            CELL_CAPACITY,
            &base.factory_state_lock,
            &base.factory_type,
        ))
        .output_data(Bytes::from(plan.after.encode().unwrap().to_vec()).pack());
    if operation.moves_custody() {
        tx = manifest_outputs(
            tx,
            &plan.retained,
            &base.factory_vault_lock,
            &plan
                .retained
                .vaults
                .iter()
                .map(|v| match v.asset {
                    VaultAsset::Ckb => None,
                    VaultAsset::Xudt(hash) => Some(
                        Script::from_slice(
                            &plan
                                .type_scripts
                                .iter()
                                .find(|s| s.type_hash == hash)
                                .unwrap()
                                .script,
                        )
                        .unwrap(),
                    ),
                })
                .collect::<Vec<_>>(),
        );
    }
    if let Some(materialisation) = &plan.materialisation {
        for child in &materialisation.children {
            let package = &child.recovery;
            let state_type = Script::from_slice(&package.scripts.state_type).unwrap();
            let state_lock = Script::from_slice(&package.scripts.state_lock).unwrap();
            let vault_lock = Script::from_slice(&package.scripts.vault_lock).unwrap();
            let mut creation = package.state.clone();
            creation.header.state_number = 0;
            creation.header.phase = Phase::Active;
            creation.vault_outpoint_set_root = [0; 32];
            tx = tx
                .output(state_cell(
                    package.state_carrier_capacity,
                    &state_lock,
                    &state_type,
                ))
                .output_data(Bytes::from(creation.encode().unwrap().to_vec()).pack());
            tx = manifest_outputs(
                tx,
                &package.manifest,
                &vault_lock,
                &base.template.vault_types,
            );
        }
    }
    for (payout, ty) in plan.payouts.iter().zip(&base.template.vault_types) {
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(payout.value.capacity().unwrap())
                    .lock(base.template.locks[0].clone())
                    .type_(ty.clone().pack())
                    .build(),
            )
            .output_data(
                if ty.is_some() {
                    xudt_amount_data(payout.value.amount)
                } else {
                    Bytes::new()
                }
                .pack(),
            );
    }
    tx = tx
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(base.template.locks[0].clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    let tx = base
        .template
        .context
        .complete_tx(tx.witness(Bytes::new()).build());
    plan.transaction_hash = tx.hash().unpack();
    if let Some(materialisation) = &mut plan.materialisation {
        materialisation.transaction_hash = plan.transaction_hash;
        for child in &mut materialisation.children {
            for point in &mut child.recovery.outpoints {
                point.tx_hash = plan.transaction_hash;
            }
            child.recovery.state.vault_outpoint_set_root = multi_asset_outpoint_commitment(
                &child.recovery.manifest,
                &child.recovery.outpoints,
            )
            .unwrap();
            signed(&mut child.recovery);
        }
    }
    let transaction = sign_release(&plan, tx);
    ReducedFixture {
        base,
        plan,
        transaction,
        root,
        activation,
    }
}
fn reduced_child_plan(
    base: &mut FactoryFixture,
    plan: &FactoryMultiAssetReducedRelease,
) -> FactoryMultiAssetMaterialisation {
    let mut materialisation = base.plan.clone();
    materialisation.old_state = plan.old_state.clone();
    materialisation.transaction_hash = [1; 32];
    materialisation.source = plan.source.clone();
    materialisation.source_outpoints = plan.source_outpoints.clone();
    materialisation.retained = Some(plan.retained.clone());
    let old = CellInput::new_builder()
        .previous_output(
            OutPoint::new_builder()
                .tx_hash(plan.old_state.tx_hash.pack())
                .index(plan.old_state.index)
                .build(),
        )
        .build();
    for child in &mut materialisation.children {
        let anchor = derived_funding_anchor(&old, child.state_output_index as u64);
        let mut args = anchor.to_vec();
        args.extend_from_slice(base.factory_type.calc_script_hash().as_slice());
        args.extend_from_slice(&base.template.since.to_le_bytes());
        let ty = deploy_contract(&mut base.template.context, "morph-state-type", args);
        let lock = deploy_contract(
            &mut base.template.context,
            "morph-state-lock",
            ty.calc_script_hash().as_slice().to_vec(),
        );
        let args = wire::encode_multi_asset_vault_args(
            &anchor,
            base.template.since,
            &ty.calc_script_hash().unpack(),
            &lock.calc_script_hash().unpack(),
        )
        .unwrap();
        let vault = deploy_contract(
            &mut base.template.context,
            "morph-vault-lock",
            args.to_vec(),
        );
        let recovery = &mut child.recovery;
        if plan.source.vaults.len() == 1
            && matches!(plan.source.vaults[0].asset, VaultAsset::Xudt(_))
            && plan.retained.vaults[0].asset == VaultAsset::Ckb
        {
            let amount = plan.source.vaults[0].value.amount;
            let ratio = amount / recovery.manifest.vaults[0].value.amount;
            recovery.manifest.vaults[0].value.amount = amount;
            for value in &mut recovery.settlement.payouts[0].values {
                value.amount *= ratio;
            }
            recovery.state.header.settlement_descriptor_commitment =
                recovery.settlement.commitment().unwrap();
        }
        recovery.scripts.state_type = ty.as_slice().to_vec();
        recovery.scripts.state_lock = lock.as_slice().to_vec();
        recovery.scripts.vault_lock = vault.as_slice().to_vec();
        recovery.state.header.funding_anchor = anchor;
        recovery.state.header.channel_id = blake2b256(&[&anchor]);
        for entry in &mut recovery.manifest.vaults {
            entry.lock_hash = vault.calc_script_hash().unpack();
        }
        recovery.state.vault_content_set_root = recovery.manifest.commitment().unwrap();
        recovery.outpoints = (0..recovery.manifest.vaults.len())
            .map(|i| MultiAssetOutPoint {
                tx_hash: [1; 32],
                index: child.state_output_index + 1 + i as u32,
            })
            .collect();
        recovery.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
    }
    materialisation
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_executes_with_one_member_after_all_member_funding() {
    let fixture = reduced_fixture();
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.root, MAX_CYCLES)
        .expect("root entitled by both members");
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.activation, MAX_CYCLES)
        .expect("complete-set activation");
    let cycles = fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("single-member release");
    eprintln!(
        "Factory reduced release cycles={cycles} bytes={}",
        fixture.transaction.data().as_slice().len()
    );
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_freshly_signed_physical_payout_change() {
    let mut fixture = reduced_fixture();
    let mut outputs: Vec<_> = fixture.transaction.outputs().into_iter().collect();
    outputs[3] = outputs[3]
        .clone()
        .as_builder()
        .capacity(fixture.plan.payouts[0].value.capacity().unwrap() - 1)
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs(outputs)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[69]);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_freshly_signed_token_change() {
    let mut fixture = reduced_fixture();
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    data[4] = xudt_amount_data(fixture.plan.payouts[1].value.amount + 1).pack();
    // Preserve global token conservation so the Factory boundary, rather
    // than the asset script's supply check, must reject the redistribution.
    data[2] = xudt_amount_data(fixture.plan.retained.vaults[1].value.amount - 1).pack();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs_data(data)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[64]);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_missing_source_vault_even_with_fresh_signature() {
    let mut fixture = reduced_fixture();
    let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
    inputs.remove(1);
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_inputs(inputs)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[66, 69]);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_duplicate_state_and_reserve_fee_diversion() {
    let mut fixture = reduced_fixture();
    let state = fixture.transaction.outputs().get(0).unwrap();
    let data = fixture.transaction.outputs_data().get(0).unwrap();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .output(state)
        .output_data(data)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[8, 69]);
    let mut fixture = reduced_fixture();
    let last = fixture.transaction.outputs().len() - 1;
    let mut outputs: Vec<_> = fixture.transaction.outputs().into_iter().collect();
    outputs[last] = outputs[last]
        .clone()
        .as_builder()
        .capacity(CELL_CAPACITY + 20_000)
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs(outputs)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[53]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_maximum_eight_types_sixteen_members_executes() {
    let fixture = reduced_fixture_profile_with_scripts(8, false, 16, true);
    let cycles = fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, 70_000_000)
        .expect("bounded maximum reduced release");
    eprintln!(
        "Factory reduced release assets=8 members=16 claims=9 cycles={cycles} bytes={}",
        fixture.transaction.data().as_slice().len()
    );
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_retained_successor_reactivates_without_member_signatures() {
    let mut fixture = reduced_fixture();
    materialise(&mut fixture.base.template.context, &fixture.transaction);
    let points: Vec<_> = (1..=fixture.plan.retained.vaults.len())
        .map(|i| MultiAssetOutPoint {
            tx_hash: fixture.transaction.hash().unpack(),
            index: i as u32,
        })
        .collect();
    let mut header = fixture.plan.after;
    header.outpoint_root =
        multi_asset_outpoint_commitment(&fixture.plan.retained, &points).unwrap();
    let fee = fixture.base.template.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY + 10_000)
            .lock(fixture.base.template.locks[0].clone())
            .build(),
        Bytes::new(),
    );
    let mut tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&fixture.transaction, 0))
                .build(),
        )
        .input(CellInput::new_builder().previous_output(fee).build())
        .output(state_cell(
            CELL_CAPACITY,
            &fixture.base.factory_state_lock,
            &fixture.base.factory_type,
        ))
        .output_data(Bytes::from(header.encode().unwrap().to_vec()).pack())
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(fixture.base.template.locks[0].clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    for i in 1..=fixture.plan.retained.vaults.len() {
        tx = tx.cell_dep(
            CellDep::new_builder()
                .out_point(point(&fixture.transaction, i))
                .build(),
        );
    }
    let tx = fixture.base.template.context.complete_tx(
        tx.witness(fs_witness(
            factory::FACTORY_STATE_WITNESS_ACTIVATE,
            &fixture.plan.retained,
            &points,
            &[],
        ))
        .build(),
    );
    fixture
        .base
        .template
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("successor activation");
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_cloned_state_outpoint_and_state_lock_alias() {
    let mut fixture = reduced_fixture();
    let input = fixture.transaction.inputs().get(0).unwrap();
    let (cell, data) = fixture
        .base
        .template
        .context
        .get_cell(&input.previous_output())
        .unwrap();
    let cloned = fixture.base.template.context.create_cell(cell, data);
    let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
    inputs[0] = inputs[0]
        .clone()
        .as_builder()
        .previous_output(cloned)
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_inputs(inputs)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[69]);
    let mut fixture = reduced_fixture();
    fixture.plan.payouts[0].lock_script = fixture.base.factory_state_lock.as_slice().to_vec();
    fixture.plan.set_locality_digest().unwrap();
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
    let mut outputs: Vec<_> = fixture.transaction.outputs().into_iter().collect();
    outputs[3] = outputs[3]
        .clone()
        .as_builder()
        .lock(fixture.base.factory_state_lock.clone())
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs(outputs)
        .set_outputs_data(data)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[69]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_authenticates_factory_type_and_state_lock() {
    for false_type in [true, false] {
        let mut fixture = reduced_fixture();
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.transaction, MAX_CYCLES)
            .unwrap();
        let original = fixture
            .transaction
            .inputs()
            .get(0)
            .unwrap()
            .previous_output();
        let (cell, data) = fixture.base.template.context.get_cell(&original).unwrap();
        let wallet = fixture.base.template.locks[0].clone();
        let ty = if false_type {
            // Retain valid Factory args but execute a permissive foreign Type.
            // Remove the genuine Type from BOTH sides, so only the authentic
            // reserve lock can catch the missing source authority.
            fixture
                .base
                .factory_type
                .clone()
                .as_builder()
                .code_hash(wallet.code_hash())
                .hash_type(wallet.hash_type())
                .build()
        } else {
            fixture.base.factory_type.clone()
        };
        let fake = fixture.base.template.context.create_cell(
            cell.as_builder()
                .lock(wallet.clone())
                .type_(Some(ty.clone()).pack())
                .build(),
            data,
        );
        let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
        inputs[0] = inputs[0]
            .clone()
            .as_builder()
            .previous_output(fake.clone())
            .build();
        let mut outputs: Vec<_> = fixture.transaction.outputs().into_iter().collect();
        outputs[0] = outputs[0]
            .clone()
            .as_builder()
            .lock(wallet)
            .type_(Some(ty).pack())
            .build();
        fixture.plan.old_state = MultiAssetOutPoint {
            tx_hash: fake.tx_hash().unpack(),
            index: fake.index().unpack(),
        };
        fixture.plan.set_locality_digest().unwrap();
        let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
        data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
        let tx = fixture
            .transaction
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(data)
            .build();
        let tx = resign(&mut fixture, tx);
        factory::FactoryReducedReleaseWitness::parse(&release_frame(&tx))
            .unwrap()
            .verify()
            .expect("the exact-body signature, both roots and all allocation proofs remain valid");
        let code = if false_type {
            ScriptError::StateCellMissing
        } else {
            ScriptError::FactoryMultiAssetPartitionMismatch
        };
        rejects(&fixture.base.template.context, &tx, &[code as i8]);
    }
}

fn approve_reduced_rights_root(
    fixture: &mut ReducedFixture,
    rights: &[FactoryRight],
) -> (TransactionView, factory::FactoryMultiAssetHeaderFields) {
    let mut header = fixture.plan.before;
    header.update_number += 1;
    header.state_root = factory_right_sparse_root(rights).unwrap();
    let metadata = fixture.base.template.context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(
                        OutPoint::new_builder()
                            .tx_hash(fixture.plan.old_state.tx_hash.pack())
                            .index(fixture.plan.old_state.index)
                            .build(),
                    )
                    .build(),
            )
            .output(state_cell(
                CELL_CAPACITY,
                &fixture.base.factory_state_lock,
                &fixture.base.factory_type,
            ))
            .output_data(Bytes::from(header.encode().unwrap().to_vec()).pack())
            .witness(Bytes::new())
            .build(),
    );
    let digest = factory::FactoryMultiAssetStateHeader::parse(&header.encode().unwrap())
        .unwrap()
        .update_signing_digest(&metadata.hash().unpack())
        .unwrap();
    let metadata = metadata
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &fixture.plan.source,
                &fixture.plan.source_outpoints,
                &factory_auth(&digest, fixture.plan.members.len() as u8),
            )
            .pack(),
        ])
        .build();
    fixture
        .base
        .template
        .context
        .verify_tx(&metadata, MAX_CYCLES)
        .expect("the complete member set independently approves the exact source root");
    materialise(&mut fixture.base.template.context, &metadata);
    (metadata, header)
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_rights_rejects_u128_group_overflow_with_valid_locality_proofs() {
    for (old_quantities, new_quantities) in [
        ([u128::MAX, 2], [u128::MAX - 1, 1]),
        ([u128::MAX - 2, 2], [u128::MAX - 1, 3]),
    ] {
        let mut fixture = reduced_fixture_operation(
            0,
            true,
            2,
            false,
            morph_core::FactoryTransitionOperation::ReducedRights,
        );
        let make_rights = |quantities: [u128; 2]| {
            quantities
                .into_iter()
                .enumerate()
                .map(|(i, quantity)| {
                    let mut right = reserve_claim(1, None, quantity);
                    right.id.subchannel = [i as u8; 32];
                    right
                })
                .collect::<Vec<_>>()
        };
        let before = make_rights([100, 20]);
        let after = make_rights([99, 19]);
        let (approved, header) = approve_reduced_rights_root(&mut fixture, &before);
        fixture.plan.before = header;
        fixture.plan.after.update_number = header.update_number + 1;
        fixture.plan.after.state_root = factory_right_sparse_root(&after).unwrap();
        fixture.plan.old_state = MultiAssetOutPoint {
            tx_hash: approved.hash().unpack(),
            index: 0,
        };
        fixture.plan.rights = before
            .iter()
            .map(|right| FactoryReducedReleaseRight {
                before: factory_right_sparse_proof_compact(&before, &right.id).unwrap(),
                after: factory_right_sparse_proof_compact(&after, &right.id).unwrap(),
            })
            .collect();
        fixture.plan.set_locality_digest().unwrap();
        let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
        inputs[0] = inputs[0]
            .clone()
            .as_builder()
            .previous_output(point(&approved, 0))
            .build();
        let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
        data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
        let baseline = fixture
            .transaction
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_outputs_data(data)
            .build();
        let baseline = resign(&mut fixture, baseline);
        fixture
            .base
            .template
            .context
            .verify_tx(&baseline, MAX_CYCLES)
            .expect("two same-asset localized changes execute with ordinary bounded quantities");

        let bad_before = make_rights(old_quantities);
        let bad_after = make_rights(new_quantities);
        // Deliberately bypass host initial-allocation admission. Consensus must
        // still reject arithmetic overflow if all members commit such a root.
        let (approved, header) = approve_reduced_rights_root(&mut fixture, &bad_before);
        let mut next = fixture.plan.after;
        next.update_number = header.update_number + 1;
        next.state_root = factory_right_sparse_root(&bad_after).unwrap();
        let mut frame = release_frame(&baseline);
        let view = factory::FactoryReducedReleaseWitness::parse(&frame).unwrap();
        let before_header = view.before().as_bytes().as_ptr() as usize - frame.as_ptr() as usize;
        let after_header = view.after().as_bytes().as_ptr() as usize - frame.as_ptr() as usize;
        let offsets: Vec<_> = (0..2)
            .map(|i| {
                view.right(i).unwrap().before.raw().as_ptr() as usize - frame.as_ptr() as usize
            })
            .collect();
        frame[before_header..before_header + 306].copy_from_slice(&header.encode().unwrap());
        frame[after_header..after_header + 306].copy_from_slice(&next.encode().unwrap());
        frame[36..68].copy_from_slice(approved.hash().as_slice());
        frame[68..72].copy_from_slice(&0u32.to_le_bytes());
        for (i, offset) in offsets.into_iter().enumerate() {
            let proofs = [
                factory_right_sparse_proof_compact(&bad_before, &bad_before[i].id).unwrap(),
                factory_right_sparse_proof_compact(&bad_after, &bad_after[i].id).unwrap(),
            ];
            let mut proof_offset = offset + 2 * morph_script_common::FACTORY_RIGHT_LEN;
            for (side, proof) in proofs.into_iter().enumerate() {
                morph_core::verify_factory_right_compact_proof(
                    if side == 0 {
                        header.state_root
                    } else {
                        next.state_root
                    },
                    &proof,
                )
                .unwrap();
                let quantity_offset =
                    offset + (side + 1) * morph_script_common::FACTORY_RIGHT_LEN - 16;
                frame[quantity_offset..quantity_offset + 16]
                    .copy_from_slice(&proof.right.quantity.to_le_bytes());
                let count = morph_script_common::read_u16(&frame, proof_offset) as usize;
                assert_eq!(count, proof.siblings.len());
                for (j, sibling) in proof.siblings.iter().enumerate() {
                    let pair = proof_offset + 2 + j * 34;
                    assert_eq!(morph_script_common::read_u16(&frame, pair), sibling.depth);
                    frame[pair + 2..pair + 34].copy_from_slice(&sibling.hash);
                }
                proof_offset += 2 + count * 34;
            }
        }
        let mut inputs: Vec<_> = baseline.inputs().into_iter().collect();
        inputs[0] = inputs[0]
            .clone()
            .as_builder()
            .previous_output(point(&approved, 0))
            .build();
        let bad = baseline.as_advanced_builder().set_inputs(inputs).build();
        let bad = sign_raw_release(bad, frame);
        let frame = release_frame(&bad);
        let view = factory::FactoryReducedReleaseWitness::parse(&frame).unwrap();
        for i in 0..2 {
            factory::verify_factory_localized_right_change(
                &view.right(i).unwrap(),
                view.touched_participant(),
                view.before().state_root(),
                view.after().state_root(),
                &[view.right(1 - i).unwrap().key()],
            )
            .expect(
                "both changed leaves have valid roots, canonical proofs and complete localization",
            );
        }
        assert_eq!(
            view.validate_transition(),
            Err(ScriptError::FactoryReducedProofMismatch)
        );
        rejects(
            &fixture.base.template.context,
            &bad,
            &[ScriptError::FactoryReducedProofMismatch as i8],
        );
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_replayed_frame_and_stale_before_header() {
    let mut fixture = reduced_fixture();
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("original exact-source release is valid");

    // Advance the authentic State with a valid N-of-N metadata update while
    // retaining the same rights and physical Vaults.
    let mut current = fixture.plan.before;
    current.update_number += 1;
    let metadata = fixture.base.template.context.complete_tx(
        TransactionBuilder::default()
            .input(fixture.transaction.inputs().get(0).unwrap())
            .output(state_cell(
                CELL_CAPACITY,
                &fixture.base.factory_state_lock,
                &fixture.base.factory_type,
            ))
            .output_data(Bytes::from(current.encode().unwrap().to_vec()).pack())
            .witness(Bytes::new())
            .build(),
    );
    let digest = factory::FactoryMultiAssetStateHeader::parse(&current.encode().unwrap())
        .unwrap()
        .update_signing_digest(&metadata.hash().unpack())
        .unwrap();
    let metadata = metadata
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &fixture.plan.source,
                &fixture.plan.source_outpoints,
                &factory_auth(&digest, 2),
            )
            .pack(),
        ])
        .build();
    fixture
        .base
        .template
        .context
        .verify_tx(&metadata, MAX_CYCLES)
        .expect("all-member metadata successor is independently valid");
    materialise(&mut fixture.base.template.context, &metadata);
    let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
    inputs[0] = inputs[0]
        .clone()
        .as_builder()
        .previous_output(point(&metadata, 0))
        .build();
    let current_source = fixture
        .transaction
        .as_advanced_builder()
        .set_inputs(inputs)
        .build();

    // Even a fresh exact-body signature cannot make an old State locator
    // authorize consumption of its authentic successor.
    let replay = sign_raw_release(current_source.clone(), release_frame(&fixture.transaction));
    factory::FactoryReducedReleaseWitness::parse(&release_frame(&replay))
        .unwrap()
        .verify()
        .expect("replayed proof and fresh signature remain internally valid");
    rejects(&fixture.base.template.context, &replay, &[69]);

    // Correct the locator too: now only the before-header bytes are stale.
    let mut frame = release_frame(&fixture.transaction);
    frame[36..68].copy_from_slice(metadata.hash().as_slice());
    frame[68..72].copy_from_slice(&0u32.to_le_bytes());
    let stale = sign_raw_release(current_source.clone(), frame);
    factory::FactoryReducedReleaseWitness::parse(&release_frame(&stale))
        .unwrap()
        .verify()
        .expect("stale header frame has valid locality, proofs and new signature");
    rejects(&fixture.base.template.context, &stale, &[69]);

    // Updating the claimed before/after progress makes this same source and
    // payout valid, isolating authentication from signatures and cell geometry.
    fixture.plan.before = current;
    fixture.plan.after.update_number = current.update_number + 1;
    fixture.plan.old_state.tx_hash = metadata.hash().unpack();
    fixture.plan.set_locality_digest().unwrap();
    let mut data: Vec<_> = current_source.outputs_data().into_iter().collect();
    data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
    let corrected = current_source
        .as_advanced_builder()
        .set_outputs_data(data)
        .build();
    let corrected = resign(&mut fixture, corrected);
    fixture
        .base
        .template
        .context
        .verify_tx(&corrected, MAX_CYCLES)
        .expect("fresh before-header and exact source permit release");
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_retained_reserve_one_below_occupied_floor() {
    let fixture = reduced_fixture_shape(
        0,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::RetainedFloor,
    );
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.root, MAX_CYCLES)
        .expect("occupied-boundary claims are fully backed at funding");
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("retained reserve exactly at occupied floor is valid");
    let floor =
        wire::multi_asset_occupied_capacity(fixture.base.factory_vault_lock.as_slice(), None, 0)
            .unwrap();
    assert_eq!(fixture.plan.retained.vaults[0].value.reserve, floor);

    // Keep actual capacities, CKB claims and both reserve/business totals
    // unchanged. Only the retained Vault's independently reserved floor fails.
    let mut retained = fixture.plan.retained.clone();
    let mut payouts = fixture.plan.payouts.clone();
    retained.vaults[0].value.reserve -= 1;
    retained.vaults[0].value.business_ckb += 1;
    payouts[0].value.reserve += 1;
    payouts[0].value.business_ckb -= 1;
    let frame = replace_release_values(&fixture.transaction, &retained, &payouts);
    let bad = sign_raw_release(fixture.transaction.clone(), frame);
    let raw = release_frame(&bad);
    let view = factory::FactoryReducedReleaseWitness::parse(&raw).unwrap();
    assert_eq!(
        view.retained().entry(0).unwrap().allocation.reserve,
        floor - 1
    );
    assert_eq!(
        view.withdrawn_value(wire::MultiAssetId::CKB).unwrap(),
        view.released_ckb().unwrap(),
        "reserve and business lanes remain exactly balanced"
    );
    assert_eq!(
        view.deposited_value(wire::MultiAssetId::CKB).unwrap(),
        wire::MultiAssetAllocation::default()
    );
    rejects(&fixture.base.template.context, &bad, &[39]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_release_rejects_token_claim_burn_for_extra_ckb_payout() {
    let fixture = reduced_fixture_shape(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::CrossAssetUnitBoundary,
    );
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.root, MAX_CYCLES)
        .expect("both members' CKB and token claims are fully backed");
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("independent per-asset claim decrements match positive payouts");

    // Preserve the valid membership, roots and localized proofs. Burn one
    // extra token claim unit for one extra shannon of physical CKB instead.
    // A cross-asset numeric sum would pass; each asset's own equation must fail.
    let mut retained = fixture.plan.retained.clone();
    let mut payouts = fixture.plan.payouts.clone();
    retained.vaults[0].value.business_ckb -= 1;
    payouts[0].value.business_ckb += 1;
    retained.vaults[1].value.amount += 1;
    payouts[1].value.amount -= 1;
    let frame = replace_release_values(&fixture.transaction, &retained, &payouts);
    let mut outputs: Vec<_> = fixture.transaction.outputs().into_iter().collect();
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    outputs[1] = outputs[1]
        .clone()
        .as_builder()
        .capacity(retained.vaults[0].value.capacity().unwrap())
        .build();
    let ckb_payout = payouts[0].output_index as usize;
    outputs[ckb_payout] = outputs[ckb_payout]
        .clone()
        .as_builder()
        .capacity(payouts[0].value.capacity().unwrap())
        .build();
    data[2] = xudt_amount_data(retained.vaults[1].value.amount).pack();
    data[payouts[1].output_index as usize] = xudt_amount_data(payouts[1].value.amount).pack();
    let bad = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs(outputs)
        .set_outputs_data(data)
        .build();
    let bad = sign_raw_release(bad, frame);
    let raw = release_frame(&bad);
    let view = factory::FactoryReducedReleaseWitness::parse(&raw).unwrap();
    let token = match retained.vaults[1].asset {
        VaultAsset::Xudt(type_hash) => wire::MultiAssetId { kind: 1, type_hash },
        VaultAsset::Ckb => unreachable!("typed fixture"),
    };
    let claim_ckb = view.right(0).unwrap().before.quantity();
    let claim_token = view.right(1).unwrap().before.quantity();
    let actual_ckb = view
        .withdrawn_value(wire::MultiAssetId::CKB)
        .unwrap()
        .capacity()
        .unwrap() as u128;
    let actual_token = view.withdrawn_value(token).unwrap().amount;
    assert_eq!(claim_ckb + 1, actual_ckb);
    assert_eq!(claim_token, actual_token + 1);
    assert_eq!(claim_ckb + claim_token, actual_ckb + actual_token);
    assert_eq!(
        view.deposited_value(wire::MultiAssetId::CKB).unwrap(),
        wire::MultiAssetAllocation::default()
    );
    assert_eq!(
        view.deposited_value(token).unwrap(),
        wire::MultiAssetAllocation::default()
    );
    rejects(&fixture.base.template.context, &bad, &[39]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_reduced_rights_and_funded_deposit_execute() {
    for operation in [
        morph_core::FactoryTransitionOperation::ReducedRights,
        morph_core::FactoryTransitionOperation::ReducedDeposit,
    ] {
        let fixture = reduced_fixture_operation(1, true, 2, false, operation);
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.root, MAX_CYCLES)
            .expect("valid original rights allocation");
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.activation, MAX_CYCLES)
            .expect("source activation");
        let cycles = fixture
            .base
            .template
            .context
            .verify_tx(&fixture.transaction, MAX_CYCLES)
            .expect("reduced current transition");
        eprintln!("Factory operation={operation:?} cycles={cycles}");
    }
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_full_custody_executes() {
    let operation = morph_core::FactoryTransitionOperation::FullCustody;
    {
        let fixture = reduced_fixture_operation(1, true, 3, false, operation);
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.transaction, MAX_CYCLES)
            .expect("full-consent current transition");
        assert!(
            fixture
                .plan
                .encode_witness(&signature(
                    &signing_key(1),
                    &fixture.plan.signing_digest().unwrap()
                ))
                .is_err(),
            "one signature cannot authorize full consent"
        );
    }
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_rejects_external_token_underfunding_with_permissive_asset() {
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        2,
        true,
        morph_core::FactoryTransitionOperation::ReducedDeposit,
    );
    let index = 1 + fixture.plan.source.vaults.len();
    let input = fixture.transaction.inputs().get(index).unwrap();
    let (cell, data) = fixture
        .base
        .template
        .context
        .get_cell(&input.previous_output())
        .unwrap();
    let amount = u128::from_le_bytes(data.as_ref().try_into().unwrap());
    let replacement = fixture
        .base
        .template
        .context
        .create_cell(cell, xudt_amount_data(amount - 1));
    let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
    inputs[index] = inputs[index]
        .clone()
        .as_builder()
        .previous_output(replacement)
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_inputs(inputs)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[64]);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_rejects_vault_spending_through_metadata_authority() {
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRights,
    );
    let vault = point(&fixture.root, 1);
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .input(CellInput::new_builder().previous_output(vault).build())
        .build();
    let tx = fixture.base.template.context.complete_tx(tx);
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[69]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_full_consent_funded_splice_in_and_signature_roles() {
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        3,
        false,
        morph_core::FactoryTransitionOperation::ReducedDeposit,
    );
    fixture.plan.operation = morph_core::FactoryTransitionOperation::FullCustody;
    fixture.plan.rights.clear();
    fixture.plan.set_locality_digest().unwrap();
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs_data(data)
        .build();
    let tx = resign(&mut fixture, tx);
    fixture
        .base
        .template
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("N-of-N externally funded current splice");
    let args = WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
    let mut frame = args.output_type().to_opt().unwrap().raw_data().to_vec();
    // The second member's signature is required even though the first signed.
    frame[788..852].copy_from_slice(&signature(
        &signing_key(1),
        &fixture.plan.signing_digest().unwrap(),
    ));
    let args = args
        .as_builder()
        .output_type(Some(Bytes::from(frame)).pack())
        .build();
    let bad = tx
        .as_advanced_builder()
        .set_witnesses(vec![args.as_bytes().pack()])
        .build();
    rejects(&fixture.base.template.context, &bad, &[24]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_reduced_child_uses_same_partition_and_child_creation_verifier() {
    let fixture = reduced_fixture_operation(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedChild,
    );
    let cycles = fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, 70_000_000)
        .expect("reduced child creation");
    eprintln!(
        "Factory reduced child cycles={cycles} bytes={}",
        fixture.transaction.data().as_slice().len()
    );
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_reduced_child_private_exit_and_host_signing_prerequisite() {
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedChild,
    );
    let materialisation = fixture.plan.materialisation.as_ref().unwrap();
    let args = WitnessArgs::from_slice(&fixture.transaction.witnesses().get(0).unwrap().raw_data())
        .unwrap();
    let raw = args.output_type().to_opt().unwrap().raw_data();
    for signature in &materialisation.children[0]
        .recovery
        .authorization
        .signatures
    {
        assert!(
            !raw.windows(signature.signature.len())
                .any(|window| window == signature.signature)
        );
    }
    let mut invalid = fixture.plan.clone();
    invalid.materialisation.as_mut().unwrap().children[0]
        .recovery
        .authorization
        .signatures[0]
        .signature[0] ^= 1;
    assert!(
        invalid.signing_digest().is_err(),
        "no Factory signing digest before complete private exit"
    );
    fixture.base.materialisation = fixture.transaction;
    fixture.base.plan = fixture.plan.materialisation.unwrap();
    verify_child_private_exit(&mut fixture.base);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_reduced_child_maximum_bounded_shape_executes() {
    let fixture = reduced_fixture_operation_children(
        8,
        false,
        16,
        true,
        morph_core::FactoryTransitionOperation::ReducedChild,
        4,
    );
    let cycles = fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, 70_000_000)
        .expect("bounded reduced materialisation");
    eprintln!(
        "Factory reduced child assets=8 children=4 members=16 claims=9 cycles={cycles} bytes={}",
        fixture.transaction.data().as_slice().len()
    );
}

#[test]
#[ignore = "requires make build-contracts; optional MORPH_FACTORY_TRANSITION_FIXTURE_OUT exports public fixtures"]
fn factory_multi_asset_transition_interop_fixture_matrix() {
    let operations = [
        morph_core::FactoryTransitionOperation::ReducedRelease,
        morph_core::FactoryTransitionOperation::ReducedRights,
        morph_core::FactoryTransitionOperation::ReducedDeposit,
        morph_core::FactoryTransitionOperation::FullCustody,
        morph_core::FactoryTransitionOperation::ReducedChild,
    ];
    let mut cases = Vec::new();
    for operation in operations {
        let fixture = reduced_fixture_operation(1, true, 2, false, operation);
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.transaction, MAX_CYCLES)
            .expect("exported exact transaction executes in CKB-VM");
        cases.push(serde_json::json!({"operation":format!("{operation:?}"),"package":{"schema":"morph.factory_transition_package.v1","transaction_hex":format!("0x{}",hex::encode(fixture.transaction.data().as_slice()))}}));
    }
    if let Some(path) = std::env::var_os("MORPH_FACTORY_TRANSITION_FIXTURE_OUT") {
        let document = serde_json::json!({"schema":"morph.factory_transition_test_cases.v1","provenance":"Synthetic CKB-VM transactions with test-only keys and assets; source cells exist only in the test Context, not on any deployed network.","cases":cases});
        std::fs::write(
            path,
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .unwrap();
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_reduced_child_rejects_freshly_authorized_physical_redistribution()
{
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedChild,
    );
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    let child = fixture.plan.materialisation.as_ref().unwrap().children[0].clone();
    data[2] = xudt_amount_data(fixture.plan.retained.vaults[1].value.amount - 1).pack();
    data[child.state_output_index as usize + 2] =
        xudt_amount_data(child.recovery.manifest.vaults[1].value.amount + 1).pack();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_outputs_data(data)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[64]);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_reduced_child_rejects_modified_child_keys_after_parent_resigning()
{
    let fixture = reduced_fixture_operation(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedChild,
    );
    let args = WitnessArgs::from_slice(&fixture.transaction.witnesses().get(0).unwrap().raw_data())
        .unwrap();
    let mut frame = args.output_type().to_opt().unwrap().raw_data().to_vec();
    let len = frame.len();
    frame[len - 33..].copy_from_slice(&pubkey(&signing_key(3)));
    let view = factory::FactoryReducedReleaseWitness::parse(&frame).unwrap();
    let digest = view.signing_digest();
    frame[724..788].copy_from_slice(&signature(&signing_key(1), &digest));
    let args = args
        .as_builder()
        .output_type(Some(Bytes::from(frame)).pack())
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_witnesses(vec![args.as_bytes().pack()])
        .build();
    rejects(&fixture.base.template.context, &tx, &[39]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_entire_type_exit_preserves_peer_ckb_in_plain_retained_vault() {
    for operation in [
        morph_core::FactoryTransitionOperation::ReducedRelease,
        morph_core::FactoryTransitionOperation::ReducedChild,
    ] {
        let fixture = reduced_fixture_shape(
            1,
            false,
            2,
            false,
            operation,
            1,
            ExitShape::WholeTokenToPlain,
        );
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.root, MAX_CYCLES)
            .expect("all members approve backed initial entitlements");
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.activation, MAX_CYCLES)
            .expect("source activation");
        fixture
            .base
            .template
            .context
            .verify_tx(&fixture.transaction, MAX_CYCLES)
            .expect("whole-token exit with remaining CKBinplainVault");
        assert_eq!(fixture.plan.retained.vaults[0].asset, VaultAsset::Ckb);
        let ckb = &fixture.plan.rights[0];
        let withdrawn = ckb.before.right.quantity - ckb.after.right.quantity;
        assert_eq!(
            withdrawn,
            fixture.plan.source.vaults[0].value.capacity().unwrap() as u128
                - fixture.plan.retained.vaults[0].value.capacity().unwrap() as u128
        );
        let token = &fixture.plan.rights[1];
        assert_eq!(
            token.before.right.quantity - token.after.right.quantity,
            fixture.plan.source.vaults[0].value.amount
        );
    }
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_entire_type_exit_cannot_charge_retained_peer_ckb() {
    let mut fixture = reduced_fixture_shape(
        1,
        false,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::WholeTokenToPlain,
    );
    fixture.plan.retained.vaults[0].value.business_ckb -= 1;
    fixture.plan.payouts[0].value.business_ckb += 1;
    fixture.plan.after.content_root = fixture.plan.retained.commitment().unwrap();
    fixture.plan.set_locality_digest().unwrap();
    assert!(
        fixture.plan.signing_digest().is_err(),
        "one extra shannon is not covered by touched member's claim decrement"
    );
    let mut fixture = reduced_fixture_shape(
        1,
        false,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::WholeTokenToPlain,
    );
    fixture.plan.rights[0].before.right.id.participant = [2; 32];
    fixture.plan.set_locality_digest().unwrap();
    assert!(
        fixture.plan.signing_digest().is_err(),
        "peer entitlement cannot authorize touched member's release"
    );
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_ten_right_metadata_preserves_flat_profile_atomic_capacity() {
    let mut fixture = reduced_fixture_operation(
        8,
        false,
        16,
        true,
        morph_core::FactoryTransitionOperation::ReducedRights,
    );
    let source_capacity: u128 = fixture
        .plan
        .source
        .vaults
        .iter()
        .map(|v| v.value.capacity().unwrap() as u128)
        .sum();
    let each = source_capacity / 20;
    let mut before: Vec<_> = (0u8..10)
        .map(|i| {
            let mut right = reserve_claim(1, None, each);
            right.id.subchannel = [i; 32];
            right
        })
        .collect();
    before.push(reserve_claim(2, None, source_capacity - 10 * each));
    for vault in &fixture.plan.source.vaults {
        if let VaultAsset::Xudt(hash) = vault.asset {
            before.push(reserve_claim(2, Some(hash), vault.value.amount));
        }
    }
    let mut after = before.clone();
    for right in after.iter_mut().take(10) {
        right.quantity -= 100_000_000;
    }
    let mut approved = fixture.plan.before;
    approved.update_number += 1;
    approved.state_root = factory_right_sparse_root(&before).unwrap();
    let metadata = fixture.base.template.context.complete_tx(
        TransactionBuilder::default()
            .input(fixture.transaction.inputs().get(0).unwrap())
            .output(state_cell(
                CELL_CAPACITY,
                &fixture.base.factory_state_lock,
                &fixture.base.factory_type,
            ))
            .output_data(Bytes::from(approved.encode().unwrap().to_vec()).pack())
            .witness(Bytes::new())
            .build(),
    );
    let digest = factory::FactoryMultiAssetStateHeader::parse(&approved.encode().unwrap())
        .unwrap()
        .update_signing_digest(&metadata.hash().unpack())
        .unwrap();
    let metadata = metadata
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &fixture.plan.source,
                &fixture.plan.source_outpoints,
                &factory_auth(&digest, 16),
            )
            .pack(),
        ])
        .build();
    fixture
        .base
        .template
        .context
        .verify_tx(&metadata, 70_000_000)
        .expect("all-member redistribution with delivered full root data");
    materialise(&mut fixture.base.template.context, &metadata);
    fixture.plan.before = approved;
    fixture.plan.after.update_number = approved.update_number + 1;
    fixture.plan.after.state_root = factory_right_sparse_root(&after).unwrap();
    fixture.plan.old_state = MultiAssetOutPoint {
        tx_hash: metadata.hash().unpack(),
        index: 0,
    };
    fixture.plan.rights = before
        .iter()
        .take(10)
        .map(|right| FactoryReducedReleaseRight {
            before: factory_right_sparse_proof_compact(&before, &right.id).unwrap(),
            after: factory_right_sparse_proof_compact(&after, &right.id).unwrap(),
        })
        .collect();
    fixture.plan.set_locality_digest().unwrap();
    let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
    inputs[0] = inputs[0]
        .clone()
        .as_builder()
        .previous_output(point(&metadata, 0))
        .build();
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_inputs(inputs)
        .set_outputs_data(data)
        .build();
    let tx = resign(&mut fixture, tx);
    let cycles = fixture
        .base
        .template
        .context
        .verify_tx(&tx, 70_000_000)
        .expect("ten touched metadata leaves in one current transaction");
    eprintln!(
        "Factory metadata rights=10 assets=8 members=16 maxscripts512 cycles={cycles} bytes={}",
        tx.data().as_slice().len()
    );
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_token_only_claim_uses_external_recipient_reserve_without_peer_ckb()
 {
    let fixture = reduced_fixture_shape(
        1,
        false,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::TokenOnlyExternalCkb,
    );
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.root, MAX_CYCLES)
        .expect("backed token-only initial entitlement");
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("external reserve pays recipient capacity");
    let raw = fixture.plan.encode_unsigned().unwrap();
    let proof = factory::FactoryReducedReleaseWitness::parse(&raw).unwrap();
    assert_eq!(
        proof
            .withdrawn_value(wire::MultiAssetId::CKB)
            .unwrap()
            .capacity()
            .unwrap(),
        0
    );
    assert!(
        proof
            .deposited_value(wire::MultiAssetId::CKB)
            .unwrap()
            .reserve
            > 0
    );
    assert_eq!(fixture.plan.rights.len(), 1);
    assert!(fixture.plan.rights[0].before.right.id.asset_type.is_some());
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_suboccupied_ckb_claim_merges_with_external_wallet_change() {
    let fixture = reduced_fixture_shape(
        0,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::DustMergedWallet,
    );
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.root, MAX_CYCLES)
        .expect("one-shannon owned claim");
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("merge with independently funded wallet output");
    assert_eq!(
        fixture.plan.rights[0].before.right.quantity - fixture.plan.rights[0].after.right.quantity,
        1
    );
    assert!(fixture.plan.payouts[0].value.capacity().unwrap() > 1);
}
#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_external_payout_topup_cannot_use_peer_reserve_or_unfunded_capacity()
 {
    let mut fixture = reduced_fixture_shape(
        1,
        false,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::TokenOnlyExternalCkb,
    );
    let index = 1 + fixture.plan.source.vaults.len();
    let original = fixture.transaction.inputs().get(index).unwrap();
    let (cell, _) = fixture
        .base
        .template
        .context
        .get_cell(&original.previous_output())
        .unwrap();
    let topup = fixture.plan.payouts[0].value.capacity().unwrap();
    let replacement = fixture.base.template.context.create_cell(
        cell.as_builder()
            .capacity(CELL_CAPACITY + topup - 1)
            .build(),
        Bytes::new(),
    );
    let mut inputs: Vec<_> = fixture.transaction.inputs().into_iter().collect();
    inputs[index] = inputs[index]
        .clone()
        .as_builder()
        .previous_output(replacement)
        .build();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .set_inputs(inputs)
        .build();
    let tx = resign(&mut fixture, tx);
    rejects(&fixture.base.template.context, &tx, &[53]);
    let mut fixture = reduced_fixture_shape(
        1,
        false,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedRelease,
        1,
        ExitShape::TokenOnlyExternalCkb,
    );
    fixture.plan.retained.vaults[0].value.reserve -= 1;
    fixture.plan.after.content_root = fixture.plan.retained.commitment().unwrap();
    fixture.plan.set_locality_digest().unwrap();
    assert!(
        fixture.plan.signing_digest().is_err(),
        "token owner has no entitlement to even one peer-owned CKB shannon"
    );
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_transition_all_member_type_replacement_needs_independent_new_type_funding() {
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        3,
        false,
        morph_core::FactoryTransitionOperation::FullCustody,
    );
    let new_type =
        deploy_always_success_with_args(&mut fixture.base.template.context, Bytes::from(vec![97]));
    let new_hash = new_type.calc_script_hash().unpack();
    let old_type = fixture.plan.source.vaults[1].asset.clone();
    let retained_amount = fixture.plan.retained.vaults[1].value.amount;
    fixture.plan.retained.vaults[1].asset = VaultAsset::Xudt(new_hash);
    fixture.plan.payouts[1].value = fixture.plan.source.vaults[1].value;
    fixture.plan.type_scripts.push(MultiAssetTypeScript {
        type_hash: new_hash,
        script: new_type.as_slice().to_vec(),
    });
    fixture.plan.type_scripts.sort_by_key(|s| s.type_hash);
    fixture.plan.after.content_root = fixture.plan.retained.commitment().unwrap();
    let retained_capacity: u128 = fixture
        .plan
        .retained
        .vaults
        .iter()
        .map(|v| v.value.capacity().unwrap() as u128)
        .sum();
    let mut new_rights = vec![
        reserve_claim(1, None, 0),
        reserve_claim(2, None, retained_capacity),
        reserve_claim(2, Some(new_hash), retained_amount),
    ];
    new_rights.sort_by(|a, b| a.id.cmp(&b.id));
    fixture.plan.after.state_root = factory_right_sparse_root(&new_rights).unwrap();
    fixture.plan.set_locality_digest().unwrap();
    let input = fixture.base.template.context.create_cell(
        CellOutput::new_builder()
            .capacity(fixture.plan.retained.vaults[1].value.capacity().unwrap())
            .lock(fixture.base.template.locks[0].clone())
            .type_(Some(new_type.clone()).pack())
            .build(),
        xudt_amount_data(retained_amount),
    );
    let mut outputs: Vec<_> = fixture.transaction.outputs().into_iter().collect();
    let mut data: Vec<_> = fixture.transaction.outputs_data().into_iter().collect();
    outputs[2] = outputs[2]
        .clone()
        .as_builder()
        .type_(Some(new_type).pack())
        .build();
    outputs[4] = outputs[4]
        .clone()
        .as_builder()
        .capacity(fixture.plan.payouts[1].value.capacity().unwrap())
        .build();
    data[0] = Bytes::from(fixture.plan.after.encode().unwrap().to_vec()).pack();
    data[4] = xudt_amount_data(fixture.plan.payouts[1].value.amount).pack();
    let tx = fixture
        .transaction
        .as_advanced_builder()
        .input(
            CellInput::new_builder()
                .previous_output(input.clone())
                .build(),
        )
        .set_outputs(outputs)
        .set_outputs_data(data)
        .build();
    let tx = fixture.base.template.context.complete_tx(tx);
    let tx = resign(&mut fixture, tx);
    fixture
        .base
        .template
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("old Type fully withdrawn, new Type independently funded");
    assert_ne!(old_type, fixture.plan.retained.vaults[1].asset);
    // New test asset is permissive: Morph must reject an underfunded Type
    // itself even when aggregate token numbers would look unchanged.
    let (cell, _) = fixture.base.template.context.get_cell(&input).unwrap();
    let replacement = fixture
        .base
        .template
        .context
        .create_cell(cell, xudt_amount_data(retained_amount - 1));
    let mut inputs: Vec<_> = tx.inputs().into_iter().collect();
    let last = inputs.len() - 1;
    inputs[last] = inputs[last]
        .clone()
        .as_builder()
        .previous_output(replacement)
        .build();
    let bad = tx.as_advanced_builder().set_inputs(inputs).build();
    let bad = resign(&mut fixture, bad);
    rejects(&fixture.base.template.context, &bad, &[64]);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_reduced_child_can_pay_outsiders_but_not_authorize_them_as_factory_members() {
    let mut fixture = reduced_fixture_operation(
        1,
        true,
        2,
        false,
        morph_core::FactoryTransitionOperation::ReducedChild,
    );
    let outsider_keys = [signing_key(9), signing_key(10)];
    let transaction = child_parties(
        fixture.plan.materialisation.as_mut().unwrap(),
        fixture.transaction.clone(),
        &outsider_keys,
    );
    fixture.plan.transaction_hash = transaction.hash().unpack();
    fixture.transaction = sign_release(&fixture.plan, transaction);
    fixture
        .base
        .template
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("one owner can transfer their proved rights into an external-party child");

    let mut raw = fixture.plan.encode_unsigned().unwrap();
    let unauthorized = signature(&outsider_keys[0], &fixture.plan.signing_digest().unwrap());
    let signature_end = factory::FACTORY_REDUCED_RELEASE_PREFIX_LEN;
    raw[signature_end - ECDSA_SIGNATURE_LEN..signature_end].copy_from_slice(&unauthorized);
    let wrong_authorizer = fixture
        .transaction
        .clone()
        .as_advanced_builder()
        .set_witnesses(vec![
            WitnessArgs::new_builder()
                .output_type(Some(Bytes::from(raw)).pack())
                .build()
                .as_bytes()
                .pack(),
        ])
        .build();
    rejects(
        &fixture.base.template.context,
        &wrong_authorizer,
        &[ScriptError::InvalidParticipantSignature as i8],
    );

    fixture.base.plan = fixture.plan.materialisation.unwrap();
    fixture.base.materialisation = fixture.transaction;
    verify_child_private_exit(&mut fixture.base);
}
