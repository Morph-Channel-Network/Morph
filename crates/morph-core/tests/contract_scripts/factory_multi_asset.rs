use super::*;
use morph_core::{
    FactoryMultiAssetChild, FactoryMultiAssetMaterialisation, FactoryParticipantSignature,
    encode_factory_all_participant_signatures, encode_factory_multi_asset_state_witness,
};
use morph_script_common::factory_multi_asset as factory;

fn factory_auth(digest: &[u8; 32], n: u8) -> Vec<FactoryParticipantSignature> {
    (1..=n)
        .map(|seed| {
            let key = signing_key(seed);
            FactoryParticipantSignature {
                participant: [seed; 32],
                pubkey_sec1: pubkey(&key).to_vec(),
                signature: signature(&key, digest).to_vec(),
            }
        })
        .collect()
}
fn members(n: u8) -> [u8; 32] {
    let auth = factory_auth(&[1; 32], n);
    morph_script_common::FactorySignatureWitness::parse(
        &encode_factory_all_participant_signatures(&auth).unwrap(),
    )
    .unwrap()
    .participants_commitment()
}
fn fs_witness(
    kind: u16,
    manifest: &MultiAssetManifest,
    points: &[MultiAssetOutPoint],
    auth: &[FactoryParticipantSignature],
) -> Bytes {
    WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                encode_factory_multi_asset_state_witness(kind, manifest, points, auth).unwrap(),
            ))
            .pack(),
        )
        .build()
        .as_bytes()
}
fn state_cell(capacity: u64, lock: &Script, ty: &Script) -> CellOutput {
    CellOutput::new_builder()
        .capacity(capacity)
        .lock(lock.clone())
        .type_(Some(ty.clone()).pack())
        .build()
}
fn manifest_outputs(
    mut tx: TransactionBuilder,
    manifest: &MultiAssetManifest,
    lock: &Script,
    types: &[Option<Script>],
) -> TransactionBuilder {
    for (vault, ty) in manifest.vaults.iter().zip(types) {
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(vault.value.capacity().unwrap())
                    .lock(lock.clone())
                    .type_(ty.clone().pack())
                    .build(),
            )
            .output_data(
                if ty.is_some() {
                    xudt_amount_data(vault.value.amount)
                } else {
                    Bytes::new()
                }
                .pack(),
            );
    }
    tx
}
struct FactoryFixture {
    template: Fixture,
    factory_type: Script,
    factory_state_lock: Script,
    factory_vault_lock: Script,
    header: factory::FactoryMultiAssetHeaderFields,
    root: TransactionView,
    active: TransactionView,
    materialisation: TransactionView,
    plan: FactoryMultiAssetMaterialisation,
    n: u8,
}
fn build_factory_profile(
    typed: usize,
    plain: bool,
    child_count: usize,
    retain: bool,
    n: u8,
    maximum_scripts: bool,
) -> FactoryFixture {
    let mut template = build_profile(typed, false, plain, maximum_scripts);
    if maximum_scripts {
        let mut types = (0..typed)
            .map(|i| {
                deploy_always_success_with_args(
                    &mut template.context,
                    Bytes::from(vec![100 + i as u8; 459]),
                )
            })
            .collect::<Vec<_>>();
        types.sort_by_key(Script::calc_script_hash);
        for (i, ty) in types.iter().enumerate() {
            let index = i + usize::from(plain);
            let id = VaultAsset::Xudt(ty.calc_script_hash().unpack());
            template.package.manifest.vaults[index].asset = id.clone();
            template.package.settlement.payouts[index].asset = id;
        }
        template.package.scripts.type_scripts = types
            .iter()
            .map(|ty| MultiAssetTypeScript {
                type_hash: ty.calc_script_hash().unpack(),
                script: ty.as_slice().to_vec(),
            })
            .collect();
        template.vault_types = if plain { vec![None] } else { vec![] };
        template.vault_types.extend(types.iter().cloned().map(Some));
        template.types = types;
        template.package.state.header.asset_registry_commitment =
            asset_registry_commitment(&template.package.manifest.registry().unwrap());
        template
            .package
            .state
            .header
            .settlement_descriptor_commitment = template.package.settlement.commitment().unwrap();
    }
    let wallet = template.locks[0].clone();
    let count = template.package.manifest.vaults.len();
    let scale = child_count as u64 + u64::from(retain);
    let root_wallet = template.context.create_cell(
        CellOutput::new_builder()
            .capacity(
                2 * CELL_CAPACITY
                    + if plain {
                        template.package.manifest.vaults[0]
                            .value
                            .capacity()
                            .unwrap()
                            * scale
                    } else {
                        0
                    }
                    + 10_000,
            )
            .lock(wallet.clone())
            .build(),
        Bytes::new(),
    );
    let first = CellInput::new_builder()
        .previous_output(root_wallet)
        .build();
    let id = derived_funding_anchor(&first, 0);
    let factory_type = deploy_contract(
        &mut template.context,
        "morph-factory-type",
        factory::encode_factory_multi_asset_type_args(&id)
            .unwrap()
            .to_vec(),
    );
    let factory_state_lock = deploy_contract(
        &mut template.context,
        "morph-state-lock",
        factory_type.calc_script_hash().as_slice().to_vec(),
    );
    let mut args = id.to_vec();
    args.extend_from_slice(factory_type.calc_script_hash().as_slice());
    let factory_vault_lock =
        deploy_contract(&mut template.context, "morph-factory-vault-lock", args);
    let mut source = template.package.manifest.clone();
    for vault in &mut source.vaults {
        vault.lock_hash = factory_vault_lock.calc_script_hash().unpack();
        vault.value.reserve *= scale;
        vault.value.business_ckb *= scale;
        vault.value.amount *= scale as u128;
    }
    let mut header = factory::FactoryMultiAssetHeaderFields {
        chain_id: [1; 32],
        factory_id: id,
        update_number: 0,
        state_root: [9; 32],
        participants_commitment: members(n),
        access_manifest_root: [10; 32],
        non_interference_digest: [11; 32],
        challenge_policy_commitment: [12; 32],
        content_root: source.commitment().unwrap(),
        outpoint_root: [0; 32],
        vault_count: count as u16,
    };
    let mut root = TransactionBuilder::default()
        .input(first)
        .output(state_cell(
            CELL_CAPACITY,
            &factory_state_lock,
            &factory_type,
        ))
        .output_data(Bytes::from(header.encode().unwrap().to_vec()).pack());
    for (vault, ty) in source.vaults.iter().zip(&template.vault_types) {
        if let Some(ty) = ty {
            let point = template.context.create_cell(
                CellOutput::new_builder()
                    .capacity(vault.value.capacity().unwrap())
                    .lock(wallet.clone())
                    .type_(Some(ty.clone()).pack())
                    .build(),
                xudt_amount_data(vault.value.amount),
            );
            root = root.input(CellInput::new_builder().previous_output(point).build());
        }
    }
    root = manifest_outputs(root, &source, &factory_vault_lock, &template.vault_types)
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wallet.clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    let root = template
        .context
        .complete_tx(root.witness(Bytes::new()).build());
    let digest = factory::FactoryMultiAssetStateHeader::parse(&header.encode().unwrap())
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
    materialise(&mut template.context, &root);
    let source_points = (0..count)
        .map(|i| MultiAssetOutPoint {
            tx_hash: root.hash().unpack(),
            index: i as u32 + 1,
        })
        .collect::<Vec<_>>();
    header.outpoint_root = multi_asset_outpoint_commitment(&source, &source_points).unwrap();
    let fee = template.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY + 10_000)
            .lock(wallet.clone())
            .build(),
        Bytes::new(),
    );
    let mut active = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&root, 0))
                .build(),
        )
        .input(CellInput::new_builder().previous_output(fee).build())
        .output(state_cell(
            CELL_CAPACITY,
            &factory_state_lock,
            &factory_type,
        ))
        .output_data(Bytes::from(header.encode().unwrap().to_vec()).pack())
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wallet.clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    for i in 0..count {
        active = active.cell_dep(
            CellDep::new_builder()
                .out_point(point(&root, i + 1))
                .build(),
        );
    }
    let active = template.context.complete_tx(
        active
            .witness(fs_witness(
                factory::FACTORY_STATE_WITNESS_ACTIVATE,
                &source,
                &source_points,
                &[],
            ))
            .build(),
    );
    materialise(&mut template.context, &active);
    let old_state = point(&active, 0);
    let retained = if retain {
        let mut m = template.package.manifest.clone();
        for vault in &mut m.vaults {
            vault.lock_hash = factory_vault_lock.calc_script_hash().unpack();
        }
        Some(m)
    } else {
        None
    };
    let mut children = Vec::new();
    for i in 0..child_count {
        let state_index = (if retain { 1 + count } else { 1 }) + i * (count + 1);
        let mut package = template.package.clone();
        let first = CellInput::new_builder()
            .previous_output(old_state.clone())
            .build();
        let anchor = derived_funding_anchor(&first, state_index as u64);
        let mut child_args = anchor.to_vec();
        child_args.extend_from_slice(factory_type.calc_script_hash().as_slice());
        child_args.extend_from_slice(&template.since.to_le_bytes());
        let ty = deploy_contract(&mut template.context, "morph-state-type", child_args);
        let lock = deploy_contract(
            &mut template.context,
            "morph-state-lock",
            ty.calc_script_hash().as_slice().to_vec(),
        );
        let args = wire::encode_multi_asset_vault_args(
            &anchor,
            template.since,
            &ty.calc_script_hash().unpack(),
            &lock.calc_script_hash().unpack(),
        )
        .unwrap();
        let vault = deploy_contract(&mut template.context, "morph-vault-lock", args.to_vec());
        package.scripts.state_type = ty.as_slice().to_vec();
        package.scripts.state_lock = lock.as_slice().to_vec();
        package.scripts.vault_lock = vault.as_slice().to_vec();
        for entry in &mut package.manifest.vaults {
            entry.lock_hash = vault.calc_script_hash().unpack();
        }
        package.state.header.funding_anchor = anchor;
        package.state.header.channel_id = blake2b256(&[&anchor]);
        package.state.header.phase = Phase::Active;
        package.state.header.state_number = 0;
        package.state.vault_content_set_root = package.manifest.commitment().unwrap();
        package.state.vault_outpoint_set_root = [0; 32];
        package.outpoints.clear();
        children.push(FactoryMultiAssetChild {
            state_output_index: state_index as u32,
            recovery: package,
        });
    }
    let fee = template.context.create_cell(
        CellOutput::new_builder()
            .capacity((child_count as u64 + 1) * CELL_CAPACITY + 10_000)
            .lock(wallet.clone())
            .build(),
        Bytes::new(),
    );
    let mut tx = TransactionBuilder::default().input(
        CellInput::new_builder()
            .previous_output(old_state.clone())
            .build(),
    );
    for i in 0..count {
        tx = tx.input(
            CellInput::new_builder()
                .previous_output(point(&root, i + 1))
                .build(),
        );
    }
    tx = tx.input(CellInput::new_builder().previous_output(fee).build());
    if let Some(retained) = &retained {
        let mut next = header;
        next.update_number = 1;
        next.state_root = [13; 32];
        next.content_root = retained.commitment().unwrap();
        next.outpoint_root = [0; 32];
        tx = tx
            .output(state_cell(
                CELL_CAPACITY,
                &factory_state_lock,
                &factory_type,
            ))
            .output_data(Bytes::from(next.encode().unwrap().to_vec()).pack());
        tx = manifest_outputs(tx, retained, &factory_vault_lock, &template.vault_types);
    } else {
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(CELL_CAPACITY)
                    .lock(wallet.clone())
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }
    for child in &children {
        let package = &child.recovery;
        let ty = Script::from_slice(&package.scripts.state_type).unwrap();
        let lock = Script::from_slice(&package.scripts.state_lock).unwrap();
        let vault = Script::from_slice(&package.scripts.vault_lock).unwrap();
        tx = tx
            .output(state_cell(CELL_CAPACITY, &lock, &ty))
            .output_data(Bytes::from(package.state.encode().unwrap().to_vec()).pack());
        tx = manifest_outputs(tx, &package.manifest, &vault, &template.vault_types);
    }
    tx = tx
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wallet.clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    let tx = template
        .context
        .complete_tx(tx.witness(Bytes::new()).build());
    for child in &mut children {
        let package = &mut child.recovery;
        package.state.header.phase = Phase::Settling;
        package.state.header.state_number = 1;
        package.outpoints = (0..count)
            .map(|j| MultiAssetOutPoint {
                tx_hash: tx.hash().unpack(),
                index: child.state_output_index + 1 + j as u32,
            })
            .collect();
        package.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
        signed(package);
    }
    let plan = FactoryMultiAssetMaterialisation {
        chain_id: [1; 32],
        factory_id: id,
        participants_commitment: members(n),
        old_state: MultiAssetOutPoint {
            tx_hash: active.hash().unpack(),
            index: 0,
        },
        transaction_hash: tx.hash().unpack(),
        source,
        source_outpoints: source_points,
        factory_vault_lock: factory_vault_lock.as_slice().to_vec(),
        type_scripts: template.package.scripts.type_scripts.clone(),
        retained,
        factory_carrier_capacity: CELL_CAPACITY,
        external_carrier_contribution: child_count as u64 * CELL_CAPACITY,
        carrier_refund_lock: if retain {
            vec![]
        } else {
            wallet.as_slice().to_vec()
        },
        children,
    };
    let witness = plan
        .encode_witness(
            &members(n),
            &factory_auth(&plan.signing_digest().unwrap(), n),
        )
        .unwrap();
    let args = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(witness)).pack())
        .build();
    let materialisation = tx
        .as_advanced_builder()
        .set_witnesses(vec![args.as_bytes().pack()])
        .build();
    FactoryFixture {
        template,
        factory_type,
        factory_state_lock,
        factory_vault_lock,
        header,
        root,
        active,
        materialisation,
        plan,
        n,
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_root_activation_and_materialisation_execute_in_vm() {
    for (typed, plain, children, retained, n) in [
        (2, false, 1, false, 2),
        (7, true, 1, true, 3),
        (8, false, 4, true, 16),
    ] {
        let fixture = build_factory_profile(typed, plain, children, retained, n, false);
        fixture
            .template
            .context
            .verify_tx(&fixture.root, MAX_CYCLES)
            .expect("Factory root");
        fixture
            .template
            .context
            .verify_tx(&fixture.active, MAX_CYCLES)
            .expect("Factory activation");
        let cycles = fixture
            .template
            .context
            .verify_tx(&fixture.materialisation, 70_000_000)
            .expect("Factory materialisation");
        eprintln!(
            "Factory assets={} children={children} participants={n} cycles={cycles}",
            typed + usize::from(plain)
        );
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_maximum_script_profile_has_a_measured_cycle_bound() {
    let fixture = build_factory_profile(8, false, 4, true, 16, true);
    let cycles = fixture
        .template
        .context
        .verify_tx(&fixture.materialisation, 70_000_000)
        .expect("maximum-script Factory materialisation");
    assert!(cycles < 53_000_000);
    assert!(fixture.materialisation.data().as_slice().len() <= 54_000);
    eprintln!(
        "Factory maximum scripts assets=8 children=4 participants=16 cycles={cycles} bytes={}",
        fixture.materialisation.data().as_slice().len()
    );
}

// Re-sign the new raw transaction so physical-boundary tests cannot pass merely
// because the original transaction commitment no longer matches.
fn reauthorise(f: &FactoryFixture, tx: TransactionView) -> TransactionView {
    let mut plan = f.plan.clone();
    plan.transaction_hash = tx.hash().unpack();
    for child in &mut plan.children {
        for p in &mut child.recovery.outpoints {
            p.tx_hash = plan.transaction_hash;
        }
        child.recovery.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&child.recovery.manifest, &child.recovery.outpoints)
                .unwrap();
        signed(&mut child.recovery);
    }
    let frame = plan
        .encode_witness(
            &members(f.n),
            &factory_auth(&plan.signing_digest().unwrap(), f.n),
        )
        .unwrap();
    tx.as_advanced_builder()
        .set_witnesses(vec![
            WitnessArgs::new_builder()
                .output_type(Some(Bytes::from(frame)).pack())
                .build()
                .as_bytes()
                .pack(),
        ])
        .build()
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_rejects_physical_changes_even_with_fresh_all_member_approval() {
    let f = build_factory_profile(2, false, 1, true, 3, false);
    // Carrier and Vault capacity cannot leak into fees or another output.
    for index in [
        0,
        1,
        f.plan.children[0].state_output_index as usize,
        f.plan.children[0].state_output_index as usize + 1,
    ] {
        let mut outputs: Vec<_> = f.materialisation.outputs().into_iter().collect();
        let capacity: u64 = outputs[index].capacity().unpack();
        outputs[index] = outputs[index]
            .clone()
            .as_builder()
            .capacity(capacity - 1)
            .build();
        let changed = f
            .materialisation
            .as_advanced_builder()
            .set_outputs(outputs)
            .build();
        let changed = reauthorise(&f, changed);
        assert!(
            f.template.context.verify_tx(&changed, 70_000_000).is_err(),
            "capacity index {index}"
        );
    }
    let mut inputs: Vec<_> = f.materialisation.inputs().into_iter().collect();
    inputs.swap(1, 2);
    let changed = reauthorise(
        &f,
        f.materialisation
            .as_advanced_builder()
            .set_inputs(inputs)
            .build(),
    );
    assert!(f.template.context.verify_tx(&changed, 70_000_000).is_err());
    let mut data: Vec<_> = f.materialisation.outputs_data().into_iter().collect();
    let index = f.plan.children[0].state_output_index as usize + 1;
    data[index] = xudt_amount_data(1).pack();
    let changed = reauthorise(
        &f,
        f.materialisation
            .as_advanced_builder()
            .set_outputs_data(data)
            .build(),
    );
    assert!(f.template.context.verify_tx(&changed, 70_000_000).is_err());
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_metadata_update_preserves_custody_and_requires_all_members() {
    let mut f = build_factory_profile(2, false, 1, true, 3, false);
    assert_eq!(f.factory_vault_lock.as_slice(), f.plan.factory_vault_lock);
    let mut fields = f.header;
    fields.update_number += 1;
    fields.state_root = [23; 32];
    let raw = fields.encode().unwrap();
    let digest = factory::FactoryMultiAssetStateHeader::parse(&raw)
        .unwrap()
        .signing_digest();
    let tx = f.template.context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(point(&f.active, 0))
                    .build(),
            )
            .output(state_cell(
                f.plan.factory_carrier_capacity,
                &f.factory_state_lock,
                &f.factory_type,
            ))
            .output_data(Bytes::from(raw.to_vec()).pack())
            .witness(fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &f.plan.source,
                &f.plan.source_outpoints,
                &factory_auth(&digest, f.n),
            ))
            .build(),
    );
    let digest = factory::FactoryMultiAssetStateHeader::parse(&raw)
        .unwrap()
        .update_signing_digest(&tx.hash().unpack())
        .unwrap();
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &f.plan.source,
                &f.plan.source_outpoints,
                &factory_auth(&digest, f.n),
            )
            .pack(),
        ])
        .build();
    f.template.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    let header_only = factory::FactoryMultiAssetStateHeader::parse(&raw)
        .unwrap()
        .signing_digest();
    let old = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &f.plan.source,
                &f.plan.source_outpoints,
                &factory_auth(&header_only, f.n),
            )
            .pack(),
        ])
        .build();
    rejects(&f.template.context, &old, &[24]);
    let args = WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
    let mut frame = args.input_type().to_opt().unwrap().raw_data().to_vec();
    frame[8..10].copy_from_slice(&1u16.to_le_bytes());
    let old = args
        .as_builder()
        .input_type(Some(Bytes::from(frame)).pack())
        .build();
    let old = tx
        .as_advanced_builder()
        .set_witnesses(vec![old.as_bytes().pack()])
        .build();
    rejects(&f.template.context, &old, &[69]);
    let short = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            fs_witness(
                factory::FACTORY_STATE_WITNESS_UPDATE,
                &f.plan.source,
                &f.plan.source_outpoints,
                &factory_auth(&digest, f.n - 1),
            )
            .pack(),
        ])
        .build();
    assert!(f.template.context.verify_tx(&short, MAX_CYCLES).is_err());
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_child_uses_private_exit_after_parent_retirement() {
    let mut f = build_factory_profile(2, false, 1, false, 2, false);
    verify_child_private_exit(&mut f);
}
fn verify_child_private_exit(f: &mut FactoryFixture) {
    f.template
        .context
        .verify_tx(&f.materialisation, 70_000_000)
        .unwrap();
    materialise(&mut f.template.context, &f.materialisation);
    let child = &f.plan.children[0];
    let package = child.recovery.clone();
    let index = child.state_output_index as usize;
    let mut active = package.clone();
    active.state.header.phase = Phase::Active;
    active.state.header.state_number = 0;
    let mut builder = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&f.materialisation, index))
                .build(),
        )
        .output(f.materialisation.outputs().get(index).unwrap())
        .output_data(Bytes::from(active.state.encode().unwrap().to_vec()).pack())
        .witness(evidence(&active, false));
    for p in &package.outpoints {
        builder = builder.cell_dep(
            CellDep::new_builder()
                .out_point(
                    OutPoint::new_builder()
                        .tx_hash(p.tx_hash.pack())
                        .index(p.index)
                        .build(),
                )
                .build(),
        );
    }
    let activation = f.template.context.complete_tx(builder.build());
    f.template
        .context
        .verify_tx(&activation, MAX_CYCLES)
        .unwrap();
    materialise(&mut f.template.context, &activation);
    let publication = f.template.context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(point(&activation, 0))
                    .build(),
            )
            .output(activation.outputs().get(0).unwrap())
            .output_data(Bytes::from(package.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&package, true))
            .build(),
    );
    f.template
        .context
        .verify_tx(&publication, MAX_CYCLES)
        .unwrap();
    materialise(&mut f.template.context, &publication);
    f.template.state_type = Script::from_slice(&package.scripts.state_type).unwrap();
    f.template.state_lock = Script::from_slice(&package.scripts.state_lock).unwrap();
    f.template.vault_lock = Script::from_slice(&package.scripts.vault_lock).unwrap();
    f.template.package = package;
    f.template.supersede = publication;
    let exit = finalise(&mut f.template);
    f.template.context.verify_tx(&exit, MAX_CYCLES).unwrap();
}

// Changing recipients changes the actual creation header and raw transaction.
// Rebuild both independent child exits before obtaining a fresh parent vote.
fn child_parties(
    plan: &mut FactoryMultiAssetMaterialisation,
    transaction: TransactionView,
    keys: &[SigningKey; 2],
) -> TransactionView {
    let mut keys = keys.clone();
    keys.sort_by_key(pubkey);
    let public = keys.each_ref().map(pubkey);
    let mut data = transaction.outputs_data().into_iter().collect::<Vec<_>>();
    for child in &mut plan.children {
        child.recovery.state.header.participants_commitment =
            participants_commitment(2, &[&public[0], &public[1]]);
        let mut creation = child.recovery.state.clone();
        creation.header.phase = Phase::Active;
        creation.header.state_number = 0;
        creation.vault_outpoint_set_root = [0; 32];
        data[child.state_output_index as usize] =
            Bytes::from(creation.encode().unwrap().to_vec()).pack();
    }
    let transaction = transaction
        .as_advanced_builder()
        .set_outputs_data(data)
        .build();
    plan.transaction_hash = transaction.hash().unpack();
    for child in &mut plan.children {
        for point in &mut child.recovery.outpoints {
            point.tx_hash = plan.transaction_hash;
        }
        child.recovery.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&child.recovery.manifest, &child.recovery.outpoints)
                .unwrap();
        let digest = child.recovery.state.signing_digest().unwrap();
        child.recovery.authorization = StateAuthorization {
            threshold: 2,
            signatures: keys
                .iter()
                .map(|key| ParticipantSignature {
                    pubkey_sec1: pubkey(key).to_vec(),
                    signature: signature(key, &digest).to_vec(),
                })
                .collect(),
        };
    }
    transaction
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_materialises_outside_parties_with_independent_private_exits() {
    let mut fixture = build_factory_profile(1, true, 1, false, 2, false);
    let keys = [signing_key(9), signing_key(10)];
    let transaction = child_parties(&mut fixture.plan, fixture.materialisation.clone(), &keys);
    let frame = fixture
        .plan
        .encode_witness(
            &members(fixture.n),
            &factory_auth(&fixture.plan.signing_digest().unwrap(), fixture.n),
        )
        .unwrap();
    fixture.materialisation = transaction
        .as_advanced_builder()
        .set_witnesses(vec![
            WitnessArgs::new_builder()
                .output_type(Some(Bytes::from(frame)).pack())
                .build()
                .as_bytes()
                .pack(),
        ])
        .build();
    verify_child_private_exit(&mut fixture);
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_retained_custody_reactivates_and_rejects_noncanonical_deps() {
    let mut f = build_factory_profile(2, false, 1, true, 3, false);
    materialise(&mut f.template.context, &f.materialisation);
    let manifest = f.plan.retained.as_ref().unwrap();
    let mut raw = f
        .materialisation
        .outputs_data()
        .get(0)
        .unwrap()
        .raw_data()
        .to_vec();
    let points = (0..manifest.vaults.len())
        .map(|i| MultiAssetOutPoint {
            tx_hash: f.materialisation.hash().unpack(),
            index: 1 + i as u32,
        })
        .collect::<Vec<_>>();
    raw[270..302].copy_from_slice(&multi_asset_outpoint_commitment(manifest, &points).unwrap());
    let mut builder = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&f.materialisation, 0))
                .build(),
        )
        .output(f.materialisation.outputs().get(0).unwrap())
        .output_data(Bytes::from(raw).pack())
        .witness(fs_witness(
            factory::FACTORY_STATE_WITNESS_ACTIVATE,
            manifest,
            &points,
            &[],
        ));
    for i in 0..points.len() {
        builder = builder.cell_dep(
            CellDep::new_builder()
                .out_point(point(&f.materialisation, 1 + i))
                .build(),
        );
    }
    let tx = f.template.context.complete_tx(builder.build());
    f.template.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    let mut deps: Vec<_> = tx.cell_deps().into_iter().collect();
    deps.swap(0, 1);
    let changed = tx.as_advanced_builder().set_cell_deps(deps).build();
    assert!(f.template.context.verify_tx(&changed, MAX_CYCLES).is_err());
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_multi_asset_root_approval_cannot_reprice_the_transaction() {
    let f = build_factory_profile(2, false, 1, false, 2, false);
    let mut outputs: Vec<_> = f.root.outputs().into_iter().collect();
    let index = outputs.len() - 1;
    let capacity: u64 = outputs[index].capacity().unpack();
    outputs[index] = outputs[index]
        .clone()
        .as_builder()
        .capacity(capacity - 1)
        .build();
    let changed = f.root.as_advanced_builder().set_outputs(outputs).build();
    assert!(f.template.context.verify_tx(&changed, MAX_CYCLES).is_err());
}

#[path = "factory_multi_asset_reduced.rs"]
mod reduced;
