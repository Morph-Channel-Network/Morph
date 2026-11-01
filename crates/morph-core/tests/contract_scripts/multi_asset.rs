use super::*;
use morph_core::{
    Mode, MultiAssetManifest, MultiAssetOutPoint, MultiAssetPayout, MultiAssetRecoveryPackage,
    MultiAssetRecoveryScripts, MultiAssetSettlement, MultiAssetState, MultiAssetTypeScript,
    MultiAssetValue, MultiAssetVault, ParticipantSignature, Phase, StateAuthorization, VaultAsset,
    asset_registry_commitment, encode_multi_asset_signatures, encode_multi_asset_witness,
    multi_asset_outpoint_commitment,
};
use morph_script_common::multi_asset as wire;

struct Fixture {
    context: Context,
    package: MultiAssetRecoveryPackage,
    state_type: ckb_testtool::ckb_types::packed::Script,
    state_lock: ckb_testtool::ckb_types::packed::Script,
    vault_lock: ckb_testtool::ckb_types::packed::Script,
    locks: [ckb_testtool::ckb_types::packed::Script; 2],
    types: Vec<ckb_testtool::ckb_types::packed::Script>,
    vault_types: Vec<Option<ckb_testtool::ckb_types::packed::Script>>,
    funding: TransactionView,
    activation: TransactionView,
    publication: TransactionView,
    supersede: TransactionView,
    since: u64,
}

fn point(tx: &TransactionView, index: usize) -> ckb_testtool::ckb_types::packed::OutPoint {
    ckb_testtool::ckb_types::packed::OutPoint::new_builder()
        .tx_hash(tx.hash())
        .index(index as u32)
        .build()
}

fn materialise(context: &mut Context, tx: &TransactionView) {
    for (index, (output, data)) in tx.outputs().into_iter().zip(tx.outputs_data()).enumerate() {
        context.create_cell_with_out_point(point(tx, index), output, data.raw_data());
    }
}

fn signed(package: &mut MultiAssetRecoveryPackage) {
    let mut keys = [signing_key(1), signing_key(2)];
    keys.sort_by_key(pubkey);
    let pubkeys = keys.each_ref().map(pubkey);
    package.state.header.participants_commitment =
        participants_commitment(2, &[&pubkeys[0], &pubkeys[1]]);
    let digest = package.state.signing_digest().unwrap();
    package.authorization = StateAuthorization {
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

fn evidence(package: &MultiAssetRecoveryPackage, signatures: bool) -> Bytes {
    let raw = encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )
    .unwrap();
    let input_type = signatures.then(|| {
        Bytes::from(
            encode_multi_asset_signatures(&package.authorization)
                .unwrap()
                .to_vec(),
        )
    });
    WitnessArgs::new_builder()
        .input_type(input_type.pack())
        .output_type(Some(Bytes::from(raw)).pack())
        .build()
        .as_bytes()
}

fn state_output(fixture: &Fixture) -> CellOutput {
    CellOutput::new_builder()
        .capacity(fixture.package.state_carrier_capacity)
        .lock(fixture.state_lock.clone())
        .type_(Some(fixture.state_type.clone()).pack())
        .build()
}

fn build(count: usize, one_sided: bool) -> Fixture {
    build_with_plain(count, one_sided, false)
}

fn build_with_plain(typed_count: usize, one_sided: bool, plain: bool) -> Fixture {
    let mut context = Context::default();
    let wallet = deploy_always_success_with_args(&mut context, Bytes::from(vec![99]));
    let mut locks = [
        deploy_always_success_with_args(&mut context, Bytes::from(vec![1])),
        deploy_always_success_with_args(&mut context, Bytes::from(vec![2])),
    ];
    locks.sort_by_key(|lock| lock.calc_script_hash());
    let carrier_capacity = CELL_CAPACITY;
    let funding_wallet = context.create_cell(
        CellOutput::new_builder()
            .capacity(carrier_capacity + if plain { 50_000_000_000 } else { 0 } + 10_000)
            .lock(wallet.clone())
            .build(),
        Bytes::new(),
    );
    let funding_input = CellInput::new_builder()
        .previous_output(funding_wallet)
        .build();
    let anchor = derived_funding_anchor(&funding_input, 0);
    let since = relative_since(6);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(anchor, since),
    );
    let state_type_hash = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(
        &mut context,
        "morph-state-lock",
        state_type.calc_script_hash().as_slice().to_vec(),
    );
    let vault_args = wire::encode_multi_asset_vault_args(
        &anchor,
        since,
        &state_type_hash,
        &state_lock.calc_script_hash().unpack(),
    )
    .unwrap();
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_args.to_vec());
    let mut types: Vec<_> = (0..typed_count)
        .map(|i| deploy_contract(&mut context, "morph-devnet-xudt", vec![(i + 1) as u8; 32]))
        .collect();
    types.sort_by_key(|script| script.calc_script_hash());
    let mut vault_types = if plain { vec![None] } else { vec![] };
    vault_types.extend(types.iter().cloned().map(Some));
    let count = vault_types.len();
    let manifest = MultiAssetManifest {
        vaults: vault_types
            .iter()
            .map(|script| MultiAssetVault {
                asset: script
                    .as_ref()
                    .map(|script| VaultAsset::Xudt(script.calc_script_hash().unpack()))
                    .unwrap_or(VaultAsset::Ckb),
                lock_hash: vault_lock.calc_script_hash().unpack(),
                value: MultiAssetValue {
                    reserve: 40_000_000_000,
                    business_ckb: 10_000_000_000,
                    amount: if script.is_some() { 1000 } else { 0 },
                },
            })
            .collect(),
    };
    let settlement = MultiAssetSettlement {
        participant_lock_hashes: locks
            .each_ref()
            .map(|lock| lock.calc_script_hash().unpack()),
        carrier_refund_lock_hash: locks[0].calc_script_hash().unpack(),
        payouts: manifest
            .vaults
            .iter()
            .map(|vault| MultiAssetPayout {
                asset: vault.asset.clone(),
                values: if one_sided {
                    [vault.value, MultiAssetValue::default()]
                } else {
                    [
                        MultiAssetValue {
                            reserve: 20_000_000_000,
                            business_ckb: 6_000_000_000,
                            amount: if vault.value.amount != 0 { 700 } else { 0 },
                        },
                        MultiAssetValue {
                            reserve: 20_000_000_000,
                            business_ckb: 4_000_000_000,
                            amount: if vault.value.amount != 0 { 300 } else { 0 },
                        },
                    ]
                },
            })
            .collect(),
    };
    let content = manifest.commitment().unwrap();
    let mut package = MultiAssetRecoveryPackage {
        state: MultiAssetState {
            header: morph_core::StateHeader {
                protocol_version: 1,
                chain_id: [1; 32],
                signature_scheme_id: 1,
                channel_id: [2; 32],
                funding_epoch: 0,
                funding_anchor: anchor,
                vault_set_commitment: content,
                state_number: 0,
                mode: Mode::BilateralPlain,
                phase: Phase::Active,
                participants_commitment: [0; 32],
                asset_registry_commitment: asset_registry_commitment(&manifest.registry().unwrap()),
                settlement_descriptor_commitment: settlement.commitment().unwrap(),
                descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
                vault_materialisation_root: [0; 32],
                challenge_policy_commitment: [3; 32],
                state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
                vault_outpoint_commitment: [0; 32],
            },
            vault_content_set_root: content,
            vault_outpoint_set_root: [0; 32],
            vault_count: count as u16,
        },
        authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        manifest,
        settlement,
        outpoints: vec![],
        state_carrier_capacity: carrier_capacity,
        scripts: MultiAssetRecoveryScripts {
            vault_lock: vault_lock.as_slice().to_vec(),
            participant_locks: locks.each_ref().map(|script| script.as_slice().to_vec()),
            carrier_refund_lock: locks[0].as_slice().to_vec(),
            state_type: state_type.as_slice().to_vec(),
            state_lock: state_lock.as_slice().to_vec(),
            type_scripts: types
                .iter()
                .map(|script| MultiAssetTypeScript {
                    type_hash: script.calc_script_hash().unpack(),
                    script: script.as_slice().to_vec(),
                })
                .collect(),
        },
    };
    signed(&mut package);
    package.validate().unwrap();
    let mut funding = TransactionBuilder::default()
        .input(funding_input)
        .output(
            CellOutput::new_builder()
                .capacity(carrier_capacity)
                .lock(state_lock.clone())
                .type_(Some(state_type.clone()).pack())
                .build(),
        )
        .output_data(Bytes::from(package.state.encode().unwrap().to_vec()).pack());
    for script in &vault_types {
        if let Some(script) = script {
            let input = context.create_cell(
                CellOutput::new_builder()
                    .capacity(50_000_000_000u64)
                    .lock(wallet.clone())
                    .type_(Some(script.clone()).pack())
                    .build(),
                xudt_amount_data(1000),
            );
            funding = funding.input(CellInput::new_builder().previous_output(input).build());
        }
        funding = funding
            .output(
                CellOutput::new_builder()
                    .capacity(50_000_000_000u64)
                    .lock(vault_lock.clone())
                    .type_(script.clone().pack())
                    .build(),
            )
            .output_data(
                if script.is_some() {
                    xudt_amount_data(1000)
                } else {
                    Bytes::new()
                }
                .pack(),
            );
    }
    let funding = context.complete_tx(funding.witness(evidence(&package, true)).build());
    let cycles = context
        .verify_tx(&funding, MAX_CYCLES)
        .expect("multi-asset funding");
    eprintln!(
        "multi-asset funding vaults={count} cycles={cycles} bytes={}",
        funding.data().as_slice().len()
    );
    materialise(&mut context, &funding);
    package.outpoints = (0..count)
        .map(|i| MultiAssetOutPoint {
            tx_hash: funding.hash().unpack(),
            index: i as u32 + 1,
        })
        .collect();
    package.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
    let mut activation = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&funding, 0))
                .build(),
        )
        .output(funding.outputs().get(0).unwrap())
        .output_data(Bytes::from(package.state.encode().unwrap().to_vec()).pack())
        .witness(evidence(&package, false));
    for i in 0..count {
        activation = activation.cell_dep(
            CellDep::new_builder()
                .out_point(point(&funding, i + 1))
                .build(),
        );
    }
    let activation = context.complete_tx(activation.build());
    let cycles = context
        .verify_tx(&activation, MAX_CYCLES)
        .expect("multi-asset activation");
    eprintln!("multi-asset activation vaults={count} cycles={cycles}");
    materialise(&mut context, &activation);
    package.state.header.phase = Phase::Settling;
    package.state.header.state_number = 1;
    signed(&mut package);
    package.validate().unwrap();
    let publication = context.complete_tx(
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
    let cycles = context
        .verify_tx(&publication, MAX_CYCLES)
        .expect("multi-asset publication");
    eprintln!("multi-asset publication vaults={count} cycles={cycles}");
    materialise(&mut context, &publication);
    package.state.header.state_number = 2;
    if !one_sided {
        for payout in &mut package.settlement.payouts {
            if matches!(payout.asset, VaultAsset::Xudt(_)) {
                payout.values[0].amount = 400;
                payout.values[1].amount = 600;
            }
        }
        package.state.header.settlement_descriptor_commitment =
            package.settlement.commitment().unwrap();
    }
    signed(&mut package);
    let supersede = context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(point(&publication, 0))
                    .build(),
            )
            .output(publication.outputs().get(0).unwrap())
            .output_data(Bytes::from(package.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&package, true))
            .build(),
    );
    context
        .verify_tx(&supersede, MAX_CYCLES)
        .expect("multi-asset supersede");
    materialise(&mut context, &supersede);
    Fixture {
        context,
        package,
        state_type,
        state_lock,
        vault_lock,
        locks,
        types,
        vault_types,
        funding,
        activation,
        publication,
        supersede,
        since,
    }
}

fn finalise(fixture: &mut Fixture) -> TransactionView {
    let mut tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&fixture.supersede, 0))
                .since(fixture.since)
                .build(),
        )
        .witness(evidence(&fixture.package, false));
    for i in 0..fixture.vault_types.len() {
        tx = tx.input(
            CellInput::new_builder()
                .previous_output(point(&fixture.funding, i + 1))
                .build(),
        );
    }
    for (asset_index, payout) in fixture.package.settlement.payouts.iter().enumerate() {
        for participant in 0..2 {
            let value = payout.values[participant];
            if value.capacity().unwrap() == 0 {
                continue;
            }
            let typed = if value.amount != 0 {
                fixture.vault_types[asset_index].clone()
            } else {
                None
            };
            tx = tx
                .output(
                    CellOutput::new_builder()
                        .capacity(value.capacity().unwrap())
                        .lock(fixture.locks[participant].clone())
                        .type_(typed.pack())
                        .build(),
                )
                .output_data(
                    if value.amount == 0 {
                        Bytes::new()
                    } else {
                        xudt_amount_data(value.amount)
                    }
                    .pack(),
                );
        }
    }
    tx = tx
        .output(
            CellOutput::new_builder()
                .capacity(fixture.package.state_carrier_capacity)
                .lock(fixture.locks[0].clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    fixture.context.complete_tx(tx.build())
}

fn rejects(context: &Context, tx: &TransactionView, codes: &[i8]) {
    let error = context
        .verify_tx(tx, MAX_CYCLES)
        .expect_err("unsafe multi-asset transaction");
    let message = error.to_string();
    assert!(
        codes
            .iter()
            .any(|code| message.contains(&format!("error code {code} "))),
        "unexpected rejection: {error:?}"
    );
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_two_xudt_full_lifecycle() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let cycles = fixture
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("multi-asset full-set finalisation");
    eprintln!(
        "multi-asset finalise vaults=2 cycles={cycles} bytes={}",
        tx.data().as_slice().len()
    );
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_plain_ckb_and_two_xudt_full_lifecycle() {
    let mut fixture = build_with_plain(2, false, true);
    assert_eq!(fixture.package.manifest.vaults.len(), 3);
    assert_eq!(
        fixture
            .package
            .manifest
            .registry()
            .unwrap()
            .xudt_types
            .len(),
        2
    );
    let tx = finalise(&mut fixture);
    fixture
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("plain CKB Vault plus two xUDT Vaults");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_one_sided_full_set_finalise() {
    let mut fixture = build(2, true);
    let tx = finalise(&mut fixture);
    fixture
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("one-sided multi-asset finalisation");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_maximum_candidate_set_full_lifecycle() {
    let mut fixture = build(wire::MULTI_ASSET_MAX_VAULTS, false);
    let tx = finalise(&mut fixture);
    let cycles = fixture
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("maximum multi-asset set");
    eprintln!(
        "multi-asset finalise vaults={} cycles={cycles} bytes={}",
        wire::MULTI_ASSET_MAX_VAULTS,
        tx.data().as_slice().len()
    );
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_partial_set_retirement() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let inputs = tx.inputs().into_iter().take(2).collect();
    let tx = tx.as_advanced_builder().set_inputs(inputs).build();
    rejects(&fixture.context, &tx, &[66]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_byte_identical_vault_substitution() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let clone = fixture.context.create_cell(
        fixture.funding.outputs().get(1).unwrap(),
        fixture.funding.outputs_data().get(1).unwrap().raw_data(),
    );
    let mut inputs: Vec<_> = tx.inputs().into_iter().collect();
    inputs[1] = CellInput::new_builder().previous_output(clone).build();
    let tx = tx.as_advanced_builder().set_inputs(inputs).build();
    rejects(&fixture.context, &tx, &[50]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_missing_carrier_refund() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let count = tx.outputs().len() - 1;
    let tx = tx
        .as_advanced_builder()
        .set_outputs(tx.outputs().into_iter().take(count).collect())
        .set_outputs_data(tx.outputs_data().into_iter().take(count).collect())
        .build();
    rejects(&fixture.context, &tx, &[65, 6]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_extra_vault_input() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let extra = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(50_000_000_000u64)
            .lock(fixture.vault_lock.clone())
            .type_(Some(fixture.types[0].clone()).pack())
            .build(),
        xudt_amount_data(1000),
    );
    let tx = tx
        .as_advanced_builder()
        .input(CellInput::new_builder().previous_output(extra).build())
        .build();
    rejects(&fixture.context, &tx, &[66]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_fake_state_authority() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let fake_type = deploy_always_success(&mut fixture.context);
    let fake_output = state_output(&fixture)
        .as_builder()
        .type_(Some(fake_type).pack())
        .build();
    let fake_state = fixture.context.create_cell(
        fake_output,
        Bytes::from(fixture.package.state.encode().unwrap().to_vec()),
    );
    let mut inputs: Vec<_> = tx.inputs().into_iter().collect();
    inputs[0] = CellInput::new_builder()
        .previous_output(fake_state)
        .since(fixture.since)
        .build();
    let tx = tx.as_advanced_builder().set_inputs(inputs).build();
    rejects(&fixture.context, &tx, &[14]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_premature_finalise() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let mut inputs: Vec<_> = tx.inputs().into_iter().collect();
    inputs[0] = inputs[0]
        .clone()
        .as_builder()
        .since(relative_since(5))
        .build();
    let tx = tx.as_advanced_builder().set_inputs(inputs).build();
    rejects(&fixture.context, &tx, &[16]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_payout_reallocation_not_in_signed_descriptor() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let mut data: Vec<_> = tx.outputs_data().into_iter().collect();
    data[0] = xudt_amount_data(399).pack();
    data[1] = xudt_amount_data(601).pack();
    let tx = tx.as_advanced_builder().set_outputs_data(data).build();
    rejects(&fixture.context, &tx, &[64]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_activation_with_reordered_direct_dependencies() {
    let fixture = build(2, false);
    let mut deps: Vec<_> = fixture.activation.cell_deps().into_iter().collect();
    deps.swap(0, 1);
    let tx = fixture
        .activation
        .as_advanced_builder()
        .set_cell_deps(deps)
        .build();
    rejects(&fixture.context, &tx, &[50]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_activation_carrier_fee_leakage() {
    let fixture = build(2, false);
    let output = state_output(&fixture)
        .as_builder()
        .capacity(fixture.package.state_carrier_capacity - 1)
        .build();
    let tx = fixture
        .activation
        .as_advanced_builder()
        .set_outputs(vec![output])
        .build();
    rejects(&fixture.context, &tx, &[52]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_rejects_signed_publication_in_changed_chain_context() {
    let mut fixture = build(2, false);
    fixture.package.state.header.state_number = 1;
    fixture.package.state.header.chain_id[0] ^= 1;
    signed(&mut fixture.package);
    let tx = fixture
        .publication
        .as_advanced_builder()
        .set_outputs_data(vec![
            Bytes::from(fixture.package.state.encode().unwrap().to_vec()).pack(),
        ])
        .set_witnesses(vec![evidence(&fixture.package, true).pack()])
        .build();
    rejects(&fixture.context, &tx, &[12]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_publication_uses_sponsor_without_spending_carrier_or_vaults() {
    let mut fixture = build(2, false);
    fixture.package.state.header.state_number = 1;
    signed(&mut fixture.package);
    let change = deploy_always_success_with_args(&mut fixture.context, Bytes::from(vec![88]));
    let mut policy = sponsor_policy(
        &change.calc_script_hash().unpack(),
        &fixture.state_type.calc_script_hash().unpack(),
        20_000,
    );
    policy[..32].copy_from_slice(&fixture.package.state.header.channel_id);
    let sponsor = deploy_contract(&mut fixture.context, "morph-sponsor-lock", policy);
    let sponsor_point = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor)
            .build(),
        Bytes::new(),
    );
    let tx = fixture.context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(point(&fixture.activation, 0))
                    .build(),
            )
            .input(
                CellInput::new_builder()
                    .previous_output(sponsor_point)
                    .build(),
            )
            .output(state_output(&fixture))
            .output_data(Bytes::from(fixture.package.state.encode().unwrap().to_vec()).pack())
            .output(
                CellOutput::new_builder()
                    .capacity(CELL_CAPACITY - 10_000)
                    .lock(change)
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .witness(evidence(&fixture.package, true))
            .build(),
    );
    fixture
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("sponsored multi-asset publication");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_plain_fee_change_can_share_the_carrier_refund_address() {
    let mut fixture = build(2, false);
    let tx = finalise(&mut fixture);
    let fee_cell = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(fixture.locks[0].clone())
            .build(),
        Bytes::new(),
    );
    let tx = tx
        .as_advanced_builder()
        .input(CellInput::new_builder().previous_output(fee_cell).build())
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 10_000)
                .lock(fixture.locks[0].clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = fixture.context.complete_tx(tx);
    fixture
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("canonical carrier refund plus independent fee change");
}
