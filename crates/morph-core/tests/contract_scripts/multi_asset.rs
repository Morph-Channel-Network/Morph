use super::*;
use ckb_testtool::ckb_types::packed::{OutPoint, Script};
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
    build_profile(typed_count, one_sided, plain, false)
}

fn build_profile(
    typed_count: usize,
    one_sided: bool,
    plain: bool,
    maximum_scripts: bool,
) -> Fixture {
    let reserve = if maximum_scripts {
        240_000_000_000u64
    } else {
        40_000_000_000
    };
    let capacity = reserve + 10_000_000_000;
    let lock_args = if maximum_scripts { 459 } else { 1 };
    let mut context = Context::default();
    let wallet = deploy_always_success_with_args(&mut context, Bytes::from(vec![99]));
    let mut locks = [
        deploy_always_success_with_args(&mut context, Bytes::from(vec![1; lock_args])),
        deploy_always_success_with_args(&mut context, Bytes::from(vec![2; lock_args])),
    ];
    locks.sort_by_key(|lock| lock.calc_script_hash());
    let carrier_capacity = CELL_CAPACITY;
    let funding_wallet = context.create_cell(
        CellOutput::new_builder()
            .capacity(carrier_capacity + if plain { capacity } else { 0 } + 10_000)
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
                    reserve,
                    business_ckb: 10_000_000_000,
                    amount: if script.is_some() { 1000 } else { 0 },
                },
            })
            .collect(),
    };
    let settlement = MultiAssetSettlement {
        capability: morph_core::MultiAssetSettlementCapability::Ordinary,
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
                            reserve: reserve / 2,
                            business_ckb: 6_000_000_000,
                            amount: if vault.value.amount != 0 { 700 } else { 0 },
                        },
                        MultiAssetValue {
                            reserve: reserve / 2,
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
            header: morph_core::MultiAssetHeader {
                protocol_version: 1,
                chain_id: [1; 32],
                signature_scheme_id: 1,
                channel_id: [2; 32],
                funding_epoch: 0,
                funding_anchor: anchor,

                state_number: 0,
                mode: Mode::BilateralPlain,
                phase: Phase::Active,
                participants_commitment: [0; 32],
                asset_registry_commitment: asset_registry_commitment(&manifest.registry().unwrap()),
                settlement_descriptor_commitment: settlement.commitment().unwrap(),
                descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,

                challenge_policy_commitment: [3; 32],
                state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
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
    package.validate_contents().unwrap();
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
                    .capacity(capacity)
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
                    .capacity(capacity)
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
    let digest = package
        .state
        .root_funding_signing_digest(&funding.hash().unpack())
        .unwrap();
    let mut keys = [signing_key(1), signing_key(2)];
    keys.sort_by_key(pubkey);
    package.authorization.signatures = keys
        .iter()
        .map(|key| ParticipantSignature {
            pubkey_sec1: pubkey(key).to_vec(),
            signature: signature(key, &digest).to_vec(),
        })
        .collect();
    let funding = funding
        .as_advanced_builder()
        .set_witnesses(vec![evidence(&package, true).pack()])
        .build();
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
                .previous_output(
                    OutPoint::new_builder()
                        .tx_hash(fixture.package.outpoints[i].tx_hash.pack())
                        .index(fixture.package.outpoints[i].index)
                        .build(),
                )
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
fn multi_asset_initial_exit_cannot_publish_settling_state_zero() {
    let mut fixture = build(2, false);
    fixture.package.state.header.phase = Phase::Settling;
    fixture.package.state.header.state_number = 0;
    signed(&mut fixture.package);
    let transaction = fixture.context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(point(&fixture.activation, 0))
                    .build(),
            )
            .output(fixture.activation.outputs().get(0).unwrap())
            .output_data(Bytes::from(fixture.package.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&fixture.package, true))
            .build(),
    );
    rejects(&fixture.context, &transaction, &[10]);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn multi_asset_root_creation_rejects_transaction_replacement() {
    let fixture = build(2, false);
    // Repricing the carrier by one shannon preserves the anchor and signed
    // State bytes, but changes every future Vault OutPoint.
    let mut outputs = fixture.funding.outputs().into_iter().collect::<Vec<_>>();
    outputs[0] = outputs[0]
        .clone()
        .as_builder()
        .capacity(u64::from(outputs[0].capacity()) - 1)
        .build();
    let replaced = fixture
        .funding
        .clone()
        .as_advanced_builder()
        .set_outputs(outputs)
        .build();
    assert_ne!(replaced.hash(), fixture.funding.hash());
    rejects(&fixture.context, &replaced, &[24]);
    // Ordinary state votes cannot stand in for transaction-bound creation.
    let raw = fixture.funding.outputs_data().get(0).unwrap().raw_data();
    let witness_raw = fixture.funding.witnesses().get(0).unwrap().raw_data();
    let args = WitnessArgs::from_slice(&witness_raw).unwrap();
    let mut creation = MultiAssetRecoveryPackage::decode_contents(
        &raw,
        &args.output_type().to_opt().unwrap().raw_data(),
        fixture.package.state_carrier_capacity,
    )
    .unwrap();
    signed(&mut creation);
    let old_vote = fixture
        .funding
        .clone()
        .as_advanced_builder()
        .set_witnesses(vec![evidence(&creation, true).pack()])
        .build();
    rejects(&fixture.context, &old_vote, &[24]);
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

struct SpliceFixture {
    base: Fixture,
    plan: morph_core::MultiAssetSpliceProposal,
    transaction: TransactionView,
    admitted_input: Option<OutPoint>,
}

#[derive(Clone, Copy, Debug)]
enum SpliceChange {
    ReplaceOne,
    ReplaceAll,
    AddOne,
    RemoveOne,
}

fn splice_transaction(
    typed_count: usize,
    plain: bool,
    weak_admission: bool,
    active: bool,
    change_kind: SpliceChange,
    maximum_scripts: bool,
) -> SpliceFixture {
    use morph_core::{
        MultiAssetSpliceFlow, MultiAssetSpliceProposal, multi_asset_splice_funding_anchor,
    };
    let mut base = build_profile(typed_count, false, plain, maximum_scripts);
    let old_point = point(
        if active {
            &base.activation
        } else {
            &base.supersede
        },
        0,
    );
    let old_state = MultiAssetOutPoint {
        tx_hash: old_point.tx_hash().unpack(),
        index: 0,
    };
    let anchor = multi_asset_splice_funding_anchor(&old_state);
    let state_type = base
        .state_type
        .clone()
        .as_builder()
        .args(state_args_with_anchor(anchor, base.since).pack())
        .build();
    let state_lock = base
        .state_lock
        .clone()
        .as_builder()
        .args(state_type.calc_script_hash().as_bytes().pack())
        .build();
    let vault_lock = base
        .vault_lock
        .clone()
        .as_builder()
        .args(
            wire::encode_multi_asset_vault_args(
                &anchor,
                base.since,
                &state_type.calc_script_hash().unpack(),
                &state_lock.calc_script_hash().unpack(),
            )
            .unwrap()
            .to_vec()
            .pack(),
        )
        .build();
    let mut next = base.package.clone();
    let template = next.manifest.vaults.last().unwrap().value;
    let removed = match change_kind {
        SpliceChange::AddOne => vec![],
        SpliceChange::ReplaceAll => std::mem::take(&mut next.manifest.vaults),
        _ => vec![next.manifest.vaults.pop().unwrap()],
    };
    next.scripts.type_scripts.retain(|entry| {
        !removed
            .iter()
            .any(|vault| vault.asset == VaultAsset::Xudt(entry.type_hash))
    });
    let admitted_count = match change_kind {
        SpliceChange::ReplaceAll => removed.len(),
        SpliceChange::RemoveOne => 0,
        _ => 1,
    };
    let mut admitted = Vec::new();
    for index in 0..admitted_count {
        let ty = if weak_admission {
            deploy_always_success_with_args(
                &mut base.context,
                Bytes::from(vec![
                    97 + index as u8;
                    if maximum_scripts { 459 } else { 32 }
                ]),
            )
        } else {
            deploy_contract(
                &mut base.context,
                "morph-devnet-xudt",
                vec![99 + index as u8; 32],
            )
        };
        let hash = ty.calc_script_hash().unpack();
        next.scripts.type_scripts.push(MultiAssetTypeScript {
            type_hash: hash,
            script: ty.as_slice().to_vec(),
        });
        admitted.push(MultiAssetVault {
            asset: VaultAsset::Xudt(hash),
            lock_hash: vault_lock.calc_script_hash().unpack(),
            value: template,
        });
    }
    let admitted_hash = admitted.first().map(|vault| match vault.asset {
        VaultAsset::Xudt(hash) => hash,
        _ => unreachable!(),
    });
    next.scripts
        .type_scripts
        .sort_by_key(|entry| entry.type_hash);
    next.scripts.state_type = state_type.as_slice().to_vec();
    next.scripts.state_lock = state_lock.as_slice().to_vec();
    next.scripts.vault_lock = vault_lock.as_slice().to_vec();
    let mut flows = Vec::new();
    for vault in &mut next.manifest.vaults {
        vault.lock_hash = vault_lock.calc_script_hash().unpack();
        let amount = if matches!(vault.asset, VaultAsset::Xudt(_)) {
            100
        } else {
            0
        };
        vault.value.amount += amount;
        flows.push(MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: MultiAssetValue {
                amount,
                ..MultiAssetValue::default()
            },
            withdrawal: MultiAssetValue::default(),
        });
    }
    for vault in &removed {
        flows.push(MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: MultiAssetValue::default(),
            withdrawal: vault.value,
        });
    }
    for vault in &admitted {
        flows.push(MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: vault.value,
            withdrawal: MultiAssetValue::default(),
        });
    }
    flows.sort_by_key(|flow| flow.asset.clone());
    next.manifest.vaults.extend(admitted);
    next.manifest
        .vaults
        .sort_by_key(|vault| vault.asset.clone());
    next.state.vault_count = next.manifest.vaults.len() as u16;
    next.settlement.payouts = next
        .manifest
        .vaults
        .iter()
        .map(|vault| MultiAssetPayout {
            asset: vault.asset.clone(),
            values: [
                MultiAssetValue {
                    reserve: vault.value.reserve / 2,
                    business_ckb: vault.value.business_ckb / 2,
                    amount: vault.value.amount / 2,
                },
                MultiAssetValue {
                    reserve: vault.value.reserve - vault.value.reserve / 2,
                    business_ckb: vault.value.business_ckb - vault.value.business_ckb / 2,
                    amount: vault.value.amount - vault.value.amount / 2,
                },
            ],
        })
        .collect();
    next.state.header.funding_epoch += 1;
    next.state.header.funding_anchor = anchor;
    next.state.header.phase = Phase::Active;
    next.state.header.state_number = 0;
    next.state.header.asset_registry_commitment =
        asset_registry_commitment(&next.manifest.registry().unwrap());
    next.state.header.settlement_descriptor_commitment = next.settlement.commitment().unwrap();
    next.state.vault_content_set_root = next.manifest.commitment().unwrap();
    next.state.vault_outpoint_set_root = [0; 32];
    next.outpoints.clear();
    signed(&mut next);
    next.validate().unwrap();
    let mut tx = TransactionBuilder::default().input(CellInput::new(old_point, 0));
    for point in &base.package.outpoints {
        tx = tx.input(CellInput::new(
            OutPoint::new(point.tx_hash.pack(), point.index),
            0,
        ));
    }
    let mut change = CELL_CAPACITY - 10_000;
    let mut admitted_input = None;
    for flow in &flows {
        if flow.deposit.amount == 0 {
            continue;
        }
        let VaultAsset::Xudt(hash) = flow.asset else {
            unreachable!()
        };
        let ty = Script::from_slice(
            &next
                .scripts
                .type_scripts
                .iter()
                .find(|entry| entry.type_hash == hash)
                .unwrap()
                .script,
        )
        .unwrap();
        let capacity = flow.deposit.capacity().unwrap().max(50_000_000_000);
        let input = base.context.create_cell(
            CellOutput::new_builder()
                .capacity(capacity)
                .lock(base.locks[0].clone())
                .type_(Some(ty).pack())
                .build(),
            xudt_amount_data(flow.deposit.amount),
        );
        if Some(hash) == admitted_hash {
            admitted_input = Some(input.clone());
        }
        tx = tx.input(CellInput::new(input, 0));
        change += capacity - flow.deposit.capacity().unwrap();
    }
    let fee = base.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(base.locks[0].clone())
            .build(),
        Bytes::new(),
    );
    tx = tx
        .input(CellInput::new(fee, 0))
        .output(
            CellOutput::new_builder()
                .capacity(next.state_carrier_capacity)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output_data(Bytes::from(next.state.encode().unwrap().to_vec()).pack());
    for vault in &next.manifest.vaults {
        let ty = match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(
                Script::from_slice(
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
            xudt_amount_data(vault.value.amount)
        } else {
            Bytes::new()
        };
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(vault.value.capacity().unwrap())
                    .lock(vault_lock.clone())
                    .type_(ty.pack())
                    .build(),
            )
            .output_data(data.pack());
    }
    for flow in &flows {
        if flow.withdrawal.capacity().unwrap() == 0 {
            continue;
        }
        let ty = if flow.withdrawal.amount == 0 {
            None
        } else {
            let VaultAsset::Xudt(hash) = flow.asset else {
                unreachable!()
            };
            Some(
                Script::from_slice(
                    &base
                        .package
                        .scripts
                        .type_scripts
                        .iter()
                        .find(|entry| entry.type_hash == hash)
                        .unwrap()
                        .script,
                )
                .unwrap(),
            )
        };
        let data = if ty.is_some() {
            xudt_amount_data(flow.withdrawal.amount)
        } else {
            Bytes::new()
        };
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(flow.withdrawal.capacity().unwrap())
                    .lock(base.locks[0].clone())
                    .type_(ty.pack())
                    .build(),
            )
            .output_data(data.pack());
    }
    tx = tx
        .output(
            CellOutput::new_builder()
                .capacity(change)
                .lock(base.locks[0].clone())
                .build(),
        )
        .output_data(Bytes::new().pack());
    let tx = base.context.complete_tx(tx.build());
    let plan = MultiAssetSpliceProposal {
        base_state_digest: base.package.state.signing_digest().unwrap(),
        old_state_outpoint: old_state,
        transaction_hash: tx.hash().unpack(),
        new_state_authorization: next.authorization.clone(),
        initial_recovery_authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        new_state: next.state,
        new_manifest: next.manifest,
        new_settlement: next.settlement,
        new_scripts: next.scripts,
        flows,
        withdrawal_lock: if removed.is_empty() {
            vec![]
        } else {
            base.locks[0].as_slice().to_vec()
        },
    };
    let mut result = SpliceFixture {
        base,
        plan,
        transaction: tx,
        admitted_input,
    };
    resign_splice(&mut result);
    result
}

fn resign_splice(fixture: &mut SpliceFixture) {
    fixture.plan.transaction_hash = fixture.transaction.hash().unpack();
    let mut recovery = MultiAssetRecoveryPackage {
        state: fixture.plan.new_state.clone(),
        authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        manifest: fixture.plan.new_manifest.clone(),
        settlement: fixture.plan.new_settlement.clone(),
        outpoints: (0..fixture.plan.new_manifest.vaults.len())
            .map(|index| MultiAssetOutPoint {
                tx_hash: fixture.plan.transaction_hash,
                index: index as u32 + 1,
            })
            .collect(),
        scripts: fixture.plan.new_scripts.clone(),
        state_carrier_capacity: fixture.base.package.state_carrier_capacity,
    };
    recovery.state.header.phase = Phase::Settling;
    recovery.state.header.state_number = 1;
    recovery.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
    signed(&mut recovery);
    fixture.plan.initial_recovery_authorization = recovery.authorization;
    let mut keys = [signing_key(1), signing_key(2)];
    keys.sort_by_key(pubkey);
    let digest = fixture.plan.signing_digest(&fixture.base.package).unwrap();
    let authorization = StateAuthorization {
        threshold: 2,
        signatures: keys
            .iter()
            .map(|key| ParticipantSignature {
                pubkey_sec1: pubkey(key).to_vec(),
                signature: signature(key, &digest).to_vec(),
            })
            .collect(),
    };
    let raw = fixture
        .plan
        .encode_witness(&fixture.base.package, &authorization)
        .unwrap();
    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                encode_multi_asset_signatures(&fixture.plan.new_state_authorization)
                    .unwrap()
                    .to_vec(),
            ))
            .pack(),
        )
        .output_type(Some(Bytes::from(raw)).pack())
        .build()
        .as_bytes();
    fixture.transaction = fixture
        .transaction
        .clone()
        .as_advanced_builder()
        .set_witnesses(vec![witness.pack()])
        .build();
    assert_eq!(
        fixture.transaction.hash().as_slice(),
        fixture.plan.transaction_hash
    );
}

#[test]
#[ignore]
fn multi_asset_splice_reanchors_full_set_with_asset_admission_withdrawal_and_recovery() {
    for (count, plain, change, maximum) in [
        (2, true, SpliceChange::ReplaceOne, false),
        (8, false, SpliceChange::ReplaceAll, false),
        (2, false, SpliceChange::AddOne, false),
        (2, false, SpliceChange::RemoveOne, false),
        (8, false, SpliceChange::ReplaceAll, true),
    ] {
        let mut fixture = splice_transaction(count, plain, maximum, count == 8, change, maximum);
        let cycles = fixture
            .base
            .context
            .verify_tx(&fixture.transaction, MAX_CYCLES)
            .expect("complete multi-asset splice");
        eprintln!(
            "multi-asset splice count={count} plain={plain} change={change:?} maximum_scripts={maximum} cycles={cycles} bytes={}",
            fixture.transaction.data().as_slice().len()
        );
        materialise(&mut fixture.base.context, &fixture.transaction);
        let recovery = fixture
            .plan
            .initial_recovery(&fixture.base.package)
            .unwrap();
        let mut active = recovery.clone();
        active.state = fixture.plan.new_state.clone();
        active.state.vault_outpoint_set_root = recovery.state.vault_outpoint_set_root;
        let mut activate = TransactionBuilder::default()
            .input(CellInput::new(point(&fixture.transaction, 0), 0))
            .output(fixture.transaction.outputs().get(0).unwrap())
            .output_data(Bytes::from(active.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&active, false));
        for point in &active.outpoints {
            activate = activate.cell_dep(
                CellDep::new_builder()
                    .out_point(OutPoint::new(point.tx_hash.pack(), point.index))
                    .build(),
            );
        }
        let activate = fixture.base.context.complete_tx(activate.build());
        fixture
            .base
            .context
            .verify_tx(&activate, MAX_CYCLES)
            .expect("splice set activation");
        materialise(&mut fixture.base.context, &activate);
        let publish = fixture.base.context.complete_tx(
            TransactionBuilder::default()
                .input(CellInput::new(point(&activate, 0), 0))
                .output(activate.outputs().get(0).unwrap())
                .output_data(Bytes::from(recovery.state.encode().unwrap().to_vec()).pack())
                .witness(evidence(&recovery, true))
                .build(),
        );
        fixture
            .base
            .context
            .verify_tx(&publish, MAX_CYCLES)
            .expect("pre-signed initial exit after splice");
        materialise(&mut fixture.base.context, &publish);
        // Reuse the ordinary complete-set finalisation builder, replacing only
        // its newly proven funding context and canonical State checkpoint.
        fixture.base.package = recovery.clone();
        fixture.base.supersede = publish;
        fixture.base.funding = fixture.transaction;
        fixture.base.vault_types = fixture
            .plan
            .new_manifest
            .vaults
            .iter()
            .map(|vault| match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => Some(
                    Script::from_slice(
                        &fixture
                            .plan
                            .new_scripts
                            .type_scripts
                            .iter()
                            .find(|entry| entry.type_hash == hash)
                            .unwrap()
                            .script,
                    )
                    .unwrap(),
                ),
            })
            .collect();
        let final_tx = finalise(&mut fixture.base);
        fixture
            .base
            .context
            .verify_tx(&final_tx, MAX_CYCLES)
            .expect("complete post-splice retirement");
        recovery.validate().unwrap();
    }
}

#[test]
#[ignore]
fn multi_asset_splice_rejects_body_changes_clone_partial_sets_withdrawal_and_carrier_substitution()
{
    for mutation in 0..9 {
        let mut fixture =
            splice_transaction(2, true, false, false, SpliceChange::ReplaceOne, false);
        let mut inputs = fixture.transaction.inputs().into_iter().collect::<Vec<_>>();
        let mut outputs = fixture
            .transaction
            .outputs()
            .into_iter()
            .collect::<Vec<_>>();
        let mut data = fixture
            .transaction
            .outputs_data()
            .into_iter()
            .collect::<Vec<_>>();
        let last = outputs.len() - 1;
        let change: u64 = outputs[last].capacity().unpack();
        let expected = match mutation {
            0 => {
                outputs[last] = outputs[last]
                    .clone()
                    .as_builder()
                    .capacity(change - 1)
                    .build();
                vec![68]
            }
            1 => {
                let old = inputs[1].previous_output();
                let (cell, bytes) = fixture.base.context.get_cell(&old).unwrap();
                let clone = fixture.base.context.create_cell(cell, bytes);
                inputs[1] = CellInput::new(clone, 0);
                vec![50]
            }
            2 => {
                inputs.remove(1);
                outputs[last] = outputs[last]
                    .clone()
                    .as_builder()
                    .capacity(change - 50_000_000_000)
                    .build();
                vec![50, 66]
            }
            3 => {
                outputs.remove(1);
                data.remove(1);
                let pos = outputs.len() - 1;
                outputs[pos] = outputs[pos]
                    .clone()
                    .as_builder()
                    .capacity(change + 50_000_000_000)
                    .build();
                vec![65, 66]
            }
            4 => {
                let index = 1 + fixture.plan.new_manifest.vaults.len();
                outputs[index] = outputs[index]
                    .clone()
                    .as_builder()
                    .lock(fixture.base.locks[1].clone())
                    .build();
                vec![65]
            }
            5 => {
                let carrier: u64 = outputs[0].capacity().unpack();
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .capacity(carrier - 1)
                    .build();
                outputs[last] = outputs[last]
                    .clone()
                    .as_builder()
                    .capacity(change + 1)
                    .build();
                vec![52]
            }
            6 => {
                let (cell, bytes) = fixture
                    .base
                    .context
                    .get_cell(&inputs[1].previous_output())
                    .unwrap();
                let extra = fixture.base.context.create_cell(cell, bytes);
                inputs.push(CellInput::new(extra, 0));
                outputs[last] = outputs[last]
                    .clone()
                    .as_builder()
                    .capacity(change + 50_000_000_000)
                    .build();
                vec![66]
            }
            7 => {
                outputs[last] = outputs[last]
                    .clone()
                    .as_builder()
                    .capacity(change - 50_000_000_000)
                    .build();
                outputs.push(outputs[1].clone());
                data.push(data[1].clone());
                vec![66, 68]
            }
            _ => {
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .type_(Some(fixture.base.locks[1].clone()).pack())
                    .build();
                vec![68]
            }
        };
        fixture.transaction = fixture
            .transaction
            .clone()
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(data)
            .build();
        if mutation != 0 {
            resign_splice(&mut fixture);
        }
        rejects(&fixture.base.context, &fixture.transaction, &expected);
    }
}

#[test]
#[ignore]
fn multi_asset_splice_independently_rejects_mint_under_a_permissive_asset_type() {
    let mut fixture = splice_transaction(2, true, true, false, SpliceChange::ReplaceOne, false);
    fixture
        .base
        .context
        .verify_tx(&fixture.transaction, MAX_CYCLES)
        .expect("valid permissive-type transfer");
    let (cell, _) = fixture
        .base
        .context
        .get_cell(fixture.admitted_input.as_ref().unwrap())
        .unwrap();
    fixture.base.context.create_cell_with_out_point(
        fixture.admitted_input.clone().unwrap(),
        cell,
        xudt_amount_data(999),
    );
    rejects(&fixture.base.context, &fixture.transaction, &[64]);
}

#[test]
#[ignore]
fn multi_asset_splice_requires_both_bridge_and_new_creation_authorizations() {
    use morph_script_common::multi_asset_splice as splice;
    for mutation in 0..3 {
        let mut fixture =
            splice_transaction(2, true, false, false, SpliceChange::ReplaceOne, false);
        let witness = fixture.transaction.witnesses().get(0).unwrap().raw_data();
        let args = WitnessArgs::from_slice(&witness).unwrap();
        let args = match mutation {
            0 => {
                let mut body = args.output_type().to_opt().unwrap().raw_data().to_vec();
                body[splice::MULTI_ASSET_SPLICE_PREFIX_LEN
                    + splice::MULTI_ASSET_SPLICE_HEADER_LEN
                    + wire::MULTI_ASSET_STATE_HEADER_LEN
                    + 37] ^= 1;
                args.as_builder()
                    .output_type(Some(Bytes::from(body)).pack())
                    .build()
            }
            1 => args.as_builder().input_type(None::<Bytes>.pack()).build(),
            _ => args
                .as_builder()
                .input_type(
                    Some(Bytes::from(
                        encode_multi_asset_signatures(&fixture.base.package.authorization)
                            .unwrap()
                            .to_vec(),
                    ))
                    .pack(),
                )
                .build(),
        };
        fixture.transaction = fixture
            .transaction
            .as_advanced_builder()
            .set_witnesses(vec![args.as_bytes().pack()])
            .build();
        rejects(
            &fixture.base.context,
            &fixture.transaction,
            if mutation == 1 { &[21] } else { &[24] },
        );
    }
}

#[test]
#[ignore]
fn multi_asset_splice_rejects_reserve_business_reclassification_even_with_valid_bridge_signatures()
{
    use morph_script_common::multi_asset_splice as splice;
    let mut fixture = splice_transaction(2, true, false, false, SpliceChange::ReplaceOne, false);
    let raw = fixture.transaction.witnesses().get(0).unwrap().raw_data();
    let args = WitnessArgs::from_slice(&raw).unwrap();
    let mut body = args.output_type().to_opt().unwrap().raw_data().to_vec();
    let flows_len = u32::from_le_bytes(body[28..32].try_into().unwrap()) as usize;
    let start = body.len() - flows_len;
    // The unchanged plain CKB Vault declares a one-shannon extra deposit;
    // physical inputs/outputs and both new-State authorizations stay valid.
    body[start + 4 + 33] = 1;
    let root = splice::MultiAssetSpliceFlows::parse(&body[start..])
        .unwrap()
        .commitment();
    let header_start = splice::MULTI_ASSET_SPLICE_PREFIX_LEN;
    body[header_start + 104..header_start + 136].copy_from_slice(&root);
    let digest = splice::MultiAssetSpliceHeader::parse(
        &body[header_start..header_start + splice::MULTI_ASSET_SPLICE_HEADER_LEN],
    )
    .unwrap()
    .signing_digest();
    let mut keys = [signing_key(1), signing_key(2)];
    keys.sort_by_key(pubkey);
    let authorization = StateAuthorization {
        threshold: 2,
        signatures: keys
            .iter()
            .map(|key| ParticipantSignature {
                pubkey_sec1: pubkey(key).to_vec(),
                signature: signature(key, &digest).to_vec(),
            })
            .collect(),
    };
    let offset =
        header_start + splice::MULTI_ASSET_SPLICE_HEADER_LEN + wire::MULTI_ASSET_STATE_HEADER_LEN;
    body[offset..offset + 198]
        .copy_from_slice(&encode_multi_asset_signatures(&authorization).unwrap());
    let witness = args
        .as_builder()
        .output_type(Some(Bytes::from(body)).pack())
        .build();
    fixture.transaction = fixture
        .transaction
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build();
    rejects(&fixture.base.context, &fixture.transaction, &[64]);
}

#[path = "factory_multi_asset.rs"]
mod factory;

#[path = "multi_asset_conditional.rs"]
mod conditional;

#[path = "current_boundaries.rs"]
mod boundaries;
