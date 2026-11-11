//! Real VM transitions: simultaneous CKB / two UDT batches, complete terminal
//! custody, independent resolution, and fail-closed asset/context boundaries.
use super::*;
use morph_core::MultiAssetSettlementCapability;

struct TypedFixture {
    base: Fixture,
    batches: Vec<ConditionalBatch>,
    terminal: TransactionView,
    initial_amounts: Vec<[u128; 2]>,
}

fn typed_fixture() -> TypedFixture {
    typed_fixture_shape(2, true, 2, false)
}

fn typed_fixture_shape(
    typed_count: usize,
    plain: bool,
    transfer_count: usize,
    maximum_scripts: bool,
) -> TypedFixture {
    assert!(matches!(transfer_count, 2 | 8));
    let mut base = build_profile(typed_count, false, plain, maximum_scripts);
    let executor = deploy_contract(&mut base.context, "morph-batch-lock", vec![]);
    let initial_amounts = base
        .package
        .settlement
        .payouts
        .iter()
        .map(|p| p.values.map(|v| v.amount))
        .collect();
    let batches = arm_all_assets(&mut base.package.settlement, transfer_count);
    base.package.settlement.capability = MultiAssetSettlementCapability::Conditional {
        batch_code_hash: executor.code_hash().unpack(),
        batch_hash_type: executor.hash_type().as_slice()[0],
        batches: batches.clone(),
    };
    base.package.state.header.state_number += 1;
    base.package.state.header.settlement_descriptor_commitment =
        base.package.settlement.commitment().unwrap();
    signed(&mut base.package);
    base.package.validate().unwrap();
    let publication = base.context.complete_tx(
        TransactionBuilder::default()
            .input(CellInput::new(point(&base.supersede, 0), 0))
            .output(base.supersede.outputs().get(0).unwrap())
            .output_data(Bytes::from(base.package.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&base.package, true))
            .build(),
    );
    base.context
        .verify_tx(&publication, MAX_CYCLES)
        .expect("typed conditional publication");
    materialise(&mut base.context, &publication);
    base.supersede = publication;
    let terminal = terminal(&mut base);
    TypedFixture {
        base,
        batches,
        terminal,
        initial_amounts,
    }
}

pub(super) fn arm_all_assets(
    settlement: &mut morph_core::MultiAssetSettlement,
    transfer_count: usize,
) -> Vec<ConditionalBatch> {
    assert!(matches!(transfer_count, 2 | 8));
    let locks = settlement.participant_lock_hashes;
    let mut batches = Vec::new();
    for (asset_index, payout) in settlement.payouts.iter_mut().enumerate() {
        let amounts: [u128; 2] = if payout.asset == VaultAsset::Ckb {
            [1_000_000_000, 2_000_000_000]
        } else if transfer_count == 8 {
            [20, 32]
        } else {
            [20, 30]
        };
        for (payer, amount) in amounts.iter().enumerate() {
            if payout.asset == VaultAsset::Ckb {
                payout.values[payer].business_ckb -= u64::try_from(*amount).unwrap();
            } else {
                payout.values[payer].amount -= amount;
            }
        }
        batches.push(ConditionalBatch {
            asset: payout.asset.clone(),
            batch_id: [31 + asset_index as u8; 32],
            application_context_commitment: [41; 32],
            participants: core::array::from_fn(|i| ConditionalParticipant {
                settlement_lock_hash: locks[i],
                settled_capacity: payout.values[i].capacity().unwrap(),
                settled_amount: payout.values[i].amount,
            }),
            transfers: (0..transfer_count)
                .map(|i| ConditionalTransferSpec {
                    transfer_id: [51 + i as u8; 32],
                    payer_lock_hash: locks[i % 2],
                    hash_algorithm: if i % 2 == 0 {
                        ConditionalHashAlgorithm::Sha256
                    } else {
                        ConditionalHashAlgorithm::CkbBlake2b
                    },
                    payment_hash: derive_conditional_payment_hash(
                        if i % 2 == 0 {
                            ConditionalHashAlgorithm::Sha256
                        } else {
                            ConditionalHashAlgorithm::CkbBlake2b
                        },
                        &[71 + i as u8; 32],
                    )
                    .unwrap(),
                    amount: amounts[i % 2] / (transfer_count / 2) as u128,
                    refund_after_block: 500 + i as u64 * 100,
                })
                .collect(),
        });
    }
    batches
}

fn terminal(base: &mut Fixture) -> TransactionView {
    let raw = encode_multi_asset_witness(
        &base.package.manifest,
        &base.package.settlement,
        &base.package.outpoints,
        &base.package.scripts,
    )
    .unwrap();
    let header_raw = base.package.state.encode().unwrap();
    let outputs = morph_core::multi_asset_settlement_outputs(
        &wire::MultiAssetWitness::parse(&raw).unwrap(),
        &wire::MultiAssetStateHeader::parse(&header_raw).unwrap(),
        base.package.state_carrier_capacity,
    )
    .unwrap();
    let mut tx = TransactionBuilder::default()
        .input(CellInput::new(point(&base.supersede, 0), base.since))
        .witness(evidence(&base.package, false));
    for point in &base.package.outpoints {
        tx = tx.input(CellInput::new(
            OutPoint::new(point.tx_hash.pack(), point.index),
            0,
        ));
    }
    for (output, data) in outputs {
        tx = tx.output(output).output_data(data.pack());
    }
    let terminal = base.context.complete_tx(tx.build());
    base.context
        .verify_tx(&terminal, MAX_CYCLES)
        .expect("complete mixed-asset Batch finalisation");
    materialise(&mut base.context, &terminal);
    terminal
}

fn resolution(
    f: &mut TypedFixture,
    batch_index: usize,
    fulfill: impl AsRef<[bool]>,
    since: u64,
) -> TransactionView {
    let batch = &f.batches[batch_index];
    let fulfill = fulfill.as_ref();
    let decisions = batch
        .transfers
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (
                t.transfer_id,
                if fulfill[i] {
                    ConditionalResolution::Fulfill {
                        preimage: [71 + i as u8; 32],
                    }
                } else {
                    ConditionalResolution::Refund
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let values = batch.resolve(&decisions, since).unwrap();
    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                batch
                    .encode_resolution_witness(&decisions)
                    .unwrap()
                    .to_vec(),
            ))
            .pack(),
        )
        .build();
    let mut tx = TransactionBuilder::default()
        .input(CellInput::new(point(&f.terminal, batch_index), since))
        .witness(witness.as_bytes());
    for (i, value) in values.iter().enumerate() {
        let ty = if value.amount > 0 {
            f.base.vault_types[batch_index].clone()
        } else {
            None
        };
        let data = if ty.is_some() {
            xudt_amount_data(value.amount)
        } else {
            Bytes::new()
        };
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(value.capacity)
                    .lock(f.base.locks[i].clone())
                    .type_(ty.pack())
                    .build(),
            )
            .output_data(data.pack());
    }
    f.base.context.complete_tx(tx.build())
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_conditions_fund_activate_and_exit_from_the_original_initial_recovery() {
    let mut base = build_initial_profile(2, false, true, false, true);
    // Recover the exact already-issued state-1 vote from the publication.
    // A later state-2 fixture vote has identical terms and is not required here.
    base.package.state.header.state_number = 1;
    signed(&mut base.package);
    let original =
        WitnessArgs::from_slice(&base.publication.witnesses().get(0).unwrap().raw_data())
            .unwrap()
            .input_type()
            .to_opt()
            .unwrap()
            .raw_data();
    assert_eq!(
        encode_multi_asset_signatures(&base.package.authorization)
            .unwrap()
            .as_slice(),
        original.as_ref()
    );
    base.supersede = base.publication.clone();
    let MultiAssetSettlementCapability::Conditional { batches, .. } =
        &base.package.settlement.capability
    else {
        panic!("conditional root")
    };
    let batches = batches.clone();
    let terminal = terminal(&mut base);
    let mut f = TypedFixture {
        base,
        batches,
        terminal,
        initial_amounts: vec![],
    };
    assert_eq!(f.batches.len(), 3);
    for index in 0..3 {
        let tx = resolution(&mut f, index, [true, true], 0);
        f.base.context.verify_tx(&tx, MAX_CYCLES).unwrap();
        if index > 0 {
            assert_eq!(
                tx.outputs_data().get(0).unwrap().raw_data().as_ref(),
                710u128.to_le_bytes()
            );
            assert_eq!(
                tx.outputs_data().get(1).unwrap().raw_data().as_ref(),
                290u128.to_le_bytes()
            );
        }
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_conditions_splice_creation_recovery_activation_and_terminal_claims() {
    let mut splice = splice_transaction_with_conditions(
        2,
        true,
        false,
        true,
        SpliceChange::ReplaceOne,
        false,
        true,
    );
    splice
        .base
        .context
        .verify_tx(&splice.transaction, MAX_CYCLES)
        .unwrap();
    materialise(&mut splice.base.context, &splice.transaction);
    let recovery = splice.plan.initial_recovery(&splice.base.package).unwrap();
    recovery.validate().unwrap();
    let MultiAssetSettlementCapability::Conditional { batches, .. } =
        &recovery.settlement.capability
    else {
        panic!("conditional successor")
    };
    let batches = batches.clone();
    let mut bound = recovery.clone();
    bound.state.header.phase = Phase::Active;
    bound.state.header.state_number = 0;
    let mut activation = TransactionBuilder::default()
        .input(CellInput::new(point(&splice.transaction, 0), 0))
        .output(splice.transaction.outputs().get(0).unwrap())
        .output_data(Bytes::from(bound.state.encode().unwrap().to_vec()).pack())
        .witness(evidence(&bound, false));
    for index in 0..recovery.manifest.vaults.len() {
        activation = activation.cell_dep(
            CellDep::new_builder()
                .out_point(point(&splice.transaction, index + 1))
                .build(),
        );
    }
    let activation = splice.base.context.complete_tx(activation.build());
    splice
        .base
        .context
        .verify_tx(&activation, MAX_CYCLES)
        .unwrap();
    materialise(&mut splice.base.context, &activation);
    let publication = splice.base.context.complete_tx(
        TransactionBuilder::default()
            .input(CellInput::new(point(&activation, 0), 0))
            .output(activation.outputs().get(0).unwrap())
            .output_data(Bytes::from(recovery.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&recovery, true))
            .build(),
    );
    splice
        .base
        .context
        .verify_tx(&publication, MAX_CYCLES)
        .unwrap();
    materialise(&mut splice.base.context, &publication);
    let mut base = splice.base;
    base.vault_types = recovery
        .manifest
        .vaults
        .iter()
        .map(|vault| match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(
                Script::from_slice(
                    &recovery
                        .scripts
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
    base.state_type = Script::from_slice(&recovery.scripts.state_type).unwrap();
    base.state_lock = Script::from_slice(&recovery.scripts.state_lock).unwrap();
    base.vault_lock = Script::from_slice(&recovery.scripts.vault_lock).unwrap();
    base.package = recovery;
    base.supersede = publication;
    let terminal = terminal(&mut base);
    let mut f = TypedFixture {
        base,
        batches,
        terminal,
        initial_amounts: vec![],
    };
    assert_eq!(f.batches.len(), 3);
    for index in 0..3 {
        let tx = resolution(
            &mut f,
            index,
            [true, false],
            absolute_block_since(600).unwrap(),
        );
        f.base.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_conditions_maximum_eight_assets_sixty_four_conditions_and_script_bounds() {
    for (typed_count, plain) in [(7, true), (8, false)] {
        let mut f = typed_fixture_shape(typed_count, plain, 8, true);
        assert_eq!(f.batches.len(), 8);
        assert_eq!(f.terminal.outputs().len(), 9);
        let finalise_cycles = f.base.context.verify_tx(&f.terminal, MAX_CYCLES).unwrap();
        eprintln!(
            "typed-max finalise cycles={finalise_cycles} bytes={}",
            f.terminal.data().as_slice().len()
        );
        for index in 0..8 {
            let fulfill = resolution(&mut f, index, [true; 8], 0);
            let refund = resolution(
                &mut f,
                index,
                [false; 8],
                absolute_block_since(1200).unwrap(),
            );
            let fulfill_cycles = f.base.context.verify_tx(&fulfill, MAX_CYCLES).unwrap();
            let refund_cycles = f.base.context.verify_tx(&refund, MAX_CYCLES).unwrap();
            eprintln!(
                "typed-max asset={index} fulfill_cycles={fulfill_cycles} refund_cycles={refund_cycles} bytes={}",
                fulfill.data().as_slice().len()
            );
        }
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_conditional_complete_custody_and_independent_mixed_resolutions() {
    let mut f = typed_fixture();
    assert_eq!(f.terminal.outputs().len(), 4); // Three asset Batches plus full carrier.
    let mixed = resolution(&mut f, 0, [true, false], absolute_block_since(600).unwrap());
    let fulfill = resolution(&mut f, 1, [true, true], 0);
    let refund = resolution(
        &mut f,
        2,
        [false, false],
        absolute_block_since(600).unwrap(),
    );
    for tx in [&mixed, &fulfill, &refund] {
        f.base.context.verify_tx(tx, MAX_CYCLES).unwrap();
    }
    assert_eq!(
        fulfill.outputs_data().get(0).unwrap().raw_data().as_ref(),
        (f.initial_amounts[1][0] + 10).to_le_bytes()
    );
    assert_eq!(
        fulfill.outputs_data().get(1).unwrap().raw_data().as_ref(),
        (f.initial_amounts[1][1] - 10).to_le_bytes()
    );
    assert_eq!(
        refund.outputs_data().get(0).unwrap().raw_data().as_ref(),
        f.initial_amounts[2][0].to_le_bytes()
    );
    assert_eq!(
        refund.outputs_data().get(1).unwrap().raw_data().as_ref(),
        f.initial_amounts[2][1].to_le_bytes()
    );
    for tx in [&fulfill, &refund] {
        for i in 0..2 {
            assert_eq!(
                u64::from(tx.outputs().get(i).unwrap().capacity()),
                f.batches[1].participants[i].settled_capacity
            );
        }
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_conditional_cooperative_close_preserves_every_independent_batch() {
    let mut f = typed_fixture();
    let mut inputs: Vec<_> = f.terminal.inputs().into_iter().collect();
    inputs[0] = inputs[0].clone().as_builder().since(0u64).build();
    let close = super::close::journal_close(
        &f.base.package,
        f.terminal
            .clone()
            .as_advanced_builder()
            .set_inputs(inputs)
            .build(),
    );
    f.base.context.verify_tx(&close, MAX_CYCLES).unwrap();
    materialise(&mut f.base.context, &close);
    f.terminal = close;
    for i in 0..3 {
        let tx = resolution(&mut f, i, [true, true], 0);
        f.base.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_conditional_rejects_asset_substitution_and_token_diversion() {
    let mut f = typed_fixture();
    let tx = resolution(&mut f, 1, [true, true], 0);
    for mutation in 0..4 {
        let mut outputs: Vec<_> = tx.outputs().into_iter().collect();
        let mut data: Vec<_> = tx.outputs_data().into_iter().collect();
        match mutation {
            0 => {
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .type_(Some(f.base.types[1].clone()).pack())
                    .build()
            }
            1 => {
                data[0] = xudt_amount_data(711).pack();
                data[1] = xudt_amount_data(289).pack();
            }
            2 => {
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .lock(f.base.locks[1].clone())
                    .build()
            }
            _ => {
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .capacity(u64::from(outputs[0].capacity()) - 1)
                    .build();
            }
        }
        let changed = f.base.context.complete_tx(
            tx.clone()
                .as_advanced_builder()
                .set_outputs(outputs)
                .set_outputs_data(data)
                .build(),
        );
        assert!(
            f.base.context.verify_tx(&changed, MAX_CYCLES).is_err(),
            "mutation {mutation}"
        );
    }
    // Omitting the final conditional Type cannot orphan its custody.
    let mut inputs: Vec<_> = f.terminal.inputs().into_iter().collect();
    inputs.pop();
    let incomplete = f.base.context.complete_tx(
        f.terminal
            .clone()
            .as_advanced_builder()
            .set_inputs(inputs)
            .build(),
    );
    assert!(f.base.context.verify_tx(&incomplete, MAX_CYCLES).is_err());
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_batch_rejects_early_refund_wrong_preimage_and_cross_batch_witness() {
    let mut f = typed_fixture();
    let mature = resolution(
        &mut f,
        1,
        [false, false],
        absolute_block_since(600).unwrap(),
    );
    let early_input = mature
        .inputs()
        .get(0)
        .unwrap()
        .as_builder()
        .since(absolute_block_since(599).unwrap())
        .build();
    let early = mature
        .clone()
        .as_advanced_builder()
        .set_inputs(vec![early_input])
        .build();
    assert!(f.base.context.verify_tx(&early, MAX_CYCLES).is_err());
    let fulfilled = resolution(&mut f, 1, [true, true], 0);
    let mut witness =
        WitnessArgs::from_slice(&fulfilled.witnesses().get(0).unwrap().raw_data()).unwrap();
    let mut raw = witness.input_type().to_opt().unwrap().raw_data().to_vec();
    raw[4 + CONDITIONAL_BATCH_DESCRIPTOR_LEN + 1] ^= 1;
    witness = witness
        .as_builder()
        .input_type(Some(Bytes::from(raw)).pack())
        .build();
    let wrong = fulfilled
        .clone()
        .as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build();
    assert!(f.base.context.verify_tx(&wrong, MAX_CYCLES).is_err());
    let other = resolution(&mut f, 2, [true, true], 0);
    let replay = other
        .as_advanced_builder()
        .set_witnesses(fulfilled.witnesses().into_iter().collect())
        .build();
    assert!(f.base.context.verify_tx(&replay, MAX_CYCLES).is_err());
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_batch_vm_resolves_above_u64_without_capacity_or_type_substitution() {
    let mut f = typed_fixture();
    let mut batch = f.batches[1].clone();
    let large = u64::MAX as u128 + 123;
    batch.participants[0].settled_amount = large;
    batch.transfers[0].amount = large;
    let raw = batch.encode_descriptor().unwrap();
    let mut args = f
        .terminal
        .outputs()
        .get(1)
        .unwrap()
        .lock()
        .args()
        .raw_data()
        .to_vec();
    args[72..].copy_from_slice(
        &morph_script_common::ConditionalBatchDescriptor::parse(&raw)
            .unwrap()
            .commitment(),
    );
    let lock = f
        .terminal
        .outputs()
        .get(1)
        .unwrap()
        .lock()
        .as_builder()
        .args(Bytes::from(args).pack())
        .build();
    let input = f.base.context.create_cell(
        CellOutput::new_builder()
            .capacity(batch.total_capacity().unwrap())
            .lock(lock)
            .type_(f.base.vault_types[1].clone().pack())
            .build(),
        xudt_amount_data(batch.total_amount().unwrap()),
    );
    let decisions = batch
        .transfers
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (
                t.transfer_id,
                ConditionalResolution::Fulfill {
                    preimage: [71 + i as u8; 32],
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let witness = WitnessArgs::new_builder()
        .input_type(
            Some(Bytes::from(
                batch
                    .encode_resolution_witness(&decisions)
                    .unwrap()
                    .to_vec(),
            ))
            .pack(),
        )
        .build();
    let values = batch.resolve(&decisions, 0).unwrap();
    let mut tx = TransactionBuilder::default()
        .input(CellInput::new(input, 0))
        .witness(witness.as_bytes());
    for (index, value) in values.iter().enumerate() {
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(value.capacity)
                    .lock(f.base.locks[index].clone())
                    .type_(f.base.vault_types[1].clone().pack())
                    .build(),
            )
            .output_data(xudt_amount_data(value.amount).pack());
    }
    let tx = f.base.context.complete_tx(tx.build());
    f.base.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    assert_eq!(values[0].amount, large + 30);
    assert_eq!(values[0].capacity, batch.participants[0].settled_capacity);
    assert!(values[1].amount > u64::MAX as u128);
}

#[test]
#[ignore = "requires built current ELFs"]
fn typed_condition_requires_future_token_payout_capacity_even_at_zero_settled_balance() {
    let mut f = typed_fixture();
    let payout = &mut f.base.package.settlement.payouts[1];
    let capacity = payout.values[0].reserve + payout.values[1].reserve;
    let business = payout.values[0].business_ckb + payout.values[1].business_ckb;
    payout.values[0].reserve = 6_000_000_000; // Fits plain output, not its future UDT output.
    payout.values[0].business_ckb = 0;
    payout.values[1].reserve = capacity - payout.values[0].reserve;
    payout.values[1].business_ckb = business;
    payout.values[0].amount = 0;
    let mut batch = f.batches[1].clone();
    batch.transfers[0].amount = f.initial_amounts[1][0];
    for index in 0..2 {
        batch.participants[index].settled_capacity = payout.values[index].capacity().unwrap();
        batch.participants[index].settled_amount = payout.values[index].amount;
    }
    if let MultiAssetSettlementCapability::Conditional { batches, .. } =
        &mut f.base.package.settlement.capability
    {
        batches[1] = batch;
    }
    f.base.package.state.header.state_number += 1;
    f.base.package.state.header.settlement_descriptor_commitment =
        f.base.package.settlement.commitment().unwrap();
    signed(&mut f.base.package);
    assert!(f.base.package.validate().is_err());
    let tx = f.base.context.complete_tx(
        TransactionBuilder::default()
            .input(CellInput::new(point(&f.base.supersede, 0), 0))
            .output(state_output(&f.base))
            .output_data(Bytes::from(f.base.package.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&f.base.package, true))
            .build(),
    );
    assert!(f.base.context.verify_tx(&tx, MAX_CYCLES).is_err());
}
