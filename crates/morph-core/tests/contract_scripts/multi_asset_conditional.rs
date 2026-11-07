use super::*;
use morph_core::MultiAssetSettlementCapability;
use morph_script_common::multi_asset_conditional::MultiAssetConditional;

struct ConditionalFixture {
    base: Fixture,
    batch: ConditionalBatch,
    batch_lock: Script,
    finalisation: TransactionView,
}

fn conditional_fixture() -> ConditionalFixture {
    // A plain CKB lane and an unrelated token lane settle atomically. Funding,
    // activation and ordinary updates run through the exact same fixture first.
    let mut base = build_with_plain(1, false, true);
    let identity = deploy_contract(&mut base.context, "morph-batch-lock", vec![]);
    base.package.settlement.payouts[0].values[0].business_ckb -= 2_000_000_000;
    let values = base.package.settlement.payouts[0].values;
    let batch = ConditionalBatch {
        batch_id: [31; 32],
        application_context_commitment: [32; 32],
        participants: core::array::from_fn(|index| ConditionalParticipant {
            settlement_lock_hash: base.package.settlement.participant_lock_hashes[index],
            settled_capacity: values[index].capacity().unwrap(),
        }),
        transfers: vec![ConditionalTransferSpec {
            transfer_id: [33; 32],
            payer_lock_hash: base.package.settlement.participant_lock_hashes[0],
            hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
            payment_hash: derive_conditional_payment_hash(
                ConditionalHashAlgorithm::CkbBlake2b,
                &[34; 32],
            )
            .unwrap(),
            amount: 2_000_000_000,
            refund_after_block: 500,
        }],
    };
    base.package.settlement.capability = MultiAssetSettlementCapability::CkbConditional {
        batch_code_hash: identity.code_hash().unpack(),
        batch_hash_type: identity.hash_type().as_slice()[0],
        batch: Box::new(batch.clone()),
    };
    base.package.state.header.state_number += 1;
    base.package.state.header.settlement_descriptor_commitment =
        base.package.settlement.commitment().unwrap();
    signed(&mut base.package);
    base.package.validate().unwrap();
    // Ordinary -> conditional changes only signed progress, never funding
    // provenance, participants, or the active signer authority.
    let publication = base.context.complete_tx(
        TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(point(&base.supersede, 0))
                    .build(),
            )
            .output(base.supersede.outputs().get(0).unwrap())
            .output_data(Bytes::from(base.package.state.encode().unwrap().to_vec()).pack())
            .witness(evidence(&base.package, true))
            .build(),
    );
    base.context
        .verify_tx(&publication, MAX_CYCLES)
        .expect("conditional publication");
    materialise(&mut base.context, &publication);
    base.supersede = publication;
    let encoded = base.package.settlement.encode().unwrap();
    let descriptor = wire::MultiAssetSettlementDescriptor::parse(&encoded).unwrap();
    let conditional: MultiAssetConditional = descriptor.conditional().unwrap().unwrap();
    let batch_lock = Script::from_slice(
        &conditional
            .batch_script(
                &base.package.state.header.channel_id,
                &base.package.state.funding_context_id().unwrap(),
                base.package.state.header.state_number,
            )
            .unwrap(),
    )
    .unwrap();
    let ordinary = finalise(&mut base);
    let mut outputs = vec![
        CellOutput::new_builder()
            .capacity(base.package.manifest.vaults[0].value.capacity().unwrap())
            .lock(batch_lock.clone())
            .build(),
    ];
    outputs.extend(ordinary.outputs().into_iter().skip(2));
    let mut data = vec![Bytes::new().pack()];
    data.extend(ordinary.outputs_data().into_iter().skip(2));
    let finalisation = base.context.complete_tx(
        ordinary
            .as_advanced_builder()
            .set_outputs(outputs)
            .set_outputs_data(data)
            .build(),
    );
    ConditionalFixture {
        base,
        batch,
        batch_lock,
        finalisation,
    }
}

fn resolve(
    fixture: &mut ConditionalFixture,
    resolution: ConditionalResolution,
    since: u64,
) -> TransactionView {
    materialise(&mut fixture.base.context, &fixture.finalisation);
    let capacities = match resolution {
        ConditionalResolution::Fulfill { .. } => [
            fixture.batch.participants[0].settled_capacity,
            fixture.batch.participants[1].settled_capacity + fixture.batch.transfers[0].amount,
        ],
        ConditionalResolution::Refund => [
            fixture.batch.participants[0].settled_capacity + fixture.batch.transfers[0].amount,
            fixture.batch.participants[1].settled_capacity,
        ],
    };
    let resolutions = BTreeMap::from([(fixture.batch.transfers[0].transfer_id, resolution)]);
    let raw = fixture
        .batch
        .encode_resolution_witness(&resolutions)
        .unwrap();
    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(raw.to_vec())).pack())
        .build();
    let mut tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(point(&fixture.finalisation, 0))
                .since(since)
                .build(),
        )
        .witness(witness.as_bytes());
    for (index, capacity) in capacities.into_iter().enumerate() {
        tx = tx
            .output(
                CellOutput::new_builder()
                    .capacity(capacity)
                    .lock(fixture.base.locks[index].clone())
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }
    fixture.base.context.complete_tx(tx.build())
}

fn add_distinct_batch_input(
    fixture: &mut ConditionalFixture,
    transaction: &TransactionView,
) -> (TransactionView, u64) {
    let first_input = transaction.inputs().get(0).unwrap();
    let (batch_cell, data) = fixture
        .base
        .context
        .get_cell(&first_input.previous_output())
        .unwrap();
    let batch_capacity = u64::from(batch_cell.capacity());
    let mut args = fixture.batch_lock.args().raw_data().to_vec();
    args[0] ^= 1;
    let distinct_batch_lock = fixture
        .batch_lock
        .clone()
        .as_builder()
        .args(Bytes::from(args).pack())
        .build();
    assert_ne!(distinct_batch_lock, fixture.batch_lock);
    let second_batch = fixture.base.context.create_cell(
        batch_cell.as_builder().lock(distinct_batch_lock).build(),
        data,
    );
    let witness = transaction.witnesses().get(0).unwrap();
    let transaction = fixture.base.context.complete_tx(
        transaction
            .clone()
            .as_advanced_builder()
            .input(CellInput::new(second_batch, 0))
            .witness(witness)
            .build(),
    );
    (transaction, batch_capacity)
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_lane_finalises_and_fulfills_with_independent_token_and_carrier() {
    let mut fixture = conditional_fixture();
    let cycles = fixture
        .base
        .context
        .verify_tx(&fixture.finalisation, MAX_CYCLES)
        .expect("conditional finalisation");
    eprintln!("current conditional finalise cycles={cycles}");
    assert_eq!(fixture.finalisation.outputs().len(), 4); // Batch, two tokens, carrier.
    assert_eq!(
        fixture.finalisation.outputs().get(0).unwrap().lock(),
        fixture.batch_lock
    );
    let resolution = resolve(
        &mut fixture,
        ConditionalResolution::Fulfill { preimage: [34; 32] },
        0,
    );
    fixture
        .base
        .context
        .verify_tx(&resolution, MAX_CYCLES)
        .expect("fulfill Batch");
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_lane_refunds_only_after_absolute_deadline() {
    let mut fixture = conditional_fixture();
    fixture
        .base
        .context
        .verify_tx(&fixture.finalisation, MAX_CYCLES)
        .unwrap();
    let early = resolve(
        &mut fixture,
        ConditionalResolution::Refund,
        absolute_block_since(499).unwrap(),
    );
    rejects(&fixture.base.context, &early, &[59]);
    let mature = resolve(
        &mut fixture,
        ConditionalResolution::Refund,
        absolute_block_since(500).unwrap(),
    );
    fixture
        .base
        .context
        .verify_tx(&mature, MAX_CYCLES)
        .expect("refund Batch");
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_lane_rejects_wrong_preimage_and_batch_destination() {
    let mut fixture = conditional_fixture();
    let resolution = resolve(
        &mut fixture,
        ConditionalResolution::Fulfill { preimage: [35; 32] },
        0,
    );
    rejects(&fixture.base.context, &resolution, &[58]);
    let mut outputs = fixture
        .finalisation
        .outputs()
        .into_iter()
        .collect::<Vec<_>>();
    outputs[0] = outputs[0]
        .clone()
        .as_builder()
        .lock(fixture.base.locks[0].clone())
        .build();
    let diverted = fixture
        .finalisation
        .as_advanced_builder()
        .set_outputs(outputs)
        .build();
    rejects(&fixture.base.context, &diverted, &[65]);
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_finalisation_binds_batch_to_exact_state_and_funding_context() {
    let fixture = conditional_fixture();
    fixture
        .base
        .context
        .verify_tx(&fixture.finalisation, MAX_CYCLES)
        .expect("the Batch lock for the actual settling State must verify");

    let header = &fixture.base.package.state.header;
    let context = fixture.base.package.state.funding_context_id().unwrap();
    assert!(header.state_number > 1);
    let mut other_channel = header.channel_id;
    other_channel[0] ^= 1;
    let mut other_context = context;
    other_context[0] ^= 1;
    let encoded = fixture.base.package.settlement.encode().unwrap();
    let descriptor = wire::MultiAssetSettlementDescriptor::parse(&encoded).unwrap();
    let conditional = descriptor.conditional().unwrap().unwrap();

    // These are individually well-formed Batch namespaces with the same terms.
    // The creation/finalisation boundary must match the actual State. Reusing a
    // preimage for another legitimately created Batch is a different question.
    for (name, channel, funding, state_number) in [
        (
            "previous State",
            header.channel_id,
            context,
            header.state_number - 1,
        ),
        (
            "future State",
            header.channel_id,
            context,
            header.state_number + 1,
        ),
        (
            "another channel",
            other_channel,
            context,
            header.state_number,
        ),
        (
            "another funding context",
            header.channel_id,
            other_context,
            header.state_number,
        ),
    ] {
        let wrong_lock = Script::from_slice(
            &conditional
                .batch_script(&channel, &funding, state_number)
                .unwrap(),
        )
        .unwrap();
        assert_ne!(wrong_lock, fixture.batch_lock, "{name}");
        let mut outputs = fixture
            .finalisation
            .outputs()
            .into_iter()
            .collect::<Vec<_>>();
        outputs[0] = outputs[0].clone().as_builder().lock(wrong_lock).build();
        let transaction = fixture
            .finalisation
            .clone()
            .as_advanced_builder()
            .set_outputs(outputs)
            .build();
        let error = fixture
            .base
            .context
            .verify_tx(&transaction, MAX_CYCLES)
            .expect_err("a Batch namespace from another State/context must fail finalisation");
        assert!(
            error.to_string().contains("error code 65 "),
            "{name}: {error:?}"
        );
    }
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_batch_spend_requires_exact_plain_unique_payouts() {
    let mut fixture = conditional_fixture();
    fixture
        .base
        .context
        .verify_tx(&fixture.finalisation, MAX_CYCLES)
        .expect("valid conditional finalisation");
    let valid = resolve(
        &mut fixture,
        ConditionalResolution::Fulfill { preimage: [34; 32] },
        0,
    );
    fixture
        .base
        .context
        .verify_tx(&valid, MAX_CYCLES)
        .expect("unchanged plain, unique Batch payouts");

    let outputs = valid.outputs().into_iter().collect::<Vec<_>>();
    let data = valid.outputs_data().into_iter().collect::<Vec<_>>();
    let mut cases = Vec::new();

    let mut changed_outputs = outputs.clone();
    changed_outputs[0] = changed_outputs[0]
        .clone()
        .as_builder()
        .capacity(u64::from(changed_outputs[0].capacity()) - 1)
        .build();
    cases.push((
        "one-shannon payout mismatch",
        valid
            .clone()
            .as_advanced_builder()
            .set_outputs(changed_outputs)
            .build(),
    ));

    let harmless_type =
        deploy_always_success_with_args(&mut fixture.base.context, Bytes::from(vec![41]));
    let mut changed_outputs = outputs.clone();
    changed_outputs[0] = changed_outputs[0]
        .clone()
        .as_builder()
        .type_(Some(harmless_type).pack())
        .build();
    cases.push((
        "typed payout with an otherwise valid Type script",
        fixture.base.context.complete_tx(
            valid
                .clone()
                .as_advanced_builder()
                .set_outputs(changed_outputs)
                .build(),
        ),
    ));

    let mut changed_data = data.clone();
    changed_data[0] = Bytes::from(vec![1]).pack();
    cases.push((
        "payout carrying unexpected data",
        valid
            .clone()
            .as_advanced_builder()
            .set_outputs_data(changed_data)
            .build(),
    ));

    let unrelated_lock =
        deploy_always_success_with_args(&mut fixture.base.context, Bytes::from(vec![42]));
    let mut changed_outputs = outputs.clone();
    changed_outputs[0] = changed_outputs[0]
        .clone()
        .as_builder()
        .lock(unrelated_lock.clone())
        .build();
    cases.push((
        "wrong payout lock",
        valid
            .clone()
            .as_advanced_builder()
            .set_outputs(changed_outputs)
            .build(),
    ));

    cases.push((
        "missing participant payout",
        valid
            .clone()
            .as_advanced_builder()
            .set_outputs(outputs[1..].to_vec())
            .set_outputs_data(data[1..].to_vec())
            .build(),
    ));

    // Fund the extra output independently. Its positive control proves that
    // unrelated wallet value is allowed; only duplicating a participant lock
    // changes in the negative case, without a capacity imbalance.
    let extra_capacity = u64::from(outputs[0].capacity());
    let extra_input = fixture.base.context.create_cell(
        CellOutput::new_builder()
            .capacity(extra_capacity)
            .lock(unrelated_lock.clone())
            .build(),
        Bytes::new(),
    );
    let funded_control = fixture.base.context.complete_tx(
        valid
            .clone()
            .as_advanced_builder()
            .input(CellInput::new(extra_input, 0))
            .output(
                CellOutput::new_builder()
                    .capacity(extra_capacity)
                    .lock(unrelated_lock)
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .build(),
    );
    fixture
        .base
        .context
        .verify_tx(&funded_control, MAX_CYCLES)
        .expect("independent wallet input/output must not disturb valid Batch payouts");
    let mut duplicated_outputs = funded_control.outputs().into_iter().collect::<Vec<_>>();
    let last = duplicated_outputs.len() - 1;
    duplicated_outputs[last] = duplicated_outputs[last]
        .clone()
        .as_builder()
        .lock(outputs[0].lock())
        .build();
    cases.push((
        "duplicate participant payout with independent funding",
        funded_control
            .as_advanced_builder()
            .set_outputs(duplicated_outputs)
            .build(),
    ));

    for (name, transaction) in cases {
        let error = fixture
            .base
            .context
            .verify_tx(&transaction, MAX_CYCLES)
            .expect_err("malformed Batch payout must fail its output guard");
        assert!(
            error.to_string().contains("error code 56 "),
            "{name}: {error:?}"
        );
    }
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_batch_rejects_cross_group_payout_reuse() {
    let mut fixture = conditional_fixture();
    let resolution = resolve(
        &mut fixture,
        ConditionalResolution::Fulfill { preimage: [34; 32] },
        0,
    );
    let (shared_payouts, batch_capacity) = add_distinct_batch_input(&mut fixture, &resolution);

    let error = fixture
        .base
        .context
        .verify_tx(&shared_payouts, MAX_CYCLES)
        .expect_err("a second Batch group must not reuse the first Batch's payouts as fee");
    assert!(error.to_string().contains("error code 8 "), "{error:?}");

    let thief_lock =
        deploy_always_success_with_args(&mut fixture.base.context, Bytes::from(vec![43]));
    let stolen_surplus = shared_payouts
        .as_advanced_builder()
        .output(
            CellOutput::new_builder()
                .capacity(batch_capacity)
                .lock(thief_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let error = fixture
        .base
        .context
        .verify_tx(&stolen_surplus, MAX_CYCLES)
        .expect_err("a second Batch group must not redirect surplus beyond shared payouts");
    assert!(error.to_string().contains("error code 8 "), "{error:?}");
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_batch_requires_leading_input_and_allows_trailing_fee_input() {
    let mut fixture = conditional_fixture();
    let resolution = resolve(
        &mut fixture,
        ConditionalResolution::Fulfill { preimage: [34; 32] },
        0,
    );
    let fee_lock =
        deploy_always_success_with_args(&mut fixture.base.context, Bytes::from(vec![44]));
    let fee_cell = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(fee_lock)
        .build();
    let fee_input = fixture
        .base
        .context
        .create_cell(fee_cell.clone(), Bytes::new());
    let with_fee = fixture.base.context.complete_tx(
        resolution
            .as_advanced_builder()
            .input(CellInput::new(fee_input, 0))
            .witness(Bytes::new().pack())
            .output(
                fee_cell
                    .as_builder()
                    .capacity(CELL_CAPACITY - 10_000)
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .build(),
    );
    fixture
        .base
        .context
        .verify_tx(&with_fee, MAX_CYCLES)
        .expect("a trailing independent fee input and change must remain valid");

    let mut inputs = with_fee.inputs().into_iter().collect::<Vec<_>>();
    inputs.reverse();
    let mut witnesses = with_fee.witnesses().into_iter().collect::<Vec<_>>();
    witnesses.reverse();
    let nonleading_batch = with_fee
        .as_advanced_builder()
        .set_inputs(inputs)
        .set_witnesses(witnesses)
        .build();
    let error = fixture
        .base
        .context
        .verify_tx(&nonleading_batch, MAX_CYCLES)
        .expect_err("the Batch must occupy transaction input zero");
    assert!(error.to_string().contains("error code 8 "), "{error:?}");
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_conditional_lane_cannot_pay_pending_from_carrier_or_omit_token() {
    let fixture = conditional_fixture();
    let mut outputs = fixture
        .finalisation
        .outputs()
        .into_iter()
        .collect::<Vec<_>>();
    let batch = u64::from(outputs[0].capacity());
    let last = outputs.len() - 1;
    let carrier = u64::from(outputs[last].capacity());
    outputs[0] = outputs[0].clone().as_builder().capacity(batch - 1).build();
    outputs[last] = outputs[last]
        .clone()
        .as_builder()
        .capacity(carrier + 1)
        .build();
    let shifted = fixture
        .finalisation
        .clone()
        .as_advanced_builder()
        .set_outputs(outputs)
        .build();
    rejects(&fixture.base.context, &shifted, &[65]);
    // Exact source sets are still required with the conditional capability.
    let mut inputs = fixture
        .finalisation
        .inputs()
        .into_iter()
        .collect::<Vec<_>>();
    inputs.pop();
    let omitted = fixture
        .finalisation
        .as_advanced_builder()
        .set_inputs(inputs)
        .build();
    rejects(&fixture.base.context, &omitted, &[66]);
}
