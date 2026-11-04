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
