use super::*;
use morph_script_common::multi_asset_close as close_wire;

pub(super) fn journal_close(
    package: &MultiAssetRecoveryPackage,
    tx: TransactionView,
) -> TransactionView {
    use morph_core::{MultiAssetChannelBackend, MultiAssetCloseProposal};
    let first = tx.inputs().get(0).unwrap().previous_output();
    let proposal = MultiAssetCloseProposal {
        source_outpoint: MultiAssetOutPoint {
            tx_hash: first.tx_hash().unpack(),
            index: first.index().unpack(),
        },
        source_state: package.state.clone(),
        transaction: tx.data().raw().as_slice().to_vec(),
    };
    let digest = proposal.signing_digest(package).unwrap();
    let hash = proposal.transaction_hash().unwrap();
    let mut backend =
        MultiAssetChannelBackend::new(package.clone(), pubkey(&signing_key(1)).to_vec()).unwrap();
    backend.prepare_close(proposal).unwrap();
    backend.reserve_close_signature(&hash).unwrap();
    let mut backend: MultiAssetChannelBackend =
        serde_json::from_slice(&serde_json::to_vec(&backend).unwrap()).unwrap();
    for key in [signing_key(1), signing_key(2)] {
        backend
            .record_close_signature(
                &hash,
                ParticipantSignature {
                    pubkey_sec1: pubkey(&key).to_vec(),
                    signature: signature(&key, &digest).to_vec(),
                },
            )
            .unwrap();
    }
    let witness = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(backend.close_witness(&hash).unwrap())).pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build()
}

#[test]
#[ignore = "requires built current ELFs"]
fn cooperative_close_host_snapshot_exports_vm_valid_complete_retirement() {
    for count in [1, 8] {
        let mut fixture = build(count, false);
        let source = point(&fixture.supersede, 0);
        let tx = terminal_from(&mut fixture, source);
        let tx = journal_close(&fixture.package, tx);
        fixture.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    }
}

pub(super) fn authorize_close(
    package: &MultiAssetRecoveryPackage,
    tx: TransactionView,
) -> TransactionView {
    let header_raw = package.state.encode().unwrap();
    let header = wire::MultiAssetStateHeader::parse(&header_raw).unwrap();
    let digest = close_wire::multi_asset_close_digest(&header, &tx.hash().unpack()).unwrap();
    let mut signed_package = package.clone();
    let mut keys = [signing_key(1), signing_key(2)];
    keys.sort_by_key(pubkey);
    signed_package.authorization.signatures = keys
        .iter()
        .map(|key| ParticipantSignature {
            pubkey_sec1: pubkey(key).to_vec(),
            signature: signature(key, &digest).to_vec(),
        })
        .collect();
    let signatures = encode_multi_asset_signatures(&signed_package.authorization).unwrap();
    with_close_signatures(package, tx, &signatures)
}

fn with_close_signatures(
    package: &MultiAssetRecoveryPackage,
    tx: TransactionView,
    signatures: &[u8],
) -> TransactionView {
    let inner = encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )
    .unwrap();
    let mut raw = vec![0; close_wire::MULTI_ASSET_CLOSE_FIXED_LEN + inner.len()];
    close_wire::encode_multi_asset_close(
        &mut raw,
        &tx.hash().unpack(),
        &package.state.encode().unwrap(),
        signatures,
        &inner,
    )
    .unwrap();
    let witness = WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(raw)).pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![witness.as_bytes().pack()])
        .build()
}

pub(super) fn terminal_from(fixture: &mut Fixture, source: OutPoint) -> TransactionView {
    let terminal = finalise(fixture);
    let mut inputs: Vec<_> = terminal.inputs().into_iter().collect();
    inputs[0] = CellInput::new(source, 0);
    let tx = terminal.as_advanced_builder().set_inputs(inputs).build();
    authorize_close(&fixture.package, tx)
}

#[test]
#[ignore = "requires built current ELFs"]
fn cooperative_close_current_complete_custody_without_delay() {
    for (count, plain) in [(0, true), (1, false), (4, false), (8, false)] {
        let mut fixture = build_with_plain(count, false, plain);
        for source in [
            point(&fixture.activation, 0),
            point(&fixture.publication, 0),
            point(&fixture.supersede, 0),
        ] {
            let tx = terminal_from(&mut fixture, source);
            let cycles = fixture
                .context
                .verify_tx(&tx, MAX_CYCLES)
                .expect("fresh exact-body terminal close");
            eprintln!(
                "cooperative-close count={} plain={} bytes={} cycles={}",
                count,
                plain,
                tx.data().as_slice().len(),
                cycles
            );
        }
    }
    let mut maximum = build_profile(8, false, false, true);
    let source = point(&maximum.activation, 0);
    let tx = terminal_from(&mut maximum, source);
    let cycles = maximum
        .context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("maximum-script complete close");
    assert!(cycles < 7_200_000);
    assert!(tx.data().as_slice().len() <= 16_400);
    eprintln!(
        "cooperative-close maximum-scripts bytes={} cycles={cycles}",
        tx.data().as_slice().len()
    );
}

#[test]
#[ignore = "requires built current ELFs"]
fn cooperative_close_rejects_roles_body_and_frame_malleation() {
    let mut fixture = build(2, false);
    let source = point(&fixture.activation, 0);
    let tx = terminal_from(&mut fixture, source);
    fixture.context.verify_tx(&tx, MAX_CYCLES).unwrap();
    let old_votes = encode_multi_asset_signatures(&fixture.package.authorization).unwrap();
    rejects(
        &fixture.context,
        &with_close_signatures(&fixture.package, tx.clone(), &old_votes),
        &[24],
    );
    let mut outputs: Vec<_> = tx.outputs().into_iter().collect();
    let capacity: u64 = outputs[0].capacity().unpack();
    outputs[0] = outputs[0]
        .clone()
        .as_builder()
        .capacity(capacity - 1)
        .build();
    rejects(
        &fixture.context,
        &tx.clone()
            .as_advanced_builder()
            .set_outputs(outputs)
            .build(),
        &[71],
    );
    let mut deps: Vec<_> = tx.cell_deps().into_iter().collect();
    deps.reverse();
    rejects(
        &fixture.context,
        &tx.clone().as_advanced_builder().set_cell_deps(deps).build(),
        &[71],
    );
    let witness = WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
    let original = witness.output_type().to_opt().unwrap().raw_data().to_vec();
    for mutation in 0..7 {
        let mut raw = original.clone();
        match mutation {
            0 => raw[8] = 2,
            1 => raw[10] = 1,
            2 => raw.push(0),
            3 => {
                raw.pop();
            }
            4 => raw[12..16].copy_from_slice(&u32::MAX.to_le_bytes()),
            5 => raw[48 + wire::MULTI_ASSET_STATE_HEADER_LEN + 3] = 1,
            _ => raw[48 + wire::MULTI_ASSET_STATE_HEADER_LEN + 37] ^= 1,
        }
        let bad = WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(raw)).pack())
            .build();
        let bad_tx = tx
            .clone()
            .as_advanced_builder()
            .set_witnesses(vec![bad.as_bytes().pack()])
            .build();
        rejects(&fixture.context, &bad_tx, &[70, 22, 24]);
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn close_delegation_cannot_use_a_vault_group_witness_as_authority() {
    let mut f = build(1, false);
    let source = point(&f.activation, 0);
    let tx = terminal_from(&mut f, source);
    let valid = tx.witnesses().get(0).unwrap();
    let args = WitnessArgs::from_slice(&valid.raw_data()).unwrap();
    let mut frame = args.output_type().to_opt().unwrap().raw_data().to_vec();
    let parsed = close_wire::MultiAssetCloseWitness::parse(&frame).unwrap();
    let signature_offset = 48 + wire::MULTI_ASSET_STATE_HEADER_LEN + 4 + 33;
    assert!(parsed.evidence().manifest().count() == 1);
    frame[signature_offset..signature_offset + 64]
        .copy_from_slice(&signature(&signing_key(1), &[201; 32]));
    let invalid = args
        .as_builder()
        .output_type(Some(Bytes::from(frame)).pack())
        .build()
        .as_bytes()
        .pack();
    f.context
        .verify_tx(
            &tx.clone()
                .as_advanced_builder()
                .set_witnesses(vec![valid.clone(), invalid.clone()])
                .build(),
            MAX_CYCLES,
        )
        .unwrap();
    let bad = tx
        .as_advanced_builder()
        .set_witnesses(vec![invalid, valid])
        .build();
    let err = f.context.verify_tx(&bad, MAX_CYCLES).unwrap_err();
    let detail = err
        .root_cause()
        .downcast_ref::<ckb_testtool::ckb_script::TransactionScriptError>()
        .unwrap();
    assert_eq!(detail.originating_script().to_string(), "Inputs[0].Type");
    assert!(matches!(
        detail.script_error(),
        ckb_testtool::ckb_script::ScriptError::ValidationFailure(_, 24)
    ));
}

#[test]
#[ignore = "requires built current ELFs"]
fn cooperative_close_fresh_signatures_cannot_waive_custody_or_payouts() {
    // Morph must reject even when the asset Type supplies no conservation check.
    let mut fixture = build_initial_profile_with_types(2, false, false, false, false, true);
    let source = point(&fixture.activation, 0);
    let tx = terminal_from(&mut fixture, source);
    for mutation in 0..7 {
        let mut inputs: Vec<_> = tx.inputs().into_iter().collect();
        let mut outputs: Vec<_> = tx.outputs().into_iter().collect();
        let mut data: Vec<_> = tx.outputs_data().into_iter().collect();
        match mutation {
            0 => {
                inputs.pop();
            }
            1 | 2 => {
                let (cell, bytes) = fixture
                    .context
                    .get_cell(&inputs[1].previous_output())
                    .unwrap();
                let clone = fixture.context.create_cell(cell, bytes);
                if mutation == 1 {
                    inputs[1] = CellInput::new(clone, 0);
                } else {
                    inputs.push(CellInput::new(clone, 0));
                }
            }
            3 => {
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .lock(fixture.locks[1].clone())
                    .build();
            }
            4 => {
                let last = outputs.len() - 1;
                outputs[last] = outputs[last]
                    .clone()
                    .as_builder()
                    .capacity(fixture.package.state_carrier_capacity - 1)
                    .build();
            }
            5 => {
                data[0] = xudt_amount_data(999).pack();
            }
            _ => {
                inputs.swap(1, 2);
            }
        }
        let bad = tx
            .clone()
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(data)
            .build();
        let bad = authorize_close(&fixture.package, bad);
        rejects(&fixture.context, &bad, &[71, 50, 66, 65, 63, 64]);
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn cooperative_close_source_progress_and_external_fee_boundaries() {
    let mut fixture = build(1, false);
    let source = point(&fixture.supersede, 0);
    let tx = terminal_from(&mut fixture, source);
    let unbound = point(&fixture.funding, 0);
    let unbound_tx = terminal_from(&mut fixture, unbound);
    rejects(&fixture.context, &unbound_tx, &[71]);
    let duplicate = authorize_close(
        &fixture.package,
        tx.clone()
            .as_advanced_builder()
            .input(CellInput::new(point(&fixture.publication, 0), 0))
            .build(),
    );
    rejects(&fixture.context, &duplicate, &[8, 15, 71]);
    for mutation in 0..3 {
        let mut source_state = fixture.package.state.clone();
        match mutation {
            0 => source_state.header.state_number += 1,
            1 => source_state.header.funding_epoch += 1,
            _ => source_state.header.settlement_descriptor_commitment = [91; 32],
        }
        let replacement = fixture.context.create_cell(
            state_output(&fixture),
            Bytes::from(source_state.encode().unwrap().to_vec()),
        );
        let bad = terminal_from(&mut fixture, replacement);
        rejects(&fixture.context, &bad, &[71]);
    }
    let fee_cell = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(fixture.locks[0].clone())
            .build(),
        Bytes::new(),
    );
    let funded = tx
        .clone()
        .as_advanced_builder()
        .input(CellInput::new(fee_cell, 0))
        .output(
            CellOutput::new_builder()
                .capacity(9_999_990_000u64)
                .lock(fixture.locks[0].clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let funded = fixture.context.complete_tx(funded);
    rejects(&fixture.context, &funded, &[71]);
    let funded = authorize_close(&fixture.package, funded);
    fixture.context.verify_tx(&funded, MAX_CYCLES).unwrap();
    let dirty_fee = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(fixture.locks[0].clone())
            .build(),
        Bytes::from_static(b"not plain"),
    );
    let mut inputs: Vec<_> = funded.inputs().into_iter().collect();
    *inputs.last_mut().unwrap() = CellInput::new(dirty_fee, 0);
    let bad = authorize_close(
        &fixture.package,
        funded.as_advanced_builder().set_inputs(inputs).build(),
    );
    rejects(&fixture.context, &bad, &[71]);
}
