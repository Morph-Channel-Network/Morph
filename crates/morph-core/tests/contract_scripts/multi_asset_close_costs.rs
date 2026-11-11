//! Current-contract measurements for ADR 005. No proposed close verifier is simulated.
use super::*;

pub(super) fn measure(context: &Context, tx: &TransactionView, label: &str) {
    let cycles = context
        .verify_tx(tx, MAX_CYCLES)
        .expect("valid measured transaction");
    let input_capacity: u64 = tx
        .inputs()
        .into_iter()
        .map(|input| {
            let capacity: u64 = context
                .get_cell(&input.previous_output())
                .unwrap()
                .0
                .capacity()
                .unpack();
            capacity
        })
        .sum();
    let output_capacity: u64 = tx
        .outputs()
        .into_iter()
        .map(|output| {
            let capacity: u64 = output.capacity().unpack();
            capacity
        })
        .sum();
    let occupied: u64 = tx
        .outputs()
        .into_iter()
        .zip(tx.outputs_data())
        .map(|(output, data)| {
            let type_script = output.type_().to_opt();
            wire::multi_asset_occupied_capacity(
                output.lock().as_slice(),
                type_script.as_ref().map(|script| script.as_slice()),
                data.raw_data().len() as u64,
            )
            .unwrap()
        })
        .sum();
    let fee = input_capacity
        .checked_sub(output_capacity)
        .expect("no capacity creation");
    eprintln!(
        "CLOSE_COST {}",
        serde_json::json!({
            "label": label, "cycles": cycles, "serialized_bytes": tx.data().as_slice().len(),
            "inputs": tx.inputs().len(), "outputs": tx.outputs().len(),
            "cell_deps": tx.cell_deps().len(), "input_capacity_shannons": input_capacity,
            "output_occupied_shannons": occupied, "actual_fee_shannons": fee,
        })
    );
}

#[test]
#[ignore = "requires built current ELFs; emits ADR 005 measurement rows"]
fn current_close_geometry_and_fresh_votes_do_not_bypass_delay() {
    for (typed, plain) in [(0, true), (1, false), (4, false), (8, false)] {
        let mut fixture = build_with_plain(typed, false, plain);
        // Publish the latest saved package directly from the bound Active cell.
        let publication = fixture.context.complete_tx(
            TransactionBuilder::default()
                .input(CellInput::new(point(&fixture.activation, 0), 0))
                .output(state_output(&fixture))
                .output_data(Bytes::from(fixture.package.state.encode().unwrap().to_vec()).pack())
                .witness(evidence(&fixture.package, true))
                .build(),
        );
        measure(
            &fixture.context,
            &publication,
            &format!("publish-{typed}-tokens-plain-{plain}"),
        );
        materialise(&mut fixture.context, &publication);
        fixture.supersede = publication;
        let terminal = finalise(&mut fixture);
        measure(
            &fixture.context,
            &terminal,
            &format!("finalise-{typed}-tokens-plain-{plain}"),
        );
        assert_eq!(
            terminal.outputs().len(),
            2 * (typed + usize::from(plain)) + 1
        );
        // Current two-party state votes are not an immediate-close authority.
        let mut inputs: Vec<_> = terminal.inputs().into_iter().collect();
        inputs[0] = inputs[0].clone().as_builder().since(0u64).build();
        let premature = terminal
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_witnesses(vec![evidence(&fixture.package, true).pack()])
            .build();
        rejects(&fixture.context, &premature, &[16]);
    }
    for count in [1, 4, 8] {
        let fixture =
            splice_transaction(count, false, false, true, SpliceChange::ReplaceAll, false);
        measure(
            &fixture.base.context,
            &fixture.transaction,
            &format!("splice-replace-all-{count}-tokens"),
        );
        assert!(fixture.transaction.outputs().len() > count);
    }
}
