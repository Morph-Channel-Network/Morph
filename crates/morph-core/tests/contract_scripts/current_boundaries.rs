use super::*;

// These are the safety boundaries previously exercised through the retired
// single-Vault fixtures. Every transaction now uses the current custody model.
#[test]
#[ignore = "requires `make build-contracts`"]
fn current_state_supersede_preserves_carrier_context_lock_and_signature_authority() {
    let fixture = build_with_plain(0, false, true);
    for mutation in 0..11 {
        let mut package = fixture.package.clone();
        let mut output = state_output(&fixture);
        let code = match mutation {
            0 | 1 => {
                output = output
                    .as_builder()
                    .capacity(if mutation == 0 {
                        package.state_carrier_capacity + 1
                    } else {
                        package.state_carrier_capacity - 1
                    })
                    .build();
                ScriptError::StateCarrierMismatch
            }
            2 => {
                output = output.as_builder().lock(fixture.locks[0].clone()).build();
                ScriptError::StateTypeMismatch
            }
            3 => {
                package.state.header.chain_id[0] ^= 1;
                ScriptError::HeaderContextChanged
            }
            4 => {
                package.state.header.state_number = 1;
                ScriptError::NonMonotonicStateNumber
            }
            5 => {
                package.state.header.phase = Phase::Active;
                ScriptError::NewStateNotSettling
            }
            6 => {
                package.state.header.participants_commitment[0] ^= 1;
                ScriptError::HeaderContextChanged
            }
            7 => {
                package.state.header.asset_registry_commitment[0] ^= 1;
                ScriptError::MultiAssetCommitmentMismatch
            }
            8 => {
                package.state.vault_outpoint_set_root[0] ^= 1;
                ScriptError::VaultOutPointMismatch
            }
            9 => ScriptError::ParticipantWitnessMissing,
            _ => ScriptError::InvalidParticipantSignature,
        };
        if mutation != 6 {
            signed(&mut package);
        }
        if mutation == 10 {
            package.authorization.signatures[0].signature[0] ^= 1;
        }
        let tx = fixture
            .supersede
            .clone()
            .as_advanced_builder()
            .set_outputs(vec![output])
            .set_outputs_data(vec![
                Bytes::from(package.state.encode().unwrap().to_vec()).pack(),
            ])
            .set_witnesses(vec![evidence(&package, mutation != 9).pack()])
            .build();
        rejects(&fixture.context, &tx, &[code as i8]);
    }
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_finalise_rejects_absolute_since_dirty_typed_split_and_standalone_retirement() {
    let mut fixture = build_with_plain(0, false, true);
    let tx = finalise(&mut fixture);
    for mutation in 0..6 {
        let mut inputs = tx.inputs().into_iter().collect::<Vec<_>>();
        let mut outputs = tx.outputs().into_iter().collect::<Vec<_>>();
        let mut data = tx.outputs_data().into_iter().collect::<Vec<_>>();
        let code = match mutation {
            0 => {
                inputs[0] = inputs[0].clone().as_builder().since(6u64).build();
                ScriptError::StateSinceNotMature
            }
            1 => {
                data[0] = Bytes::from(vec![1]).pack();
                ScriptError::MultiAssetConservationMismatch
            }
            2 => {
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .type_(Some(fixture.locks[1].clone()).pack())
                    .build();
                ScriptError::MultiAssetCapacityMismatch
            }
            3 => {
                let capacity: u64 = outputs[0].capacity().unpack();
                outputs[0] = outputs[0]
                    .clone()
                    .as_builder()
                    .capacity(capacity / 2)
                    .build();
                outputs.insert(1, outputs[0].clone());
                data.insert(1, Bytes::new().pack());
                ScriptError::MultiAssetCapacityMismatch
            }
            4 => {
                inputs.truncate(1);
                outputs.truncate(1);
                data.truncate(1);
                ScriptError::MultiAssetVaultSetIncomplete
            }
            _ => {
                outputs.push(state_output(&fixture));
                data.push(Bytes::from(fixture.package.state.encode().unwrap().to_vec()).pack());
                ScriptError::WrongGroupShape
            }
        };
        let changed = tx
            .clone()
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(data)
            .build();
        let changed = fixture.context.complete_tx(changed);
        rejects(&fixture.context, &changed, &[code as i8]);
    }
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_vault_authority_checks_state_lock_identity_and_unique_authentic_state() {
    let mut fixture = build_with_plain(0, false, true);
    let tx = finalise(&mut fixture);
    let state_bytes = Bytes::from(fixture.package.state.encode().unwrap().to_vec());
    let fake_state = fixture.context.create_cell(
        state_output(&fixture)
            .as_builder()
            .lock(fixture.locks[0].clone())
            .build(),
        state_bytes.clone(),
    );
    let mut inputs = tx.inputs().into_iter().collect::<Vec<_>>();
    inputs[0] = CellInput::new(fake_state, fixture.since);
    let changed = fixture
        .context
        .complete_tx(tx.clone().as_advanced_builder().set_inputs(inputs).build());
    rejects(
        &fixture.context,
        &changed,
        &[ScriptError::StateTypeMismatch as i8],
    );

    let second = fixture
        .context
        .create_cell(state_output(&fixture), state_bytes);
    let changed = tx
        .as_advanced_builder()
        .input(CellInput::new(second, fixture.since))
        .build();
    rejects(
        &fixture.context,
        &changed,
        &[
            ScriptError::WrongGroupShape as i8,
            ScriptError::StateCellAmbiguous as i8,
        ],
    );
}

fn sponsored(fixture: &mut Fixture, mutation: u8) -> TransactionView {
    let mut package = fixture.package.clone();
    package.state.header.state_number = 1;
    signed(&mut package);
    let change = deploy_always_success_with_args(&mut fixture.context, Bytes::from(vec![88]));
    let mut policy = sponsor_policy_with_already_spent(
        &change.calc_script_hash().unpack(),
        &fixture.state_type.calc_script_hash().unpack(),
        if mutation == 1 { 99 } else { 1_000 },
        u64::MAX,
        if mutation == 2 { u64::MAX } else { 0 },
    );
    policy[..32].copy_from_slice(&package.state.header.channel_id);
    if mutation == 3 {
        put_u64(&mut policy, 32, 2);
    }
    let sponsor = deploy_contract(&mut fixture.context, "morph-sponsor-lock", policy);
    let source = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor)
            .build(),
        Bytes::new(),
    );
    let mut inputs = vec![
        CellInput::new(point(&fixture.activation, 0), 0),
        CellInput::new(source, 0),
    ];
    let mut outputs = vec![
        state_output(fixture),
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY - 100)
            .lock(change)
            .build(),
    ];
    let mut data = vec![
        Bytes::from(package.state.encode().unwrap().to_vec()).pack(),
        Bytes::new().pack(),
    ];
    match mutation {
        4 => data[1] = Bytes::from(vec![1]).pack(),
        5 => {
            outputs[1] = outputs[1]
                .clone()
                .as_builder()
                .type_(Some(fixture.locks[1].clone()).pack())
                .build()
        }
        6 => {
            outputs[1] = outputs[1]
                .clone()
                .as_builder()
                .capacity(CELL_CAPACITY - 10_000_000_100)
                .build();
            outputs.push(
                CellOutput::new_builder()
                    .capacity(10_000_000_000u64)
                    .lock(fixture.locks[1].clone())
                    .build(),
            );
            data.push(Bytes::new().pack());
        }
        7 => {
            inputs.remove(0);
            outputs.remove(0);
            data.remove(0);
        }
        8 => {
            inputs.remove(0);
            // Use a fee source to balance the fake publication; it is still
            // not a StateType input authorizing publication.
            let wallet = fixture.context.create_cell(
                CellOutput::new_builder()
                    .capacity(package.state_carrier_capacity)
                    .lock(fixture.locks[0].clone())
                    .build(),
                Bytes::new(),
            );
            inputs.push(CellInput::new(wallet, 0));
        }
        9 => {
            outputs[0] = outputs[0]
                .clone()
                .as_builder()
                .type_(None::<Script>.pack())
                .build()
        }
        _ => {}
    }
    fixture.context.complete_tx(
        TransactionBuilder::default()
            .set_inputs(inputs)
            .set_outputs(outputs)
            .set_outputs_data(data)
            .witness(evidence(&package, true))
            .build(),
    )
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_sponsor_bounds_fee_budget_change_attribution_and_authentic_publication() {
    let mut fixture = build_with_plain(0, false, true);
    let baseline = sponsored(&mut fixture, 0);
    fixture
        .context
        .verify_tx(&baseline, MAX_CYCLES)
        .expect("current sponsor publication");
    let codes = [
        ScriptError::SponsorFeeTooHigh,
        ScriptError::SponsorBudgetExceeded,
        ScriptError::SponsorStateOutOfRange,
        ScriptError::SponsorBudgetExceeded,
        ScriptError::SponsorBudgetExceeded,
        ScriptError::SponsorFeeMismatch,
        ScriptError::StateCellMissing,
        ScriptError::SponsorStateOutOfRange,
        ScriptError::StateTypeMismatch,
    ];
    for (index, code) in codes.into_iter().enumerate() {
        let tx = sponsored(&mut fixture, index as u8 + 1);
        rejects(&fixture.context, &tx, &[code as i8]);
    }
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn current_contracts_reject_retired_state_vault_and_factory_shapes() {
    let mut fixture = build_with_plain(0, false, true);
    // No retired encoder is retained for these rejection probes.
    let mut retired_state = fixture.package.state.encode().unwrap().to_vec();
    retired_state.resize(346, 0);
    let tx = fixture
        .supersede
        .clone()
        .as_advanced_builder()
        .set_outputs_data(vec![Bytes::from(retired_state).pack()])
        .build();
    rejects(
        &fixture.context,
        &tx,
        &[ScriptError::MultiAssetEncoding as i8],
    );
    for (name, args, data, code) in [
        (
            "morph-vault-lock",
            vec![0; 139],
            vec![],
            ScriptError::MultiAssetEncoding,
        ),
        (
            "morph-factory-vault-lock",
            vec![0; 32],
            vec![],
            ScriptError::WrongArgsLength,
        ),
    ] {
        let lock = deploy_contract(&mut fixture.context, name, args);
        let source = fixture.context.create_cell(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(lock)
                .build(),
            data.into(),
        );
        let tx = fixture.context.complete_tx(
            TransactionBuilder::default()
                .input(CellInput::new(source, 0))
                .output(
                    CellOutput::new_builder()
                        .capacity(CELL_CAPACITY)
                        .lock(fixture.locks[0].clone())
                        .build(),
                )
                .output_data(Bytes::new().pack())
                .build(),
        );
        rejects(&fixture.context, &tx, &[code as i8]);
    }
    let factory_type = deploy_contract(&mut fixture.context, "morph-factory-type", vec![0; 32]);
    let source = fixture.context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(fixture.locks[0].clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        vec![0; 302].into(),
    );
    let tx = fixture.context.complete_tx(
        TransactionBuilder::default()
            .input(CellInput::new(source, 0))
            .output(
                CellOutput::new_builder()
                    .capacity(CELL_CAPACITY)
                    .lock(fixture.locks[0].clone())
                    .type_(Some(factory_type).pack())
                    .build(),
            )
            .output_data(Bytes::from(vec![0; 302]).pack())
            .build(),
    );
    rejects(
        &fixture.context,
        &tx,
        &[ScriptError::FactoryMultiAssetPartitionMismatch as i8],
    );
}
