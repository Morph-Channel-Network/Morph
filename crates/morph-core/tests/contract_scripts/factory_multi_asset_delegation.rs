use super::*;

// Exercise all three paths through the reserve gate. Authorization remains in
// the exact Factory Type; these tests identify the rejecting script as well as
// its exit code so another verifier cannot accidentally satisfy the negative.
enum GateFixture {
    Materialisation(Box<FactoryFixture>),
    Reduced(Box<ReducedFixture>),
}

impl GateFixture {
    fn build(profile: u8) -> Self {
        match profile {
            0 => Self::Materialisation(Box::new(build_factory_profile(0, true, 1, true, 2, false))),
            1 | 2 => Self::Reduced(Box::new(reduced_fixture_operation(
                0,
                true,
                2,
                false,
                if profile == 1 {
                    morph_core::FactoryTransitionOperation::ReducedRelease
                } else {
                    morph_core::FactoryTransitionOperation::ReducedChild
                },
            ))),
            _ => unreachable!(),
        }
    }

    fn base(&self) -> &FactoryFixture {
        match self {
            Self::Materialisation(fixture) => fixture,
            Self::Reduced(fixture) => &fixture.base,
        }
    }

    fn context(&self) -> &Context {
        &self.base().template.context
    }

    fn context_mut(&mut self) -> &mut Context {
        match self {
            Self::Materialisation(fixture) => &mut fixture.template.context,
            Self::Reduced(fixture) => &mut fixture.base.template.context,
        }
    }

    fn transaction(&self) -> &TransactionView {
        match self {
            Self::Materialisation(fixture) => &fixture.materialisation,
            Self::Reduced(fixture) => &fixture.transaction,
        }
    }

    fn authorise(&mut self, transaction: TransactionView) -> TransactionView {
        let transaction = match self {
            Self::Materialisation(fixture) => reauthorise(fixture, transaction),
            Self::Reduced(fixture) => resign(fixture, transaction),
        };
        verify_frame(&release_frame(&transaction));
        transaction
    }
}

fn verify_frame(raw: &[u8]) {
    if raw.starts_with(factory::FACTORY_MATERIALISATION_MAGIC) {
        factory::FactoryMaterialisationWitness::parse(raw)
            .unwrap()
            .verify()
            .expect("all member signatures and public child terms are valid");
    } else {
        factory::FactoryReducedReleaseWitness::parse(raw)
            .unwrap()
            .verify()
            .expect("exact-body member signatures, locality and rights proofs are valid");
    }
}

fn gate_rejects(context: &Context, transaction: &TransactionView, source: &str, code: ScriptError) {
    let error = context
        .verify_tx(transaction, MAX_CYCLES)
        .expect_err("unsafe Factory delegation");
    let script_error = error
        .root_cause()
        .downcast_ref::<ckb_testtool::ckb_script::TransactionScriptError>()
        .expect("the target script must reject, not transaction resolution or VM setup");
    assert_eq!(script_error.originating_script().to_string(), source);
    assert!(
        matches!(
            script_error.script_error(),
            ckb_testtool::ckb_script::ScriptError::ValidationFailure(_, actual)
                if *actual == code as i8
        ),
        "unexpected rejection: {error:?}"
    );
}

fn frame_witness(frame: Vec<u8>) -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(frame)).pack())
        .build()
        .as_bytes()
        .pack()
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_vault_delegation_uses_global_frame_and_requires_type_authorization() {
    for profile in 0..3 {
        let fixture = GateFixture::build(profile);
        let transaction = fixture.transaction();
        let frame = release_frame(transaction);
        verify_frame(&frame);
        fixture
            .context()
            .verify_tx(transaction, MAX_CYCLES)
            .expect("authentic Factory Type and reserve gate accept the valid control");

        let mut invalid = frame.clone();
        let original_signature = if profile == 0 {
            factory::FactoryMaterialisationWitness::parse(&invalid)
                .unwrap()
                .factory_signatures()
                .signature(0)
        } else {
            factory::FactoryReducedReleaseWitness::parse(&invalid)
                .unwrap()
                .signature(0)
                .unwrap()
        };
        let offset = original_signature.as_ptr() as usize - invalid.as_ptr() as usize;
        invalid[offset..offset + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(&signing_key(1), &[211; 32]));

        // The Vault group's own witness is input one. It cannot override the
        // global frame, whether it supplies valid or invalid authorization.
        let valid_global = transaction
            .as_advanced_builder()
            .set_witnesses(vec![
                frame_witness(frame.clone()),
                frame_witness(invalid.clone()),
            ])
            .build();
        fixture
            .context()
            .verify_tx(&valid_global, MAX_CYCLES)
            .expect("only global witness zero supplies the Factory transition frame");
        let invalid_global = transaction
            .as_advanced_builder()
            .set_witnesses(vec![frame_witness(invalid), frame_witness(frame)])
            .build();
        gate_rejects(
            fixture.context(),
            &invalid_global,
            "Inputs[0].Type",
            ScriptError::InvalidParticipantSignature,
        );
    }
}

#[test]
#[ignore = "requires built current ELFs"]
fn factory_authority_rejects_upgradeable_type_hash_code_selection() {
    let mut f = GateFixture::build(0);
    let args = f.base().factory_type.args().raw_data();
    let code = f
        .context_mut()
        .deploy_cell(contract_bin("morph-factory-type"));
    // Context's default constructs a Type-ID-selected code Script. Assets and
    // wallets may use it, but it cannot be the delegated Factory authority.
    let ty = f.context_mut().build_script(&code, args).unwrap();
    assert_eq!(ty.hash_type().as_slice(), &[1]);
    let lock = f.base().template.locks[0].clone();
    let input = f.context_mut().create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let tx = f.context_mut().complete_tx(
        TransactionBuilder::default()
            .input(CellInput::new(input, 0))
            .output(
                CellOutput::new_builder()
                    .capacity(CELL_CAPACITY)
                    .lock(lock)
                    .type_(Some(ty).pack())
                    .build(),
            )
            .output_data(Bytes::from(vec![0; 306]).pack())
            .build(),
    );
    gate_rejects(
        f.context(),
        &tx,
        "Outputs[0].Type",
        ScriptError::UnsupportedProtocolProfile,
    );
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_vault_delegation_rejects_foreign_missing_and_aliased_source_types() {
    for profile in 0..3 {
        for false_type in 0..3 {
            let mut fixture = GateFixture::build(profile);
            let transaction = fixture.transaction().clone();
            let source = transaction.inputs().get(0).unwrap().previous_output();
            let (cell, data) = fixture.context().get_cell(&source).unwrap();
            let wallet = fixture.base().template.locks[0].clone();
            let ty = match false_type {
                // Valid Factory args on foreign permissive code do not bind
                // custody to the exact Type committed by the Vault lock.
                0 => Some(
                    fixture
                        .base()
                        .factory_type
                        .clone()
                        .as_builder()
                        .code_hash(wallet.code_hash())
                        .hash_type(wallet.hash_type())
                        .build(),
                ),
                1 => None,
                2 => Some(
                    fixture
                        .base()
                        .factory_type
                        .clone()
                        .as_builder()
                        .args(
                            Bytes::from(
                                factory::encode_factory_multi_asset_type_args(&[42; 32])
                                    .unwrap()
                                    .to_vec(),
                            )
                            .pack(),
                        )
                        .build(),
                ),
                _ => unreachable!(),
            };
            // Replace the resolved synthetic cell at its exact OutPoint, so
            // the frame retains valid exact-body signatures and source roots.
            // Remove the genuine Type on both sides and use a wallet lock so
            // StateLock cannot cause this negative to pass before the Vault.
            fixture.context_mut().create_cell_with_out_point(
                source,
                cell.as_builder()
                    .lock(wallet.clone())
                    .type_(ty.clone().pack())
                    .build(),
                data,
            );
            let mut outputs: Vec<_> = transaction.outputs().into_iter().collect();
            outputs[0] = outputs[0]
                .clone()
                .as_builder()
                .lock(wallet)
                .type_(ty.pack())
                .build();
            let changed = transaction
                .as_advanced_builder()
                .set_outputs(outputs)
                .build();
            let changed = fixture.context_mut().complete_tx(changed);
            let changed = fixture.authorise(changed);
            gate_rejects(
                fixture.context(),
                &changed,
                "Inputs[1].Lock",
                ScriptError::StateCellMissing,
            );
        }
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_vault_delegation_rejects_group_frame_mixed_roles_and_source_relocation() {
    for profile in 0..3 {
        let mut fixture = GateFixture::build(profile);
        let transaction = fixture.transaction().clone();
        let frame = release_frame(&transaction);
        verify_frame(&frame);
        let relocated = transaction
            .as_advanced_builder()
            .set_witnesses(vec![
                WitnessArgs::default().as_bytes().pack(),
                frame_witness(frame.clone()),
            ])
            .build();
        gate_rejects(
            fixture.context(),
            &relocated,
            "Inputs[1].Lock",
            ScriptError::FactoryMultiAssetPartitionMismatch,
        );
        let mixed = transaction
            .as_advanced_builder()
            .set_witnesses(vec![
                WitnessArgs::new_builder()
                    .input_type(Some(Bytes::from(vec![1])).pack())
                    .output_type(Some(Bytes::from(frame)).pack())
                    .build()
                    .as_bytes()
                    .pack(),
            ])
            .build();
        gate_rejects(
            fixture.context(),
            &mixed,
            "Inputs[1].Lock",
            ScriptError::FactoryMultiAssetPartitionMismatch,
        );

        let mut inputs: Vec<_> = transaction.inputs().into_iter().collect();
        let last = inputs.len() - 1;
        inputs.swap(0, last);
        let moved_source = transaction.as_advanced_builder().set_inputs(inputs).build();
        let moved_source = fixture.authorise(moved_source);
        gate_rejects(
            fixture.context(),
            &moved_source,
            "Inputs[1].Lock",
            ScriptError::FactoryMultiAssetPartitionMismatch,
        );
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_vault_delegation_binds_actual_transaction_before_delegating_signatures() {
    for profile in 0..3 {
        let mut fixture = GateFixture::build(profile);
        let transaction = fixture.transaction().clone();
        let mut outputs: Vec<_> = transaction.outputs().into_iter().collect();
        let last = outputs.len() - 1;
        let capacity: u64 = outputs[last].capacity().unpack();
        outputs[last] = outputs[last]
            .clone()
            .as_builder()
            .capacity(capacity - 1)
            .build();
        let changed = transaction
            .as_advanced_builder()
            .set_outputs(outputs)
            .build();
        verify_frame(&release_frame(&changed));
        gate_rejects(
            fixture.context(),
            &changed,
            "Inputs[1].Lock",
            ScriptError::FactoryMultiAssetPartitionMismatch,
        );
        let reapproved = fixture.authorise(changed);
        fixture
            .context()
            .verify_tx(&reapproved, MAX_CYCLES)
            .expect("the same fee change is valid with fresh exact-transaction approval");
    }
}

#[test]
#[ignore = "requires make build-contracts"]
fn factory_vault_delegation_applies_type_transaction_bounds() {
    for profile in 0..3 {
        let mut fixture = GateFixture::build(profile);
        let transaction = fixture.transaction().clone();
        let version = transaction.as_advanced_builder().version(1u32).build();
        let version = fixture.authorise(version);
        gate_rejects(
            fixture.context(),
            &version,
            "Inputs[1].Lock",
            ScriptError::FactoryMultiAssetPartitionMismatch,
        );
        let mut witnesses = vec![Bytes::new().pack(); transaction.inputs().len() + 1];
        witnesses[0] = transaction.witnesses().get(0).unwrap();
        let excess_witness = transaction
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .build();
        verify_frame(&release_frame(&excess_witness));
        gate_rejects(
            fixture.context(),
            &excess_witness,
            "Inputs[1].Lock",
            ScriptError::FactoryMultiAssetPartitionMismatch,
        );
    }
}
