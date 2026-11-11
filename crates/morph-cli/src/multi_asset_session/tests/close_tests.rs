use super::canonical_fixture::{Fixture, setup};
use super::*;
use crate::participant_signer::tests::{ChildGuard, configuration, start};
use ckb_types::core::TransactionBuilder;
use morph_packages::multi_asset_close::CloseDraft;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn prepare(f: &Fixture) -> (CloseDraft, Bytes32) {
    let p = f.package.recovery().unwrap();
    let header = p.state.encode().unwrap();
    let inner =
        encode_multi_asset_witness(&p.manifest, &p.settlement, &p.outpoints, &p.scripts).unwrap();
    let outputs = multi_asset_settlement_outputs(
        &wire::MultiAssetWitness::parse(&inner).unwrap(),
        &wire::MultiAssetStateHeader::parse(&header).unwrap(),
        p.state_carrier_capacity,
    )
    .unwrap();
    let mut tx = TransactionBuilder::default()
        .input(packed::CellInput::new(f.state_point.clone(), 0))
        .cell_deps(packages::decode_dependency_records(&f.package.cell_deps).unwrap());
    for point in &p.outpoints {
        tx = tx.input(packed::CellInput::new(
            packed::OutPoint::new(point.tx_hash.pack(), point.index),
            0,
        ));
    }
    for (output, data) in outputs {
        tx = tx.output(output).output_data(data.pack());
    }
    let tx = tx.build();
    let mut source = p.state.clone();
    source.header.phase = Phase::Active;
    source.header.state_number = 0;
    let plan = MultiAssetCloseProposal {
        source_outpoint: MultiAssetOutPoint {
            tx_hash: f.state_point.tx_hash().unpack(),
            index: 0,
        },
        source_state: source,
        transaction: tx.data().raw().as_slice().to_vec(),
    };
    let draft = CloseDraft::from_proposal(&plan).unwrap();
    let path = f.dir.path().join("close.json");
    crate::persistence::write_private_atomic(&path, &serde_json::to_vec(&draft).unwrap()).unwrap();
    for journal in &f.paths {
        super::super::run(
            journal,
            SessionCommand::CooperativeClose {
                operation: CloseCommand::Prepare {
                    draft: path.clone(),
                },
            },
        )
        .unwrap();
    }
    (draft, plan.transaction_hash().unwrap())
}
fn config(f: &Fixture) -> (PathBuf, PathBuf, PathBuf) {
    let (config, socket, key) = configuration(
        f.dir.path(),
        &f.paths[0],
        &f.rpc.url,
        &f.package.recovery().unwrap(),
        &[1; 32],
    );
    let mut value: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    value["targets"]
        .as_array_mut()
        .unwrap()
        .push("cooperative_close".into());
    crate::persistence::write_private_atomic(&config, &serde_json::to_vec(&value).unwrap())
        .unwrap();
    (config, socket, key)
}
fn command(path: &Path, hash: &Bytes32, config: &Path) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "multi_asset_session::tests::close_tests::host_child",
        "--nocapture",
    ])
    .env("MORPH_CLOSE_TEST_PATH", path)
    .env("MORPH_CLOSE_TEST_HASH", canonical_hex(hash))
    .env("MORPH_CLOSE_TEST_CONFIG", config)
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    cmd
}
#[test]
fn host_child() {
    let Some(path) = std::env::var_os("MORPH_CLOSE_TEST_PATH") else {
        return;
    };
    let value = super::super::run(
        Path::new(&path),
        SessionCommand::CooperativeClose {
            operation: CloseCommand::Sign {
                transaction_hash: std::env::var("MORPH_CLOSE_TEST_HASH").unwrap(),
                signer_config: PathBuf::from(std::env::var_os("MORPH_CLOSE_TEST_CONFIG").unwrap()),
            },
        },
    )
    .unwrap();
    if let Some(path) = std::env::var_os("MORPH_CLOSE_TEST_OUTPUT") {
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
}
#[test]
fn close_real_host_kill_at_reservation_receipt_and_record_retains_authority() {
    for stage in ["reserved", "received", "recorded"] {
        let f = setup();
        let (_, hash) = prepare(&f);
        let (config, socket, key) = config(&f);
        let mut signer = if stage == "reserved" {
            None
        } else {
            Some(start(&config, &key, &socket))
        };
        let marker = f.dir.path().join("cut");
        let mut host = ChildGuard(
            command(&f.paths[0], &hash, &config)
                .env("MORPH_FAULT_STAGE", stage)
                .env("MORPH_FAULT_MARKER", &marker)
                .env("MORPH_FAULT_RELEASE", f.dir.path().join("release"))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(12);
        while !marker.exists() {
            assert!(
                Instant::now() < deadline && host.0.try_wait().unwrap().is_none(),
                "close host failed before {stage}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        host.0.kill().unwrap();
        host.0.wait().unwrap();
        if let Some(signer) = &mut signer {
            assert!(signer.0.wait().unwrap().success());
        }
        let session: StoredSession =
            serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
        assert!(session.backend.close_signature_reserved(&hash).unwrap());
        let before = fs::read(&f.paths[0]).unwrap();
        assert!(
            super::super::run(
                &f.paths[0],
                SessionCommand::CooperativeClose {
                    operation: CloseCommand::Cancel
                }
            )
            .is_err()
        );
        assert_eq!(fs::read(&f.paths[0]).unwrap(), before);
        let mut retry_signer = if stage == "recorded" {
            None
        } else {
            Some(start(&config, &key, &socket))
        };
        let output = f.dir.path().join("receipt.json");
        let mut retry = ChildGuard(
            command(&f.paths[0], &hash, &config)
                .env("MORPH_CLOSE_TEST_OUTPUT", &output)
                .spawn()
                .unwrap(),
        );
        assert!(retry.0.wait().unwrap().success());
        if let Some(signer) = &mut retry_signer {
            assert!(signer.0.wait().unwrap().success());
        }
        let msg: SignatureMessage = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        let session: StoredSession =
            serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
        assert_eq!(session.backend.close_attempts()[0].signatures.len(), 1);
        assert_eq!(
            msg.signing_digest,
            canonical_hex(
                &session.backend.close_attempts()[0]
                    .proposal
                    .signing_digest(session.backend.current())
                    .unwrap()
            )
        );
    }
}

#[test]
fn close_preparation_and_export_are_real_and_keep_unilateral_recovery() {
    let f = setup();
    let (draft, hash) = prepare(&f);
    let (config, socket, key) = config(&f);
    let mut signer = start(&config, &key, &socket);
    let receipt = super::super::run(
        &f.paths[0],
        SessionCommand::CooperativeClose {
            operation: CloseCommand::Sign {
                transaction_hash: canonical_hex(&hash),
                signer_config: config,
            },
        },
    )
    .unwrap();
    assert!(signer.0.wait().unwrap().success());
    assert!(receipt.get("signature").is_some());
    let p = f.package.recovery().unwrap();
    let plan = draft.proposal(&p).unwrap();
    let digest = plan.signing_digest(&p).unwrap();
    let key = SigningKey::from_slice(&[2; 32]).unwrap();
    let sig: Signature = key.sign_prehash(&digest).unwrap();
    let peer = SignatureMessage::new(
        &digest,
        &ParticipantSignature {
            pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        },
    );
    let path = f.dir.path().join("peer.json");
    crate::persistence::write_private_atomic(&path, &serde_json::to_vec(&peer).unwrap()).unwrap();
    let summary = super::super::run(
        &f.paths[0],
        SessionCommand::CooperativeClose {
            operation: CloseCommand::AddSignature {
                transaction_hash: canonical_hex(&hash),
                signature: path,
            },
        },
    )
    .unwrap();
    assert_eq!(
        summary["close"][0]["transaction_hash"],
        canonical_hex(&hash)
    );
    assert_eq!(summary["close"][0]["signature_reserved"], true);
    assert_eq!(summary["close"][0]["signature_count"], 2);
    assert_eq!(summary["close"][0]["participant_authorized"], true);
    let output = f.dir.path().join("close.tx");
    super::super::run(
        &f.paths[0],
        SessionCommand::CooperativeClose {
            operation: CloseCommand::Export {
                transaction_hash: canonical_hex(&hash),
                output: output.clone(),
            },
        },
    )
    .unwrap();
    let tx = packed::Transaction::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(tx.calc_tx_hash().as_slice(), hash);
    let session: StoredSession = serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
    assert_eq!(session.backend.current(), &p);
    let witness =
        packed::WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
    let bytes = witness.output_type().to_opt().unwrap().raw_data();
    let frame =
        morph_script_common::multi_asset_close::MultiAssetCloseWitness::parse(&bytes).unwrap();
    let source = plan.source_state.encode().unwrap();
    frame
        .validate_source(&wire::MultiAssetStateHeader::parse(&source).unwrap())
        .unwrap();
}

#[test]
fn close_receipt_space_is_reserved_and_oversized_replacement_never_changes_disk() {
    let f = setup();
    let (draft, hash) = prepare(&f);
    let mut session: StoredSession =
        serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
    session.backend.reserve_close_signature(&hash).unwrap();
    save(&f.paths[0], &session).unwrap();
    let base = draft.proposal(session.backend.current()).unwrap();
    let fee_lock = packed::Script::new_builder()
        .code_hash([99; 32].pack())
        .hash_type(2u8)
        .args(vec![255u8; 459].pack())
        .build();
    let raw = base.raw_transaction().unwrap();
    let mut outputs: Vec<_> = raw.outputs().into_iter().collect();
    let mut data: Vec<_> = raw.outputs_data().into_iter().collect();
    while outputs.len() < 62 {
        outputs.push(
            packed::CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .lock(fee_lock.clone())
                .build(),
        );
        data.push(Bytes::new().pack());
    }
    let mut stopped = false;
    for marker in 1..=20u8 {
        let mut candidate: StoredSession =
            serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
        let mut proposal = base.clone();
        let mut inputs: Vec<_> = raw.inputs().into_iter().collect();
        inputs.push(packed::CellInput::new(
            packed::OutPoint::new([marker + 100; 32].pack(), 0),
            0,
        ));
        proposal.transaction = raw
            .clone()
            .as_builder()
            .inputs(inputs.pack())
            .outputs(outputs.clone().pack())
            .outputs_data(data.clone().pack())
            .build()
            .as_slice()
            .to_vec();
        candidate.backend.prepare_close(proposal).unwrap();
        let before = fs::read(&f.paths[0]).unwrap();
        if let Err(error) = save(&f.paths[0], &candidate) {
            assert!(error.to_string().contains("byte budget"));
            assert_eq!(fs::read(&f.paths[0]).unwrap(), before);
            stopped = true;
            break;
        }
    }
    assert!(
        stopped,
        "aggregate receipt budget must fail before Core history ceiling"
    );
    let retained: StoredSession = serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
    assert!(retained.backend.close_signature_reserved(&hash).unwrap());
    assert_eq!(retained.backend.current(), &f.package.recovery().unwrap());
}

#[test]
fn close_signer_rejects_wrong_role_and_changed_canonical_source_before_key_use() {
    let f = setup();
    let (draft, hash) = prepare(&f);
    let (config, _, _) = config(&f);
    let payload = morph_packages::signer_protocol::Payload::CooperativeClose {
        current: Box::new(f.package.clone()),
        draft,
    };
    for target in [
        morph_packages::signer_protocol::Target::RootExit,
        morph_packages::signer_protocol::Target::RootCreation,
        morph_packages::signer_protocol::Target::Update,
        morph_packages::signer_protocol::Target::SpliceCreation,
        morph_packages::signer_protocol::Target::SpliceRecovery,
        morph_packages::signer_protocol::Target::SpliceBridge,
    ] {
        assert!(
            crate::participant_signer::tests::try_request(&config, target, payload.clone())
                .is_err()
        );
    }
    let request = crate::participant_signer::tests::request(
        &config,
        morph_packages::signer_protocol::Target::CooperativeClose,
        payload,
    );
    assert_eq!(
        request.review.domain,
        canonical_hex(morph_core::hash::MULTI_ASSET_CLOSE_DOMAIN)
    );
    assert_eq!(
        request
            .review
            .transaction
            .as_ref()
            .unwrap()
            .transaction_hash,
        canonical_hex(&hash)
    );
    assert_ne!(
        request.review.domain,
        canonical_hex(morph_core::hash::MULTI_ASSET_STATE_DOMAIN)
    );
    let mut session: StoredSession =
        serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
    session.backend.reserve_close_signature(&hash).unwrap();
    save(&f.paths[0], &session).unwrap();
    let point =
        serde_json::to_value(ckb_jsonrpc_types::OutPoint::from(f.state_point.clone())).unwrap();
    f.rpc.respond(
        "get_live_cell",
        json!([point, true, false]),
        json!({"status":"dead","cell":null}),
    );
    let rpc = crate::rpc::CkbRpcClient::new_signer(&f.rpc.url, Duration::from_secs(5)).unwrap();
    assert!(
        super::super::external_close_authority(&fs::read(&f.paths[0]).unwrap(), &hash, &rpc)
            .is_err()
    );
    let retained: StoredSession = serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
    assert!(retained.backend.close_signature_reserved(&hash).unwrap());
}

#[test]
fn close_actual_write_sync_rename_and_directory_failures_recover_exact_authority() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let build = tempfile::tempdir().unwrap();
    let library = build.path().join("close-io.so");
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-Wall", "-Werror"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/session_io_fault.c"))
            .args(["-ldl", "-o"])
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    for ordinal in [1, 2] {
        for mode in ["write", "sync", "rename", "directory"] {
            let f = setup();
            let (_, hash) = prepare(&f);
            let (config, socket, key) = config(&f);
            let before = fs::read(&f.paths[0]).unwrap();
            let listener = if ordinal == 1 {
                let listener = UnixListener::bind(&socket).unwrap();
                fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
                listener.set_nonblocking(true).unwrap();
                Some(listener)
            } else {
                None
            };
            let mut signer = if ordinal == 2 {
                Some(start(&config, &key, &socket))
            } else {
                None
            };
            let hit = f.dir.path().join("io-hit");
            let mut host = ChildGuard(
                command(&f.paths[0], &hash, &config)
                    .env("LD_PRELOAD", &library)
                    .env("MORPH_IO_MODE", mode)
                    .env("MORPH_IO_ORDINAL", ordinal.to_string())
                    .env("MORPH_IO_TMP_PREFIX", f.dir.path().join(".alice.json."))
                    .env("MORPH_IO_PARENT", f.dir.path())
                    .env("MORPH_IO_HIT", &hit)
                    .spawn()
                    .unwrap(),
            );
            assert!(!host.0.wait().unwrap().success(), "{ordinal}/{mode}");
            assert!(hit.exists(), "syscall injection did not fire");
            if let Some(listener) = listener {
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                drop(listener);
                fs::remove_file(&socket).unwrap();
            }
            if let Some(signer) = &mut signer {
                assert!(signer.0.wait().unwrap().success());
            }
            let saved: StoredSession =
                serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
            let recorded = ordinal == 2 && mode == "directory";
            assert_eq!(
                saved.backend.close_attempts()[0].signatures.len(),
                usize::from(recorded)
            );
            if ordinal == 1 && mode != "directory" {
                assert_eq!(fs::read(&f.paths[0]).unwrap(), before);
                assert!(!saved.backend.close_signature_reserved(&hash).unwrap());
            } else {
                assert!(saved.backend.close_signature_reserved(&hash).unwrap());
                let mut backend = saved.backend.clone();
                assert!(backend.cancel_close().is_err());
            }
            let output = f.dir.path().join("retry.json");
            let mut signer = if recorded {
                None
            } else {
                Some(start(&config, &key, &socket))
            };
            let mut retry = ChildGuard(
                command(&f.paths[0], &hash, &config)
                    .env("MORPH_CLOSE_TEST_OUTPUT", &output)
                    .spawn()
                    .unwrap(),
            );
            assert!(retry.0.wait().unwrap().success());
            if let Some(signer) = &mut signer {
                assert!(signer.0.wait().unwrap().success());
            }
            let receipt: SignatureMessage =
                serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
            let saved: StoredSession =
                serde_json::from_slice(&fs::read(&f.paths[0]).unwrap()).unwrap();
            assert!(saved.backend.close_signature_reserved(&hash).unwrap());
            assert_eq!(saved.backend.close_attempts()[0].signatures.len(), 1);
            assert_eq!(
                receipt.signing_digest,
                canonical_hex(
                    &saved.backend.close_attempts()[0]
                        .proposal
                        .signing_digest(saved.backend.current())
                        .unwrap()
                )
            );
            assert_eq!(saved.backend.current(), &f.package.recovery().unwrap());
        }
    }
}
