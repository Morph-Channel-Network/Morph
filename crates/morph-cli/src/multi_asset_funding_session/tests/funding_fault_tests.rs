//! Real host/key subprocess cuts against a controlled RPC fixture, not native CKB.
use super::*;
use crate::participant_signer::tests::{ChildGuard, configuration, start};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "missing fault checkpoint");
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn setup() -> (
    TempDir,
    [PathBuf; 2],
    [String; 2],
    crate::admission_channel::tests::MockRpc,
    morph_core::MultiAssetRecoveryPackage,
) {
    use ckb_types::prelude::*;
    let draft = crate::multi_asset_funding::tests::admitted_draft_fixture();
    let (_, recovery) = draft.evidence().unwrap();
    let rpc = crate::admission_channel::tests::MockRpc::start(recovery.state.header.chain_id, 100);
    let tx = draft.transaction().unwrap();
    let capacity = tx
        .raw()
        .outputs()
        .into_iter()
        .map(|o| u64::from(o.capacity()))
        .sum::<u64>()
        + 1000;
    for input in tx.raw().inputs() {
        rpc.set_live_cell(
            &input.previous_output(),
            &tx.raw()
                .outputs()
                .get(0)
                .unwrap()
                .as_builder()
                .capacity(capacity)
                .build(),
        );
    }
    let (dir, paths, keys, _) = fixture_with_draft(draft, Some(&rpc.url));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    (dir, paths, keys, rpc, recovery)
}
#[test]
fn host_child() {
    let Some(path) = std::env::var_os("MORPH_FAULT_HOST_JOURNAL") else {
        return;
    };
    let config = PathBuf::from(std::env::var_os("MORPH_FAULT_HOST_CONFIG").unwrap());
    let target = if std::env::var("MORPH_FAULT_HOST_TARGET").unwrap() == "creation" {
        FundingTarget::Creation
    } else {
        FundingTarget::Exit
    };
    let receipt = run(
        Path::new(&path),
        FundingSessionCommand::Sign {
            target,
            signer_config: config,
        },
    )
    .unwrap();
    if let Some(path) = std::env::var_os("MORPH_FAULT_HOST_OUTPUT") {
        std::fs::write(path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }
}
fn fresh_host(
    path: &Path,
    target: FundingTarget,
    config: &Path,
    output: &Path,
) -> serde_json::Value {
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "multi_asset_funding_session::tests::fault_tests::host_child",
                "--nocapture",
            ])
            .env("MORPH_FAULT_HOST_JOURNAL", path)
            .env("MORPH_FAULT_HOST_CONFIG", config)
            .env(
                "MORPH_FAULT_HOST_TARGET",
                if matches!(target, FundingTarget::Creation) {
                    "creation"
                } else {
                    "exit"
                },
            )
            .env("MORPH_FAULT_HOST_OUTPUT", output)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(child.0.wait().unwrap().success());
    serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap()
}
#[test]
fn real_host_kill_after_reserve_receipt_and_record_keeps_both_root_roles_monotonic() {
    for target in [FundingTarget::Exit, FundingTarget::Creation] {
        for stage in ["reserved", "received", "recorded"] {
            let (dir, paths, keys, rpc, recovery) = setup();
            if matches!(target, FundingTarget::Creation) {
                collect(&paths, &keys, dir.path(), FundingTarget::Exit);
            }
            let (config, socket, key) =
                configuration(dir.path(), &paths[0], &rpc.url, &recovery, &[1; 32]);
            let marker = dir.path().join("cut");
            let release = dir.path().join("release");
            let mut signer = if stage == "reserved" {
                None
            } else {
                Some(start(&config, &key, &socket))
            };
            let mut host = ChildGuard(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "multi_asset_funding_session::tests::fault_tests::host_child",
                        "--nocapture",
                    ])
                    .env("MORPH_FAULT_HOST_JOURNAL", &paths[0])
                    .env("MORPH_FAULT_HOST_CONFIG", &config)
                    .env(
                        "MORPH_FAULT_HOST_TARGET",
                        if matches!(target, FundingTarget::Creation) {
                            "creation"
                        } else {
                            "exit"
                        },
                    )
                    .env("MORPH_FAULT_STAGE", stage)
                    .env("MORPH_FAULT_MARKER", &marker)
                    .env("MORPH_FAULT_RELEASE", &release)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            wait_file(&marker);
            host.0.kill().unwrap();
            host.0.wait().unwrap();
            if let Some(signer) = &mut signer {
                assert!(signer.0.wait().unwrap().success());
            }
            let bytes = read(&paths[0]).unwrap();
            let journal: FundingJournal = serde_json::from_slice(&bytes).unwrap();
            assert!(journal.reserved(target));
            assert_eq!(
                journal.signatures(target).len(),
                usize::from(stage == "recorded")
            );
            let expected = canonical_hex(&journal.digest(target).unwrap());
            let mut retry_signer = if stage == "recorded" {
                None
            } else {
                Some(start(&config, &key, &socket))
            };
            let output = dir.path().join("fresh-output.json");
            let receipt = fresh_host(&paths[0], target, &config, &output);
            if let Some(signer) = &mut retry_signer {
                assert!(signer.0.wait().unwrap().success());
            }
            assert_eq!(receipt["signing_digest"], expected);
            let persisted = read(&paths[0]).unwrap();
            let current: FundingJournal = serde_json::from_slice(&persisted).unwrap();
            assert!(current.reserved(target));
            assert_eq!(current.signatures(target).len(), 1);
            assert_eq!(fresh_host(&paths[0], target, &config, &output), receipt);
            assert_eq!(read(&paths[0]).unwrap(), persisted);
            if stage == "recorded" {
                assert_eq!(persisted, bytes);
            }
        }
    }
}
#[test]
fn authority_advance_after_review_rejects_before_key_use_and_preserves_reservation() {
    use morph_packages::signer_protocol::Target;
    for target in [FundingTarget::Exit, FundingTarget::Creation] {
        let (dir, paths, keys, rpc, recovery) = setup();
        if matches!(target, FundingTarget::Creation) {
            collect(&paths, &keys, dir.path(), FundingTarget::Exit);
        }
        let (config, socket, key) =
            configuration(dir.path(), &paths[0], &rpc.url, &recovery, &[1; 32]);
        let mut journal: FundingJournal =
            serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        match target {
            FundingTarget::Exit => journal.exit_reserved = true,
            FundingTarget::Creation => journal.creation_reserved = true,
        }
        save(&paths[0], &journal).unwrap();
        let request = crate::participant_signer::tests::request(
            &config,
            if matches!(target, FundingTarget::Exit) {
                Target::RootExit
            } else {
                Target::RootCreation
            },
            journal.external_payload().unwrap(),
        );
        let marker = dir.path().join("reviewed");
        let release = dir.path().join("continue");
        let key_use = dir.path().join("key-used");
        let mut signer = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "participant_signer::tests::service_child",
                    "--nocapture",
                ])
                .env("MORPH_SIGNER_TEST_CONFIG", &config)
                .env("MORPH_SIGNER_TEST_KEY_FILE", &key)
                .env("MORPH_FAULT_STAGE", "reviewed")
                .env("MORPH_FAULT_MARKER", &marker)
                .env("MORPH_FAULT_RELEASE", &release)
                .env("MORPH_FAULT_KEY_USE", &key_use)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_file(&socket);
        let copy = socket.clone();
        let caller = std::thread::spawn(move || {
            morph_signer::ipc::exchange(&copy, &request, Duration::from_secs(10))
        });
        wait_file(&marker);
        // A new peer receipt is a legitimate forward journal change; never restore
        // an old snapshot or clear the local reservation to simulate the race.
        let peer = run(
            &paths[1],
            FundingSessionCommand::SignLocal {
                target,
                private_key: keys[1].clone().into(),
            },
        )
        .unwrap();
        let peer_file = dir.path().join("peer-receipt.json");
        std::fs::write(&peer_file, serde_json::to_vec(&peer).unwrap()).unwrap();
        run(
            &paths[0],
            FundingSessionCommand::AddSignature {
                target,
                signature: peer_file,
            },
        )
        .unwrap();
        let advanced = read(&paths[0]).unwrap();
        std::fs::write(&release, b"continue").unwrap();
        assert!(caller.join().unwrap().is_err());
        assert!(!signer.0.wait().unwrap().success());
        assert!(!key_use.exists());
        assert_eq!(read(&paths[0]).unwrap(), advanced);
        let mut signer = start(&config, &key, &socket);
        run(
            &paths[0],
            FundingSessionCommand::Sign {
                target,
                signer_config: config,
            },
        )
        .unwrap();
        assert!(signer.0.wait().unwrap().success());
        let final_journal: FundingJournal =
            serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
        assert!(final_journal.reserved(target));
        assert_eq!(final_journal.signatures(target).len(), 2);
    }
}

#[test]
fn malformed_oversized_and_cross_role_replies_leave_real_host_reservations_recoverable() {
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    use morph_packages::signer_protocol::{MAX_RESPONSE_BYTES, Request, Response, Target, VERSION};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    for target in [FundingTarget::Exit, FundingTarget::Creation] {
        for bad in ["malformed", "oversized", "cross-role"] {
            let (dir, paths, keys, rpc, recovery) = setup();
            if matches!(target, FundingTarget::Creation) {
                collect(&paths, &keys, dir.path(), FundingTarget::Exit);
            }
            let (config, socket, key_file) =
                configuration(dir.path(), &paths[0], &rpc.url, &recovery, &[1; 32]);
            let listener = UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let peer = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline);
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut prefix = [0; 4];
                stream.read_exact(&mut prefix).unwrap();
                let size = u32::from_be_bytes(prefix) as usize;
                assert!(size <= morph_packages::signer_protocol::MAX_REQUEST_BYTES);
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).unwrap();
                let request = Request::decode(&bytes).unwrap();
                let mut end = [0];
                assert_eq!(stream.read(&mut end).unwrap(), 0);
                if bad == "oversized" {
                    stream
                        .write_all(&((MAX_RESPONSE_BYTES + 1) as u32).to_be_bytes())
                        .unwrap();
                    return;
                }
                let bytes = if bad == "malformed" {
                    b"{not-json".to_vec()
                } else {
                    let key = SigningKey::from_slice(&[1; 32]).unwrap();
                    let digest = decode_hex(&request.review.signing_digest, 32).unwrap();
                    let signature: Signature = key.sign_prehash(&digest).unwrap();
                    let receipt = SignatureMessage::new(
                        &digest.try_into().unwrap(),
                        &ParticipantSignature {
                            pubkey_sec1: key
                                .verifying_key()
                                .to_sec1_point(true)
                                .as_bytes()
                                .to_vec(),
                            signature: signature.to_bytes().to_vec(),
                        },
                    );
                    serde_json::to_vec(&Response {
                        version: VERSION.into(),
                        request_id: request.request_id,
                        target: if matches!(request.review.target, Target::RootExit) {
                            Target::RootCreation
                        } else {
                            Target::RootExit
                        },
                        receipt,
                    })
                    .unwrap()
                };
                stream
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&bytes).unwrap();
            });
            let mut host = ChildGuard(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "multi_asset_funding_session::tests::fault_tests::host_child",
                        "--nocapture",
                    ])
                    .env("MORPH_FAULT_HOST_JOURNAL", &paths[0])
                    .env("MORPH_FAULT_HOST_CONFIG", &config)
                    .env(
                        "MORPH_FAULT_HOST_TARGET",
                        if matches!(target, FundingTarget::Creation) {
                            "creation"
                        } else {
                            "exit"
                        },
                    )
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            assert!(!host.0.wait().unwrap().success());
            peer.join().unwrap();
            std::fs::remove_file(&socket).unwrap();
            let journal: FundingJournal =
                serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
            assert!(journal.reserved(target));
            assert!(journal.signatures(target).is_empty());
            let mut service = start(&config, &key_file, &socket);
            run(
                &paths[0],
                FundingSessionCommand::Sign {
                    target,
                    signer_config: config,
                },
            )
            .unwrap();
            assert!(service.0.wait().unwrap().success());
            let current: FundingJournal =
                serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
            assert!(current.reserved(target));
            assert_eq!(current.signatures(target).len(), 1);
        }
    }
}

#[test]
fn actual_write_sync_rename_and_directory_failures_keep_root_roles_recoverable() {
    use std::os::unix::net::UnixListener;
    let build = tempfile::tempdir().unwrap();
    let library = build.path().join("root-io.so");
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
    for target in [FundingTarget::Exit, FundingTarget::Creation] {
        for ordinal in [1, 2] {
            for mode in ["write", "sync", "rename", "directory"] {
                let (dir, paths, keys, rpc, recovery) = setup();
                if matches!(target, FundingTarget::Creation) {
                    collect(&paths, &keys, dir.path(), FundingTarget::Exit);
                }
                let (config, socket, key) =
                    configuration(dir.path(), &paths[0], &rpc.url, &recovery, &[1; 32]);
                let before = read(&paths[0]).unwrap();
                let listener = if ordinal == 1 {
                    let l = UnixListener::bind(&socket).unwrap();
                    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
                    l.set_nonblocking(true).unwrap();
                    Some(l)
                } else {
                    None
                };
                let mut signer = if ordinal == 2 {
                    Some(start(&config, &key, &socket))
                } else {
                    None
                };
                let hit = dir.path().join("io-hit");
                let mut host = ChildGuard(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "multi_asset_funding_session::tests::fault_tests::host_child",
                            "--nocapture",
                        ])
                        .env("MORPH_FAULT_HOST_JOURNAL", &paths[0])
                        .env("MORPH_FAULT_HOST_CONFIG", &config)
                        .env(
                            "MORPH_FAULT_HOST_TARGET",
                            if matches!(target, FundingTarget::Creation) {
                                "creation"
                            } else {
                                "exit"
                            },
                        )
                        .env("LD_PRELOAD", &library)
                        .env("MORPH_IO_MODE", mode)
                        .env("MORPH_IO_ORDINAL", ordinal.to_string())
                        .env("MORPH_IO_TMP_PREFIX", dir.path().join(".alice.json."))
                        .env("MORPH_IO_PARENT", dir.path())
                        .env("MORPH_IO_HIT", &hit)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                assert!(!host.0.wait().unwrap().success());
                assert!(hit.exists(), "syscall injection did not fire");
                if let Some(l) = listener {
                    assert_eq!(
                        l.accept().unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    drop(l);
                    fs::remove_file(&socket).unwrap();
                }
                if let Some(signer) = &mut signer {
                    assert!(signer.0.wait().unwrap().success());
                }
                let saved: FundingJournal =
                    serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
                let recorded = ordinal == 2 && mode == "directory";
                assert_eq!(saved.signatures(target).len(), usize::from(recorded));
                assert_eq!(saved.reserved(target), ordinal == 2 || mode == "directory");
                if ordinal == 1 && mode != "directory" {
                    assert_eq!(read(&paths[0]).unwrap(), before);
                }
                let mut retry = if recorded {
                    None
                } else {
                    Some(start(&config, &key, &socket))
                };
                let receipt =
                    fresh_host(&paths[0], target, &config, &dir.path().join("retry.json"));
                if let Some(signer) = &mut retry {
                    assert!(signer.0.wait().unwrap().success());
                }
                let final_journal: FundingJournal =
                    serde_json::from_slice(&read(&paths[0]).unwrap()).unwrap();
                assert!(final_journal.reserved(target));
                assert_eq!(final_journal.signatures(target).len(), 1);
                assert_eq!(
                    receipt["signing_digest"],
                    canonical_hex(&saved.digest(target).unwrap())
                );
            }
        }
    }
}
