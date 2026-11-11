//! Combined host/key subprocess faults with explicit canonical RPC responses.
use super::canonical_fixture::{Fixture, setup};
use super::*;
use crate::participant_signer::tests::{ChildGuard, configuration, start};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const TARGETS: [SigningTarget; 4] = [
    SigningTarget::Update,
    SigningTarget::SpliceCreation,
    SigningTarget::SpliceRecovery,
    SigningTarget::SpliceBridge,
];
fn target_name(target: SigningTarget) -> &'static str {
    match target {
        SigningTarget::Update => "update",
        SigningTarget::SpliceCreation => "creation",
        SigningTarget::SpliceRecovery => "recovery",
        SigningTarget::SpliceBridge => "bridge",
    }
}
fn journal(path: &Path) -> StoredSession {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "missing checkpoint {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn host_command(path: &Path, target: SigningTarget, config: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "multi_asset_session::tests::fault_tests::host_child",
            "--nocapture",
        ])
        .env("MORPH_FAULT_HOST_JOURNAL", path)
        .env("MORPH_FAULT_HOST_CONFIG", config)
        .env("MORPH_FAULT_HOST_TARGET", target_name(target))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
#[test]
fn host_child() {
    let Some(path) = std::env::var_os("MORPH_FAULT_HOST_JOURNAL") else {
        return;
    };
    let target = match std::env::var("MORPH_FAULT_HOST_TARGET").unwrap().as_str() {
        "update" => SigningTarget::Update,
        "creation" => SigningTarget::SpliceCreation,
        "recovery" => SigningTarget::SpliceRecovery,
        "bridge" => SigningTarget::SpliceBridge,
        _ => panic!("bad target"),
    };
    // Use the public production run path, including canonical lineage verification.
    let receipt = super::super::run(
        Path::new(&path),
        SessionCommand::Sign {
            target,
            signer_config: PathBuf::from(std::env::var_os("MORPH_FAULT_HOST_CONFIG").unwrap()),
        },
    )
    .unwrap();
    if let Some(output) = std::env::var_os("MORPH_FAULT_HOST_OUTPUT") {
        fs::write(output, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }
}
fn fresh_host(path: &Path, target: SigningTarget, config: &Path, output: &Path) -> Value {
    let mut child = ChildGuard(
        host_command(path, target, config)
            .env("MORPH_FAULT_HOST_OUTPUT", output)
            .spawn()
            .unwrap(),
    );
    assert!(
        child.0.wait().unwrap().success(),
        "host failed for {target:?}"
    );
    serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
}
fn signer_config(f: &Fixture) -> (PathBuf, PathBuf, PathBuf) {
    configuration(
        f.dir.path(),
        &f.paths[0],
        &f.rpc.url,
        &f.package.recovery().unwrap(),
        &[1; 32],
    )
}
#[test]
fn real_host_kill_after_reserve_receipt_and_record_keeps_all_session_roles_monotonic() {
    for target in TARGETS {
        for stage in ["reserved", "received", "recorded"] {
            let f = setup();
            f.prepare(target);
            let (config, socket, key) = signer_config(&f);
            let marker = f.dir.path().join("cut");
            let mut signer = if stage == "reserved" {
                None
            } else {
                Some(start(&config, &key, &socket))
            };
            let mut host = ChildGuard(
                host_command(&f.paths[0], target, &config)
                    .env("MORPH_FAULT_STAGE", stage)
                    .env("MORPH_FAULT_MARKER", &marker)
                    .env("MORPH_FAULT_RELEASE", f.dir.path().join("release"))
                    .spawn()
                    .unwrap(),
            );
            wait_file(&marker);
            host.0.kill().unwrap();
            host.0.wait().unwrap();
            if let Some(signer) = &mut signer {
                assert!(signer.0.wait().unwrap().success());
            }
            let bytes = fs::read(&f.paths[0]).unwrap();
            let current = journal(&f.paths[0]);
            current.reserved_external_payload(target).unwrap();
            assert_eq!(
                target.signatures(&current.backend).len(),
                usize::from(stage == "recorded")
            );
            let expected = canonical_hex(&target.digest(&current.backend).unwrap());
            let mut retry = if stage == "recorded" {
                None
            } else {
                Some(start(&config, &key, &socket))
            };
            let output = f.dir.path().join("output.json");
            let receipt = fresh_host(&f.paths[0], target, &config, &output);
            if let Some(signer) = &mut retry {
                assert!(signer.0.wait().unwrap().success());
            }
            assert_eq!(receipt["signing_digest"], expected);
            let persisted = fs::read(&f.paths[0]).unwrap();
            let current = journal(&f.paths[0]);
            current.reserved_external_payload(target).unwrap();
            assert_eq!(target.signatures(&current.backend).len(), 1);
            assert_eq!(fresh_host(&f.paths[0], target, &config, &output), receipt);
            assert_eq!(fs::read(&f.paths[0]).unwrap(), persisted);
            if stage == "recorded" {
                assert_eq!(persisted, bytes);
            }
        }
    }
}

#[test]
fn authority_advance_after_review_rejects_before_key_use_for_all_session_roles() {
    for target in TARGETS {
        let f = setup();
        f.prepare(target);
        let (config, socket, key) = signer_config(&f);
        let mut current = journal(&f.paths[0]);
        target.reserve(&mut current.backend).unwrap();
        save(&f.paths[0], &current).unwrap();
        let request = crate::participant_signer::tests::request(
            &config,
            target.into(),
            current.reserved_external_payload(target).unwrap(),
        );
        let marker = f.dir.path().join("reviewed");
        let release = f.dir.path().join("continue");
        let key_use = f.dir.path().join("key-used");
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
        // Advance the journal through a valid peer receipt, never by restoring a snapshot.
        let peer = super::super::run(
            &f.paths[1],
            SessionCommand::SignLocal {
                target,
                private_key: hex::encode([2u8; 32]).into(),
            },
        )
        .unwrap();
        let file = f.dir.path().join("peer.json");
        fs::write(&file, serde_json::to_vec(&peer).unwrap()).unwrap();
        super::super::run(
            &f.paths[0],
            SessionCommand::AddSignature {
                target,
                signature: file,
            },
        )
        .unwrap();
        let advanced = fs::read(&f.paths[0]).unwrap();
        fs::write(&release, b"continue").unwrap();
        assert!(caller.join().unwrap().is_err());
        assert!(!signer.0.wait().unwrap().success());
        assert!(!key_use.exists());
        assert_eq!(fs::read(&f.paths[0]).unwrap(), advanced);
        let mut service = start(&config, &key, &socket);
        fresh_host(
            &f.paths[0],
            target,
            &config,
            &f.dir.path().join("output.json"),
        );
        assert!(service.0.wait().unwrap().success());
        let current = journal(&f.paths[0]);
        current.reserved_external_payload(target).unwrap();
        assert_eq!(target.signatures(&current.backend).len(), 2);
    }
}

#[test]
fn malformed_oversized_and_cross_role_replies_preserve_all_session_reservations() {
    use morph_packages::signer_protocol::{MAX_RESPONSE_BYTES, Request, Response, Target, VERSION};
    use std::{
        io::{Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
    };
    for target in TARGETS {
        for bad in ["malformed", "oversized", "cross-role"] {
            let f = setup();
            f.prepare(target);
            let (config, socket, key_file) = signer_config(&f);
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
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
                    let digest = digest(&request.review.signing_digest).unwrap();
                    let signature: Signature = key.sign_prehash(&digest).unwrap();
                    let receipt = SignatureMessage::new(
                        &digest,
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
                        target: if matches!(request.review.target, Target::Update) {
                            Target::SpliceBridge
                        } else {
                            Target::Update
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
            let mut host = ChildGuard(host_command(&f.paths[0], target, &config).spawn().unwrap());
            assert!(!host.0.wait().unwrap().success());
            peer.join().unwrap();
            fs::remove_file(&socket).unwrap();
            let current = journal(&f.paths[0]);
            current.reserved_external_payload(target).unwrap();
            assert!(target.signatures(&current.backend).is_empty());
            let mut signer = start(&config, &key_file, &socket);
            fresh_host(
                &f.paths[0],
                target,
                &config,
                &f.dir.path().join("output.json"),
            );
            assert!(signer.0.wait().unwrap().success());
            let current = journal(&f.paths[0]);
            current.reserved_external_payload(target).unwrap();
            assert_eq!(target.signatures(&current.backend).len(), 1);
        }
    }
}

#[test]
fn actual_write_sync_rename_and_directory_failures_keep_session_roles_recoverable() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let build = tempfile::tempdir().unwrap();
    let library = build.path().join("session-io.so");
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
    for target in TARGETS {
        for ordinal in [1, 2] {
            for mode in ["write", "sync", "rename", "directory"] {
                let f = setup();
                f.prepare(target);
                let (config, socket, key) = signer_config(&f);
                let before = fs::read(&f.paths[0]).unwrap();
                // At the reservation boundary there must be no external call at all.
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
                let hit = f.dir.path().join("io-hit");
                let mut host = ChildGuard(
                    host_command(&f.paths[0], target, &config)
                        .env("LD_PRELOAD", &library)
                        .env("MORPH_IO_MODE", mode)
                        .env("MORPH_IO_ORDINAL", ordinal.to_string())
                        .env("MORPH_IO_TMP_PREFIX", f.dir.path().join(".alice.json."))
                        .env("MORPH_IO_PARENT", f.dir.path())
                        .env("MORPH_IO_HIT", &hit)
                        .spawn()
                        .unwrap(),
                );
                assert!(
                    !host.0.wait().unwrap().success(),
                    "{target:?}/{ordinal}/{mode}"
                );
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
                let saved = journal(&f.paths[0]);
                let recorded = ordinal == 2 && mode == "directory";
                assert_eq!(
                    target.signatures(&saved.backend).len(),
                    usize::from(recorded)
                );
                if ordinal == 1 && mode != "directory" {
                    assert_eq!(fs::read(&f.paths[0]).unwrap(), before);
                    assert!(saved.reserved_external_payload(target).is_err());
                } else {
                    saved.reserved_external_payload(target).unwrap();
                }
                // Directory sync may fail after rename. Read the canonical journal;
                // never restore `before` or use leftover temporary files as authority.
                let mut retry = if recorded {
                    None
                } else {
                    Some(start(&config, &key, &socket))
                };
                let receipt = fresh_host(
                    &f.paths[0],
                    target,
                    &config,
                    &f.dir.path().join("retry.json"),
                );
                if let Some(signer) = &mut retry {
                    assert!(signer.0.wait().unwrap().success());
                }
                let final_journal = journal(&f.paths[0]);
                final_journal.reserved_external_payload(target).unwrap();
                assert_eq!(target.signatures(&final_journal.backend).len(), 1);
                assert_eq!(
                    receipt["signing_digest"],
                    canonical_hex(&target.digest(&saved.backend).unwrap())
                );
            }
        }
    }
}
