//! Actual CLI/key-process liveness, policy and busy-queue observations. No chain,
//! journal or signing request is needed to observe the explicitly limited scope.
#![cfg(target_os = "linux")]
use ckb_types::prelude::*;
use k256::ecdsa::SigningKey;
use morph_packages::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn private(path: &Path, body: &[u8]) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn start(config: &Path, key: &Path, socket: &Path) -> Process {
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_morph-cli"))
            .arg("participant-signer-serve")
            .arg("--config")
            .arg(config)
            .arg("--private-key-file")
            .arg(key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let begun = Instant::now();
    while !socket.exists() {
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(begun.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    process
}
fn probe(config: &Path, metrics: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_morph-cli"));
    command
        .arg("participant-signer-readiness")
        .arg("--config")
        .arg(config);
    if metrics {
        command.arg("--metrics");
    }
    command.output().unwrap()
}
fn parsed(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn live_cli_rejects_busy_changed_policy_and_killed_process_then_recovers() {
    let root = std::env::temp_dir().join(format!("morph-key-live-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let _files = Files(root.clone());
    let fixture: StoredMultiAssetPackage = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol/multi-asset.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let package = fixture.recovery().unwrap();
    let identity = |bytes: &[u8]| {
        let script = ckb_types::packed::Script::from_slice(bytes).unwrap();
        json!({"code_hash":canonical_hex(script.code_hash().as_slice()), "hash_type":u8::from(script.hash_type())})
    };
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let config = root.join("signer.json");
    let key_file = root.join("key");
    let socket = root.join("signer.sock");
    let journal = root.join("absent-journal");
    let mut settings = json!({
        "schema":"morph.participant_signer_config.v1", "socket":socket, "journal":journal,
        "rpc_url":"http://127.0.0.1:1",
        "expected_pubkey":canonical_hex(key.verifying_key().to_sec1_point(true).as_bytes()),
        "network_genesis":canonical_hex(&package.state.header.chain_id),
        "chain_id":canonical_hex(&package.state.header.chain_id),
        "channel_id":canonical_hex(&package.state.header.channel_id),
        "deployments":[{"state_type":identity(&package.scripts.state_type),"state_lock":identity(&package.scripts.state_lock),"vault_lock":identity(&package.scripts.vault_lock)}],
        "targets":["update"]
    });
    private(&config, &serde_json::to_vec(&settings).unwrap());
    private(&key_file, hex::encode([1; 32]).as_bytes());
    let mut service = start(&config, &key_file, &socket);
    let ready = probe(&config, false);
    assert!(ready.status.success());
    assert_eq!(parsed(&ready)["policy_ready"], true);
    assert_eq!(parsed(&ready)["scope"], "key_process_policy");
    let metrics = probe(&config, true);
    assert!(metrics.status.success());
    let metrics = String::from_utf8(metrics.stdout).unwrap();
    assert_eq!(
        metrics
            .lines()
            .filter(|line| !line.starts_with('#'))
            .count(),
        2
    );
    assert!(metrics.contains("morph_signer_policy_ready 1"));

    // Occupy the real single-reader socket with an incomplete frame. Readiness
    // must time out without a separate healthy heartbeat hiding this queue.
    let mut stalled = UnixStream::connect(&socket).unwrap();
    stalled.write_all(&100u32.to_be_bytes()).unwrap();
    let began = Instant::now();
    let busy = probe(&config, false);
    assert!(!busy.status.success());
    assert_eq!(parsed(&busy)["policy_ready"], false);
    assert!(began.elapsed() < Duration::from_secs(5));
    drop(stalled);
    assert!(probe(&config, false).status.success());

    settings["targets"] = json!(["update", "cooperative_close"]);
    private(&config, &serde_json::to_vec(&settings).unwrap());
    let changed = probe(&config, false);
    assert!(!changed.status.success());
    assert_eq!(parsed(&changed)["responsive"], true);
    assert_eq!(parsed(&changed)["reason"], "policy_denied");
    service.0.kill().unwrap();
    service.0.wait().unwrap();
    let killed = probe(&config, false);
    assert!(!killed.status.success());
    assert_eq!(parsed(&killed)["responsive"], false);
    let metrics = probe(&config, true);
    assert!(metrics.status.success());
    assert!(
        String::from_utf8(metrics.stdout)
            .unwrap()
            .contains("morph_signer_policy_ready 0")
    );
    // The process is confirmed stopped; only its owned socket is removed.
    fs::remove_file(&socket).unwrap();
    let _restarted = start(&config, &key_file, &socket);
    assert!(probe(&config, false).status.success());
    assert!(!journal.exists());
    assert!(!journal.with_extension("lock").exists());
    for output in [&ready, &busy, &changed, &killed] {
        let public = String::from_utf8_lossy(&output.stdout);
        assert!(!public.contains(root.to_str().unwrap()));
        assert!(!public.contains("receipt"));
        assert!(!public.contains("expected_pubkey"));
    }
}
