use super::*;
use std::os::unix::fs::PermissionsExt;
fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn config(dir: &Path) -> Config {
    Config {
        schema: "morph.shadow_service.v1".into(),
        store: dir.join("coordinator.db"),
        chain_rpc_url: "http://127.0.0.1:1".into(),
        contracts_dir: dir.join("contracts"),
        deployment_id: format!("0x{}", "12".repeat(32)),
        min_confirmations: 4,
        provider_rpc_url: "http://127.0.0.1:1".into(),
        callback_endpoint: "http://127.0.0.1:2/callback".into(),
        bearer_token_file: None,
        policy: HookPolicy {
            fiber_commit: "a5faac7177a2a2ec086a2c6d0da1840ec9fe5703".into(),
            patch_hash: format!("0x{}", "13".repeat(32)),
            ckb_genesis_hash: format!("0x{}", "14".repeat(32)),
        },
        sources: vec![Source {
            session: dir.join("session.json"),
            participants: [
                ChannelParticipant {
                    node_id: [1; 32],
                    settlement_lock_hash: [2; 32],
                },
                ChannelParticipant {
                    node_id: [3; 32],
                    settlement_lock_hash: [4; 32],
                },
            ],
            asset: GatewayAsset::Ckb {
                ckb_genesis_hash: [20; 32],
            },
            reservation: None,
        }],
        poll_ms: 100,
        observe_budget_ms: 100,
        reconcile_budget_ms: 100,
        lease_ms: 1000,
    }
}
fn install(dir: &Path) -> (PathBuf, Config, String) {
    let config = config(dir);
    let path = dir.join("config.json");
    write_private_atomic(&path, &serde_json::to_vec(&config).unwrap()).unwrap();
    let (_, digest) = load(&path).unwrap();
    (path, config, digest)
}
#[test]
fn configuration_pins_paths_budgets_and_rejects_implicit_or_remote_credentials() {
    let dir = directory();
    let (path, mut c, _) = install(dir.path());
    c.lease_ms = 300;
    assert!(c.validate(&path).is_err());
    c.lease_ms = 1000;
    c.provider_rpc_url = "http://localhost:1".into();
    assert!(c.validate(&path).is_err());
    c.provider_rpc_url = "https://provider.invalid".into();
    assert!(c.validate(&path).is_err());
    c.bearer_token_file = Some(dir.path().join("token"));
    assert!(c.validate(&path).is_ok());
    c.sources[0].session = c.store.clone();
    assert!(c.validate(&path).is_err());
    let mut value = serde_json::to_value(config(dir.path())).unwrap();
    value.as_object_mut().unwrap().remove("bearer_token_file");
    assert!(serde_json::from_value::<Config>(value).is_err());
}
#[test]
fn protected_provider_token_and_config_never_echo_contents() {
    let dir = directory();
    let mut c = config(dir.path());
    let path = dir.path().join("token");
    c.bearer_token_file = Some(path.clone());
    let secret = "secret-biscuit-token";
    write_private_atomic(&path, secret.as_bytes()).unwrap();
    assert_eq!(token(&c).unwrap().as_deref(), Some(secret));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = token(&c).unwrap_err().to_string();
    assert!(!err.contains(secret));
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    c.bearer_token_file = Some(alias);
    assert!(token(&c).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    c.bearer_token_file = Some(path.clone());
    write_private_atomic(&path, b"secret\nheader-injection").unwrap();
    assert!(token(&c).is_err());
}
#[test]
fn readiness_requires_current_config_store_revision_worker_and_both_clocks() {
    let dir = directory();
    let (path, c, digest) = install(dir.path());
    let local = Coordinator::open(
        &c.store,
        c.policy.clone(),
        &c.provider_rpc_url,
        &c.callback_endpoint,
    )
    .unwrap();
    local.bind_owner(&digest).unwrap();
    let wall = now().unwrap();
    let boot = boot_clock().unwrap();
    let mut h = Health {
        schema: "morph.shadow_service_health.v1".into(),
        config_digest: digest.clone(),
        store_id: hash(&local.identity()),
        revision: local.revision().unwrap(),
        cycle: 1,
        started_at_ms: wall,
        expires_at_ms: wall + 1000,
        boot_id: boot.id.clone(),
        started_boot_ms: boot.ms,
        expires_boot_ms: boot.ms + 1000,
        running: true,
        sources_verified: true,
        provider_reconciled: true,
        acknowledged: 0,
        forwarding: false,
    };
    let health = sidecar(&c.store, ".health.json");
    write_private_atomic(&health, &serde_json::to_vec(&h).unwrap()).unwrap();
    assert!(probe(&c, &digest).ready);
    assert!(!h.fresh(&c, &digest, wall - 1, &boot));
    assert!(!h.fresh(
        &c,
        &digest,
        wall,
        &BootClock {
            id: boot.id.clone(),
            ms: boot.ms + 1000
        }
    ));
    h.running = false;
    write_private_atomic(&health, &serde_json::to_vec(&h).unwrap()).unwrap();
    assert!(!probe(&c, &digest).ready);
    h.running = true;
    h.revision += 1;
    write_private_atomic(&health, &serde_json::to_vec(&h).unwrap()).unwrap();
    assert!(!probe(&c, &digest).ready);
    assert!(!probe(&c, &hash(b"other config")).ready);
    write_private_atomic(&path, b"changed").unwrap();
    assert!(!config_current(&path, &digest));
}
#[tokio::test]
async fn missing_authority_revokes_saved_observation_and_keeps_readiness_false() {
    let dir = directory();
    let (path, c, digest) = install(dir.path());
    let local = Coordinator::open(
        &c.store,
        c.policy.clone(),
        &c.provider_rpc_url,
        &c.callback_endpoint,
    )
    .unwrap();
    local.bind_owner(&digest).unwrap();
    let client = FiberHookClient::new(
        &c.provider_rpc_url,
        None,
        &c.callback_endpoint,
        c.policy.clone(),
    )
    .unwrap();
    let wall = now().unwrap();
    local
        .observe(
            local.revision().unwrap(),
            ObservedBatch {
                observed_at_ms: wall,
                valid_until_ms: wall + 1000,
                edges: vec![],
            },
            wall,
        )
        .unwrap();
    let before = local.revision().unwrap();
    let h = cycle(&c, &path, &digest, &local, &client, 1).await.unwrap();
    assert!(!h.sources_verified && !h.provider_reconciled && !h.forwarding);
    assert!(local.revision().unwrap() > before);
    assert!(!probe(&c, &digest).ready);
    assert!(local.next(&[], now().unwrap()).unwrap().is_none());
}
#[test]
fn real_worker_refuses_second_owner_and_reports_stopped_after_finite_run() {
    // Exercise the actual command loop, protected config and SQLite binding.
    let dir = directory();
    let (path, c, digest) = install(dir.path());
    let lock = try_lock_private_path(&sidecar(&c.store, ".worker"))
        .unwrap()
        .unwrap();
    assert!(
        run(&path, Command::Run { passes: 1 })
            .unwrap_err()
            .to_string()
            .contains("already running")
    );
    drop(lock);
    run(&path, Command::Run { passes: 1 }).unwrap();
    let h: Health = serde_json::from_slice(
        &morph_signer::files::read(&sidecar(&c.store, ".health.json"), 8192).unwrap(),
    )
    .unwrap();
    assert!(!h.running && !h.sources_verified && !h.forwarding);
    assert!(!probe(&c, &digest).ready);
    assert!(run(&path, Command::Readiness).is_err());
}
