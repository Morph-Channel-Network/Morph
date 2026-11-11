//! Real CLI supervisor lifecycle; no canonical chain success is fabricated here.
#![cfg(all(target_os = "linux", feature = "devnet"))]
use morph_observability::{Readiness, Reason, Scope, Service};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn probe(config: &Path, health: &Path, metrics: bool) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_morph-cli"));
    cmd.arg("multi-asset-supervision-readiness")
        .arg("--config")
        .arg(config)
        .arg("--health-file")
        .arg(health);
    if metrics {
        cmd.arg("--metrics");
    }
    cmd.output().unwrap()
}
#[test]
fn real_supervisor_stop_expires_redacted_observation_without_mutating_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    let health = dir.path().join("private/health.json");
    let alerts = dir.path().join("private/alerts.jsonl");
    let missing = dir.path().join("private-authority-marker.json");
    fs::write(&config,serde_json::to_vec(&serde_json::json!({"schema":"morph.multi_asset_supervision.v1","sessions":[missing],"poll_ms":100,"rpc_budget_ms":100,"stale_after_ms":1500})).unwrap()).unwrap();
    let mut worker = Worker(
        Command::new(env!("CARGO_BIN_EXE_morph-cli"))
            .arg("multi-asset-supervise")
            .arg("--config")
            .arg(&config)
            .arg("--health-file")
            .arg(&health)
            .arg("--alert-file")
            .arg(&alerts)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    while !health.exists() {
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "supervisor exited before evidence"
        );
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    let current = probe(&config, &health, false);
    assert!(!current.status.success());
    let report: Readiness = serde_json::from_slice(&current.stdout).unwrap();
    assert!(report.consistent());
    assert_eq!(report.service, Service::SignerSupervisor);
    assert_eq!(report.scopes[0].scope, Scope::AuthoritySupervision);
    assert_eq!(report.scopes[0].checks[0].reason, Reason::Unavailable);
    assert!(!report.scopes[1].configured);
    assert!(!String::from_utf8_lossy(&current.stdout).contains("private-authority-marker"));
    worker.0.kill().unwrap();
    worker.0.wait().unwrap();
    let before = fs::read(&health).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(state["schema"], "morph.multi_asset_supervision_health.v2");
    assert!(state["boot_id"].as_str().unwrap().len() == 36);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = probe(&config, &health, false);
        let report: Readiness = serde_json::from_slice(&result.stdout).unwrap();
        if report.scopes[0].checks[0].reason == Reason::Stale {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
    let result = probe(&config, &health, true);
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert_eq!(
        text.lines()
            .filter(|s| !s.starts_with('#') && !s.is_empty())
            .count(),
        8
    );
    assert_eq!(text.lines().filter(|s| s.ends_with("NaN")).count(), 6);
    assert!(!text.contains("private-authority-marker"));
    assert_eq!(fs::read(&health).unwrap(), before);
}
