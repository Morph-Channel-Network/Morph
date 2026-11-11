#![cfg(target_os = "linux")]
use std::{fs, process::Command};
#[test]
fn real_campaign_records_corpus_counts_and_replays_retained_input() {
    let temp = tempfile::tempdir().unwrap();
    let out = temp.path().join("smoke");
    let exe = env!("CARGO_BIN_EXE_morph-fuzz");
    assert!(
        Command::new(exe)
            .args(["--output"])
            .arg(&out)
            .args(["--cases", "20", "--seconds", "10"])
            .status()
            .unwrap()
            .success()
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "pass");
    let targets = report["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 26);
    for row in targets {
        assert_eq!(row["cases"], 20);
        assert!(row["accepted"].as_u64().unwrap() > 0);
        assert!(row["rejected"].as_u64().unwrap() > 0);
        let name = row["target"].as_str().unwrap();
        assert!(
            Command::new(exe)
                .args(["--worker", name, "--output"])
                .arg(&out)
                .arg("--replay")
                .arg(out.join(name).join("current.bin"))
                .status()
                .unwrap()
                .success()
        );
    }
    assert!(
        !Command::new(exe)
            .arg("--output")
            .arg(&out)
            .status()
            .unwrap()
            .success()
    );
}
#[test]
fn real_worker_deadlines_fail_campaign_and_retain_last_attempt() {
    let temp = tempfile::tempdir().unwrap();
    let out = temp.path().join("timeout");
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_morph-fuzz"))
            .arg("--output")
            .arg(&out)
            .args(["--cases", "1000000", "--seconds", "1"])
            .status()
            .unwrap()
            .success()
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "fail");
    for row in report["targets"].as_array().unwrap() {
        assert_eq!(row["status"], "fail");
        let dir = out.join(row["target"].as_str().unwrap());
        assert!(dir.join("current.bin").exists());
        assert!(dir.join("current.json").exists());
    }
}
