use super::*;

#[test]
fn short_lived_observation_rejects_suspend_reboot_clock_rollback_and_late_results() {
    let boot = BootClock {
        id: "boot-a".into(),
        ms: 100,
    };
    let end = BootClock {
        id: "boot-a".into(),
        ms: 110,
    };
    let make = |result, wall, end: Option<&BootClock>, elapsed| {
        report(result, 1_000, wall, Some(&boot), end, elapsed)
    };
    let ready = make(Some(true), 1_010, Some(&end), Duration::from_millis(10));
    assert!(ready.policy_ready && ready.responsive);
    let denied = make(Some(false), 1_010, Some(&end), Duration::from_millis(10));
    assert!(!denied.policy_ready && denied.responsive);
    assert_eq!(denied.reason, Reason::PolicyDenied);
    let unavailable = make(None, 1_010, Some(&end), Duration::from_millis(10));
    assert!(!unavailable.policy_ready && !unavailable.responsive);
    for (wall, after, elapsed) in [
        (999, Some(&end), Duration::from_millis(10)),
        (3_000, Some(&end), Duration::from_millis(10)),
        (1_010, Some(&end), Duration::from_millis(PROBE_MS)),
        (1_010, None, Duration::from_millis(10)),
        (
            1_010,
            Some(&BootClock {
                id: "boot-b".into(),
                ms: 110,
            }),
            Duration::from_millis(10),
        ),
        (
            1_010,
            Some(&BootClock {
                id: "boot-a".into(),
                ms: 99,
            }),
            Duration::from_millis(10),
        ),
        (
            1_010,
            Some(&BootClock {
                id: "boot-a".into(),
                ms: 2_100,
            }),
            Duration::from_millis(10),
        ),
    ] {
        let value = make(Some(true), wall, after, elapsed);
        assert!(!value.policy_ready && !value.responsive);
    }
    let json = serde_json::to_value(&ready).unwrap();
    assert_eq!(json["checked_at_ms"], "1000");
    assert_eq!(json["valid_until_ms"], "3000");
    assert_eq!(json["scope"], "key_process_policy");
    assert!(json.get("channel_signing").is_none());
    let text = metrics(&ready);
    assert_eq!(
        text.lines().filter(|line| !line.starts_with('#')).count(),
        2
    );
    assert!(!text.contains('{'));
}

#[cfg(target_os = "linux")]
#[test]
fn real_key_process_policy_probe_detects_config_change_stop_and_recovery_without_journal() {
    use crate::participant_signer::tests::{configuration, start};
    use std::{fs, os::unix::fs::DirBuilderExt};
    let dir = std::env::temp_dir().join(format!("morph-key-probe-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let fixture: morph_packages::multi_asset_packages::StoredMultiAssetPackage =
        serde_json::from_slice(
            &fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures/protocol/multi-asset.json"),
            )
            .unwrap(),
        )
        .unwrap();
    let journal = dir.join("never-created-journal.json");
    // No real RPC server or journal: a policy probe must access neither.
    let (config, socket, key_file) = configuration(
        &dir,
        &journal,
        "http://127.0.0.1:1",
        &fixture.recovery().unwrap(),
        &[1; 32],
    );
    let original = fs::read(&config).unwrap();
    let mut child = start(&config, &key_file, &socket);
    let healthy = observe(config.clone()).unwrap();
    assert!(healthy.policy_ready && healthy.responsive);
    assert!(child.0.wait().unwrap().success());
    assert!(!journal.exists());
    assert!(!journal.with_extension("json.lock").exists());
    let stopped = observe(config.clone()).unwrap();
    assert!(!stopped.policy_ready && !stopped.responsive);

    let mut child = start(&config, &key_file, &socket);
    let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    changed["targets"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("cooperative_close"));
    crate::persistence::write_private_atomic(&config, &serde_json::to_vec(&changed).unwrap())
        .unwrap();
    let stale_policy = observe(config.clone()).unwrap();
    assert!(stale_policy.responsive && !stale_policy.policy_ready);
    assert_eq!(stale_policy.reason, Reason::PolicyDenied);
    assert!(child.0.wait().unwrap().success());

    // Restart loads the new installed policy; the same independently loaded pin
    // becomes ready again. No timestamp editing or old journal restoration.
    let mut child = start(&config, &key_file, &socket);
    assert!(observe(config.clone()).unwrap().policy_ready);
    assert!(child.0.wait().unwrap().success());
    assert!(!journal.exists());
    let public = serde_json::to_string(&stale_policy).unwrap();
    for private in [
        dir.to_str().unwrap(),
        "expected_pubkey",
        "network_genesis",
        "challenge",
        "receipt",
        "signature",
    ] {
        assert!(!public.contains(private));
    }
}
