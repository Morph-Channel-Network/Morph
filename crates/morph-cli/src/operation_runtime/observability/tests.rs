use super::super::tests::{committed, fixture, preflight};
use super::*;
use serde_json::json;

#[test]
fn real_transitions_count_once_survive_restart_and_distinguish_historical_finality() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    let revision = tracker.store.revision().unwrap();
    tracker.register(preflight(&spec)).unwrap();
    assert_eq!(tracker.store.revision().unwrap(), revision);
    tracker.reconcile().unwrap();
    let revision = tracker.store.revision().unwrap();
    tracker.reconcile().unwrap();
    assert_eq!(tracker.store.revision().unwrap(), revision);
    tracker.broadcast().unwrap();
    committed(&rpc, &spec);
    tracker.reconcile().unwrap();
    rpc.set_tip(11);
    tracker.reconcile().unwrap();
    let before = load(&path, now().unwrap()).unwrap();
    assert_eq!(before.counts[6].states[4].entries, 1); // depth change is not a new state entry
    rpc.set_tip(13);
    tracker.reconcile().unwrap();
    let snapshot = load(&path, now().unwrap()).unwrap();
    let c = &snapshot.counts[6];
    assert_eq!(c.records, 1);
    assert_eq!(c.broadcast_intents, 1);
    assert_eq!(c.states[0].entries, 1);
    assert_eq!(c.states[1].entries, 1);
    assert_eq!(c.states[7].entries, 2); // unknown -> broadcast intent -> unknown
    assert_eq!(c.states[5].entries, 1);
    assert_eq!(c.states[5].current_records, 1);
    assert_eq!(c.oldest_unresolved_ms, 0);
    let revision = tracker.store.revision().unwrap();
    // Scraping is read-only and cannot turn the saved result into live evidence.
    let second = load(&path, now().unwrap()).unwrap();
    assert_eq!(second.revision, revision);
    assert_eq!(tracker.store.revision().unwrap(), revision);
    drop(tracker);
    // Concurrent process-spawning tests briefly inherit CLOEXEC lock FDs between
    // fork and exec. The production lock correctly reports busy during that gap.
    // Retry only this classified transient, without relaxing the ownership check.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut tracker = loop {
        match Tracker::open(&path, spec.clone()) {
            Ok(tracker) => break tracker,
            Err(error) if error.downcast_ref::<Busy>().is_some() && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("failed to reopen exact operation: {error}"),
        }
    };
    let before = serde_json::to_value(load(&path, now().unwrap()).unwrap()).unwrap();
    assert_eq!(before["counts"][6]["states"][5]["entries"], "1");
    rpc.respond(
        "get_block_hash",
        json!(["0x0"]),
        json!(format!("0x{}", hex::encode([99; 32]))),
    );
    tracker.reconcile().unwrap();
    let failed = load(&path, now().unwrap()).unwrap();
    assert_eq!(failed.counts[6].states[5].current_records, 0);
    assert_eq!(failed.counts[6].states[5].entries, 1); // historical success retained
    assert_eq!(failed.counts[6].states[11].current_records, 1);
    rpc.respond(
        "get_block_hash",
        json!(["0x0"]),
        json!(format!("0x{}", hex::encode([7; 32]))),
    );
    let tx = spec.transaction().unwrap();
    rpc.respond("get_transaction",json!([format!("{:#x}",H256::from(tx.calc_tx_hash())),"0x2",null]),json!({"transaction":null,"tx_status":{"status":"unknown","block_hash":null,"block_number":null,"tx_index":null,"reason":null}}));
    tracker.reconcile().unwrap();
    let reorg = load(&path, now().unwrap()).unwrap();
    assert_eq!(reorg.counts[6].states[9].current_records, 1);
    assert_eq!(reorg.counts[6].states[9].entries, 1);
    assert_eq!(reorg.counts[6].states[11].entries, 1);
    assert_eq!(reorg.counts[6].states[5].entries, 1);
}

#[test]
fn replacement_registration_counts_approvals_not_winners_and_metrics_are_fixed() {
    let (dir, _rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut first = Tracker::open(&path, spec.clone()).unwrap();
    first.register(preflight(&spec)).unwrap();
    let mut next = spec.clone();
    let tx = spec.transaction().unwrap().into_view();
    let changed = tx
        .as_advanced_builder()
        .output(packed::CellOutput::new_builder().capacity(1u64).build())
        .output_data(ckb_types::bytes::Bytes::new().pack())
        .build();
    next.transaction_hex = hex::encode(changed.data().as_slice());
    next.replaces = Some(spec.id().unwrap());
    let mut second = Tracker::open(&path, next.clone()).unwrap();
    second.register(preflight(&next)).unwrap();
    let snapshot = load(&path, now().unwrap()).unwrap();
    assert_eq!(snapshot.counts[6].records, 2);
    assert_eq!(snapshot.counts[6].replacements_registered, 1);
    assert_eq!(snapshot.counts[6].states[6].entries, 0);
    let mut observation = Observation {
        schema: "morph.operation_observability.v1",
        scope: "saved_operation_history",
        store_available: true,
        checked_at_ms: 1,
        valid_until_ms: 5001,
        snapshot: Some(snapshot),
    };
    let valid = metrics(&observation);
    assert_eq!(valid.lines().filter(|s| !s.starts_with('#')).count(), 225);
    assert!(valid.len() < 64 * 1024);
    for secret in [
        &spec.context_id,
        &spec.evidence_digest,
        &spec.rpc_url,
        &spec.id().unwrap(),
    ] {
        assert!(!valid.contains(secret));
    }
    observation.store_available = false;
    observation.snapshot = None;
    let failed = metrics(&observation);
    assert!(failed.contains("morph_operation_store_available 0"));
    assert_eq!(failed.lines().filter(|s| s.ends_with(" NaN")).count(), 224);
    assert_eq!(
        valid
            .lines()
            .filter(|s| !s.starts_with('#'))
            .map(|s| s.split(' ').next().unwrap())
            .collect::<Vec<_>>(),
        failed
            .lines()
            .filter(|s| !s.starts_with('#'))
            .map(|s| s.split(' ').next().unwrap())
            .collect::<Vec<_>>()
    );
}

#[test]
fn missing_old_schema_missing_counters_invalid_counters_and_clock_future_fail_closed() {
    let (dir, _rpc, spec) = fixture();
    assert!(load(&dir.path().join("missing.db"), now().unwrap()).is_err());
    assert!(!dir.path().join("missing.db").exists());
    for mode in ["schema", "missing", "count", "future", "overflow"] {
        let path = dir.path().join(format!("{mode}.db"));
        let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
        tracker.register(preflight(&spec)).unwrap();
        let saved = tracker
            .store
            .read(Family::Publication, &spec.id().unwrap())
            .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(saved.record.unwrap().body.bytes()).unwrap();
        match mode {
            "schema" => value["schema"] = json!("morph.ckb_operation.v1"),
            "missing" => {
                value.as_object_mut().unwrap().remove("lifecycle");
            }
            "count" => value["lifecycle"]["entries"][1] = json!(1),
            "future" => value["lifecycle"]["entered_ms"] = json!(u64::MAX),
            _ => value["lifecycle"]["entries"][7] = json!(u64::MAX),
        }
        tracker
            .store
            .commit_new(&Commit {
                operation_id: "test-invalid-record".into(),
                expected_revision: saved.revision,
                intent: body(&value).unwrap(),
                writes: vec![Write {
                    family: Family::Publication,
                    id: spec.id().unwrap(),
                    value: Some(body(&value).unwrap()),
                }],
                events: vec![],
                attempts: vec![],
            })
            .unwrap();
        let revision = tracker.store.revision().unwrap();
        assert!(load(&path, now().unwrap()).is_err(), "{mode}");
        assert_eq!(tracker.store.revision().unwrap(), revision);
    }
}

#[test]
fn failed_compare_and_swap_does_not_commit_phantom_transition_counts() {
    let (dir, _rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    let stale_revision = tracker.store.revision().unwrap();
    let mut competitor = spec.clone();
    competitor.context_id = hex::encode([41; 32]);
    let mut other = Tracker::open(&path, competitor.clone()).unwrap();
    other.register(preflight(&competitor)).unwrap();
    let mut change = tracker.record.clone().unwrap();
    change.status = Status::Pending;
    assert!(
        tracker
            .persist(change.clone(), stale_revision, "observe")
            .is_err()
    );
    let snapshot = load(&path, now().unwrap()).unwrap();
    assert_eq!(snapshot.counts[6].states[2].entries, 0);
    assert_eq!(snapshot.counts[6].states[2].current_records, 0);
    tracker
        .persist(change, tracker.store.revision().unwrap(), "observe")
        .unwrap();
    let snapshot = load(&path, now().unwrap()).unwrap();
    assert_eq!(snapshot.counts[6].states[2].entries, 1);
    assert_eq!(snapshot.counts[6].states[2].current_records, 1);
}

#[test]
fn read_only_command_child() {
    let Some(path) = std::env::var_os("MORPH_OPERATION_OBSERVATION_TEST") else {
        return;
    };
    run(
        path.into(),
        std::env::var_os("MORPH_OPERATION_OBSERVATION_METRICS").is_some(),
    )
    .unwrap();
}

#[test]
fn independent_read_only_process_exports_history_without_rpc_or_operation_lock() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    let revision = tracker.store.revision().unwrap();
    drop(rpc);
    // Parent deliberately retains the operation writer lock. A scrape is neither
    // a mutation nor live-chain reconciliation and must not acquire that lock.
    for as_metrics in [false, true] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "operation_runtime::observability::tests::read_only_command_child",
                "--nocapture",
            ])
            .env("MORPH_OPERATION_OBSERVATION_TEST", &path);
        if as_metrics {
            command.env("MORPH_OPERATION_OBSERVATION_METRICS", "1");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        if as_metrics {
            assert_eq!(
                stdout
                    .lines()
                    .filter(|line| line.starts_with("morph_operation_"))
                    .count(),
                225
            );
        } else {
            let report: serde_json::Value =
                serde_json::from_str(stdout.lines().find(|line| line.starts_with('{')).unwrap())
                    .unwrap();
            assert_eq!(report["scope"], "saved_operation_history");
            assert_eq!(report["store_available"], true);
            assert_eq!(report["snapshot"]["counts"][6]["records"], "1");
        }
        assert_eq!(tracker.store.revision().unwrap(), revision);
        assert!(!stdout.contains(&spec.rpc_url));
    }
}
