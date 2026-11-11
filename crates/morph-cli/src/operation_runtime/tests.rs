mod model;
mod records;

use super::*;
use crate::admission_channel::tests::MockRpc;
use ckb_types::{
    bytes::Bytes,
    core::{BlockBuilder, TransactionBuilder},
};
use serde_json::json;

pub(super) fn fixture() -> (tempfile::TempDir, MockRpc, Spec) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let rpc = MockRpc::start([7; 32], 10);
    let point = packed::OutPoint::new([8; 32].pack(), 0);
    let output = packed::CellOutput::new_builder()
        .capacity(100_000_000_000u64)
        .build();
    rpc.set_live_cell(&point, &output);
    let tx = TransactionBuilder::default()
        .input(packed::CellInput::new(point, 0))
        .output(output)
        .output_data(Bytes::new().pack())
        .witness(Bytes::from(vec![1]))
        .build();
    let spec = Spec {
        kind: Kind::CooperativeClose,
        genesis: hex::encode([7; 32]),
        rpc_url: rpc.url.clone(),
        context_id: hex::encode([9; 32]),
        evidence_digest: hex::encode([10; 32]),
        transaction_hex: hex::encode(tx.data().as_slice()),
        required_depth: 4,
        replaces: None,
    };
    (dir, rpc, spec)
}
pub(super) fn preflight(spec: &Spec) -> Preflight {
    Preflight {
        fee: 100,
        estimated_cycles: 100,
        tx_size_bytes: spec.transaction().unwrap().as_slice().len(),
    }
}
pub(super) fn committed(rpc: &MockRpc, spec: &Spec) {
    let tx = spec.transaction().unwrap().into_view();
    let block = BlockBuilder::default()
        .number(10u64)
        .epoch(ckb_types::core::EpochNumberWithFraction::new(1, 0, 100).full_value())
        .transaction(tx.clone())
        .build();
    let view: ckb_jsonrpc_types::BlockView = block.clone().into();
    rpc.respond(
        "get_block_by_number",
        json!(["0xa", "0x2", false]),
        serde_json::to_value(view).unwrap(),
    );
    rpc.respond("get_transaction",json!([format!("{:#x}",H256::from(tx.hash())),"0x2",null]),json!({"transaction":null,"tx_status":{"status":"committed","block_hash":format!("{:#x}",H256::from(block.hash())),"block_number":"0xa","tx_index":"0x0","reason":null}}));
}
#[test]
fn duplicate_registration_conflict_and_nonblocking_owner() {
    let (dir, _rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    let revision = tracker.store.revision().unwrap();
    tracker.register(preflight(&spec)).unwrap();
    assert_eq!(tracker.store.revision().unwrap(), revision);
    assert!(Tracker::open(&path, spec.clone()).is_err());
    drop(tracker);
    let mut other = spec.clone();
    other.evidence_digest = hex::encode([11; 32]);
    assert!(Tracker::open(&path, other).is_err());
    let tracker = Tracker::open(&path, spec).unwrap();
    assert!(tracker.exists());
}
#[test]
fn unknown_reply_is_durable_and_restart_needs_fresh_observation() {
    let (dir, _rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    assert!(tracker.broadcast().is_err());
    assert_eq!(tracker.reconcile().unwrap().status, Status::Unknown);
    assert_eq!(tracker.broadcast().unwrap().status, Status::Unknown);
    assert_eq!(tracker.report().unwrap().broadcasts, 1);
    drop(tracker);
    let mut tracker = Tracker::open(&path, spec).unwrap();
    assert!(tracker.broadcast().is_err());
    assert_eq!(tracker.reconcile().unwrap().status, Status::Unknown);
    assert!(tracker.broadcast().is_err()); // retry cadence, not a new authorization
}
#[test]
fn canonical_depth_orphan_and_spent_input_never_trust_old_success() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    committed(&rpc, &spec);
    assert!(matches!(
        tracker.reconcile().unwrap().status,
        Status::Committed { depth: 1, .. }
    ));
    rpc.set_tip(13);
    assert!(matches!(
        tracker.reconcile().unwrap().status,
        Status::Finalised { depth: 4, .. }
    ));
    drop(tracker);
    let tx = spec.transaction().unwrap();
    rpc.respond("get_transaction",json!([format!("{:#x}",H256::from(tx.calc_tx_hash())),"0x2",null]),json!({"transaction":null,"tx_status":{"status":"unknown","block_hash":null,"block_number":null,"tx_index":null,"reason":null}}));
    let mut tracker = Tracker::open(&path, spec).unwrap();
    assert_eq!(tracker.reconcile().unwrap().status, Status::Reorged);
    let point: ckb_jsonrpc_types::OutPoint =
        tx.raw().inputs().get(0).unwrap().previous_output().into();
    rpc.respond(
        "get_live_cell",
        json!([point, false, false]),
        json!({"status":"dead","cell":null}),
    );
    assert_eq!(tracker.reconcile().unwrap().status, Status::OperatorAction);
    assert!(tracker.broadcast().is_err());
}
#[test]
fn forged_inclusion_and_changed_network_invalidate_cached_success() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    committed(&rpc, &spec);
    rpc.set_tip(13);
    assert_eq!(tracker.reconcile().unwrap().canonical_confirmations, 4);
    rpc.respond(
        "get_block_by_number",
        json!(["0xa", "0x2", false]),
        json!(null),
    );
    assert_eq!(tracker.reconcile().unwrap().status, Status::RpcUnavailable);
    assert_eq!(tracker.report().unwrap().canonical_confirmations, 0);
    committed(&rpc, &spec);
    rpc.respond(
        "get_block_hash",
        json!(["0x0"]),
        json!(format!("0x{}", hex::encode([99; 32]))),
    );
    assert_eq!(tracker.reconcile().unwrap().status, Status::RpcUnavailable);
    assert!(tracker.broadcast().is_err());
}
#[test]
fn lost_send_response_can_reconcile_canonical_success_without_second_send() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    tracker.reconcile().unwrap();
    // The controlled peer rejects send_transaction, yet an independent observed
    // canonical inclusion exists. Returned RPC text is never the success predicate.
    committed(&rpc, &spec);
    rpc.set_tip(13);
    let report = tracker.broadcast().unwrap();
    assert_eq!(report.canonical_confirmations, 4);
    assert_eq!(report.broadcasts, 1);
    assert!(tracker.broadcast().is_err());
}

#[test]
fn broadcast_child() {
    let Some(path) = std::env::var_os("MORPH_OPERATION_TEST_STORE") else {
        return;
    };
    let spec: Spec = serde_json::from_slice(
        &std::fs::read(std::env::var_os("MORPH_OPERATION_TEST_SPEC").unwrap()).unwrap(),
    )
    .unwrap();
    let mut tracker = Tracker::open(Path::new(&path), spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    tracker.reconcile().unwrap();
    tracker.broadcast().unwrap();
}

#[test]
fn killed_broadcaster_retains_exact_intent_and_restart_reconciles_instead_of_resending() {
    use std::process::{Command, Stdio};
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let spec_path = dir.path().join("spec.json");
    std::fs::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
    let marker = dir.path().join("checkpoint");
    let release = dir.path().join("release");
    let mut child = crate::participant_signer::tests::ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "operation_runtime::tests::broadcast_child",
                "--nocapture",
            ])
            .env("MORPH_OPERATION_TEST_STORE", &path)
            .env("MORPH_OPERATION_TEST_SPEC", &spec_path)
            .env("MORPH_FAULT_STAGE", "operation_broadcast_intent")
            .env("MORPH_FAULT_MARKER", &marker)
            .env("MORPH_FAULT_RELEASE", &release)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = std::time::Instant::now();
    while !marker.exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(5));
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    assert_eq!(tracker.report().unwrap().status, Status::BroadcastUnknown);
    assert_eq!(tracker.report().unwrap().broadcasts, 1);
    assert_eq!(
        tracker.record.as_ref().unwrap().spec.transaction_hex,
        spec.transaction_hex
    );
    assert!(tracker.broadcast().is_err());
    let page = morph_events::event_page(
        &tracker.store,
        &morph_events::EventPageRequest {
            after: None,
            limit: 64,
        },
    )
    .unwrap();
    assert!(
        page.events
            .iter()
            .any(|event| event.kind == morph_events::Kind::OperationBroadcastIntent)
    );
    assert_eq!(page.events.len() as u64, tracker.store.revision().unwrap());
    committed(&rpc, &spec);
    rpc.set_tip(13);
    let recovered = tracker.reconcile().unwrap();
    assert_eq!(recovered.canonical_confirmations, 4);
    assert_eq!(recovered.broadcasts, 1);
}

#[test]
fn offline_export_keeps_bytes_and_revision_without_reporting_cached_success() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    committed(&rpc, &spec);
    rpc.set_tip(13);
    tracker.reconcile().unwrap();
    let revision = tracker.store.revision().unwrap();
    let id = spec.id().unwrap();
    drop(tracker);
    drop(rpc);
    let output = dir.path().join("recovered.tx");
    let result = export(&path, &id, &output).unwrap();
    assert_eq!(result["canonical_confirmation_checked"], false);
    assert!(result.get("status").is_none());
    assert_eq!(
        std::fs::read(&output).unwrap(),
        spec.transaction().unwrap().as_slice()
    );
    assert_eq!(export(&path, &id, &output).unwrap(), result);
    let other = dir.path().join("conflict.tx");
    std::fs::write(&other, b"retained evidence").unwrap();
    assert!(export(&path, &id, &other).is_err());
    assert_eq!(std::fs::read(&other).unwrap(), b"retained evidence");
    let tracker = Tracker::open(&path, spec).unwrap();
    assert_eq!(tracker.store.revision().unwrap(), revision);
    assert_eq!(tracker.report().unwrap().broadcasts, 0);
}

#[test]
fn typed_outbox_is_atomic_redacted_and_deduplicates_same_observation() {
    let (dir, _rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    tracker.reconcile().unwrap();
    let revision = tracker.store.revision().unwrap();
    tracker.reconcile().unwrap();
    assert_eq!(revision, tracker.store.revision().unwrap());
    let request = morph_events::EventPageRequest {
        after: None,
        limit: 64,
    };
    let page = morph_events::event_page(&tracker.store, &request).unwrap();
    assert!(page.valid_for(&request));
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].kind, morph_events::Kind::OperationRegistered);
    assert_eq!(page.events[1].kind, morph_events::Kind::OperationObserved);
    for event in page.events {
        assert_eq!(
            event.subject_id.as_deref(),
            Some(spec.id().unwrap().as_str())
        );
        assert_eq!(event.component, morph_events::Component::Operation);
        assert_eq!(
            event.evidence_level,
            morph_events::EvidenceLevel::LocalRecord
        );
        let text = String::from_utf8(event.encode().unwrap()).unwrap();
        assert!(!text.contains(&spec.transaction_hex));
        assert!(!text.contains(&spec.rpc_url));
        assert!(!text.contains(path.to_str().unwrap()));
    }
}

#[test]
fn independent_depth_waiters_do_not_change_policy_or_duplicate_observation_history() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
    tracker.register(preflight(&spec)).unwrap();
    committed(&rpc, &spec);
    rpc.set_tip(13);
    tracker.reconcile().unwrap();
    let revision = tracker.store.revision().unwrap();
    let id = spec.id().unwrap();
    drop(tracker);
    let first = status(&path, &id, 1, 0).unwrap();
    let second = status(&path, &id, 8, 0).unwrap();
    assert_eq!(first["depth_reached"], true);
    assert_eq!(second["depth_reached"], false);
    assert_eq!(second["operation"]["required_depth"], 4);
    let tracker = Tracker::open(&path, spec).unwrap();
    assert_eq!(tracker.store.revision().unwrap(), revision);
    assert_eq!(tracker.report().unwrap().broadcasts, 0);
}

#[test]
fn pending_proposed_and_rejected_restart_without_becoming_success_or_broadcast_permission() {
    for state in ["pending", "proposed", "rejected"] {
        let (dir, rpc, spec) = fixture();
        let path = dir.path().join("operations.db");
        let tx = spec.transaction().unwrap();
        rpc.respond("get_transaction",json!([format!("{:#x}",H256::from(tx.calc_tx_hash())),"0x2",null]),json!({"transaction":null,"tx_status":{"status":state,"block_hash":null,"block_number":null,"tx_index":null,"reason":null}}));
        let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
        tracker.register(preflight(&spec)).unwrap();
        let report = tracker.reconcile().unwrap();
        assert_eq!(report.canonical_confirmations, 0);
        assert!(tracker.broadcast().is_err());
        drop(tracker);
        let mut tracker = Tracker::open(&path, spec).unwrap();
        let again = tracker.reconcile().unwrap();
        assert_eq!(report.status, again.status);
        assert_eq!(again.broadcasts, 0);
        assert!(tracker.broadcast().is_err());
    }
}

fn replacement(prior: &Spec, fee: u64) -> Spec {
    let mut spec = prior.clone();
    let tx = prior.transaction().unwrap();
    let output = tx
        .raw()
        .outputs()
        .get(0)
        .unwrap()
        .as_builder()
        .capacity(100_000_000_000u64 - fee)
        .build();
    let raw = tx.raw().as_builder().outputs(vec![output]).build();
    spec.transaction_hex = hex::encode(tx.as_builder().raw(raw).build().as_slice());
    spec.replaces = Some(prior.id().unwrap());
    spec
}
fn input_dead(rpc: &MockRpc, spec: &Spec) {
    let point: ckb_jsonrpc_types::OutPoint = spec
        .transaction()
        .unwrap()
        .raw()
        .inputs()
        .get(0)
        .unwrap()
        .previous_output()
        .into();
    rpc.respond(
        "get_live_cell",
        json!([point, false, false]),
        json!({"status":"dead","cell":null}),
    );
}
fn absent(rpc: &MockRpc, spec: &Spec) {
    rpc.respond("get_transaction",json!([format!("{:#x}",H256::from(spec.transaction().unwrap().calc_tx_hash())),"0x2",null]),json!({"transaction":null,"tx_status":{"status":"unknown","block_hash":null,"block_number":null,"tx_index":null,"reason":null}}));
}

// The all-features suite forks fault-test children concurrently. A just-dropped
// flock can remain held briefly by an inherited descriptor until child exec.
// Retry only Busy at a sequential reopen, never policy/conflict failures or a
// test which intentionally keeps an owner alive. Production stays nonblocking.
fn reopen_after_drop(path: &Path, spec: &Spec) -> Tracker {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match Tracker::open(path, spec.clone()) {
            Ok(tracker) => return tracker,
            Err(error)
                if error.downcast_ref::<Busy>().is_some()
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("sequential operation reopen failed: {error}"),
        }
    }
}

#[test]
fn replacement_registration_preserves_authority_policy_and_old_approval() {
    let (dir, _rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut prior = Tracker::open(&path, spec.clone()).unwrap();
    prior.register(preflight(&spec)).unwrap();
    let revision = prior.store.revision().unwrap();
    let valid = replacement(&spec, 200);
    let mut variants = Vec::new();
    for field in [
        "context", "genesis", "evidence", "rpc", "depth", "kind", "source", "missing",
    ] {
        let mut bad = valid.clone();
        match field {
            "context" => bad.context_id = "11".repeat(32),
            "genesis" => bad.genesis = "11".repeat(32),
            "evidence" => bad.evidence_digest = "11".repeat(32),
            "rpc" => bad.rpc_url = "http://127.0.0.1:1".into(),
            "depth" => bad.required_depth = 1,
            "kind" => bad.kind = Kind::Splice,
            "missing" => bad.replaces = Some("11".repeat(32)),
            "source" => {
                let tx = bad.transaction().unwrap();
                let input = packed::CellInput::new(packed::OutPoint::new([1; 32].pack(), 0), 0);
                let raw = tx.raw().as_builder().inputs(vec![input]).build();
                bad.transaction_hex = hex::encode(tx.as_builder().raw(raw).build().as_slice());
            }
            _ => unreachable!(),
        }
        variants.push(bad);
    }
    for bad in variants {
        let mut other = reopen_after_drop(&path, &bad);
        assert!(other.register(preflight(&bad)).is_err());
        assert_eq!(other.store.revision().unwrap(), revision);
    }
    let mut next = reopen_after_drop(&path, &valid);
    next.register(preflight(&valid)).unwrap();
    assert_eq!(next.report().unwrap().replaces, Some(spec.id().unwrap()));
    assert_eq!(prior.reconcile().unwrap().status, Status::Unknown);
    assert!(prior.can_broadcast); // declaration alone never revokes the older body
    drop(next);
    let mut omitted = valid;
    omitted.replaces = None;
    assert!(Tracker::open(&path, omitted).is_err());
}

#[test]
fn replacement_winner_requires_canonical_proof_and_reorg_removes_attribution() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut old = Tracker::open(&path, spec.clone()).unwrap();
    old.register(preflight(&spec)).unwrap();
    let next_spec = replacement(&spec, 200);
    let mut next = Tracker::open(&path, next_spec.clone()).unwrap();
    next.register(preflight(&next_spec)).unwrap();
    // A persisted peer projection alone is not winner evidence.
    let mut fake = next.record.clone().unwrap();
    fake.status = Status::Finalised {
        block_hash: "00".repeat(32),
        block_number: 10,
        depth: 4,
    };
    next.persist(fake, next.store.revision().unwrap(), "observe")
        .unwrap();
    input_dead(&rpc, &spec);
    assert_eq!(old.reconcile().unwrap().status, Status::OperatorAction);
    committed(&rpc, &next_spec);
    rpc.set_tip(13);
    let report = old.reconcile().unwrap();
    assert!(
        matches!(report.status, Status::Replaced { ref by_operation_id, depth:4, .. } if *by_operation_id == next_spec.id().unwrap())
    );
    assert_eq!(report.canonical_confirmations, 0);
    assert!(!old.can_broadcast);
    // A fresh canonical-block failure invalidates the previous attribution.
    rpc.respond(
        "get_block_by_number",
        json!(["0xa", "0x2", false]),
        serde_json::Value::Null,
    );
    assert_eq!(old.reconcile().unwrap().status, Status::RpcUnavailable);
    absent(&rpc, &next_spec);
    let tx = spec.transaction().unwrap();
    let point: ckb_jsonrpc_types::OutPoint =
        tx.raw().inputs().get(0).unwrap().previous_output().into();
    let output: ckb_jsonrpc_types::CellOutput = tx.raw().outputs().get(0).unwrap().into();
    rpc.respond(
        "get_live_cell",
        json!([point, false, false]),
        json!({"status":"live","cell":{"output":output,"data":null}}),
    );
    assert_eq!(old.reconcile().unwrap().status, Status::Unknown);
    assert!(old.can_broadcast);
}

#[test]
fn predecessor_can_win_and_descendants_do_not_claim_its_confirmations() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut root = Tracker::open(&path, spec.clone()).unwrap();
    root.register(preflight(&spec)).unwrap();
    let next_spec = replacement(&spec, 200);
    let mut next = Tracker::open(&path, next_spec.clone()).unwrap();
    next.register(preflight(&next_spec)).unwrap();
    let third_spec = replacement(&next_spec, 300);
    let mut third = Tracker::open(&path, third_spec.clone()).unwrap();
    third.register(preflight(&third_spec)).unwrap();
    committed(&rpc, &spec);
    input_dead(&rpc, &spec);
    rpc.set_tip(13);
    let report = third.reconcile().unwrap();
    assert!(
        matches!(report.status, Status::Replaced { ref by_operation_id, depth:4, .. } if *by_operation_id == spec.id().unwrap())
    );
    assert_eq!(report.canonical_confirmations, 0);
    assert_eq!(report.broadcasts, 0);
    assert!(third.broadcast().is_err());
}

#[test]
fn unlinked_same_context_transaction_does_not_become_declared_replacement() {
    let (dir, rpc, spec) = fixture();
    let path = dir.path().join("operations.db");
    let mut original = Tracker::open(&path, spec.clone()).unwrap();
    original.register(preflight(&spec)).unwrap();
    let mut unrelated = replacement(&spec, 200);
    unrelated.replaces = None;
    let mut other = Tracker::open(&path, unrelated.clone()).unwrap();
    other.register(preflight(&unrelated)).unwrap();
    committed(&rpc, &unrelated);
    input_dead(&rpc, &spec);
    assert_eq!(original.reconcile().unwrap().status, Status::OperatorAction);
}
