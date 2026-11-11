//! Controlled-RPC model of sequential canonical observations. The oracle tracks
//! inclusion history and expected classes independently of observe()/persist().
use super::*;

fn enter(entries: &mut [u64; 12], prior: &mut usize, next: usize) {
    if *prior != next {
        entries[next] += 1;
    }
    *prior = next;
}

#[test]
fn seeded_operation_model_reobserves_finality_and_retains_exact_broadcast_history() {
    for seed in [1u64, 17, 332_043_276_360] {
        let (dir, rpc, spec) = fixture();
        let path = dir.path().join("model.db");
        let tx = spec.transaction().unwrap();
        let hash = format!("{:#x}", H256::from(tx.calc_tx_hash()));
        let input = tx.raw().inputs().get(0).unwrap().previous_output();
        let output = tx.raw().outputs().get(0).unwrap();
        let query = json!([hash, "0x2", null]);
        let absent = |status: &str| {
            json!({"transaction":null,"tx_status":{"status":status,
            "block_hash":null,"block_number":null,"tx_index":null,"reason":null}})
        };
        let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
        tracker.register(preflight(&spec)).unwrap();
        let mut entries = [0u64; 12];
        entries[0] = 1;
        let mut prior = 0;
        rpc.respond("get_transaction", query.clone(), absent("unknown"));
        tracker.reconcile().unwrap();
        enter(&mut entries, &mut prior, 7);
        tracker.broadcast().unwrap(); // Mock peer loses/rejects send response.
        enter(&mut entries, &mut prior, 1);
        enter(&mut entries, &mut prior, 7);
        let mut had_inclusion = false;
        let mut rng = seed;
        for step in 0..64 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let command = if step < 10 { step } else { (rng % 10) as usize };
            if step % 7 == 0 {
                drop(tracker);
                tracker = Tracker::open(&path, spec.clone()).unwrap();
                assert!(
                    tracker.broadcast().is_err(),
                    "restart reused stale broadcast permission"
                );
            }
            rpc.set_tip(10);
            rpc.respond(
                "get_block_hash",
                json!(["0x0"]),
                json!(format!("0x{}", spec.genesis)),
            );
            let point: ckb_jsonrpc_types::OutPoint = input.clone().into();
            rpc.respond("get_live_cell", json!([point, false, false]),
                json!({"status":"live","cell":{"output":ckb_jsonrpc_types::CellOutput::from(output.clone()),"data":null}}));
            rpc.respond("get_transaction", query.clone(), absent("unknown"));
            let (class, confirmations, allowed) = match command {
                0 => (if had_inclusion { 9 } else { 7 }, 0, true),
                1 => {
                    rpc.respond("get_transaction", query.clone(), absent("pending"));
                    (2, 0, false)
                }
                2 => {
                    rpc.respond("get_transaction", query.clone(), absent("proposed"));
                    (3, 0, false)
                }
                3 => {
                    rpc.respond("get_transaction", query.clone(), absent("rejected"));
                    (if had_inclusion { 9 } else { 8 }, 0, had_inclusion)
                }
                4..=6 => {
                    committed(&rpc, &spec);
                    let depth = [1, 4, 9][command - 4];
                    rpc.set_tip(9 + depth);
                    had_inclusion = true;
                    (if depth < 4 { 4 } else { 5 }, depth, false)
                }
                7 => {
                    rpc.respond(
                        "get_block_hash",
                        json!(["0x0"]),
                        json!(format!("0x{}", "ff".repeat(32))),
                    );
                    (11, 0, false)
                }
                8 => {
                    let point: ckb_jsonrpc_types::OutPoint = input.clone().into();
                    rpc.respond(
                        "get_live_cell",
                        json!([point, false, false]),
                        json!({"status":"dead","cell":null}),
                    );
                    (10, 0, false)
                }
                9 => {
                    committed(&rpc, &spec);
                    rpc.set_tip(9);
                    (11, 0, false)
                }
                _ => unreachable!(),
            };
            let report = tracker.reconcile().unwrap();
            let actual_class = match &report.status {
                Status::Ready => 0,
                Status::BroadcastUnknown => 1,
                Status::Pending => 2,
                Status::Proposed => 3,
                Status::Committed { .. } => 4,
                Status::Finalised { .. } => 5,
                Status::Replaced { .. } => 6,
                Status::Unknown => 7,
                Status::Rejected => 8,
                Status::Reorged => 9,
                Status::OperatorAction => 10,
                Status::RpcUnavailable => 11,
            };
            assert_eq!(actual_class, class, "seed={seed} step={step}");
            assert_eq!(report.canonical_confirmations, confirmations);
            assert_eq!(report.broadcasts, 1);
            assert_eq!(tracker.can_broadcast, allowed);
            enter(&mut entries, &mut prior, class);
            let record = tracker.record.as_ref().unwrap();
            assert_eq!(record.spec.transaction_hex, spec.transaction_hex);
            assert_eq!(record.had_inclusion, had_inclusion);
            assert_eq!(
                serde_json::to_value(&record.lifecycle).unwrap()["entries"],
                json!(entries)
            );
            let integrity = tracker.store.validate().unwrap();
            assert_eq!(integrity.records, 1);
            assert_eq!(integrity.intents, integrity.revision);
            assert_eq!(integrity.events, integrity.revision);
            assert_eq!(integrity.attempts, integrity.revision);
            // Polling exactly the same evidence cannot manufacture a transition
            // or another durable outbox/attempt, regardless of elapsed wall time.
            let again = tracker.reconcile().unwrap();
            assert_eq!(again.status, report.status);
            assert_eq!(tracker.store.revision().unwrap(), integrity.revision);
            if !allowed {
                assert!(tracker.broadcast().is_err());
                assert_eq!(tracker.store.revision().unwrap(), integrity.revision);
            }
        }
    }
}
