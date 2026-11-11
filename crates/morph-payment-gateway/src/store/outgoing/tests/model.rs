//! A bounded independent payment ledger. Unknown results keep their reservation;
//! the first terminal result and the original submission survive every retry.
use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct Model {
    attempts: BTreeMap<u64, Option<Value>>,
    events: Vec<(Kind, Option<String>)>,
    grants: BTreeMap<u64, usize>,
}
impl Model {
    fn reserve(&mut self, store: &DurableStore, tag: u64) {
        match reserve(store, &request(tag)).unwrap() {
            OutgoingReservation::New => {
                assert!(
                    !self.attempts.contains_key(&tag),
                    "a retry regained send authority"
                );
                self.attempts.insert(tag, None);
                *self.grants.entry(tag).or_default() += 1;
                self.events
                    .push((Kind::GatewayOutgoingReserved, Some(format!("{tag:064x}"))));
            }
            OutgoingReservation::Existing(saved) => {
                let expected = self.attempts.get(&tag).expect("unreserved model payment");
                assert_eq!(
                    saved.response.map(|r| serde_json::to_value(r).unwrap()),
                    *expected
                );
            }
        }
    }
    fn finish(&mut self, store: &DurableStore, tag: u64, completed: bool, step: usize) {
        let req = request(tag);
        let proposed = PayResponse {
            completed,
            payment_hash: req.requirements.payment_hash.clone(),
            fiber_result: serde_json::json!({
                "payment_hash":req.requirements.payment_hash,
                "status":if completed { "Success" } else { "Failed" },
                "observation":step,
            }),
        };
        let value = serde_json::to_value(&proposed).unwrap();
        let actual = store.finish_outgoing(&req, PROVIDER, proposed, step as u64 + 2);
        match self.attempts.get_mut(&tag) {
            None => assert!(matches!(actual, Err(StoreError::Conflict))),
            Some(Some(first)) if first["completed"] != completed => {
                assert!(matches!(actual, Err(StoreError::Conflict)));
            }
            Some(Some(first)) => assert_eq!(serde_json::to_value(actual.unwrap()).unwrap(), *first),
            Some(slot @ None) => {
                assert_eq!(serde_json::to_value(actual.unwrap()).unwrap(), value);
                *slot = Some(value);
                self.events.push((
                    if completed {
                        Kind::GatewayOutgoingSucceeded
                    } else {
                        Kind::GatewayOutgoingFailed
                    },
                    Some(format!("{tag:064x}")),
                ));
            }
        }
    }
    fn verify(&self, store: &DurableStore) {
        // No retries, lookups or failures may create additional business commits.
        assert_eq!(store.load().unwrap().0, self.events.len() as u64);
        assert!(self.grants.values().all(|grants| *grants == 1));
        for tag in 1..=8 {
            let req = request(tag);
            match (
                self.attempts.get(&tag),
                store.outgoing(&req, PROVIDER).unwrap(),
            ) {
                (None, None) => {}
                (Some(expected), Some(saved)) => {
                    assert_eq!(
                        saved.response.map(|r| serde_json::to_value(r).unwrap()),
                        *expected
                    );
                    assert_eq!(
                        saved.submission,
                        serde_json::json!({"invoice":req.requirements.invoice})
                    );
                    assert_eq!(saved.timeout_seconds, 2);
                    assert_eq!(saved.created_at, 1);
                }
                _ => panic!("reservation disappeared or was invented"),
            }
        }
        let page = store
            .events(&morph_packages::events::EventPageRequest {
                after: None,
                limit: 64,
            })
            .unwrap();
        let observed: Vec<_> = page
            .events
            .iter()
            .map(|e| (e.kind, e.payment_hash.clone()))
            .collect();
        assert_eq!(observed, self.events);
        let actual: BTreeMap<_, _> = store
            .payments(64)
            .unwrap()
            .into_iter()
            .map(|p| (p.payment_hash, p.status))
            .collect();
        let expected: BTreeMap<_, _> = self
            .attempts
            .iter()
            .map(|(tag, response)| {
                (
                    format!("0x{tag:064x}"),
                    match response {
                        None => "PendingSubmission",
                        Some(v) if v["completed"] == true => "Success",
                        Some(_) => "Failed",
                    }
                    .to_owned(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
        // All original 2-second budgets are expired. An unresolved result must
        // remain visible and reserved; expiration is not a failure or refund.
        let metrics = store.probe_source().observe(1_000_000).unwrap();
        assert_eq!(
            metrics.outgoing_succeeded,
            self.attempts
                .values()
                .filter(|v| v.as_ref().is_some_and(|r| r["completed"] == true))
                .count()
        );
        assert_eq!(
            metrics.outgoing_failed,
            self.attempts
                .values()
                .filter(|v| v.as_ref().is_some_and(|r| r["completed"] == false))
                .count()
        );
        assert_eq!(
            metrics.overdue_unresolved,
            self.attempts.values().filter(|v| v.is_none()).count()
        );
    }
}

#[test]
fn seeded_payment_attempt_model_never_regrants_submission_or_replaces_terminal_evidence() {
    for seed in [1u64, 17, 332_043_276_360] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/model.sqlite");
        let mut store = DurableStore::open(&path, [9; 32]).unwrap();
        let mut model = Model {
            events: vec![(Kind::GatewayInitialized, None)],
            ..Model::default()
        };
        // Keep half initially absent to exercise terminal-before-reservation.
        for tag in 1..=4 {
            model.reserve(&store, tag);
        }
        let mut rng = seed;
        let mut covered = [false; 10];
        for step in 0..160 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let tag = 1 + (rng >> 8) % 8;
            let command = if step < 10 { step } else { (rng % 10) as usize };
            covered[command] = true;
            match command {
                0 | 1 => model.reserve(&store, tag),
                2 | 3 => model.finish(&store, tag, command == 2, step),
                4 => {
                    drop(store);
                    store = DurableStore::open(&path, [9; 32]).unwrap();
                }
                5 => {
                    // Use an existing identity, so a changed request can never
                    // be mistaken for an unrelated, valid new payment.
                    let mut req = request(1);
                    req.max_fee_amount = Some("6".into());
                    assert!(matches!(reserve(&store, &req), Err(StoreError::Conflict)));
                }
                6 => assert!(matches!(
                    store.outgoing(&request(1), "http://127.0.0.1:9999/"),
                    Err(StoreError::Conflict)
                )),
                7 => {
                    let mut req = request(99);
                    req.requirements.requirement_id = request(1).requirements.requirement_id;
                    req.payload.requirement_id = req.requirements.requirement_id.clone();
                    assert!(matches!(reserve(&store, &req), Err(StoreError::Conflict)));
                }
                8 => {
                    // Changed process-local construction parameters cannot
                    // replace the persisted submission or obtain another grant.
                    assert!(matches!(
                        store.reserve_outgoing(
                            &request(1),
                            PROVIDER,
                            serde_json::json!({"invoice":"different local proposal"}),
                            999,
                            999
                        ),
                        Ok(OutgoingReservation::Existing(_))
                    ));
                }
                9 => {
                    let req = request(tag);
                    let invalid = PayResponse {
                        completed: true,
                        payment_hash: req.requirements.payment_hash.clone(),
                        fiber_result: serde_json::json!({"status":"Pending", "payment_hash":req.requirements.payment_hash}),
                    };
                    assert!(matches!(
                        store.finish_outgoing(&req, PROVIDER, invalid, 999),
                        Err(StoreError::Conflict)
                    ));
                }
                _ => unreachable!(),
            }
            model.verify(&store);
        }
        assert!(covered.into_iter().all(|v| v));
        drop(store);
        let store = DurableStore::open(&path, [9; 32]).unwrap();
        // End in an explicit all-reserved state, retry every payment after reopen.
        for tag in 1..=8 {
            model.reserve(&store, tag);
            model.verify(&store);
        }
    }
}
