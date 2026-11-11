//! Non-evicting submission identities. The bounded payment list is a view, not
//! authority to forget a possibly submitted payment and send it again.
use super::*;
use crate::api::{PayRequest, PayResponse};

pub(crate) const MAX_OUTGOING_ATTEMPTS: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutgoingAttempt {
    pub request: Value,
    pub provider: String,
    pub submission: Value,
    pub timeout_seconds: u64,
    pub created_at: u64,
    pub response: Option<PayResponse>,
}

pub(crate) enum OutgoingReservation {
    New,
    Existing(Box<OutgoingAttempt>),
}

fn request_value(request: &PayRequest) -> Result<Value, StoreError> {
    let bytes = Zeroizing::new(serde_json::to_vec(request).map_err(|_| StoreError::Corrupt)?);
    if bytes.len() > MAX_TRACKED_PAYMENT_JSON_BYTES {
        return Err(StoreError::CapacityExceeded);
    }
    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)
}

impl DurableStore {
    /// Authenticate the caller before invoking this lookup. A matching record
    /// permits observation/cached delivery only, never another submission.
    pub(crate) fn outgoing(
        &self,
        request: &PayRequest,
        provider: &str,
    ) -> Result<Option<OutgoingAttempt>, StoreError> {
        let value = request_value(request)?;
        self.read(|state| {
            state
                .outgoing
                .get(&request.requirements.payment_hash)
                .map(|attempt| {
                    if attempt.request != value || attempt.provider != provider {
                        Err(StoreError::Conflict)
                    } else {
                        Ok(attempt.clone())
                    }
                })
                .transpose()
        })?
    }

    /// The sole successful NEW commit is the authority for one send_payment
    /// call. CAS losers or uncertain commits must not send. A restart only polls.
    pub(crate) fn reserve_outgoing(
        &self,
        request: &PayRequest,
        provider: &str,
        submission: Value,
        timeout_seconds: u64,
        now: u64,
    ) -> Result<OutgoingReservation, StoreError> {
        let value = request_value(request)?;
        if serde_json::to_vec(&submission)
            .map_err(|_| StoreError::Corrupt)?
            .len()
            > MAX_TRACKED_PAYMENT_JSON_BYTES
        {
            return Err(StoreError::CapacityExceeded);
        }
        let outcome = self.mutate_new(
            serde_json::json!({"operation":"reserve_outgoing","payment_hash":request.requirements.payment_hash}),
            Change::new(Kind::GatewayOutgoingReserved, Some(&request.requirements.requirement_id), Some(&request.requirements.payment_hash))?,
            |state| {
                if let Some(attempt) = state.outgoing.get(&request.requirements.payment_hash) {
                    return if attempt.request == value && attempt.provider == provider {
                        Ok(OutgoingReservation::Existing(Box::new(attempt.clone())))
                    } else {
                        Err(StoreError::Conflict)
                    };
                }
                if state.outgoing.len() >= MAX_OUTGOING_ATTEMPTS {
                    return Err(StoreError::CapacityExceeded);
                }
                if state.outgoing.values().any(|attempt| {
                    attempt.request.pointer("/requirements/requirement_id").and_then(Value::as_str)
                        == Some(&request.requirements.requirement_id)
                }) {
                    return Err(StoreError::Conflict);
                }
                state.outgoing.insert(request.requirements.payment_hash.clone(), OutgoingAttempt {
                    request: value, provider: provider.into(), submission,
                    timeout_seconds, created_at: now, response: None,
                });
                record_payment_in(state, TrackedPayment {
                    payment_hash: request.requirements.payment_hash.clone(),
                    requirement_id: request.requirements.requirement_id.clone(),
                    direction: PaymentDirection::Outgoing, status: "PendingSubmission".into(),
                    updated_at: now, fiber_result: serde_json::json!({"status":"PendingSubmission"}),
                })?;
                ensure_transient_reserve(state)?;
                Ok(OutgoingReservation::New)
            },
        );
        if matches!(outcome, Err(StoreError::Conflict)) {
            // A second process may have committed the same reservation. Reload
            // it, but do not mistake a cached transaction receipt for NEW.
            if let Some(attempt) = self.outgoing(request, provider)? {
                return Ok(OutgoingReservation::Existing(Box::new(attempt)));
            }
            // A different payment hash cannot reuse a durable requirement ID.
            // Preserve that permanent conflict instead of advertising a retryable
            // CAS race. Only an unrelated concurrent commit is transient Busy.
            return self.read(|state| {
                if state.outgoing.values().any(|attempt| {
                    attempt
                        .request
                        .pointer("/requirements/requirement_id")
                        .and_then(Value::as_str)
                        == Some(&request.requirements.requirement_id)
                }) {
                    Err(StoreError::Conflict)
                } else {
                    Err(StoreError::Busy)
                }
            })?;
        }
        outcome
    }

    pub(crate) fn finish_outgoing(
        &self,
        request: &PayRequest,
        provider: &str,
        response: PayResponse,
        now: u64,
    ) -> Result<PayResponse, StoreError> {
        let value = request_value(request)?;
        let status = response
            .fiber_result
            .get("status")
            .and_then(Value::as_str)
            .ok_or(StoreError::Conflict)?
            .to_owned();
        if response.payment_hash != request.requirements.payment_hash
            || response
                .fiber_result
                .get("payment_hash")
                .and_then(Value::as_str)
                != Some(&response.payment_hash)
            || !matches!(status.as_str(), "Success" | "Failed")
            || response.completed != (status == "Success")
        {
            return Err(StoreError::Conflict);
        }
        self.mutate(
            serde_json::json!({"operation":"finish_outgoing","payment_hash":response.payment_hash}),
            Change::new(
                if response.completed {
                    Kind::GatewayOutgoingSucceeded
                } else {
                    Kind::GatewayOutgoingFailed
                },
                Some(&request.requirements.requirement_id),
                Some(&response.payment_hash),
            )?,
            |state| {
                let attempt = state
                    .outgoing
                    .get_mut(&response.payment_hash)
                    .ok_or(StoreError::Conflict)?;
                if attempt.request != value || attempt.provider != provider {
                    return Err(StoreError::Conflict);
                }
                if let Some(saved) = &attempt.response {
                    // First terminal evidence is immutable; duplicate polling must
                    // neither count twice nor replace it with a later failure.
                    return if saved.completed == response.completed {
                        Ok(saved.clone())
                    } else {
                        Err(StoreError::Conflict)
                    };
                }
                attempt.response = Some(response.clone());
                record_payment_in(
                    state,
                    TrackedPayment {
                        payment_hash: response.payment_hash.clone(),
                        requirement_id: request.requirements.requirement_id.clone(),
                        direction: PaymentDirection::Outgoing,
                        status,
                        updated_at: now,
                        fiber_result: response.fiber_result.clone(),
                    },
                )?;
                ensure_transient_reserve(state)?;
                Ok(response)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    mod model;
    use super::*;
    use crate::protocol::PaymentPayload;
    fn request(tag: u64) -> PayRequest {
        let mut requirements = super::super::tests::challenge().requirement;
        requirements.payment_hash = format!("0x{tag:064x}");
        requirements.requirement_id = format!("0x{:064x}", tag + 1000);
        // Store-only fixture: authorization is exercised by the HTTP tests.
        let payload = PaymentPayload {
            requirement_id: requirements.requirement_id.clone(),
            payment_hash: requirements.payment_hash.clone(),
            payer: requirements.payer.clone(),
            payer_pubkey_sec1: "store-public-key-marker".into(),
            payer_signature: "private-signature-marker".into(),
            payment_preimage: None,
        };
        PayRequest {
            requirements,
            payload,
            timeout_seconds: Some(2),
            max_fee_amount: Some("5".into()),
        }
    }
    fn reserve(
        store: &DurableStore,
        request: &PayRequest,
    ) -> Result<OutgoingReservation, StoreError> {
        store.reserve_outgoing(
            request,
            "http://127.0.0.1:8227/",
            serde_json::json!({"invoice":request.requirements.invoice}),
            2,
            1,
        )
    }
    const PROVIDER: &str = "http://127.0.0.1:8227/";

    #[test]
    fn reused_requirement_with_different_payment_hash_is_conflict_not_retryable_busy() {
        let dir = tempfile::tempdir().unwrap();
        let store = DurableStore::open(dir.path().join("private/store.db"), [9; 32]).unwrap();
        reserve(&store, &request(1)).unwrap();
        let before = store.load().unwrap().0;
        let mut conflicting = request(2);
        conflicting.requirements.requirement_id = request(1).requirements.requirement_id;
        conflicting.payload.requirement_id = conflicting.requirements.requirement_id.clone();
        assert!(matches!(
            reserve(&store, &conflicting),
            Err(StoreError::Conflict)
        ));
        assert_eq!(store.load().unwrap().0, before);
        assert!(store.outgoing(&request(2), PROVIDER).unwrap().is_none());
        assert!(matches!(
            reserve(&store, &request(2)),
            Ok(OutgoingReservation::New)
        ));
    }

    #[test]
    fn competing_store_instances_grant_exactly_one_submission_and_reopen_retains_it() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/store.db");
        let a = DurableStore::open(&path, [7; 32]).unwrap();
        let b = DurableStore::open(&path, [7; 32]).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles = [a, b]
            .into_iter()
            .map(|store| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    reserve(&store, &request(1))
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(OutgoingReservation::New)))
                .count(),
            1
        );
        let reopened = DurableStore::open(&path, [7; 32]).unwrap();
        assert!(matches!(
            reserve(&reopened, &request(1)).unwrap(),
            OutgoingReservation::Existing(_)
        ));
        assert!(
            !std::fs::read(path)
                .unwrap()
                .windows(b"private-signature-marker".len())
                .any(|w| w == b"private-signature-marker")
        );
    }

    #[test]
    fn submission_identity_survives_display_eviction_and_full_ledger_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = DurableStore::open(dir.path().join("private/store.db"), [8; 32]).unwrap();
        reserve(&store, &request(1)).unwrap();
        // Populate bounded views/ledger in one fixture transaction to exercise
        // the capacity edge without hundreds of unrelated fsync test writes.
        store
            .mutate(
                serde_json::json!({"operation":"test_capacity"}),
                Change::initialized(),
                |state| {
                    let template = state.outgoing.values().next().unwrap().clone();
                    for tag in 2..=MAX_OUTGOING_ATTEMPTS as u64 {
                        let req = request(tag);
                        let mut attempt = template.clone();
                        attempt.request = request_value(&req)?;
                        state
                            .outgoing
                            .insert(req.requirements.payment_hash, attempt);
                    }
                    for tag in 2..=MAX_TRACKED_PAYMENTS as u64 + 1 {
                        record_payment_in(
                            state,
                            TrackedPayment {
                                payment_hash: request(tag).requirements.payment_hash,
                                requirement_id: "index-only".into(),
                                direction: PaymentDirection::Incoming,
                                status: "Observed".into(),
                                updated_at: tag,
                                fiber_result: serde_json::json!({}),
                            },
                        )?;
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert!(
            !store
                .payments(MAX_TRACKED_PAYMENTS)
                .unwrap()
                .iter()
                .any(|p| p.payment_hash == request(1).requirements.payment_hash)
        );
        assert!(matches!(
            reserve(&store, &request(1)).unwrap(),
            OutgoingReservation::Existing(_)
        ));
        assert!(matches!(
            reserve(&store, &request(999)),
            Err(StoreError::CapacityExceeded)
        ));
        assert!(matches!(
            store.outgoing(&request(1), "http://127.0.0.1:9999/"),
            Err(StoreError::Conflict)
        ));
        let mut conflicting = request(1);
        conflicting.max_fee_amount = Some("6".into());
        assert!(matches!(
            reserve(&store, &conflicting),
            Err(StoreError::Conflict)
        ));
    }

    #[test]
    fn terminal_evidence_and_payment_projection_commit_once_without_regression() {
        let dir = tempfile::tempdir().unwrap();
        let store = DurableStore::open(dir.path().join("private/store.db"), [9; 32]).unwrap();
        let req = request(1);
        reserve(&store, &req).unwrap();
        let response = PayResponse {
            completed: true,
            payment_hash: req.requirements.payment_hash.clone(),
            fiber_result: serde_json::json!({"payment_hash":req.requirements.payment_hash,"status":"Success","private":"first evidence"}),
        };
        let saved = store
            .finish_outgoing(&req, PROVIDER, response.clone(), 2)
            .unwrap();
        let revision = store.load().unwrap().0;
        let mut duplicate = response.clone();
        duplicate.fiber_result["private"] = serde_json::json!("changed observation");
        assert_eq!(
            serde_json::to_value(store.finish_outgoing(&req, PROVIDER, duplicate, 3).unwrap())
                .unwrap(),
            serde_json::to_value(saved).unwrap()
        );
        assert_eq!(store.load().unwrap().0, revision);
        let mut conflict = response;
        conflict.completed = false;
        conflict.fiber_result["status"] = serde_json::json!("Failed");
        assert!(matches!(
            store.finish_outgoing(&req, PROVIDER, conflict, 4),
            Err(StoreError::Conflict)
        ));
        assert_eq!(store.payments(1).unwrap()[0].status, "Success");
        assert_eq!(store.load().unwrap().0, revision);
        let page = store
            .events(&morph_packages::events::EventPageRequest {
                after: None,
                limit: 64,
            })
            .unwrap();
        let kinds: Vec<_> = page.events.iter().map(|event| event.kind).collect();
        assert_eq!(
            kinds,
            [
                Kind::GatewayInitialized,
                Kind::GatewayOutgoingReserved,
                Kind::GatewayOutgoingSucceeded
            ]
        );
        let encoded = serde_json::to_string(&page).unwrap();
        for secret in [
            "private-signature-marker",
            "first evidence",
            "changed observation",
            PROVIDER,
        ] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(
            page.events[2].payment_hash.as_deref(),
            Some(req.requirements.payment_hash.trim_start_matches("0x"))
        );
    }
    #[test]
    fn business_counts_survive_retries_display_eviction_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/store.db");
        let store = DurableStore::open(&path, [9; 32]).unwrap();
        for tag in 1..=3 {
            reserve(&store, &request(tag)).unwrap();
        }
        for (tag, completed) in [(1, true), (2, false)] {
            let req = request(tag);
            let response = PayResponse {
                completed,
                payment_hash: req.requirements.payment_hash.clone(),
                fiber_result: serde_json::json!({"payment_hash":req.requirements.payment_hash,
                    "status":if completed {"Success"} else {"Failed"}}),
            };
            store
                .finish_outgoing(&req, PROVIDER, response.clone(), 2)
                .unwrap();
            let revision = store.load().unwrap().0;
            reserve(&store, &req).unwrap();
            store.finish_outgoing(&req, PROVIDER, response, 3).unwrap();
            assert_eq!(store.load().unwrap().0, revision);
        }
        // The bounded display is not the source of lifetime business counts.
        store
            .mutate(
                serde_json::json!({"operation":"test_display_eviction"}),
                Change::initialized(),
                |s| {
                    s.payments.clear();
                    Ok(())
                },
            )
            .unwrap();
        let revision = store.load().unwrap().0;
        let before_deadline = store.probe_source().observe(2_999).unwrap();
        assert_eq!(before_deadline.overdue_unresolved, 0);
        assert_eq!(
            store
                .probe_source()
                .observe(3_000)
                .unwrap()
                .overdue_unresolved,
            1
        );
        let observation = store.probe_source().observe(4_000).unwrap();
        assert_eq!(observation.overdue_unresolved, 1);
        assert_eq!(
            (
                observation.outgoing,
                observation.outgoing_succeeded,
                observation.outgoing_failed,
                observation.unresolved
            ),
            (3, 1, 1, 1)
        );
        assert_eq!(observation.oldest_unresolved_age_ms, 3000);
        assert_eq!(store.load().unwrap().0, revision);
        drop(store);
        let reopened = DurableStore::open(&path, [9; 32]).unwrap();
        let observation = reopened.probe_source().observe(5_000).unwrap();
        assert_eq!(
            (
                observation.outgoing,
                observation.outgoing_succeeded,
                observation.outgoing_failed,
                observation.unresolved
            ),
            (3, 1, 1, 1)
        );
        assert_eq!(reopened.load().unwrap().0, revision);
        // A contradictory persisted result is not silently counted as success.
        reopened
            .mutate(
                serde_json::json!({"operation":"test_bad_terminal"}),
                Change::initialized(),
                |s| {
                    s.outgoing
                        .get_mut(&request(1).requirements.payment_hash)
                        .unwrap()
                        .response
                        .as_mut()
                        .unwrap()
                        .completed = false;
                    Ok(())
                },
            )
            .unwrap();
        assert!(matches!(
            reopened.probe_source().observe(5_000),
            Err(morph_observability::Reason::StoreInconsistent)
        ));
    }
}
