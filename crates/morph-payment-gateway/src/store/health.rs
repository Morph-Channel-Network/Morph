//! Independent read-only connection: probes never hold the business store mutex.
use super::*;
use morph_observability::Reason;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct ProbeSource(Arc<Source>);
struct Source {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity: [u8; 32],
}
#[derive(Clone, Copy)]
pub(crate) struct StoreObservation {
    pub revision: u64,
    pub challenges: usize,
    pub receipts: usize,
    pub offers: usize,
    pub outgoing: usize,
    pub unresolved: usize,
    pub overdue_unresolved: usize,
    pub outgoing_succeeded: usize,
    pub outgoing_failed: usize,
    pub oldest_unresolved_age_ms: u64,
    pub history_rows: u64,
    pub payload_bytes: u64,
    pub general_capacity: bool,
    pub invoice_capacity: bool,
    pub payment_capacity: bool,
}
impl ProbeSource {
    pub(super) fn new(path: PathBuf, key: [u8; 32], identity: [u8; 32]) -> Self {
        Self(Arc::new(Source {
            path,
            key: Zeroizing::new(key),
            identity,
        }))
    }
    pub(crate) fn observe(&self, now_ms: u64) -> Result<StoreObservation, Reason> {
        let read = || -> Result<StoreObservation, morph_runtime_store::StoreError> {
            use morph_runtime_store::StoreError as E;
            let runtime = Store::read_only(&self.0.path, Protection::encrypted(*self.0.key))?;
            if runtime.identity() != self.0.identity {
                return Err(E::Conflict);
            }
            let report = runtime.validate()?;
            let snapshot = runtime.read(Family::Gateway, "state")?;
            let record = snapshot.record.ok_or(E::Corrupt)?;
            let state: PersistedState =
                serde_json::from_slice(record.body.bytes()).map_err(|_| E::Corrupt)?;
            if state.schema_version != STORE_SCHEMA_VERSION {
                return Err(E::Schema);
            }
            if snapshot.revision != report.revision || runtime.revision()? != report.revision {
                return Err(E::Conflict);
            }
            let history_rows = report
                .intents
                .saturating_add(report.events)
                .saturating_add(report.attempts);
            // Preserve room for one bounded transaction; this is observed space,
            // not a reservation or a promise that an arbitrary request will fit.
            let general_capacity = report.intents < morph_runtime_store::MAX_HISTORY_ROWS as u64
                && report.events < morph_runtime_store::MAX_HISTORY_ROWS as u64
                && report
                    .payload_bytes
                    .saturating_add(morph_runtime_store::MAX_TRANSACTION_BYTES as u64)
                    < morph_runtime_store::MAX_STORED_BYTES as u64
                && record.body.bytes().len() < MAX_TRANSIENT_STORE_BYTES;
            let live_challenges = state
                .challenges
                .iter()
                .filter(|(id, c)| {
                    c.requirement.expires_at > now_ms / 1000 && !state.receipts.contains_key(*id)
                })
                .count();
            let mut outgoing_succeeded = 0;
            let mut outgoing_failed = 0;
            for (payment_hash, attempt) in &state.outgoing {
                if let Some(response) = &attempt.response {
                    let status = response.fiber_result.get("status").and_then(Value::as_str);
                    if response.payment_hash != *payment_hash
                        || response
                            .fiber_result
                            .get("payment_hash")
                            .and_then(Value::as_str)
                            != Some(payment_hash.as_str())
                        || !matches!(status, Some("Success" | "Failed"))
                        || response.completed != (status == Some("Success"))
                    {
                        return Err(E::Corrupt);
                    }
                    if response.completed {
                        outgoing_succeeded += 1;
                    } else {
                        outgoing_failed += 1;
                    }
                }
            }
            let unresolved = state
                .outgoing
                .values()
                .filter(|a| a.response.is_none())
                .collect::<Vec<_>>();
            if unresolved.iter().any(|a| a.created_at > now_ms / 1000) {
                return Err(E::Corrupt);
            }
            Ok(StoreObservation {
                revision: report.revision,
                challenges: state.challenges.len(),
                receipts: state.receipts.len(),
                offers: state.offers.len(),
                outgoing: state.outgoing.len(),
                unresolved: unresolved.len(),
                overdue_unresolved: unresolved
                    .iter()
                    .filter(|a| now_ms / 1000 - a.created_at >= a.timeout_seconds)
                    .count(),
                outgoing_succeeded,
                outgoing_failed,
                oldest_unresolved_age_ms: unresolved
                    .iter()
                    .map(|a| now_ms.saturating_sub(a.created_at.saturating_mul(1000)))
                    .max()
                    .unwrap_or(0),
                history_rows,
                payload_bytes: report.payload_bytes,
                general_capacity,
                invoice_capacity: general_capacity
                    && live_challenges < MAX_OUTSTANDING_CHALLENGES
                    && state.receipts.len() < MAX_SETTLED_RECEIPTS,
                payment_capacity: general_capacity
                    && state.outgoing.len() < outgoing::MAX_OUTGOING_ATTEMPTS,
            })
        };
        read().map_err(|e| match e {
            morph_runtime_store::StoreError::Busy => Reason::Busy,
            morph_runtime_store::StoreError::Conflict
            | morph_runtime_store::StoreError::Revision { .. } => Reason::RevisionChanged,
            morph_runtime_store::StoreError::Schema => Reason::UnsupportedSchema,
            morph_runtime_store::StoreError::Corrupt
            | morph_runtime_store::StoreError::Protection => Reason::StoreInconsistent,
            morph_runtime_store::StoreError::Full => Reason::CapacityExhausted,
            _ => Reason::Unavailable,
        })
    }
}
impl DurableStore {
    pub(crate) fn probe_source(&self) -> ProbeSource {
        self.probe_source.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_observation_tracks_real_quota_without_pruning_or_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/gateway.db");
        let store = DurableStore::open(&path, [9; 32]).unwrap();
        store
            .mutate(
                serde_json::json!({"operation":"test_health_quota"}),
                Change::initialized(),
                |state| {
                    for i in 0..MAX_OUTSTANDING_CHALLENGES as u64 {
                        let record = super::super::tests::challenge_with_tag(i, 1, 100);
                        state
                            .challenges
                            .insert(record.requirement.requirement_id.clone(), record);
                    }
                    Ok(())
                },
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let source = store.probe_source();
        let full = source.observe(2_000).unwrap();
        assert_eq!(full.challenges, MAX_OUTSTANDING_CHALLENGES);
        assert!(!full.invoice_capacity && full.payment_capacity && full.general_capacity);
        // Expired challenges can be pruned by a future business mutation; the
        // observation must count that room without performing the pruning.
        let expired = source.observe(100_000).unwrap();
        assert!(expired.invoice_capacity);
        assert_eq!(expired.challenges, MAX_OUTSTANDING_CHALLENGES);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let record = super::super::tests::challenge_with_tag(5000, 2, 100);
        assert!(matches!(
            store.insert_challenge(record),
            Err(StoreError::CapacityExceeded)
        ));
    }
}
