//! The Hub only reports scopes it actually implements. Probes run outside the
//! request/store lock; expiry fails closed if I/O hangs. At most one is in flight.
use super::*;
use morph_observability::{
    Check, Dependency, Observation, Readiness, Reason, Scope, ScopeReadiness, Service,
};
use std::sync::TryLockError;

const PROBE_TTL_MS: u64 = 5_000;
#[derive(Default)]
pub(super) struct Cache {
    in_flight: bool,
    value: Option<Probe>,
}
#[derive(Clone, Copy)]
struct Probe {
    revision: u64,
    started: Instant,
    observation: Observation,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|t| t.as_millis().try_into().ok())
        .unwrap_or(0)
}
fn observation(reason: Reason, now: u64) -> Observation {
    Observation {
        dependency: Dependency::Store,
        reason,
        checked_at_ms: now,
        valid_until_ms: now.saturating_add(PROBE_TTL_MS),
    }
}

pub(super) fn report(server: &HubServer) -> Readiness {
    let now = now_ms();
    let store_check = if now == 0 {
        observation(Reason::ClockInvalid, now)
    } else {
        match server.store.try_lock() {
            Ok(store) => {
                let path = store.path.clone();
                let revision = store.revision;
                drop(store);
                cached_probe(server, path, revision, now)
            }
            Err(TryLockError::WouldBlock) => observation(Reason::Busy, now),
            Err(TryLockError::Poisoned(_)) => observation(Reason::StoreInconsistent, now),
        }
    };
    let mut invoice = ScopeReadiness::evaluate(
        Scope::InvoiceIssuance,
        server.invoice_signing_key.is_some(),
        &[Dependency::Store],
        &[store_check],
        now,
    );
    invoice.checks.push(Check {
        dependency: Dependency::SignerPolicy,
        checked_at_ms: Some(now),
        valid_until_ms: Some(now.saturating_add(PROBE_TTL_MS)),
        reason: if server.invoice_signing_key.is_some() {
            Reason::Verified
        } else {
            Reason::NotConfigured
        },
    });
    Readiness::new(
        Service::Hub,
        now,
        vec![
            ScopeReadiness::evaluate(
                Scope::LocalRegistry,
                true,
                &[Dependency::Store],
                &[store_check],
                now,
            ),
            invoice,
            ScopeReadiness::unsupported(Scope::ChannelSigning),
            ScopeReadiness::unsupported(Scope::PaymentSubmission),
            ScopeReadiness::unsupported(Scope::ChainPublication),
            ScopeReadiness::unsupported(Scope::EventDispatch),
        ],
    )
}

fn cached_probe(server: &HubServer, path: PathBuf, revision: u64, now: u64) -> Observation {
    let Ok(mut cache) = server.health_cache.try_lock() else {
        return observation(Reason::Busy, now);
    };
    let current = cache
        .value
        .map(|probe| {
            let mut result = probe.observation;
            if probe.revision != revision {
                result.reason = Reason::RevisionChanged;
            }
            // A wall-clock adjustment cannot extend a previously elapsed lease.
            if probe.started.elapsed() >= Duration::from_millis(PROBE_TTL_MS) {
                result.reason = Reason::Stale;
            }
            result
        })
        .unwrap_or_else(|| observation(Reason::Unverified, now));
    let refresh = cache.value.is_none_or(|probe| {
        probe.revision != revision || probe.started.elapsed() >= Duration::from_millis(PROBE_TTL_MS)
    });
    if refresh && !cache.in_flight {
        cache.in_flight = true;
        let shared = Arc::clone(&server.health_cache);
        let started = Instant::now();
        let spawned = thread::Builder::new()
            .name("morph-hub-store-probe".into())
            .spawn(move || {
                let reason = probe_store(&path, revision);
                if let Ok(mut cache) = shared.lock() {
                    cache.value = Some(Probe {
                        revision,
                        started,
                        observation: observation(reason, now),
                    });
                    cache.in_flight = false;
                }
            });
        if spawned.is_err() {
            cache.in_flight = false;
            return observation(Reason::Unavailable, now);
        }
    }
    current
}

fn probe_store(path: &Path, expected_revision: u64) -> Reason {
    let probe = || -> Result<()> {
        let runtime = RuntimeStore::read_only(path, RuntimeProtection::private_plaintext())?;
        runtime.validate()?;
        let state = runtime.read(RuntimeFamily::Hub, "state")?;
        if state.revision != expected_revision {
            return Err(morph_runtime_store::StoreError::Revision {
                expected: expected_revision,
                actual: state.revision,
            }
            .into());
        }
        let record = state
            .record
            .ok_or(morph_runtime_store::StoreError::Corrupt)?;
        let persisted: PersistedHubState = serde_json::from_slice(record.body.bytes())
            .map_err(|_| morph_runtime_store::StoreError::Schema)?;
        HubRuntimeState::from_persisted(persisted)
            .map_err(|_| morph_runtime_store::StoreError::Corrupt)?;
        Ok(())
    };
    match probe() {
        Ok(()) => Reason::Verified,
        Err(error) => match error.downcast_ref::<morph_runtime_store::StoreError>() {
            Some(morph_runtime_store::StoreError::Schema) => Reason::UnsupportedSchema,
            Some(morph_runtime_store::StoreError::Corrupt) => Reason::StoreInconsistent,
            Some(morph_runtime_store::StoreError::Busy) => Reason::Busy,
            Some(morph_runtime_store::StoreError::Revision { .. }) => Reason::RevisionChanged,
            _ => Reason::Unavailable,
        },
    }
}

pub(super) fn operation(endpoint: Option<Endpoint>) -> morph_observability::metrics::Operation {
    use morph_observability::metrics::Operation;
    match endpoint {
        None => Operation::Unknown,
        Some(Endpoint::Health | Endpoint::Readiness | Endpoint::Metrics) => Operation::Observe,
        Some(
            Endpoint::CreateInvoice
            | Endpoint::DecodeInvoice
            | Endpoint::ReceiveInvoice
            | Endpoint::SettleInvoice,
        ) => Operation::Invoice,
        Some(Endpoint::PreviewRestore | Endpoint::RestoreState | Endpoint::ExportState) => {
            Operation::Restore
        }
        Some(
            Endpoint::ImportRecovery
            | Endpoint::ImportBatch
            | Endpoint::ImportRoot
            | Endpoint::RootSignature,
        ) => Operation::Recovery,
        Some(endpoint) if endpoint.mutates() => Operation::Registry,
        Some(_) => Operation::Read,
    }
}

#[cfg(test)]
#[path = "hub_health/tests.rs"]
mod tests;
