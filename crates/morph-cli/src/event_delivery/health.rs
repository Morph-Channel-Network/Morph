//! Local dispatch observations, never receipt finality or a signing admission.
//! A probe has a bounded wall duration; it never acquires the worker's file lock.
use super::*;
use morph_events::{Binding, Health, QueueObservation};
use morph_observability::{
    Dependency, Observation, Readiness, Reason, Scope, ScopeReadiness, Service,
};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path, time::Instant};

const PROBE_MS: u64 = 2_000;
const MAX_LEASE_MS: u64 = 75_000;

#[derive(Debug, Clone, Copy, clap::Args)]
pub struct ProbeOptions {
    /// Local no-value dispatch budget, not a measured chain challenge budget.
    #[arg(long, default_value_t = 300_000)]
    max_pending_age_ms: u64,
    #[arg(long, default_value_t = 30_000)]
    max_critical_age_ms: u64,
}
impl ProbeOptions {
    fn validate(self) -> Result<()> {
        ensure!(
            (1_000..=morph_events::MAX_AGE_MS).contains(&self.max_pending_age_ms)
                && (1_000..=self.max_pending_age_ms).contains(&self.max_critical_age_ms),
            "invalid delivery readiness age budgets"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
enum LeaseSchema {
    #[serde(rename = "morph.event.worker_lease.v1")]
    Current,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    schema: LeaseSchema,
    binding: Binding,
    boot_id: String,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    checked_at_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    valid_until_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    checked_boot_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    valid_until_boot_ms: u64,
    running: bool,
}
use morph_observability::clock::{BootClock, read as boot_clock};

pub(super) fn default_path(store: &Path) -> PathBuf {
    let mut name = store.as_os_str().to_os_string();
    name.push(".health.json");
    PathBuf::from(name)
}
fn read_lease(path: &Path) -> Result<Lease> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "worker heartbeat must be a regular file"
    );
    let file = fs::File::open(path)?;
    crate::persistence::require_private_file(&file)?;
    ensure!(
        file.metadata()?.len() <= 4096,
        "worker heartbeat exceeds bound"
    );
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "worker heartbeat exceeds bound");
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) fn pulse(path: &Path, binding: &Binding, ttl: u64, running: bool) -> Result<()> {
    ensure!(
        (15_000..=MAX_LEASE_MS).contains(&ttl),
        "invalid worker heartbeat horizon"
    );
    if path.exists() {
        ensure!(
            read_lease(path)?.binding == *binding,
            "worker heartbeat belongs to another subscription or generation"
        );
    }
    let wall = now()?;
    let boot = boot_clock()?;
    let lease = Lease {
        schema: LeaseSchema::Current,
        binding: binding.clone(),
        boot_id: boot.id,
        checked_at_ms: wall,
        valid_until_ms: wall
            .checked_add(ttl)
            .ok_or_else(|| anyhow::anyhow!("invalid clock"))?,
        checked_boot_ms: boot.ms,
        valid_until_boot_ms: boot
            .ms
            .checked_add(ttl)
            .ok_or_else(|| anyhow::anyhow!("invalid boot clock"))?,
        running,
    };
    crate::persistence::write_private_atomic(path, &serde_json::to_vec(&lease)?)
}
fn lease_reason(lease: &Lease, binding: &Binding, wall: u64, boot: &BootClock) -> Reason {
    if lease.binding != *binding {
        return Reason::RevisionChanged;
    }
    if lease.boot_id != boot.id {
        return Reason::Stale;
    }
    let Some(ttl) = lease.valid_until_ms.checked_sub(lease.checked_at_ms) else {
        return Reason::ClockInvalid;
    };
    if ttl == 0
        || ttl > MAX_LEASE_MS
        || lease.valid_until_boot_ms.checked_sub(lease.checked_boot_ms) != Some(ttl)
        || wall < lease.checked_at_ms
        || boot.ms < lease.checked_boot_ms
    {
        return Reason::ClockInvalid;
    }
    if wall >= lease.valid_until_ms || boot.ms >= lease.valid_until_boot_ms {
        return Reason::Stale;
    }
    if !lease.running {
        return Reason::WorkerStopped;
    }
    Reason::Verified
}
fn error_reason(error: &anyhow::Error) -> Reason {
    use morph_runtime_store::StoreError;
    if let Some(error) = error.downcast_ref::<morph_events::Error>() {
        return match error {
            morph_events::Error::ArchiveRequired => Reason::ArchiveRequired,
            morph_events::Error::Policy => Reason::PolicyDenied,
            morph_events::Error::Conflict => Reason::RevisionChanged,
            morph_events::Error::Invalid => Reason::StoreInconsistent,
            morph_events::Error::Full => Reason::OutboxBlocked,
            morph_events::Error::Store(error) => store_reason(error),
        };
    }
    if let Some(error) = error.downcast_ref::<StoreError>() {
        return store_reason(error);
    }
    Reason::Unavailable
}
fn store_reason(error: &morph_runtime_store::StoreError) -> Reason {
    use morph_runtime_store::StoreError;
    match error {
        StoreError::Busy => Reason::Busy,
        StoreError::Schema => Reason::UnsupportedSchema,
        StoreError::Corrupt => Reason::StoreInconsistent,
        StoreError::Revision { .. } => Reason::RevisionChanged,
        StoreError::Full => Reason::OutboxBlocked,
        _ => Reason::Unavailable,
    }
}
fn backlog_reason(health: &Health, budget: ProbeOptions) -> Reason {
    if health.sealed {
        Reason::ConsumerSealed
    } else if health.archive_required {
        Reason::ArchiveRequired
    } else if health.dead_letter > 0 {
        Reason::DeadLetters
    } else if health.source_pending || health.source_blocked {
        Reason::OutboxBlocked
    } else if health.oldest_pending_age_ms >= budget.max_pending_age_ms
        || health.oldest_critical_age_ms >= budget.max_critical_age_ms
    {
        Reason::BacklogAged
    } else {
        Reason::Verified
    }
}
struct Probe {
    observation: Option<QueueObservation>,
    reasons: [Reason; 4],
    worker_until_ms: Option<u64>,
}
fn probe(options: &Options, budget: ProbeOptions) -> Probe {
    let attempt = || -> Result<(QueueObservation, Reason, Option<u64>)> {
        let (queue, _) = super::open(options, true)?;
        let snapshot = queue.observe(now()?)?;
        let path = options
            .health_file
            .clone()
            .unwrap_or_else(|| default_path(&options.store));
        let (worker, until) = match read_lease(&path) {
            Ok(lease) => {
                // Sample clocks after reading the atomic heartbeat: a worker
                // pulse during backlog reads must not look like a future lease.
                let wall = now()?;
                let boot = boot_clock()?;
                let reason = lease_reason(&lease, &snapshot.binding, wall, &boot);
                let until = lease
                    .valid_until_boot_ms
                    .checked_sub(boot.ms)
                    .and_then(|remaining| wall.checked_add(remaining))
                    .map(|monotonic_expiry| monotonic_expiry.min(lease.valid_until_ms));
                (reason, until)
            }
            Err(_) => (Reason::Unavailable, None),
        };
        Ok((snapshot, worker, until))
    };
    match attempt() {
        Ok((snapshot, worker, worker_until_ms)) => {
            let reasons = [
                Reason::Verified,
                backlog_reason(&snapshot.health, budget),
                worker,
                if snapshot.delivery_allowed {
                    Reason::Verified
                } else {
                    Reason::PolicyDenied
                },
            ];
            Probe {
                observation: Some(snapshot),
                reasons,
                worker_until_ms,
            }
        }
        Err(error) => Probe {
            observation: None,
            worker_until_ms: None,
            reasons: [
                error_reason(&error),
                Reason::Unverified,
                Reason::Unverified,
                Reason::Unverified,
            ],
        },
    }
}
fn readiness(probe: &Probe, started: u64, finished: u64, elapsed: Duration) -> Readiness {
    let dependencies = [
        Dependency::Store,
        Dependency::Outbox,
        Dependency::Worker,
        Dependency::DeliveryPolicy,
    ];
    let observations: Vec<_> = dependencies
        .into_iter()
        .zip(probe.reasons)
        .map(|(dependency, reason)| Observation {
            dependency,
            reason: if elapsed >= Duration::from_millis(PROBE_MS) {
                Reason::Stale
            } else {
                reason
            },
            checked_at_ms: started,
            valid_until_ms: if dependency == Dependency::Worker {
                probe
                    .worker_until_ms
                    .unwrap_or(u64::MAX)
                    .min(started.saturating_add(PROBE_MS))
            } else {
                started.saturating_add(PROBE_MS)
            },
        })
        .collect();
    Readiness::new(
        Service::EventConsumer,
        finished,
        vec![ScopeReadiness::evaluate(
            Scope::EventDispatch,
            true,
            &dependencies,
            &observations,
            finished,
        )],
    )
}
fn metrics(report: &Readiness, probe: &Probe) -> String {
    use std::fmt::Write as _;
    let verified = |dependency| {
        report
            .scopes
            .iter()
            .flat_map(|scope| &scope.checks)
            .any(|check| check.dependency == dependency && check.reason == Reason::Verified)
    };
    let available = verified(Dependency::Store) && probe.observation.is_some();
    let mut text = String::from(
        "# HELP morph_event_delivery_observation_available Whether backlog values were read consistently.\n# TYPE morph_event_delivery_observation_available gauge\n",
    );
    let _ = writeln!(
        text,
        "morph_event_delivery_observation_available {}",
        u8::from(available)
    );
    text.push_str("# TYPE morph_runtime_scope_ready gauge\n");
    let _ = writeln!(
        text,
        "morph_runtime_scope_ready{{service=\"event_consumer\",scope=\"event_dispatch\"}} {}",
        u8::from(report.consistent() && report.ready)
    );
    let health = probe
        .observation
        .as_ref()
        .filter(|_| available)
        .map(|s| &s.health);
    let values: [(&str, Option<u64>); 15] = [
        ("retained", health.map(|h| h.retained as u64)),
        ("pending", health.map(|h| h.pending as u64)),
        ("in_flight", health.map(|h| h.in_flight as u64)),
        ("acknowledged", health.map(|h| h.acknowledged as u64)),
        ("dead_letter", health.map(|h| h.dead_letter as u64)),
        (
            "critical_pending",
            health.map(|h| h.critical_pending as u64),
        ),
        (
            "critical_dead_letter",
            health.map(|h| h.critical_dead_letter as u64),
        ),
        (
            "oldest_pending_age_ms",
            health.map(|h| h.oldest_pending_age_ms),
        ),
        (
            "oldest_critical_age_ms",
            health.map(|h| h.oldest_critical_age_ms),
        ),
        (
            "source_pending",
            health.map(|h| u64::from(h.source_pending)),
        ),
        (
            "source_blocked",
            health.map(|h| u64::from(h.source_blocked)),
        ),
        (
            "archive_required",
            health.map(|h| u64::from(h.archive_required)),
        ),
        ("sealed", health.map(|h| u64::from(h.sealed))),
        (
            "worker_fresh",
            Some(u64::from(verified(Dependency::Worker))),
        ),
        (
            "policy_allowed",
            probe
                .observation
                .as_ref()
                .filter(|_| available)
                .map(|s| u64::from(s.delivery_allowed)),
        ),
    ];
    for (name, value) in values {
        let _ = writeln!(
            text,
            "# TYPE morph_event_delivery_{name} gauge\nmorph_event_delivery_{name} {}",
            value.map_or_else(|| "NaN".into(), |v| v.to_string())
        );
    }
    text
}
pub(super) fn run(options: Options, budget: ProbeOptions, as_metrics: bool) -> Result<()> {
    budget.validate()?;
    let started_wall = now()?;
    let started = Instant::now();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("morph-event-readiness".into())
        .spawn(move || {
            let _ = tx.send(probe(&options, budget));
        })?;
    let result = rx
        .recv_timeout(Duration::from_millis(PROBE_MS))
        .unwrap_or(Probe {
            observation: None,
            worker_until_ms: None,
            reasons: [
                Reason::Stale,
                Reason::Unverified,
                Reason::Unverified,
                Reason::Unverified,
            ],
        });
    let report = readiness(&result, started_wall, now()?, started.elapsed());
    if as_metrics {
        println!("{}", metrics(&report, &result));
        Ok(())
    } else {
        println!("{}", serde_json::to_string(&report)?);
        ensure!(report.ready, "event dispatch is not ready");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            source_id: "11".repeat(32),
            consumer_id: "22".repeat(32),
            policy: "33".repeat(32),
        }
    }
    fn lease() -> Lease {
        Lease {
            schema: LeaseSchema::Current,
            binding: binding(),
            boot_id: "boot-a".into(),
            checked_at_ms: 10_000,
            valid_until_ms: 25_000,
            checked_boot_ms: 100_000,
            valid_until_boot_ms: 115_000,
            running: true,
        }
    }
    fn budget() -> ProbeOptions {
        ProbeOptions {
            max_pending_age_ms: 300_000,
            max_critical_age_ms: 30_000,
        }
    }
    #[test]
    fn heartbeat_writer_cannot_replace_another_generation_or_a_database() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("health.json");
        pulse(&path, &binding(), 15_000, true).unwrap();
        let before = fs::read(&path).unwrap();
        let mut other = binding();
        other.consumer_id = "44".repeat(32);
        assert!(pulse(&path, &other, 15_000, true).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let path = dir.path().join("source.db");
        drop(Store::open(&path, Protection::private_plaintext()).unwrap());
        let before = fs::read(&path).unwrap();
        assert!(pulse(&path, &binding(), 15_000, true).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    #[test]
    fn wall_clock_changes_boot_changes_and_wrong_generation_cannot_extend_heartbeat() {
        let mut lease = lease();
        let boot = |ms| BootClock {
            id: "boot-a".into(),
            ms,
        };
        assert_eq!(
            lease_reason(&lease, &binding(), 10_001, &boot(100_001)),
            Reason::Verified
        );
        assert_eq!(
            lease_reason(&lease, &binding(), 10_001, &boot(115_000)),
            Reason::Stale
        );
        assert_eq!(
            lease_reason(&lease, &binding(), 9_999, &boot(100_001)),
            Reason::ClockInvalid
        );
        assert_eq!(
            lease_reason(&lease, &binding(), 25_000, &boot(100_001)),
            Reason::Stale
        );
        assert_eq!(
            lease_reason(
                &lease,
                &binding(),
                10_001,
                &BootClock {
                    id: "boot-b".into(),
                    ms: 100_001
                }
            ),
            Reason::Stale
        );
        let mut other = binding();
        other.consumer_id = "44".repeat(32);
        assert_eq!(
            lease_reason(&lease, &other, 10_001, &boot(100_001)),
            Reason::RevisionChanged
        );
        lease.running = false;
        assert_eq!(
            lease_reason(&lease, &binding(), 10_001, &boot(100_001)),
            Reason::WorkerStopped
        );
    }
    #[test]
    fn probe_cannot_extend_a_lease_that_expires_during_validation_or_after_monotonic_budget() {
        let probe = Probe {
            observation: None,
            reasons: [Reason::Verified; 4],
            worker_until_ms: Some(110),
        };
        let valid = readiness(&probe, 100, 109, Duration::from_millis(9));
        assert!(valid.ready && valid.consistent());
        let expired = readiness(&probe, 100, 110, Duration::from_millis(10));
        assert!(!expired.ready && expired.consistent());
        let late = readiness(&probe, 100, 101, Duration::from_millis(PROBE_MS));
        assert!(!late.ready && late.consistent());
        let invalid = readiness(&probe, 100, 99, Duration::from_millis(1));
        assert!(!invalid.ready && invalid.consistent());
    }
    #[test]
    fn unresolved_source_dead_letters_age_and_archive_each_fail_readiness() {
        let mut health = Health::default();
        assert_eq!(backlog_reason(&health, budget()), Reason::Verified);
        health.oldest_critical_age_ms = 30_000;
        assert_eq!(backlog_reason(&health, budget()), Reason::BacklogAged);
        health.oldest_critical_age_ms = 0;
        health.oldest_pending_age_ms = 300_000;
        assert_eq!(backlog_reason(&health, budget()), Reason::BacklogAged);
        health.oldest_pending_age_ms = 0;
        health.source_pending = true;
        assert_eq!(backlog_reason(&health, budget()), Reason::OutboxBlocked);
        health.source_pending = false;
        health.dead_letter = 1;
        assert_eq!(backlog_reason(&health, budget()), Reason::DeadLetters);
        health.dead_letter = 0;
        health.archive_required = true;
        assert_eq!(backlog_reason(&health, budget()), Reason::ArchiveRequired);
        health.sealed = true;
        assert_eq!(backlog_reason(&health, budget()), Reason::ConsumerSealed);
    }
    #[test]
    fn metrics_are_fixed_and_do_not_export_bindings_or_fake_zero_backlogs() {
        let absent = Probe {
            observation: None,
            reasons: [Reason::Unavailable; 4],
            worker_until_ms: None,
        };
        let report = readiness(&absent, 100, 101, Duration::from_millis(1));
        let unknown = metrics(&report, &absent);
        assert!(unknown.contains("morph_event_delivery_pending NaN"));
        assert!(unknown.contains("morph_event_delivery_observation_available 0"));
        let present = Probe {
            observation: Some(QueueObservation {
                binding: binding(),
                health: Health::default(),
                delivery_allowed: true,
                source_revision: 1,
                consumer_revision: 1,
            }),
            reasons: [Reason::Verified; 4],
            worker_until_ms: Some(1000),
        };
        let report = readiness(&present, 100, 101, Duration::from_millis(1));
        let known = metrics(&report, &present);
        assert_eq!(unknown.lines().filter(|l| !l.starts_with('#')).count(), 17);
        assert_eq!(known.lines().filter(|l| !l.starts_with('#')).count(), 17);
        for value in [binding().source_id, binding().consumer_id, binding().policy] {
            assert!(!known.contains(&value));
        }
    }
}
