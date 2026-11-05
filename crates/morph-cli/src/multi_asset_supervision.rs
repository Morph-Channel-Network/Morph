//! Read-only supervision of authoritative signer journals. A health file is
//! observation evidence, never a substitute for the signer's own chain guard.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::canonical_hex;
use crate::persistence::{
    append_private_jsonl, required_option, try_lock_private_path, write_private_atomic,
};
use crate::watch_alert::WatchAlertSeverity;

const CONFIG_SCHEMA: &str = "morph.multi_asset_supervision.v1";
const HEALTH_SCHEMA: &str = "morph.multi_asset_supervision_health.v1";
const ALERT_SCHEMA: &str = "morph.multi_asset_supervision_alert.v1";
const MAX_BYTES: u64 = 256 * 1024;
const MAX_SESSIONS: usize = 32;
const WORKERS: usize = 4;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub sessions: Vec<PathBuf>,
    pub poll_ms: u64,
    pub rpc_budget_ms: u64,
    pub stale_after_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Verified,
    Busy,
    Unmanaged,
    Blocked,
    Unreadable,
    DuplicateAuthority,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub pubkey: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub state_number: String,
}
#[derive(Debug, Clone)]
pub struct Observation {
    pub identity: Option<Identity>,
    pub status: Status,
    pub error: Option<String>,
}
impl Observation {
    pub fn failure(status: Status, error: impl ToString) -> Self {
        Self {
            identity: None,
            status,
            error: Some(error.to_string()),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableObservation {
    pub status: Status,
    #[serde(deserialize_with = "required_option")]
    pub identity: Option<Identity>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHealth {
    pub session: PathBuf,
    pub started_unix_ms: u64,
    pub checked_unix_ms: u64,
    pub elapsed_ms: u64,
    #[serde(deserialize_with = "required_option")]
    pub identity: Option<Identity>,
    pub status: Status,
    #[serde(deserialize_with = "required_option")]
    pub error: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub last_stable: Option<StableObservation>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: String,
    pub config_digest: String,
    pub cycle: u64,
    pub completed_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub sessions: Vec<SessionHealth>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    GuardBlocked,
    GuardRecovered,
    ContextChanged,
    AuthorityConflict,
}
#[derive(Debug, Serialize)]
struct Alert<'a> {
    schema: &'static str,
    created_unix_ms: u64,
    session: &'a Path,
    event: Event,
    severity: WatchAlertSeverity,
    status: Status,
    identity: &'a Option<Identity>,
    error: &'a Option<String>,
}
#[derive(Serialize)]
pub struct Health {
    pub healthy: bool,
    pub stale: bool,
    pub snapshot: Snapshot,
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "supervision file exceeds byte limit"
    );
    Ok(bytes)
}
fn config(path: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&read_bounded(path)?)?;
    ensure!(
        config.schema == CONFIG_SCHEMA,
        "unsupported supervision schema"
    );
    ensure!(
        (1..=MAX_SESSIONS).contains(&config.sessions.len()),
        "supervision requires 1..={MAX_SESSIONS} journals"
    );
    let mut paths = BTreeSet::new();
    for path in &config.sessions {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir)),
            "journal paths must be absolute without parent traversal"
        );
        ensure!(paths.insert(path), "duplicate journal path");
    }
    ensure!(
        (100..=60_000).contains(&config.poll_ms) && (100..=10_000).contains(&config.rpc_budget_ms),
        "invalid supervision interval or RPC budget"
    );
    let waves = config.sessions.len().div_ceil(WORKERS) as u64;
    let minimum_age = waves * config.rpc_budget_ms + config.poll_ms;
    ensure!(
        (minimum_age..=3_600_000).contains(&config.stale_after_ms),
        "health age must cover one bounded check cycle and poll interval"
    );
    Ok(config)
}
fn digest(config: &Config) -> Result<String> {
    Ok(canonical_hex(&morph_core::blake2b256(&serde_json::to_vec(
        config,
    )?)))
}
fn load_snapshot(path: &Path) -> Result<Snapshot> {
    let snapshot: Snapshot = serde_json::from_slice(&read_bounded(path)?)?;
    ensure!(
        snapshot.schema == HEALTH_SCHEMA
            && snapshot.cycle > 0
            && (1..=MAX_SESSIONS).contains(&snapshot.sessions.len()),
        "invalid supervision health shape"
    );
    let mut paths = BTreeSet::new();
    for session in &snapshot.sessions {
        ensure!(
            paths.insert(&session.session)
                && session.started_unix_ms <= session.checked_unix_ms
                && session.checked_unix_ms <= snapshot.completed_unix_ms,
            "invalid supervision health history"
        );
        ensure!(
            session.status != Status::Verified
                || (session.identity.is_some() && session.error.is_none()),
            "verified health requires signer identity"
        );
        ensure!(
            session
                .last_stable
                .as_ref()
                .is_none_or(|stable| stable.status != Status::Busy
                    && (stable.status != Status::Verified || stable.identity.is_some())),
            "invalid persisted stable observation"
        );
        ensure!(
            session.status == Status::Busy
                || session
                    .last_stable
                    .as_ref()
                    .is_some_and(|stable| stable.status == session.status
                        && stable.identity == session.identity),
            "missing or inconsistent stable supervision history"
        );
    }
    Ok(snapshot)
}
fn evaluate(snapshot: Snapshot, config: &Config, at: u64) -> Result<Health> {
    ensure!(
        snapshot.config_digest == digest(config)?,
        "health belongs to another supervision configuration"
    );
    ensure!(
        snapshot
            .sessions
            .iter()
            .map(|entry| &entry.session)
            .eq(config.sessions.iter()),
        "health session set differs from configured authority paths"
    );
    let oldest = snapshot
        .sessions
        .iter()
        .map(|entry| entry.checked_unix_ms)
        .min()
        .ok_or_else(|| anyhow!("no supervision results"))?;
    ensure!(
        oldest.checked_add(config.stale_after_ms) == Some(snapshot.expires_unix_ms),
        "health expiry differs from configured freshness policy"
    );
    let stale = at < snapshot.completed_unix_ms || at >= snapshot.expires_unix_ms;
    let healthy = !stale
        && snapshot
            .sessions
            .iter()
            .all(|entry| entry.status == Status::Verified);
    Ok(Health {
        healthy,
        stale,
        snapshot,
    })
}
pub fn health(config_path: &Path, health_path: &Path) -> Result<Health> {
    let config = config(config_path)?;
    let snapshot = load_snapshot(health_path)?;
    evaluate(snapshot, &config, now_ms()?)
}
fn conflicts(sessions: &mut [SessionHealth]) {
    let mut authorities = BTreeMap::<(String, String), Vec<usize>>::new();
    for (index, session) in sessions.iter().enumerate() {
        if let Some(identity) = &session.identity {
            authorities
                .entry((identity.channel_id.clone(), identity.pubkey.clone()))
                .or_default()
                .push(index);
        }
    }
    for indices in authorities.values().filter(|indices| indices.len() > 1) {
        for &index in indices {
            sessions[index].status = Status::DuplicateAuthority;
            sessions[index].error =
                Some("same channel signer is registered at multiple active paths".to_string());
        }
    }
}
fn transition(
    before: Option<&StableObservation>,
    after: &SessionHealth,
) -> Option<(Event, WatchAlertSeverity)> {
    match after.status {
        Status::Verified => match before {
            Some(before) if !matches!(before.status, Status::Verified | Status::Busy) => {
                Some((Event::GuardRecovered, WatchAlertSeverity::Info))
            }
            Some(before)
                if before
                    .identity
                    .as_ref()
                    .map(|identity| &identity.funding_context_id)
                    != after
                        .identity
                        .as_ref()
                        .map(|identity| &identity.funding_context_id) =>
            {
                Some((Event::ContextChanged, WatchAlertSeverity::Info))
            }
            _ => None,
        },
        Status::Busy => None,
        _ if before.is_some_and(|before| {
            before.status == after.status
                && before.identity.as_ref().map(|identity| {
                    (
                        &identity.channel_id,
                        &identity.pubkey,
                        &identity.funding_context_id,
                    )
                }) == after.identity.as_ref().map(|identity| {
                    (
                        &identity.channel_id,
                        &identity.pubkey,
                        &identity.funding_context_id,
                    )
                })
        }) =>
        {
            None
        }
        Status::DuplicateAuthority => {
            Some((Event::AuthorityConflict, WatchAlertSeverity::Critical))
        }
        _ => Some((Event::GuardBlocked, WatchAlertSeverity::Critical)),
    }
}
fn check(path: PathBuf, budget: Duration) -> Result<SessionHealth> {
    let started_unix_ms = now_ms()?;
    let started = Instant::now();
    let mut observation = crate::multi_asset_session::observe_for_supervision(&path, budget);
    if let Some(error) = &mut observation.error
        && error.len() > 4096
    {
        let mut end = 4096;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    let checked_unix_ms = now_ms()?;
    ensure!(
        checked_unix_ms >= started_unix_ms,
        "wall clock moved backwards during supervision"
    );
    Ok(SessionHealth {
        session: path,
        started_unix_ms,
        checked_unix_ms,
        elapsed_ms: started.elapsed().as_millis().try_into()?,
        identity: observation.identity,
        status: observation.status,
        error: observation.error,
        last_stable: None,
    })
}
fn comparable_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    match absolute.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = absolute
                .parent()
                .ok_or_else(|| anyhow!("supervision output needs a parent"))?;
            match parent.canonicalize() {
                Ok(parent) => Ok(parent.join(
                    absolute
                        .file_name()
                        .ok_or_else(|| anyhow!("supervision output needs a file name"))?,
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}
fn same_file(a: &Path, b: &Path) -> Result<bool> {
    if comparable_path(a)? == comparable_path(b)? {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            return Ok(a.dev() == b.dev() && a.ino() == b.ino());
        }
    }
    Ok(false)
}

pub fn run(
    config_path: &Path,
    health_path: &Path,
    alert_path: &Path,
    cycles: Option<u64>,
) -> Result<Health> {
    ensure!(cycles != Some(0), "supervision cycles must be positive");
    let config = config(config_path)?;
    ensure!(
        !same_file(health_path, alert_path)?,
        "health output and alert stream must be distinct"
    );
    for source in std::iter::once(config_path).chain(config.sessions.iter().map(PathBuf::as_path)) {
        ensure!(
            !same_file(source, health_path)? && !same_file(source, alert_path)?,
            "supervision output cannot replace an input configuration or signer journal"
        );
    }
    let _lock = try_lock_private_path(health_path)?
        .ok_or_else(|| anyhow!("another supervisor owns this health file"))?;
    let config_digest = digest(&config)?;
    let mut previous = if health_path.exists() {
        Some(load_snapshot(health_path)?)
    } else {
        None
    };
    let mut count = 0u64;
    loop {
        let mut sessions = Vec::new();
        for chunk in config.sessions.chunks(WORKERS) {
            let mut workers = Vec::new();
            for path in chunk {
                let path = path.clone();
                let budget = Duration::from_millis(config.rpc_budget_ms);
                workers.push(
                    std::thread::Builder::new()
                        .name("morph-signer-supervision".to_string())
                        .spawn(move || check(path, budget))?,
                );
            }
            for worker in workers {
                sessions.push(
                    worker
                        .join()
                        .map_err(|_| anyhow!("signer supervision worker terminated"))??,
                );
            }
        }
        conflicts(&mut sessions);
        let completed = now_ms()?;
        ensure!(
            previous
                .as_ref()
                .is_none_or(|snapshot| completed >= snapshot.completed_unix_ms),
            "wall clock moved backwards since last supervision cycle"
        );
        let oldest = sessions
            .iter()
            .map(|entry| entry.checked_unix_ms)
            .min()
            .ok_or_else(|| anyhow!("no supervision results"))?;
        let expires = oldest
            .checked_add(config.stale_after_ms)
            .ok_or_else(|| anyhow!("health expiry overflow"))?;
        let previous_by_path: BTreeMap<_, _> = previous
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .sessions
                    .iter()
                    .map(|entry| (&entry.session, entry))
                    .collect()
            })
            .unwrap_or_default();
        for session in &mut sessions {
            let last_stable = previous_by_path
                .get(&session.session)
                .and_then(|before| before.last_stable.as_ref());
            if let Some((event, severity)) = transition(last_stable, session) {
                append_private_jsonl(
                    alert_path,
                    &Alert {
                        schema: ALERT_SCHEMA,
                        created_unix_ms: completed,
                        session: &session.session,
                        event,
                        severity,
                        status: session.status,
                        identity: &session.identity,
                        error: &session.error,
                    },
                )?;
            }
            session.last_stable = if session.status == Status::Busy {
                last_stable.cloned()
            } else {
                Some(StableObservation {
                    status: session.status,
                    identity: session.identity.clone(),
                })
            };
        }
        let cycle = previous.as_ref().map_or(Ok(1), |snapshot| {
            snapshot
                .cycle
                .checked_add(1)
                .ok_or_else(|| anyhow!("supervision cycle overflow"))
        })?;
        let snapshot = Snapshot {
            schema: HEALTH_SCHEMA.to_string(),
            config_digest: config_digest.clone(),
            cycle,
            completed_unix_ms: completed,
            expires_unix_ms: expires,
            sessions,
        };
        let encoded = serde_json::to_vec(&snapshot)?;
        ensure!(
            encoded.len() as u64 <= MAX_BYTES,
            "supervision health exceeds byte limit"
        );
        write_private_atomic(health_path, &encoded)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow!("supervision run counter overflow"))?;
        if cycles == Some(count) {
            return evaluate(snapshot, &config, now_ms()?);
        }
        previous = Some(snapshot);
        std::thread::sleep(Duration::from_millis(config.poll_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "morph-supervision-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    fn profile(paths: Vec<PathBuf>) -> Config {
        Config {
            schema: CONFIG_SCHEMA.to_string(),
            sessions: paths,
            poll_ms: 100,
            rpc_budget_ms: 100,
            stale_after_ms: 1000,
        }
    }
    fn entry(path: PathBuf, status: Status) -> SessionHealth {
        let identity = Identity {
            pubkey: canonical_hex(&[2; 33]),
            channel_id: canonical_hex(&[3; 32]),
            funding_context_id: canonical_hex(&[4; 32]),
            state_number: "1".to_string(),
        };
        SessionHealth {
            session: path,
            started_unix_ms: 10,
            checked_unix_ms: 20,
            elapsed_ms: 10,
            identity: Some(identity.clone()),
            status,
            error: None,
            last_stable: Some(StableObservation {
                status,
                identity: Some(identity),
            }),
        }
    }
    fn snapshot(config: &Config) -> Snapshot {
        Snapshot {
            schema: HEALTH_SCHEMA.to_string(),
            config_digest: digest(config).unwrap(),
            cycle: 1,
            completed_unix_ms: 20,
            expires_unix_ms: 20 + config.stale_after_ms,
            sessions: config
                .sessions
                .iter()
                .map(|path| entry(path.clone(), Status::Verified))
                .collect(),
        }
    }
    #[test]
    fn freshness_is_bound_to_exact_configuration_and_oldest_completed_check() {
        let config = profile(vec![PathBuf::from("/tmp/authority.json")]);
        assert!(evaluate(snapshot(&config), &config, 21).unwrap().healthy);
        assert!(evaluate(snapshot(&config), &config, 1020).unwrap().stale);
        assert!(evaluate(snapshot(&config), &config, 19).unwrap().stale);
        let mut tampered = snapshot(&config);
        tampered.expires_unix_ms += 1;
        assert!(evaluate(tampered, &config, 21).is_err());
        let other = profile(vec![PathBuf::from("/tmp/another-authority.json")]);
        assert!(evaluate(snapshot(&config), &other, 21).is_err());
    }
    #[test]
    fn busy_checks_preserve_failure_deduplication_and_later_recovery() {
        let mut current = entry(PathBuf::from("/tmp/authority.json"), Status::Blocked);
        assert!(matches!(
            transition(None, &current),
            Some((Event::GuardBlocked, _))
        ));
        let stable = current.last_stable.clone().unwrap();
        current.status = Status::Busy;
        assert!(transition(Some(&stable), &current).is_none());
        current.status = Status::Blocked;
        assert!(transition(Some(&stable), &current).is_none());
        current.status = Status::Verified;
        assert!(matches!(
            transition(Some(&stable), &current),
            Some((Event::GuardRecovered, _))
        ));
        let verified = StableObservation {
            status: Status::Verified,
            identity: current.identity.clone(),
        };
        current.identity.as_mut().unwrap().funding_context_id = canonical_hex(&[5; 32]);
        assert!(matches!(
            transition(Some(&verified), &current),
            Some((Event::ContextChanged, _))
        ));
    }
    #[test]
    fn duplicate_signers_are_rejected_even_across_different_contexts() {
        let mut entries = vec![
            entry(PathBuf::from("/tmp/a"), Status::Verified),
            entry(PathBuf::from("/tmp/b"), Status::Verified),
        ];
        entries[1].identity.as_mut().unwrap().funding_context_id = canonical_hex(&[5; 32]);
        conflicts(&mut entries);
        assert!(
            entries
                .iter()
                .all(|entry| entry.status == Status::DuplicateAuthority)
        );
    }
    #[test]
    fn repeated_failures_survive_restart_without_duplicate_alerts() {
        let dir = directory();
        let config_path = dir.join("config.json");
        let health_path = dir.join("health.json");
        let alerts = dir.join("alerts.jsonl");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&profile(vec![dir.join("missing.json")])).unwrap(),
        )
        .unwrap();
        let first = run(&config_path, &health_path, &alerts, Some(2)).unwrap();
        assert!(!first.healthy && !first.stale);
        assert_eq!(first.snapshot.sessions[0].status, Status::Unreadable);
        let second = run(&config_path, &health_path, &alerts, Some(1)).unwrap();
        assert_eq!(second.snapshot.cycle, 3);
        assert_eq!(std::fs::read_to_string(&alerts).unwrap().lines().count(), 1);
        let lock = crate::persistence::lock_private_path(&health_path).unwrap();
        assert!(run(&config_path, &health_path, &alerts, Some(1)).is_err());
        drop(lock);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&health_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn busy_and_unmanaged_root_journals_never_report_verified() {
        use crate::multi_asset_session::test_session;
        let dir = directory();
        let package = crate::multi_asset_packages::fixture_package().unwrap();
        let package_path = dir.join("package.json");
        let signer = dir.join("signer.json");
        std::fs::write(&package_path, serde_json::to_vec(&package).unwrap()).unwrap();
        let pubkey = package.validate().unwrap().signer_pubkeys[0].clone();
        test_session(&signer, &package_path, &pubkey).unwrap();
        let config_path = dir.join("config.json");
        let health_path = dir.join("health.json");
        let alerts = dir.join("alerts.jsonl");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&profile(vec![signer.clone()])).unwrap(),
        )
        .unwrap();
        assert_eq!(
            run(&config_path, &health_path, &alerts, Some(1))
                .unwrap()
                .snapshot
                .sessions[0]
                .status,
            Status::Unmanaged
        );
        let lock = crate::persistence::lock_private_path(&signer).unwrap();
        let busy = run(&config_path, &health_path, &alerts, Some(1)).unwrap();
        assert_eq!(busy.snapshot.sessions[0].status, Status::Busy);
        assert_eq!(
            busy.snapshot.sessions[0]
                .last_stable
                .as_ref()
                .unwrap()
                .status,
            Status::Unmanaged
        );
        drop(lock);
        run(&config_path, &health_path, &alerts, Some(1)).unwrap();
        assert_eq!(std::fs::read_to_string(&alerts).unwrap().lines().count(), 1);
        #[cfg(unix)]
        {
            let alias = dir.join("alias.json");
            std::fs::hard_link(&signer, &alias).unwrap();
            let before = std::fs::read(&signer).unwrap();
            assert!(run(&config_path, &health_path, &alias, Some(1)).is_err());
            assert_eq!(std::fs::read(&signer).unwrap(), before);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
