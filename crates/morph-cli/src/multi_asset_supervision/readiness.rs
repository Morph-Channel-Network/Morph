//! Redacted observations of the supervisor, not proof that a key process is live.
use super::*;
use morph_observability::{
    Dependency, Observation as CheckObservation, Readiness, Reason, Scope, ScopeReadiness, Service,
};
const PROBE_MS: u64 = 2_000;

fn reason(health: &Health) -> Reason {
    if health.stale {
        return Reason::Stale;
    }
    if health
        .snapshot
        .sessions
        .iter()
        .any(|s| s.status == Status::DuplicateAuthority)
    {
        return Reason::StoreInconsistent;
    }
    if health
        .snapshot
        .sessions
        .iter()
        .any(|s| s.status == Status::Unreadable)
    {
        return Reason::Unavailable;
    }
    if health
        .snapshot
        .sessions
        .iter()
        .any(|s| s.status == Status::Blocked)
    {
        return Reason::Unverified;
    }
    if health
        .snapshot
        .sessions
        .iter()
        .any(|s| s.status == Status::Unmanaged)
    {
        return Reason::NotConfigured;
    }
    if health
        .snapshot
        .sessions
        .iter()
        .any(|s| s.status == Status::Busy)
    {
        return Reason::Busy;
    }
    if health.healthy {
        Reason::Verified
    } else {
        Reason::Unverified
    }
}
fn report(
    health: Option<&Health>,
    failure: Reason,
    wall: u64,
    boot: Option<&BootClock>,
    elapsed: Duration,
) -> Readiness {
    let (checked, expires, reason) = match (health, boot) {
        (Some(h), Some(b)) => {
            let expires = h
                .snapshot
                .expires_boot_ms
                .checked_sub(b.ms)
                .and_then(|left| wall.checked_add(left))
                .map(|end| end.min(h.snapshot.expires_unix_ms))
                .unwrap_or(wall);
            (
                h.snapshot.started_unix_ms,
                expires,
                if h.snapshot.boot_id != b.id
                    || b.ms < h.snapshot.completed_boot_ms
                    || b.ms >= h.snapshot.expires_boot_ms
                    || wall < h.snapshot.completed_unix_ms
                    || wall >= h.snapshot.expires_unix_ms
                {
                    Reason::Stale
                } else {
                    reason(h)
                },
            )
        }
        _ => (wall, wall.saturating_add(1), failure),
    };
    let reason = if elapsed >= Duration::from_millis(PROBE_MS) {
        Reason::Stale
    } else {
        reason
    };
    Readiness::new(
        Service::SignerSupervisor,
        wall,
        vec![
            ScopeReadiness::evaluate(
                Scope::AuthoritySupervision,
                true,
                &[Dependency::Supervision],
                &[CheckObservation {
                    dependency: Dependency::Supervision,
                    reason,
                    checked_at_ms: checked,
                    valid_until_ms: expires,
                }],
                wall,
            ),
            ScopeReadiness::unsupported(Scope::ChannelSigning),
        ],
    )
}
fn metrics(report: &Readiness, health: Option<&Health>) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    let available = health.filter(|h| {
        !h.stale
            && !matches!(
                report.scopes[0].checks[0].reason,
                Reason::Stale | Reason::ClockInvalid
            )
    });
    let _ = writeln!(
        text,
        "# TYPE morph_runtime_scope_ready gauge\nmorph_runtime_scope_ready{{service=\"signer_supervisor\",scope=\"authority_supervision\"}} {}",
        u8::from(report.consistent() && report.ready)
    );
    let _ = writeln!(
        text,
        "# TYPE morph_signer_supervision_observation_available gauge\nmorph_signer_supervision_observation_available {}",
        u8::from(available.is_some())
    );
    for (name, status) in [
        ("verified", Status::Verified),
        ("busy", Status::Busy),
        ("unmanaged", Status::Unmanaged),
        ("blocked", Status::Blocked),
        ("unreadable", Status::Unreadable),
        ("duplicate_authority", Status::DuplicateAuthority),
    ] {
        let value = available
            .map(|h| {
                h.snapshot
                    .sessions
                    .iter()
                    .filter(|s| s.status == status)
                    .count()
                    .to_string()
            })
            .unwrap_or_else(|| "NaN".into());
        let _ = writeln!(
            text,
            "# TYPE morph_signer_supervision_{name} gauge\nmorph_signer_supervision_{name} {value}"
        );
    }
    text
}
pub fn run(config_path: PathBuf, health_path: PathBuf, as_metrics: bool) -> Result<()> {
    let started = Instant::now();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("morph-supervision-observation".into())
        .spawn(move || {
            let load = || -> Result<Health> {
                let config = config(&config_path)?;
                let mut snapshot = load_snapshot(&health_path)?;
                conflicts(&mut snapshot.sessions);
                let boot = boot_clock()?;
                let wall = now_ms()?;
                evaluate_at(snapshot, &config, wall, &boot)
            };
            let _ = tx.send(load().ok());
        })?;
    let result = rx.recv_timeout(Duration::from_millis(PROBE_MS));
    let wall = now_ms()?;
    let boot = boot_clock().ok();
    // Re-evaluate expiry on return; a clock sample from before a slow read is not fresh.
    let health = result.as_ref().ok().and_then(|v| v.as_ref());
    let report = report(
        health,
        if result.is_err() {
            Reason::Stale
        } else {
            Reason::Unavailable
        },
        wall,
        boot.as_ref(),
        started.elapsed(),
    );
    if as_metrics {
        println!("{}", metrics(&report, health));
    } else {
        println!("{}", serde_json::to_string(&report)?);
        ensure!(report.ready, "signer context supervision is not ready");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacted_reports_never_expose_paths_keys_errors_or_claim_signing() {
        let config = super::super::tests::profile(vec![PathBuf::from("/private/secret-journal")]);
        let boot = BootClock {
            id: "test-boot".into(),
            ms: 111,
        };
        let health =
            evaluate_at(super::super::tests::snapshot(&config), &config, 21, &boot).unwrap();
        let report = report(
            Some(&health),
            Reason::Unavailable,
            21,
            Some(&boot),
            Duration::from_millis(1),
        );
        assert!(report.ready && report.consistent());
        assert!(!report.scopes[1].configured && !report.scopes[1].ready);
        let text = serde_json::to_string(&report).unwrap() + &metrics(&report, Some(&health));
        assert!(
            !text.contains("secret-journal")
                && !text.contains("pubkey")
                && !text.contains("funding_context")
        );
        assert_eq!(
            metrics(&report, Some(&health))
                .lines()
                .filter(|s| !s.starts_with('#') && !s.is_empty())
                .count(),
            8
        );
        let missing = report_missing();
        assert_eq!(
            metrics(&missing, None)
                .lines()
                .filter(|s| s.ends_with("NaN"))
                .count(),
            6
        );
    }
    fn report_missing() -> Readiness {
        report(
            None,
            Reason::Unavailable,
            21,
            None,
            Duration::from_millis(1),
        )
    }
}
