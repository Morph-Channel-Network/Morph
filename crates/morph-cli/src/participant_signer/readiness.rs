//! Live observation of the loaded key-process policy, never signing authority.
//! Uses the actual private signing listener, without creating a signing request.
use super::*;
use morph_observability::{Reason, clock::BootClock};

const PROBE_MS: u64 = 2_000;

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    scope: &'static str,
    responsive: bool,
    policy_ready: bool,
    reason: Reason,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    checked_at_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    valid_until_ms: u64,
}

fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

#[cfg(target_os = "linux")]
fn inspect(config_path: &Path, started: Instant) -> Result<bool> {
    let config = Config::load(config_path)?;
    let policy = config.observation_digest()?;
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).map_err(|_| anyhow!("probe entropy unavailable"))?;
    let remaining = Duration::from_millis(PROBE_MS)
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| anyhow!("probe expired"))?;
    let ready = morph_signer::ipc::probe(&config.socket, challenge, policy, remaining)?;
    // Neither a changed file nor a stale service may attest the other policy.
    ensure!(
        Config::load(config_path)?.observation_digest()? == policy,
        "probe configuration changed"
    );
    Ok(ready)
}
#[cfg(not(target_os = "linux"))]
fn inspect(_: &Path, _: Instant) -> Result<bool> {
    Err(anyhow!("participant signer requires Linux"))
}

fn report(
    result: Option<bool>,
    checked: u64,
    wall: u64,
    before: Option<&BootClock>,
    after: Option<&BootClock>,
    elapsed: Duration,
) -> Report {
    let expires = checked.saturating_add(PROBE_MS);
    let reason = match (before, after) {
        (Some(a), Some(b)) if a.id == b.id && b.ms >= a.ms && wall >= checked => {
            if elapsed >= Duration::from_millis(PROBE_MS)
                || b.ms - a.ms >= PROBE_MS
                || wall >= expires
            {
                Reason::Stale
            } else {
                match result {
                    Some(true) => Reason::Verified,
                    Some(false) => Reason::PolicyDenied,
                    None => Reason::Unavailable,
                }
            }
        }
        _ => Reason::ClockInvalid,
    };
    Report {
        schema: "morph.participant_signer_readiness.v1",
        scope: "key_process_policy",
        responsive: matches!(reason, Reason::Verified | Reason::PolicyDenied),
        policy_ready: reason == Reason::Verified,
        reason,
        checked_at_ms: checked,
        valid_until_ms: expires,
    }
}

fn observe(config_path: PathBuf) -> Result<Report> {
    let started = Instant::now();
    let checked = wall_ms()?;
    let before = morph_observability::clock::read().ok();
    // One CLI observation owns at most one worker. Slow filesystem reads cannot
    // renew evidence or create replacement workers; there is no in-process loop.
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("morph-key-policy-observation".into())
        .spawn(move || {
            let _ = tx.send(inspect(&config_path, started).ok());
        })?;
    let remaining = Duration::from_millis(PROBE_MS).saturating_sub(started.elapsed());
    let result = rx.recv_timeout(remaining).ok().flatten();
    let wall = wall_ms()?;
    let after = morph_observability::clock::read().ok();
    Ok(report(
        result,
        checked,
        wall,
        before.as_ref(),
        after.as_ref(),
        started.elapsed(),
    ))
}

fn metrics(report: &Report) -> String {
    format!(
        "# TYPE morph_signer_responsive gauge\nmorph_signer_responsive {}\n\
         # TYPE morph_signer_policy_ready gauge\nmorph_signer_policy_ready {}\n",
        u8::from(report.responsive),
        u8::from(report.policy_ready),
    )
}

pub(crate) fn run(config_path: PathBuf, as_metrics: bool) -> Result<()> {
    let report = observe(config_path)?;
    if as_metrics {
        print!("{}", metrics(&report));
    } else {
        println!("{}", serde_json::to_string(&report)?);
        ensure!(
            report.policy_ready,
            "participant signer policy is not ready"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
