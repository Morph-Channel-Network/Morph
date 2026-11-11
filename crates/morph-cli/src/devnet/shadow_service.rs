//! One bounded, non-forwarding canonical observer/reconciler. Health is an
//! expiring observation of this worker, never signing or payment authority.
use crate::{
    multi_asset_session::shadow::{self, Snapshot},
    persistence::{required_option, try_lock_private_path, write_private_atomic},
};
pub(crate) mod acceptance;
use anyhow::{Result, anyhow, ensure};
use clap::Subcommand;
use morph_core::{ChannelParticipant, FactoryRightReservation, GatewayAsset};
use morph_fiber_adapter::{
    FiberHookClient, HookPolicy, MirrorState,
    coordinator::{Coordinator, DesiredEdge, ObservedBatch},
};
use morph_observability::clock::{BootClock, read as boot_clock};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run until interrupted; a finite pass count is useful for no-value acceptance.
    Run {
        #[arg(long, default_value_t = 0)]
        passes: u64,
    },
    /// Read-only, boot/time/config/database-bound diagnostic readiness.
    Readiness,
    /// Fixed-cardinality textfile metrics; never exposes paths or participant IDs.
    Metrics,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    pub session: PathBuf,
    pub participants: [ChannelParticipant; 2],
    pub asset: GatewayAsset,
    #[serde(deserialize_with = "required_option")]
    pub reservation: Option<FactoryRightReservation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub schema: String,
    pub store: PathBuf,
    pub chain_rpc_url: String,
    pub contracts_dir: PathBuf,
    pub deployment_id: String,
    pub min_confirmations: u64,
    pub provider_rpc_url: String,
    pub callback_endpoint: String,
    #[serde(deserialize_with = "required_option")]
    pub bearer_token_file: Option<PathBuf>,
    pub policy: HookPolicy,
    pub sources: Vec<Source>,
    pub poll_ms: u64,
    pub observe_budget_ms: u64,
    pub reconcile_budget_ms: u64,
    pub lease_ms: u64,
}
fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(morph_core::blake2b256(bytes)))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn sidecar(store: &Path, suffix: &str) -> PathBuf {
    let mut path = store.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}
impl Config {
    fn validate(&self, config_path: &Path) -> Result<()> {
        ensure!(
            self.schema == "morph.shadow_service.v1",
            "unsupported shadow service configuration"
        );
        self.policy.validate()?;
        crate::multi_asset_session_chain::rpc_endpoint(&self.chain_rpc_url)?;
        ensure!(
            self.deployment_id.len() == 66
                && self.deployment_id.starts_with("0x")
                && self.deployment_id[2..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && self.deployment_id[2..].bytes().any(|b| b != b'0'),
            "invalid deployment identity"
        );
        ensure!(
            (1..=32).contains(&self.sources.len())
                && (1..=1024).contains(&self.min_confirmations)
                && (100..=10_000).contains(&self.poll_ms)
                && (100..=20_000).contains(&self.observe_budget_ms)
                && (100..=20_000).contains(&self.reconcile_budget_ms)
                && self.lease_ms <= 60_000
                && self.lease_ms > self.observe_budget_ms + self.reconcile_budget_ms + self.poll_ms,
            "shadow service budgets outside bounds"
        );
        let mut paths = BTreeSet::new();
        for path in [
            config_path,
            &self.store,
            &sidecar(&self.store, ".health.json"),
            &sidecar(&self.store, ".worker"),
        ] {
            ensure!(
                absolute(path) && paths.insert(path.to_path_buf()),
                "invalid or overlapping service path"
            );
        }
        ensure!(
            absolute(&self.contracts_dir),
            "contracts path must be absolute"
        );
        if let Some(path) = &self.bearer_token_file {
            ensure!(
                absolute(path) && paths.insert(path.clone()),
                "invalid credential path"
            );
        } else {
            let url = url::Url::parse(&self.provider_rpc_url)?;
            ensure!(
                url.host_str().is_some_and(|h| h
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())),
                "unauthenticated shadow provider must be literal loopback"
            );
        }
        let mut pairs = BTreeSet::new();
        for source in &self.sources {
            ensure!(
                absolute(&source.session) && !paths.contains(&source.session),
                "invalid source path"
            );
            ensure!(
                !matches!(source.asset, GatewayAsset::Rgbpp(_)),
                "RGB++ shadow admission is unavailable"
            );
            ensure!(
                pairs.insert((
                    source.session.clone(),
                    serde_json::to_string(&source.asset)?
                )),
                "duplicate shadow source"
            );
        }
        // Validate URL/callback configuration even for read-only commands.
        FiberHookClient::new(
            &self.provider_rpc_url,
            None,
            &self.callback_endpoint,
            self.policy.clone(),
        )?;
        Ok(())
    }
}
fn load(path: &Path) -> Result<(Config, String)> {
    let bytes = morph_signer::files::read(path, 2 * 1024 * 1024)?;
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("invalid shadow service configuration"))?;
    config.validate(path)?;
    Ok((config, hash(&bytes)))
}
fn token(config: &Config) -> Result<Option<String>> {
    config
        .bearer_token_file
        .as_ref()
        .map(|path| {
            let bytes = morph_signer::files::read(path, 16 * 1024)?;
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| anyhow!("invalid provider credential"))?
                .trim();
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic()),
                "invalid provider credential"
            );
            Ok(value.to_owned())
        })
        .transpose()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Health {
    schema: String,
    config_digest: String,
    store_id: String,
    revision: u64,
    cycle: u64,
    started_at_ms: u64,
    expires_at_ms: u64,
    boot_id: String,
    started_boot_ms: u64,
    expires_boot_ms: u64,
    running: bool,
    sources_verified: bool,
    provider_reconciled: bool,
    acknowledged: u64,
    forwarding: bool,
}
impl Health {
    fn fresh(&self, config: &Config, digest: &str, wall: u64, boot: &BootClock) -> bool {
        self.schema == "morph.shadow_service_health.v1"
            && self.config_digest == digest
            && !self.forwarding
            && self.boot_id == boot.id
            && self.expires_at_ms.checked_sub(self.started_at_ms) == Some(config.lease_ms)
            && self.expires_boot_ms.checked_sub(self.started_boot_ms) == Some(config.lease_ms)
            && (self.started_at_ms..self.expires_at_ms).contains(&wall)
            && (self.started_boot_ms..self.expires_boot_ms).contains(&boot.ms)
    }
}
#[derive(Serialize)]
struct Report {
    schema: &'static str,
    scope: &'static str,
    ready: bool,
    forwarding: bool,
    worker_fresh: bool,
    sources_verified: bool,
    provider_reconciled: bool,
}
fn probe(config: &Config, digest: &str) -> Report {
    let result = (|| -> Result<(bool, bool, bool)> {
        let began = Instant::now();
        let bytes = morph_signer::files::read(&sidecar(&config.store, ".health.json"), 8192)?;
        let health: Health = serde_json::from_slice(&bytes)?;
        let (id, revision) = Coordinator::probe(&config.store, digest)?;
        ensure!(
            health.store_id == hash(&id) && health.revision == revision,
            "health belongs to another database revision"
        );
        let fresh = health.fresh(config, digest, now()?, &boot_clock()?)
            && health.running
            && began.elapsed() < Duration::from_secs(2);
        Ok((
            fresh,
            fresh && health.sources_verified,
            fresh && health.provider_reconciled,
        ))
    })();
    let (worker_fresh, sources_verified, provider_reconciled) =
        result.unwrap_or((false, false, false));
    Report {
        schema: "morph.shadow_service_readiness.v1",
        scope: "local_registry",
        ready: worker_fresh && sources_verified && provider_reconciled,
        forwarding: false,
        worker_fresh,
        sources_verified,
        provider_reconciled,
    }
}
fn config_current(path: &Path, digest: &str) -> bool {
    morph_signer::files::read(path, 2 * 1024 * 1024).is_ok_and(|bytes| hash(&bytes) == digest)
}
fn collect(config: &Config) -> Result<(Vec<Snapshot>, Vec<DesiredEdge>)> {
    let start = Instant::now();
    let mut snapshots = vec![];
    let mut edges = vec![];
    let mut tip = None;
    for source in &config.sources {
        let snapshot = shadow::capture(
            &source.session,
            source.participants.clone(),
            source.asset.clone(),
            source.reservation.clone(),
        )?;
        let remaining = Duration::from_millis(config.observe_budget_ms)
            .checked_sub(start.elapsed())
            .ok_or_else(|| anyhow!("observation budget exhausted"))?
            .min(Duration::from_secs(10));
        let observed = snapshot.observe_pinned(
            &config.chain_rpc_url,
            &config.contracts_dir,
            config.min_confirmations,
            remaining,
        )?;
        ensure!(
            format!("0x{}", hex::encode(observed.edge.deployment_id)) == config.deployment_id,
            "deployment identity differs from installed policy"
        );
        if let Some(previous) = &tip {
            ensure!(
                *previous == observed.tip_hash,
                "observation batch spans different chain tips"
            );
        }
        tip = Some(observed.tip_hash);
        let state = if snapshot.draining {
            MirrorState::Draining
        } else {
            MirrorState::Active
        };
        edges.push(DesiredEdge {
            edge: observed.edge,
            state,
        });
        snapshots.push(snapshot);
    }
    for snapshot in &snapshots {
        snapshot.ensure_current()?;
    }
    ensure!(
        start.elapsed() < Duration::from_millis(config.observe_budget_ms),
        "observation budget exhausted"
    );
    Ok((snapshots, edges))
}
async fn cycle(
    config: &Config,
    path: &Path,
    digest: &str,
    local: &Coordinator,
    client: &FiberHookClient,
    number: u64,
) -> Result<Health> {
    let wall = now()?;
    let boot = boot_clock()?;
    let mut health = Health {
        schema: "morph.shadow_service_health.v1".into(),
        config_digest: digest.into(),
        store_id: hash(&local.identity()),
        revision: local.revision()?,
        cycle: number,
        started_at_ms: wall,
        expires_at_ms: wall
            .checked_add(config.lease_ms)
            .ok_or_else(|| anyhow!("clock overflow"))?,
        boot_id: boot.id.clone(),
        started_boot_ms: boot.ms,
        expires_boot_ms: boot
            .ms
            .checked_add(config.lease_ms)
            .ok_or_else(|| anyhow!("clock overflow"))?,
        running: true,
        sources_verified: false,
        provider_reconciled: false,
        acknowledged: 0,
        forwarding: false,
    };
    // A restarted worker must not inherit health. During later probes retain
    // only the previous bounded lease, avoiding a false outage every poll.
    if number == 1 {
        write_private_atomic(
            &sidecar(&config.store, ".health.json"),
            &serde_json::to_vec(&health)?,
        )?;
    }
    let observed = if config_current(path, digest) {
        let owned = config.clone();
        // Canonical RPC uses the existing blocking client. Keep it off Tokio's
        // I/O thread; one awaited, deadline-bounded worker prevents accumulation.
        tokio::task::spawn_blocking(move || collect(&owned))
            .await?
            .ok()
    } else {
        None
    };
    let snapshots = if let Some((snapshots, edges)) = observed {
        let observed = local.observe(
            local.revision()?,
            ObservedBatch {
                observed_at_ms: wall,
                valid_until_ms: health.expires_at_ms,
                edges,
            },
            now()?,
        );
        if observed.is_ok() {
            health.sources_verified = true;
            snapshots
        } else {
            local.invalidate(now()?)?;
            vec![]
        }
    } else {
        local.invalidate(now()?)?;
        vec![]
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(config.reconcile_budget_ms);
    let lease = health.clone();
    // A full bounded registry can require drain + disable + successor registration.
    for _ in 0..(morph_fiber_adapter::MAX_SHADOW_EDGES * 3 + 1) {
        let current = || {
            config_current(path, digest)
                && snapshots.iter().all(|s| s.ensure_current().is_ok())
                && lease.fresh(
                    config,
                    digest,
                    now().unwrap_or(u64::MAX),
                    &boot_clock().unwrap_or(BootClock {
                        id: String::new(),
                        ms: 0,
                    }),
                )
        };
        if !current() {
            health.sources_verified = false;
            local.invalidate(now()?)?;
        }
        match tokio::time::timeout_at(deadline, local.reconcile_guarded(client, current)).await {
            Ok(Ok(Some(_))) => health.acknowledged += 1,
            Ok(Ok(None)) => {
                // None can also mean that the final pre-send guard invalidated
                // a queued operation. Confirm against a fresh list on the next pass.
                let mirrors = match tokio::time::timeout_at(deadline, client.list_edges()).await {
                    Ok(Ok(mirrors)) => mirrors,
                    _ => break,
                };
                if local.next(&mirrors, now()?)?.is_none() {
                    health.provider_reconciled = true;
                    break;
                }
            }
            _ => break,
        }
    }
    if !config_current(path, digest)
        || snapshots.iter().any(|s| s.ensure_current().is_err())
        || !lease.fresh(config, digest, now()?, &boot_clock()?)
    {
        health.sources_verified = false;
        local.invalidate(now()?)?;
    }
    health.revision = local.revision()?;
    write_private_atomic(
        &sidecar(&config.store, ".health.json"),
        &serde_json::to_vec(&health)?,
    )?;
    Ok(health)
}
pub(crate) fn run(path: &Path, command: Command) -> Result<()> {
    let (config, digest) = load(path)?;
    match command {
        Command::Readiness | Command::Metrics => {
            let report = probe(&config, &digest);
            if matches!(command, Command::Metrics) {
                println!(
                    "# TYPE morph_shadow_ready gauge\nmorph_shadow_ready {}\n# TYPE morph_shadow_worker_fresh gauge\nmorph_shadow_worker_fresh {}\n# TYPE morph_shadow_sources_verified gauge\nmorph_shadow_sources_verified {}\n# TYPE morph_shadow_provider_reconciled gauge\nmorph_shadow_provider_reconciled {}\n# TYPE morph_shadow_forwarding gauge\nmorph_shadow_forwarding 0",
                    u8::from(report.ready),
                    u8::from(report.worker_fresh),
                    u8::from(report.sources_verified),
                    u8::from(report.provider_reconciled)
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
                ensure!(report.ready, "shadow registry is not ready");
            }
            Ok(())
        }
        Command::Run { passes } => {
            let _owner = try_lock_private_path(&sidecar(&config.store, ".worker"))?
                .ok_or_else(|| anyhow!("shadow worker already running"))?;
            let local = Coordinator::open(
                &config.store,
                config.policy.clone(),
                &config.provider_rpc_url,
                &config.callback_endpoint,
            )?;
            local.bind_owner(&digest)?;
            let client = FiberHookClient::new(
                &config.provider_rpc_url,
                token(&config)?,
                &config.callback_endpoint,
                config.policy.clone(),
            )?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut number = 0u64;
                loop {
                    number = number.checked_add(1).ok_or_else(|| anyhow!("cycle limit"))?;
                    let mut health = cycle(&config, path, &digest, &local, &client, number).await?;
                    println!("{}", serde_json::json!({"schema":"morph.shadow_service_cycle.v1","cycle":number.to_string(),"sources_verified":health.sources_verified,"provider_reconciled":health.provider_reconciled,"acknowledged":health.acknowledged.to_string(),"forwarding":false}));
                    let changed = !config_current(path, &digest);
                    let stop = changed || (passes != 0 && number >= passes) || tokio::select! {
                        _ = tokio::signal::ctrl_c() => true,
                        _ = tokio::time::sleep(Duration::from_millis(config.poll_ms)) => false,
                    };
                    if stop {
                        health.running = false;
                        write_private_atomic(&sidecar(&config.store, ".health.json"), &serde_json::to_vec(&health)?)?;
                        ensure!(!changed, "shadow configuration changed; restart with reviewed binding");
                        return Ok(());
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests;
