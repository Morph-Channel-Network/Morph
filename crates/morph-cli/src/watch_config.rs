use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "devnet")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::canonical_fields::canonical_hex32;
#[cfg(feature = "devnet")]
use crate::devnet::multi_asset_watch::{self, AutoSponsorFunding, Options as CurrentWatchOptions};
use crate::publication::read_publication_profile;
#[cfg(feature = "devnet")]
use crate::rpc::CkbRpcClient;

const WATCH_CONFIG_SCHEMA: &str = "morph.watchtower_config.v1";
const WATCH_CONFIG_RUN_SCHEMA: &str = "morph.watchtower_config_run";
const WATCH_CONFIG_LOOP_SCHEMA: &str = "morph.watchtower_config_loop";
const WATCH_CONFIG_SERVICE_SCHEMA: &str = "morph.watchtower_config_service";
pub(crate) const WATCH_CONFIG_HEALTH_SCHEMA: &str = "morph.watchtower_health.v3";
const DEFAULT_STORE_DIR: &str = "packages";
const DEFAULT_DETECTION_DEPTH: u64 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const DEFAULT_POLL_MS: u64 = 1_000;
const DEFAULT_FEE: u64 = 100_000_000;
const DEFAULT_MINE_BLOCKS: u64 = 4;
const DEFAULT_AUTO_SPONSOR_CAPACITY: u64 = 50_000_000_000;
const MAX_LOOP_PASSES: u64 = 10_000;
const MAX_SERVICE_PASSES: u64 = 1_000_000;
mod readiness;
pub use readiness::inspect_health;

fn bytes32_hex(seed: u8) -> String {
    format!("0x{}", format!("{seed:02x}").repeat(32))
}

const FIXTURE_OPERATOR_ID: &str = "watchtower-a";

fn validate_operator_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty(),
        "watchtower operator_id must not be empty"
    );
    ensure!(
        value.len() <= 64,
        "watchtower operator_id must not exceed 64 bytes"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "watchtower operator_id contains unsupported characters"
    );
    Ok(())
}

fn validate_publication_profile_operator(path: &Path, operator_id: &str) -> Result<()> {
    let profile = read_publication_profile(path)?;
    ensure!(
        profile.operator_id == operator_id,
        "publication profile operator_id {} does not match watchtower config operator_id {}",
        profile.operator_id,
        operator_id
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchtowerConfig {
    pub schema: String,
    pub operator_id: String,
    pub defaults: WatchtowerConfigDefaults,
    pub channels: Vec<WatchtowerChannelConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchtowerConfigDefaults {
    pub store_dir: Option<PathBuf>,
    pub watch_policy: Option<PathBuf>,
    pub publication_profile: Option<PathBuf>,
    pub publication_attempt_log: Option<PathBuf>,
    pub alert_file: Option<PathBuf>,
    pub detection_depth: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub poll_ms: Option<u64>,
    pub fee: Option<u64>,
    pub mine_blocks: Option<u64>,
    pub auto_fund_sponsor: Option<bool>,
    pub auto_sponsor_capacity: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchtowerChannelConfig {
    pub channel_id: String,
    pub from_block: u64,
    pub sponsor_out_point: Option<String>,
    pub store_dir: Option<PathBuf>,
    pub cursor_file: Option<PathBuf>,
    pub watch_policy: Option<PathBuf>,
    pub publication_profile: Option<PathBuf>,
    pub publication_attempt_log: Option<PathBuf>,
    pub alert_file: Option<PathBuf>,
    pub detection_depth: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub poll_ms: Option<u64>,
    pub fee: Option<u64>,
    pub mine_blocks: Option<u64>,
    pub auto_fund_sponsor: Option<bool>,
    pub auto_sponsor_capacity: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct WatchtowerRuntimeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: morph_key_input::SecretString,
}

#[derive(Debug, Clone)]
pub struct WatchtowerConfigLoopOptions {
    pub passes: u64,
    pub sleep_ms: u64,
    pub stop_after_publication: bool,
}

#[derive(Debug, Clone)]
pub struct WatchtowerConfigServiceOptions {
    pub max_passes: Option<u64>,
    pub sleep_ms: u64,
    pub error_backoff_ms: u64,
    pub max_consecutive_errors: u64,
    pub stop_after_publication: bool,
    pub stop_file: Option<PathBuf>,
    pub health_file: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerConfigRunReport {
    pub schema: String,
    pub operator_id: String,
    pub config_path: String,
    pub channel_count: usize,
    pub published_count: usize,
    pub idle_count: usize,
    pub failed_count: usize,
    pub config_digest: String,
    pub channels: Vec<WatchtowerChannelRunReport>,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerChannelRunReport {
    pub channel_id: String,
    pub report: serde_json::Value,
    pub observation: readiness::ChannelObservation,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerConfigLoopReport {
    pub schema: String,
    pub operator_id: String,
    pub config_path: String,
    pub requested_passes: u64,
    pub completed_passes: u64,
    pub stopped_after_publication: bool,
    pub published_count: usize,
    pub idle_count: usize,
    pub passes: Vec<WatchtowerConfigPassReport>,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerConfigPassReport {
    pub pass_number: u64,
    pub report: WatchtowerConfigRunReport,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerConfigServiceReport {
    pub schema: String,
    pub operator_id: String,
    pub config_path: String,
    pub completed_passes: u64,
    pub published_count: usize,
    pub idle_count: usize,
    pub error_count: u64,
    pub consecutive_errors: u64,
    pub stopped_reason: String,
    pub last_error: Option<String>,
    pub stop_file: Option<PathBuf>,
    pub health_file: Option<PathBuf>,
    pub last_pass: Option<WatchtowerConfigRunReport>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchtowerConfigServiceHealth {
    pub schema: String,
    pub operator_id: String,
    pub config_path: String,
    pub updated_unix_ms: u64,
    pub completed_passes: u64,
    pub published_count: usize,
    pub idle_count: usize,
    pub error_count: u64,
    pub consecutive_errors: u64,
    pub status: String,
    pub stopped_reason: Option<String>,
    pub last_error: Option<String>,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    pub config_digest: Option<String>,
    pub channels: Vec<readiness::ChannelObservation>,
}

impl WatchtowerConfig {
    pub fn fixture() -> Self {
        Self {
            schema: WATCH_CONFIG_SCHEMA.to_string(),
            operator_id: FIXTURE_OPERATOR_ID.to_string(),
            defaults: WatchtowerConfigDefaults {
                store_dir: Some(PathBuf::from(DEFAULT_STORE_DIR)),
                watch_policy: Some(PathBuf::from("watch-policy.json")),
                publication_profile: Some(PathBuf::from("publication-profile.json")),
                publication_attempt_log: Some(PathBuf::from("watch-publication-attempts.jsonl")),
                alert_file: Some(PathBuf::from("watch-alerts.jsonl")),
                detection_depth: Some(3),
                timeout_secs: Some(30),
                poll_ms: Some(1_000),
                fee: Some(DEFAULT_FEE),
                mine_blocks: Some(DEFAULT_MINE_BLOCKS),
                auto_fund_sponsor: Some(true),
                auto_sponsor_capacity: Some(DEFAULT_AUTO_SPONSOR_CAPACITY),
            },
            channels: vec![WatchtowerChannelConfig {
                channel_id: bytes32_hex(1),
                from_block: 0,
                sponsor_out_point: None,
                store_dir: None,
                cursor_file: None,
                watch_policy: None,
                publication_profile: None,
                publication_attempt_log: None,
                alert_file: None,
                detection_depth: None,
                timeout_secs: None,
                poll_ms: None,
                fee: None,
                mine_blocks: None,
                auto_fund_sponsor: None,
                auto_sponsor_capacity: None,
            }],
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == WATCH_CONFIG_SCHEMA,
            "unsupported watchtower config schema {}",
            self.schema
        );
        validate_operator_id(&self.operator_id)?;
        ensure!(
            (1..=32).contains(&self.channels.len()),
            "watchtower config must contain one to 32 channels"
        );
        ensure_positive(self.defaults.detection_depth, "default detection_depth")?;
        ensure_positive(self.defaults.timeout_secs, "default timeout_secs")?;
        ensure_positive(self.defaults.poll_ms, "default poll_ms")?;
        ensure_positive(self.defaults.fee, "default fee")?;
        ensure_positive(
            self.defaults.auto_sponsor_capacity,
            "default auto_sponsor_capacity",
        )?;

        let mut seen = BTreeSet::new();
        for channel in &self.channels {
            let canonical = canonical_hex32(&channel.channel_id)
                .context("watchtower config channel_id must be canonical hex32")?;
            ensure!(
                channel.channel_id == canonical,
                "watchtower config channel_id must be canonical"
            );
            ensure!(
                seen.insert(canonical.clone()),
                "watchtower config contains duplicate channel {}",
                channel.channel_id
            );
            ensure_positive(channel.detection_depth, "channel detection_depth")?;
            ensure_positive(channel.timeout_secs, "channel timeout_secs")?;
            ensure_positive(channel.poll_ms, "channel poll_ms")?;
            ensure_positive(channel.fee, "channel fee")?;
            ensure_positive(
                channel.auto_sponsor_capacity,
                "channel auto_sponsor_capacity",
            )?;

            let auto_fund_sponsor = channel
                .auto_fund_sponsor
                .or(self.defaults.auto_fund_sponsor)
                .unwrap_or(false);
            ensure!(
                channel.sponsor_out_point.is_some() || auto_fund_sponsor,
                "watchtower channel {} needs sponsor_out_point or auto_fund_sponsor",
                channel.channel_id
            );
            ensure!(
                channel.sponsor_out_point.is_none() || !auto_fund_sponsor,
                "watchtower channel {} must not combine sponsor_out_point with auto_fund_sponsor",
                channel.channel_id
            );
            let mine_blocks = channel
                .mine_blocks
                .or(self.defaults.mine_blocks)
                .unwrap_or(DEFAULT_MINE_BLOCKS);
            ensure!(
                !auto_fund_sponsor || mine_blocks > 0,
                "watchtower channel {} auto sponsor requires mine_blocks greater than zero",
                channel.channel_id
            );
        }
        Ok(())
    }

    pub fn validate_for_path(&self, config_path: &Path) -> Result<()> {
        self.validate()?;
        let base_dir = config_base_dir(config_path);
        for channel in &self.channels {
            let profile_path = optional_resolved_path(
                &base_dir,
                channel
                    .publication_profile
                    .as_ref()
                    .or(self.defaults.publication_profile.as_ref()),
            );
            let attempt_log = optional_resolved_path(
                &base_dir,
                channel
                    .publication_attempt_log
                    .as_ref()
                    .or(self.defaults.publication_attempt_log.as_ref()),
            );
            ensure!(
                profile_path.is_some() && attempt_log.is_some(),
                "watchtower channel {} needs an explicit publication_profile and publication_attempt_log for current bounded publication",
                channel.channel_id
            );
            if let Some(profile_path) = profile_path.as_ref() {
                validate_publication_profile_operator(profile_path, &self.operator_id)
                    .with_context(|| {
                        format!(
                            "invalid publication settings for channel {}",
                            channel.channel_id
                        )
                    })?;
            }
        }
        Ok(())
    }
}

pub fn fixture_config() -> WatchtowerConfig {
    WatchtowerConfig::fixture()
}

pub fn read_watchtower_config(path: &Path) -> Result<WatchtowerConfig> {
    let bytes = readiness::bounded(path)
        .with_context(|| format!("failed to read watchtower config {}", path.display()))?;
    let config: WatchtowerConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse watchtower config {}", path.display()))?;
    config
        .validate_for_path(path)
        .with_context(|| format!("invalid watchtower config {}", path.display()))?;
    Ok(config)
}

#[cfg(feature = "devnet")]
pub fn run_watchtower_config_once(
    rpc: &CkbRpcClient,
    config_path: &Path,
    config: &WatchtowerConfig,
    runtime: WatchtowerRuntimeOptions,
) -> Result<WatchtowerConfigRunReport> {
    config.validate_for_path(config_path)?;
    let base_dir = config_base_dir(config_path);
    let config_digest = readiness::config_digest(config_path, config)?;
    let reports = collect_channels(config, |channel| {
        let options = channel_options(&base_dir, &config.defaults, channel, &runtime)?;
        ensure!(
            options.timeout_secs <= 300,
            "watch pass timeout exceeds five minutes"
        );
        let bounded = CkbRpcClient::new_supervision(
            rpc.endpoint(),
            Duration::from_secs(options.timeout_secs + 5),
        )?;
        let report = multi_asset_watch::watch(&bounded, options)?;
        ensure!(
            report["operator_id"].as_str() == Some(config.operator_id.as_str()),
            "watch publication operator changed"
        );
        bounded.ensure_deadline()?;
        Ok(report)
    })?;
    ensure!(
        readiness::config_digest(config_path, &read_watchtower_config(config_path)?)?
            == config_digest,
        "watch configuration changed during pass"
    );
    let published_count = reports
        .iter()
        .filter(|channel| {
            terminal_publication_observed(
                channel.report["publication"]["canonical_confirmed"]
                    .as_bool()
                    .unwrap_or(false),
                channel.report["publication_reconciliation"]["confirmed"]
                    .as_u64()
                    .unwrap_or(0) as usize,
            )
        })
        .count();
    let failed_count = reports.iter().filter(|r| !r.observation.completed).count();
    Ok(WatchtowerConfigRunReport {
        schema: WATCH_CONFIG_RUN_SCHEMA.to_string(),
        operator_id: config.operator_id.clone(),
        config_path: config_path.display().to_string(),
        channel_count: reports.len(),
        published_count,
        idle_count: reports.len().saturating_sub(published_count + failed_count),
        failed_count,
        config_digest,
        channels: reports,
    })
}

#[cfg(feature = "devnet")]
fn collect_channels(
    config: &WatchtowerConfig,
    mut run: impl FnMut(&WatchtowerChannelConfig) -> Result<serde_json::Value>,
) -> Result<Vec<WatchtowerChannelRunReport>> {
    let mut reports = Vec::with_capacity(config.channels.len());
    for channel in &config.channels {
        let started = readiness::Stamp::now()?;
        let result = run(channel);
        let observation =
            readiness::ChannelObservation::from_result(&channel.channel_id, started, &result)?;
        // Only fixed errors leave the aggregate boundary; later channels still run.
        reports.push(WatchtowerChannelRunReport {
            channel_id: channel.channel_id.clone(),
            report: result.unwrap_or_else(|_| serde_json::json!({"status":"unavailable"})),
            observation,
        });
    }
    Ok(reports)
}

fn terminal_publication_observed(
    publication_canonical_confirmed: bool,
    reconciled_confirmed: usize,
) -> bool {
    publication_canonical_confirmed || reconciled_confirmed > 0
}

#[cfg(feature = "devnet")]
pub fn run_watchtower_config_loop(
    rpc: &CkbRpcClient,
    config_path: &Path,
    config: &WatchtowerConfig,
    runtime: WatchtowerRuntimeOptions,
    options: WatchtowerConfigLoopOptions,
) -> Result<WatchtowerConfigLoopReport> {
    config.validate()?;
    ensure!(
        options.passes > 0,
        "watchtower loop passes must be non-zero"
    );
    ensure!(
        options.passes <= MAX_LOOP_PASSES,
        "watchtower loop passes must not exceed {MAX_LOOP_PASSES}"
    );
    ensure!(
        options.sleep_ms > 0,
        "watchtower loop sleep_ms must be non-zero"
    );

    let mut pass_reports = Vec::with_capacity(options.passes as usize);
    let mut published_count = 0usize;
    let mut stopped_after_publication = false;

    for pass_number in 1..=options.passes {
        let reloaded = reload_config(config_path, &config.operator_id)?;
        let report = run_watchtower_config_once(rpc, config_path, &reloaded, runtime.clone())?;
        let pass_published = report.published_count;
        published_count += pass_published;
        pass_reports.push(WatchtowerConfigPassReport {
            pass_number,
            report,
        });

        if options.stop_after_publication && pass_published > 0 {
            stopped_after_publication = true;
            break;
        }

        if pass_number < options.passes {
            std::thread::sleep(Duration::from_millis(options.sleep_ms));
        }
    }

    let completed_passes = pass_reports.len() as u64;
    let total_idle = pass_reports
        .iter()
        .map(|pass| pass.report.idle_count)
        .sum::<usize>();
    Ok(WatchtowerConfigLoopReport {
        schema: WATCH_CONFIG_LOOP_SCHEMA.to_string(),
        operator_id: config.operator_id.clone(),
        config_path: config_path.display().to_string(),
        requested_passes: options.passes,
        completed_passes,
        stopped_after_publication,
        published_count,
        idle_count: total_idle,
        passes: pass_reports,
    })
}

#[cfg(feature = "devnet")]
pub fn run_watchtower_config_service(
    rpc: &CkbRpcClient,
    config_path: &Path,
    config: &WatchtowerConfig,
    runtime: WatchtowerRuntimeOptions,
    options: WatchtowerConfigServiceOptions,
) -> Result<WatchtowerConfigServiceReport> {
    validate_service_options(&options)?;
    config.validate()?;
    let _health_owner = options
        .health_file
        .as_ref()
        .map(|path| {
            crate::persistence::try_lock_private_path(path)?
                .ok_or_else(|| anyhow::anyhow!("watch health already owned"))
        })
        .transpose()?;

    let config_path_string = config_path.display().to_string();
    let mut completed_passes = 0u64;
    let mut published_count = 0usize;
    let mut idle_count = 0usize;
    let mut error_count = 0u64;
    let mut consecutive_errors = 0u64;
    let mut last_error = None;
    let mut last_pass = None;

    write_service_health_if_requested(
        &options.health_file,
        service_health(
            &config_path_string,
            &config.operator_id,
            "starting",
            None,
            completed_passes,
            published_count,
            idle_count,
            error_count,
            consecutive_errors,
            last_error.clone(),
            last_pass.as_ref(),
        )?,
    )?;

    let stopped_reason = loop {
        if stop_file_exists(&options.stop_file) {
            break "stop_file".to_string();
        }
        if options
            .max_passes
            .is_some_and(|max_passes| completed_passes >= max_passes)
        {
            break "max_passes".to_string();
        }

        match reload_config(config_path, &config.operator_id).and_then(|current| {
            run_watchtower_config_once(rpc, config_path, &current, runtime.clone())
        }) {
            Ok(report) => {
                completed_passes = completed_passes.saturating_add(1);
                published_count = published_count.saturating_add(report.published_count);
                idle_count = idle_count.saturating_add(report.idle_count);
                if report.failed_count > 0 {
                    error_count = error_count.saturating_add(report.failed_count as u64);
                }
                consecutive_errors = if report.failed_count == report.channel_count {
                    consecutive_errors.saturating_add(1)
                } else {
                    0
                };
                last_error = None;
                let pass_published = report.published_count;
                last_pass = Some(report);

                write_service_health_if_requested(
                    &options.health_file,
                    service_health(
                        &config_path_string,
                        &config.operator_id,
                        "running",
                        None,
                        completed_passes,
                        published_count,
                        idle_count,
                        error_count,
                        consecutive_errors,
                        None,
                        last_pass.as_ref(),
                    )?,
                )?;

                if consecutive_errors >= options.max_consecutive_errors {
                    break "max_consecutive_errors".to_string();
                }
                if options.stop_after_publication && pass_published > 0 {
                    break "publication".to_string();
                }
                if options
                    .max_passes
                    .is_some_and(|max_passes| completed_passes >= max_passes)
                {
                    break "max_passes".to_string();
                }
                std::thread::sleep(Duration::from_millis(options.sleep_ms));
            }
            Err(err) => {
                error_count = error_count.saturating_add(1);
                consecutive_errors = consecutive_errors.saturating_add(1);
                let _ = err;
                last_error = Some("watch_pass_unavailable".to_string());
                write_service_health_if_requested(
                    &options.health_file,
                    service_health(
                        &config_path_string,
                        &config.operator_id,
                        "error",
                        None,
                        completed_passes,
                        published_count,
                        idle_count,
                        error_count,
                        consecutive_errors,
                        last_error.clone(),
                        None,
                    )?,
                )?;
                if consecutive_errors >= options.max_consecutive_errors {
                    break "max_consecutive_errors".to_string();
                }
                std::thread::sleep(Duration::from_millis(options.error_backoff_ms));
            }
        }
    };

    write_service_health_if_requested(
        &options.health_file,
        service_health(
            &config_path_string,
            &config.operator_id,
            "stopped",
            Some(stopped_reason.clone()),
            completed_passes,
            published_count,
            idle_count,
            error_count,
            consecutive_errors,
            last_error.clone(),
            last_pass.as_ref(),
        )?,
    )?;

    Ok(WatchtowerConfigServiceReport {
        schema: WATCH_CONFIG_SERVICE_SCHEMA.to_string(),
        operator_id: config.operator_id.clone(),
        config_path: config_path_string,
        completed_passes,
        published_count,
        idle_count,
        error_count,
        consecutive_errors,
        stopped_reason,
        last_error,
        stop_file: options.stop_file,
        health_file: options.health_file,
        last_pass,
    })
}

#[cfg(feature = "devnet")]
fn reload_config(path: &Path, operator: &str) -> Result<WatchtowerConfig> {
    let current = read_watchtower_config(path)?;
    ensure!(
        current.operator_id == operator,
        "reloaded watch config changes operator identity; restart explicitly"
    );
    Ok(current)
}

#[cfg(feature = "devnet")]
fn channel_options(
    base_dir: &Path,
    defaults: &WatchtowerConfigDefaults,
    channel: &WatchtowerChannelConfig,
    runtime: &WatchtowerRuntimeOptions,
) -> Result<CurrentWatchOptions> {
    let store_dir = resolve_path(
        base_dir,
        channel
            .store_dir
            .as_ref()
            .or(defaults.store_dir.as_ref())
            .cloned()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STORE_DIR)),
    );
    let key = crate::devnet::parse_privkey(&runtime.private_key)
        .map_err(|_| anyhow::anyhow!("invalid watch sponsor funding key"))?;
    let change_pubkey = hex::encode(
        key.pubkey()
            .context("cannot derive watch sponsor change key")?
            .serialize(),
    );
    let auto = channel
        .auto_fund_sponsor
        .or(defaults.auto_fund_sponsor)
        .unwrap_or(false);
    let fee = channel.fee.or(defaults.fee).unwrap_or(DEFAULT_FEE);
    let publication_profile = optional_resolved_path(
        base_dir,
        channel
            .publication_profile
            .as_ref()
            .or(defaults.publication_profile.as_ref()),
    )
    .context("current watch requires publication_profile")?;
    let attempt_log = optional_resolved_path(
        base_dir,
        channel
            .publication_attempt_log
            .as_ref()
            .or(defaults.publication_attempt_log.as_ref()),
    )
    .context("current watch requires publication_attempt_log")?;
    let max_fee = read_publication_profile(&publication_profile)?.fee.max_fee;
    let cursor_file = optional_resolved_path(base_dir, channel.cursor_file.as_ref())
        .map(Ok)
        .unwrap_or_else(|| {
            crate::watch_cursor::default_watch_cursor_path(&store_dir, &channel.channel_id)
        })?;
    let alert_file = optional_resolved_path(
        base_dir,
        channel.alert_file.as_ref().or(defaults.alert_file.as_ref()),
    )
    .unwrap_or_else(|| {
        store_dir.join(format!(
            "watch-alerts-{}.jsonl",
            channel.channel_id.trim_start_matches("0x")
        ))
    });
    Ok(CurrentWatchOptions {
        contracts_dir: runtime.contracts_dir.clone(),
        fee_authorization: crate::devnet::multi_asset_operator::FeeAuthorization::Sponsor {
            change_pubkey,
        },
        fee_out_point: channel.sponsor_out_point.clone().unwrap_or_default(),
        store_dir,
        channel_id: channel.channel_id.clone(),
        from_block: channel.from_block,
        cursor_file,
        alert_file,
        publication_profile,
        attempt_log,
        watch_policy: optional_resolved_path(
            base_dir,
            channel
                .watch_policy
                .as_ref()
                .or(defaults.watch_policy.as_ref()),
        ),
        detection_depth: channel
            .detection_depth
            .or(defaults.detection_depth)
            .unwrap_or(DEFAULT_DETECTION_DEPTH),
        timeout_secs: channel
            .timeout_secs
            .or(defaults.timeout_secs)
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
        poll_ms: channel
            .poll_ms
            .or(defaults.poll_ms)
            .unwrap_or(DEFAULT_POLL_MS),
        max_fee,
        mine_blocks: channel
            .mine_blocks
            .or(defaults.mine_blocks)
            .unwrap_or(DEFAULT_MINE_BLOCKS),
        auto_fund_sponsor: auto.then(|| AutoSponsorFunding {
            private_key: runtime.private_key.clone(),
            capacity: channel
                .auto_sponsor_capacity
                .or(defaults.auto_sponsor_capacity)
                .unwrap_or(DEFAULT_AUTO_SPONSOR_CAPACITY),
            funding_fee: fee,
        }),
    })
}

fn ensure_positive(value: Option<u64>, field: &str) -> Result<()> {
    if let Some(value) = value {
        ensure!(value > 0, "{field} must be non-zero");
    }
    Ok(())
}

fn config_base_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn optional_resolved_path(base_dir: &Path, path: Option<&PathBuf>) -> Option<PathBuf> {
    path.cloned().map(|path| resolve_path(base_dir, path))
}

fn resolve_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn validate_service_options(options: &WatchtowerConfigServiceOptions) -> Result<()> {
    if let Some(max_passes) = options.max_passes {
        ensure!(
            max_passes > 0,
            "watchtower service max_passes must be non-zero"
        );
        ensure!(
            max_passes <= MAX_SERVICE_PASSES,
            "watchtower service max_passes must not exceed {MAX_SERVICE_PASSES}"
        );
    }
    ensure!(
        options.sleep_ms > 0,
        "watchtower service sleep_ms must be non-zero"
    );
    ensure!(
        options.error_backoff_ms > 0,
        "watchtower service error_backoff_ms must be non-zero"
    );
    ensure!(
        options.max_consecutive_errors > 0,
        "watchtower service max_consecutive_errors must be non-zero"
    );
    Ok(())
}

fn stop_file_exists(stop_file: &Option<PathBuf>) -> bool {
    stop_file.as_ref().is_some_and(|path| path.exists())
}

fn write_service_health_if_requested(
    path: &Option<PathBuf>,
    health: WatchtowerConfigServiceHealth,
) -> Result<()> {
    if let Some(path) = path {
        write_service_health(path, &health)?;
    }
    Ok(())
}

fn write_service_health(path: &Path, health: &WatchtowerConfigServiceHealth) -> Result<()> {
    crate::persistence::write_private_atomic(path, &serde_json::to_vec_pretty(health)?)
}

#[allow(clippy::too_many_arguments)]
fn service_health(
    config_path: &str,
    operator_id: &str,
    status: &str,
    stopped_reason: Option<String>,
    completed_passes: u64,
    published_count: usize,
    idle_count: usize,
    error_count: u64,
    consecutive_errors: u64,
    last_error: Option<String>,
    pass: Option<&WatchtowerConfigRunReport>,
) -> Result<WatchtowerConfigServiceHealth> {
    Ok(WatchtowerConfigServiceHealth {
        schema: WATCH_CONFIG_HEALTH_SCHEMA.to_string(),
        operator_id: operator_id.to_string(),
        config_path: config_path.to_string(),
        updated_unix_ms: now_unix_ms()?,
        completed_passes,
        published_count,
        idle_count,
        error_count,
        consecutive_errors,
        status: status.to_string(),
        stopped_reason,
        last_error,
        config_digest: pass.map(|p| p.config_digest.clone()),
        channels: pass
            .map(|p| p.channels.iter().map(|c| c.observation.clone()).collect())
            .unwrap_or_default(),
    })
}

fn now_unix_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?;
    Ok(elapsed.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_requires_explicit_operator_defaults_and_scan_origin() {
        let current = serde_json::to_value(WatchtowerConfig::fixture()).unwrap();
        for field in ["operator_id", "defaults"] {
            let mut incomplete = current.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<WatchtowerConfig>(incomplete).is_err());
        }
        let mut retired = current.clone();
        retired["schema"] = serde_json::json!("morph.watchtower_config");
        assert!(
            serde_json::from_value::<WatchtowerConfig>(retired)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut unknown = current.clone();
        unknown["channels"][0]["legacy_package"] = serde_json::json!("old.json");
        assert!(serde_json::from_value::<WatchtowerConfig>(unknown).is_err());
        let mut missing_origin = current;
        missing_origin["channels"][0]
            .as_object_mut()
            .unwrap()
            .remove("from_block");
        assert!(serde_json::from_value::<WatchtowerConfig>(missing_origin).is_err());
    }

    #[test]
    fn validates_fixture_config() {
        let config = WatchtowerConfig::fixture();
        config.validate().unwrap();
        assert_eq!(config.channels.len(), 1);
    }

    #[test]
    fn watch_profiles_reject_participant_keys_and_signer_handles_at_every_level() {
        let current = serde_json::to_value(WatchtowerConfig::fixture()).unwrap();
        for field in [
            "private_key",
            "participant_private_key",
            "signer_config",
            "participant_signer",
        ] {
            for pointer in ["", "/defaults", "/channels/0"] {
                let mut injected = current.clone();
                injected
                    .pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), serde_json::json!("not-a-watch-capability"));
                assert!(
                    serde_json::from_value::<WatchtowerConfig>(injected).is_err(),
                    "accepted {field} at {pointer}"
                );
            }
        }
    }

    #[test]
    fn rejects_duplicate_channels() {
        let mut config = WatchtowerConfig::fixture();
        config.channels.push(config.channels[0].clone());
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate channel"));
    }

    #[test]
    fn rejects_channel_without_sponsor_path() {
        let mut config = WatchtowerConfig::fixture();
        config.defaults.auto_fund_sponsor = Some(false);
        config.channels[0].sponsor_out_point = None;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("needs sponsor_out_point"));
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn resolves_channel_options_relative_to_config_file() {
        let dir = std::env::temp_dir().join(format!(
            "morph-current-watch-options-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let mut config = WatchtowerConfig::fixture();
        config.defaults.store_dir = Some(PathBuf::from("packages"));
        config.defaults.watch_policy = Some(PathBuf::from("policy.json"));
        config.defaults.alert_file = Some(PathBuf::from("alerts.jsonl"));
        config.defaults.publication_profile = Some(PathBuf::from("profile.json"));
        config.defaults.publication_attempt_log = Some(PathBuf::from("attempts.jsonl"));
        config.channels[0].cursor_file = Some(PathBuf::from("cursor.db"));
        let profile = crate::publication::fixture_publication_profile();
        fs::write(
            dir.join("profile.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        let options =
            channel_options(&dir, &config.defaults, &config.channels[0], &test_runtime()).unwrap();
        assert_eq!(options.store_dir, dir.join("packages"));
        assert_eq!(options.watch_policy, Some(dir.join("policy.json")));
        assert_eq!(options.alert_file, dir.join("alerts.jsonl"));
        assert_eq!(options.cursor_file, dir.join("cursor.db"));
        assert_eq!(options.max_fee, profile.fee.max_fee);
        assert_eq!(
            options.auto_fund_sponsor.as_ref().unwrap().capacity,
            DEFAULT_AUTO_SPONSOR_CAPACITY
        );
        assert!(options.fee_out_point.is_empty());
        assert!(matches!(
            options.fee_authorization,
            crate::devnet::multi_asset_operator::FeeAuthorization::Sponsor { .. }
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_publication_profile_operator_before_rpc_work() {
        let path = std::env::temp_dir().join(format!(
            "morph-watch-profile-operator-{}.json",
            std::process::id()
        ));
        let mut profile = crate::publication::fixture_publication_profile();
        profile.operator_id = "watchtower-b".to_string();
        fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let error = validate_publication_profile_operator(&path, "watchtower-a").unwrap_err();
        assert!(error.to_string().contains("does not match"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn config_preflight_requires_attempt_log_for_effective_profile() {
        let dir =
            std::env::temp_dir().join(format!("morph-watch-profile-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let profile_path = dir.join("profile.json");
        let config_path = dir.join("watch.json");
        let mut profile = crate::publication::fixture_publication_profile();
        profile.operator_id = FIXTURE_OPERATOR_ID.to_string();
        fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let mut config = WatchtowerConfig::fixture();
        config.defaults.publication_profile = Some(PathBuf::from("profile.json"));
        config.defaults.publication_attempt_log = None;
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

        let error = read_watchtower_config(&config_path).unwrap_err();
        assert!(format!("{error:#}").contains("publication_attempt_log"));

        config.defaults.publication_attempt_log = Some(PathBuf::from("attempts.jsonl"));
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        read_watchtower_config(&config_path).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn service_reload_revalidates_current_policy_paths_and_freezes_operator_identity() {
        let dir =
            std::env::temp_dir().join(format!("morph-watch-current-reload-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let mut profile = crate::publication::fixture_publication_profile();
        let mut config = WatchtowerConfig::fixture();
        config.operator_id = profile.operator_id.clone();
        config.defaults.publication_profile = Some(PathBuf::from("profile.json"));
        config.defaults.publication_attempt_log = Some(PathBuf::from("attempts.jsonl"));
        fs::write(
            dir.join("profile.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(reload_config(&path, &config.operator_id).unwrap(), config);
        config.defaults.poll_ms = Some(200);
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(
            reload_config(&path, &config.operator_id)
                .unwrap()
                .defaults
                .poll_ms,
            Some(200)
        );
        let original = config.operator_id.clone();
        profile.operator_id = "another-operator".to_string();
        config.operator_id = profile.operator_id.clone();
        fs::write(
            dir.join("profile.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(
            reload_config(&path, &original)
                .unwrap_err()
                .to_string()
                .contains("changes operator identity")
        );
        config.defaults.publication_profile = None;
        assert!(config.validate_for_path(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stop_count_requires_a_canonically_confirmed_publication() {
        assert!(!terminal_publication_observed(false, 0));
        assert!(terminal_publication_observed(true, 0));
        assert!(terminal_publication_observed(false, 1));
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn rejects_zero_loop_options() {
        let config = WatchtowerConfig::fixture();
        let runtime = test_runtime();
        let err = run_watchtower_config_loop(
            &CkbRpcClient::new("http://127.0.0.1:1").unwrap(),
            Path::new("watch.json"),
            &config,
            runtime.clone(),
            WatchtowerConfigLoopOptions {
                passes: 0,
                sleep_ms: 1_000,
                stop_after_publication: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("passes must be non-zero"));

        let err = run_watchtower_config_loop(
            &CkbRpcClient::new("http://127.0.0.1:1").unwrap(),
            Path::new("watch.json"),
            &config,
            runtime,
            WatchtowerConfigLoopOptions {
                passes: 1,
                sleep_ms: 0,
                stop_after_publication: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("sleep_ms must be non-zero"));
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn rejects_unbounded_loop_report_size() {
        let config = WatchtowerConfig::fixture();
        let runtime = test_runtime();
        let err = run_watchtower_config_loop(
            &CkbRpcClient::new("http://127.0.0.1:1").unwrap(),
            Path::new("watch.json"),
            &config,
            runtime,
            WatchtowerConfigLoopOptions {
                passes: MAX_LOOP_PASSES + 1,
                sleep_ms: 1_000,
                stop_after_publication: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not exceed"));
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn service_stops_before_rpc_when_stop_file_exists() {
        let dir =
            std::env::temp_dir().join(format!("morph-watch-service-{}-stop", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let stop_file = dir.join("stop");
        let health_file = dir.join("health.json");
        fs::write(&stop_file, b"stop").unwrap();
        let config = WatchtowerConfig::fixture();
        let runtime = test_runtime();

        let report = run_watchtower_config_service(
            &CkbRpcClient::new("http://127.0.0.1:1").unwrap(),
            &dir.join("watch.json"),
            &config,
            runtime,
            WatchtowerConfigServiceOptions {
                max_passes: None,
                sleep_ms: 1_000,
                error_backoff_ms: 1_000,
                max_consecutive_errors: 3,
                stop_after_publication: false,
                stop_file: Some(stop_file),
                health_file: Some(health_file.clone()),
            },
        )
        .unwrap();

        assert_eq!(report.stopped_reason, "stop_file");
        assert_eq!(report.completed_passes, 0);
        let health: WatchtowerConfigServiceHealth =
            serde_json::from_slice(&fs::read(&health_file).unwrap()).unwrap();
        assert_eq!(health.schema, WATCH_CONFIG_HEALTH_SCHEMA);
        assert_eq!(health.status, "stopped");
        assert_eq!(health.stopped_reason.as_deref(), Some("stop_file"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn service_stops_after_bounded_errors_and_writes_health() {
        let dir =
            std::env::temp_dir().join(format!("morph-watch-service-{}-error", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let health_file = dir.join("health.json");
        let config = WatchtowerConfig::fixture();
        let runtime = test_runtime();

        let report = run_watchtower_config_service(
            &CkbRpcClient::new("http://127.0.0.1:1").unwrap(),
            &dir.join("watch.json"),
            &config,
            runtime,
            WatchtowerConfigServiceOptions {
                max_passes: None,
                sleep_ms: 1,
                error_backoff_ms: 1,
                max_consecutive_errors: 1,
                stop_after_publication: false,
                stop_file: None,
                health_file: Some(health_file.clone()),
            },
        )
        .unwrap();

        assert_eq!(report.stopped_reason, "max_consecutive_errors");
        assert_eq!(report.completed_passes, 0);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.consecutive_errors, 1);
        assert!(report.last_error.is_some());

        let health: WatchtowerConfigServiceHealth =
            serde_json::from_slice(&fs::read(&health_file).unwrap()).unwrap();
        assert_eq!(health.schema, WATCH_CONFIG_HEALTH_SCHEMA);
        assert_eq!(health.status, "stopped");
        assert_eq!(
            health.stopped_reason.as_deref(),
            Some("max_consecutive_errors")
        );
        assert_eq!(health.completed_passes, 0);
        assert_eq!(health.error_count, 1);
        assert_eq!(health.consecutive_errors, 1);
        assert!(health.last_error.is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn rejects_invalid_service_options() {
        let config = WatchtowerConfig::fixture();
        let runtime = test_runtime();
        let err = run_watchtower_config_service(
            &CkbRpcClient::new("http://127.0.0.1:1").unwrap(),
            Path::new("watch.json"),
            &config,
            runtime,
            WatchtowerConfigServiceOptions {
                max_passes: Some(0),
                sleep_ms: 1_000,
                error_backoff_ms: 1_000,
                max_consecutive_errors: 3,
                stop_after_publication: false,
                stop_file: None,
                health_file: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("max_passes must be non-zero"));
    }

    fn test_runtime() -> WatchtowerRuntimeOptions {
        WatchtowerRuntimeOptions {
            contracts_dir: PathBuf::from("contracts"),
            private_key: private_key_hex(1).into(),
        }
    }

    fn private_key_hex(seed: u8) -> String {
        format!("0x{}", format!("{seed:02x}").repeat(32))
    }
}
