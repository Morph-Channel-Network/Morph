//! Expiring per-resource scan observations, not future publication authority.
use super::*;
use crate::publication::BudgetReason;
use crate::publication::PublicationBudget;
use morph_observability::clock::{self, BootClock};
use std::io::Read;

const LEASE_MS: u64 = 600_000;
const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    wall_ms: u64,
    boot_ms: u64,
    boot_id: String,
}
impl Stamp {
    #[cfg(feature = "devnet")]
    pub fn now() -> Result<Self> {
        let boot = clock::read()?;
        Ok(Self {
            wall_ms: now_unix_ms()?,
            boot_ms: boot.ms,
            boot_id: boot.id,
        })
    }
    fn fresh(&self, wall: u64, boot: &BootClock) -> bool {
        self.boot_id == boot.id
            && wall
                .checked_sub(self.wall_ms)
                .is_some_and(|age| age < LEASE_MS)
            && boot
                .ms
                .checked_sub(self.boot_ms)
                .is_some_and(|age| age < LEASE_MS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelObservation {
    pub channel_id: String,
    pub started: Stamp,
    pub completed: bool,
    pub caught_up: bool,
    pub reorg_reset: bool,
    pub publication_confirmed: bool,
    pub budget_checked: Stamp,
    pub publication_budget: PublicationBudget,
}
impl ChannelObservation {
    #[cfg(feature = "devnet")]
    pub fn from_result(
        channel: &str,
        started: Stamp,
        result: &Result<serde_json::Value>,
    ) -> Result<Self> {
        let report = result.as_ref().ok();
        Ok(Self {
            channel_id: canonical_hex32(channel)?,
            started,
            completed: report.is_some(),
            caught_up: report.is_some_and(|r| r["caught_up"].as_bool() == Some(true)),
            reorg_reset: report.is_some_and(|r| !r["reorg_recovery"].is_null()),
            publication_confirmed: report
                .is_some_and(|r| r["publication"]["canonical_confirmed"].as_bool() == Some(true)),
            budget_checked: Stamp::now()?,
            publication_budget: report
                .and_then(|r| serde_json::from_value(r["publication_budget"].clone()).ok())
                .unwrap_or(PublicationBudget::NotPrepared {
                    reason: BudgetReason::PreflightUnavailable,
                }),
        })
    }
}

pub(super) fn bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BYTES,
        "watch observation input too large"
    );
    Ok(bytes)
}

pub(super) fn config_digest(path: &Path, config: &WatchtowerConfig) -> Result<String> {
    let base = fs::canonicalize(config_base_dir(path))?;
    let location = base.join(path.file_name().context("missing config file name")?);
    let mut bytes = serde_json::to_vec(&(location, config))?;
    let mut paths = BTreeSet::new();
    for channel in &config.channels {
        for p in [
            channel
                .watch_policy
                .as_ref()
                .or(config.defaults.watch_policy.as_ref()),
            channel
                .publication_profile
                .as_ref()
                .or(config.defaults.publication_profile.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            paths.insert(resolve_path(&base, p.clone()));
        }
    }
    for p in paths {
        // Fixed-width hashes after canonical config bytes avoid concatenation
        // ambiguity; config commits the path mapping itself.
        bytes.extend(morph_core::blake2b256(&bounded(&p)?));
    }
    Ok(hex::encode(morph_core::blake2b256(&bytes)))
}

fn assessment(
    config: &WatchtowerConfig,
    digest: &str,
    health: &WatchtowerConfigServiceHealth,
    wall: u64,
    boot: &BootClock,
) -> serde_json::Value {
    let bound = health.schema == WATCH_CONFIG_HEALTH_SCHEMA
        && health.config_digest.as_deref() == Some(digest)
        && health.operator_id == config.operator_id
        && health.status == "running"
        && health.channels.len() == config.channels.len()
        && health
            .channels
            .iter()
            .zip(&config.channels)
            .all(|(h, c)| h.channel_id == c.channel_id);
    let resources = config
        .channels
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let h = health.channels.get(i);
            let fresh = bound && h.is_some_and(|h| h.started.fresh(wall, boot));
            let completed = fresh && h.is_some_and(|h| h.completed);
            let caught_up = completed && h.is_some_and(|h| h.caught_up);
            let current_budget = h.filter(|h| caught_up && budget_fresh(h, wall, boot));
            let summary = current_budget.and_then(|h| budget_summary(h, wall, boot));
            let reason = if !fresh {
                "evidence_unavailable"
            } else if !completed {
                "scan_failed"
            } else if !caught_up {
                "scan_behind"
            } else if let Some(h) = current_budget {
                match &h.publication_budget {
                    PublicationBudget::NotPrepared { reason } => match reason {
                        BudgetReason::FundingNotPrepared => "funding_not_prepared",
                        BudgetReason::SourceNotObserved => "source_not_observed",
                        BudgetReason::RecoveryNotAvailable => "recovery_not_available",
                        BudgetReason::PreflightUnavailable => "preflight_unavailable",
                        BudgetReason::SourceConsumed => "source_consumed",
                    },
                    PublicationBudget::Verified { .. } if summary.is_none() => "budget_invalid",
                    PublicationBudget::Verified { .. } if h.publication_budget.ready() => "ready",
                    PublicationBudget::Verified { .. } => "fee_headroom_insufficient",
                }
            } else {
                "budget_expired"
            };
            let publication_ready = reason == "ready";
            serde_json::json!({"resource_index":i,"evidence_fresh":fresh,
            "scan_completed":completed,"caught_up":caught_up,
            "publication_ready":publication_ready,"reason":reason,
            "budget_summary":summary,
            "publication_budget":current_budget.map(|h| &h.publication_budget),
            "reorg_reset":fresh && h.is_some_and(|h| h.reorg_reset),
            "publication_confirmed":fresh && h.is_some_and(|h| h.publication_confirmed)})
        })
        .collect::<Vec<_>>();
    let ready = !resources.is_empty() && resources.iter().all(|r| r["caught_up"] == true);
    let publication_ready = ready && resources.iter().all(|r| r["publication_ready"] == true);
    serde_json::json!({"schema":"morph.watchtower_readiness.v3","scan_coverage_ready":ready,
        "publication_ready":publication_ready,
        "scope":"scan_coverage","lease_ms":LEASE_MS.to_string(),
        "resources":resources})
}

const REASONS: [&str; 12] = [
    "evidence_unavailable",
    "scan_failed",
    "scan_behind",
    "budget_expired",
    "funding_not_prepared",
    "source_not_observed",
    "recovery_not_available",
    "preflight_unavailable",
    "source_consumed",
    "budget_invalid",
    "fee_headroom_insufficient",
    "ready",
];

fn quote_age(h: &ChannelObservation, wall: u64, boot: &BootClock) -> Option<u64> {
    let checked = &h.budget_checked;
    if checked.boot_id != boot.id {
        return None;
    }
    let wall_age = wall.checked_sub(checked.wall_ms)?;
    let boot_age = boot.ms.checked_sub(checked.boot_ms)?;
    if wall_age >= 30_000 || boot_age >= 30_000 {
        return None;
    }
    let age = match &h.publication_budget {
        PublicationBudget::Verified {
            observed_unix_ms, ..
        } => {
            let initial = checked.wall_ms.checked_sub(*observed_unix_ms)?;
            wall.checked_sub(*observed_unix_ms)?
                .max(initial.checked_add(boot_age)?)
        }
        PublicationBudget::NotPrepared { .. } => wall_age.max(boot_age),
    };
    (age < 30_000).then_some(age)
}
fn budget_fresh(h: &ChannelObservation, wall: u64, boot: &BootClock) -> bool {
    quote_age(h, wall, boot).is_some_and(|age| match h.publication_budget {
        PublicationBudget::Verified { execution_ms, .. } => age < execution_ms,
        PublicationBudget::NotPrepared { .. } => true,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetSummary {
    #[serde(with = "morph_packages::public_encoding::decimal")]
    fee_headroom_shannons: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    fee_shortfall_shannons: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    execution_remaining_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    observation_ttl_ms: u64,
}
fn budget_summary(h: &ChannelObservation, wall: u64, boot: &BootClock) -> Option<BudgetSummary> {
    let age = quote_age(h, wall, boot)?;
    let PublicationBudget::Verified {
        initial_fee,
        profile_fee_ceiling,
        operator_fee_cap,
        sponsor_remaining,
        sponsor_per_tx,
        capacity_after_change_floor,
        full_fee_ceiling_supported,
        execution_blocks,
        execution_ms,
        tx_size_bytes,
        ..
    } = &h.publication_budget
    else {
        return None;
    };
    let available = *operator_fee_cap
        .min(sponsor_remaining)
        .min(sponsor_per_tx)
        .min(capacity_after_change_floor);
    if *initial_fee == 0
        || initial_fee > profile_fee_ceiling
        || *execution_blocks == 0
        || *tx_size_bytes == 0
        || (*full_fee_ceiling_supported != (available >= *profile_fee_ceiling))
    {
        return None;
    }
    let remaining = execution_ms
        .checked_sub(age)
        .filter(|remaining| *remaining > 0)?;
    Some(BudgetSummary {
        fee_headroom_shannons: available.saturating_sub(*profile_fee_ceiling),
        fee_shortfall_shannons: profile_fee_ceiling.saturating_sub(available),
        execution_remaining_ms: remaining,
        observation_ttl_ms: (30_000 - age).min(remaining),
    })
}

/// Read-only and keyless. This report never claims a sponsor can fund a future
/// dispute, nor that the latest saved package is the latest privately signed one.
pub fn inspect_health(config: &Path, health: &Path, metrics: bool) -> Result<()> {
    let config_value = read_watchtower_config(config)?;
    let digest = config_digest(config, &config_value)?;
    let saved: WatchtowerConfigServiceHealth = serde_json::from_slice(&bounded(health)?)?;
    ensure!(
        config_digest(config, &read_watchtower_config(config)?)? == digest,
        "watch configuration changed during health read"
    );
    let report = assessment(
        &config_value,
        &digest,
        &saved,
        now_unix_ms()?,
        &clock::read()?,
    );
    if metrics {
        print!("{}", render_metrics(&report));
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report["publication_ready"] == true,
            "watch publication readiness not verified"
        );
    }
    Ok(())
}

fn render_metrics(report: &serde_json::Value) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for name in ["scan_coverage_ready", "publication_ready"] {
        let value = u8::from(report[name] == true);
        let _ = writeln!(
            text,
            "# TYPE morph_watch_{name} gauge\nmorph_watch_{name} {value}"
        );
    }
    if let Some(resources) = report["resources"].as_array() {
        let _ = writeln!(
            text,
            "# TYPE morph_watch_resources gauge\nmorph_watch_resources {}",
            resources.len()
        );
        for name in [
            "evidence_fresh",
            "scan_completed",
            "caught_up",
            "reorg_reset",
            "publication_confirmed",
        ] {
            let value = resources.iter().filter(|r| r[name] == true).count();
            let _ = writeln!(
                text,
                "# TYPE morph_watch_{name} gauge\nmorph_watch_{name} {value}"
            );
        }
        let prepared = resources
            .iter()
            .filter(|r| r["publication_ready"] == true)
            .count();
        let _ = writeln!(
            text,
            "# TYPE morph_watch_publication_ready_resources gauge\nmorph_watch_publication_ready_resources {prepared}"
        );
    }
    let resources = report["resources"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let _ = writeln!(text, "# TYPE morph_watch_readiness_reason_resources gauge");
    for reason in REASONS {
        let count = resources.iter().filter(|r| r["reason"] == reason).count();
        let _ = writeln!(
            text,
            "morph_watch_readiness_reason_resources{{reason=\"{reason}\"}} {count}"
        );
    }
    let budgets: Vec<BudgetSummary> = resources
        .iter()
        .filter_map(|r| serde_json::from_value(r["budget_summary"].clone()).ok())
        .collect();
    let _ = writeln!(
        text,
        "# TYPE morph_watch_budget_quoted_resources gauge\nmorph_watch_budget_quoted_resources {}",
        budgets.len()
    );
    for (name, value) in [
        (
            "min_fee_headroom_shannons",
            budgets.iter().map(|b| b.fee_headroom_shannons).min(),
        ),
        (
            "max_fee_shortfall_shannons",
            budgets.iter().map(|b| b.fee_shortfall_shannons).max(),
        ),
        (
            "min_execution_remaining_ms",
            budgets.iter().map(|b| b.execution_remaining_ms).min(),
        ),
        (
            "min_observation_ttl_ms",
            budgets.iter().map(|b| b.observation_ttl_ms).min(),
        ),
    ] {
        let _ = writeln!(
            text,
            "# TYPE morph_watch_{name} gauge\nmorph_watch_{name} {}",
            value.map(|n| n.to_string()).unwrap_or_else(|| "NaN".into())
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (WatchtowerConfig, WatchtowerConfigServiceHealth, BootClock) {
        let mut config = WatchtowerConfig::fixture();
        let mut second = config.channels[0].clone();
        second.channel_id = bytes32_hex(18);
        config.channels.push(second);
        let boot = BootClock {
            id: "test-boot".into(),
            ms: 1000,
        };
        let mut health = service_health(
            "private-config",
            &config.operator_id,
            "running",
            None,
            1,
            0,
            2,
            0,
            0,
            None,
            None,
        )
        .unwrap();
        health.config_digest = Some("digest".into());
        health.channels = config
            .channels
            .iter()
            .map(|c| ChannelObservation {
                channel_id: c.channel_id.clone(),
                started: Stamp {
                    wall_ms: 1000,
                    boot_ms: 1000,
                    boot_id: boot.id.clone(),
                },
                completed: true,
                caught_up: true,
                reorg_reset: false,
                publication_confirmed: false,
                budget_checked: Stamp {
                    wall_ms: 1000,
                    boot_ms: 1000,
                    boot_id: boot.id.clone(),
                },
                publication_budget: PublicationBudget::NotPrepared {
                    reason: BudgetReason::FundingNotPrepared,
                },
            })
            .collect();
        (config, health, boot)
    }
    fn quote() -> PublicationBudget {
        PublicationBudget::Verified {
            observed_unix_ms: 1000,
            initial_fee: 10,
            profile_fee_ceiling: 100,
            operator_fee_cap: 200,
            sponsor_remaining: 200,
            sponsor_per_tx: 200,
            capacity_after_change_floor: 200,
            full_fee_ceiling_supported: true,
            execution_blocks: 2,
            execution_ms: 10_000,
            tx_size_bytes: 1000,
        }
    }
    #[test]
    fn margins_preserve_partial_coverage_shortfalls_and_fixed_metric_labels() {
        let (config, mut health, boot) = fixture();
        health.channels[0].publication_budget = quote();
        let partial = assessment(&config, "digest", &health, 1000, &boot);
        assert_eq!(partial["schema"], "morph.watchtower_readiness.v3");
        assert_eq!(partial["publication_ready"], false);
        assert_eq!(partial["resources"][0]["reason"], "ready");
        assert_eq!(partial["resources"][1]["reason"], "funding_not_prepared");
        let text = render_metrics(&partial);
        assert!(text.contains("morph_watch_budget_quoted_resources 1\n"));
        assert!(text.contains("morph_watch_min_fee_headroom_shannons 100\n"));
        assert_eq!(text.lines().filter(|s| !s.starts_with('#')).count(), 26);
        assert_eq!(
            text.lines()
                .filter(|s| !s.starts_with('#'))
                .map(|s| s.split(' ').next().unwrap())
                .collect::<BTreeSet<_>>()
                .len(),
            26
        );
        health.channels[1].publication_budget = quote();
        if let PublicationBudget::Verified {
            operator_fee_cap,
            full_fee_ceiling_supported,
            ..
        } = &mut health.channels[0].publication_budget
        {
            *operator_fee_cap = 80;
            *full_fee_ceiling_supported = false;
        }
        let limited = assessment(&config, "digest", &health, 1000, &boot);
        assert_eq!(
            limited["resources"][0]["reason"],
            "fee_headroom_insufficient"
        );
        let text = render_metrics(&limited);
        assert!(text.contains("morph_watch_budget_quoted_resources 2\n"));
        assert!(text.contains("morph_watch_min_fee_headroom_shannons 0\n"));
        assert!(text.contains("morph_watch_max_fee_shortfall_shannons 20\n"));
        assert!(!text.contains(&config.channels[0].channel_id));
        if let PublicationBudget::Verified {
            full_fee_ceiling_supported,
            ..
        } = &mut health.channels[0].publication_budget
        {
            *full_fee_ceiling_supported = true; // contradictory persisted quote
        }
        let invalid = assessment(&config, "digest", &health, 1000, &boot);
        assert_eq!(invalid["resources"][0]["reason"], "budget_invalid");
        assert!(invalid["resources"][0]["budget_summary"].is_null());
        health.status = "stopped".into();
        let stopped = render_metrics(&assessment(&config, "digest", &health, 1000, &boot));
        assert!(stopped.contains(
            "morph_watch_readiness_reason_resources{reason=\"evidence_unavailable\"} 2\n"
        ));
        assert!(stopped.contains("morph_watch_budget_quoted_resources 0\n"));
        assert_eq!(stopped.lines().filter(|s| s.ends_with(" NaN")).count(), 4);
    }
    #[test]
    fn remaining_time_uses_initial_quote_age_and_boot_elapsed_not_only_wall_time() {
        let (config, mut health, mut boot) = fixture();
        for h in &mut health.channels {
            h.publication_budget = quote();
            h.budget_checked.wall_ms = 1500;
        }
        boot.ms = 2000; // 1000 ms after capture; quote was already 500 ms old
        let report = assessment(&config, "digest", &health, 1600, &boot);
        assert_eq!(report["publication_ready"], true);
        assert_eq!(
            report["resources"][0]["budget_summary"]["execution_remaining_ms"],
            "8500"
        );
        assert_eq!(
            report["resources"][0]["budget_summary"]["observation_ttl_ms"],
            "8500"
        );
        boot.ms = 10_500; // initial 500 + elapsed 9500 exhausts the quote
        let expired = assessment(&config, "digest", &health, 1600, &boot);
        assert_eq!(expired["scan_coverage_ready"], true);
        assert_eq!(expired["publication_ready"], false);
        assert_eq!(expired["resources"][0]["reason"], "budget_expired");
        assert!(expired["resources"][0]["budget_summary"].is_null());
    }
    #[test]
    fn each_resource_has_one_fixed_diagnosis_without_hiding_other_resources() {
        let (config, health, boot) = fixture();
        for reason in [
            BudgetReason::FundingNotPrepared,
            BudgetReason::SourceNotObserved,
            BudgetReason::RecoveryNotAvailable,
            BudgetReason::PreflightUnavailable,
            BudgetReason::SourceConsumed,
        ] {
            let mut h = health.clone_for_test();
            h.channels[0].publication_budget = PublicationBudget::NotPrepared { reason };
            let report = assessment(&config, "digest", &h, 1000, &boot);
            assert_eq!(
                report["resources"][0]["reason"],
                serde_json::to_value(reason).unwrap()
            );
        }
        for (mode, expected) in [
            (0, "scan_failed"),
            (1, "scan_behind"),
            (2, "budget_expired"),
            (3, "evidence_unavailable"),
        ] {
            let mut h = health.clone_for_test();
            h.channels[1].publication_budget = quote();
            match mode {
                0 => h.channels[0].completed = false,
                1 => h.channels[0].caught_up = false,
                2 => h.channels[0].budget_checked.boot_id = "another-boot".into(),
                _ => h.channels[0].started.boot_id = "another-boot".into(),
            }
            let report = assessment(&config, "digest", &h, 1000, &boot);
            assert_eq!(report["resources"][0]["reason"], expected);
            assert_eq!(report["resources"][1]["reason"], "ready");
            let text = render_metrics(&report);
            let total: u64 = text
                .lines()
                .filter(|s| s.starts_with("morph_watch_readiness_reason_resources{"))
                .map(|s| s.rsplit(' ').next().unwrap().parse::<u64>().unwrap())
                .sum();
            assert_eq!(total, 2);
        }
    }
    #[test]
    fn fresh_scan_is_not_a_future_publication_guarantee() {
        let (config, mut health, boot) = fixture();
        let ready = assessment(&config, "digest", &health, 1000, &boot);
        assert_eq!(ready["scan_coverage_ready"], true);
        assert_eq!(ready["publication_ready"], false);
        assert_eq!(
            ready["resources"][0]["publication_budget"]["reason"],
            "funding_not_prepared"
        );
        health.channels[0].completed = false;
        let partial = assessment(&config, "digest", &health, 1000, &boot);
        assert_eq!(partial["scan_coverage_ready"], false);
        assert_eq!(partial["resources"][1]["caught_up"], true);
        let metrics = render_metrics(&partial);
        assert_eq!(metrics.lines().filter(|l| !l.starts_with('#')).count(), 26);
        assert!(!metrics.contains(&config.channels[0].channel_id));
        assert!(!metrics.contains("private-config"));
    }
    #[test]
    fn publication_requires_full_fee_headroom_and_short_fresh_window() {
        let (config, mut health, boot) = fixture();
        let budget = PublicationBudget::Verified {
            observed_unix_ms: 1000,
            initial_fee: 10,
            profile_fee_ceiling: 100,
            operator_fee_cap: 100,
            sponsor_remaining: 100,
            sponsor_per_tx: 100,
            capacity_after_change_floor: 100,
            full_fee_ceiling_supported: true,
            execution_blocks: 2,
            execution_ms: 20_000,
            tx_size_bytes: 1000,
        };
        for h in &mut health.channels {
            h.publication_budget = budget.clone();
        }
        assert_eq!(
            assessment(&config, "digest", &health, 1000, &boot)["publication_ready"],
            true
        );
        let later = BootClock {
            id: boot.id.clone(),
            ms: 21_000,
        };
        assert_eq!(
            assessment(&config, "digest", &health, 21_000, &later)["publication_ready"],
            false
        );
        assert_eq!(
            assessment(&config, "digest", &health, 21_000, &later)["scan_coverage_ready"],
            true
        );
        let mut value = serde_json::to_value(&budget).unwrap();
        for field in [
            "operator_fee_cap",
            "sponsor_remaining",
            "sponsor_per_tx",
            "capacity_after_change_floor",
        ] {
            value[field] = serde_json::json!("99");
            let limited: PublicationBudget = serde_json::from_value(value.clone()).unwrap();
            assert!(
                !limited.ready(),
                "{field} below declared ceiling must reject even if flag is true"
            );
            value[field] = serde_json::json!("100");
        }
        value["full_fee_ceiling_supported"] = serde_json::json!(false);
        assert!(
            !serde_json::from_value::<PublicationBudget>(value)
                .unwrap()
                .ready()
        );
        let wrong_boot = BootClock {
            id: "another-boot".into(),
            ms: 1000,
        };
        assert_eq!(
            assessment(&config, "digest", &health, 1000, &wrong_boot)["publication_ready"],
            false
        );
    }
    #[test]
    fn stale_boot_clock_schema_order_config_and_stop_all_revoke_scan_readiness() {
        let (config, health, boot) = fixture();
        for mutation in 0..8 {
            let mut bad = health.clone_for_test();
            match mutation {
                0 => bad.schema = "morph.watchtower_health".into(),
                1 => bad.config_digest = Some("other".into()),
                2 => bad.status = "stopped".into(),
                3 => bad.channels.swap(0, 1),
                4 => {
                    bad.channels.pop();
                }
                5 => bad.channels[0].started.boot_id = "reboot".into(),
                6 => bad.channels[0].started.wall_ms = 1001,
                _ => bad.channels[0].started.boot_ms = 1001,
            }
            assert_eq!(
                assessment(&config, "digest", &bad, 1000, &boot)["scan_coverage_ready"],
                false
            );
        }
        let later = BootClock {
            id: boot.id,
            ms: 1000 + LEASE_MS,
        };
        assert_eq!(
            assessment(&config, "digest", &health, 1000, &later)["scan_coverage_ready"],
            false
        );
        let mut missing = serde_json::to_value(&health).unwrap();
        missing.as_object_mut().unwrap().remove("config_digest");
        assert!(serde_json::from_value::<WatchtowerConfigServiceHealth>(missing).is_err());
    }
    impl WatchtowerConfigServiceHealth {
        fn clone_for_test(&self) -> Self {
            serde_json::from_value(serde_json::to_value(self).unwrap()).unwrap()
        }
    }
    #[cfg(feature = "devnet")]
    #[test]
    fn failed_resource_does_not_skip_next_resource_or_leak_error_body() {
        let (config, _, _) = fixture();
        let mut visited = Vec::new();
        let reports = collect_channels(&config, |channel| {
            visited.push(channel.channel_id.clone());
            if visited.len() == 1 {
                anyhow::bail!("private-RPC-error-token");
            }
            Ok(serde_json::json!({"caught_up":true}))
        })
        .unwrap();
        assert_eq!(visited.len(), 2);
        assert!(!reports[0].observation.completed);
        assert!(reports[1].observation.caught_up);
        assert!(
            !serde_json::to_string(&reports)
                .unwrap()
                .contains("private-RPC-error-token")
        );
        let recovered =
            collect_channels(&config, |_| Ok(serde_json::json!({"caught_up":true}))).unwrap();
        assert!(recovered.iter().all(|r| r.observation.caught_up));
    }
    #[test]
    fn policy_content_changes_invalidate_same_config_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = WatchtowerConfig::fixture();
        let path = dir.path().join("config.json");
        fs::write(dir.path().join("watch-policy.json"), b"policy-a").unwrap();
        fs::write(dir.path().join("publication-profile.json"), b"profile-a").unwrap();
        let first = config_digest(&path, &config).unwrap();
        fs::write(dir.path().join("watch-policy.json"), b"policy-b").unwrap();
        assert_ne!(config_digest(&path, &config).unwrap(), first);
        assert_ne!(
            config_digest(&dir.path().join("another-config.json"), &config).unwrap(),
            config_digest(&path, &config).unwrap()
        );
    }
}
