use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::packages::canonical_hex32;

const WATCH_POLICY_SCHEMA: &str = "morph.watchtower_policy";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerPolicy {
    pub schema: String,
    pub channel_id: Option<String>,
    pub min_detection_depth: u64,
    pub min_timeout_secs: u64,
    pub max_poll_ms: u64,
    pub max_fee: u64,
    pub allow_explicit_sponsor: bool,
    pub require_auto_fund_sponsor: bool,
    pub max_auto_sponsor_capacity: u64,
    pub require_mine_blocks: bool,
    pub allow_webhook_alerts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchPolicyRun<'a> {
    pub channel_id: &'a str,
    pub detection_depth: u64,
    pub timeout_secs: u64,
    pub poll_ms: u64,
    pub fee: u64,
    pub mine_blocks: u64,
    pub sponsor_out_point_present: bool,
    pub auto_fund_sponsor: bool,
    pub auto_sponsor_capacity: u64,
    pub alert_webhook_present: bool,
}

impl WatchtowerPolicy {
    pub fn fixture() -> Self {
        Self {
            schema: WATCH_POLICY_SCHEMA.to_string(),
            channel_id: None,
            min_detection_depth: 3,
            min_timeout_secs: 30,
            max_poll_ms: 1_000,
            max_fee: 200_000_000,
            allow_explicit_sponsor: true,
            require_auto_fund_sponsor: false,
            max_auto_sponsor_capacity: 50_000_000_000,
            require_mine_blocks: true,
            allow_webhook_alerts: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == WATCH_POLICY_SCHEMA,
            "unsupported watchtower policy schema {}",
            self.schema
        );
        if let Some(channel_id) = &self.channel_id {
            ensure!(
                channel_id == &canonical_hex32(channel_id)?,
                "watchtower policy channel_id must be canonical"
            );
        }
        ensure!(
            self.min_detection_depth > 0,
            "watchtower policy min_detection_depth must be at least one"
        );
        ensure!(
            self.max_poll_ms > 0,
            "watchtower policy max_poll_ms must be non-zero"
        );
        ensure!(
            self.max_fee > 0,
            "watchtower policy max_fee must be non-zero"
        );
        ensure!(
            self.max_auto_sponsor_capacity >= self.max_fee,
            "watchtower policy max_auto_sponsor_capacity must cover max_fee"
        );
        ensure!(
            self.allow_explicit_sponsor || self.require_auto_fund_sponsor,
            "watchtower policy must allow an explicit sponsor or require auto funding"
        );
        Ok(())
    }

    pub fn validate_run(&self, run: &WatchPolicyRun<'_>) -> Result<()> {
        self.validate()?;
        let run_channel_id = canonical_hex32(run.channel_id)?;
        if let Some(policy_channel_id) = &self.channel_id {
            ensure!(
                policy_channel_id == &run_channel_id,
                "watchtower policy is for channel {}, not {}",
                policy_channel_id,
                run_channel_id
            );
        }
        ensure!(
            run.detection_depth >= self.min_detection_depth,
            "watchtower detection depth {} is below policy minimum {}",
            run.detection_depth,
            self.min_detection_depth
        );
        ensure!(
            run.timeout_secs >= self.min_timeout_secs,
            "watchtower timeout {}s is below policy minimum {}s",
            run.timeout_secs,
            self.min_timeout_secs
        );
        ensure!(run.poll_ms > 0, "watchtower poll interval must be non-zero");
        ensure!(
            run.poll_ms <= self.max_poll_ms,
            "watchtower poll interval {}ms exceeds policy maximum {}ms",
            run.poll_ms,
            self.max_poll_ms
        );
        ensure!(
            run.fee <= self.max_fee,
            "watchtower fee {} exceeds policy maximum {}",
            run.fee,
            self.max_fee
        );
        if !self.allow_explicit_sponsor {
            ensure!(
                !run.sponsor_out_point_present,
                "watchtower policy does not allow an explicit sponsor out point"
            );
        }
        if self.require_auto_fund_sponsor {
            ensure!(
                run.auto_fund_sponsor,
                "watchtower policy requires auto-funded sponsor rotation"
            );
        }
        if run.auto_fund_sponsor {
            ensure!(
                run.auto_sponsor_capacity <= self.max_auto_sponsor_capacity,
                "watchtower auto sponsor capacity {} exceeds policy maximum {}",
                run.auto_sponsor_capacity,
                self.max_auto_sponsor_capacity
            );
        }
        if self.require_mine_blocks {
            ensure!(
                run.mine_blocks > 0,
                "watchtower policy requires mine_blocks greater than zero"
            );
        }
        if run.alert_webhook_present {
            ensure!(
                self.allow_webhook_alerts,
                "watchtower policy does not allow webhook alerts"
            );
        }
        Ok(())
    }
}

pub fn fixture_policy() -> WatchtowerPolicy {
    WatchtowerPolicy::fixture()
}

pub fn read_watchtower_policy(path: &Path) -> Result<WatchtowerPolicy> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read watchtower policy {}", path.display()))?;
    let policy: WatchtowerPolicy = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse watchtower policy {}", path.display()))?;
    policy
        .validate()
        .with_context(|| format!("invalid watchtower policy {}", path.display()))?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_run() -> WatchPolicyRun<'static> {
        WatchPolicyRun {
            channel_id: Box::leak(bytes32_hex(1).into_boxed_str()),
            detection_depth: 3,
            timeout_secs: 30,
            poll_ms: 1_000,
            fee: 100_000_000,
            mine_blocks: 4,
            sponsor_out_point_present: true,
            auto_fund_sponsor: false,
            auto_sponsor_capacity: 50_000_000_000,
            alert_webhook_present: false,
        }
    }

    #[test]
    fn accepts_fixture_policy_run() {
        WatchtowerPolicy::fixture()
            .validate_run(&valid_run())
            .unwrap();
    }

    #[test]
    fn rejects_shallow_detection_depth() {
        let mut run = valid_run();
        run.detection_depth = 1;
        let err = WatchtowerPolicy::fixture().validate_run(&run).unwrap_err();
        assert!(err.to_string().contains("below policy minimum"));
    }

    #[test]
    fn rejects_fee_above_operator_limit() {
        let mut run = valid_run();
        run.fee = 300_000_000;
        let err = WatchtowerPolicy::fixture().validate_run(&run).unwrap_err();
        assert!(err.to_string().contains("exceeds policy maximum"));
    }

    #[test]
    fn rejects_explicit_sponsor_when_policy_forbids_it() {
        let mut policy = WatchtowerPolicy::fixture();
        policy.allow_explicit_sponsor = false;
        policy.require_auto_fund_sponsor = true;

        let mut run = valid_run();
        run.auto_fund_sponsor = true;

        let err = policy.validate_run(&run).unwrap_err();
        assert!(err.to_string().contains("explicit sponsor"));
    }

    #[test]
    fn rejects_wrong_channel_policy() {
        let mut policy = WatchtowerPolicy::fixture();
        policy.channel_id = Some(bytes32_hex(2));

        let err = policy.validate_run(&valid_run()).unwrap_err();
        assert!(err.to_string().contains("not"));
    }

    #[test]
    fn rejects_webhook_when_policy_forbids_it() {
        let mut policy = WatchtowerPolicy::fixture();
        policy.allow_webhook_alerts = false;

        let mut run = valid_run();
        run.alert_webhook_present = true;

        let err = policy.validate_run(&run).unwrap_err();
        assert!(err.to_string().contains("webhook alerts"));
    }

    fn bytes32_hex(seed: u8) -> String {
        format!("0x{}", format!("{seed:02x}").repeat(32))
    }
}
