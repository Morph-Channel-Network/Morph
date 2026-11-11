use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::Status;
use ckb_types::H256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::rpc::{CkbRpcClient, rpc_method_error};

const PUBLICATION_PROFILE_SCHEMA: &str = "morph.publication_profile";
const PUBLICATION_ATTEMPT_SCHEMA: &str = "morph.publication_attempt";
const CHALLENGE_WINDOW_DATASET_SCHEMA: &str = "morph.challenge_window_dataset";
const CHALLENGE_WINDOW_ASSESSMENT_SCHEMA: &str = "morph.challenge_window_assessment";
const BASIS_POINTS_DENOMINATOR: u64 = 10_000;
const FEE_RATE_BYTES: u64 = 1_000;
const MIN_PRODUCTION_SAMPLES: usize = 1_000;
const MIN_PRODUCTION_SAMPLES_PER_FAULT: usize = 1_000;
const MAX_PUBLICATION_PROFILE_BYTES: usize = 64 * 1024;
const MAX_ATTEMPT_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHALLENGE_DATASET_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHALLENGE_SAMPLES: usize = 1_000_000;
const MAX_FAULT_LABELS_PER_SAMPLE: usize = 32;
const MAX_FAULT_LABEL_BYTES: usize = 64;
const CKB_POOL_REJECTED_RBF_CODE: i64 = -1111;
const PUBLIC_CKB_NETWORKS: [&str; 2] = ["ckb", "ckb_testnet"];
const PUBLICATION_PROFILE_DIGEST_DOMAIN: &[u8] = b"CKB_MORPH_PUBLICATION_PROFILE_V1";
const REQUIRED_PRODUCTION_FAULT_LABELS: [&str; 5] = [
    "ordinary_load",
    "fee_pressure",
    "rpc_delay",
    "operator_failover",
    "induced_reorg",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationProfile {
    pub schema: String,
    pub operator_id: String,
    pub fee: PublicationFeePolicy,
    pub window: PublicationWindowPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationFeePolicy {
    pub min_fee_rate: u64,
    pub max_fee_rate: u64,
    pub max_fee: u64,
    pub estimator_multiplier_bps: u64,
    pub replacement_multiplier_bps: u64,
    pub max_attempts: u16,
    pub bump_after_ms: u64,
    pub require_rbf: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationWindowPolicy {
    pub configured_challenge_blocks: u64,
    pub conservative_block_ms: u64,
    pub canonical_confirmation_blocks: u64,
    pub reorg_budget_blocks: u64,
    pub failover_budget_blocks: u64,
    pub safety_margin_blocks: u64,
    pub max_measurement_age_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeObservation {
    pub observed_unix_ms: u64,
    pub estimator_fee_rate: u64,
    pub confirmed_mean_fee_rate: Option<u64>,
    pub confirmed_median_fee_rate: Option<u64>,
    pub pool_min_fee_rate: u64,
    pub pool_min_rbf_rate: u64,
    pub pool_pending: u64,
    pub pool_proposed: u64,
    pub pool_total_tx_size: u64,
    pub rbf_enabled: bool,
}

/// Exact-source, read-only quote. It is not a reservation or a promise that
/// capacity, fees or the canonical source will remain unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationBudget {
    NotPrepared {
        reason: BudgetReason,
    },
    Verified {
        #[serde(with = "morph_packages::public_encoding::decimal")]
        observed_unix_ms: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        initial_fee: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        profile_fee_ceiling: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        operator_fee_cap: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        sponsor_remaining: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        sponsor_per_tx: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        capacity_after_change_floor: u64,
        full_fee_ceiling_supported: bool,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        execution_blocks: u64,
        #[serde(with = "morph_packages::public_encoding::decimal")]
        execution_ms: u64,
        tx_size_bytes: usize,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetReason {
    FundingNotPrepared,
    SourceNotObserved,
    RecoveryNotAvailable,
    PreflightUnavailable,
    SourceConsumed,
}

impl PublicationBudget {
    pub fn ready(&self) -> bool {
        match self {
            Self::Verified {
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
            } => {
                *full_fee_ceiling_supported
                    && *initial_fee > 0
                    && initial_fee <= profile_fee_ceiling
                    && profile_fee_ceiling <= operator_fee_cap
                    && profile_fee_ceiling
                        <= sponsor_remaining
                            .min(sponsor_per_tx)
                            .min(capacity_after_change_floor)
                    && *execution_blocks > 0
                    && *execution_ms > 0
                    && *tx_size_bytes > 0
            }
            Self::NotPrepared { .. } => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationAttemptRecord {
    pub schema: String,
    pub recorded_unix_ms: u64,
    pub operator_id: String,
    pub intent_id: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub target_state_number: u64,
    pub attempt: u16,
    pub fee: u64,
    pub fee_rate: u64,
    pub tx_size_bytes: usize,
    pub tx_hash: String,
    pub replaces_tx_hash: Option<String>,
    pub node_min_replace_fee: Option<u64>,
    pub status: String,
    pub error_class: Option<String>,
    pub elapsed_ms: u64,
    pub fee_observation: FeeObservation,
    pub tip_number: u64,
    pub tip_hash: String,
}

pub struct PublicationAttemptInput {
    pub fee_observation: FeeObservation,
    pub intent_id: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub target_state_number: u64,
    pub attempt: u16,
    pub fee: u64,
    pub tx_size_bytes: usize,
    pub tx_hash: String,
    pub replaces_tx_hash: Option<String>,
    pub node_min_replace_fee: Option<u64>,
    pub status: String,
    pub error_class: Option<String>,
    pub elapsed_ms: u64,
    pub tip_number: u64,
    pub tip_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicationReconciliationReport {
    pub operator_id: String,
    pub inspected: usize,
    pub appended: usize,
    pub confirmed: usize,
    pub committed: usize,
    pub rejected: usize,
    pub pending: usize,
    pub proposed: usize,
    pub unknown: usize,
    pub recovered_trailing_bytes: u64,
    pub recovered_tail_path: Option<String>,
    pub normalized_unterminated_record: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindowDataset {
    pub schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub ckb_version: String,
    pub profile_digest: String,
    pub generated_unix_ms: u64,
    pub samples: Vec<ChallengeWindowSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindowSample {
    pub started_unix_ms: u64,
    pub end_to_end_ms: u64,
    pub detection_ms: u64,
    pub build_and_verify_ms: u64,
    pub queue_and_rbf_ms: u64,
    pub confirmation_ms: u64,
    pub reorg_recovery_ms: u64,
    pub failover_ms: u64,
    pub fault_labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChallengeWindowAssessment {
    pub schema: String,
    pub network: String,
    pub genesis_hash: String,
    pub ckb_version: String,
    pub profile_digest: String,
    pub generated_unix_ms: u64,
    pub oldest_sample_started_unix_ms: u64,
    pub newest_sample_ended_unix_ms: u64,
    pub observed_fault_labels: Vec<String>,
    pub fault_label_sample_counts: BTreeMap<String, usize>,
    pub fault_label_p999_end_to_end_ms: BTreeMap<String, u64>,
    pub production: bool,
    pub production_provenance_verified: bool,
    pub production_network_eligible: bool,
    pub unique_samples: bool,
    pub fault_evidence_valid: bool,
    pub rbf_profile_eligible: bool,
    pub sufficient_samples: bool,
    pub fresh: bool,
    pub required_faults_present: bool,
    pub sufficient_fault_samples: bool,
    pub missing_fault_labels: Vec<String>,
    pub under_sampled_fault_labels: Vec<String>,
    pub deployed_challenge_blocks: Option<u64>,
    pub deployment_matches_profile: bool,
    pub sample_count: usize,
    pub p50_end_to_end_ms: u64,
    pub p95_end_to_end_ms: u64,
    pub p99_end_to_end_ms: u64,
    pub p999_end_to_end_ms: u64,
    pub worst_required_fault_p999_end_to_end_ms: Option<u64>,
    pub effective_p999_end_to_end_ms: u64,
    pub max_end_to_end_ms: u64,
    pub measured_latency_blocks: u64,
    pub required_challenge_blocks: u64,
    pub configured_challenge_blocks: u64,
    pub passes: bool,
}

impl PublicationProfile {
    pub fn fixture() -> Self {
        Self {
            schema: PUBLICATION_PROFILE_SCHEMA.to_string(),
            operator_id: "watchtower-a".to_string(),
            fee: PublicationFeePolicy {
                min_fee_rate: 1_000,
                max_fee_rate: 200_000_000,
                max_fee: 200_000_000,
                estimator_multiplier_bps: 12_500,
                replacement_multiplier_bps: 12_500,
                max_attempts: 3,
                bump_after_ms: 1_000,
                require_rbf: true,
            },
            window: PublicationWindowPolicy {
                configured_challenge_blocks: 24,
                conservative_block_ms: 10_000,
                canonical_confirmation_blocks: 4,
                reorg_budget_blocks: 6,
                failover_budget_blocks: 3,
                safety_margin_blocks: 6,
                max_measurement_age_secs: 7 * 24 * 60 * 60,
            },
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == PUBLICATION_PROFILE_SCHEMA,
            "unsupported publication profile schema {}",
            self.schema
        );
        validate_operator_id(&self.operator_id)?;
        ensure!(self.fee.min_fee_rate > 0, "min_fee_rate must be non-zero");
        ensure!(
            self.fee.max_fee_rate >= self.fee.min_fee_rate,
            "max_fee_rate must be at least min_fee_rate"
        );
        ensure!(self.fee.max_fee > 0, "max_fee must be non-zero");
        ensure!(
            self.fee.estimator_multiplier_bps >= BASIS_POINTS_DENOMINATOR,
            "estimator_multiplier_bps must not reduce the node estimate"
        );
        ensure!(
            self.fee.replacement_multiplier_bps > BASIS_POINTS_DENOMINATOR,
            "replacement_multiplier_bps must increase the previous fee"
        );
        ensure!(self.fee.max_attempts > 0, "max_attempts must be non-zero");
        ensure!(self.fee.bump_after_ms > 0, "bump_after_ms must be non-zero");
        ensure!(
            !self.fee.require_rbf || self.fee.max_attempts >= 2,
            "require_rbf needs at least two publication attempts"
        );
        ensure!(
            self.fee.require_rbf || self.fee.max_attempts == 1,
            "max_attempts must be one when require_rbf is false"
        );
        ensure!(
            self.window.configured_challenge_blocks > 0,
            "configured_challenge_blocks must be non-zero"
        );
        ensure!(
            self.window.conservative_block_ms > 0,
            "conservative_block_ms must be non-zero"
        );
        ensure!(
            self.window.canonical_confirmation_blocks > 0,
            "canonical_confirmation_blocks must be non-zero"
        );
        ensure!(
            self.window.max_measurement_age_secs > 0,
            "max_measurement_age_secs must be non-zero"
        );
        let static_window_budget = self
            .window
            .canonical_confirmation_blocks
            .checked_add(self.window.reorg_budget_blocks)
            .and_then(|value| value.checked_add(self.window.failover_budget_blocks))
            .and_then(|value| value.checked_add(self.window.safety_margin_blocks))
            .ok_or_else(|| anyhow!("static challenge-window budget overflow"))?;
        ensure!(
            self.window.configured_challenge_blocks >= static_window_budget,
            "configured_challenge_blocks {} is below the static confirmation/reorg/failover/safety budget {static_window_budget}",
            self.window.configured_challenge_blocks
        );
        let retry_ladder_ms = u64::from(self.fee.max_attempts.saturating_sub(1))
            .checked_mul(self.fee.bump_after_ms)
            .ok_or_else(|| anyhow!("publication retry ladder duration overflow"))?;
        let retry_budget_ms = self
            .window
            .configured_challenge_blocks
            .checked_sub(static_window_budget)
            .and_then(|blocks| blocks.checked_mul(self.window.conservative_block_ms))
            .ok_or_else(|| anyhow!("publication retry budget duration overflow"))?;
        ensure!(
            retry_ladder_ms < retry_budget_ms,
            "publication retry ladder {retry_ladder_ms}ms does not fit strictly inside the challenge-window retry budget {retry_budget_ms}ms"
        );
        Ok(())
    }

    pub fn observe_fee_market(&self, rpc: &CkbRpcClient) -> Result<FeeObservation> {
        self.validate()?;
        let pool = rpc.tx_pool_info()?;
        let statistics = rpc.fee_rate_statistics(None)?;
        let observation = FeeObservation {
            observed_unix_ms: unix_ms()?,
            estimator_fee_rate: rpc.estimate_fee_rate()?,
            confirmed_mean_fee_rate: statistics.as_ref().map(|stats| stats.mean.value()),
            confirmed_median_fee_rate: statistics.as_ref().map(|stats| stats.median.value()),
            pool_min_fee_rate: pool.min_fee_rate.value(),
            pool_min_rbf_rate: pool.min_rbf_rate.value(),
            pool_pending: pool.pending.value(),
            pool_proposed: pool.proposed.value(),
            pool_total_tx_size: pool.total_tx_size.value(),
            rbf_enabled: pool.min_rbf_rate.value() > pool.min_fee_rate.value(),
        };
        validate_rbf_requirement(&self.fee, &observation)?;
        Ok(observation)
    }
}

fn validate_rbf_requirement(
    policy: &PublicationFeePolicy,
    observation: &FeeObservation,
) -> Result<()> {
    ensure!(
        !policy.require_rbf || observation.rbf_enabled,
        "publication profile requires RBF, but node min_rbf_rate {} is not greater than min_fee_rate {}",
        observation.pool_min_rbf_rate,
        observation.pool_min_fee_rate
    );
    Ok(())
}

pub fn read_publication_profile(path: &Path) -> Result<PublicationProfile> {
    let bytes = read_bounded_file(path, MAX_PUBLICATION_PROFILE_BYTES, "publication profile")?;
    let profile: PublicationProfile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse publication profile {}", path.display()))?;
    profile
        .validate()
        .with_context(|| format!("invalid publication profile {}", path.display()))?;
    Ok(profile)
}

pub fn publication_profile_digest(profile: &PublicationProfile) -> Result<String> {
    profile.validate()?;
    let encoded = serde_json::to_vec(profile).context("failed to encode publication profile")?;
    let mut committed = Vec::with_capacity(PUBLICATION_PROFILE_DIGEST_DOMAIN.len() + encoded.len());
    committed.extend_from_slice(PUBLICATION_PROFILE_DIGEST_DOMAIN);
    committed.extend_from_slice(&encoded);
    Ok(format!("0x{}", hex::encode(blake2b_256(&committed))))
}

pub fn initial_fee_rate(
    policy: &PublicationFeePolicy,
    observation: &FeeObservation,
) -> Result<u64> {
    let multiplied_estimate = multiply_bps(
        observation.estimator_fee_rate,
        policy.estimator_multiplier_bps,
    )?;
    let rate = policy
        .min_fee_rate
        .max(observation.pool_min_fee_rate)
        .max(multiplied_estimate)
        .max(observation.confirmed_mean_fee_rate.unwrap_or_default())
        .max(observation.confirmed_median_fee_rate.unwrap_or_default());
    ensure!(
        rate <= policy.max_fee_rate,
        "required fee rate {rate} exceeds operator maximum {}",
        policy.max_fee_rate
    );
    Ok(rate)
}

pub fn fee_for_rate(fee_rate: u64, tx_size_bytes: usize) -> Result<u64> {
    ensure!(tx_size_bytes > 0, "transaction size must be non-zero");
    let product = u128::from(fee_rate)
        .checked_mul(tx_size_bytes as u128)
        .ok_or_else(|| anyhow!("fee calculation overflow"))?;
    let fee = product
        .checked_add(u128::from(FEE_RATE_BYTES - 1))
        .ok_or_else(|| anyhow!("fee rounding overflow"))?
        / u128::from(FEE_RATE_BYTES);
    u64::try_from(fee).map_err(|_| anyhow!("calculated fee exceeds u64"))
}

pub fn effective_fee_rate(fee: u64, tx_size_bytes: usize) -> Result<u64> {
    ensure!(tx_size_bytes > 0, "transaction size must be non-zero");
    let numerator = u128::from(fee)
        .checked_mul(u128::from(FEE_RATE_BYTES))
        .ok_or_else(|| anyhow!("effective fee-rate overflow"))?;
    u64::try_from(numerator / tx_size_bytes as u128)
        .map_err(|_| anyhow!("effective fee rate exceeds u64"))
}

pub fn verify_initial_fee_convergence(
    selected_fee_rate: u64,
    fee: u64,
    final_tx_size_bytes: usize,
) -> Result<u64> {
    let expected_fee = fee_for_rate(selected_fee_rate, final_tx_size_bytes)?;
    ensure!(
        fee == expected_fee,
        "rebuilt publication fee {fee} did not converge for final transaction size {final_tx_size_bytes}; expected {expected_fee} at selected fee rate {selected_fee_rate}"
    );
    let effective_rate = effective_fee_rate(fee, final_tx_size_bytes)?;
    ensure!(
        effective_rate >= selected_fee_rate,
        "rebuilt publication effective fee rate {effective_rate} is below selected fee rate {selected_fee_rate}"
    );
    Ok(effective_rate)
}

pub fn replacement_fee(
    policy: &PublicationFeePolicy,
    old_fee: u64,
    tx_size_bytes: usize,
    pool_min_rbf_rate: u64,
    node_min_replace_fee: Option<u64>,
) -> Result<u64> {
    let multiplied = multiply_bps(old_fee, policy.replacement_multiplier_bps)?;
    let incremental = old_fee
        .checked_add(fee_for_rate(pool_min_rbf_rate, tx_size_bytes)?)
        .ok_or_else(|| anyhow!("replacement fee overflow"))?;
    let fee = multiplied
        .max(incremental)
        .max(node_min_replace_fee.unwrap_or_default());
    ensure!(
        fee <= policy.max_fee,
        "replacement fee {fee} exceeds operator maximum {}",
        policy.max_fee
    );
    let maximum_fee_at_rate = fee_for_rate(policy.max_fee_rate, tx_size_bytes)?;
    ensure!(
        fee <= maximum_fee_at_rate,
        "replacement fee {fee} exceeds operator maximum fee rate {} for {tx_size_bytes} bytes",
        policy.max_fee_rate
    );
    Ok(fee)
}

/// Extract CKB's authoritative replacement floor from a `PoolRejectedRBF`
/// response. A competing operator may not know the transaction hash it is
/// replacing, so the first submission is also the only race-safe way to learn
/// the aggregate conflict fee used by the node.
pub fn required_replacement_fee_from_error(error: &anyhow::Error) -> Option<u64> {
    let rpc_error = rpc_method_error(error)?;
    required_replacement_fee_from_parts(rpc_error.code(), rpc_error.message())
}

fn required_replacement_fee_from_parts(code: i64, message: &str) -> Option<u64> {
    const REQUIREMENT: &str = "expect it to >=";

    if code != CKB_POOL_REJECTED_RBF_CODE {
        return None;
    }
    let suffix = message.split_once(REQUIREMENT)?.1.trim_start();
    let digits = suffix
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

pub fn append_publication_attempt(path: &Path, record: &PublicationAttemptRecord) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        crate::persistence::create_private_directories(parent).with_context(|| {
            format!(
                "failed to create attempt-log directory {}",
                parent.display()
            )
        })?;
    }
    let mut encoded = serde_json::to_vec(record).with_context(|| {
        format!(
            "failed to encode publication attempt for {}",
            path.display()
        )
    })?;
    encoded.push(b'\n');
    let appended_len =
        u64::try_from(encoded.len()).context("publication attempt record length exceeds u64")?;
    let mut file = open_private_append(path)?;
    file.lock()
        .with_context(|| format!("failed to lock publication attempt log {}", path.display()))?;
    let existing_len = file
        .metadata()
        .with_context(|| format!("failed to stat publication attempt log {}", path.display()))?
        .len();
    ensure!(
        existing_len
            .checked_add(appended_len)
            .is_some_and(|length| length <= MAX_ATTEMPT_LOG_BYTES),
        "publication attempt log {} reached the {}-byte rotation limit",
        path.display(),
        MAX_ATTEMPT_LOG_BYTES
    );
    file.write_all(&encoded)
        .with_context(|| format!("failed to append publication attempt to {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("failed to sync publication attempt log {}", path.display()))?;
    Ok(())
}

pub fn reconcile_publication_attempts(
    rpc: &CkbRpcClient,
    path: &Path,
    profile: &PublicationProfile,
) -> Result<PublicationReconciliationReport> {
    profile.validate()?;
    let operator_id = profile.operator_id.as_str();
    validate_operator_id(operator_id)?;
    if !path.exists() {
        return Ok(PublicationReconciliationReport {
            operator_id: operator_id.to_string(),
            inspected: 0,
            appended: 0,
            confirmed: 0,
            committed: 0,
            rejected: 0,
            pending: 0,
            proposed: 0,
            unknown: 0,
            recovered_trailing_bytes: 0,
            recovered_tail_path: None,
            normalized_unterminated_record: false,
        });
    }
    let log_len = fs::metadata(path)
        .with_context(|| format!("failed to stat publication attempt log {}", path.display()))?
        .len();
    ensure!(
        log_len <= MAX_ATTEMPT_LOG_BYTES,
        "publication attempt log {} exceeds the {}-byte reconciliation limit; rotate it before restart",
        path.display(),
        MAX_ATTEMPT_LOG_BYTES
    );
    let (content, recovered_trailing_bytes, recovered_tail_path, normalized_unterminated_record) =
        recover_attempt_log_tail(path)?;
    let mut latest_by_hash = BTreeMap::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: PublicationAttemptRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "invalid publication attempt at {} line {}",
                path.display(),
                index + 1
            )
        })?;
        ensure!(
            record.schema == PUBLICATION_ATTEMPT_SCHEMA,
            "unsupported publication attempt schema {} at {} line {}",
            record.schema,
            path.display(),
            index + 1
        );
        if record.operator_id == operator_id {
            latest_by_hash.insert(record.tx_hash.clone(), record);
        }
    }

    let mut report = PublicationReconciliationReport {
        operator_id: operator_id.to_string(),
        inspected: 0,
        appended: 0,
        confirmed: 0,
        committed: 0,
        rejected: 0,
        pending: 0,
        proposed: 0,
        unknown: 0,
        recovered_trailing_bytes,
        recovered_tail_path,
        normalized_unterminated_record,
    };
    for record in latest_by_hash.into_values() {
        // No locally recorded status is terminal across restart: committed
        // transactions can be orphaned, and a submission error may have been
        // ambiguous. Re-query every latest hash against the current node view.
        report.inspected += 1;
        let tx_hash = record
            .tx_hash
            .strip_prefix("0x")
            .unwrap_or(&record.tx_hash)
            .parse::<H256>()
            .with_context(|| {
                format!(
                    "invalid transaction hash in attempt log: {}",
                    record.tx_hash
                )
            })?;
        let status = rpc.transaction(tx_hash)?;
        let normalized = match status.tx_status.status {
            Status::Committed => {
                let canonical_confirmations = if let (Some(number), Some(hash)) = (
                    status.tx_status.block_number.as_ref(),
                    status.tx_status.block_hash.as_ref(),
                ) {
                    let block_number = number.value();
                    match rpc.block_by_number(block_number)? {
                        Some(block) if &block.header.hash == hash => {
                            let tip_number = rpc.tip_header()?.number_value()?;
                            Some(tip_number.saturating_sub(block_number).saturating_add(1))
                        }
                        Some(_) | None => None,
                    }
                } else {
                    None
                };
                match canonical_confirmations {
                    Some(confirmations)
                        if confirmations >= profile.window.canonical_confirmation_blocks =>
                    {
                        report.confirmed += 1;
                        "confirmed"
                    }
                    Some(_) => {
                        report.committed += 1;
                        "committed"
                    }
                    None => {
                        report.unknown += 1;
                        "unknown"
                    }
                }
            }
            Status::Rejected => {
                report.rejected += 1;
                "rejected"
            }
            Status::Pending => {
                report.pending += 1;
                "pending"
            }
            Status::Proposed => {
                report.proposed += 1;
                "proposed"
            }
            Status::Unknown => {
                report.unknown += 1;
                "unknown"
            }
        };
        if record.status == normalized {
            continue;
        }
        let tip = rpc.tip_header()?;
        let error_class = if matches!(record.status.as_str(), "committed" | "confirmed")
            && !matches!(normalized, "committed" | "confirmed")
        {
            Some("canonicality_lost".to_string())
        } else {
            status.tx_status.reason.as_deref().and_then(|reason| {
                if reason.contains("RBFRejected") {
                    Some("rbf_replaced".to_string())
                } else if normalized == "rejected" {
                    Some("transaction_rejected".to_string())
                } else {
                    None
                }
            })
        };
        let mut reconciled = record;
        reconciled.recorded_unix_ms = unix_ms()?;
        reconciled.status = normalized.to_string();
        reconciled.error_class = error_class;
        reconciled.tip_number = tip.number_value()?;
        reconciled.tip_hash = tip.hash;
        append_publication_attempt(path, &reconciled)?;
        report.appended += 1;
    }
    Ok(report)
}

pub fn publication_attempt_record(
    profile: &PublicationProfile,
    input: PublicationAttemptInput,
) -> Result<PublicationAttemptRecord> {
    Ok(PublicationAttemptRecord {
        schema: PUBLICATION_ATTEMPT_SCHEMA.to_string(),
        recorded_unix_ms: unix_ms()?,
        operator_id: profile.operator_id.clone(),
        intent_id: input.intent_id,
        channel_id: input.channel_id,
        funding_context_id: input.funding_context_id,
        target_state_number: input.target_state_number,
        attempt: input.attempt,
        fee: input.fee,
        fee_rate: effective_fee_rate(input.fee, input.tx_size_bytes)?,
        tx_size_bytes: input.tx_size_bytes,
        tx_hash: input.tx_hash,
        replaces_tx_hash: input.replaces_tx_hash,
        node_min_replace_fee: input.node_min_replace_fee,
        status: input.status,
        error_class: input.error_class,
        elapsed_ms: input.elapsed_ms,
        fee_observation: input.fee_observation,
        tip_number: input.tip_number,
        tip_hash: input.tip_hash,
    })
}

pub fn read_challenge_window_dataset(path: &Path) -> Result<ChallengeWindowDataset> {
    let bytes = read_bounded_file(
        path,
        MAX_CHALLENGE_DATASET_BYTES,
        "challenge-window dataset",
    )?;
    let dataset: ChallengeWindowDataset = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse challenge-window dataset {}",
            path.display()
        )
    })?;
    validate_challenge_window_dataset(&dataset)?;
    Ok(dataset)
}

pub fn challenge_window_dataset_sha256(path: &Path) -> Result<String> {
    let bytes = read_bounded_file(
        path,
        MAX_CHALLENGE_DATASET_BYTES,
        "challenge-window dataset",
    )?;
    Ok(format!("0x{}", hex::encode(Sha256::digest(bytes))))
}

pub fn assess_challenge_window(
    profile: &PublicationProfile,
    dataset: &ChallengeWindowDataset,
    production: bool,
    deployed_challenge_blocks: Option<u64>,
    now_unix_ms: u64,
) -> Result<ChallengeWindowAssessment> {
    profile.validate()?;
    validate_challenge_window_dataset(dataset)?;
    ensure!(
        dataset.profile_digest == publication_profile_digest(profile)?,
        "challenge-window dataset was measured with a different publication profile"
    );
    ensure!(
        !dataset.samples.is_empty(),
        "challenge-window dataset is empty"
    );
    let production_network_eligible =
        !production || PUBLIC_CKB_NETWORKS.contains(&dataset.network.as_str());
    let rbf_profile_eligible =
        !production || (profile.fee.require_rbf && profile.fee.max_attempts >= 2);
    let mut sample_fingerprints = BTreeSet::new();
    let unique_samples = dataset.samples.iter().try_fold(true, |unique, sample| {
        let encoded = serde_json::to_vec(sample)
            .context("failed to encode challenge-window sample fingerprint")?;
        Ok::<bool, anyhow::Error>(unique && sample_fingerprints.insert(encoded))
    })?;
    let fault_evidence_valid = !production
        || dataset
            .samples
            .iter()
            .all(sample_has_valid_production_evidence);
    let mut durations = dataset
        .samples
        .iter()
        .map(|sample| sample.end_to_end_ms)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    let sufficient_samples = !production || durations.len() >= MIN_PRODUCTION_SAMPLES;
    let observed_fault_labels = dataset
        .samples
        .iter()
        .flat_map(|sample| sample.fault_labels.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let observed_fault_labels_vec = observed_fault_labels
        .iter()
        .map(|label| (*label).to_string())
        .collect::<Vec<_>>();
    let mut durations_by_fault = BTreeMap::<String, Vec<u64>>::new();
    for sample in &dataset.samples {
        for label in &sample.fault_labels {
            durations_by_fault
                .entry(label.clone())
                .or_default()
                .push(sample.end_to_end_ms);
        }
    }
    let fault_label_sample_counts = durations_by_fault
        .iter()
        .map(|(label, values)| (label.clone(), values.len()))
        .collect::<BTreeMap<_, _>>();
    let fault_label_p999_end_to_end_ms = durations_by_fault
        .iter_mut()
        .map(|(label, values)| {
            values.sort_unstable();
            (label.clone(), nearest_rank(values, 9_990, 10_000))
        })
        .collect::<BTreeMap<_, _>>();
    let missing_fault_labels = if production {
        REQUIRED_PRODUCTION_FAULT_LABELS
            .iter()
            .filter(|label| !observed_fault_labels.contains(**label))
            .map(|label| (*label).to_string())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let required_faults_present = missing_fault_labels.is_empty();
    let under_sampled_fault_labels = if production {
        REQUIRED_PRODUCTION_FAULT_LABELS
            .iter()
            .filter(|label| {
                fault_label_sample_counts
                    .get(**label)
                    .copied()
                    .unwrap_or_default()
                    < MIN_PRODUCTION_SAMPLES_PER_FAULT
            })
            .map(|label| (*label).to_string())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let sufficient_fault_samples = under_sampled_fault_labels.is_empty();
    let deployment_matches_profile = deployed_challenge_blocks
        .map(|blocks| blocks == profile.window.configured_challenge_blocks)
        .unwrap_or(!production);
    let max_age_ms = profile
        .window
        .max_measurement_age_secs
        .checked_mul(1_000)
        .ok_or_else(|| anyhow!("measurement age limit overflow"))?;
    let sample_ends = dataset
        .samples
        .iter()
        .map(|sample| {
            sample
                .started_unix_ms
                .checked_add(sample.end_to_end_ms)
                .ok_or_else(|| anyhow!("challenge-window sample end timestamp overflow"))
        })
        .collect::<Result<Vec<_>>>()?;
    let oldest_sample_started_unix_ms = dataset
        .samples
        .iter()
        .map(|sample| sample.started_unix_ms)
        .min()
        .ok_or_else(|| anyhow!("challenge-window dataset is empty"))?;
    let newest_sample_ended_unix_ms = sample_ends
        .iter()
        .copied()
        .max()
        .ok_or_else(|| anyhow!("challenge-window dataset is empty"))?;
    let fresh = now_unix_ms
        .checked_sub(dataset.generated_unix_ms)
        .is_some_and(|age| age <= max_age_ms)
        && sample_ends.iter().all(|sample_end| {
            now_unix_ms
                .checked_sub(*sample_end)
                .is_some_and(|age| age <= max_age_ms)
        })
        && dataset.samples.iter().all(|sample| {
            now_unix_ms
                .checked_sub(sample.started_unix_ms)
                .is_some_and(|age| age <= max_age_ms)
        });
    let p999 = nearest_rank(&durations, 9_990, 10_000);
    let worst_required_fault_p999_end_to_end_ms = if production {
        REQUIRED_PRODUCTION_FAULT_LABELS
            .iter()
            .filter_map(|label| fault_label_p999_end_to_end_ms.get(*label).copied())
            .max()
    } else {
        None
    };
    let effective_p999_end_to_end_ms =
        p999.max(worst_required_fault_p999_end_to_end_ms.unwrap_or_default());
    let measured_latency_blocks = ceil_div(
        effective_p999_end_to_end_ms,
        profile.window.conservative_block_ms,
    )?;
    let required_challenge_blocks = measured_latency_blocks
        .checked_add(profile.window.canonical_confirmation_blocks)
        .and_then(|value| value.checked_add(profile.window.reorg_budget_blocks))
        .and_then(|value| value.checked_add(profile.window.failover_budget_blocks))
        .and_then(|value| value.checked_add(profile.window.safety_margin_blocks))
        .ok_or_else(|| anyhow!("required challenge-window calculation overflow"))?;
    // Exact-byte and structural validation cannot prove who collected samples
    // or whether the declared fault was actually injected. Keep the local
    // production decision closed until a trusted receipt verifier is wired in.
    let production_provenance_verified = false;
    let passes = sufficient_samples
        && production_network_eligible
        && unique_samples
        && fault_evidence_valid
        && rbf_profile_eligible
        && fresh
        && required_faults_present
        && sufficient_fault_samples
        && deployment_matches_profile
        && (!production || production_provenance_verified)
        && profile.window.configured_challenge_blocks >= required_challenge_blocks;
    Ok(ChallengeWindowAssessment {
        schema: CHALLENGE_WINDOW_ASSESSMENT_SCHEMA.to_string(),
        network: dataset.network.clone(),
        genesis_hash: dataset.genesis_hash.clone(),
        ckb_version: dataset.ckb_version.clone(),
        profile_digest: dataset.profile_digest.clone(),
        generated_unix_ms: dataset.generated_unix_ms,
        oldest_sample_started_unix_ms,
        newest_sample_ended_unix_ms,
        observed_fault_labels: observed_fault_labels_vec,
        fault_label_sample_counts,
        fault_label_p999_end_to_end_ms,
        production,
        production_provenance_verified,
        production_network_eligible,
        unique_samples,
        fault_evidence_valid,
        rbf_profile_eligible,
        sufficient_samples,
        fresh,
        required_faults_present,
        sufficient_fault_samples,
        missing_fault_labels,
        under_sampled_fault_labels,
        deployed_challenge_blocks,
        deployment_matches_profile,
        sample_count: durations.len(),
        p50_end_to_end_ms: nearest_rank(&durations, 50, 100),
        p95_end_to_end_ms: nearest_rank(&durations, 95, 100),
        p99_end_to_end_ms: nearest_rank(&durations, 99, 100),
        p999_end_to_end_ms: p999,
        worst_required_fault_p999_end_to_end_ms,
        effective_p999_end_to_end_ms,
        max_end_to_end_ms: durations[durations.len() - 1],
        measured_latency_blocks,
        required_challenge_blocks,
        configured_challenge_blocks: profile.window.configured_challenge_blocks,
        passes,
    })
}

fn sample_has_valid_production_evidence(sample: &ChallengeWindowSample) -> bool {
    let component_total = sample
        .detection_ms
        .checked_add(sample.build_and_verify_ms)
        .and_then(|value| value.checked_add(sample.queue_and_rbf_ms))
        .and_then(|value| value.checked_add(sample.confirmation_ms))
        .and_then(|value| value.checked_add(sample.reorg_recovery_ms))
        .and_then(|value| value.checked_add(sample.failover_ms));
    if component_total.is_none_or(|total| total > sample.end_to_end_ms)
        || sample.build_and_verify_ms == 0
        || sample.confirmation_ms == 0
    {
        return false;
    }
    sample
        .fault_labels
        .iter()
        .all(|label| match label.as_str() {
            "fee_pressure" => sample.queue_and_rbf_ms > 0,
            "rpc_delay" => sample.detection_ms > 0,
            "operator_failover" => sample.failover_ms > 0,
            "induced_reorg" => sample.reorg_recovery_ms > 0,
            _ => true,
        })
}

fn validate_challenge_window_dataset(dataset: &ChallengeWindowDataset) -> Result<()> {
    ensure!(
        dataset.schema == CHALLENGE_WINDOW_DATASET_SCHEMA,
        "unsupported challenge-window dataset schema {}",
        dataset.schema
    );
    ensure!(
        !dataset.network.is_empty() && dataset.network.len() <= 128,
        "dataset network must contain at most 128 bytes"
    );
    validate_hex32(&dataset.genesis_hash, "dataset genesis_hash")?;
    ensure!(
        !dataset.ckb_version.is_empty() && dataset.ckb_version.len() <= 256,
        "dataset ckb_version must contain at most 256 bytes"
    );
    validate_hex32(&dataset.profile_digest, "dataset profile_digest")?;
    ensure!(
        !dataset.samples.is_empty(),
        "challenge-window dataset is empty"
    );
    ensure!(
        dataset.samples.len() <= MAX_CHALLENGE_SAMPLES,
        "challenge-window dataset exceeds the {MAX_CHALLENGE_SAMPLES}-sample limit"
    );
    for (index, sample) in dataset.samples.iter().enumerate() {
        ensure!(
            sample.end_to_end_ms > 0,
            "sample {} duration must be non-zero",
            index + 1
        );
        let ended_unix_ms = sample
            .started_unix_ms
            .checked_add(sample.end_to_end_ms)
            .ok_or_else(|| anyhow!("sample {} end timestamp overflow", index + 1))?;
        ensure!(
            ended_unix_ms <= dataset.generated_unix_ms,
            "sample {} ends after dataset generation time",
            index + 1
        );
        for (name, component) in [
            ("detection_ms", sample.detection_ms),
            ("build_and_verify_ms", sample.build_and_verify_ms),
            ("queue_and_rbf_ms", sample.queue_and_rbf_ms),
            ("confirmation_ms", sample.confirmation_ms),
            ("reorg_recovery_ms", sample.reorg_recovery_ms),
            ("failover_ms", sample.failover_ms),
        ] {
            ensure!(
                component <= sample.end_to_end_ms,
                "sample {} {name} exceeds end_to_end_ms",
                index + 1
            );
        }
        ensure!(
            sample.fault_labels.len() <= MAX_FAULT_LABELS_PER_SAMPLE,
            "sample {} exceeds the {MAX_FAULT_LABELS_PER_SAMPLE}-label limit",
            index + 1
        );
        let mut labels = BTreeSet::new();
        for label in &sample.fault_labels {
            ensure!(
                !label.is_empty()
                    && label.len() <= MAX_FAULT_LABEL_BYTES
                    && label.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    }),
                "sample {} has an invalid fault label",
                index + 1
            );
            ensure!(
                labels.insert(label.as_str()),
                "sample {} contains duplicate fault label {label}",
                index + 1
            );
        }
    }
    Ok(())
}

fn validate_hex32(value: &str, field: &str) -> Result<()> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("{field} must be 0x-prefixed"))?;
    ensure!(raw.len() == 64, "{field} must encode exactly 32 bytes");
    hex::decode(raw).with_context(|| format!("{field} must be valid hexadecimal"))?;
    Ok(())
}

fn read_bounded_file(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>> {
    let limit_u64 = u64::try_from(limit).context("file-size limit exceeds u64")?;
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {label} {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{label} {} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.len() <= limit_u64,
        "{label} {} exceeds the {limit}-byte limit",
        path.display()
    );
    let bytes =
        fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "{label} {} grew beyond the {limit}-byte limit while it was read",
        path.display()
    );
    Ok(bytes)
}

fn open_private_append(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open publication attempt log {}", path.display()))
}

fn open_private_repair(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open publication attempt log {}", path.display()))
}

fn recover_attempt_log_tail(path: &Path) -> Result<(String, u64, Option<String>, bool)> {
    let mut file = open_private_repair(path)?;
    file.lock()
        .with_context(|| format!("failed to lock publication attempt log {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read publication attempt log {}", path.display()))?;
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        let content = String::from_utf8(bytes)
            .with_context(|| format!("publication attempt log {} is not UTF-8", path.display()))?;
        return Ok((content, 0, None, false));
    }

    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let tail = &bytes[complete_len..];
    if serde_json::from_slice::<PublicationAttemptRecord>(tail).is_ok() {
        file.seek(SeekFrom::End(0)).with_context(|| {
            format!("failed to seek publication attempt log {}", path.display())
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "failed to normalize publication attempt log {}",
                path.display()
            )
        })?;
        file.sync_data().with_context(|| {
            format!(
                "failed to sync normalized publication attempt log {}",
                path.display()
            )
        })?;
        let content = String::from_utf8(bytes)
            .with_context(|| format!("publication attempt log {} is not UTF-8", path.display()))?;
        return Ok((content, 0, None, true));
    }

    let recovered_tail_path = torn_tail_path(path)?;
    write_private_new(&recovered_tail_path, tail)?;
    file.set_len(u64::try_from(complete_len).context("attempt log length exceeds u64")?)
        .with_context(|| format!("failed to remove torn tail from {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("failed to sync repaired attempt log {}", path.display()))?;
    let content = String::from_utf8(bytes[..complete_len].to_vec())
        .with_context(|| format!("publication attempt log {} is not UTF-8", path.display()))?;
    Ok((
        content,
        u64::try_from(tail.len()).context("torn attempt-log tail exceeds u64")?,
        Some(recovered_tail_path.display().to_string()),
        false,
    ))
}

fn torn_tail_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("publication attempt log path has no UTF-8 file name"))?;
    Ok(path.with_file_name(format!("{file_name}.torn-{}", unix_ms()?)))
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create torn-tail evidence {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to preserve torn-tail evidence {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync torn-tail evidence {}", path.display()))
}

pub fn fixture_publication_profile() -> PublicationProfile {
    PublicationProfile::fixture()
}

fn validate_operator_id(value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "operator_id must not be empty");
    ensure!(value.len() <= 64, "operator_id must not exceed 64 bytes");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "operator_id may contain only ASCII letters, digits, '.', '_' and '-'"
    );
    Ok(())
}

fn multiply_bps(value: u64, basis_points: u64) -> Result<u64> {
    let product = u128::from(value)
        .checked_mul(u128::from(basis_points))
        .ok_or_else(|| anyhow!("basis-point multiplication overflow"))?;
    let rounded = product
        .checked_add(u128::from(BASIS_POINTS_DENOMINATOR - 1))
        .ok_or_else(|| anyhow!("basis-point rounding overflow"))?
        / u128::from(BASIS_POINTS_DENOMINATOR);
    u64::try_from(rounded).map_err(|_| anyhow!("basis-point result exceeds u64"))
}

fn nearest_rank(values: &[u64], numerator: usize, denominator: usize) -> u64 {
    let rank = values
        .len()
        .saturating_mul(numerator)
        .saturating_add(denominator.saturating_sub(1))
        / denominator;
    values[rank.saturating_sub(1).min(values.len().saturating_sub(1))]
}

fn ceil_div(value: u64, divisor: u64) -> Result<u64> {
    ensure!(divisor > 0, "division by zero");
    value
        .checked_add(divisor - 1)
        .map(|rounded| rounded / divisor)
        .ok_or_else(|| anyhow!("ceiling division overflow"))
}

fn unix_ms() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis();
    u64::try_from(millis).context("Unix timestamp does not fit in u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> FeeObservation {
        FeeObservation {
            observed_unix_ms: 1,
            estimator_fee_rate: 2_000,
            confirmed_mean_fee_rate: Some(1_500),
            confirmed_median_fee_rate: Some(1_200),
            pool_min_fee_rate: 1_000,
            pool_min_rbf_rate: 1_500,
            pool_pending: 0,
            pool_proposed: 0,
            pool_total_tx_size: 0,
            rbf_enabled: true,
        }
    }

    #[test]
    fn fixture_profile_is_valid() {
        PublicationProfile::fixture().validate().unwrap();
    }

    #[test]
    fn profile_rejects_window_below_static_budgets() {
        let mut profile = PublicationProfile::fixture();
        profile.window.configured_challenge_blocks = 18;
        let error = profile.validate().unwrap_err();
        assert!(error.to_string().contains("below the static"));
    }

    #[test]
    fn profile_rejects_rbf_without_a_replacement_attempt() {
        let mut profile = PublicationProfile::fixture();
        profile.fee.max_attempts = 1;
        let error = profile.validate().unwrap_err();
        assert!(error.to_string().contains("at least two"));
    }

    #[test]
    fn profile_rejects_retry_ladder_beyond_window_budget() {
        let mut profile = PublicationProfile::fixture();
        profile.fee.bump_after_ms = 30_000;
        let error = profile.validate().unwrap_err();
        assert!(error.to_string().contains("retry ladder"));
    }

    #[test]
    fn profile_rejects_retry_ladder_equal_to_window_budget() {
        let mut profile = PublicationProfile::fixture();
        // Fixture budget is (24 - 19) * 10s = 50s, with two bump waits.
        profile.fee.bump_after_ms = 25_000;
        let error = profile.validate().unwrap_err();
        assert!(error.to_string().contains("strictly inside"));
    }

    #[test]
    fn initial_rate_applies_estimator_headroom() {
        let profile = PublicationProfile::fixture();
        assert_eq!(
            initial_fee_rate(&profile.fee, &observation()).unwrap(),
            2_500
        );
    }

    #[test]
    fn initial_rate_fails_closed_on_overflow_and_operator_cap() {
        let mut profile = PublicationProfile::fixture();
        let mut observed = observation();
        observed.estimator_fee_rate = u64::MAX;
        profile.fee.estimator_multiplier_bps = u64::MAX;
        let overflow = initial_fee_rate(&profile.fee, &observed).unwrap_err();
        let overflow = format!("{overflow:#}");
        assert!(overflow.contains("overflow") || overflow.contains("exceeds u64"));

        profile = PublicationProfile::fixture();
        observed = observation();
        observed.estimator_fee_rate = profile.fee.max_fee_rate + 1;
        let capped = initial_fee_rate(&profile.fee, &observed).unwrap_err();
        assert!(capped.to_string().contains("operator maximum"));
    }

    #[test]
    fn rbf_required_profile_rejects_an_rbf_disabled_node_observation() {
        let profile = PublicationProfile::fixture();
        let mut observed = observation();
        observed.rbf_enabled = false;
        observed.pool_min_rbf_rate = observed.pool_min_fee_rate;
        let error = validate_rbf_requirement(&profile.fee, &observed).unwrap_err();
        assert!(error.to_string().contains("requires RBF"));
    }

    #[test]
    fn fee_calculation_rounds_up() {
        assert_eq!(fee_for_rate(1_001, 1_001).unwrap(), 1_003);
        assert_eq!(effective_fee_rate(1_003, 1_001).unwrap(), 1_001);
    }

    #[test]
    fn initial_fee_convergence_checks_the_rebuilt_transaction_size() {
        let selected_fee_rate = 1_001;
        let converged_fee = fee_for_rate(selected_fee_rate, 1_001).unwrap();
        assert_eq!(
            verify_initial_fee_convergence(selected_fee_rate, converged_fee, 1_001).unwrap(),
            selected_fee_rate
        );

        let provisional_fee = fee_for_rate(selected_fee_rate, 1_000).unwrap();
        let error =
            verify_initial_fee_convergence(selected_fee_rate, provisional_fee, 1_001).unwrap_err();
        assert!(error.to_string().contains("did not converge"));
    }

    #[test]
    fn node_replacement_requirement_wins() {
        let profile = PublicationProfile::fixture();
        assert_eq!(
            replacement_fee(&profile.fee, 10_000, 1_000, 1_500, Some(20_000)).unwrap(),
            20_000
        );
    }

    #[test]
    fn replacement_fails_closed_at_operator_cap() {
        let mut profile = PublicationProfile::fixture();
        profile.fee.max_fee = 10_000;
        let err = replacement_fee(&profile.fee, 10_000, 1_000, 1_500, None).unwrap_err();
        assert!(err.to_string().contains("exceeds operator maximum"));
    }

    #[test]
    fn parses_ckb_rbf_replacement_floor() {
        let message = "PoolRejectedRBF: RBF rejected: Tx's current fee is 47605748, expect it to >= 47623598 to replace old txs";
        assert_eq!(
            required_replacement_fee_from_parts(CKB_POOL_REJECTED_RBF_CODE, message),
            Some(47_623_598)
        );
        assert_eq!(required_replacement_fee_from_parts(-1104, message), None);
    }

    #[test]
    fn production_window_needs_one_thousand_fresh_samples() {
        let profile = PublicationProfile::fixture();
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 25_000,
            samples: vec![ChallengeWindowSample {
                started_unix_ms: 900,
                end_to_end_ms: 20_000,
                detection_ms: 1_000,
                build_and_verify_ms: 1_000,
                queue_and_rbf_ms: 5_000,
                confirmation_ms: 10_000,
                reorg_recovery_ms: 2_000,
                failover_ms: 1_000,
                fault_labels: vec!["fee_pressure".to_string()],
            }],
        };
        let assessment = assess_challenge_window(&profile, &dataset, true, None, 26_000).unwrap();
        assert!(!assessment.sufficient_samples);
        assert!(!assessment.required_faults_present);
        assert!(!assessment.sufficient_fault_samples);
        assert!(
            assessment
                .under_sampled_fault_labels
                .contains(&"fee_pressure".to_string())
        );
        assert!(!assessment.deployment_matches_profile);
        assert!(!assessment.passes);
    }

    #[test]
    fn production_window_rejects_synthetic_duplicate_devnet_samples() {
        let profile = PublicationProfile::fixture();
        let sample = ChallengeWindowSample {
            started_unix_ms: 1_000,
            end_to_end_ms: 1_000,
            detection_ms: 0,
            build_and_verify_ms: 0,
            queue_and_rbf_ms: 0,
            confirmation_ms: 0,
            reorg_recovery_ms: 0,
            failover_ms: 0,
            fault_labels: REQUIRED_PRODUCTION_FAULT_LABELS
                .iter()
                .map(|label| (*label).to_string())
                .collect(),
        };
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "ckb_dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 3_000,
            samples: vec![sample; MIN_PRODUCTION_SAMPLES],
        };

        let assessment =
            assess_challenge_window(&profile, &dataset, true, Some(24), 3_500).unwrap();
        assert!(assessment.sufficient_samples);
        assert!(assessment.required_faults_present);
        assert!(assessment.sufficient_fault_samples);
        assert!(!assessment.production_network_eligible);
        assert!(!assessment.unique_samples);
        assert!(!assessment.fault_evidence_valid);
        assert!(!assessment.passes);
    }

    #[test]
    fn production_window_stays_closed_without_trusted_provenance() {
        let profile = PublicationProfile::fixture();
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "ckb_testnet".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 10_000,
            samples: (0..MIN_PRODUCTION_SAMPLES)
                .map(|index| ChallengeWindowSample {
                    started_unix_ms: 1_000 + index as u64,
                    end_to_end_ms: 1_000,
                    detection_ms: 100,
                    build_and_verify_ms: 100,
                    queue_and_rbf_ms: 100,
                    confirmation_ms: 100,
                    reorg_recovery_ms: 100,
                    failover_ms: 100,
                    fault_labels: REQUIRED_PRODUCTION_FAULT_LABELS
                        .iter()
                        .map(|label| (*label).to_string())
                        .collect(),
                })
                .collect(),
        };

        let assessment =
            assess_challenge_window(&profile, &dataset, true, Some(24), 11_000).unwrap();
        assert!(assessment.production_network_eligible);
        assert!(assessment.unique_samples);
        assert!(assessment.fault_evidence_valid);
        assert!(assessment.rbf_profile_eligible);
        assert!(!assessment.production_provenance_verified);
        assert!(!assessment.passes);
    }

    #[test]
    fn production_window_rejects_a_profile_without_rbf() {
        let mut profile = PublicationProfile::fixture();
        profile.fee.require_rbf = false;
        profile.fee.max_attempts = 1;
        profile.validate().unwrap();
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "ckb_testnet".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 3_000,
            samples: vec![ChallengeWindowSample {
                started_unix_ms: 1_000,
                end_to_end_ms: 1_000,
                detection_ms: 100,
                build_and_verify_ms: 100,
                queue_and_rbf_ms: 100,
                confirmation_ms: 100,
                reorg_recovery_ms: 100,
                failover_ms: 100,
                fault_labels: REQUIRED_PRODUCTION_FAULT_LABELS
                    .iter()
                    .map(|label| (*label).to_string())
                    .collect(),
            }],
        };

        let assessment =
            assess_challenge_window(&profile, &dataset, true, Some(24), 3_500).unwrap();
        assert!(!assessment.rbf_profile_eligible);
        assert!(!assessment.passes);
    }

    #[test]
    fn devnet_window_uses_nearest_rank_p999() {
        let profile = PublicationProfile::fixture();
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 20_000,
            samples: (1..=10)
                .map(|value| ChallengeWindowSample {
                    started_unix_ms: value,
                    end_to_end_ms: value * 1_000,
                    detection_ms: value,
                    build_and_verify_ms: value,
                    queue_and_rbf_ms: value,
                    confirmation_ms: value,
                    reorg_recovery_ms: value,
                    failover_ms: value,
                    fault_labels: Vec::new(),
                })
                .collect(),
        };
        let assessment = assess_challenge_window(&profile, &dataset, false, None, 21_000).unwrap();
        assert_eq!(assessment.p999_end_to_end_ms, 10_000);
        assert_eq!(assessment.measured_latency_blocks, 1);
        assert_eq!(assessment.required_challenge_blocks, 20);
        assert!(assessment.passes);
    }

    #[test]
    fn window_rejects_a_different_profile_digest() {
        let profile = PublicationProfile::fixture();
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: format!("0x{}", "11".repeat(32)),
            generated_unix_ms: 2_000,
            samples: vec![ChallengeWindowSample {
                started_unix_ms: 900,
                end_to_end_ms: 1_000,
                detection_ms: 1,
                build_and_verify_ms: 1,
                queue_and_rbf_ms: 1,
                confirmation_ms: 1,
                reorg_recovery_ms: 1,
                failover_ms: 1,
                fault_labels: Vec::new(),
            }],
        };
        let error = assess_challenge_window(&profile, &dataset, false, None, 2_000).unwrap_err();
        assert!(error.to_string().contains("different publication profile"));
    }

    #[test]
    fn replacement_fails_closed_at_fee_rate_cap() {
        let mut profile = PublicationProfile::fixture();
        profile.fee.max_fee = u64::MAX;
        profile.fee.max_fee_rate = 1_000;
        let error = replacement_fee(&profile.fee, 2_000, 1_000, 1_500, Some(3_000)).unwrap_err();
        assert!(error.to_string().contains("maximum fee rate"));
    }

    #[test]
    fn recent_dataset_timestamp_cannot_hide_stale_samples() {
        let mut profile = PublicationProfile::fixture();
        profile.window.max_measurement_age_secs = 1;
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 10_000,
            samples: vec![ChallengeWindowSample {
                started_unix_ms: 1_000,
                end_to_end_ms: 1_000,
                detection_ms: 100,
                build_and_verify_ms: 100,
                queue_and_rbf_ms: 100,
                confirmation_ms: 100,
                reorg_recovery_ms: 100,
                failover_ms: 100,
                fault_labels: Vec::new(),
            }],
        };
        let assessment = assess_challenge_window(&profile, &dataset, false, None, 10_500).unwrap();
        assert!(!assessment.fresh);
        assert!(!assessment.passes);
    }

    #[test]
    fn dataset_rejects_sample_that_ends_after_generation() {
        let profile = PublicationProfile::fixture();
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 1_500,
            samples: vec![ChallengeWindowSample {
                started_unix_ms: 1_000,
                end_to_end_ms: 1_000,
                detection_ms: 100,
                build_and_verify_ms: 100,
                queue_and_rbf_ms: 100,
                confirmation_ms: 100,
                reorg_recovery_ms: 100,
                failover_ms: 100,
                fault_labels: Vec::new(),
            }],
        };
        let error = assess_challenge_window(&profile, &dataset, false, None, 2_000).unwrap_err();
        assert!(error.to_string().contains("ends after dataset generation"));
    }

    #[test]
    fn production_window_uses_the_worst_fault_family_p999() {
        let profile = PublicationProfile::fixture();
        let mut samples = (0..1_000)
            .map(|index| ChallengeWindowSample {
                started_unix_ms: 1_000 + index,
                end_to_end_ms: 1_000,
                detection_ms: 100,
                build_and_verify_ms: 100,
                queue_and_rbf_ms: 100,
                confirmation_ms: 100,
                reorg_recovery_ms: 0,
                failover_ms: 0,
                fault_labels: REQUIRED_PRODUCTION_FAULT_LABELS
                    .iter()
                    .filter(|label| **label != "induced_reorg")
                    .map(|label| (*label).to_string())
                    .collect(),
            })
            .collect::<Vec<_>>();
        samples.push(ChallengeWindowSample {
            started_unix_ms: 2_001,
            end_to_end_ms: 100_000,
            detection_ms: 100,
            build_and_verify_ms: 100,
            queue_and_rbf_ms: 100,
            confirmation_ms: 100,
            reorg_recovery_ms: 99_000,
            failover_ms: 0,
            fault_labels: vec!["induced_reorg".to_string()],
        });
        let dataset = ChallengeWindowDataset {
            schema: CHALLENGE_WINDOW_DATASET_SCHEMA.to_string(),
            network: "dev".to_string(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            ckb_version: "test".to_string(),
            profile_digest: publication_profile_digest(&profile).unwrap(),
            generated_unix_ms: 200_000,
            samples,
        };
        let assessment =
            assess_challenge_window(&profile, &dataset, true, Some(24), 201_000).unwrap();
        assert_eq!(assessment.p999_end_to_end_ms, 1_000);
        assert_eq!(
            assessment.worst_required_fault_p999_end_to_end_ms,
            Some(100_000)
        );
        assert_eq!(assessment.effective_p999_end_to_end_ms, 100_000);
        assert_eq!(assessment.measured_latency_blocks, 10);
        assert!(!assessment.sufficient_fault_samples);
        assert!(!assessment.passes);
    }

    #[test]
    fn dataset_sha256_binds_exact_file_bytes() {
        let path = std::env::temp_dir().join(format!(
            "morph-publication-digest-{}-{}.json",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            challenge_window_dataset_sha256(&path).unwrap(),
            "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn attempt_log_append_waits_for_the_shared_file_lock() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = std::env::temp_dir().join(format!(
            "morph-publication-lock-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("attempts.jsonl");
        let locker = open_private_append(&path).unwrap();
        locker.lock().unwrap();
        let profile = PublicationProfile::fixture();
        let record = publication_attempt_record(
            &profile,
            PublicationAttemptInput {
                fee_observation: observation(),
                intent_id: "intent".to_string(),
                channel_id: format!("0x{}", "11".repeat(32)),
                funding_context_id: format!("0x{}", "22".repeat(32)),
                target_state_number: 1,
                attempt: 1,
                fee: 2_000,
                tx_size_bytes: 1_000,
                tx_hash: format!("0x{}", "33".repeat(32)),
                replaces_tx_hash: None,
                node_min_replace_fee: None,
                status: "built".to_string(),
                error_class: None,
                elapsed_ms: 1,
                tip_number: 1,
                tip_hash: format!("0x{}", "44".repeat(32)),
            },
        )
        .unwrap();
        let (sender, receiver) = mpsc::channel();
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let result = append_publication_attempt(&writer_path, &record);
            sender.send(result).unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        drop(locker);
        receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn attempt_log_recovery_waits_for_the_shared_file_lock() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = std::env::temp_dir().join(format!(
            "morph-publication-recovery-lock-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("attempts.jsonl");
        let profile = PublicationProfile::fixture();
        let record = publication_attempt_record(
            &profile,
            PublicationAttemptInput {
                fee_observation: observation(),
                intent_id: "intent".to_string(),
                channel_id: format!("0x{}", "11".repeat(32)),
                funding_context_id: format!("0x{}", "22".repeat(32)),
                target_state_number: 1,
                attempt: 1,
                fee: 2_000,
                tx_size_bytes: 1_000,
                tx_hash: format!("0x{}", "33".repeat(32)),
                replaces_tx_hash: None,
                node_min_replace_fee: None,
                status: "built".to_string(),
                error_class: None,
                elapsed_ms: 1,
                tip_number: 1,
                tip_hash: format!("0x{}", "44".repeat(32)),
            },
        )
        .unwrap();
        append_publication_attempt(&path, &record).unwrap();
        let mut torn = OpenOptions::new().append(true).open(&path).unwrap();
        torn.write_all(b"{\"torn\":").unwrap();
        torn.sync_all().unwrap();
        drop(torn);

        let locker = open_private_append(&path).unwrap();
        locker.lock().unwrap();
        let (sender, receiver) = mpsc::channel();
        let recovery_path = path.clone();
        let recovery = std::thread::spawn(move || {
            sender
                .send(recover_attempt_log_tail(&recovery_path))
                .unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
        drop(locker);
        let (content, recovered_bytes, _, normalized) = receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        recovery.join().unwrap();
        assert_eq!(content.lines().count(), 1);
        assert_eq!(recovered_bytes, 8);
        assert!(!normalized);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovers_only_a_torn_attempt_log_tail_and_preserves_evidence() {
        let dir = std::env::temp_dir().join(format!(
            "morph-publication-tail-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("attempts.jsonl");
        let profile = PublicationProfile::fixture();
        let record = publication_attempt_record(
            &profile,
            PublicationAttemptInput {
                fee_observation: observation(),
                intent_id: "intent".to_string(),
                channel_id: format!("0x{}", "11".repeat(32)),
                funding_context_id: format!("0x{}", "22".repeat(32)),
                target_state_number: 1,
                attempt: 1,
                fee: 2_000,
                tx_size_bytes: 1_000,
                tx_hash: format!("0x{}", "33".repeat(32)),
                replaces_tx_hash: None,
                node_min_replace_fee: None,
                status: "built".to_string(),
                error_class: None,
                elapsed_ms: 1,
                tip_number: 1,
                tip_hash: format!("0x{}", "44".repeat(32)),
            },
        )
        .unwrap();
        append_publication_attempt(&path, &record).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"torn\":").unwrap();
        file.sync_all().unwrap();

        let (content, recovered_bytes, evidence_path, normalized) =
            recover_attempt_log_tail(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
        assert_eq!(recovered_bytes, 8);
        assert!(!normalized);
        let evidence_path = evidence_path.map(PathBuf::from).unwrap();
        assert_eq!(fs::read(&evidence_path).unwrap(), b"{\"torn\":");
        assert!(fs::read(&path).unwrap().ends_with(b"\n"));

        fs::remove_dir_all(dir).unwrap();
    }
}
