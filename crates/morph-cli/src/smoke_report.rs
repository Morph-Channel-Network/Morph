use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use ckb_hash::blake2b_256;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::factory_packages::{StoredFactoryReducedSplicePackage, StoredFactorySplicePackage};
use crate::packages::{
    StoredFactoryLocalExitPackage, StoredFactoryMerkleUpdateStatePackage,
    StoredFactoryReducedRightsPackage,
};
use crate::watch_alert::{WatchAlertEvent, WatchAlertSeverity, WatchtowerAlert};

const DEVNET_SMOKE_BUDGET_SCHEMA: &str = "morph.devnet_smoke_budget";

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeSummary {
    pub directory: String,
    pub manifest: BTreeMap<String, String>,
    pub json_files: usize,
    pub json_checks: Vec<String>,
    pub transactions: Vec<TransactionSummary>,
    pub script_failures: Vec<ScriptFailureSummary>,
    pub deployed_scripts: Vec<DeployedScriptSummary>,
    pub watchtower_alerts: Vec<WatchtowerAlertSummary>,
    pub watchtower_services: Vec<WatchtowerServiceSummary>,
    pub factory_reduced_rights_updates: Vec<FactoryReducedRightsEvidenceSummary>,
    pub factory_merkle_updates: Vec<FactoryMerkleUpdateEvidenceSummary>,
    pub factory_proof_profiles: Vec<FactoryProofProfileSummary>,
    pub factory_reduced_exits: Vec<FactoryReducedExitEvidenceSummary>,
    pub factory_local_exits: Vec<FactoryLocalExitEvidenceSummary>,
    pub factory_splices: Vec<FactorySpliceEvidenceSummary>,
    pub splice_payouts: Vec<SplicePayoutEvidenceSummary>,
    pub sponsor_policies: Vec<SponsorPolicySummary>,
    pub totals: MetricTotals,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeAssertionReport {
    pub directory: String,
    pub git_commit: Option<String>,
    pub git_dirty: Option<String>,
    pub transaction_count: usize,
    pub committed_count: usize,
    pub expected_script_failures: usize,
    pub deployed_scripts: usize,
    pub deployed_script_hashes_verified: bool,
    pub watchtower_alerts: usize,
    pub watchtower_publication_alerts: usize,
    pub watchtower_service_records: usize,
    pub factory_reduced_rights_updates: usize,
    pub factory_merkle_updates: usize,
    pub factory_proof_profiles: usize,
    pub factory_reduced_exits: usize,
    pub factory_local_exits: usize,
    pub factory_splices: usize,
    pub splice_payouts: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<DevnetSmokeBudgetReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionSummary {
    pub check: String,
    pub path: String,
    pub tx_hash: String,
    pub status: Option<String>,
    pub block_number: Option<u64>,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptFailureSummary {
    pub check: String,
    pub path: String,
    pub source: Option<String>,
    pub error_code: Option<i64>,
    pub morph_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeployedScriptSummary {
    pub check: String,
    pub path: String,
    pub name: String,
    pub out_point: String,
    pub data_hash: String,
    pub hash_type: String,
    pub data_len: usize,
    pub capacity: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchtowerAlertSummary {
    pub check: String,
    pub path: String,
    pub channel_id: String,
    pub severity: String,
    pub event: String,
    pub selected_state_number: u64,
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchtowerServiceSummary {
    pub check: String,
    pub path: String,
    pub schema: String,
    pub status: Option<String>,
    pub stopped_reason: Option<String>,
    pub completed_passes: u64,
    pub published_count: usize,
    pub idle_count: usize,
    pub error_count: u64,
    pub consecutive_errors: u64,
    pub health_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryLocalExitEvidenceSummary {
    pub check: String,
    pub path: String,
    pub factory_id: String,
    pub update_number: u64,
    pub exit_digest: String,
    pub child_channel_id: String,
    pub child_state_number: u64,
    pub child_phase: String,
    pub descriptor_version: u16,
    pub state_output_index: u32,
    pub vault_output_index: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryReducedRightsEvidenceSummary {
    pub check: String,
    pub path: String,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub signing_digest: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub witness_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryMerkleUpdateEvidenceSummary {
    pub check: String,
    pub path: String,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub signing_digest: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub changed_participant: String,
    pub quantity_before: u128,
    pub quantity_after: u128,
    pub proof_siblings: usize,
    pub witness_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryProofProfileSummary {
    pub check: String,
    pub transaction_path: String,
    pub evidence_path: String,
    pub proof_kind: String,
    pub proof_siblings: usize,
    pub witness_len: usize,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactoryReducedExitEvidenceSummary {
    pub check: String,
    pub path: String,
    pub authorisation: String,
    pub release_quantity: u128,
    pub witness_len: usize,
    pub local_exit_digest: String,
    pub non_interference_digest: String,
    pub child_xudt_amount: Option<u128>,
    pub alice_xudt_amount: Option<u128>,
    pub bob_xudt_amount: Option<u128>,
    pub xudt_type_hash: Option<String>,
    pub factory_vault_change_xudt_amount: Option<u128>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FactorySpliceEvidenceSummary {
    pub check: String,
    pub path: String,
    pub factory_id: String,
    pub kind: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub reserve_claim_asset: String,
    pub reserve_claim_before: u128,
    pub reserve_claim_after: u128,
    pub vault_old_amount: u128,
    pub vault_new_amount: u128,
    pub external_input: u128,
    pub withdrawal: u128,
    pub proof_siblings: usize,
    pub signatures: usize,
    pub signing_digest: String,
    pub vault_delta_commitment: String,
    pub non_interference_digest: String,
    pub witness_len: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SplicePayoutEvidenceSummary {
    pub check: String,
    pub path: String,
    pub withdrawal_payout_policy: String,
    pub withdrawal_participant_pubkey_sec1: Option<String>,
    pub withdrawal_lock_hash: Option<String>,
    pub withdrawal_out_point: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SponsorPolicySummary {
    pub check: String,
    pub path: String,
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub state_number_span: u64,
    pub max_fee_per_tx: u64,
    pub max_total_fee: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MetricTotals {
    pub transaction_count: usize,
    pub committed_count: usize,
    pub pending_count: usize,
    pub total_estimated_cycles: u64,
    pub max_estimated_cycles: u64,
    pub total_tx_size_bytes: usize,
    pub max_tx_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeComparison {
    pub baseline_directory: String,
    pub candidate_directory: String,
    pub compared_transactions: usize,
    pub missing_from_candidate: Vec<String>,
    pub added_in_candidate: Vec<String>,
    pub total_estimated_cycles_delta: i64,
    pub total_tx_size_bytes_delta: i64,
    pub transaction_deltas: Vec<TransactionMetricDelta>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DevnetSmokeBudgetLimits {
    pub max_total_cycles: Option<u64>,
    pub max_tx_cycles: Option<u64>,
    pub max_total_bytes: Option<usize>,
    pub max_tx_bytes: Option<usize>,
    pub transactions: Vec<DevnetSmokeTransactionBudgetLimit>,
    pub proof_profiles: Vec<DevnetSmokeProofProfileBudgetLimit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeBudgetReport {
    pub total_estimated_cycles: u64,
    pub max_estimated_cycles: u64,
    pub total_tx_size_bytes: usize,
    pub max_tx_size_bytes: usize,
    pub max_total_cycles: Option<u64>,
    pub max_tx_cycles: Option<u64>,
    pub max_total_bytes: Option<usize>,
    pub max_tx_bytes: Option<usize>,
    pub transactions: Vec<DevnetSmokeTransactionBudgetReport>,
    pub proof_profiles: Vec<DevnetSmokeProofProfileBudgetReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevnetSmokeTransactionBudgetLimit {
    pub check: String,
    pub path: String,
    pub max_cycles: Option<u64>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeTransactionBudgetReport {
    pub check: String,
    pub path: String,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
    pub max_cycles: Option<u64>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevnetSmokeProofProfileBudgetLimit {
    pub check: String,
    pub transaction_path: String,
    pub proof_kind: String,
    pub proof_siblings: Option<usize>,
    pub max_witness_len: Option<usize>,
    pub max_cycles: Option<u64>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeProofProfileBudgetReport {
    pub check: String,
    pub transaction_path: String,
    pub proof_kind: String,
    pub proof_siblings: usize,
    pub witness_len: usize,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
    pub expected_proof_siblings: Option<usize>,
    pub max_witness_len: Option<usize>,
    pub max_cycles: Option<u64>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
struct DevnetSmokeBudgetProfile {
    schema: String,
    max_total_cycles: Option<u64>,
    max_tx_cycles: Option<u64>,
    max_total_bytes: Option<usize>,
    max_tx_bytes: Option<usize>,
    #[serde(default)]
    transactions: Vec<DevnetSmokeTransactionBudgetLimit>,
    #[serde(default)]
    proof_profiles: Vec<DevnetSmokeProofProfileBudgetLimit>,
}

impl DevnetSmokeBudgetLimits {
    pub fn has_any_limit(&self) -> bool {
        self.max_total_cycles.is_some()
            || self.max_tx_cycles.is_some()
            || self.max_total_bytes.is_some()
            || self.max_tx_bytes.is_some()
            || !self.transactions.is_empty()
            || !self.proof_profiles.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DevnetSmokeComparisonLimits {
    pub fail_on_transaction_set_change: bool,
    pub fail_on_status_change: bool,
    pub max_abs_total_cycle_delta: Option<u64>,
    pub max_abs_tx_cycle_delta: Option<u64>,
    pub max_abs_total_byte_delta: Option<u64>,
    pub max_abs_tx_byte_delta: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionMetricDelta {
    pub key: String,
    pub baseline_status: Option<String>,
    pub candidate_status: Option<String>,
    pub baseline_estimated_cycles: u64,
    pub candidate_estimated_cycles: u64,
    pub estimated_cycles_delta: i64,
    pub baseline_tx_size_bytes: usize,
    pub candidate_tx_size_bytes: usize,
    pub tx_size_bytes_delta: i64,
}

pub fn summarize_devnet_smoke(dir: &Path) -> Result<DevnetSmokeSummary> {
    ensure_directory(dir)?;
    let manifest = read_manifest(dir)?;
    let mut json_paths = Vec::new();
    collect_json_files(dir, &mut json_paths)?;
    let json_checks = json_paths
        .iter()
        .map(|path| {
            path.strip_prefix(dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
                .trim_end_matches(".json")
                .to_string()
        })
        .collect::<Vec<_>>();
    let mut watch_alert_paths = Vec::new();
    collect_watch_alert_files(dir, &mut watch_alert_paths)?;

    let mut transactions = Vec::new();
    let mut script_failures = Vec::new();
    let mut deployed_scripts = Vec::new();
    let mut watchtower_alerts = Vec::new();
    let mut watchtower_services = Vec::new();
    let mut factory_reduced_rights_updates = Vec::new();
    let mut factory_merkle_updates = Vec::new();
    let mut factory_reduced_exits = Vec::new();
    let mut factory_local_exits = Vec::new();
    let mut factory_splices = Vec::new();
    let mut splice_payouts = Vec::new();
    let mut sponsor_policies = Vec::new();
    {
        let mut collections = SmokeCollections {
            transactions: &mut transactions,
            script_failures: &mut script_failures,
            deployed_scripts: &mut deployed_scripts,
            watchtower_services: &mut watchtower_services,
            factory_reduced_rights_updates: &mut factory_reduced_rights_updates,
            factory_merkle_updates: &mut factory_merkle_updates,
            factory_reduced_exits: &mut factory_reduced_exits,
            factory_local_exits: &mut factory_local_exits,
            factory_splices: &mut factory_splices,
            splice_payouts: &mut splice_payouts,
            sponsor_policies: &mut sponsor_policies,
        };
        for path in &json_paths {
            let relative = path
                .strip_prefix(dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let check = relative.trim_end_matches(".json").to_string();
            let raw = fs::read(path)
                .with_context(|| format!("failed to read smoke JSON {}", path.display()))?;
            let value: Value = serde_json::from_slice(&raw)
                .with_context(|| format!("failed to parse smoke JSON {}", path.display()))?;
            collect_from_value(&check, "$", &value, &mut collections)
                .with_context(|| format!("failed to inspect smoke JSON {}", path.display()))?;
        }
    }
    for path in &watch_alert_paths {
        collect_watchtower_alerts(dir, path, &mut watchtower_alerts)?;
    }

    let factory_proof_profiles = factory_proof_profiles(
        &factory_reduced_rights_updates,
        &factory_merkle_updates,
        &factory_reduced_exits,
        &factory_splices,
        &transactions,
    );
    let totals = summarise_totals(&transactions);
    Ok(DevnetSmokeSummary {
        directory: dir.display().to_string(),
        manifest,
        json_files: json_paths.len(),
        json_checks,
        transactions,
        script_failures,
        deployed_scripts,
        watchtower_alerts,
        watchtower_services,
        factory_reduced_rights_updates,
        factory_merkle_updates,
        factory_proof_profiles,
        factory_reduced_exits,
        factory_local_exits,
        factory_splices,
        splice_payouts,
        sponsor_policies,
        totals,
    })
}

pub fn compare_devnet_smoke(
    baseline_dir: &Path,
    candidate_dir: &Path,
) -> Result<DevnetSmokeComparison> {
    let baseline = summarize_devnet_smoke(baseline_dir)?;
    let candidate = summarize_devnet_smoke(candidate_dir)?;
    Ok(compare_summaries(&baseline, &candidate))
}

pub fn read_smoke_budget_profile(path: &Path) -> Result<DevnetSmokeBudgetLimits> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read smoke budget profile {}", path.display()))?;
    let profile: DevnetSmokeBudgetProfile = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse smoke budget profile {}", path.display()))?;
    if profile.schema != DEVNET_SMOKE_BUDGET_SCHEMA {
        return Err(anyhow!(
            "unsupported smoke budget profile schema {}",
            profile.schema
        ));
    }
    Ok(DevnetSmokeBudgetLimits {
        max_total_cycles: profile.max_total_cycles,
        max_tx_cycles: profile.max_tx_cycles,
        max_total_bytes: profile.max_total_bytes,
        max_tx_bytes: profile.max_tx_bytes,
        transactions: profile.transactions,
        proof_profiles: profile.proof_profiles,
    })
}

pub fn assert_default_devnet_smoke(
    dir: &Path,
    contracts_dir: &Path,
) -> Result<DevnetSmokeAssertionReport> {
    assert_default_devnet_smoke_with_budget(dir, contracts_dir, None)
}

pub fn assert_default_devnet_smoke_with_budget(
    dir: &Path,
    contracts_dir: &Path,
    budget_limits: Option<&DevnetSmokeBudgetLimits>,
) -> Result<DevnetSmokeAssertionReport> {
    let summary = summarize_devnet_smoke(dir)?;
    assert_devnet_smoke_summary(&summary)?;
    assert_deployed_script_hashes(&summary, contracts_dir)?;
    let budget = budget_limits
        .filter(|limits| limits.has_any_limit())
        .map(|limits| assert_smoke_budget(&summary, limits))
        .transpose()?;
    Ok(DevnetSmokeAssertionReport {
        git_commit: summary.manifest.get("git_commit").cloned(),
        git_dirty: summary.manifest.get("git_dirty").cloned(),
        directory: summary.directory,
        transaction_count: summary.totals.transaction_count,
        committed_count: summary.totals.committed_count,
        expected_script_failures: EXPECTED_SCRIPT_FAILURES.len(),
        deployed_scripts: summary.deployed_scripts.len(),
        deployed_script_hashes_verified: true,
        watchtower_alerts: summary.watchtower_alerts.len(),
        watchtower_publication_alerts: summary
            .watchtower_alerts
            .iter()
            .filter(|alert| {
                alert.event == "publication_submitted"
                    || alert.event == "splice_publication_submitted"
            })
            .count(),
        watchtower_service_records: summary.watchtower_services.len(),
        factory_reduced_rights_updates: summary.factory_reduced_rights_updates.len(),
        factory_merkle_updates: summary.factory_merkle_updates.len(),
        factory_proof_profiles: summary.factory_proof_profiles.len(),
        factory_reduced_exits: summary.factory_reduced_exits.len(),
        factory_local_exits: summary.factory_local_exits.len(),
        factory_splices: summary.factory_splices.len(),
        splice_payouts: summary.splice_payouts.len(),
        budget,
    })
}

pub fn assert_devnet_smoke_summary(summary: &DevnetSmokeSummary) -> Result<()> {
    if summary.manifest.get("status").map(String::as_str) != Some("passed") {
        return Err(anyhow!("smoke manifest status is not passed"));
    }
    if summary.totals.transaction_count == 0 || summary.totals.committed_count == 0 {
        return Err(anyhow!("smoke summary contains no committed transactions"));
    }
    assert_business_matrix_coverage(summary)?;
    if summary.script_failures.len() != EXPECTED_SCRIPT_FAILURES.len() {
        return Err(anyhow!(
            "unexpected script failure count: got {}, expected {}",
            summary.script_failures.len(),
            EXPECTED_SCRIPT_FAILURES.len()
        ));
    }
    for expected in EXPECTED_SCRIPT_FAILURES {
        let found = summary.script_failures.iter().any(|failure| {
            failure.check == expected.check
                && failure.morph_error.as_deref() == Some(expected.morph_error)
                && failure.error_code == Some(expected.error_code)
        });
        if !found {
            return Err(anyhow!(
                "missing expected script failure: {} {} {}",
                expected.check,
                expected.morph_error,
                expected.error_code
            ));
        }
    }

    if summary.deployed_scripts.len() != EXPECTED_DEPLOYED_SCRIPT_NAMES.len() {
        return Err(anyhow!(
            "unexpected deployed script count: got {}, expected {}",
            summary.deployed_scripts.len(),
            EXPECTED_DEPLOYED_SCRIPT_NAMES.len()
        ));
    }
    let deployed_names = summary
        .deployed_scripts
        .iter()
        .map(|script| script.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_names = EXPECTED_DEPLOYED_SCRIPT_NAMES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if deployed_names != expected_names {
        return Err(anyhow!(
            "unexpected deployed script set: got {:?}, expected {:?}",
            deployed_names,
            expected_names
        ));
    }
    if summary
        .deployed_scripts
        .iter()
        .any(|script| script.hash_type != "data1" || script.data_len == 0 || script.capacity == 0)
    {
        return Err(anyhow!(
            "deployed scripts must use data1 hashes and non-empty occupied cells"
        ));
    }

    assert_watchtower_alert_coverage(summary)?;
    assert_watchtower_splice_guard_coverage(summary)?;
    assert_watchtower_service_coverage(summary)?;
    assert_factory_reduced_rights_coverage(summary)?;
    assert_factory_merkle_update_coverage(summary)?;
    assert_factory_proof_profile_coverage(summary)?;
    assert_factory_reduced_exit_coverage(summary)?;
    assert_factory_splice_coverage(summary)?;
    assert_splice_smoke_coverage(summary)?;

    let expected_factory_local_exits = [
        ("factory/exit-channel", 1u16),
        ("factory/local-exit-package", 1),
        ("factory-xudt/local-exit-package", 2),
        ("factory-xudt/smoke", 2),
        ("factory-xudt-negative/local-exit-package", 2),
        ("factory-xudt-negative/smoke", 2),
        ("factory-splice-in-smoke", 1),
        ("factory-splice-out-smoke", 1),
        ("factory-reduced-xudt-splice-in-smoke", 2),
        ("factory-reduced-xudt-splice-out-smoke", 2),
        ("factory-xudt-splice-in-smoke", 2),
        ("factory-xudt-splice-out-smoke", 2),
    ];
    for (check, descriptor_version) in expected_factory_local_exits.iter().copied() {
        let found = summary
            .factory_local_exits
            .iter()
            .any(|exit| exit.check == check && exit.descriptor_version == descriptor_version);
        if !found {
            return Err(anyhow!(
                "missing factory local-exit evidence for {check} descriptor {descriptor_version}"
            ));
        }
    }
    if summary
        .factory_local_exits
        .iter()
        .any(|exit| exit.child_phase != "active" || exit.child_state_number != 0)
    {
        return Err(anyhow!(
            "factory local-exit evidence must create active child state number 0"
        ));
    }
    let expected_checks = expected_factory_local_exits
        .iter()
        .map(|(check, _)| *check)
        .collect::<BTreeSet<_>>();
    let matched_exits = summary
        .factory_local_exits
        .iter()
        .filter(|exit| expected_checks.contains(exit.check.as_str()))
        .collect::<Vec<_>>();
    if matched_exits.len() != expected_factory_local_exits.len() {
        return Err(anyhow!(
            "unexpected expected factory local-exit evidence count: got {}, expected {}",
            matched_exits.len(),
            expected_factory_local_exits.len()
        ));
    }
    let ckb_descriptors = matched_exits
        .iter()
        .filter(|exit| exit.descriptor_version == 1)
        .count();
    let xudt_descriptors = matched_exits
        .iter()
        .filter(|exit| exit.descriptor_version == 2)
        .count();
    if ckb_descriptors != 4 || xudt_descriptors != 8 {
        return Err(anyhow!(
            "unexpected factory descriptor coverage: got CKB {ckb_descriptors}, xUDT {xudt_descriptors}; expected CKB 4, xUDT 8"
        ));
    }
    Ok(())
}

fn assert_business_matrix_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    let json_checks = summary
        .json_checks
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for expected in EXPECTED_BUSINESS_MATRIX_JSON_CHECKS {
        if !json_checks.contains(expected) {
            return Err(anyhow!("missing business matrix JSON check: {expected}"));
        }
    }

    for (check, path) in EXPECTED_BUSINESS_MATRIX_TRANSACTIONS {
        let committed = summary.transactions.iter().any(|tx| {
            tx.check == *check && tx.path == *path && tx.status.as_deref() == Some("Committed")
        });
        if !committed {
            return Err(anyhow!(
                "missing committed business matrix transaction {check} {path}"
            ));
        }
    }
    Ok(())
}

fn assert_splice_smoke_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    for (check, payout_policy, requires_withdrawal) in [
        ("splice-in-smoke", "none", false),
        ("splice-out-smoke", "participant_signature_pubkey", true),
        ("xudt-splice-in-smoke", "none", false),
        (
            "xudt-splice-out-smoke",
            "participant_signature_pubkey",
            true,
        ),
    ] {
        let finalise_path = if check.starts_with("xudt-") {
            "$.xudt_finalise"
        } else {
            "$.finalise"
        };
        for path in [
            "$.apply",
            "$.post_splice_sponsor",
            "$.publish",
            finalise_path,
        ] {
            let committed = summary.transactions.iter().any(|tx| {
                tx.check == check && tx.path == path && tx.status.as_deref() == Some("Committed")
            });
            if !committed {
                return Err(anyhow!(
                    "missing committed splice smoke transaction {check} {path}"
                ));
            }
        }
        assert_splice_payout_evidence(summary, check, payout_policy, requires_withdrawal)?;
    }
    Ok(())
}

fn assert_splice_payout_evidence(
    summary: &DevnetSmokeSummary,
    check: &str,
    payout_policy: &str,
    requires_withdrawal: bool,
) -> Result<()> {
    let Some(evidence) = summary
        .splice_payouts
        .iter()
        .find(|evidence| evidence.check == check && evidence.path == "$.apply")
    else {
        return Err(anyhow!(
            "missing splice payout evidence for {check} $.apply"
        ));
    };
    if evidence.withdrawal_payout_policy != payout_policy {
        return Err(anyhow!(
            "splice payout policy for {check} was {}, expected {}",
            evidence.withdrawal_payout_policy,
            payout_policy
        ));
    }
    if requires_withdrawal {
        if evidence
            .withdrawal_participant_pubkey_sec1
            .as_deref()
            .is_none_or(|pubkey| !pubkey.starts_with("0x") || pubkey.len() <= 2)
            || evidence
                .withdrawal_lock_hash
                .as_deref()
                .is_none_or(|hash| !hash.starts_with("0x") || hash.len() != 66)
            || evidence.withdrawal_out_point.is_none()
        {
            return Err(anyhow!(
                "splice payout evidence for {check} must include participant pubkey, lock hash, and withdrawal out point"
            ));
        }
    } else if evidence.withdrawal_participant_pubkey_sec1.is_some()
        || evidence.withdrawal_lock_hash.is_some()
        || evidence.withdrawal_out_point.is_some()
    {
        return Err(anyhow!(
            "splice-in payout evidence for {check} must not include withdrawal target fields"
        ));
    }
    Ok(())
}

fn assert_factory_reduced_rights_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    let update_committed = summary.transactions.iter().any(|tx| {
        tx.check == "factory-reduced-rights-smoke"
            && tx.path == "$.update"
            && tx.status.as_deref() == Some("Committed")
    });
    if !update_committed {
        return Err(anyhow!(
            "missing committed factory-reduced-rights smoke update transaction"
        ));
    }

    if summary.factory_reduced_rights_updates.is_empty() {
        return Err(anyhow!("missing factory reduced-rights package evidence"));
    }
    for update in &summary.factory_reduced_rights_updates {
        if update.new_update_number <= update.old_update_number {
            return Err(anyhow!(
                "factory reduced-rights update must be strictly monotonic"
            ));
        }
        if update.signing_digest.is_empty() || update.non_interference_digest.is_empty() {
            return Err(anyhow!(
                "factory reduced-rights update must include signing and non-interference digests"
            ));
        }
        if update.witness_len == 0 {
            return Err(anyhow!(
                "factory reduced-rights update must include witness length"
            ));
        }
    }
    Ok(())
}

fn assert_factory_merkle_update_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    let update_committed = summary.transactions.iter().any(|tx| {
        tx.check == "factory-merkle-update-smoke"
            && tx.path == "$.update"
            && tx.status.as_deref() == Some("Committed")
    });
    if !update_committed {
        return Err(anyhow!(
            "missing committed factory-merkle-update smoke transaction"
        ));
    }

    if summary.factory_merkle_updates.is_empty() {
        return Err(anyhow!("missing factory Merkle update package evidence"));
    }
    for update in &summary.factory_merkle_updates {
        if update.new_update_number <= update.old_update_number {
            return Err(anyhow!("factory Merkle update must be strictly monotonic"));
        }
        if update.proof_siblings != 256 || update.witness_len == 0 {
            return Err(anyhow!(
                "factory Merkle update must include the full sparse proof witness"
            ));
        }
        if update.quantity_after >= update.quantity_before {
            return Err(anyhow!(
                "factory Merkle update fixture must decrease a right"
            ));
        }
        if update.signing_digest.is_empty() || update.non_interference_digest.is_empty() {
            return Err(anyhow!(
                "factory Merkle update must include signing and non-interference digests"
            ));
        }
    }
    Ok(())
}

fn assert_factory_proof_profile_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    assert_factory_proof_profile(
        summary,
        "factory-reduced-rights-smoke",
        "factory_reduced_rights_bounded_claim_decrease",
        "$.update",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-merkle-update-smoke",
        "factory_sparse_merkle_update",
        "$.update",
        Some(256),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-exit-smoke",
        "factory_reduced_exit_ckb_reserve_claim",
        "$.exit",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-exit-asymmetric-smoke",
        "factory_reduced_exit_ckb_reserve_claim",
        "$.exit",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-xudt-exit-smoke",
        "factory_reduced_exit_xudt_change_reserve_claim",
        "$.exit",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-xudt-exit-full-smoke",
        "factory_reduced_exit_xudt_reserve_claim",
        "$.exit",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-xudt-exit-one-sided-smoke",
        "factory_reduced_exit_xudt_one_sided_reserve_claim",
        "$.exit",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-splice-in-smoke",
        "factory_splice_all_participants_ckb",
        "$.apply",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-splice-out-smoke",
        "factory_splice_all_participants_ckb",
        "$.apply",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-splice-in-smoke",
        "factory_reduced_splice_ckb_sparse_merkle",
        "$.apply",
        Some(morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-splice-out-smoke",
        "factory_reduced_splice_ckb_sparse_merkle",
        "$.apply",
        Some(morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-xudt-splice-in-smoke",
        "factory_reduced_splice_xudt_sparse_merkle",
        "$.apply",
        Some(morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-reduced-xudt-splice-out-smoke",
        "factory_reduced_splice_xudt_sparse_merkle",
        "$.apply",
        Some(morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-xudt-splice-in-smoke",
        "factory_splice_all_participants_xudt",
        "$.apply",
        Some(0),
    )?;
    assert_factory_proof_profile(
        summary,
        "factory-xudt-splice-out-smoke",
        "factory_splice_all_participants_xudt",
        "$.apply",
        Some(0),
    )?;
    Ok(())
}

fn assert_factory_proof_profile(
    summary: &DevnetSmokeSummary,
    check: &str,
    proof_kind: &str,
    transaction_path: &str,
    proof_siblings: Option<usize>,
) -> Result<()> {
    let Some(profile) = summary.factory_proof_profiles.iter().find(|profile| {
        profile.check == check
            && profile.proof_kind == proof_kind
            && profile.transaction_path == transaction_path
    }) else {
        return Err(anyhow!(
            "missing factory proof budget profile evidence for {check} {proof_kind}"
        ));
    };
    if proof_siblings.is_some_and(|siblings| profile.proof_siblings != siblings)
        || profile.witness_len == 0
        || profile.estimated_cycles == 0
        || profile.tx_size_bytes == 0
    {
        return Err(anyhow!(
            "factory proof budget profile for {check} must bind proof shape to non-zero transaction metrics"
        ));
    }
    Ok(())
}

fn assert_factory_reduced_exit_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    for check in [
        "factory-reduced-exit-smoke",
        "factory-reduced-exit-asymmetric-smoke",
        "factory-reduced-xudt-exit-smoke",
        "factory-reduced-xudt-exit-full-smoke",
        "factory-reduced-xudt-exit-one-sided-smoke",
    ] {
        let committed = summary.transactions.iter().any(|tx| {
            tx.check == check && tx.path == "$.exit" && tx.status.as_deref() == Some("Committed")
        });
        if !committed {
            return Err(anyhow!(
                "missing committed factory reduced-exit smoke transaction {check}"
            ));
        }
    }
    if summary.factory_reduced_exits.len() != EXPECTED_FACTORY_REDUCED_EXITS {
        return Err(anyhow!(
            "unexpected factory reduced-exit evidence count: got {}, expected {}",
            summary.factory_reduced_exits.len(),
            EXPECTED_FACTORY_REDUCED_EXITS
        ));
    }
    let ckb_exits = summary
        .factory_reduced_exits
        .iter()
        .filter(|exit| exit.xudt_type_hash.is_none())
        .count();
    if ckb_exits != EXPECTED_FACTORY_REDUCED_CKB_EXITS {
        return Err(anyhow!(
            "unexpected factory reduced-exit descriptor coverage: got CKB {}, expected CKB {}",
            ckb_exits,
            EXPECTED_FACTORY_REDUCED_CKB_EXITS,
        ));
    }
    let xudt_exits = summary
        .factory_reduced_exits
        .iter()
        .filter(|exit| exit.xudt_type_hash.is_some())
        .count();
    if xudt_exits != EXPECTED_FACTORY_REDUCED_XUDT_EXITS {
        return Err(anyhow!(
            "unexpected factory reduced-exit descriptor coverage: got xUDT {}, expected xUDT {}",
            xudt_exits,
            EXPECTED_FACTORY_REDUCED_XUDT_EXITS,
        ));
    }
    for check in [
        "factory-reduced-xudt-exit-smoke",
        "factory-reduced-xudt-exit-full-smoke",
        "factory-reduced-xudt-exit-one-sided-smoke",
    ] {
        let exit = summary
            .factory_reduced_exits
            .iter()
            .find(|exit| exit.check == check)
            .ok_or_else(|| anyhow!("missing xUDT factory reduced-exit evidence for {check}"))?;
        let child_amount = exit
            .child_xudt_amount
            .ok_or_else(|| anyhow!("{check} must record the child xUDT amount"))?;
        ensure!(
            exit.release_quantity == child_amount,
            "{check} release_quantity must equal child xUDT amount"
        );
        ensure!(
            exit.xudt_type_hash
                .as_deref()
                .is_some_and(|value| value.starts_with("0x") && value.len() == 66),
            "{check} must record a canonical xUDT type hash"
        );
        ensure!(
            exit.alice_xudt_amount
                .zip(exit.bob_xudt_amount)
                .is_some_and(|(alice, bob)| alice.checked_add(bob) == Some(child_amount)),
            "{check} Alice/Bob xUDT amounts must sum to the child amount"
        );
        ensure!(
            exit.factory_vault_change_xudt_amount.is_some(),
            "{check} must record the FactoryVault typed change amount"
        );
    }
    let partial = summary
        .factory_reduced_exits
        .iter()
        .find(|exit| exit.check == "factory-reduced-xudt-exit-smoke")
        .ok_or_else(|| anyhow!("missing partial xUDT factory reduced-exit evidence"))?;
    ensure!(
        partial.factory_vault_change_xudt_amount.unwrap_or_default() > 0,
        "partial xUDT reduced exit must retain a typed FactoryVault change"
    );
    let full = summary
        .factory_reduced_exits
        .iter()
        .find(|exit| exit.check == "factory-reduced-xudt-exit-full-smoke")
        .ok_or_else(|| anyhow!("missing full xUDT factory reduced-exit evidence"))?;
    ensure!(
        full.factory_vault_change_xudt_amount.unwrap_or_default() == 0,
        "full xUDT reduced exit must record zero typed FactoryVault change"
    );
    let one_sided = summary
        .factory_reduced_exits
        .iter()
        .find(|exit| exit.check == "factory-reduced-xudt-exit-one-sided-smoke")
        .ok_or_else(|| anyhow!("missing one-sided xUDT factory reduced-exit evidence"))?;
    ensure!(
        matches!(
            (one_sided.alice_xudt_amount, one_sided.bob_xudt_amount),
            (Some(0), Some(amount)) | (Some(amount), Some(0)) if amount > 0
        ),
        "one-sided xUDT reduced exit must settle all tokens to one participant"
    );
    if summary.factory_reduced_exits.iter().any(|exit| {
        exit.authorisation != "reduced-reserve-claim"
            || exit.release_quantity == 0
            || exit.witness_len == 0
            || exit.local_exit_digest.is_empty()
            || exit.non_interference_digest.is_empty()
    }) {
        return Err(anyhow!(
            "factory reduced-exit evidence must include reserve-claim authorisation, release quantity, witness length, and digests"
        ));
    }
    Ok(())
}

fn assert_watchtower_service_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    if summary.watchtower_services.len() != EXPECTED_WATCHTOWER_SERVICE_RECORDS {
        return Err(anyhow!(
            "unexpected watchtower service record count: got {}, expected {}",
            summary.watchtower_services.len(),
            EXPECTED_WATCHTOWER_SERVICE_RECORDS
        ));
    }
    let service = summary
        .watchtower_services
        .iter()
        .find(|record| record.schema == "morph.watchtower_config_service")
        .ok_or_else(|| anyhow!("missing watchtower service report"))?;
    if service.stopped_reason.as_deref() != Some("stop_file") {
        return Err(anyhow!(
            "watchtower service report must stop through stop_file"
        ));
    }
    if service.completed_passes != 0 || service.error_count != 0 {
        return Err(anyhow!(
            "watchtower service stop-file smoke must stop before passes or errors"
        ));
    }
    if service.health_file.is_none() {
        return Err(anyhow!(
            "watchtower service report must include health_file"
        ));
    }

    let health = summary
        .watchtower_services
        .iter()
        .find(|record| record.schema == "morph.watchtower_health")
        .ok_or_else(|| anyhow!("missing watchtower health report"))?;
    if health.status.as_deref() != Some("stopped")
        || health.stopped_reason.as_deref() != Some("stop_file")
    {
        return Err(anyhow!(
            "watchtower health report must show stopped by stop_file"
        ));
    }
    if health.completed_passes != 0 || health.error_count != 0 {
        return Err(anyhow!(
            "watchtower health stop-file smoke must stop before passes or errors"
        ));
    }
    Ok(())
}

fn assert_factory_splice_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    let expected = [
        ("factory-splice-in-smoke", "splice_in", "ckb", true, false),
        ("factory-splice-out-smoke", "splice_out", "ckb", false, true),
        (
            "factory-reduced-splice-in-smoke",
            "splice_in",
            "ckb",
            true,
            false,
        ),
        (
            "factory-reduced-splice-out-smoke",
            "splice_out",
            "ckb",
            false,
            true,
        ),
        (
            "factory-reduced-xudt-splice-in-smoke",
            "splice_in",
            "xudt:",
            true,
            false,
        ),
        (
            "factory-reduced-xudt-splice-out-smoke",
            "splice_out",
            "xudt:",
            false,
            true,
        ),
        (
            "factory-xudt-splice-in-smoke",
            "splice_in",
            "xudt:",
            true,
            false,
        ),
        (
            "factory-xudt-splice-out-smoke",
            "splice_out",
            "xudt:",
            false,
            true,
        ),
    ];
    for item in expected {
        assert_factory_splice_smoke(summary, item)?;
    }
    let expected_checks = expected
        .iter()
        .map(|(check, _, _, _, _)| *check)
        .collect::<BTreeSet<_>>();
    let matched_expected = summary
        .factory_splices
        .iter()
        .filter(|splice| expected_checks.contains(splice.check.as_str()))
        .count();
    if matched_expected != expected.len() {
        return Err(anyhow!(
            "unexpected expected factory splice evidence count: got {}, expected {}",
            matched_expected,
            expected.len()
        ));
    }
    Ok(())
}

fn assert_factory_splice_smoke(
    summary: &DevnetSmokeSummary,
    (check, kind, asset_prefix, expects_external, expects_withdrawal): (
        &str,
        &str,
        &str,
        bool,
        bool,
    ),
) -> Result<()> {
    for path in ["$.open", "$.apply", "$.exit"] {
        let committed = summary.transactions.iter().any(|tx| {
            tx.check == check && tx.path == path && tx.status.as_deref() == Some("Committed")
        });
        if !committed {
            return Err(anyhow!(
                "missing committed factory splice smoke transaction {check} {path}"
            ));
        }
    }
    if expects_external && check.contains("xudt") {
        let committed = summary.transactions.iter().any(|tx| {
            tx.check == check
                && tx.path == "$.external_xudt"
                && tx.status.as_deref() == Some("Committed")
        });
        if !committed {
            return Err(anyhow!(
                "missing committed factory splice external xUDT transaction {check}"
            ));
        }
    }

    let Some(splice) = summary.factory_splices.iter().find(|splice| {
        splice.check == check
            && splice.path == "$.package.package"
            && splice.kind == kind
            && splice.reserve_claim_asset.starts_with(asset_prefix)
    }) else {
        return Err(anyhow!(
            "missing factory splice package evidence for {check} {kind} {asset_prefix}"
        ));
    };
    if splice.new_update_number <= splice.old_update_number
        || splice.signing_digest.is_empty()
        || splice.vault_delta_commitment.is_empty()
        || splice.non_interference_digest.is_empty()
        || splice.witness_len == 0
    {
        return Err(anyhow!(
            "factory splice evidence for {check} must bind monotonic update, signatures, digests, and witness length"
        ));
    }
    let reduced = check.contains("reduced");
    let expected_min_signatures = if reduced { 1 } else { 2 };
    let expected_proof_siblings = if reduced {
        morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH
    } else {
        0
    };
    if splice.signatures < expected_min_signatures
        || splice.proof_siblings != expected_proof_siblings
    {
        return Err(anyhow!(
            "factory splice evidence for {check} has unexpected signature/proof shape"
        ));
    }
    if expects_external
        && (splice.external_input == 0
            || splice.withdrawal != 0
            || splice.reserve_claim_after <= splice.reserve_claim_before
            || splice.vault_new_amount <= splice.vault_old_amount)
    {
        return Err(anyhow!(
            "factory splice-in evidence for {check} has inconsistent reserve/vault direction"
        ));
    }
    if expects_withdrawal
        && (splice.withdrawal == 0
            || splice.external_input != 0
            || splice.reserve_claim_after >= splice.reserve_claim_before
            || splice.vault_new_amount >= splice.vault_old_amount)
    {
        return Err(anyhow!(
            "factory splice-out evidence for {check} has inconsistent reserve/vault direction"
        ));
    }
    Ok(())
}

fn assert_watchtower_alert_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    if summary.watchtower_alerts.len() < EXPECTED_WATCHTOWER_EVENTS.len() {
        return Err(anyhow!(
            "insufficient watchtower alert count: got {}, expected at least {}",
            summary.watchtower_alerts.len(),
            EXPECTED_WATCHTOWER_EVENTS.len()
        ));
    }
    for expected in EXPECTED_WATCHTOWER_EVENTS {
        if !summary
            .watchtower_alerts
            .iter()
            .any(|alert| alert.event == *expected)
        {
            return Err(anyhow!(
                "missing expected watchtower alert event: {expected}"
            ));
        }
    }
    for alert in &summary.watchtower_alerts {
        if alert.next_from_block <= alert.scanned_to_block {
            return Err(anyhow!(
                "watchtower alert {} did not advance the scan cursor",
                alert.event
            ));
        }
        if alert.event == "scan_idle" {
            if alert.severity != "info" {
                return Err(anyhow!("watchtower idle alert must be info severity"));
            }
            continue;
        }
        if alert.severity != "warning" {
            return Err(anyhow!(
                "watchtower alert {} must be warning severity",
                alert.event
            ));
        }
        let Some(observed_state_number) = alert.observed_state_number else {
            return Err(anyhow!(
                "watchtower alert {} must include observed state number",
                alert.event
            ));
        };
        if alert.observed_out_point.is_none() {
            return Err(anyhow!(
                "watchtower alert {} must include observed out point",
                alert.event
            ));
        }
        let requires_newer_selected_state = matches!(
            alert.event.as_str(),
            "older_state_detected" | "publication_submitted" | "splice_publication_submitted"
        );
        if requires_newer_selected_state && alert.selected_state_number <= observed_state_number {
            return Err(anyhow!(
                "watchtower alert {} did not select a newer state",
                alert.event
            ));
        }
        if (alert.event == "publication_submitted" || alert.event == "splice_publication_submitted")
            && alert.publication_tx_hash.is_none()
        {
            return Err(anyhow!(
                "watchtower publication alert must include publication transaction hash"
            ));
        }
    }
    Ok(())
}

fn assert_watchtower_splice_guard_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    let apply_committed = summary.transactions.iter().any(|tx| {
        tx.check == "watch-splice-stale/apply"
            && tx.path == "$"
            && tx.status.as_deref() == Some("Committed")
    });
    if !apply_committed {
        return Err(anyhow!(
            "missing committed watchtower splice guard transaction"
        ));
    }

    for expected in ["splice_detected", "splice_package_stale"] {
        let found = summary.watchtower_alerts.iter().any(|alert| {
            alert.check == "watch-splice-stale/watch-alerts" && alert.event == expected
        });
        if !found {
            return Err(anyhow!(
                "missing watchtower splice guard alert event: {expected}"
            ));
        }
    }

    let stale_publication = summary.watchtower_alerts.iter().any(|alert| {
        alert.check == "watch-splice-stale/watch-alerts"
            && (alert.event == "publication_submitted"
                || alert.event == "splice_publication_submitted")
    });
    if stale_publication {
        return Err(anyhow!(
            "watchtower splice guard must not publish a stale package"
        ));
    }

    let watch_transaction = summary
        .transactions
        .iter()
        .any(|tx| tx.check == "watch-splice-stale/watch");
    if watch_transaction {
        return Err(anyhow!(
            "watchtower splice guard watch report must not include a publication transaction"
        ));
    }
    Ok(())
}

pub fn assert_deployed_script_hashes(
    summary: &DevnetSmokeSummary,
    contracts_dir: &Path,
) -> Result<()> {
    for expected in EXPECTED_DEPLOYED_SCRIPT_NAMES {
        let script = summary
            .deployed_scripts
            .iter()
            .find(|script| script.name == *expected)
            .ok_or_else(|| anyhow!("missing deployed script record for {expected}"))?;
        let path = contracts_dir.join(expected);
        let data = fs::read(&path)
            .with_context(|| format!("failed to read contract binary {}", path.display()))?;
        let expected_hash = format!("0x{}", hex::encode(blake2b_256(&data)));
        if script.data_hash != expected_hash {
            return Err(anyhow!(
                "deployed script {} hash mismatch: summary {}, local {}",
                expected,
                script.data_hash,
                expected_hash
            ));
        }
        if script.data_len != data.len() {
            return Err(anyhow!(
                "deployed script {} length mismatch: summary {}, local {}",
                expected,
                script.data_len,
                data.len()
            ));
        }
    }
    Ok(())
}

pub fn compare_summaries(
    baseline: &DevnetSmokeSummary,
    candidate: &DevnetSmokeSummary,
) -> DevnetSmokeComparison {
    let baseline_map = transaction_map(&baseline.transactions);
    let candidate_map = transaction_map(&candidate.transactions);

    let mut transaction_deltas = Vec::new();
    let mut missing_from_candidate = Vec::new();
    for (key, baseline_tx) in &baseline_map {
        let Some(candidate_tx) = candidate_map.get(key) else {
            missing_from_candidate.push(key.clone());
            continue;
        };
        transaction_deltas.push(TransactionMetricDelta {
            key: key.clone(),
            baseline_status: baseline_tx.status.clone(),
            candidate_status: candidate_tx.status.clone(),
            baseline_estimated_cycles: baseline_tx.estimated_cycles,
            candidate_estimated_cycles: candidate_tx.estimated_cycles,
            estimated_cycles_delta: signed_delta_u64(
                baseline_tx.estimated_cycles,
                candidate_tx.estimated_cycles,
            ),
            baseline_tx_size_bytes: baseline_tx.tx_size_bytes,
            candidate_tx_size_bytes: candidate_tx.tx_size_bytes,
            tx_size_bytes_delta: signed_delta_usize(
                baseline_tx.tx_size_bytes,
                candidate_tx.tx_size_bytes,
            ),
        });
    }
    transaction_deltas.sort_by(|left, right| left.key.cmp(&right.key));

    let mut added_in_candidate = Vec::new();
    for key in candidate_map.keys() {
        if !baseline_map.contains_key(key) {
            added_in_candidate.push(key.clone());
        }
    }

    DevnetSmokeComparison {
        baseline_directory: baseline.directory.clone(),
        candidate_directory: candidate.directory.clone(),
        compared_transactions: transaction_deltas.len(),
        missing_from_candidate,
        added_in_candidate,
        total_estimated_cycles_delta: signed_delta_u64(
            baseline.totals.total_estimated_cycles,
            candidate.totals.total_estimated_cycles,
        ),
        total_tx_size_bytes_delta: signed_delta_usize(
            baseline.totals.total_tx_size_bytes,
            candidate.totals.total_tx_size_bytes,
        ),
        transaction_deltas,
    }
}

pub fn assert_comparison_limits(
    comparison: &DevnetSmokeComparison,
    limits: &DevnetSmokeComparisonLimits,
) -> Result<()> {
    if limits.fail_on_transaction_set_change {
        if !comparison.missing_from_candidate.is_empty() {
            return Err(anyhow!(
                "candidate smoke is missing {} baseline transactions",
                comparison.missing_from_candidate.len()
            ));
        }
        if !comparison.added_in_candidate.is_empty() {
            return Err(anyhow!(
                "candidate smoke added {} transactions",
                comparison.added_in_candidate.len()
            ));
        }
    }

    if limits.fail_on_status_change
        && let Some(delta) = comparison
            .transaction_deltas
            .iter()
            .find(|delta| delta.baseline_status != delta.candidate_status)
    {
        return Err(anyhow!(
            "transaction {} status changed from {} to {}",
            delta.key,
            delta.baseline_status.as_deref().unwrap_or(""),
            delta.candidate_status.as_deref().unwrap_or("")
        ));
    }

    if let Some(limit) = limits.max_abs_total_cycle_delta {
        let actual = abs_i64(comparison.total_estimated_cycles_delta);
        if actual > limit {
            return Err(anyhow!("total cycle delta {actual} exceeds limit {limit}"));
        }
    }
    if let Some(limit) = limits.max_abs_total_byte_delta {
        let actual = abs_i64(comparison.total_tx_size_bytes_delta);
        if actual > limit {
            return Err(anyhow!("total byte delta {actual} exceeds limit {limit}"));
        }
    }
    if let Some(limit) = limits.max_abs_tx_cycle_delta
        && let Some(delta) = comparison
            .transaction_deltas
            .iter()
            .find(|delta| abs_i64(delta.estimated_cycles_delta) > limit)
    {
        return Err(anyhow!(
            "transaction {} cycle delta {} exceeds limit {}",
            delta.key,
            abs_i64(delta.estimated_cycles_delta),
            limit
        ));
    }
    if let Some(limit) = limits.max_abs_tx_byte_delta
        && let Some(delta) = comparison
            .transaction_deltas
            .iter()
            .find(|delta| abs_i64(delta.tx_size_bytes_delta) > limit)
    {
        return Err(anyhow!(
            "transaction {} byte delta {} exceeds limit {}",
            delta.key,
            abs_i64(delta.tx_size_bytes_delta),
            limit
        ));
    }
    Ok(())
}

pub fn assert_smoke_budget(
    summary: &DevnetSmokeSummary,
    limits: &DevnetSmokeBudgetLimits,
) -> Result<DevnetSmokeBudgetReport> {
    if let Some(limit) = limits.max_total_cycles {
        let actual = summary.totals.total_estimated_cycles;
        if actual > limit {
            return Err(anyhow!(
                "total estimated cycles {actual} exceeds budget {limit}"
            ));
        }
    }
    if let Some(limit) = limits.max_tx_cycles {
        let actual = summary.totals.max_estimated_cycles;
        if actual > limit {
            return Err(anyhow!(
                "max transaction estimated cycles {actual} exceeds budget {limit}"
            ));
        }
    }
    if let Some(limit) = limits.max_total_bytes {
        let actual = summary.totals.total_tx_size_bytes;
        if actual > limit {
            return Err(anyhow!(
                "total transaction bytes {actual} exceeds budget {limit}"
            ));
        }
    }
    if let Some(limit) = limits.max_tx_bytes {
        let actual = summary.totals.max_tx_size_bytes;
        if actual > limit {
            return Err(anyhow!(
                "max transaction bytes {actual} exceeds budget {limit}"
            ));
        }
    }

    let mut transaction_reports = Vec::new();
    for limit in &limits.transactions {
        let transaction = summary
            .transactions
            .iter()
            .find(|tx| tx.check == limit.check && tx.path == limit.path)
            .ok_or_else(|| {
                anyhow!(
                    "budgeted transaction {} {} is missing from smoke summary",
                    limit.check,
                    limit.path
                )
            })?;
        if let Some(max_cycles) = limit.max_cycles
            && transaction.estimated_cycles > max_cycles
        {
            return Err(anyhow!(
                "transaction {} {} estimated cycles {} exceeds budget {}",
                limit.check,
                limit.path,
                transaction.estimated_cycles,
                max_cycles
            ));
        }
        if let Some(max_bytes) = limit.max_bytes
            && transaction.tx_size_bytes > max_bytes
        {
            return Err(anyhow!(
                "transaction {} {} bytes {} exceeds budget {}",
                limit.check,
                limit.path,
                transaction.tx_size_bytes,
                max_bytes
            ));
        }
        transaction_reports.push(DevnetSmokeTransactionBudgetReport {
            check: limit.check.clone(),
            path: limit.path.clone(),
            estimated_cycles: transaction.estimated_cycles,
            tx_size_bytes: transaction.tx_size_bytes,
            max_cycles: limit.max_cycles,
            max_bytes: limit.max_bytes,
        });
    }

    let mut proof_profile_reports = Vec::new();
    for limit in &limits.proof_profiles {
        let profile = summary
            .factory_proof_profiles
            .iter()
            .find(|profile| {
                profile.check == limit.check
                    && profile.transaction_path == limit.transaction_path
                    && profile.proof_kind == limit.proof_kind
            })
            .ok_or_else(|| {
                anyhow!(
                    "budgeted proof profile {} {} {} is missing from smoke summary",
                    limit.check,
                    limit.transaction_path,
                    limit.proof_kind
                )
            })?;
        if let Some(proof_siblings) = limit.proof_siblings
            && profile.proof_siblings != proof_siblings
        {
            return Err(anyhow!(
                "proof profile {} {} {} siblings {} differs from expected {}",
                limit.check,
                limit.transaction_path,
                limit.proof_kind,
                profile.proof_siblings,
                proof_siblings
            ));
        }
        if let Some(max_witness_len) = limit.max_witness_len
            && profile.witness_len > max_witness_len
        {
            return Err(anyhow!(
                "proof profile {} {} {} witness length {} exceeds budget {}",
                limit.check,
                limit.transaction_path,
                limit.proof_kind,
                profile.witness_len,
                max_witness_len
            ));
        }
        if let Some(max_cycles) = limit.max_cycles
            && profile.estimated_cycles > max_cycles
        {
            return Err(anyhow!(
                "proof profile {} {} {} estimated cycles {} exceeds budget {}",
                limit.check,
                limit.transaction_path,
                limit.proof_kind,
                profile.estimated_cycles,
                max_cycles
            ));
        }
        if let Some(max_bytes) = limit.max_bytes
            && profile.tx_size_bytes > max_bytes
        {
            return Err(anyhow!(
                "proof profile {} {} {} bytes {} exceeds budget {}",
                limit.check,
                limit.transaction_path,
                limit.proof_kind,
                profile.tx_size_bytes,
                max_bytes
            ));
        }
        proof_profile_reports.push(DevnetSmokeProofProfileBudgetReport {
            check: limit.check.clone(),
            transaction_path: limit.transaction_path.clone(),
            proof_kind: limit.proof_kind.clone(),
            proof_siblings: profile.proof_siblings,
            witness_len: profile.witness_len,
            estimated_cycles: profile.estimated_cycles,
            tx_size_bytes: profile.tx_size_bytes,
            expected_proof_siblings: limit.proof_siblings,
            max_witness_len: limit.max_witness_len,
            max_cycles: limit.max_cycles,
            max_bytes: limit.max_bytes,
        });
    }

    Ok(DevnetSmokeBudgetReport {
        total_estimated_cycles: summary.totals.total_estimated_cycles,
        max_estimated_cycles: summary.totals.max_estimated_cycles,
        total_tx_size_bytes: summary.totals.total_tx_size_bytes,
        max_tx_size_bytes: summary.totals.max_tx_size_bytes,
        max_total_cycles: limits.max_total_cycles,
        max_tx_cycles: limits.max_tx_cycles,
        max_total_bytes: limits.max_total_bytes,
        max_tx_bytes: limits.max_tx_bytes,
        transactions: transaction_reports,
        proof_profiles: proof_profile_reports,
    })
}

pub fn render_markdown(summary: &DevnetSmokeSummary) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Smoke Summary\n\n");
    out.push_str(&format!("Directory: `{}`\n\n", summary.directory));

    if !summary.manifest.is_empty() {
        out.push_str("## Manifest\n\n");
        out.push_str("| Key | Value |\n");
        out.push_str("| --- | --- |\n");
        for (key, value) in &summary.manifest {
            out.push_str(&format!(
                "| {} | {} |\n",
                table_cell(key),
                table_cell(value)
            ));
        }
        out.push('\n');
    }

    out.push_str("## Totals\n\n");
    out.push_str("| JSON files | Transactions | Committed | Pending | Total cycles | Max cycles | Total bytes | Max bytes |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} |\n\n",
        summary.json_files,
        summary.totals.transaction_count,
        summary.totals.committed_count,
        summary.totals.pending_count,
        summary.totals.total_estimated_cycles,
        summary.totals.max_estimated_cycles,
        summary.totals.total_tx_size_bytes,
        summary.totals.max_tx_size_bytes
    ));

    out.push_str("## Transactions\n\n");
    out.push_str("| Check | Path | Status | Block | Cycles | Bytes | Tx |\n");
    out.push_str("| --- | --- | --- | ---: | ---: | ---: | --- |\n");
    for tx in &summary.transactions {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | `{}` |\n",
            table_cell(&tx.check),
            table_cell(&tx.path),
            table_cell(tx.status.as_deref().unwrap_or("")),
            tx.block_number
                .map(|number| number.to_string())
                .unwrap_or_default(),
            tx.estimated_cycles,
            tx.tx_size_bytes,
            tx.tx_hash
        ));
    }
    out.push('\n');

    out.push_str("## Splice Payouts\n\n");
    if summary.splice_payouts.is_empty() {
        out.push_str("No splice payout evidence was recorded.\n");
    } else {
        out.push_str(
            "| Check | Path | Policy | Participant pubkey | Lock hash | Withdrawal out point |\n",
        );
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for payout in &summary.splice_payouts {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                table_cell(&payout.check),
                table_cell(&payout.path),
                table_cell(&payout.withdrawal_payout_policy),
                payout
                    .withdrawal_participant_pubkey_sec1
                    .as_deref()
                    .map(|pubkey| format!("`{pubkey}`"))
                    .unwrap_or_default(),
                payout
                    .withdrawal_lock_hash
                    .as_deref()
                    .map(|hash| format!("`{hash}`"))
                    .unwrap_or_default(),
                payout
                    .withdrawal_out_point
                    .as_deref()
                    .map(|out_point| format!("`{out_point}`"))
                    .unwrap_or_default()
            ));
        }
    }
    out.push('\n');

    out.push_str("## Sponsor Policies\n\n");
    if summary.sponsor_policies.is_empty() {
        out.push_str("No sponsor policy evidence was recorded.\n");
    } else {
        out.push_str(
            "| Check | Path | Min state | Max state | Span | Max fee/tx | Max total fee |\n",
        );
        out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n");
        for policy in &summary.sponsor_policies {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                table_cell(&policy.check),
                table_cell(&policy.path),
                policy.min_state_number,
                policy.max_state_number,
                policy.state_number_span,
                policy.max_fee_per_tx,
                policy.max_total_fee
            ));
        }
    }
    out.push('\n');

    out.push_str("## Script Failures\n\n");
    if summary.script_failures.is_empty() {
        out.push_str("No expected script failures were recorded.\n");
    } else {
        out.push_str("| Check | Path | Error | Code | Source |\n");
        out.push_str("| --- | --- | --- | ---: | --- |\n");
        for failure in &summary.script_failures {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                table_cell(&failure.check),
                table_cell(&failure.path),
                table_cell(failure.morph_error.as_deref().unwrap_or("")),
                failure
                    .error_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
                table_cell(failure.source.as_deref().unwrap_or(""))
            ));
        }
    }
    out.push('\n');

    out.push_str("## Deployed Scripts\n\n");
    if summary.deployed_scripts.is_empty() {
        out.push_str("No deployed script records were found.\n");
    } else {
        out.push_str("| Name | Out point | Hash type | Data bytes | Capacity | Data hash |\n");
        out.push_str("| --- | --- | --- | ---: | ---: | --- |\n");
        for script in &summary.deployed_scripts {
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | `{}` |\n",
                table_cell(&script.name),
                script.out_point,
                table_cell(&script.hash_type),
                script.data_len,
                script.capacity,
                script.data_hash
            ));
        }
    }
    out.push('\n');

    out.push_str("## Watchtower Alerts\n\n");
    if summary.watchtower_alerts.is_empty() {
        out.push_str("No watchtower alerts were recorded.\n");
    } else {
        out.push_str(
            "| Check | Event | Severity | Selected | Observed | Publication tx | Cursor |\n",
        );
        out.push_str("| --- | --- | --- | ---: | ---: | --- | --- |\n");
        for alert in &summary.watchtower_alerts {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} -> {} |\n",
                table_cell(&alert.check),
                table_cell(&alert.event),
                table_cell(&alert.severity),
                alert.selected_state_number,
                alert
                    .observed_state_number
                    .map(|number| number.to_string())
                    .unwrap_or_default(),
                alert
                    .publication_tx_hash
                    .as_deref()
                    .map(|hash| format!("`{hash}`"))
                    .unwrap_or_default(),
                alert.scanned_to_block,
                alert.next_from_block
            ));
        }
    }
    out.push('\n');

    out.push_str("## Watchtower Service\n\n");
    if summary.watchtower_services.is_empty() {
        out.push_str("No watchtower service records were found.\n");
    } else {
        out.push_str("| Check | Schema | Status | Stop reason | Passes | Published | Idle | Errors | Health file |\n");
        out.push_str("| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |\n");
        for service in &summary.watchtower_services {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                table_cell(&service.check),
                table_cell(&service.schema),
                table_cell(service.status.as_deref().unwrap_or("")),
                table_cell(service.stopped_reason.as_deref().unwrap_or("")),
                service.completed_passes,
                service.published_count,
                service.idle_count,
                service.error_count,
                table_cell(service.health_file.as_deref().unwrap_or(""))
            ));
        }
    }
    out.push('\n');

    out.push_str("## Factory Reduced-Rights Updates\n\n");
    if summary.factory_reduced_rights_updates.is_empty() {
        out.push_str("No factory reduced-rights packages were recorded.\n");
    } else {
        out.push_str("| Check | Path | Old update | New update | Witness bytes | Signing digest | Non-interference digest |\n");
        out.push_str("| --- | --- | ---: | ---: | ---: | --- | --- |\n");
        for update in &summary.factory_reduced_rights_updates {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | `{}` | `{}` |\n",
                table_cell(&update.check),
                table_cell(&update.path),
                update.old_update_number,
                update.new_update_number,
                update.witness_len,
                update.signing_digest,
                update.non_interference_digest
            ));
        }
    }
    out.push('\n');

    out.push_str("## Factory Merkle Updates\n\n");
    if summary.factory_merkle_updates.is_empty() {
        out.push_str("No factory Merkle update packages were recorded.\n");
    } else {
        out.push_str("| Check | Path | Old update | New update | Quantity | Proof siblings | Witness bytes | Non-interference digest |\n");
        out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n");
        for update in &summary.factory_merkle_updates {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} -> {} | {} | {} | `{}` |\n",
                table_cell(&update.check),
                table_cell(&update.path),
                update.old_update_number,
                update.new_update_number,
                update.quantity_before,
                update.quantity_after,
                update.proof_siblings,
                update.witness_len,
                update.non_interference_digest
            ));
        }
    }
    out.push('\n');

    out.push_str("## Factory Proof Profiles\n\n");
    if summary.factory_proof_profiles.is_empty() {
        out.push_str("No factory proof budget profiles were recorded.\n");
    } else {
        out.push_str(
            "| Check | Kind | Proof siblings | Witness bytes | Cycles | Tx bytes | Evidence |\n",
        );
        out.push_str("| --- | --- | ---: | ---: | ---: | ---: | --- |\n");
        for profile in &summary.factory_proof_profiles {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                table_cell(&profile.check),
                table_cell(&profile.proof_kind),
                profile.proof_siblings,
                profile.witness_len,
                profile.estimated_cycles,
                profile.tx_size_bytes,
                table_cell(&profile.evidence_path)
            ));
        }
    }
    out.push('\n');

    out.push_str("## Factory Reduced Exits\n\n");
    if summary.factory_reduced_exits.is_empty() {
        out.push_str("No factory reduced-exit evidence was recorded.\n");
    } else {
        out.push_str("| Check | Path | Auth | Release | Witness bytes | xUDT amount | Alice xUDT | Bob xUDT | xUDT change | Non-interference digest |\n");
        out.push_str("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n");
        for exit in &summary.factory_reduced_exits {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | `{}` |\n",
                table_cell(&exit.check),
                table_cell(&exit.path),
                table_cell(&exit.authorisation),
                exit.release_quantity,
                exit.witness_len,
                exit.child_xudt_amount
                    .map(|amount| amount.to_string())
                    .unwrap_or_default(),
                exit.alice_xudt_amount
                    .map(|amount| amount.to_string())
                    .unwrap_or_default(),
                exit.bob_xudt_amount
                    .map(|amount| amount.to_string())
                    .unwrap_or_default(),
                exit.factory_vault_change_xudt_amount
                    .map(|amount| amount.to_string())
                    .unwrap_or_default(),
                exit.non_interference_digest
            ));
        }
    }
    out.push('\n');

    out.push_str("## Factory Local Exits\n\n");
    if summary.factory_local_exits.is_empty() {
        out.push_str("No factory local-exit evidence packages were recorded.\n");
    } else {
        out.push_str("| Check | Path | Update | Child state | Phase | Descriptor | State out | Vault out | Exit digest |\n");
        out.push_str("| --- | --- | ---: | ---: | --- | ---: | ---: | ---: | --- |\n");
        for exit in &summary.factory_local_exits {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | `{}` |\n",
                table_cell(&exit.check),
                table_cell(&exit.path),
                exit.update_number,
                exit.child_state_number,
                table_cell(&exit.child_phase),
                exit.descriptor_version,
                exit.state_output_index,
                exit.vault_output_index,
                exit.exit_digest
            ));
        }
    }
    out.push('\n');

    out.push_str("## Factory Splices\n\n");
    if summary.factory_splices.is_empty() {
        out.push_str("No factory splice packages were recorded.\n");
    } else {
        out.push_str("| Check | Path | Kind | Update | Asset | Claim | Vault | External | Withdrawal | Signatures | Witness | Digest |\n");
        out.push_str(
            "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n",
        );
        for splice in &summary.factory_splices {
            out.push_str(&format!(
                "| {} | {} | {} | {} -> {} | {} | {} -> {} | {} -> {} | {} | {} | {} | {} | `{}` |\n",
                table_cell(&splice.check),
                table_cell(&splice.path),
                table_cell(&splice.kind),
                splice.old_update_number,
                splice.new_update_number,
                table_cell(&splice.reserve_claim_asset),
                splice.reserve_claim_before,
                splice.reserve_claim_after,
                splice.vault_old_amount,
                splice.vault_new_amount,
                splice.external_input,
                splice.withdrawal,
                splice.signatures,
                splice.witness_len,
                splice.signing_digest
            ));
        }
    }

    out
}

pub fn render_comparison_markdown(comparison: &DevnetSmokeComparison) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Smoke Comparison\n\n");
    out.push_str(&format!(
        "Baseline: `{}`\n\nCandidate: `{}`\n\n",
        comparison.baseline_directory, comparison.candidate_directory
    ));

    out.push_str("## Totals\n\n");
    out.push_str("| Compared txs | Cycle delta | Byte delta | Missing | Added |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} |\n\n",
        comparison.compared_transactions,
        comparison.total_estimated_cycles_delta,
        comparison.total_tx_size_bytes_delta,
        comparison.missing_from_candidate.len(),
        comparison.added_in_candidate.len()
    ));

    out.push_str("## Transaction Deltas\n\n");
    out.push_str("| Transaction | Status | Cycle delta | Byte delta | Baseline cycles | Candidate cycles | Baseline bytes | Candidate bytes |\n");
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for delta in &comparison.transaction_deltas {
        let status = match (&delta.baseline_status, &delta.candidate_status) {
            (Some(left), Some(right)) if left == right => left.clone(),
            (left, right) => format!(
                "{} -> {}",
                left.as_deref().unwrap_or(""),
                right.as_deref().unwrap_or("")
            ),
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            table_cell(&delta.key),
            table_cell(&status),
            delta.estimated_cycles_delta,
            delta.tx_size_bytes_delta,
            delta.baseline_estimated_cycles,
            delta.candidate_estimated_cycles,
            delta.baseline_tx_size_bytes,
            delta.candidate_tx_size_bytes
        ));
    }
    out.push('\n');

    if !comparison.missing_from_candidate.is_empty() {
        out.push_str("## Missing From Candidate\n\n");
        for key in &comparison.missing_from_candidate {
            out.push_str(&format!("- `{}`\n", key));
        }
        out.push('\n');
    }

    if !comparison.added_in_candidate.is_empty() {
        out.push_str("## Added In Candidate\n\n");
        for key in &comparison.added_in_candidate {
            out.push_str(&format!("- `{}`\n", key));
        }
    }

    out
}

struct ExpectedScriptFailure {
    check: &'static str,
    morph_error: &'static str,
    error_code: i64,
}

const EXPECTED_SCRIPT_FAILURES: &[ExpectedScriptFailure] = &[
    ExpectedScriptFailure {
        check: "factory-reduced-xudt-negative-exit-smoke",
        morph_error: "SettlementOutputMismatch",
        error_code: 28,
    },
    ExpectedScriptFailure {
        check: "factory-xudt-negative/smoke",
        morph_error: "SettlementOutputMismatch",
        error_code: 28,
    },
    ExpectedScriptFailure {
        check: "finalise-since-negative-smoke",
        morph_error: "StateSinceNotMature",
        error_code: 16,
    },
    ExpectedScriptFailure {
        check: "sponsor-budget-negative-smoke",
        morph_error: "SponsorFeeTooHigh",
        error_code: 17,
    },
    ExpectedScriptFailure {
        check: "sponsor-policy-negative-smoke",
        morph_error: "SponsorStateOutOfRange",
        error_code: 29,
    },
    ExpectedScriptFailure {
        check: "xudt-negative-smoke",
        morph_error: "SettlementOutputMismatch",
        error_code: 28,
    },
];
const EXPECTED_DEPLOYED_SCRIPT_NAMES: &[&str] = &[
    "morph-state-lock",
    "morph-state-type",
    "morph-factory-type",
    "morph-factory-vault-lock",
    "morph-vault-lock",
    "morph-batch-lock",
    "morph-sponsor-lock",
    "morph-devnet-xudt",
];
const EXPECTED_BUSINESS_MATRIX_JSON_CHECKS: &[&str] = &[
    "devnet-tip",
    "devnet-wait-tip",
    "manual-channel/package",
    "manual-channel/list-packages",
    "manual-channel/latest-package",
    "manual-channel/publish-latest",
    "manual-sponsor/fund",
    "xudt-one-sided-smoke",
    "splice-in-asymmetric-smoke",
    "splice-out-asymmetric-smoke",
    "xudt-splice-in-one-sided-smoke",
    "xudt-splice-out-one-sided-smoke",
    "factory-smoke",
    "factory-reduced-rights-tight-smoke",
    "factory-merkle-update-tight-smoke",
    "factory-reduced-exit-asymmetric-smoke",
    "factory-reduced-xudt-exit-smoke",
    "factory-reduced-xudt-exit-full-smoke",
    "factory-reduced-xudt-exit-one-sided-smoke",
    "factory-reduced-xudt-negative-exit-smoke",
    "factory-splice-in-asymmetric-smoke",
    "factory-splice-out-asymmetric-smoke",
    "factory-reduced-splice-in-asymmetric-smoke",
    "factory-reduced-splice-out-asymmetric-smoke",
    "factory-reduced-xudt-splice-in-one-sided-smoke",
    "factory-reduced-xudt-splice-out-one-sided-smoke",
    "factory-xudt-splice-in-one-sided-smoke",
    "factory-xudt-splice-out-one-sided-smoke",
    "factory/list-packages",
    "factory-xudt-one-sided/smoke",
    "factory-xudt-one-sided/local-exit-package-check",
    "watch-direct-sponsor/watch",
    "watch-config-loop/loop",
    "watch-splice-stale/watch",
];
const EXPECTED_BUSINESS_MATRIX_TRANSACTIONS: &[(&str, &str)] = &[
    ("manual-channel/open", "$"),
    ("manual-channel/publish-latest", "$.publication"),
    ("manual-channel/finalise", "$"),
    ("manual-sponsor/fund", "$"),
    ("manual-sponsor/publish", "$"),
    ("manual-sponsor/finalise", "$"),
    ("xudt-one-sided-smoke", "$.finalise"),
    ("splice-in-asymmetric-smoke", "$.apply"),
    ("splice-in-asymmetric-smoke", "$.finalise"),
    ("splice-out-asymmetric-smoke", "$.apply"),
    ("splice-out-asymmetric-smoke", "$.finalise"),
    ("xudt-splice-in-one-sided-smoke", "$.apply"),
    ("xudt-splice-in-one-sided-smoke", "$.xudt_finalise"),
    ("xudt-splice-out-one-sided-smoke", "$.apply"),
    ("xudt-splice-out-one-sided-smoke", "$.xudt_finalise"),
    ("factory-smoke", "$.update"),
    ("factory-reduced-rights-tight-smoke", "$.update"),
    ("factory-merkle-update-tight-smoke", "$.update"),
    ("factory-reduced-exit-asymmetric-smoke", "$.exit"),
    ("factory-reduced-xudt-exit-smoke", "$.exit"),
    ("factory-reduced-xudt-exit-smoke", "$.finalise"),
    ("factory-reduced-xudt-exit-full-smoke", "$.exit"),
    ("factory-reduced-xudt-exit-full-smoke", "$.finalise"),
    ("factory-reduced-xudt-exit-one-sided-smoke", "$.exit"),
    ("factory-reduced-xudt-exit-one-sided-smoke", "$.finalise"),
    ("factory-splice-in-asymmetric-smoke", "$.apply"),
    ("factory-splice-out-asymmetric-smoke", "$.apply"),
    ("factory-reduced-splice-in-asymmetric-smoke", "$.apply"),
    ("factory-reduced-splice-out-asymmetric-smoke", "$.apply"),
    ("factory-reduced-xudt-splice-in-one-sided-smoke", "$.apply"),
    ("factory-reduced-xudt-splice-out-one-sided-smoke", "$.apply"),
    ("factory-xudt-splice-in-one-sided-smoke", "$.apply"),
    ("factory-xudt-splice-out-one-sided-smoke", "$.apply"),
    ("factory-xudt-one-sided/smoke", "$.exit"),
    ("factory-xudt-one-sided/smoke", "$.finalise"),
    ("watch-direct-sponsor/watch", "$.publication"),
    ("watch-direct-sponsor/finalise", "$"),
    ("watch-config-loop/finalise", "$"),
];
const EXPECTED_FACTORY_REDUCED_EXITS: usize = 5;
const EXPECTED_FACTORY_REDUCED_CKB_EXITS: usize = 2;
const EXPECTED_FACTORY_REDUCED_XUDT_EXITS: usize = 3;
const EXPECTED_WATCHTOWER_EVENTS: &[&str] = &[
    "older_state_detected",
    "publication_submitted",
    "splice_detected",
    "splice_package_stale",
];
const EXPECTED_WATCHTOWER_SERVICE_RECORDS: usize = 2;

fn ensure_directory(dir: &Path) -> Result<()> {
    let metadata = fs::metadata(dir)
        .with_context(|| format!("failed to read smoke directory {}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(anyhow!("{} is not a directory", dir.display()));
    }
    Ok(())
}

fn read_manifest(dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = dir.join("manifest.txt");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read manifest {}", path.display()))?;
    let mut manifest = BTreeMap::new();
    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        manifest.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(manifest)
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to list directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, out)?;
            continue;
        }
        let file_name = path.file_name().and_then(|name| name.to_str());
        if matches!(
            file_name,
            Some("summary.json" | "summary-check.json" | "summary-budget-check.json")
        ) {
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_watch_alert_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to list directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_watch_alert_files(&path, out)?;
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_watchtower_alerts(
    smoke_dir: &Path,
    path: &Path,
    watchtower_alerts: &mut Vec<WatchtowerAlertSummary>,
) -> Result<()> {
    let relative = path
        .strip_prefix(smoke_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let check = relative.trim_end_matches(".jsonl").to_string();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read watchtower alerts {}", path.display()))?;
    for (line_index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse watchtower alert JSONL {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        if value.get("schema").and_then(Value::as_str) != Some("morph.watchtower_alert") {
            continue;
        }
        let alert: WatchtowerAlert = serde_json::from_value(value).with_context(|| {
            format!(
                "failed to decode watchtower alert {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        watchtower_alerts.push(WatchtowerAlertSummary {
            check: check.clone(),
            path: format!("line {}", line_index + 1),
            channel_id: alert.channel_id,
            severity: watch_alert_severity_name(&alert.severity).to_string(),
            event: watch_alert_event_name(&alert.event).to_string(),
            selected_state_number: alert.selected_state_number,
            observed_state_number: alert.observed_state_number,
            observed_out_point: alert.observed_out_point,
            publication_tx_hash: alert.publication_tx_hash,
            scanned_to_block: alert.scanned_to_block,
            next_from_block: alert.next_from_block,
        });
    }
    Ok(())
}

fn watch_alert_severity_name(severity: &WatchAlertSeverity) -> &'static str {
    match severity {
        WatchAlertSeverity::Info => "info",
        WatchAlertSeverity::Warning => "warning",
        WatchAlertSeverity::Critical => "critical",
    }
}

fn watch_alert_event_name(event: &WatchAlertEvent) -> &'static str {
    match event {
        WatchAlertEvent::ChainReorgDetected => "chain_reorg_detected",
        WatchAlertEvent::RecoveryDataInvalid => "recovery_data_invalid",
        WatchAlertEvent::PublicationFailed => "publication_failed",
        WatchAlertEvent::OlderStateDetected => "older_state_detected",
        WatchAlertEvent::PublicationSubmitted => "publication_submitted",
        WatchAlertEvent::SpliceDetected => "splice_detected",
        WatchAlertEvent::SplicePackageStale => "splice_package_stale",
        WatchAlertEvent::SplicePublicationSubmitted => "splice_publication_submitted",
        WatchAlertEvent::ScanIdle => "scan_idle",
    }
}

struct SmokeCollections<'a> {
    transactions: &'a mut Vec<TransactionSummary>,
    script_failures: &'a mut Vec<ScriptFailureSummary>,
    deployed_scripts: &'a mut Vec<DeployedScriptSummary>,
    watchtower_services: &'a mut Vec<WatchtowerServiceSummary>,
    factory_reduced_rights_updates: &'a mut Vec<FactoryReducedRightsEvidenceSummary>,
    factory_merkle_updates: &'a mut Vec<FactoryMerkleUpdateEvidenceSummary>,
    factory_reduced_exits: &'a mut Vec<FactoryReducedExitEvidenceSummary>,
    factory_local_exits: &'a mut Vec<FactoryLocalExitEvidenceSummary>,
    factory_splices: &'a mut Vec<FactorySpliceEvidenceSummary>,
    splice_payouts: &'a mut Vec<SplicePayoutEvidenceSummary>,
    sponsor_policies: &'a mut Vec<SponsorPolicySummary>,
}

fn collect_from_value(
    check: &str,
    path: &str,
    value: &Value,
    collections: &mut SmokeCollections<'_>,
) -> Result<()> {
    let Value::Object(object) = value else {
        return Ok(());
    };

    if let Some(tx) = transaction_from_object(check, path, object) {
        collections.transactions.push(tx);
    }
    for prefix in ["activation", "factory_activation", "state_activation"] {
        if let Some(tx) = prefixed_transaction_from_object(check, path, object, prefix) {
            collections.transactions.push(tx);
        }
    }

    if let Some(payout) = splice_payout_from_object(check, path, object) {
        collections.splice_payouts.push(payout);
    }

    if let Some(policy) = sponsor_policy_from_object(check, path, object) {
        collections.sponsor_policies.push(policy);
    }

    if let Some(Value::Object(failure)) = object.get("script_failure") {
        collections.script_failures.push(ScriptFailureSummary {
            check: check.to_string(),
            path: append_path(path, "script_failure"),
            source: string_field(failure, "source"),
            error_code: failure.get("error_code").and_then(Value::as_i64),
            morph_error: string_field(failure, "morph_error"),
        });
    }

    if let Some(Value::Array(scripts)) = object.get("scripts") {
        for (index, script) in scripts.iter().enumerate() {
            let Value::Object(script) = script else {
                continue;
            };
            if let Some(deployed_script) = deployed_script_from_object(
                check,
                &append_index_path(path, "scripts", index),
                script,
            ) {
                collections.deployed_scripts.push(deployed_script);
            }
        }
    }

    if object.get("schema").and_then(Value::as_str) == Some("morph.factory_local_exit_package") {
        let package: StoredFactoryLocalExitPackage =
            serde_json::from_value(Value::Object(object.clone())).with_context(|| {
                format!("failed to decode factory local-exit package at {path}")
            })?;
        let summary = package
            .summary()
            .with_context(|| format!("invalid factory local-exit package at {path}"))?;
        collections
            .factory_local_exits
            .push(FactoryLocalExitEvidenceSummary {
                check: check.to_string(),
                path: path.to_string(),
                factory_id: summary.factory_id,
                update_number: summary.update_number,
                exit_digest: summary.exit_digest,
                child_channel_id: summary.child_channel_id,
                child_state_number: summary.child_state_number,
                child_phase: summary.child_phase,
                descriptor_version: summary.descriptor_version,
                state_output_index: summary.state_output_index,
                vault_output_index: summary.vault_output_index,
            });
    }

    if object.get("schema").and_then(Value::as_str) == Some("morph.factory_reduced_rights_package")
    {
        let package: StoredFactoryReducedRightsPackage =
            serde_json::from_value(Value::Object(object.clone())).with_context(|| {
                format!("failed to decode factory reduced-rights package at {path}")
            })?;
        let summary = package
            .summary()
            .with_context(|| format!("invalid factory reduced-rights package at {path}"))?;
        collections
            .factory_reduced_rights_updates
            .push(FactoryReducedRightsEvidenceSummary {
                check: check.to_string(),
                path: path.to_string(),
                factory_id: summary.factory_id,
                old_update_number: summary.old_update_number,
                new_update_number: summary.new_update_number,
                signing_digest: summary.signing_digest,
                old_state_root: summary.old_state_root,
                new_state_root: summary.new_state_root,
                old_access_manifest_root: summary.old_access_manifest_root,
                new_access_manifest_root: summary.new_access_manifest_root,
                non_interference_digest: summary.non_interference_digest,
                witness_len: summary.witness_len,
            });
    }

    if object.get("schema").and_then(Value::as_str)
        == Some("morph.factory_merkle_update_state_package")
    {
        let package: StoredFactoryMerkleUpdateStatePackage =
            serde_json::from_value(Value::Object(object.clone())).with_context(|| {
                format!("failed to decode factory Merkle update package at {path}")
            })?;
        let summary = package
            .summary()
            .with_context(|| format!("invalid factory Merkle update package at {path}"))?;
        collections
            .factory_merkle_updates
            .push(FactoryMerkleUpdateEvidenceSummary {
                check: check.to_string(),
                path: path.to_string(),
                factory_id: summary.factory_id,
                old_update_number: summary.old_update_number,
                new_update_number: summary.new_update_number,
                signing_digest: summary.signing_digest,
                old_state_root: summary.old_state_root,
                new_state_root: summary.new_state_root,
                old_access_manifest_root: summary.old_access_manifest_root,
                new_access_manifest_root: summary.new_access_manifest_root,
                non_interference_digest: summary.non_interference_digest,
                changed_participant: summary.changed_participant,
                quantity_before: summary.quantity_before,
                quantity_after: summary.quantity_after,
                proof_siblings: summary.proof_siblings,
                witness_len: summary.witness_len,
            });
    }

    if object.get("schema").and_then(Value::as_str) == Some("morph.factory_splice_package") {
        let package: StoredFactorySplicePackage =
            serde_json::from_value(Value::Object(object.clone()))
                .with_context(|| format!("failed to decode factory splice package at {path}"))?;
        let summary = package
            .summary()
            .with_context(|| format!("invalid factory splice package at {path}"))?;
        collections
            .factory_splices
            .push(FactorySpliceEvidenceSummary {
                check: check.to_string(),
                path: path.to_string(),
                factory_id: summary.factory_id,
                kind: summary.kind,
                old_update_number: summary.old_update_number,
                new_update_number: summary.new_update_number,
                reserve_claim_asset: summary.reserve_claim_asset,
                reserve_claim_before: summary.reserve_claim_before,
                reserve_claim_after: summary.reserve_claim_after,
                vault_old_amount: summary.vault_old_amount,
                vault_new_amount: summary.vault_new_amount,
                external_input: summary.external_input,
                withdrawal: summary.withdrawal,
                proof_siblings: 0,
                signatures: summary.signatures,
                signing_digest: summary.signing_digest,
                vault_delta_commitment: summary.vault_delta_commitment,
                non_interference_digest: summary.non_interference_digest,
                witness_len: summary.contract_witness_len,
            });
    }

    if object.get("schema").and_then(Value::as_str) == Some("morph.factory_reduced_splice_package")
    {
        let package: StoredFactoryReducedSplicePackage =
            serde_json::from_value(Value::Object(object.clone())).with_context(|| {
                format!("failed to decode reduced factory splice package at {path}")
            })?;
        let summary = package
            .summary()
            .with_context(|| format!("invalid reduced factory splice package at {path}"))?;
        collections
            .factory_splices
            .push(FactorySpliceEvidenceSummary {
                check: check.to_string(),
                path: path.to_string(),
                factory_id: summary.factory_id,
                kind: summary.kind,
                old_update_number: summary.old_update_number,
                new_update_number: summary.new_update_number,
                reserve_claim_asset: summary.reserve_claim_asset,
                reserve_claim_before: summary.reserve_claim_before,
                reserve_claim_after: summary.reserve_claim_after,
                vault_old_amount: summary.vault_old_amount,
                vault_new_amount: summary.vault_new_amount,
                external_input: summary.external_input,
                withdrawal: summary.withdrawal,
                proof_siblings: summary.proof_siblings,
                signatures: summary.signatures,
                signing_digest: summary.signing_digest,
                vault_delta_commitment: summary.vault_delta_commitment,
                non_interference_digest: summary.non_interference_digest,
                witness_len: summary.contract_witness_len,
            });
    }

    if let Some(Value::Object(reduced_exit)) = object.get("reduced_exit") {
        collections
            .factory_reduced_exits
            .push(FactoryReducedExitEvidenceSummary {
                check: check.to_string(),
                path: append_path(path, "reduced_exit"),
                authorisation: string_field(object, "authorisation").unwrap_or_default(),
                release_quantity: reduced_exit
                    .get("release_quantity")
                    .and_then(value_as_u128)
                    .unwrap_or_default(),
                witness_len: reduced_exit
                    .get("witness_len")
                    .and_then(Value::as_u64)
                    .unwrap_or_default() as usize,
                local_exit_digest: string_field(reduced_exit, "local_exit_digest")
                    .unwrap_or_default(),
                non_interference_digest: string_field(reduced_exit, "non_interference_digest")
                    .unwrap_or_default(),
                child_xudt_amount: object.get("child_xudt_amount").and_then(value_as_u128),
                alice_xudt_amount: object.get("alice_xudt_amount").and_then(value_as_u128),
                bob_xudt_amount: object.get("bob_xudt_amount").and_then(value_as_u128),
                xudt_type_hash: string_field(object, "xudt_type_hash"),
                factory_vault_change_xudt_amount: object
                    .get("factory_vault_change_xudt_amount")
                    .and_then(value_as_u128),
            });
    }

    if let Some(service) = watchtower_service_from_object(check, path, object) {
        collections.watchtower_services.push(service);
    }

    for (key, child) in object {
        collect_from_value(check, &append_path(path, key), child, collections)?;
    }
    Ok(())
}

fn watchtower_service_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<WatchtowerServiceSummary> {
    let schema = string_field(object, "schema")?;
    if schema != "morph.watchtower_config_service" && schema != "morph.watchtower_health" {
        return None;
    }
    Some(WatchtowerServiceSummary {
        check: check.to_string(),
        path: path.to_string(),
        schema,
        status: string_field(object, "status"),
        stopped_reason: string_field(object, "stopped_reason"),
        completed_passes: object.get("completed_passes")?.as_u64()?,
        published_count: object
            .get("published_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        idle_count: object
            .get("idle_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        error_count: object.get("error_count")?.as_u64()?,
        consecutive_errors: object.get("consecutive_errors")?.as_u64()?,
        health_file: string_field(object, "health_file"),
    })
}

fn transaction_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<TransactionSummary> {
    let tx_hash = string_field(object, "tx_hash")?;
    let metrics = object.get("metrics")?.as_object()?;
    let estimated_cycles = metrics.get("estimated_cycles")?.as_u64()?;
    let tx_size_bytes = metrics.get("tx_size_bytes")?.as_u64()? as usize;
    Some(TransactionSummary {
        check: check.to_string(),
        path: path.to_string(),
        tx_hash,
        status: string_field(object, "status"),
        block_number: object.get("block_number").and_then(Value::as_u64),
        estimated_cycles,
        tx_size_bytes,
    })
}

fn prefixed_transaction_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
    prefix: &str,
) -> Option<TransactionSummary> {
    let tx_hash = string_field(object, &format!("{prefix}_tx_hash"))?;
    let metrics = object.get(&format!("{prefix}_metrics"))?.as_object()?;
    let estimated_cycles = metrics.get("estimated_cycles")?.as_u64()?;
    let tx_size_bytes = metrics.get("tx_size_bytes")?.as_u64()? as usize;
    Some(TransactionSummary {
        check: check.to_string(),
        path: append_path(path, prefix),
        tx_hash,
        status: string_field(object, &format!("{prefix}_status")),
        block_number: object
            .get(&format!("{prefix}_block_number"))
            .and_then(Value::as_u64),
        estimated_cycles,
        tx_size_bytes,
    })
}

fn splice_payout_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<SplicePayoutEvidenceSummary> {
    let withdrawal_payout_policy = string_field(object, "withdrawal_payout_policy")?;
    Some(SplicePayoutEvidenceSummary {
        check: check.to_string(),
        path: path.to_string(),
        withdrawal_payout_policy,
        withdrawal_participant_pubkey_sec1: string_field(
            object,
            "withdrawal_participant_pubkey_sec1",
        ),
        withdrawal_lock_hash: string_field(object, "withdrawal_lock_hash"),
        withdrawal_out_point: object
            .get("withdrawal_out_point")
            .and_then(out_point_string_from_value),
    })
}

fn sponsor_policy_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<SponsorPolicySummary> {
    let min_state_number = object.get("min_state_number")?.as_u64()?;
    let max_state_number = object.get("max_state_number")?.as_u64()?;
    Some(SponsorPolicySummary {
        check: check.to_string(),
        path: path.to_string(),
        min_state_number,
        max_state_number,
        state_number_span: max_state_number.saturating_sub(min_state_number),
        max_fee_per_tx: object.get("max_fee_per_tx")?.as_u64()?,
        max_total_fee: object.get("max_total_fee")?.as_u64()?,
    })
}

fn out_point_string_from_value(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    let tx_hash = string_field(object, "tx_hash")?;
    let index = object.get("index")?.as_u64()?;
    Some(format!("{tx_hash}:{index}"))
}

fn deployed_script_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<DeployedScriptSummary> {
    let name = string_field(object, "name")?;
    let data_hash = string_field(object, "data_hash")?;
    let hash_type = string_field(object, "hash_type")?;
    let data_len = object.get("data_len")?.as_u64()? as usize;
    let capacity = object.get("capacity")?.as_u64()?;
    let out_point = object.get("out_point")?.as_object()?;
    let tx_hash = string_field(out_point, "tx_hash")?;
    let index = out_point.get("index")?.as_u64()?;
    Some(DeployedScriptSummary {
        check: check.to_string(),
        path: path.to_string(),
        name,
        out_point: format!("{tx_hash}:{index}"),
        data_hash,
        hash_type,
        data_len,
        capacity,
    })
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn value_as_u128(value: &Value) -> Option<u128> {
    value.as_u64().map(u128::from)
}

fn factory_proof_profiles(
    reduced_rights_updates: &[FactoryReducedRightsEvidenceSummary],
    merkle_updates: &[FactoryMerkleUpdateEvidenceSummary],
    reduced_exits: &[FactoryReducedExitEvidenceSummary],
    factory_splices: &[FactorySpliceEvidenceSummary],
    transactions: &[TransactionSummary],
) -> Vec<FactoryProofProfileSummary> {
    let mut profiles = reduced_rights_updates
        .iter()
        .filter_map(|update| {
            transactions
                .iter()
                .find(|tx| tx.check == update.check && tx.path == "$.update")
                .map(|tx| FactoryProofProfileSummary {
                    check: update.check.clone(),
                    transaction_path: tx.path.clone(),
                    evidence_path: update.path.clone(),
                    proof_kind: "factory_reduced_rights_bounded_claim_decrease".to_string(),
                    proof_siblings: 0,
                    witness_len: update.witness_len,
                    estimated_cycles: tx.estimated_cycles,
                    tx_size_bytes: tx.tx_size_bytes,
                })
        })
        .collect::<Vec<_>>();

    profiles.extend(merkle_updates.iter().filter_map(|update| {
        transactions
            .iter()
            .find(|tx| tx.check == update.check && tx.path == "$.update")
            .map(|tx| FactoryProofProfileSummary {
                check: update.check.clone(),
                transaction_path: tx.path.clone(),
                evidence_path: update.path.clone(),
                proof_kind: "factory_sparse_merkle_update".to_string(),
                proof_siblings: update.proof_siblings,
                witness_len: update.witness_len,
                estimated_cycles: tx.estimated_cycles,
                tx_size_bytes: tx.tx_size_bytes,
            })
    }));

    profiles.extend(reduced_exits.iter().filter_map(|exit| {
        transactions
            .iter()
            .find(|tx| tx.check == exit.check && tx.path == "$.exit")
            .map(|tx| FactoryProofProfileSummary {
                check: exit.check.clone(),
                transaction_path: tx.path.clone(),
                evidence_path: exit.path.clone(),
                proof_kind: if exit.xudt_type_hash.is_some()
                    && exit.factory_vault_change_xudt_amount.unwrap_or_default() > 0
                {
                    "factory_reduced_exit_xudt_change_reserve_claim"
                } else if exit.xudt_type_hash.is_some()
                    && matches!(
                        (exit.alice_xudt_amount, exit.bob_xudt_amount),
                        (Some(0), Some(amount)) | (Some(amount), Some(0)) if amount > 0
                    )
                {
                    "factory_reduced_exit_xudt_one_sided_reserve_claim"
                } else if exit.xudt_type_hash.is_some() {
                    "factory_reduced_exit_xudt_reserve_claim"
                } else {
                    "factory_reduced_exit_ckb_reserve_claim"
                }
                .to_string(),
                proof_siblings: 0,
                witness_len: exit.witness_len,
                estimated_cycles: tx.estimated_cycles,
                tx_size_bytes: tx.tx_size_bytes,
            })
    }));

    profiles.extend(factory_splices.iter().filter_map(|splice| {
        transactions
            .iter()
            .find(|tx| tx.check == splice.check && tx.path == "$.apply")
            .map(|tx| FactoryProofProfileSummary {
                check: splice.check.clone(),
                transaction_path: tx.path.clone(),
                evidence_path: splice.path.clone(),
                proof_kind: if splice.reserve_claim_asset.starts_with("xudt:") {
                    if splice.proof_siblings > 0 {
                        "factory_reduced_splice_xudt_sparse_merkle"
                    } else {
                        "factory_splice_all_participants_xudt"
                    }
                } else if splice.proof_siblings > 0 {
                    "factory_reduced_splice_ckb_sparse_merkle"
                } else {
                    "factory_splice_all_participants_ckb"
                }
                .to_string(),
                proof_siblings: splice.proof_siblings,
                witness_len: splice.witness_len,
                estimated_cycles: tx.estimated_cycles,
                tx_size_bytes: tx.tx_size_bytes,
            })
    }));

    profiles
}

fn summarise_totals(transactions: &[TransactionSummary]) -> MetricTotals {
    let mut totals = MetricTotals {
        transaction_count: transactions.len(),
        ..MetricTotals::default()
    };
    for tx in transactions {
        if tx.status.as_deref() == Some("Committed") {
            totals.committed_count += 1;
        }
        if tx.status.as_deref() == Some("Pending") {
            totals.pending_count += 1;
        }
        totals.total_estimated_cycles = totals
            .total_estimated_cycles
            .saturating_add(tx.estimated_cycles);
        totals.max_estimated_cycles = totals.max_estimated_cycles.max(tx.estimated_cycles);
        totals.total_tx_size_bytes = totals.total_tx_size_bytes.saturating_add(tx.tx_size_bytes);
        totals.max_tx_size_bytes = totals.max_tx_size_bytes.max(tx.tx_size_bytes);
    }
    totals
}

fn append_path(parent: &str, child: &str) -> String {
    if parent == "$" {
        format!("$.{child}")
    } else {
        format!("{parent}.{child}")
    }
}

fn append_index_path(parent: &str, child: &str, index: usize) -> String {
    if parent == "$" {
        format!("$.{child}[{index}]")
    } else {
        format!("{parent}.{child}[{index}]")
    }
}

fn table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn transaction_map(transactions: &[TransactionSummary]) -> BTreeMap<String, &TransactionSummary> {
    transactions
        .iter()
        .map(|tx| (format!("{} {}", tx.check, tx.path), tx))
        .collect()
}

fn signed_delta_u64(baseline: u64, candidate: u64) -> i64 {
    i64_saturating_from_i128(i128::from(candidate) - i128::from(baseline))
}

fn signed_delta_usize(baseline: usize, candidate: usize) -> i64 {
    let baseline = i128::try_from(baseline).unwrap_or(i128::MAX);
    let candidate = i128::try_from(candidate).unwrap_or(i128::MAX);
    i64_saturating_from_i128(candidate - baseline)
}

fn i64_saturating_from_i128(value: i128) -> i64 {
    i64::try_from(value).unwrap_or_else(|_| {
        if value.is_negative() {
            i64::MIN
        } else {
            i64::MAX
        }
    })
}

fn abs_i64(value: i64) -> u64 {
    value.unsigned_abs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn summarises_smoke_metrics_and_script_failures() {
        let dir = temp_report_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("manifest.txt"),
            "rpc_url=http://127.0.0.1:18114\nstatus=passed\n",
        )
        .unwrap();
        fs::write(
            dir.join("open.json"),
            r#"{
              "tx_hash": "0xabc",
              "status": "Committed",
              "block_number": 7,
              "sponsor_policy": {
                "min_state_number": 1,
                "max_state_number": 1048576,
                "max_fee_per_tx": 100,
                "max_total_fee": 200,
                "expiry": 18446744073709551615
              },
              "metrics": {
                "estimated_cycles": 11,
                "tx_size_bytes": 22
              }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.join("negative.json"),
            r#"{
              "open": {
                "tx_hash": "0xdef",
                "status": "Committed",
                "block_number": 8,
                "metrics": {
                  "estimated_cycles": 33,
                  "tx_size_bytes": 44
                }
              },
              "script_failure": {
                "source": "Inputs",
                "error_code": 16,
                "morph_error": "StateSinceNotMature"
              }
            }"#,
        )
        .unwrap();
        let local_exit_package =
            serde_json::to_string(&crate::packages::fixture_factory_local_exit_package().unwrap())
                .unwrap();
        fs::write(
            dir.join("factory.json"),
            format!(
                r#"{{
                  "exit": {{
                    "tx_hash": "0xbeef",
                    "status": "Committed",
                    "block_number": 10,
                    "metrics": {{
                      "estimated_cycles": 77,
                      "tx_size_bytes": 88
                    }},
                    "authorisation": "reduced-reserve-claim",
                    "child_xudt_amount": 100,
                    "alice_xudt_amount": 60,
                    "bob_xudt_amount": 40,
                    "factory_vault_change_xudt_amount": 50,
                    "xudt_type_hash": "0x1234",
                    "local_exit_package": {local_exit_package},
                    "reduced_exit": {{
                      "release_quantity": 200,
                      "witness_len": 3122,
                      "local_exit_digest": "0xabcd",
                      "non_interference_digest": "0xef01"
                    }}
                  }}
                }}"#
            ),
        )
        .unwrap();
        let reduced_package = serde_json::to_string(
            &crate::packages::fixture_factory_reduced_rights_package().unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("factory-reduced.json"),
            format!(r#"{{"package": {reduced_package}}}"#),
        )
        .unwrap();
        let merkle_package = serde_json::to_string(
            &crate::packages::fixture_factory_merkle_update_package().unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("factory-merkle.json"),
            format!(
                r#"{{
                  "package": {merkle_package},
                  "update": {{
                    "tx_hash": "0xfeed",
                    "status": "Committed",
                    "block_number": 9,
                    "metrics": {{
                      "estimated_cycles": 55,
                      "tx_size_bytes": 66
                    }}
                  }}
                }}"#
            ),
        )
        .unwrap();
        let withdrawal_participant_pubkey_sec1 = compressed_pubkey_hex(41);
        let withdrawal_lock_hash = bytes32_hex(73);
        let splice_report = serde_json::json!({
            "apply": {
                "tx_hash": "0xsp1",
                "status": "Committed",
                "block_number": 11,
                "withdrawal_payout_policy": "participant_signature_pubkey",
                "withdrawal_participant_pubkey_sec1": withdrawal_participant_pubkey_sec1,
                "withdrawal_lock_hash": withdrawal_lock_hash,
                "withdrawal_out_point": {
                    "tx_hash": "0xsp1",
                    "index": 2
                },
                "metrics": {
                    "estimated_cycles": 11,
                    "tx_size_bytes": 12
                }
            }
        });
        fs::write(
            dir.join("splice.json"),
            serde_json::to_string_pretty(&splice_report).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("deploy.json"),
            r#"{
              "scripts": [{
                "name": "morph-state-lock",
                "out_point": {
                  "tx_hash": "0xabc",
                  "index": 0
                },
                "data_hash": "0x123",
                "hash_type": "data1",
                "data_len": 11,
                "capacity": 22
              }]
            }"#,
        )
        .unwrap();
        let alert_channel_id = bytes32_hex(89);
        let watch_alerts = [
            serde_json::json!({
                "schema": "morph.watchtower_alert",
                "created_unix_ms": 1,
                "channel_id": alert_channel_id.clone(),
                "severity": "warning",
                "event": "older_state_detected",
                "message": "old state",
                "selected_state_number": 2,
                "observed_state_number": 0,
                "observed_out_point": "0xabc:0",
                "publication_tx_hash": null,
                "scanned_to_block": 10,
                "next_from_block": 11
            }),
            serde_json::json!({
                "schema": "morph.watchtower_alert",
                "created_unix_ms": 2,
                "channel_id": alert_channel_id.clone(),
                "severity": "warning",
                "event": "publication_submitted",
                "message": "published",
                "selected_state_number": 2,
                "observed_state_number": 0,
                "observed_out_point": "0xabc:0",
                "publication_tx_hash": "0xdef",
                "scanned_to_block": 10,
                "next_from_block": 11
            }),
            serde_json::json!({
                "schema": "morph.watchtower_alert",
                "created_unix_ms": 3,
                "channel_id": alert_channel_id.clone(),
                "severity": "warning",
                "event": "splice_detected",
                "message": "splice",
                "selected_state_number": 1,
                "observed_state_number": 0,
                "observed_out_point": "0xdef:0",
                "publication_tx_hash": null,
                "scanned_to_block": 20,
                "next_from_block": 21
            }),
            serde_json::json!({
                "schema": "morph.watchtower_alert",
                "created_unix_ms": 4,
                "channel_id": alert_channel_id.clone(),
                "severity": "warning",
                "event": "splice_package_stale",
                "message": "stale",
                "selected_state_number": 1,
                "observed_state_number": 0,
                "observed_out_point": "0xdef:0",
                "publication_tx_hash": null,
                "scanned_to_block": 20,
                "next_from_block": 21
            }),
            serde_json::json!({
                "schema": "morph.watchtower_alert",
                "created_unix_ms": 5,
                "channel_id": alert_channel_id,
                "severity": "info",
                "event": "scan_idle",
                "message": "idle",
                "selected_state_number": 1,
                "observed_state_number": null,
                "observed_out_point": null,
                "publication_tx_hash": null,
                "scanned_to_block": 20,
                "next_from_block": 21
            }),
        ]
        .into_iter()
        .map(|alert| alert.to_string())
        .collect::<Vec<_>>()
        .join("\n");
        fs::write(dir.join("watch-alerts.jsonl"), format!("{watch_alerts}\n")).unwrap();
        fs::write(
            dir.join("service.json"),
            r#"{
              "schema": "morph.watchtower_config_service",
              "config_path": "watch-config.json",
              "completed_passes": 0,
              "published_count": 0,
              "idle_count": 0,
              "error_count": 0,
              "consecutive_errors": 0,
              "stopped_reason": "stop_file",
              "last_error": null,
              "stop_file": "service.stop",
              "health_file": "service-health.json"
            }"#,
        )
        .unwrap();
        fs::write(
            dir.join("service-health.json"),
            r#"{
              "schema": "morph.watchtower_health",
              "config_path": "watch-config.json",
              "updated_unix_ms": 1,
              "completed_passes": 0,
              "published_count": 0,
              "idle_count": 0,
              "error_count": 0,
              "consecutive_errors": 0,
              "status": "stopped",
              "stopped_reason": "stop_file",
              "last_error": null
            }"#,
        )
        .unwrap();
        let factory_splice_package = serde_json::to_string(
            &crate::factory_packages::fixture_factory_splice_package_with_kind(
                crate::factory_packages::FixtureFactorySpliceKind::CkbSpliceIn,
            )
            .unwrap(),
        )
        .unwrap();
        fs::write(dir.join("factory-splice.json"), factory_splice_package).unwrap();

        let summary = summarize_devnet_smoke(&dir).unwrap();
        assert_eq!(summary.manifest.get("status").unwrap(), "passed");
        assert_eq!(summary.json_files, 10);
        assert!(summary.json_checks.contains(&"open".to_string()));
        assert_eq!(summary.transactions.len(), 5);
        assert_eq!(summary.script_failures.len(), 1);
        assert_eq!(summary.sponsor_policies.len(), 1);
        assert_eq!(summary.sponsor_policies[0].path, "$.sponsor_policy");
        assert_eq!(summary.sponsor_policies[0].state_number_span, 1_048_575);
        assert_eq!(summary.deployed_scripts.len(), 1);
        assert_eq!(summary.deployed_scripts[0].name, "morph-state-lock");
        assert_eq!(summary.factory_local_exits.len(), 1);
        assert_eq!(
            summary.factory_local_exits[0].path,
            "$.exit.local_exit_package"
        );
        assert_eq!(summary.factory_reduced_rights_updates.len(), 1);
        assert_eq!(summary.factory_reduced_rights_updates[0].path, "$.package");
        assert_eq!(summary.factory_merkle_updates.len(), 1);
        assert_eq!(summary.factory_merkle_updates[0].path, "$.package");
        assert_eq!(summary.factory_merkle_updates[0].proof_siblings, 256);
        assert_eq!(summary.factory_proof_profiles.len(), 2);
        assert_eq!(summary.factory_proof_profiles[0].proof_siblings, 256);
        assert_eq!(summary.factory_proof_profiles[0].estimated_cycles, 55);
        assert!(
            summary
                .factory_proof_profiles
                .iter()
                .any(|profile| profile.proof_kind
                    == "factory_reduced_exit_xudt_change_reserve_claim"
                    && profile.estimated_cycles == 77)
        );
        assert_eq!(summary.factory_reduced_exits.len(), 1);
        assert_eq!(summary.factory_reduced_exits[0].witness_len, 3122);
        assert_eq!(
            summary.factory_reduced_exits[0].child_xudt_amount,
            Some(100)
        );
        assert_eq!(summary.factory_reduced_exits[0].alice_xudt_amount, Some(60));
        assert_eq!(summary.factory_reduced_exits[0].bob_xudt_amount, Some(40));
        assert_eq!(
            summary.factory_reduced_exits[0].factory_vault_change_xudt_amount,
            Some(50)
        );
        assert!(summary.watchtower_alerts.len() >= EXPECTED_WATCHTOWER_EVENTS.len());
        assert_eq!(summary.watchtower_alerts[1].event, "publication_submitted");
        assert_eq!(summary.watchtower_services.len(), 2);
        assert!(
            summary
                .watchtower_services
                .iter()
                .any(|service| service.schema == "morph.watchtower_config_service")
        );
        assert!(
            summary
                .watchtower_services
                .iter()
                .any(|service| service.schema == "morph.watchtower_health")
        );
        assert_eq!(summary.factory_splices.len(), 1);
        assert_eq!(summary.factory_splices[0].kind, "splice_in");
        assert_eq!(summary.factory_splices[0].external_input, 20);
        assert_eq!(summary.splice_payouts.len(), 1);
        assert_eq!(summary.splice_payouts[0].path, "$.apply");
        assert_eq!(
            summary.splice_payouts[0].withdrawal_payout_policy,
            "participant_signature_pubkey"
        );
        assert_eq!(
            summary.splice_payouts[0].withdrawal_out_point.as_deref(),
            Some("0xsp1:2")
        );
        assert_eq!(summary.totals.total_estimated_cycles, 187);
        assert_eq!(summary.totals.total_tx_size_bytes, 232);

        let markdown = render_markdown(&summary);
        assert!(markdown.contains("StateSinceNotMature"));
        assert!(markdown.contains("0xabc"));
        assert!(markdown.contains("Deployed Scripts"));
        assert!(markdown.contains("Splice Payouts"));
        assert!(markdown.contains("Sponsor Policies"));
        assert!(markdown.contains("Watchtower Alerts"));
        assert!(markdown.contains("Watchtower Service"));
        assert!(markdown.contains("Factory Reduced-Rights Updates"));
        assert!(markdown.contains("Factory Merkle Updates"));
        assert!(markdown.contains("Factory Proof Profiles"));
        assert!(markdown.contains("Factory Local Exits"));
        assert!(markdown.contains("Factory Splices"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn asserts_full_smoke_semantic_coverage() {
        let summary = passing_assertion_summary();
        assert_devnet_smoke_summary(&summary).unwrap();
    }

    #[test]
    fn rejects_missing_expected_smoke_failure() {
        let mut summary = passing_assertion_summary();
        summary.script_failures.pop();
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(err.to_string().contains("unexpected script failure count"));
    }

    #[test]
    fn rejects_incomplete_factory_exit_coverage() {
        let mut summary = passing_assertion_summary();
        summary.factory_local_exits[0].descriptor_version = 2;
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing factory local-exit evidence")
        );
    }

    #[test]
    fn rejects_missing_factory_splice_coverage() {
        let mut summary = passing_assertion_summary();
        summary
            .transactions
            .retain(|tx| tx.check != "factory-xudt-splice-out-smoke");
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing committed factory splice smoke transaction")
        );
    }

    #[test]
    fn rejects_factory_splice_without_contract_witness_evidence() {
        let mut summary = passing_assertion_summary();
        summary.factory_splices[0].witness_len = 0;
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("factory splice evidence for factory-splice-in-smoke")
        );
    }

    #[test]
    fn rejects_incomplete_deployment_coverage() {
        let mut summary = passing_assertion_summary();
        summary.deployed_scripts.pop();
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(err.to_string().contains("unexpected deployed script count"));
    }

    #[test]
    fn rejects_missing_watchtower_alert_coverage() {
        let mut summary = passing_assertion_summary();
        summary
            .watchtower_alerts
            .retain(|alert| alert.event != "publication_submitted");
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing expected watchtower alert event")
        );
    }

    #[test]
    fn rejects_missing_watchtower_service_coverage() {
        let mut summary = passing_assertion_summary();
        summary.watchtower_services.pop();
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected watchtower service record count")
        );
    }

    #[test]
    fn rejects_unhealthy_watchtower_service_coverage() {
        let mut summary = passing_assertion_summary();
        summary.watchtower_services[1].status = Some("running".to_string());
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("watchtower health report must show stopped by stop_file")
        );
    }

    #[test]
    fn rejects_missing_splice_payout_evidence() {
        let mut summary = passing_assertion_summary();
        summary
            .splice_payouts
            .retain(|payout| payout.check != "splice-out-smoke");
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(err.to_string().contains("missing splice payout evidence"));
    }

    #[test]
    fn rejects_non_participant_splice_out_policy() {
        let mut summary = passing_assertion_summary();
        let payout = summary
            .splice_payouts
            .iter_mut()
            .find(|payout| payout.check == "xudt-splice-out-smoke")
            .unwrap();
        payout.withdrawal_payout_policy = "arbitrary_signed_payout_lock".to_string();
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(err.to_string().contains("splice payout policy"));
    }

    #[test]
    fn smoke_budget_accepts_within_limits() {
        let mut summary = passing_assertion_summary();
        summary.totals.total_estimated_cycles = 100;
        summary.totals.max_estimated_cycles = 80;
        summary.totals.total_tx_size_bytes = 200;
        summary.totals.max_tx_size_bytes = 120;

        let report = assert_smoke_budget(
            &summary,
            &DevnetSmokeBudgetLimits {
                max_total_cycles: Some(100),
                max_tx_cycles: Some(80),
                max_total_bytes: Some(200),
                max_tx_bytes: Some(120),
                transactions: vec![DevnetSmokeTransactionBudgetLimit {
                    check: "factory-reduced-rights-smoke".to_string(),
                    path: "$.update".to_string(),
                    max_cycles: Some(1),
                    max_bytes: Some(1),
                }],
                proof_profiles: vec![DevnetSmokeProofProfileBudgetLimit {
                    check: "factory-reduced-rights-smoke".to_string(),
                    transaction_path: "$.update".to_string(),
                    proof_kind: "factory_reduced_rights_bounded_claim_decrease".to_string(),
                    proof_siblings: Some(0),
                    max_witness_len: Some(2_580),
                    max_cycles: Some(1),
                    max_bytes: Some(1),
                }],
            },
        )
        .unwrap();
        assert_eq!(report.total_estimated_cycles, 100);
        assert_eq!(report.max_estimated_cycles, 80);
        assert_eq!(report.transactions.len(), 1);
        assert_eq!(report.proof_profiles.len(), 1);
    }

    #[test]
    fn smoke_budget_rejects_excess_transaction_cycles() {
        let mut summary = passing_assertion_summary();
        summary.totals.max_estimated_cycles = 81;

        let err = assert_smoke_budget(
            &summary,
            &DevnetSmokeBudgetLimits {
                max_tx_cycles: Some(80),
                ..DevnetSmokeBudgetLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("max transaction estimated cycles"));
    }

    #[test]
    fn smoke_budget_rejects_named_transaction_budget() {
        let summary = passing_assertion_summary();

        let err = assert_smoke_budget(
            &summary,
            &DevnetSmokeBudgetLimits {
                transactions: vec![DevnetSmokeTransactionBudgetLimit {
                    check: "factory-reduced-rights-smoke".to_string(),
                    path: "$.update".to_string(),
                    max_cycles: Some(0),
                    max_bytes: None,
                }],
                ..DevnetSmokeBudgetLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("factory-reduced-rights-smoke"));
    }

    #[test]
    fn smoke_budget_rejects_named_proof_profile_budget() {
        let summary = passing_assertion_summary();

        let err = assert_smoke_budget(
            &summary,
            &DevnetSmokeBudgetLimits {
                proof_profiles: vec![DevnetSmokeProofProfileBudgetLimit {
                    check: "factory-reduced-rights-smoke".to_string(),
                    transaction_path: "$.update".to_string(),
                    proof_kind: "factory_reduced_rights_bounded_claim_decrease".to_string(),
                    proof_siblings: Some(0),
                    max_witness_len: Some(1),
                    max_cycles: None,
                    max_bytes: None,
                }],
                ..DevnetSmokeBudgetLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("witness length"));
    }

    #[test]
    fn reads_smoke_budget_profile() {
        let dir = temp_report_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("budget.json");
        fs::write(
            &path,
            r#"{
              "schema": "morph.devnet_smoke_budget",
              "max_total_cycles": 100,
              "max_tx_cycles": 80,
              "max_total_bytes": 200,
              "max_tx_bytes": 120,
              "transactions": [{
                "check": "factory-reduced-rights-smoke",
                "path": "$.update",
                "max_cycles": 1,
                "max_bytes": 1
              }],
              "proof_profiles": [{
                "check": "factory-reduced-rights-smoke",
                "transaction_path": "$.update",
                "proof_kind": "factory_reduced_rights_bounded_claim_decrease",
                "proof_siblings": 0,
                "max_witness_len": 2580,
                "max_cycles": 1,
                "max_bytes": 1
              }]
            }"#,
        )
        .unwrap();

        let profile = read_smoke_budget_profile(&path).unwrap();
        assert_eq!(profile.max_total_cycles, Some(100));
        assert_eq!(profile.transactions.len(), 1);
        assert_eq!(profile.transactions[0].path, "$.update");
        assert_eq!(profile.proof_profiles.len(), 1);
        assert_eq!(profile.proof_profiles[0].proof_siblings, Some(0));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reads_repository_smoke_budget_profile() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repository root");
        let path = repo_root.join("docs/devnet-smoke-budget.example.json");

        let profile = read_smoke_budget_profile(&path).unwrap();
        assert_eq!(profile.max_total_cycles, Some(1_600_000_000));
        assert_eq!(profile.max_tx_bytes, Some(500_000));
        assert!(
            profile
                .transactions
                .iter()
                .any(|limit| limit.check == "deploy-contracts" && limit.path == "$")
        );
        assert!(profile.transactions.iter().any(|limit| {
            limit.check == "factory-reduced-rights-smoke" && limit.path == "$.update"
        }));
        assert!(profile.transactions.iter().any(|limit| {
            limit.check == "factory-merkle-update-smoke" && limit.path == "$.update"
        }));
        assert!(profile.transactions.iter().any(|limit| {
            limit.check == "factory-reduced-exit-smoke" && limit.path == "$.exit"
        }));
        assert!(profile.transactions.iter().any(|limit| {
            limit.check == "factory-xudt-splice-in-smoke" && limit.path == "$.apply"
        }));
        assert!(profile.proof_profiles.iter().any(|limit| {
            limit.check == "factory-reduced-exit-smoke"
                && limit.proof_kind == "factory_reduced_exit_ckb_reserve_claim"
        }));
        assert!(profile.proof_profiles.iter().any(|limit| {
            limit.check == "factory-reduced-xudt-exit-smoke"
                && limit.proof_kind == "factory_reduced_exit_xudt_change_reserve_claim"
                && limit.proof_siblings == Some(0)
        }));
        assert!(profile.proof_profiles.iter().any(|limit| {
            limit.check == "factory-reduced-xudt-exit-one-sided-smoke"
                && limit.proof_kind == "factory_reduced_exit_xudt_one_sided_reserve_claim"
                && limit.proof_siblings == Some(0)
        }));
        assert!(profile.proof_profiles.iter().any(|limit| {
            limit.check == "factory-xudt-splice-out-smoke"
                && limit.proof_kind == "factory_splice_all_participants_xudt"
                && limit.proof_siblings == Some(0)
        }));
    }

    #[test]
    fn verifies_deployed_script_hashes_against_local_binaries() {
        let dir = temp_report_dir();
        fs::create_dir_all(&dir).unwrap();
        let mut summary = passing_assertion_summary();
        for (index, script) in summary.deployed_scripts.iter_mut().enumerate() {
            let data = vec![index as u8; index + 1];
            fs::write(dir.join(&script.name), &data).unwrap();
            script.data_hash = format!("0x{}", hex::encode(blake2b_256(&data)));
            script.data_len = data.len();
        }

        assert_deployed_script_hashes(&summary, &dir).unwrap();
        summary.deployed_scripts[0].data_hash = "0x00".to_string();
        let err = assert_deployed_script_hashes(&summary, &dir).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compares_smoke_summary_metrics() {
        let baseline_dir = temp_report_dir();
        let candidate_dir = temp_report_dir();
        fs::create_dir_all(&baseline_dir).unwrap();
        fs::create_dir_all(&candidate_dir).unwrap();
        write_metric_json(&baseline_dir, "open.json", "0xaaa", 10, 20);
        write_metric_json(&candidate_dir, "open.json", "0xbbb", 13, 18);
        write_metric_json(&candidate_dir, "extra.json", "0xccc", 1, 2);

        let comparison = compare_devnet_smoke(&baseline_dir, &candidate_dir).unwrap();
        assert_eq!(comparison.compared_transactions, 1);
        assert_eq!(comparison.total_estimated_cycles_delta, 4);
        assert_eq!(comparison.total_tx_size_bytes_delta, 0);
        assert_eq!(comparison.added_in_candidate, vec!["extra $".to_string()]);
        assert!(comparison.missing_from_candidate.is_empty());
        assert_eq!(comparison.transaction_deltas[0].estimated_cycles_delta, 3);
        assert_eq!(comparison.transaction_deltas[0].tx_size_bytes_delta, -2);
        assert!(render_comparison_markdown(&comparison).contains("Devnet Smoke Comparison"));

        fs::remove_dir_all(&baseline_dir).ok();
        fs::remove_dir_all(&candidate_dir).ok();
    }

    #[test]
    fn comparison_limits_reject_metric_regressions() {
        let baseline_dir = temp_report_dir();
        let candidate_dir = temp_report_dir();
        fs::create_dir_all(&baseline_dir).unwrap();
        fs::create_dir_all(&candidate_dir).unwrap();
        write_metric_json(&baseline_dir, "open.json", "0xaaa", 10, 20);
        write_metric_json(&candidate_dir, "open.json", "0xbbb", 13, 18);

        let comparison = compare_devnet_smoke(&baseline_dir, &candidate_dir).unwrap();
        assert_comparison_limits(
            &comparison,
            &DevnetSmokeComparisonLimits {
                max_abs_tx_cycle_delta: Some(3),
                max_abs_tx_byte_delta: Some(2),
                ..DevnetSmokeComparisonLimits::default()
            },
        )
        .unwrap();
        let err = assert_comparison_limits(
            &comparison,
            &DevnetSmokeComparisonLimits {
                max_abs_tx_cycle_delta: Some(2),
                ..DevnetSmokeComparisonLimits::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("cycle delta"));

        fs::remove_dir_all(&baseline_dir).ok();
        fs::remove_dir_all(&candidate_dir).ok();
    }

    #[test]
    fn comparison_limits_reject_set_and_status_changes() {
        let baseline = DevnetSmokeSummary {
            directory: "baseline".to_string(),
            manifest: BTreeMap::new(),
            json_files: 1,
            json_checks: vec!["open".to_string()],
            transactions: vec![TransactionSummary {
                check: "open".to_string(),
                path: "$".to_string(),
                tx_hash: "0xaaa".to_string(),
                status: Some("Committed".to_string()),
                block_number: Some(1),
                estimated_cycles: 10,
                tx_size_bytes: 20,
            }],
            script_failures: Vec::new(),
            deployed_scripts: Vec::new(),
            watchtower_alerts: Vec::new(),
            watchtower_services: Vec::new(),
            factory_reduced_rights_updates: Vec::new(),
            factory_merkle_updates: Vec::new(),
            factory_proof_profiles: Vec::new(),
            factory_reduced_exits: Vec::new(),
            factory_local_exits: Vec::new(),
            factory_splices: Vec::new(),
            splice_payouts: Vec::new(),
            sponsor_policies: Vec::new(),
            totals: MetricTotals::default(),
        };
        let mut candidate = baseline.clone();
        candidate.transactions[0].status = Some("Pending".to_string());
        candidate.transactions.push(TransactionSummary {
            check: "extra".to_string(),
            path: "$".to_string(),
            tx_hash: "0xbbb".to_string(),
            status: Some("Committed".to_string()),
            block_number: Some(2),
            estimated_cycles: 1,
            tx_size_bytes: 1,
        });

        let comparison = compare_summaries(&baseline, &candidate);
        let status_err = assert_comparison_limits(
            &comparison,
            &DevnetSmokeComparisonLimits {
                fail_on_status_change: true,
                ..DevnetSmokeComparisonLimits::default()
            },
        )
        .unwrap_err();
        assert!(status_err.to_string().contains("status changed"));
        let set_err = assert_comparison_limits(
            &comparison,
            &DevnetSmokeComparisonLimits {
                fail_on_transaction_set_change: true,
                ..DevnetSmokeComparisonLimits::default()
            },
        )
        .unwrap_err();
        assert!(set_err.to_string().contains("added"));
    }

    fn passing_assertion_summary() -> DevnetSmokeSummary {
        let mut manifest = BTreeMap::new();
        manifest.insert("status".to_string(), "passed".to_string());
        DevnetSmokeSummary {
            directory: "target/devnet-smoke/test".to_string(),
            manifest,
            json_files: 48,
            json_checks: EXPECTED_BUSINESS_MATRIX_JSON_CHECKS
                .iter()
                .map(|check| (*check).to_string())
                .collect(),
            transactions: vec![
                transaction("watch-splice-stale/apply", "$", "Committed"),
                transaction("manual-channel/open", "$", "Committed"),
                transaction(
                    "manual-channel/publish-latest",
                    "$.publication",
                    "Committed",
                ),
                transaction("manual-channel/finalise", "$", "Committed"),
                transaction("manual-sponsor/fund", "$", "Committed"),
                transaction("manual-sponsor/publish", "$", "Committed"),
                transaction("manual-sponsor/finalise", "$", "Committed"),
                transaction("splice-in-smoke", "$.apply", "Committed"),
                transaction("splice-in-smoke", "$.post_splice_sponsor", "Committed"),
                transaction("splice-in-smoke", "$.publish", "Committed"),
                transaction("splice-in-smoke", "$.finalise", "Committed"),
                transaction("splice-out-smoke", "$.apply", "Committed"),
                transaction("splice-out-smoke", "$.post_splice_sponsor", "Committed"),
                transaction("splice-out-smoke", "$.publish", "Committed"),
                transaction("splice-out-smoke", "$.finalise", "Committed"),
                transaction("splice-in-asymmetric-smoke", "$.apply", "Committed"),
                transaction("splice-in-asymmetric-smoke", "$.finalise", "Committed"),
                transaction("splice-out-asymmetric-smoke", "$.apply", "Committed"),
                transaction("splice-out-asymmetric-smoke", "$.finalise", "Committed"),
                transaction("xudt-one-sided-smoke", "$.finalise", "Committed"),
                transaction("xudt-splice-in-smoke", "$.apply", "Committed"),
                transaction("xudt-splice-in-smoke", "$.post_splice_sponsor", "Committed"),
                transaction("xudt-splice-in-smoke", "$.publish", "Committed"),
                transaction("xudt-splice-in-smoke", "$.xudt_finalise", "Committed"),
                transaction("xudt-splice-out-smoke", "$.apply", "Committed"),
                transaction(
                    "xudt-splice-out-smoke",
                    "$.post_splice_sponsor",
                    "Committed",
                ),
                transaction("xudt-splice-out-smoke", "$.publish", "Committed"),
                transaction("xudt-splice-out-smoke", "$.xudt_finalise", "Committed"),
                transaction("xudt-splice-in-one-sided-smoke", "$.apply", "Committed"),
                transaction(
                    "xudt-splice-in-one-sided-smoke",
                    "$.xudt_finalise",
                    "Committed",
                ),
                transaction("xudt-splice-out-one-sided-smoke", "$.apply", "Committed"),
                transaction(
                    "xudt-splice-out-one-sided-smoke",
                    "$.xudt_finalise",
                    "Committed",
                ),
                transaction("factory-smoke", "$.update", "Committed"),
                transaction("factory-reduced-rights-smoke", "$.update", "Committed"),
                transaction(
                    "factory-reduced-rights-tight-smoke",
                    "$.update",
                    "Committed",
                ),
                transaction("factory-merkle-update-smoke", "$.update", "Committed"),
                transaction("factory-merkle-update-tight-smoke", "$.update", "Committed"),
                transaction("factory-reduced-exit-smoke", "$.exit", "Committed"),
                transaction(
                    "factory-reduced-exit-asymmetric-smoke",
                    "$.exit",
                    "Committed",
                ),
                transaction("factory-reduced-xudt-exit-smoke", "$.exit", "Committed"),
                transaction("factory-reduced-xudt-exit-smoke", "$.finalise", "Committed"),
                transaction(
                    "factory-reduced-xudt-exit-full-smoke",
                    "$.exit",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-exit-full-smoke",
                    "$.finalise",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-exit-one-sided-smoke",
                    "$.exit",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-exit-one-sided-smoke",
                    "$.finalise",
                    "Committed",
                ),
                transaction("factory-splice-in-smoke", "$.open", "Committed"),
                transaction("factory-splice-in-smoke", "$.apply", "Committed"),
                transaction("factory-splice-in-smoke", "$.exit", "Committed"),
                transaction("factory-splice-out-smoke", "$.open", "Committed"),
                transaction("factory-splice-out-smoke", "$.apply", "Committed"),
                transaction("factory-splice-out-smoke", "$.exit", "Committed"),
                transaction("factory-splice-in-asymmetric-smoke", "$.apply", "Committed"),
                transaction(
                    "factory-splice-out-asymmetric-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction("factory-reduced-splice-in-smoke", "$.open", "Committed"),
                transaction("factory-reduced-splice-in-smoke", "$.apply", "Committed"),
                transaction("factory-reduced-splice-in-smoke", "$.exit", "Committed"),
                transaction("factory-reduced-splice-out-smoke", "$.open", "Committed"),
                transaction("factory-reduced-splice-out-smoke", "$.apply", "Committed"),
                transaction("factory-reduced-splice-out-smoke", "$.exit", "Committed"),
                transaction(
                    "factory-reduced-splice-in-asymmetric-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-splice-out-asymmetric-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-in-smoke",
                    "$.open",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-in-smoke",
                    "$.external_xudt",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-in-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-in-smoke",
                    "$.exit",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-out-smoke",
                    "$.open",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-out-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-out-smoke",
                    "$.exit",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-in-one-sided-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction(
                    "factory-reduced-xudt-splice-out-one-sided-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction("factory-xudt-splice-in-smoke", "$.open", "Committed"),
                transaction(
                    "factory-xudt-splice-in-smoke",
                    "$.external_xudt",
                    "Committed",
                ),
                transaction("factory-xudt-splice-in-smoke", "$.apply", "Committed"),
                transaction("factory-xudt-splice-in-smoke", "$.exit", "Committed"),
                transaction("factory-xudt-splice-out-smoke", "$.open", "Committed"),
                transaction("factory-xudt-splice-out-smoke", "$.apply", "Committed"),
                transaction("factory-xudt-splice-out-smoke", "$.exit", "Committed"),
                transaction(
                    "factory-xudt-splice-in-one-sided-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction(
                    "factory-xudt-splice-out-one-sided-smoke",
                    "$.apply",
                    "Committed",
                ),
                transaction("factory-xudt-one-sided/smoke", "$.exit", "Committed"),
                transaction("factory-xudt-one-sided/smoke", "$.finalise", "Committed"),
                transaction("watch-direct-sponsor/watch", "$.publication", "Committed"),
                transaction("watch-direct-sponsor/finalise", "$", "Committed"),
                transaction("watch-config-loop/finalise", "$", "Committed"),
            ],
            script_failures: vec![
                failure(
                    "factory-reduced-xudt-negative-exit-smoke",
                    "SettlementOutputMismatch",
                    28,
                ),
                failure(
                    "factory-xudt-negative/smoke",
                    "SettlementOutputMismatch",
                    28,
                ),
                failure("finalise-since-negative-smoke", "StateSinceNotMature", 16),
                failure("sponsor-budget-negative-smoke", "SponsorFeeTooHigh", 17),
                failure(
                    "sponsor-policy-negative-smoke",
                    "SponsorStateOutOfRange",
                    29,
                ),
                failure("xudt-negative-smoke", "SettlementOutputMismatch", 28),
            ],
            watchtower_alerts: watchtower_alerts(),
            watchtower_services: watchtower_services(),
            factory_reduced_rights_updates: vec![factory_reduced_rights_update()],
            factory_merkle_updates: vec![factory_merkle_update()],
            factory_proof_profiles: vec![
                factory_reduced_rights_proof_profile(),
                factory_proof_profile(),
                factory_reduced_exit_proof_profile(
                    "factory-reduced-exit-smoke",
                    "factory_reduced_exit_ckb_reserve_claim",
                ),
                factory_reduced_exit_proof_profile(
                    "factory-reduced-exit-asymmetric-smoke",
                    "factory_reduced_exit_ckb_reserve_claim",
                ),
                factory_reduced_exit_proof_profile(
                    "factory-reduced-xudt-exit-smoke",
                    "factory_reduced_exit_xudt_change_reserve_claim",
                ),
                factory_reduced_exit_proof_profile(
                    "factory-reduced-xudt-exit-full-smoke",
                    "factory_reduced_exit_xudt_reserve_claim",
                ),
                factory_reduced_exit_proof_profile(
                    "factory-reduced-xudt-exit-one-sided-smoke",
                    "factory_reduced_exit_xudt_one_sided_reserve_claim",
                ),
                factory_splice_proof_profile(
                    "factory-splice-in-smoke",
                    "factory_splice_all_participants_ckb",
                    0,
                ),
                factory_splice_proof_profile(
                    "factory-splice-out-smoke",
                    "factory_splice_all_participants_ckb",
                    0,
                ),
                factory_splice_proof_profile(
                    "factory-reduced-splice-in-smoke",
                    "factory_reduced_splice_ckb_sparse_merkle",
                    morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH,
                ),
                factory_splice_proof_profile(
                    "factory-reduced-splice-out-smoke",
                    "factory_reduced_splice_ckb_sparse_merkle",
                    morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH,
                ),
                factory_splice_proof_profile(
                    "factory-reduced-xudt-splice-in-smoke",
                    "factory_reduced_splice_xudt_sparse_merkle",
                    morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH,
                ),
                factory_splice_proof_profile(
                    "factory-reduced-xudt-splice-out-smoke",
                    "factory_reduced_splice_xudt_sparse_merkle",
                    morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH,
                ),
                factory_splice_proof_profile(
                    "factory-xudt-splice-in-smoke",
                    "factory_splice_all_participants_xudt",
                    0,
                ),
                factory_splice_proof_profile(
                    "factory-xudt-splice-out-smoke",
                    "factory_splice_all_participants_xudt",
                    0,
                ),
            ],
            factory_reduced_exits: vec![
                factory_reduced_exit("factory-reduced-exit-smoke", None),
                factory_reduced_exit("factory-reduced-exit-asymmetric-smoke", None),
                factory_reduced_xudt_exit("factory-reduced-xudt-exit-smoke", 100, 60, 40, 50),
                factory_reduced_xudt_exit("factory-reduced-xudt-exit-full-smoke", 100, 60, 40, 0),
                factory_reduced_xudt_exit(
                    "factory-reduced-xudt-exit-one-sided-smoke",
                    100,
                    0,
                    100,
                    0,
                ),
            ],
            factory_local_exits: vec![
                factory_exit("factory/exit-channel", 1),
                factory_exit("factory/local-exit-package", 1),
                factory_exit("factory-xudt/local-exit-package", 2),
                factory_exit("factory-xudt/smoke", 2),
                factory_exit("factory-xudt-negative/local-exit-package", 2),
                factory_exit("factory-xudt-negative/smoke", 2),
                factory_exit("factory-splice-in-smoke", 1),
                factory_exit("factory-splice-out-smoke", 1),
                factory_exit("factory-reduced-xudt-splice-in-smoke", 2),
                factory_exit("factory-reduced-xudt-splice-out-smoke", 2),
                factory_exit("factory-xudt-splice-in-smoke", 2),
                factory_exit("factory-xudt-splice-out-smoke", 2),
            ],
            factory_splices: vec![
                factory_splice("factory-splice-in-smoke", "splice_in", "ckb", 20, 0),
                factory_splice("factory-splice-out-smoke", "splice_out", "ckb", 0, 20),
                factory_reduced_splice(
                    "factory-reduced-splice-in-smoke",
                    "splice_in",
                    "ckb",
                    20,
                    0,
                ),
                factory_reduced_splice(
                    "factory-reduced-splice-out-smoke",
                    "splice_out",
                    "ckb",
                    0,
                    20,
                ),
                factory_reduced_splice(
                    "factory-reduced-xudt-splice-in-smoke",
                    "splice_in",
                    &xudt_asset_id(101),
                    20,
                    0,
                ),
                factory_reduced_splice(
                    "factory-reduced-xudt-splice-out-smoke",
                    "splice_out",
                    &xudt_asset_id(102),
                    0,
                    20,
                ),
                factory_splice(
                    "factory-xudt-splice-in-smoke",
                    "splice_in",
                    &xudt_asset_id(103),
                    20,
                    0,
                ),
                factory_splice(
                    "factory-xudt-splice-out-smoke",
                    "splice_out",
                    &xudt_asset_id(104),
                    0,
                    20,
                ),
            ],
            splice_payouts: vec![
                splice_payout("splice-in-smoke", "none", false),
                splice_payout("splice-out-smoke", "participant_signature_pubkey", true),
                splice_payout("xudt-splice-in-smoke", "none", false),
                splice_payout(
                    "xudt-splice-out-smoke",
                    "participant_signature_pubkey",
                    true,
                ),
            ],
            sponsor_policies: Vec::new(),
            deployed_scripts: deployed_scripts(),
            totals: MetricTotals {
                transaction_count: 70,
                committed_count: 69,
                pending_count: 1,
                total_estimated_cycles: 1,
                max_estimated_cycles: 1,
                total_tx_size_bytes: 1,
                max_tx_size_bytes: 1,
            },
        }
    }

    fn splice_payout(
        check: &str,
        withdrawal_payout_policy: &str,
        has_withdrawal: bool,
    ) -> SplicePayoutEvidenceSummary {
        SplicePayoutEvidenceSummary {
            check: check.to_string(),
            path: "$.apply".to_string(),
            withdrawal_payout_policy: withdrawal_payout_policy.to_string(),
            withdrawal_participant_pubkey_sec1: has_withdrawal.then(|| compressed_pubkey_hex(41)),
            withdrawal_lock_hash: has_withdrawal.then(|| bytes32_hex(73)),
            withdrawal_out_point: has_withdrawal.then(|| "0xabc:2".to_string()),
        }
    }

    fn transaction(check: &str, path: &str, status: &str) -> TransactionSummary {
        TransactionSummary {
            check: check.to_string(),
            path: path.to_string(),
            tx_hash: "0xabc".to_string(),
            status: Some(status.to_string()),
            block_number: Some(1),
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn failure(check: &str, morph_error: &str, error_code: i64) -> ScriptFailureSummary {
        ScriptFailureSummary {
            check: check.to_string(),
            path: "$.script_failure".to_string(),
            source: Some("Inputs[0].Type".to_string()),
            error_code: Some(error_code),
            morph_error: Some(morph_error.to_string()),
        }
    }

    fn factory_reduced_rights_update() -> FactoryReducedRightsEvidenceSummary {
        FactoryReducedRightsEvidenceSummary {
            check: "factory-reduced-rights-smoke".to_string(),
            path: "$.package.package".to_string(),
            factory_id: "0x00".to_string(),
            old_update_number: 0,
            new_update_number: 1,
            signing_digest: "0x11".to_string(),
            old_state_root: "0x22".to_string(),
            new_state_root: "0x33".to_string(),
            old_access_manifest_root: "0x44".to_string(),
            new_access_manifest_root: "0x55".to_string(),
            non_interference_digest: "0x66".to_string(),
            witness_len: 2580,
        }
    }

    fn factory_merkle_update() -> FactoryMerkleUpdateEvidenceSummary {
        FactoryMerkleUpdateEvidenceSummary {
            check: "factory-merkle-update-smoke".to_string(),
            path: "$.package.package".to_string(),
            factory_id: "0x00".to_string(),
            old_update_number: 0,
            new_update_number: 1,
            signing_digest: "0x11".to_string(),
            old_state_root: "0x22".to_string(),
            new_state_root: "0x33".to_string(),
            old_access_manifest_root: "0x44".to_string(),
            new_access_manifest_root: "0x44".to_string(),
            non_interference_digest: "0x66".to_string(),
            changed_participant: "0x77".to_string(),
            quantity_before: 1000,
            quantity_after: 900,
            proof_siblings: 256,
            witness_len: 8720,
        }
    }

    fn factory_proof_profile() -> FactoryProofProfileSummary {
        FactoryProofProfileSummary {
            check: "factory-merkle-update-smoke".to_string(),
            transaction_path: "$.update".to_string(),
            evidence_path: "$.package.package".to_string(),
            proof_kind: "factory_sparse_merkle_update".to_string(),
            proof_siblings: 256,
            witness_len: 8720,
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn factory_reduced_rights_proof_profile() -> FactoryProofProfileSummary {
        FactoryProofProfileSummary {
            check: "factory-reduced-rights-smoke".to_string(),
            transaction_path: "$.update".to_string(),
            evidence_path: "$.package.package".to_string(),
            proof_kind: "factory_reduced_rights_bounded_claim_decrease".to_string(),
            proof_siblings: 0,
            witness_len: 2580,
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn factory_reduced_exit_proof_profile(
        check: &str,
        proof_kind: &str,
    ) -> FactoryProofProfileSummary {
        FactoryProofProfileSummary {
            check: check.to_string(),
            transaction_path: "$.exit".to_string(),
            evidence_path: "$.exit.reduced_exit".to_string(),
            proof_kind: proof_kind.to_string(),
            proof_siblings: 0,
            witness_len: 1,
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn factory_splice_proof_profile(
        check: &str,
        proof_kind: &str,
        proof_siblings: usize,
    ) -> FactoryProofProfileSummary {
        FactoryProofProfileSummary {
            check: check.to_string(),
            transaction_path: "$.apply".to_string(),
            evidence_path: "$.package.package".to_string(),
            proof_kind: proof_kind.to_string(),
            proof_siblings,
            witness_len: 1,
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn factory_reduced_exit(
        check: &str,
        child_xudt_amount: Option<u128>,
    ) -> FactoryReducedExitEvidenceSummary {
        FactoryReducedExitEvidenceSummary {
            check: check.to_string(),
            path: "$.exit.reduced_exit".to_string(),
            authorisation: "reduced-reserve-claim".to_string(),
            release_quantity: 1,
            witness_len: 1,
            local_exit_digest: "0x77".to_string(),
            non_interference_digest: "0x88".to_string(),
            child_xudt_amount,
            alice_xudt_amount: child_xudt_amount.map(|amount| amount / 2),
            bob_xudt_amount: child_xudt_amount.map(|amount| amount - (amount / 2)),
            xudt_type_hash: child_xudt_amount.map(|_| "0x99".to_string()),
            factory_vault_change_xudt_amount: None,
        }
    }

    fn factory_reduced_xudt_exit(
        check: &str,
        child_xudt_amount: u128,
        alice_xudt_amount: u128,
        bob_xudt_amount: u128,
        factory_vault_change_xudt_amount: u128,
    ) -> FactoryReducedExitEvidenceSummary {
        FactoryReducedExitEvidenceSummary {
            check: check.to_string(),
            path: "$.exit.reduced_exit".to_string(),
            authorisation: "reduced-reserve-claim".to_string(),
            release_quantity: child_xudt_amount,
            witness_len: 1,
            local_exit_digest: "0x77".to_string(),
            non_interference_digest: "0x88".to_string(),
            child_xudt_amount: Some(child_xudt_amount),
            alice_xudt_amount: Some(alice_xudt_amount),
            bob_xudt_amount: Some(bob_xudt_amount),
            xudt_type_hash: Some(
                "0x9999999999999999999999999999999999999999999999999999999999999999".to_string(),
            ),
            factory_vault_change_xudt_amount: Some(factory_vault_change_xudt_amount),
        }
    }

    fn factory_exit(check: &str, descriptor_version: u16) -> FactoryLocalExitEvidenceSummary {
        FactoryLocalExitEvidenceSummary {
            check: check.to_string(),
            path: "$.local_exit_package".to_string(),
            factory_id: "0x00".to_string(),
            update_number: 1,
            exit_digest: "0x11".to_string(),
            child_channel_id: "0x22".to_string(),
            child_state_number: 0,
            child_phase: "active".to_string(),
            descriptor_version,
            state_output_index: 0,
            vault_output_index: 1,
        }
    }

    fn factory_splice(
        check: &str,
        kind: &str,
        reserve_claim_asset: &str,
        external_input: u128,
        withdrawal: u128,
    ) -> FactorySpliceEvidenceSummary {
        let (before, after) = if kind == "splice_in" {
            (100, 120)
        } else {
            (100, 80)
        };
        FactorySpliceEvidenceSummary {
            check: check.to_string(),
            path: "$.package.package".to_string(),
            factory_id: "0x00".to_string(),
            kind: kind.to_string(),
            old_update_number: 0,
            new_update_number: 1,
            reserve_claim_asset: reserve_claim_asset.to_string(),
            reserve_claim_before: before,
            reserve_claim_after: after,
            vault_old_amount: before,
            vault_new_amount: after,
            external_input,
            withdrawal,
            proof_siblings: 0,
            signatures: 2,
            signing_digest: "0x11".to_string(),
            vault_delta_commitment: "0x22".to_string(),
            non_interference_digest: "0x33".to_string(),
            witness_len: 1,
        }
    }

    fn factory_reduced_splice(
        check: &str,
        kind: &str,
        reserve_claim_asset: &str,
        external_input: u128,
        withdrawal: u128,
    ) -> FactorySpliceEvidenceSummary {
        let mut summary =
            factory_splice(check, kind, reserve_claim_asset, external_input, withdrawal);
        summary.proof_siblings = morph_script_common::FACTORY_SPARSE_MERKLE_DEPTH;
        summary.signatures = 1;
        summary.witness_len = morph_script_common::factory_reduced_splice_witness_len(2);
        summary
    }

    fn deployed_scripts() -> Vec<DeployedScriptSummary> {
        EXPECTED_DEPLOYED_SCRIPT_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| DeployedScriptSummary {
                check: "deploy-contracts".to_string(),
                path: format!("$.scripts[{index}]"),
                name: (*name).to_string(),
                out_point: format!("0x{index}:0"),
                data_hash: format!("0x{index}"),
                hash_type: "data1".to_string(),
                data_len: 1,
                capacity: 1,
            })
            .collect()
    }

    fn watchtower_alerts() -> Vec<WatchtowerAlertSummary> {
        vec![
            WatchtowerAlertSummary {
                check: "watch-auto-sponsor/watch-alerts".to_string(),
                path: "line 1".to_string(),
                channel_id: "0x11".to_string(),
                severity: "warning".to_string(),
                event: "older_state_detected".to_string(),
                selected_state_number: 2,
                observed_state_number: Some(0),
                observed_out_point: Some("0xabc:0".to_string()),
                publication_tx_hash: None,
                scanned_to_block: 10,
                next_from_block: 11,
            },
            WatchtowerAlertSummary {
                check: "watch-auto-sponsor/watch-alerts".to_string(),
                path: "line 2".to_string(),
                channel_id: "0x11".to_string(),
                severity: "warning".to_string(),
                event: "publication_submitted".to_string(),
                selected_state_number: 2,
                observed_state_number: Some(0),
                observed_out_point: Some("0xabc:0".to_string()),
                publication_tx_hash: Some("0xdef".to_string()),
                scanned_to_block: 10,
                next_from_block: 11,
            },
            WatchtowerAlertSummary {
                check: "watch-splice-stale/watch-alerts".to_string(),
                path: "line 1".to_string(),
                channel_id: "0x11".to_string(),
                severity: "warning".to_string(),
                event: "splice_detected".to_string(),
                selected_state_number: 1,
                observed_state_number: Some(0),
                observed_out_point: Some("0xdef:0".to_string()),
                publication_tx_hash: None,
                scanned_to_block: 20,
                next_from_block: 21,
            },
            WatchtowerAlertSummary {
                check: "watch-splice-stale/watch-alerts".to_string(),
                path: "line 2".to_string(),
                channel_id: "0x11".to_string(),
                severity: "warning".to_string(),
                event: "splice_package_stale".to_string(),
                selected_state_number: 1,
                observed_state_number: Some(0),
                observed_out_point: Some("0xdef:0".to_string()),
                publication_tx_hash: None,
                scanned_to_block: 20,
                next_from_block: 21,
            },
            WatchtowerAlertSummary {
                check: "watch-splice-stale/watch-alerts".to_string(),
                path: "line 3".to_string(),
                channel_id: "0x11".to_string(),
                severity: "info".to_string(),
                event: "scan_idle".to_string(),
                selected_state_number: 1,
                observed_state_number: None,
                observed_out_point: None,
                publication_tx_hash: None,
                scanned_to_block: 20,
                next_from_block: 21,
            },
        ]
    }

    fn watchtower_services() -> Vec<WatchtowerServiceSummary> {
        vec![
            WatchtowerServiceSummary {
                check: "watch-auto-sponsor/service".to_string(),
                path: "$".to_string(),
                schema: "morph.watchtower_config_service".to_string(),
                status: None,
                stopped_reason: Some("stop_file".to_string()),
                completed_passes: 0,
                published_count: 0,
                idle_count: 0,
                error_count: 0,
                consecutive_errors: 0,
                health_file: Some(
                    "target/devnet-smoke/test/watch-auto-sponsor/service-health.json".to_string(),
                ),
            },
            WatchtowerServiceSummary {
                check: "watch-auto-sponsor/service-health".to_string(),
                path: "$".to_string(),
                schema: "morph.watchtower_health".to_string(),
                status: Some("stopped".to_string()),
                stopped_reason: Some("stop_file".to_string()),
                completed_passes: 0,
                published_count: 0,
                idle_count: 0,
                error_count: 0,
                consecutive_errors: 0,
                health_file: None,
            },
        ]
    }

    fn write_metric_json(dir: &Path, file_name: &str, tx_hash: &str, cycles: u64, bytes: usize) {
        fs::write(
            dir.join(file_name),
            format!(
                r#"{{
                  "tx_hash": "{tx_hash}",
                  "status": "Committed",
                  "block_number": 1,
                  "metrics": {{
                    "estimated_cycles": {cycles},
                    "tx_size_bytes": {bytes}
                  }}
                }}"#
            ),
        )
        .unwrap();
    }

    fn bytes32_hex(seed: u8) -> String {
        let hex = (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<String>();
        format!("0x{hex}")
    }

    fn compressed_pubkey_hex(seed: u8) -> String {
        let body = (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<String>();
        format!("0x02{body}")
    }

    fn xudt_asset_id(seed: u8) -> String {
        format!("xudt:{}", bytes32_hex(seed))
    }

    fn temp_report_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "morph-smoke-report-test-{}-{nanos}-{counter}",
            std::process::id()
        ))
    }
}
