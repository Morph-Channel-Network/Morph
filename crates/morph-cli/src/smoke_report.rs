//! Offline evidence for the sole current acceptance matrix. Reports account for
//! current transactions, proofs and operational reliability; they confer no
//! canonical-chain, deployed-code approval or signer authority.
use crate::multi_asset_packages::{canonical_hex, decode_hex, read_bounded_json};
use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::{FactorySigningRequest, FactorySigningRole, FactoryTransactionView};
use morph_script_common::factory_multi_asset as factory;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const MATRIX_SCHEMA: &str = "morph.current_acceptance_matrix.v1";
const BUDGET_SCHEMA: &str = "morph.current_acceptance_budget.v1";
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 4096;
const MAX_TOTAL_JSON_BYTES: u64 = 128 * 1024 * 1024;
const KINDS: &[&str] = &[
    "bilateral_shared",
    "bilateral_max_assets",
    "splice",
    "factory",
    "watch_service",
];
const SCRIPTS: &[&str] = &[
    "morph-state-lock",
    "morph-state-type",
    "morph-factory-type",
    "morph-factory-vault-lock",
    "morph-vault-lock",
    "morph-batch-lock",
    "morph-sponsor-lock",
    "morph-devnet-xudt",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentMatrix {
    pub schema: String,
    pub cases: Vec<CurrentCase>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentCase {
    pub name: String,
    pub kind: String,
    pub report_path: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct CaseSummary {
    pub name: String,
    pub kind: String,
    pub report_path: String,
    pub operator_checks: Vec<String>,
    pub totals: MetricTotals,
}
#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeSummary {
    pub schema: String,
    pub directory: String,
    pub matrix: CurrentMatrix,
    pub cases: Vec<CaseSummary>,
    pub json_files: usize,
    pub transactions: Vec<TransactionSummary>,
    pub transaction_observations: Vec<TransactionSummary>,
    pub script_failures: Vec<ScriptFailureSummary>,
    pub deployed_scripts: Vec<DeployedScriptSummary>,
    pub watchtower_alerts: Vec<WatchtowerAlertSummary>,
    pub watchtower_services: Vec<WatchtowerServiceSummary>,
    pub publication_attempts: Vec<PublicationAttemptSummary>,
    pub publication_reconciliations: Vec<PublicationReconciliationSummary>,
    pub sponsor_policies: Vec<SponsorPolicySummary>,
    pub factory_proofs: Vec<FactoryProofSummary>,
    pub totals: MetricTotals,
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
    pub selected_funding_anchor: Option<String>,
    pub observed_funding_anchor: Option<String>,
    pub selected_funding_context_id: Option<String>,
    pub observed_funding_context_id: Option<String>,
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
pub struct SponsorPolicySummary {
    pub check: String,
    pub path: String,
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub state_number_span: u64,
    pub max_fee_per_tx: u64,
    pub max_total_fee: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct PublicationAttemptSummary {
    pub check: String,
    pub path: String,
    pub intent_id: String,
    pub tx_hash: String,
    pub attempt: u16,
    pub fee: u64,
    pub status: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct PublicationReconciliationSummary {
    pub check: String,
    pub path: String,
    pub inspected: usize,
    pub confirmed: usize,
    pub committed: usize,
    pub rejected: usize,
    pub pending: usize,
    pub proposed: usize,
    pub unknown: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct FactoryProofSummary {
    pub check: String,
    pub path: String,
    pub operation: String,
    pub request_id: Option<String>,
    pub tx_hash: String,
    pub signing_digest: String,
    pub member_count: usize,
    pub signature_count: usize,
    pub right_count: usize,
    pub proof_siblings: usize,
    pub witness_len: usize,
    pub transaction_bytes: usize,
    pub source_vaults: usize,
    pub retained_vaults: usize,
    pub children: usize,
    pub authorized: bool,
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
pub struct DevnetSmokeAssertionReport {
    pub directory: String,
    pub git_commit: Option<String>,
    pub git_dirty: Option<String>,
    pub case_count: usize,
    pub transaction_count: usize,
    pub committed_count: usize,
    pub expected_script_failures: usize,
    pub deployed_scripts: usize,
    pub deployed_script_hashes_verified: bool,
    pub watchtower_alerts: usize,
    pub watchtower_publication_alerts: usize,
    pub watchtower_service_records: usize,
    pub publication_attempts: usize,
    pub factory_proofs: usize,
    pub sponsor_policies: usize,
    pub budget: Option<DevnetSmokeBudgetReport>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct DevnetSmokeBudgetLimits {
    pub max_total_cycles: Option<u64>,
    pub max_tx_cycles: Option<u64>,
    pub max_total_bytes: Option<usize>,
    pub max_tx_bytes: Option<usize>,
    pub cases: Vec<DevnetSmokeCaseBudgetLimit>,
    pub transactions: Vec<DevnetSmokeTransactionBudgetLimit>,
    pub proof_profiles: Vec<DevnetSmokeProofProfileBudgetLimit>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetSmokeCaseBudgetLimit {
    pub name: String,
    pub max_cycles: Option<u64>,
    pub max_bytes: Option<usize>,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    pub max_tx_cycles: Option<u64>,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    pub max_tx_bytes: Option<usize>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetSmokeTransactionBudgetLimit {
    pub check: String,
    pub path: String,
    pub max_cycles: Option<u64>,
    pub max_bytes: Option<usize>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetSmokeProofProfileBudgetLimit {
    pub check: String,
    pub operation: String,
    pub max_witness_len: Option<usize>,
    pub max_proof_siblings: Option<usize>,
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
#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeProofProfileBudgetReport {
    pub check: String,
    pub operation: String,
    pub proof_siblings: usize,
    pub witness_len: usize,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeCaseBudgetReport {
    pub name: String,
    pub total_estimated_cycles: u64,
    pub total_tx_size_bytes: usize,
    pub max_estimated_cycles: u64,
    pub max_tx_size_bytes: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeBudgetReport {
    pub total_estimated_cycles: u64,
    pub max_estimated_cycles: u64,
    pub total_tx_size_bytes: usize,
    pub max_tx_size_bytes: usize,
    pub cases: Vec<DevnetSmokeCaseBudgetReport>,
    pub transactions: Vec<DevnetSmokeTransactionBudgetReport>,
    pub proof_profiles: Vec<DevnetSmokeProofProfileBudgetReport>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetProfile {
    schema: String,
    basis: String,
    max_total_cycles: Option<u64>,
    max_tx_cycles: Option<u64>,
    max_total_bytes: Option<usize>,
    max_tx_bytes: Option<usize>,
    cases: Vec<DevnetSmokeCaseBudgetLimit>,
    transactions: Vec<DevnetSmokeTransactionBudgetLimit>,
    proof_profiles: Vec<DevnetSmokeProofProfileBudgetLimit>,
}
impl DevnetSmokeBudgetLimits {
    pub fn has_any_limit(&self) -> bool {
        self.max_total_cycles.is_some()
            || self.max_tx_cycles.is_some()
            || self.max_total_bytes.is_some()
            || self.max_tx_bytes.is_some()
            || !self.cases.is_empty()
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
    pub estimated_cycles_delta: i128,
    pub baseline_tx_size_bytes: usize,
    pub candidate_tx_size_bytes: usize,
    pub tx_size_bytes_delta: i128,
}
#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeComparison {
    pub baseline_directory: String,
    pub candidate_directory: String,
    pub compared_transactions: usize,
    pub missing_from_candidate: Vec<String>,
    pub added_in_candidate: Vec<String>,
    pub total_estimated_cycles_delta: i128,
    pub total_tx_size_bytes_delta: i128,
    pub transaction_deltas: Vec<TransactionMetricDelta>,
}

fn number(v: &Value) -> Option<u64> {
    match v {
        Value::String(raw) => raw.parse::<u64>().ok().filter(|n| n.to_string() == *raw),
        _ => v.as_u64(),
    }
}
fn usize_value(v: &Value) -> Option<usize> {
    number(v).and_then(|n| usize::try_from(n).ok())
}
fn string(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}
fn hash_string(raw: &str) -> Result<String> {
    let bytes = decode_hex(raw, 32)?;
    ensure!(
        bytes.len() == 32 && bytes.iter().any(|b| *b != 0),
        "invalid current transaction/hash identity"
    );
    Ok(raw.to_string())
}
fn safe_path(root: &Path, path: &str) -> Result<PathBuf> {
    let raw = Path::new(path);
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        root.join(raw)
    };
    let canonical = fs::canonicalize(&candidate)
        .with_context(|| format!("missing evidence {}", candidate.display()))?;
    ensure!(
        canonical.starts_with(root),
        "evidence path escapes current run directory"
    );
    ensure!(canonical.is_file(), "evidence must be a regular file");
    Ok(canonical)
}
fn artifact_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    ensure!(depth <= 16, "artifact directory depth limit");
    let mut entries = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        ensure!(
            !entry.file_type()?.is_symlink(),
            "symlink in acceptance evidence"
        );
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            artifact_files(root, &path, out, depth + 1)?;
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("json" | "jsonl" | "tx")
        ) {
            ensure!(path.starts_with(root), "artifact escaped run");
            // The runner redirects these derived outputs before invoking the
            // reader. They may be empty or contain an earlier summary; neither
            // is source evidence. Keep this exception at the matrix root only.
            if path.parent() == Some(root)
                && matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("summary.json" | "summary-check.json")
                )
            {
                continue;
            }
            out.push(path);
            ensure!(out.len() <= MAX_ARTIFACTS, "too many acceptance artifacts");
        }
    }
    Ok(())
}
fn totals(txs: &[TransactionSummary]) -> Result<MetricTotals> {
    let mut out = MetricTotals::default();
    for tx in unique_transactions(txs)? {
        out.transaction_count += 1;
        out.committed_count += usize::from(tx.status.as_deref() == Some("Committed"));
        out.pending_count +=
            usize::from(matches!(tx.status.as_deref(), Some("Pending" | "Proposed")));
        out.total_estimated_cycles = out
            .total_estimated_cycles
            .checked_add(tx.estimated_cycles)
            .context("cycle total overflow")?;
        out.total_tx_size_bytes = out
            .total_tx_size_bytes
            .checked_add(tx.tx_size_bytes)
            .context("byte total overflow")?;
        out.max_estimated_cycles = out.max_estimated_cycles.max(tx.estimated_cycles);
        out.max_tx_size_bytes = out.max_tx_size_bytes.max(tx.tx_size_bytes);
    }
    Ok(out)
}
fn unique_transactions(all: &[TransactionSummary]) -> Result<Vec<TransactionSummary>> {
    let mut map: BTreeMap<String, TransactionSummary> = BTreeMap::new();
    for tx in all {
        if let Some(old) = map.get_mut(&tx.tx_hash) {
            ensure!(
                old.estimated_cycles == tx.estimated_cycles
                    && old.tx_size_bytes == tx.tx_size_bytes,
                "same transaction has conflicting resource measurements"
            );
            if tx.status.as_deref() == Some("Committed") {
                old.status = tx.status.clone();
                old.block_number = tx.block_number;
            }
        } else {
            map.insert(tx.tx_hash.clone(), tx.clone());
        }
    }
    Ok(map.into_values().collect())
}
fn checks(
    value: &Value,
    out: &mut BTreeSet<String>,
    facts: &mut BTreeMap<String, bool>,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 64, "report nesting limit");
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                if key == "operator_checks"
                    && let Some(list) = v.as_array()
                {
                    for item in list {
                        out.insert(
                            item.as_str()
                                .context("operator check must be a string")?
                                .to_string(),
                        );
                    }
                }
                if let Some(flag) = v.as_bool() {
                    facts
                        .entry(key.clone())
                        .and_modify(|old| *old &= flag)
                        .or_insert(flag);
                }
                checks(v, out, facts, depth + 1)?;
            }
        }
        Value::Array(list) => {
            for item in list {
                checks(item, out, facts, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn schema_current(value: &Value) -> Result<()> {
    if let Some(schema) = value.get("schema").and_then(Value::as_str) {
        ensure!(
            !matches!(
                schema,
                "morph.state_package"
                    | "morph.splice_package"
                    | "morph.factory_package"
                    | "morph.factory_state_package"
                    | "morph.factory_local_exit_package"
                    | "morph.factory_reduced_rights_package"
                    | "morph.factory_merkle_update_state_package"
                    | "morph.factory_splice_package"
                    | "morph.factory_reduced_splice_package"
                    | "morph.factory_multi_asset_materialisation.v1"
            ),
            "retired wire artifact in current matrix: {schema}"
        );
    }
    Ok(())
}
fn collect(
    value: &Value,
    check: &str,
    path: &str,
    summary: &mut DevnetSmokeSummary,
    nodes: &mut usize,
    depth: usize,
) -> Result<()> {
    *nodes += 1;
    ensure!(*nodes <= 200_000 && depth <= 64, "report node/depth bound");
    schema_current(value)?;
    if let Value::Object(map) = value {
        if let (Some(tx_hash), Some(metrics)) = (
            value.get("tx_hash").and_then(Value::as_str),
            value.get("metrics"),
        ) {
            let cycles =
                number(&metrics["estimated_cycles"]).context("transaction metric lacks cycles")?;
            let size = usize_value(&metrics["tx_size_bytes"])
                .context("transaction metric lacks byte length")?;
            summary.transaction_observations.push(TransactionSummary {
                check: check.to_string(),
                path: path.to_string(),
                tx_hash: hash_string(tx_hash)?,
                status: string(value, "status"),
                block_number: number(&value["block_number"]),
                estimated_cycles: cycles,
                tx_size_bytes: size,
            });
        }
        if let Some(failure) = value.get("script_failure").filter(|v| v.is_object()) {
            summary.script_failures.push(ScriptFailureSummary {
                check: check.to_string(),
                path: format!("{path}.script_failure"),
                source: string(failure, "source"),
                error_code: failure["error_code"].as_i64(),
                morph_error: string(failure, "morph_error"),
            });
        }
        if let Some(policy) = value.get("sponsor_policy").filter(|v| v.is_object()) {
            let min = number(&policy["min_state_number"]).context("sponsor min missing")?;
            let max = number(&policy["max_state_number"]).context("sponsor max missing")?;
            summary.sponsor_policies.push(SponsorPolicySummary {
                check: check.to_string(),
                path: format!("{path}.sponsor_policy"),
                min_state_number: min,
                max_state_number: max,
                state_number_span: max.checked_sub(min).context("sponsor range inverted")?,
                max_fee_per_tx: number(&policy["max_fee_per_tx"]).context("sponsor cap missing")?,
                max_total_fee: number(&policy["max_total_fee"])
                    .context("sponsor total cap missing")?,
            });
        }
        if let Some(reconciliation) = value
            .get("publication_reconciliation")
            .filter(|value| value.is_object())
        {
            summary
                .publication_reconciliations
                .push(PublicationReconciliationSummary {
                    check: check.to_string(),
                    path: format!("{path}.publication_reconciliation"),
                    inspected: usize_value(&reconciliation["inspected"])
                        .context("reconciliation inspected missing")?,
                    confirmed: usize_value(&reconciliation["confirmed"])
                        .context("reconciliation confirmed missing")?,
                    committed: usize_value(&reconciliation["committed"])
                        .context("reconciliation committed missing")?,
                    rejected: usize_value(&reconciliation["rejected"])
                        .context("reconciliation rejected missing")?,
                    pending: usize_value(&reconciliation["pending"])
                        .context("reconciliation pending missing")?,
                    proposed: usize_value(&reconciliation["proposed"])
                        .context("reconciliation proposed missing")?,
                    unknown: usize_value(&reconciliation["unknown"])
                        .context("reconciliation unknown missing")?,
                });
        }
        if let Some(raw) = value.get("error").and_then(Value::as_str) {
            let parsed = crate::devnet::parse_script_failure(raw);
            if parsed.error_code.is_some() {
                summary.script_failures.push(ScriptFailureSummary {
                    check: check.to_string(),
                    path: format!("{path}.error"),
                    source: parsed.source,
                    error_code: parsed.error_code.map(i64::from),
                    morph_error: parsed.morph_error,
                });
            }
        }
        let schema = value.get("schema").and_then(Value::as_str).unwrap_or("");
        if schema == "morph.watchtower_alert" {
            let alert: crate::watch_alert::WatchtowerAlert = serde_json::from_value(value.clone())?;
            summary.watchtower_alerts.push(WatchtowerAlertSummary {
                check: check.to_string(),
                path: path.to_string(),
                channel_id: alert.channel_id,
                severity: serde_json::to_value(alert.severity)?
                    .as_str()
                    .context("alert severity")?
                    .to_string(),
                event: serde_json::to_value(alert.event)?
                    .as_str()
                    .context("alert event")?
                    .to_string(),
                selected_state_number: alert.selected_state_number,
                observed_state_number: alert.observed_state_number,
                observed_out_point: alert.observed_out_point,
                publication_tx_hash: alert.publication_tx_hash,
                selected_funding_anchor: alert.selected_funding_anchor,
                observed_funding_anchor: alert.observed_funding_anchor,
                selected_funding_context_id: alert.selected_funding_context_id,
                observed_funding_context_id: alert.observed_funding_context_id,
                scanned_to_block: alert.scanned_to_block,
                next_from_block: alert.next_from_block,
            });
        }
        if matches!(
            schema,
            "morph.watchtower_config_service" | "morph.watchtower_health"
        ) {
            summary.watchtower_services.push(WatchtowerServiceSummary {
                check: check.to_string(),
                path: path.to_string(),
                schema: schema.to_string(),
                status: string(value, "status"),
                stopped_reason: string(value, "stopped_reason"),
                completed_passes: number(&value["completed_passes"])
                    .context("service passes missing")?,
                published_count: usize_value(&value["published_count"])
                    .context("service publication count missing")?,
                idle_count: usize_value(&value["idle_count"])
                    .context("service idle count missing")?,
                error_count: number(&value["error_count"])
                    .context("service error count missing")?,
                consecutive_errors: number(&value["consecutive_errors"])
                    .context("service error streak missing")?,
                health_file: string(value, "health_file"),
            });
        }
        if schema == "morph.publication_attempt" {
            let attempt: crate::publication::PublicationAttemptRecord =
                serde_json::from_value(value.clone())?;
            summary
                .publication_attempts
                .push(PublicationAttemptSummary {
                    check: check.to_string(),
                    path: path.to_string(),
                    intent_id: attempt.intent_id,
                    tx_hash: attempt.tx_hash,
                    attempt: attempt.attempt,
                    fee: attempt.fee,
                    status: attempt.status,
                });
        }
        for (key, item) in map {
            collect(
                item,
                check,
                &format!("{path}.{key}"),
                summary,
                nodes,
                depth + 1,
            )?;
        }
    } else if let Value::Array(list) = value {
        for (i, item) in list.iter().enumerate() {
            collect(
                item,
                check,
                &format!("{path}[{i}]"),
                summary,
                nodes,
                depth + 1,
            )?;
        }
    }
    Ok(())
}
fn proof_from_request(
    check: &str,
    path: &str,
    request: &FactorySigningRequest,
    signed: Option<&packed::Transaction>,
) -> Result<FactoryProofSummary> {
    request.validate_for_review(&request.members()?)?;
    if let Some(tx) = signed {
        request.verify_authorized_transaction(tx)?;
    }
    let (operation, rights, siblings, children) = match request.role {
        FactorySigningRole::Transition => {
            let frame = factory::FactoryReducedReleaseWitness::parse(&request.witness)
                .map_err(|e| anyhow!("invalid Factory transition: {e:?}"))?;
            let mut siblings = 0;
            for i in 0..frame.right_count() {
                siblings += frame
                    .right(i)
                    .map_err(|e| anyhow!("invalid right: {e:?}"))?
                    .proof_sibling_count();
            }
            (
                format!("{:?}", frame.operation()),
                frame.right_count(),
                siblings,
                frame
                    .child_intent()
                    .map_or(0, |intent| intent.child_count()),
            )
        }
        FactorySigningRole::Materialisation => {
            let frame = factory::FactoryMaterialisationWitness::parse(&request.witness)
                .map_err(|e| anyhow!("invalid materialisation: {e:?}"))?;
            (
                "materialisation".to_string(),
                request.target_rights.len(),
                0,
                frame.intent().child_count(),
            )
        }
        FactorySigningRole::RootFunding => (
            "root_funding".to_string(),
            request.target_rights.len(),
            0,
            0,
        ),
        FactorySigningRole::MetadataUpdate => (
            "metadata_update".to_string(),
            request.target_rights.len(),
            0,
            0,
        ),
    };
    Ok(FactoryProofSummary {
        check: check.to_string(),
        path: path.to_string(),
        operation,
        request_id: Some(canonical_hex(&request.request_id()?)),
        tx_hash: canonical_hex(&request.transaction_hash()?),
        signing_digest: canonical_hex(&request.signing_digest()?),
        member_count: request.members()?.len(),
        signature_count: if signed.is_some() {
            request.required_members()?.len()
        } else {
            0
        },
        right_count: rights,
        proof_siblings: siblings,
        witness_len: request.witness.len(),
        transaction_bytes: signed.map_or(request.transaction.len(), |tx| tx.as_slice().len()),
        source_vaults: request
            .source
            .as_ref()
            .map_or(0, |source| source.manifest.vaults.len()),
        retained_vaults: request
            .target
            .as_ref()
            .map_or(0, |target| target.manifest.vaults.len()),
        children,
        authorized: signed.is_some(),
    })
}
fn proof_from_frame(
    check: &str,
    path: &str,
    view: &FactoryTransactionView,
) -> Result<FactoryProofSummary> {
    let frame = view.witness()?;
    let mut siblings = 0;
    for i in 0..frame.right_count() {
        siblings += frame
            .right(i)
            .map_err(|e| anyhow!("invalid proof metrics: {e:?}"))?
            .proof_sibling_count();
    }
    Ok(FactoryProofSummary {
        check: check.to_string(),
        path: path.to_string(),
        operation: format!("{:?}", frame.operation()),
        request_id: None,
        tx_hash: canonical_hex(view.transaction().calc_tx_hash().as_slice()),
        signing_digest: canonical_hex(&frame.signing_digest()),
        member_count: frame.member_count(),
        signature_count: frame.signature_count(),
        right_count: frame.right_count(),
        proof_siblings: siblings,
        witness_len: frame.as_bytes().len(),
        transaction_bytes: view.transaction().as_slice().len(),
        source_vaults: frame.source().count(),
        retained_vaults: frame.retained().count(),
        children: frame
            .child_intent()
            .map_or(0, |intent| intent.child_count()),
        authorized: true,
    })
}
fn case_semantics(
    case: &CurrentCase,
    value: &Value,
    operator_checks: &BTreeSet<String>,
) -> Result<()> {
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .context("case report has no current schema")?;
    let committed = |v: &Value| v.get("status").and_then(Value::as_str) == Some("Committed");
    match case.kind.as_str() {
        "bilateral_shared" | "bilateral_max_assets" => {
            ensure!(
                schema == "morph.multi_asset_devnet_acceptance.v1",
                "wrong bilateral report schema"
            );
            ensure!(
                committed(&value["fund"])
                    && committed(&value["activation"])
                    && committed(&value["finalise"]),
                "bilateral case lacks committed funding/activation/terminal"
            );
            if case.kind == "bilateral_shared" {
                ensure!(
                    value["shared_funding"] == true,
                    "bilateral shared case used only one funding wallet"
                );
            } else {
                ensure!(
                    number(&value["asset_count"]) == Some(8) && value["shared_funding"] == true,
                    "maximum-asset case does not exercise eight assets and independent funders"
                );
            }
        }
        "splice" => {
            ensure!(
                schema == "morph.current_splice_devnet_acceptance.v1",
                "wrong splice report schema"
            );
            ensure!(
                committed(&value["fund"]) && committed(&value["activation"]),
                "splice case lacks committed root funding/activation"
            );
            let transitions = &value["transitions"];
            let operations = transitions["operations"]
                .as_array()
                .context("splice transition evidence missing")?;
            ensure!(
                operations.len() == 2
                    && operations
                        .iter()
                        .filter_map(|op| op["operation"].as_str())
                        .collect::<BTreeSet<_>>()
                        == BTreeSet::from(["admit", "remove"])
                    && operations
                        .iter()
                        .all(|op| op["withheld_bridge_receipt_reconciled"] == true
                            && committed(&op["submission"])
                            && committed(&op["activation"])),
                "splice admission/removal or withheld bridge recovery incomplete"
            );
            let terminal = transitions["terminal"]
                .as_array()
                .context("splice terminal evidence missing")?;
            ensure!(
                terminal.len() == 2 && terminal.iter().all(committed),
                "splice terminal publish/finalise missing"
            );
        }
        "factory" => {
            ensure!(
                schema == "morph.current_factory_acceptance.v1",
                "wrong native Factory report schema"
            );
            ensure!(
                committed(&value["root"]["report"])
                    && committed(&value["activation"]["report"])
                    && value["canonical_replay"]["canonical_replay"] == true
                    && committed(&value["transitions"]["escape"]["report"])
                    && committed(&value["transitions"]["deposit"]["report"]),
                "Factory root, activation, exact replay or unilateral escape/deposit incomplete"
            );
            for child in ["reduced", "terminal"] {
                let lifecycle = &value["transitions"]["child"][child];
                ensure!(
                    committed(&lifecycle["parent"]["report"])
                        && committed(&lifecycle["activation"])
                        && committed(&lifecycle["finalise"]),
                    "Factory {child} child lifecycle incomplete"
                );
            }
            for required in [
                "wrong_key_preserves_journal",
                "partial_export_cannot_poison_path",
                "same_path_handoff",
                "withheld_full_consent_escaped",
                "previous_approval_not_revoked",
                "peer_refreshed_from_public_changes",
                "initial_exit_required_before_parent_vote",
                "private_exit_signatures_absent_from_parent",
                "retired",
            ] {
                ensure!(
                    operator_checks.contains(required),
                    "Factory case lacks {required} evidence"
                );
            }
        }
        "watch_service" => {
            ensure!(
                schema == "morph.multi_asset_devnet_acceptance.v1",
                "wrong watch service report schema"
            );
            for required in [
                "watch_kept_active_channel_open",
                "watch_rejected_conflicting_signed_states",
                "watch_rejected_late_scan_origin",
                "watch_rejected_same_number_on_chain_conflict",
                "current_watch_service_auto_sponsor_published",
                "current_watch_service_health_verified",
                "watch_published_late_recovery_package",
                "watch_reorg_rescan_republished",
            ] {
                ensure!(
                    operator_checks.contains(required),
                    "watch service case lacks {required}"
                );
            }
            ensure!(
                committed(&value["finalise"]),
                "watch service case lacks terminal finalisation"
            );
        }
        _ => return Err(anyhow!("unsupported current matrix case kind")),
    }
    Ok(())
}
pub fn summarize_devnet_smoke(dir: &Path) -> Result<DevnetSmokeSummary> {
    let root = fs::canonicalize(dir).context("current run directory missing")?;
    ensure!(root.is_dir(), "run directory is not a directory");
    let matrix: CurrentMatrix = read_bounded_json(&root.join("matrix.json"), 64 * 1024)?;
    ensure!(
        matrix.schema == MATRIX_SCHEMA && (1..=64).contains(&matrix.cases.len()),
        "unsupported/unbounded current acceptance matrix"
    );
    let mut names = BTreeSet::new();
    for case in &matrix.cases {
        ensure!(
            !case.name.is_empty()
                && case.name != "deployment"
                && case.name.len() <= 64
                && case
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && names.insert(case.name.clone()),
            "invalid/duplicate matrix case name"
        );
        ensure!(
            KINDS.contains(&case.kind.as_str()),
            "unknown matrix case kind"
        );
    }
    let mut summary = DevnetSmokeSummary {
        schema: "morph.current_acceptance_summary.v1".to_string(),
        directory: root.display().to_string(),
        matrix: matrix.clone(),
        cases: vec![],
        json_files: 0,
        transactions: vec![],
        transaction_observations: vec![],
        script_failures: vec![],
        deployed_scripts: vec![],
        watchtower_alerts: vec![],
        watchtower_services: vec![],
        publication_attempts: vec![],
        publication_reconciliations: vec![],
        sponsor_policies: vec![],
        factory_proofs: vec![],
        totals: MetricTotals::default(),
    };
    let mut tx_case = BTreeMap::new();
    let mut channel_case = BTreeMap::new();
    let mut nodes = 0;
    for case in &matrix.cases {
        let path = safe_path(&root, &case.report_path)?;
        let value: Value = read_bounded_json(&path, MAX_JSON_BYTES)?;
        summary.json_files += 1;
        let mut check_set = BTreeSet::new();
        let mut facts = BTreeMap::new();
        checks(&value, &mut check_set, &mut facts, 0)?;
        for (key, flag) in facts {
            if flag {
                check_set.insert(key);
            } else {
                check_set.remove(&key);
            }
        }
        case_semantics(case, &value, &check_set).with_context(|| format!("case {}", case.name))?;
        let start = summary.transaction_observations.len();
        collect(&value, &case.name, "$", &mut summary, &mut nodes, 0)?;
        for tx in &summary.transaction_observations[start..] {
            tx_case
                .entry(tx.tx_hash.clone())
                .or_insert_with(|| case.name.clone());
        }
        fn channels(v: &Value, out: &mut BTreeSet<String>) {
            match v {
                Value::Object(m) => {
                    if let Some(s) = v.get("channel_id").and_then(Value::as_str) {
                        out.insert(s.to_string());
                    }
                    for child in m.values() {
                        channels(child, out);
                    }
                }
                Value::Array(l) => {
                    for child in l {
                        channels(child, out);
                    }
                }
                _ => {}
            }
        }
        let mut channels_set = BTreeSet::new();
        channels(&value, &mut channels_set);
        for channel in channels_set {
            channel_case.insert(channel, case.name.clone());
        }
        summary.cases.push(CaseSummary {
            name: case.name.clone(),
            kind: case.kind.clone(),
            report_path: case.report_path.clone(),
            operator_checks: check_set.into_iter().collect(),
            totals: totals(&summary.transaction_observations[start..])?,
        });
    }
    let deployment: Value =
        read_bounded_json(&safe_path(&root, "deployment.json")?, MAX_JSON_BYTES)?;
    summary.json_files += 1;
    let deployment_start = summary.transaction_observations.len();
    collect(&deployment, "deployment", "$", &mut summary, &mut nodes, 0)?;
    summary.cases.push(CaseSummary {
        name: "deployment".to_string(),
        kind: "deployment".to_string(),
        report_path: "deployment.json".to_string(),
        operator_checks: vec![],
        totals: totals(&summary.transaction_observations[deployment_start..])?,
    });
    let scripts = deployment["scripts"]
        .as_array()
        .context("deployment scripts absent")?;
    let mut seen = BTreeSet::new();
    for (index, script) in scripts.iter().enumerate() {
        let name = string(script, "name").context("deployment script name absent")?;
        ensure!(
            SCRIPTS.contains(&name.as_str()) && seen.insert(name.clone()),
            "unknown/duplicate deployment script"
        );
        let point = &script["out_point"];
        let tx = hash_string(
            point["tx_hash"]
                .as_str()
                .context("deployment outpoint hash absent")?,
        )?;
        let output = number(&point["index"]).context("deployment output index absent")?;
        summary.deployed_scripts.push(DeployedScriptSummary {
            check: "deployment".to_string(),
            path: format!("$.scripts[{index}]"),
            name,
            out_point: format!("{tx}:{output}"),
            data_hash: hash_string(
                script["data_hash"]
                    .as_str()
                    .context("deployment data hash absent")?,
            )?,
            hash_type: string(script, "hash_type").context("deployment hash type absent")?,
            data_len: usize_value(&script["data_len"]).context("deployment data length absent")?,
            capacity: number(&script["capacity"]).context("deployment capacity absent")?,
        });
    }
    ensure!(
        seen.len() == SCRIPTS.len(),
        "incomplete current script deployment"
    );
    let mut files = Vec::new();
    artifact_files(&root, &root, &mut files, 0)?;
    let mut total_bytes = 0u64;
    let mut requests: BTreeMap<String, (String, FactorySigningRequest)> = BTreeMap::new();
    let mut transactions: BTreeMap<String, Vec<(String, packed::Transaction)>> = BTreeMap::new();
    let mut frames = Vec::new();
    for path in files {
        let size = fs::metadata(&path)?.len();
        total_bytes = total_bytes
            .checked_add(size)
            .context("artifact byte counter overflow")?;
        ensure!(
            total_bytes <= MAX_TOTAL_JSON_BYTES,
            "acceptance artifact total byte bound"
        );
        let label = path.strip_prefix(&root)?.display().to_string();
        match path.extension().and_then(|s| s.to_str()) {
            Some("tx") => {
                ensure!(
                    size <= morph_core::FACTORY_MAX_TRANSACTION_BYTES as u64,
                    "transaction artifact bound"
                );
                let tx = packed::Transaction::from_slice(&fs::read(&path)?)
                    .context("noncanonical current transaction artifact")?;
                let id = canonical_hex(tx.calc_tx_hash().as_slice());
                transactions.entry(id).or_default().push((label, tx));
            }
            Some("jsonl") => {
                ensure!(size <= 16 * 1024 * 1024, "diagnostic log bound");
                let raw = fs::read_to_string(&path)?;
                for (i, line) in raw.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let value: Value =
                        serde_json::from_str(line).context("incomplete diagnostic JSONL record")?;
                    let schema = value["schema"].as_str().unwrap_or("");
                    if matches!(
                        schema,
                        "morph.watchtower_alert" | "morph.publication_attempt"
                    ) {
                        let owner = value["channel_id"]
                            .as_str()
                            .and_then(|id| channel_case.get(id))
                            .cloned()
                            .unwrap_or_else(|| "diagnostics".to_string());
                        collect(
                            &value,
                            &owner,
                            &format!("{label}:{}", i + 1),
                            &mut summary,
                            &mut nodes,
                            0,
                        )?;
                    }
                }
            }
            Some("json") => {
                if size > MAX_JSON_BYTES as u64 {
                    continue;
                }
                let value: Value = read_bounded_json(&path, MAX_JSON_BYTES)?;
                schema_current(&value)?;
                match value["schema"].as_str() {
                    Some(crate::factory_packets::REQUEST_SCHEMA) => {
                        let packet: crate::factory_packets::StoredFactoryRequest =
                            serde_json::from_value(value)?;
                        let request = packet.decode_for_delivery_review()?;
                        let id = canonical_hex(&request.transaction_hash()?);
                        if requests
                            .get(&id)
                            .is_none_or(|(_, old)| old.deliveries.len() < request.deliveries.len())
                        {
                            requests.insert(id, (label, request));
                        }
                    }
                    Some(crate::factory_transition_packages::SCHEMA) => {
                        let packet:crate::factory_transition_packages::StoredFactoryTransitionPackage=serde_json::from_value(value)?;
                        frames.push((label, packet.validate()?));
                    }
                    Some("morph.watchtower_health") => {
                        let owner = summary
                            .cases
                            .iter()
                            .find(|case| case.kind == "watch_service")
                            .map(|case| case.name.clone())
                            .unwrap_or_else(|| "diagnostics".to_string());
                        collect(&value, &owner, &label, &mut summary, &mut nodes, 0)?;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    for (id, (path, request)) in requests {
        let Some(case) = tx_case.get(&id) else {
            continue;
        };
        // Drafts and final wallet/Morph signatures share the raw CKB tx hash.
        // A larger draft is not evidence of authorization: reuse Core's exact
        // role/signature verifier to select a complete public transaction.
        let signed = transactions.get(&id).and_then(|variants| {
            variants
                .iter()
                .map(|(_, tx)| tx)
                .find(|tx| request.verify_authorized_transaction(tx).is_ok())
        });
        summary
            .factory_proofs
            .push(proof_from_request(case, &path, &request, signed)?);
    }
    let mut proof_ids = summary
        .factory_proofs
        .iter()
        .map(|proof| proof.tx_hash.clone())
        .collect::<BTreeSet<_>>();
    for (path, view) in frames {
        let id = canonical_hex(view.transaction().calc_tx_hash().as_slice());
        if !proof_ids.insert(id.clone()) {
            continue;
        }
        if let Some(case) = tx_case.get(&id) {
            summary
                .factory_proofs
                .push(proof_from_frame(case, &path, &view)?);
        }
    }
    for (id, variants) in &transactions {
        if proof_ids.contains(id) {
            continue;
        }
        if let Some(case) = tx_case.get(id) {
            for (path, tx) in variants {
                if let Ok(view) = FactoryTransactionView::parse(tx.as_slice()) {
                    summary
                        .factory_proofs
                        .push(proof_from_frame(case, path, &view)?);
                    break;
                }
            }
        }
    }
    summary.transactions = unique_transactions(&summary.transaction_observations)?;
    summary.totals = totals(&summary.transactions)?;
    assert_deployed_script_hashes(&summary, &root.join("contracts"))?;
    Ok(summary)
}
pub fn assert_deployed_script_hashes(
    summary: &DevnetSmokeSummary,
    contracts_dir: &Path,
) -> Result<()> {
    ensure!(
        summary.deployed_scripts.len() == SCRIPTS.len(),
        "current deployment must contain all scripts"
    );
    let mut seen = BTreeSet::new();
    for script in &summary.deployed_scripts {
        ensure!(
            seen.insert(&script.name)
                && SCRIPTS.contains(&script.name.as_str())
                && script.hash_type == "data1",
            "invalid current deployment script identity"
        );
        let path = contracts_dir.join(&script.name);
        let bytes =
            fs::read(&path).with_context(|| format!("missing frozen ELF {}", path.display()))?;
        ensure!(
            bytes.len() == script.data_len
                && canonical_hex(&ckb_hash::blake2b_256(&bytes)) == script.data_hash,
            "deployed script hash/length mismatch for {}",
            script.name
        );
    }
    Ok(())
}
pub fn assert_devnet_smoke_summary(summary: &DevnetSmokeSummary) -> Result<()> {
    ensure!(
        summary.schema == "morph.current_acceptance_summary.v1"
            && summary.matrix.schema == MATRIX_SCHEMA,
        "retired acceptance summary"
    );
    for kind in KINDS {
        ensure!(
            summary.cases.iter().any(|case| case.kind == *kind),
            "missing current matrix kind {kind}"
        );
    }
    ensure!(
        summary.cases.len() == summary.matrix.cases.len() + 1
            && summary
                .cases
                .iter()
                .filter(|case| case.name == "deployment" && case.kind == "deployment")
                .count()
                == 1
            && summary.totals.transaction_count > 0
            && summary.totals.committed_count > 0,
        "empty/incomplete matrix coverage"
    );
    for case in &summary.cases {
        ensure!(
            case.totals.transaction_count > 0 && case.totals.committed_count > 0,
            "case {} has no committed transaction evidence",
            case.name
        );
    }
    let factory_case = summary
        .cases
        .iter()
        .find(|case| case.kind == "factory")
        .context("native Factory case missing")?;
    for operation in [
        "root_funding",
        "ReducedRelease",
        "ReducedDeposit",
        "ReducedChild",
        "materialisation",
    ] {
        ensure!(
            summary
                .factory_proofs
                .iter()
                .any(|proof| proof.check == factory_case.name
                    && proof.operation == operation
                    && proof.authorized),
            "native Factory lacks authorized current {operation} proof evidence"
        );
    }
    let watch = summary
        .cases
        .iter()
        .find(|case| case.kind == "watch_service")
        .context("watch case missing")?;
    ensure!(
        summary
            .watchtower_alerts
            .iter()
            .any(|alert| alert.check == watch.name && alert.event == "chain_reorg_detected"),
        "watch service lacks retained reorg alert"
    );
    ensure!(
        summary
            .watchtower_alerts
            .iter()
            .any(|alert| alert.check == watch.name
                && alert.event == "publication_submitted"
                && alert.selected_funding_anchor.is_some()
                && alert.observed_funding_anchor.is_some()
                && alert.selected_funding_context_id.is_some()
                && alert.observed_funding_context_id.is_some()
                && alert.publication_tx_hash.as_ref().is_some_and(|id| summary
                    .transactions
                    .iter()
                    .any(|tx| tx.check == watch.name
                        && tx.tx_hash == *id
                        && tx.status.as_deref() == Some("Committed")))),
        "watch service lacks exact publication/anchor/context alert evidence"
    );
    ensure!(
        summary
            .watchtower_services
            .iter()
            .any(|service| service.check == watch.name
                && service.schema == "morph.watchtower_config_service"
                && service.completed_passes > 0
                && service.published_count > 0
                && service.error_count == 0
                && service.stopped_reason.as_deref() == Some("publication")),
        "watch service lacks healthy canonically confirmed publication"
    );
    ensure!(
        summary
            .watchtower_services
            .iter()
            .any(|service| service.check == watch.name
                && service.schema == "morph.watchtower_health"
                && service.status.as_deref() == Some("stopped")
                && service.completed_passes > 0
                && service.error_count == 0),
        "watch service lacks terminal health snapshot"
    );
    ensure!(
        summary
            .publication_reconciliations
            .iter()
            .any(|record| record.check == watch.name && record.inspected > 0),
        "watch service lacks durable attempt reconciliation"
    );
    ensure!(
        summary
            .publication_attempts
            .iter()
            .any(|attempt| attempt.check == watch.name),
        "watch service lacks durable publication attempts"
    );
    ensure!(
        summary
            .sponsor_policies
            .iter()
            .any(|policy| policy.check == watch.name
                && policy.min_state_number > 0
                && policy.max_state_number >= policy.min_state_number
                && policy.max_total_fee >= policy.max_fee_per_tx
                && policy.max_fee_per_tx > 0),
        "watch service lacks bounded current sponsor evidence"
    );
    Ok(())
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
    limits: Option<&DevnetSmokeBudgetLimits>,
) -> Result<DevnetSmokeAssertionReport> {
    let summary = summarize_devnet_smoke(dir)?;
    assert_devnet_smoke_summary(&summary)?;
    assert_deployed_script_hashes(&summary, contracts_dir)?;
    let budget = limits
        .filter(|limits| limits.has_any_limit())
        .map(|limits| assert_smoke_budget(&summary, limits))
        .transpose()?;
    Ok(DevnetSmokeAssertionReport {
        directory: summary.directory,
        git_commit: None,
        git_dirty: None,
        case_count: summary.cases.len(),
        transaction_count: summary.totals.transaction_count,
        committed_count: summary.totals.committed_count,
        expected_script_failures: summary.script_failures.len(),
        deployed_scripts: summary.deployed_scripts.len(),
        deployed_script_hashes_verified: true,
        watchtower_alerts: summary.watchtower_alerts.len(),
        watchtower_publication_alerts: summary
            .watchtower_alerts
            .iter()
            .filter(|alert| {
                matches!(
                    alert.event.as_str(),
                    "publication_submitted" | "splice_publication_submitted"
                )
            })
            .count(),
        watchtower_service_records: summary.watchtower_services.len(),
        publication_attempts: summary.publication_attempts.len(),
        factory_proofs: summary.factory_proofs.len(),
        sponsor_policies: summary.sponsor_policies.len(),
        budget,
    })
}
pub fn read_smoke_budget_profile(path: &Path) -> Result<DevnetSmokeBudgetLimits> {
    let profile: BudgetProfile = read_bounded_json(path, 256 * 1024)?;
    ensure!(
        profile.schema == BUDGET_SCHEMA && !profile.basis.trim().is_empty(),
        "unsupported current budget schema or missing measurement basis"
    );
    let limits = DevnetSmokeBudgetLimits {
        max_total_cycles: profile.max_total_cycles,
        max_tx_cycles: profile.max_tx_cycles,
        max_total_bytes: profile.max_total_bytes,
        max_tx_bytes: profile.max_tx_bytes,
        cases: profile.cases,
        transactions: profile.transactions,
        proof_profiles: profile.proof_profiles,
    };
    validate_budget(&limits)?;
    Ok(limits)
}
fn validate_budget(limits: &DevnetSmokeBudgetLimits) -> Result<()> {
    let mut names = BTreeSet::new();
    for case in &limits.cases {
        ensure!(
            names.insert(&case.name)
                && (case.max_cycles.is_some()
                    || case.max_bytes.is_some()
                    || case.max_tx_cycles.is_some()
                    || case.max_tx_bytes.is_some()),
            "duplicate/unbounded case budget"
        );
    }
    let mut transactions = BTreeSet::new();
    for tx in &limits.transactions {
        ensure!(
            transactions.insert((&tx.check, &tx.path))
                && (tx.max_cycles.is_some() || tx.max_bytes.is_some()),
            "duplicate/unbounded named transaction budget"
        );
    }
    let mut proofs = BTreeSet::new();
    for proof in &limits.proof_profiles {
        ensure!(
            proofs.insert((&proof.check, &proof.operation))
                && (proof.max_witness_len.is_some()
                    || proof.max_proof_siblings.is_some()
                    || proof.max_cycles.is_some()
                    || proof.max_bytes.is_some()),
            "duplicate/unbounded current proof budget"
        );
    }
    Ok(())
}
fn cap<T: PartialOrd + std::fmt::Display + Copy>(
    actual: T,
    limit: Option<T>,
    label: &str,
) -> Result<()> {
    if let Some(limit) = limit {
        ensure!(actual <= limit, "{label} {actual} exceeds budget {limit}");
    }
    Ok(())
}
pub fn assert_smoke_budget(
    summary: &DevnetSmokeSummary,
    limits: &DevnetSmokeBudgetLimits,
) -> Result<DevnetSmokeBudgetReport> {
    validate_budget(limits)?;
    let total = &summary.totals;
    cap(
        total.total_estimated_cycles,
        limits.max_total_cycles,
        "total cycles",
    )?;
    cap(
        total.max_estimated_cycles,
        limits.max_tx_cycles,
        "single-transaction cycles",
    )?;
    cap(
        total.total_tx_size_bytes,
        limits.max_total_bytes,
        "total bytes",
    )?;
    cap(
        total.max_tx_size_bytes,
        limits.max_tx_bytes,
        "single-transaction bytes",
    )?;
    let mut cases = Vec::new();
    for limit in &limits.cases {
        let case = summary
            .cases
            .iter()
            .find(|case| case.name == limit.name)
            .with_context(|| format!("missing budget case {}", limit.name))?;
        cap(
            case.totals.total_estimated_cycles,
            limit.max_cycles,
            "case cycles",
        )?;
        cap(
            case.totals.total_tx_size_bytes,
            limit.max_bytes,
            "case bytes",
        )?;
        cap(
            case.totals.max_estimated_cycles,
            limit.max_tx_cycles,
            "case single-transaction cycles",
        )?;
        cap(
            case.totals.max_tx_size_bytes,
            limit.max_tx_bytes,
            "case single-transaction bytes",
        )?;
        cases.push(DevnetSmokeCaseBudgetReport {
            name: case.name.clone(),
            total_estimated_cycles: case.totals.total_estimated_cycles,
            total_tx_size_bytes: case.totals.total_tx_size_bytes,
            max_estimated_cycles: case.totals.max_estimated_cycles,
            max_tx_size_bytes: case.totals.max_tx_size_bytes,
        });
    }
    let mut transactions = Vec::new();
    for limit in &limits.transactions {
        let tx = summary
            .transaction_observations
            .iter()
            .find(|tx| tx.check == limit.check && tx.path == limit.path)
            .with_context(|| {
                format!(
                    "missing named transaction budget {} {}",
                    limit.check, limit.path
                )
            })?;
        cap(
            tx.estimated_cycles,
            limit.max_cycles,
            "named transaction cycles",
        )?;
        cap(tx.tx_size_bytes, limit.max_bytes, "named transaction bytes")?;
        transactions.push(DevnetSmokeTransactionBudgetReport {
            check: tx.check.clone(),
            path: tx.path.clone(),
            estimated_cycles: tx.estimated_cycles,
            tx_size_bytes: tx.tx_size_bytes,
            max_cycles: limit.max_cycles,
            max_bytes: limit.max_bytes,
        });
    }
    let mut proofs = Vec::new();
    for limit in &limits.proof_profiles {
        let selected = summary
            .factory_proofs
            .iter()
            .filter(|proof| proof.check == limit.check && proof.operation == limit.operation)
            .collect::<Vec<_>>();
        ensure!(
            !selected.is_empty(),
            "missing current proof budget {} {}",
            limit.check,
            limit.operation
        );
        let mut siblings = 0;
        let mut witness = 0;
        let mut cycles = 0;
        let mut size = 0;
        for proof in selected {
            siblings = siblings.max(proof.proof_siblings);
            witness = witness.max(proof.witness_len);
            size = size.max(proof.transaction_bytes);
            let tx = summary
                .transactions
                .iter()
                .find(|tx| tx.tx_hash == proof.tx_hash)
                .context("current proof lacks transaction resource evidence")?;
            cycles = cycles.max(tx.estimated_cycles);
            size = size.max(tx.tx_size_bytes);
        }
        cap(siblings, limit.max_proof_siblings, "compact proof siblings")?;
        cap(witness, limit.max_witness_len, "current witness bytes")?;
        cap(cycles, limit.max_cycles, "current proof transaction cycles")?;
        cap(size, limit.max_bytes, "current proof transaction bytes")?;
        proofs.push(DevnetSmokeProofProfileBudgetReport {
            check: limit.check.clone(),
            operation: limit.operation.clone(),
            proof_siblings: siblings,
            witness_len: witness,
            estimated_cycles: cycles,
            tx_size_bytes: size,
        });
    }
    Ok(DevnetSmokeBudgetReport {
        total_estimated_cycles: total.total_estimated_cycles,
        max_estimated_cycles: total.max_estimated_cycles,
        total_tx_size_bytes: total.total_tx_size_bytes,
        max_tx_size_bytes: total.max_tx_size_bytes,
        cases,
        transactions,
        proof_profiles: proofs,
    })
}
pub fn compare_devnet_smoke(baseline: &Path, candidate: &Path) -> Result<DevnetSmokeComparison> {
    Ok(compare_summaries(
        &summarize_devnet_smoke(baseline)?,
        &summarize_devnet_smoke(candidate)?,
    ))
}
pub fn compare_summaries(
    baseline: &DevnetSmokeSummary,
    candidate: &DevnetSmokeSummary,
) -> DevnetSmokeComparison {
    let key = |tx: &TransactionSummary| format!("{} {}", tx.check, tx.path);
    let before = baseline
        .transactions
        .iter()
        .map(|tx| (key(tx), tx))
        .collect::<BTreeMap<_, _>>();
    let after = candidate
        .transactions
        .iter()
        .map(|tx| (key(tx), tx))
        .collect::<BTreeMap<_, _>>();
    let missing = before
        .keys()
        .filter(|k| !after.contains_key(*k))
        .cloned()
        .collect();
    let added = after
        .keys()
        .filter(|k| !before.contains_key(*k))
        .cloned()
        .collect();
    let mut deltas = Vec::new();
    for (k, a) in &before {
        if let Some(b) = after.get(k) {
            deltas.push(TransactionMetricDelta {
                key: k.clone(),
                baseline_status: a.status.clone(),
                candidate_status: b.status.clone(),
                baseline_estimated_cycles: a.estimated_cycles,
                candidate_estimated_cycles: b.estimated_cycles,
                estimated_cycles_delta: i128::from(b.estimated_cycles)
                    - i128::from(a.estimated_cycles),
                baseline_tx_size_bytes: a.tx_size_bytes,
                candidate_tx_size_bytes: b.tx_size_bytes,
                tx_size_bytes_delta: b.tx_size_bytes as i128 - a.tx_size_bytes as i128,
            });
        }
    }
    DevnetSmokeComparison {
        baseline_directory: baseline.directory.clone(),
        candidate_directory: candidate.directory.clone(),
        compared_transactions: deltas.len(),
        missing_from_candidate: missing,
        added_in_candidate: added,
        total_estimated_cycles_delta: i128::from(candidate.totals.total_estimated_cycles)
            - i128::from(baseline.totals.total_estimated_cycles),
        total_tx_size_bytes_delta: candidate.totals.total_tx_size_bytes as i128
            - baseline.totals.total_tx_size_bytes as i128,
        transaction_deltas: deltas,
    }
}
pub fn assert_comparison_limits(
    comparison: &DevnetSmokeComparison,
    limits: &DevnetSmokeComparisonLimits,
) -> Result<()> {
    if limits.fail_on_transaction_set_change {
        ensure!(
            comparison.missing_from_candidate.is_empty()
                && comparison.added_in_candidate.is_empty(),
            "current transaction set changed"
        );
    }
    if limits.fail_on_status_change {
        ensure!(
            comparison
                .transaction_deltas
                .iter()
                .all(|tx| tx.baseline_status == tx.candidate_status),
            "transaction status changed"
        );
    }
    cap(
        comparison.total_estimated_cycles_delta.unsigned_abs(),
        limits.max_abs_total_cycle_delta.map(u128::from),
        "absolute total cycle delta",
    )?;
    cap(
        comparison.total_tx_size_bytes_delta.unsigned_abs(),
        limits.max_abs_total_byte_delta.map(u128::from),
        "absolute total byte delta",
    )?;
    for tx in &comparison.transaction_deltas {
        cap(
            tx.estimated_cycles_delta.unsigned_abs(),
            limits.max_abs_tx_cycle_delta.map(u128::from),
            "absolute transaction cycle delta",
        )?;
        cap(
            tx.tx_size_bytes_delta.unsigned_abs(),
            limits.max_abs_tx_byte_delta.map(u128::from),
            "absolute transaction byte delta",
        )?;
    }
    Ok(())
}
pub fn render_markdown(summary: &DevnetSmokeSummary) -> String {
    let mut out = format!(
        "# Current acceptance evidence\n\nOffline controlled-devnet evidence; no chain or signer authority.\n\n{} unique transactions, {} committed, {} cycles, {} bytes.\n\n| Case | Kind | Transactions | Cycles | Bytes |\n| --- | --- | ---: | ---: | ---: |\n",
        summary.totals.transaction_count,
        summary.totals.committed_count,
        summary.totals.total_estimated_cycles,
        summary.totals.total_tx_size_bytes
    );
    for case in &summary.cases {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            case.name,
            case.kind,
            case.totals.transaction_count,
            case.totals.total_estimated_cycles,
            case.totals.total_tx_size_bytes
        ));
    }
    out.push_str("\n| Case | Preserved operator checks |\n| --- | --- |\n");
    for case in &summary.cases {
        out.push_str(&format!(
            "| {} | {} |\n",
            cell(&case.name),
            cell(&case.operator_checks.join(", "))
        ));
    }
    out.push_str("\nAll status observations are retained below; totals count each raw transaction hash once.\n\n| Case | Report path | Status | Cycles | Bytes | Transaction |\n| --- | --- | --- | ---: | ---: | --- |\n");
    for tx in &summary.transaction_observations {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            cell(&tx.check),
            cell(&tx.path),
            cell(tx.status.as_deref().unwrap_or("unreported")),
            tx.estimated_cycles,
            tx.tx_size_bytes,
            tx.tx_hash
        ));
    }
    out.push_str("\n| Factory operation | Members | Signatures | Changed rights | Compact siblings | Witness bytes | Authorized |\n| --- | ---: | ---: | ---: | ---: | ---: | --- |\n");
    for p in &summary.factory_proofs {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            p.operation,
            p.member_count,
            p.signature_count,
            p.right_count,
            p.proof_siblings,
            p.witness_len,
            p.authorized
        ));
    }
    out.push_str(
        "\n| Frozen script | Deployed OutPoint | Bytes | Data hash |\n| --- | --- | ---: | --- |\n",
    );
    for script in &summary.deployed_scripts {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            script.name, script.out_point, script.data_len, script.data_hash
        ));
    }
    out.push_str("\n| Watch case | Event | Severity | Selected / observed state | Publication | Funding context |\n| --- | --- | --- | --- | --- | --- |\n");
    for alert in &summary.watchtower_alerts {
        out.push_str(&format!(
            "| {} | {} | {} | {} / {} | {} | {} |\n",
            cell(&alert.check),
            cell(&alert.event),
            cell(&alert.severity),
            alert.selected_state_number,
            alert
                .observed_state_number
                .map_or_else(|| "none".to_string(), |n| n.to_string()),
            cell(alert.publication_tx_hash.as_deref().unwrap_or("none")),
            cell(
                alert
                    .selected_funding_context_id
                    .as_deref()
                    .unwrap_or("none")
            )
        ));
    }
    out.push_str("\n| Service / health | Status / stop | Passes | Published | Idle | Errors / consecutive |\n| --- | --- | ---: | ---: | ---: | --- |\n");
    for service in &summary.watchtower_services {
        out.push_str(&format!(
            "| {} {} | {} / {} | {} | {} | {} | {} / {} |\n",
            cell(&service.check),
            cell(&service.path),
            cell(service.status.as_deref().unwrap_or("none")),
            cell(service.stopped_reason.as_deref().unwrap_or("none")),
            service.completed_passes,
            service.published_count,
            service.idle_count,
            service.error_count,
            service.consecutive_errors
        ));
    }
    out.push_str("\n| Publication case | Attempt | Status | Fee | Intent | Transaction |\n| --- | ---: | --- | ---: | --- | --- |\n");
    for attempt in &summary.publication_attempts {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            cell(&attempt.check),
            attempt.attempt,
            cell(&attempt.status),
            attempt.fee,
            cell(&attempt.intent_id),
            cell(&attempt.tx_hash)
        ));
    }
    out.push_str("\n| Reconciliation case | Inspected | Confirmed | Committed | Pending / proposed | Rejected / unknown |\n| --- | ---: | ---: | ---: | --- | --- |\n");
    for result in &summary.publication_reconciliations {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} / {} | {} / {} |\n",
            cell(&result.check),
            result.inspected,
            result.confirmed,
            result.committed,
            result.pending,
            result.proposed,
            result.rejected,
            result.unknown
        ));
    }
    out.push_str("\n| Sponsor case | State range | Span | Per-TX fee cap | Cell total fee cap |\n| --- | --- | ---: | ---: | ---: |\n");
    for policy in &summary.sponsor_policies {
        out.push_str(&format!(
            "| {} | {}–{} | {} | {} | {} |\n",
            cell(&policy.check),
            policy.min_state_number,
            policy.max_state_number,
            policy.state_number_span,
            policy.max_fee_per_tx,
            policy.max_total_fee
        ));
    }
    out.push_str("\n| Script failure case | Path | Source | Code | Current error |\n| --- | --- | --- | --- | --- |\n");
    for failure in &summary.script_failures {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            cell(&failure.check),
            cell(&failure.path),
            cell(failure.source.as_deref().unwrap_or("unreported")),
            failure
                .error_code
                .map_or_else(|| "none".to_string(), |n| n.to_string()),
            cell(failure.morph_error.as_deref().unwrap_or("unreported"))
        ));
    }
    out
}
fn cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}
pub fn render_comparison_markdown(comparison: &DevnetSmokeComparison) -> String {
    let mut out = format!(
        "# Current acceptance comparison\n\nCompared {} transactions. Cycle delta: {}. Byte delta: {}. Added: {}. Missing: {}.\n",
        comparison.compared_transactions,
        comparison.total_estimated_cycles_delta,
        comparison.total_tx_size_bytes_delta,
        comparison.added_in_candidate.len(),
        comparison.missing_from_candidate.len()
    );
    out.push_str("\n| Transaction observation | Previous status | Current status | Previous cycles | Current cycles | Cycle delta | Previous bytes | Current bytes | Byte delta |\n| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for tx in &comparison.transaction_deltas {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            cell(&tx.key),
            cell(tx.baseline_status.as_deref().unwrap_or("unreported")),
            cell(tx.candidate_status.as_deref().unwrap_or("unreported")),
            tx.baseline_estimated_cycles,
            tx.candidate_estimated_cycles,
            tx.estimated_cycles_delta,
            tx.baseline_tx_size_bytes,
            tx.candidate_tx_size_bytes,
            tx.tx_size_bytes_delta
        ));
    }
    for (label, observations) in [
        ("Missing", &comparison.missing_from_candidate),
        ("Added", &comparison.added_in_candidate),
    ] {
        for observation in observations {
            out.push_str(&format!("\n- {label}: {}\n", cell(observation)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_packets::{FactorySignatureReceipt, StoredFactoryRequest};
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Run(PathBuf);
    impl Run {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "morph-current-report-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(path.join("contracts")).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, value: &Value) {
            fs::write(self.0.join(name), serde_json::to_vec(value).unwrap()).unwrap();
        }
        fn read(&self, name: &str) -> Value {
            serde_json::from_slice(&fs::read(self.0.join(name)).unwrap()).unwrap()
        }
    }
    impl Drop for Run {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tx(seed: u8, cycles: u64, bytes: usize) -> Value {
        json!({"tx_hash":canonical_hex(&[seed;32]),"status":"Committed","block_number":"1",
            "metrics":{"estimated_cycles":cycles,"tx_size_bytes":bytes}})
    }
    fn bilateral(seed: u8) -> Value {
        json!({"schema":"morph.multi_asset_devnet_acceptance.v1","asset_count":8,"shared_funding":true,
            "fund":tx(seed,10,100),"activation":tx(seed+1,20,200),"finalise":tx(seed+2,30,300)})
    }
    fn factory_checks() -> Vec<&'static str> {
        vec![
            "wrong_key_preserves_journal",
            "partial_export_cannot_poison_path",
            "same_path_handoff",
            "withheld_full_consent_escaped",
            "previous_approval_not_revoked",
            "peer_refreshed_from_public_changes",
            "initial_exit_required_before_parent_vote",
            "private_exit_signatures_absent_from_parent",
            "retired",
        ]
    }
    fn watch_checks() -> Vec<&'static str> {
        vec![
            "watch_kept_active_channel_open",
            "watch_rejected_conflicting_signed_states",
            "watch_rejected_late_scan_origin",
            "watch_rejected_same_number_on_chain_conflict",
            "current_watch_service_auto_sponsor_published",
            "current_watch_service_health_verified",
            "watch_published_late_recovery_package",
            "watch_reorg_rescan_republished",
        ]
    }
    /// Report-only synthetic measurements. These bytes deliberately make no
    /// claim of a CKB deployment; proof tests below use real current encoders.
    fn matrix_fixture() -> Run {
        let run = Run::new();
        run.write(
            "matrix.json",
            &json!({"schema":MATRIX_SCHEMA,"cases":[
            {"name":"shared","kind":"bilateral_shared","report_path":"shared.json"},
            {"name":"maximum","kind":"bilateral_max_assets","report_path":"maximum.json"},
            {"name":"splice","kind":"splice","report_path":"splice.json"},
            {"name":"factory","kind":"factory","report_path":"factory.json"},
            {"name":"watch","kind":"watch_service","report_path":"watch.json"}]}),
        );
        run.write("shared.json", &bilateral(1));
        run.write("maximum.json", &bilateral(4));
        run.write("splice.json", &json!({"schema":"morph.current_splice_devnet_acceptance.v1",
            "fund":tx(7,10,100),"activation":tx(8,20,200),"transitions":{
                "operations":[{"operation":"remove","submission":tx(9,30,300),"activation":tx(10,40,400),"withheld_bridge_receipt_reconciled":true},
                    {"operation":"admit","submission":tx(11,50,500),"activation":tx(12,60,600),"withheld_bridge_receipt_reconciled":true}],
                "terminal":[tx(13,70,700),tx(14,80,800)]}}));
        run.write("factory.json", &json!({"schema":"morph.current_factory_acceptance.v1",
            "operator_checks":factory_checks(),"canonical_replay":{"canonical_replay":true},
            "root":{"report":tx(15,10,100)},"activation":{"report":tx(16,20,200)},
            "transitions":{"escape":{"report":tx(17,30,300)},"deposit":{"report":tx(18,40,400)},
                "child":{"reduced":{"parent":{"report":tx(19,50,500)},"activation":tx(20,60,600),"finalise":tx(21,70,700)},
                    "terminal":{"parent":{"report":tx(22,80,800)},"activation":tx(23,90,900),"finalise":tx(24,100,1000)}}}}));
        let mut watched = bilateral(25);
        watched["operator_checks"] = json!(watch_checks());
        watched["sponsor_policy"] = json!({"min_state_number":"2","max_state_number":"2","max_fee_per_tx":"1000","max_total_fee":"2000"});
        watched["publication_reconciliation"] = json!({"inspected":1,"confirmed":0,"committed":0,"rejected":0,"pending":0,"proposed":0,"unknown":1});
        watched["service"] = json!({"schema":"morph.watchtower_config_service","completed_passes":1,"published_count":1,"idle_count":0,"error_count":0,"consecutive_errors":0,"stopped_reason":"publication"});
        run.write("watch.json", &watched);
        run.write("health.json", &json!({"schema":"morph.watchtower_health","status":"stopped","completed_passes":1,"published_count":1,"idle_count":0,"error_count":0,"consecutive_errors":0}));
        let scripts = SCRIPTS.iter().enumerate().map(|(index,name)| {
            let bytes = format!("synthetic current report fixture {name}").into_bytes();
            fs::write(run.0.join("contracts").join(name), &bytes).unwrap();
            json!({"name":name,"out_point":{"tx_hash":canonical_hex(&[31;32]),"index":index},
                "data_hash":canonical_hex(&ckb_hash::blake2b_256(&bytes)),"hash_type":"data1","data_len":bytes.len(),"capacity":"10000000000"})
        }).collect::<Vec<_>>();
        run.write(
            "deployment.json",
            &json!({"scripts":scripts,"transactions":[tx(31,10,100)]}),
        );
        run
    }
    fn root_request() -> (FactorySigningRequest, packed::Transaction) {
        let corpus = crate::factory_packets::sdk_packet_fixture();
        let case = &corpus["cases"][0];
        let packet: StoredFactoryRequest = serde_json::from_value(case["request"].clone()).unwrap();
        let request = packet.decode().unwrap();
        let signatures = case["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let receipt: FactorySignatureReceipt =
                    serde_json::from_value(entry.clone()).unwrap();
                receipt.verify(&request).unwrap()
            })
            .collect::<Vec<_>>();
        let transaction = crate::factory_session::authorized_transaction(
            &request,
            request.authorized_witness(&signatures).unwrap(),
        )
        .unwrap();
        (request, transaction)
    }
    #[test]
    fn current_matrix_counts_unique_transactions_and_preserves_observations() {
        let run = matrix_fixture();
        let mut report = run.read("shared.json");
        report["aa_pending_observation"] = report["fund"].clone();
        report["aa_pending_observation"]["status"] = json!("Pending");
        run.write("shared.json", &report);
        let summary = summarize_devnet_smoke(&run.0).unwrap();
        assert_eq!(summary.cases.len(), 6);
        assert_eq!(summary.totals.transaction_count, 28);
        assert_eq!(summary.transaction_observations.len(), 29);
        assert_eq!(summary.totals.committed_count, 28);
        assert_eq!(summary.cases[0].totals.transaction_count, 3);
        assert_eq!(summary.cases[0].totals.committed_count, 3);
        assert_eq!(summary.sponsor_policies[0].state_number_span, 0);
        assert_eq!(summary.publication_reconciliations[0].unknown, 1);
        assert_eq!(summary.watchtower_services.len(), 2);
        assert!(render_markdown(&summary).contains("Offline controlled-devnet"));
        assert!(
            assert_devnet_smoke_summary(&summary)
                .unwrap_err()
                .to_string()
                .contains("authorized current")
        );
        report["aa_pending_observation"]["metrics"]["estimated_cycles"] = json!(11);
        run.write("shared.json", &report);
        assert!(
            summarize_devnet_smoke(&run.0)
                .unwrap_err()
                .to_string()
                .contains("conflicting resource")
        );
    }
    #[test]
    fn current_matrix_excludes_only_reserved_derived_outputs_on_repeat_ingestion() {
        let run = matrix_fixture();
        fs::write(run.0.join("summary.json"), []).unwrap();
        fs::write(run.0.join("summary-check.json"), []).unwrap();
        let first = summarize_devnet_smoke(&run.0).unwrap();
        run.write("summary.json", &serde_json::to_value(&first).unwrap());
        run.write("summary-check.json", &json!({"derived":true}));
        let second = summarize_devnet_smoke(&run.0).unwrap();
        assert_eq!(
            first.totals.transaction_count,
            second.totals.transaction_count
        );
        assert_eq!(
            first.transaction_observations.len(),
            second.transaction_observations.len()
        );
        assert_eq!(
            first.watchtower_services.len(),
            second.watchtower_services.len()
        );
        assert_eq!(first.sponsor_policies.len(), second.sponsor_policies.len());
        // A source report explicitly referenced by the matrix is never hidden.
        let mut matrix = run.read("matrix.json");
        matrix["cases"][0]["report_path"] = json!("summary.json");
        run.write("matrix.json", &matrix);
        assert!(summarize_devnet_smoke(&run.0).is_err());
        fs::create_dir(run.0.join("nested")).unwrap();
        fs::write(run.0.join("nested/summary.json"), []).unwrap();
        matrix["cases"][0]["report_path"] = json!("shared.json");
        run.write("matrix.json", &matrix);
        assert!(summarize_devnet_smoke(&run.0).is_err());
    }
    #[test]
    fn current_matrix_rejects_missing_lifecycle_checks_unknown_and_retired_schema() {
        let run = matrix_fixture();
        for (file, pointer, changed) in [
            ("maximum.json", "/asset_count", json!(7)),
            ("maximum.json", "/shared_funding", json!(false)),
            (
                "splice.json",
                "/transitions/operations/1/operation",
                json!("remove"),
            ),
            (
                "factory.json",
                "/transitions/deposit/report/status",
                json!("Pending"),
            ),
            ("watch.json", "/operator_checks", json!([])),
        ] {
            let original = run.read(file);
            let mut broken = original.clone();
            *broken.pointer_mut(pointer).unwrap() = changed;
            run.write(file, &broken);
            assert!(summarize_devnet_smoke(&run.0).is_err(), "{file} {pointer}");
            run.write(file, &original);
        }
        let original = run.read("matrix.json");
        let mut matrix = original.clone();
        matrix["old_checks"] = json!([]);
        run.write("matrix.json", &matrix);
        assert!(summarize_devnet_smoke(&run.0).is_err());
        matrix = original.clone();
        matrix["schema"] = json!("morph.devnet_smoke_matrix");
        run.write("matrix.json", &matrix);
        assert!(summarize_devnet_smoke(&run.0).is_err());
        run.write("matrix.json", &original);
        run.write(
            "retired.json",
            &json!({"schema":"morph.factory_multi_asset_materialisation.v1"}),
        );
        assert!(
            summarize_devnet_smoke(&run.0)
                .unwrap_err()
                .to_string()
                .contains("retired wire")
        );
    }
    #[test]
    fn current_matrix_rejects_path_escape_and_changed_frozen_deployment() {
        let run = matrix_fixture();
        let other = matrix_fixture();
        let original = run.read("matrix.json");
        let mut matrix = original.clone();
        matrix["cases"][0]["report_path"] = json!(other.0.join("shared.json"));
        run.write("matrix.json", &matrix);
        assert!(
            summarize_devnet_smoke(&run.0)
                .unwrap_err()
                .to_string()
                .contains("escapes")
        );
        run.write("matrix.json", &original);
        fs::write(run.0.join("contracts").join(SCRIPTS[0]), b"changed").unwrap();
        assert!(
            summarize_devnet_smoke(&run.0)
                .unwrap_err()
                .to_string()
                .contains("hash/length mismatch")
        );
    }
    #[test]
    fn current_proof_metrics_delegate_to_real_request_and_frame_validation() {
        let (request, transaction) = root_request();
        let unsigned = proof_from_request("factory", "root.json", &request, None).unwrap();
        assert!(!unsigned.authorized);
        assert_eq!(unsigned.signature_count, 0);
        let signed =
            proof_from_request("factory", "root.json", &request, Some(&transaction)).unwrap();
        assert!(signed.authorized);
        assert_eq!(signed.operation, "root_funding");
        assert_eq!(
            signed.signature_count,
            request.required_members().unwrap().len()
        );
        let first =
            packed::WitnessArgs::from_slice(&transaction.witnesses().get(0).unwrap().raw_data())
                .unwrap();
        let mut frame = first.input_type().to_opt().unwrap().raw_data().to_vec();
        let last = frame.len() - 1;
        frame[last] ^= 1;
        let altered = first
            .as_builder()
            .input_type(Some(ckb_types::bytes::Bytes::from(frame)).pack())
            .build();
        let mut witnesses = transaction.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[0] = altered.as_bytes().pack();
        let damaged = transaction.as_builder().witnesses(witnesses.pack()).build();
        assert!(proof_from_request("factory", "root.json", &request, Some(&damaged)).is_err());
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/factory-transitions.json"
        ))
        .unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            let packet: crate::factory_transition_packages::StoredFactoryTransitionPackage =
                serde_json::from_value(case["package"].clone()).unwrap();
            let view = packet.validate().unwrap();
            let metrics = proof_from_frame("factory", "frame.json", &view).unwrap();
            assert_eq!(metrics.operation, case["operation"]);
            assert!(metrics.authorized && metrics.signature_count > 0 && metrics.witness_len > 0);
            assert!(
                metrics.proof_siblings
                    <= factory::FACTORY_TRANSITION_MAX_RIGHTS
                        * 2
                        * morph_script_common::FACTORY_COMPACT_PROOF_MAX_SIBLINGS
            );
        }
    }
    #[test]
    fn current_matrix_joins_exact_signed_request_and_recorded_transaction() {
        let run = matrix_fixture();
        let (request, transaction) = root_request();
        let packet = StoredFactoryRequest::from_core(&request).unwrap();
        run.write("root-request.json", &serde_json::to_value(packet).unwrap());
        fs::write(run.0.join("root.tx"), transaction.as_slice()).unwrap();
        let first =
            packed::WitnessArgs::from_slice(&transaction.witnesses().get(0).unwrap().raw_data())
                .unwrap();
        let draft = first
            .as_builder()
            .input_type(Some(ckb_types::bytes::Bytes::from(request.witness.clone())).pack())
            .build();
        let mut witnesses = transaction.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[0] = draft.as_bytes().pack();
        let unsigned = transaction
            .clone()
            .as_builder()
            .witnesses(witnesses.pack())
            .build();
        fs::write(run.0.join("aaa-root-draft.tx"), unsigned.as_slice()).unwrap();
        let mut report = run.read("factory.json");
        report["root"]["report"]["tx_hash"] =
            json!(canonical_hex(&request.transaction_hash().unwrap()));
        run.write("factory.json", &report);
        let summary = summarize_devnet_smoke(&run.0).unwrap();
        assert_eq!(summary.factory_proofs.len(), 1);
        assert!(summary.factory_proofs[0].authorized);
        assert_eq!(
            summary.factory_proofs[0].transaction_bytes,
            transaction.as_slice().len()
        );
    }
    #[test]
    fn current_budget_enforces_each_scope_and_fails_missing_evidence() {
        let run = matrix_fixture();
        let mut summary = summarize_devnet_smoke(&run.0).unwrap();
        let (request, transaction) = root_request();
        let mut proof =
            proof_from_request("factory", "root.json", &request, Some(&transaction)).unwrap();
        // Scope test associates real proof metrics with one synthetic node measurement.
        proof.tx_hash = summary.transactions[0].tx_hash.clone();
        summary.factory_proofs.push(proof.clone());
        let limits = DevnetSmokeBudgetLimits {
            max_total_cycles: Some(summary.totals.total_estimated_cycles),
            max_tx_cycles: Some(summary.totals.max_estimated_cycles),
            max_total_bytes: Some(summary.totals.total_tx_size_bytes),
            max_tx_bytes: Some(summary.totals.max_tx_size_bytes),
            cases: vec![DevnetSmokeCaseBudgetLimit {
                name: "factory".into(),
                max_cycles: Some(summary.cases[3].totals.total_estimated_cycles),
                max_bytes: None,
                max_tx_cycles: Some(100),
                max_tx_bytes: Some(1_000),
            }],
            transactions: vec![DevnetSmokeTransactionBudgetLimit {
                check: "shared".into(),
                path: "$.fund".into(),
                max_cycles: Some(10),
                max_bytes: Some(100),
            }],
            proof_profiles: vec![DevnetSmokeProofProfileBudgetLimit {
                check: "factory".into(),
                operation: "root_funding".into(),
                max_witness_len: Some(proof.witness_len),
                max_proof_siblings: Some(0),
                max_cycles: Some(100),
                max_bytes: Some(proof.transaction_bytes),
            }],
        };
        assert_smoke_budget(&summary, &limits).unwrap();
        let mut fail = limits.clone();
        fail.max_total_cycles = Some(1);
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.max_tx_bytes = Some(1);
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.cases[0].max_cycles = Some(1);
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.transactions[0].max_cycles = Some(9);
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.proof_profiles[0].max_witness_len = Some(proof.witness_len - 1);
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.proof_profiles[0].operation = "missing".into();
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.transactions[0].path = "$.missing".into();
        assert!(assert_smoke_budget(&summary, &fail).is_err());
        fail = limits.clone();
        fail.cases.push(fail.cases[0].clone());
        assert!(assert_smoke_budget(&summary, &fail).is_err());
    }
    #[test]
    fn current_budget_keeps_native_transaction_caps_below_deployment_allowance() {
        let run = matrix_fixture();
        let mut report = run.read("factory.json");
        report["root"]["report"]["metrics"]["tx_size_bytes"] = json!(100_001);
        run.write("factory.json", &report);
        let summary = summarize_devnet_smoke(&run.0).unwrap();
        let native = summary
            .cases
            .iter()
            .find(|case| case.name == "factory")
            .unwrap();
        assert!(native.totals.total_tx_size_bytes < 300_000);
        let mut limits = DevnetSmokeBudgetLimits {
            max_total_bytes: Some(2_000_000),
            max_tx_bytes: Some(300_000),
            cases: vec![DevnetSmokeCaseBudgetLimit {
                name: "factory".to_string(),
                max_cycles: None,
                max_bytes: Some(300_000),
                max_tx_cycles: Some(40_000_000),
                max_tx_bytes: Some(100_000),
            }],
            ..Default::default()
        };
        let error = assert_smoke_budget(&summary, &limits)
            .unwrap_err()
            .to_string();
        assert!(error.contains("case single-transaction bytes 100001"));
        limits.cases[0].max_tx_bytes = Some(100_001);
        assert_smoke_budget(&summary, &limits).unwrap();
        // These protections are explicit nullable fields in the sole current
        // profile: an earlier shape cannot silently omit them.
        let mut encoded = serde_json::to_value(&limits.cases[0]).unwrap();
        encoded.as_object_mut().unwrap().remove("max_tx_bytes");
        assert!(serde_json::from_value::<DevnetSmokeCaseBudgetLimit>(encoded).is_err());
        let encoded = json!({"name":"explicitly_unbounded","max_cycles":null,"max_bytes":1,"max_tx_cycles":null,"max_tx_bytes":null});
        serde_json::from_value::<DevnetSmokeCaseBudgetLimit>(encoded).unwrap();
    }
    #[test]
    fn current_budget_profile_rejects_old_fields_and_requires_basis() {
        let run = Run::new();
        let profile = json!({"schema":BUDGET_SCHEMA,"basis":"Synthetic parser coverage; not a measured release budget.",
            "max_total_cycles":1,"max_tx_cycles":1,"max_total_bytes":1,"max_tx_bytes":1,"cases":[],"transactions":[],"proof_profiles":[]});
        run.write("budget.json", &profile);
        read_smoke_budget_profile(&run.0.join("budget.json")).unwrap();
        let mut broken = profile.clone();
        broken["description"] = json!("retired");
        run.write("budget.json", &broken);
        assert!(read_smoke_budget_profile(&run.0.join("budget.json")).is_err());
        let example = read_smoke_budget_profile(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/devnet-smoke-budget.example.json"),
        )
        .unwrap();
        assert_eq!(example.cases.len(), KINDS.len() + 1);
        assert_eq!(
            example
                .proof_profiles
                .iter()
                .map(|profile| profile.operation.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "root_funding",
                "ReducedRelease",
                "ReducedDeposit",
                "ReducedChild",
                "materialisation"
            ])
        );
        broken = profile.clone();
        broken["schema"] = json!("morph.devnet_smoke_budget");
        run.write("budget.json", &broken);
        assert!(read_smoke_budget_profile(&run.0.join("budget.json")).is_err());
        broken = profile;
        broken["basis"] = json!("");
        run.write("budget.json", &broken);
        assert!(read_smoke_budget_profile(&run.0.join("budget.json")).is_err());
    }
    #[test]
    fn current_comparison_preserves_status_set_and_checked_numeric_limits() {
        let run = matrix_fixture();
        let before = summarize_devnet_smoke(&run.0).unwrap();
        let mut after = before.clone();
        after.transactions[0].estimated_cycles += 1;
        after.transactions[0].status = Some("Pending".into());
        after.totals = totals(&after.transactions).unwrap();
        let comparison = compare_summaries(&before, &after);
        assert_eq!(comparison.total_estimated_cycles_delta, 1);
        assert!(
            assert_comparison_limits(
                &comparison,
                &DevnetSmokeComparisonLimits {
                    fail_on_status_change: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(
            assert_comparison_limits(
                &comparison,
                &DevnetSmokeComparisonLimits {
                    max_abs_tx_cycle_delta: Some(0),
                    ..Default::default()
                }
            )
            .is_err()
        );
        after.transactions.remove(0);
        after.totals = totals(&after.transactions).unwrap();
        assert!(
            assert_comparison_limits(
                &compare_summaries(&before, &after),
                &DevnetSmokeComparisonLimits {
                    fail_on_transaction_set_change: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
        let mut overflow = before.transactions[..2].to_vec();
        overflow[0].estimated_cycles = u64::MAX;
        assert!(totals(&overflow).is_err());
    }
}
