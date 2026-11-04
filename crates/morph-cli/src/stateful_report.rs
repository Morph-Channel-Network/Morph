use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::smoke_report::{
    self, DevnetSmokeAssertionReport, DevnetSmokeBudgetLimits, DevnetSmokeSummary,
};

const MAX_SPONSOR_STATE_NUMBER_SPAN: u64 = crate::devnet::DEFAULT_SPONSOR_MAX_STATE_NUMBER
    - crate::devnet::DEFAULT_SPONSOR_MIN_STATE_NUMBER;
const DEVNET_STATEFUL_SCENARIO_SCHEMA: &str = "morph.current_stateful_scenario.v1";
const DEVNET_AUDIT_PROFILE_SCHEMA: &str = "morph.current_stateful_audit.v1";
const MAX_SCENARIO_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;

const REQUIRED_SCENARIOS: &[&str] = &[
    "root_funding",
    "bilateral_splice",
    "bilateral_unilateral_close",
    "factory_reduced_escape",
    "factory_deposit",
    "factory_children",
    "factory_terminal_materialisation",
    "watch_service_reorg",
    "maximum_asset_lifecycle",
];
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatefulEvidenceDimension {
    State,
    Assets,
    Persistence,
    Reorg,
    Authority,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatefulEvidenceAssertion {
    pub dimension: StatefulEvidenceDimension,
    pub artifact: String,
    pub pointer: String,
    pub expected: serde_json::Value,
}
fn required_dimensions(scenario: &str) -> Result<BTreeSet<StatefulEvidenceDimension>> {
    use StatefulEvidenceDimension::*;
    ensure!(
        REQUIRED_SCENARIOS.contains(&scenario),
        "unknown current stateful scenario {scenario}"
    );
    let mut required = BTreeSet::from([State, Assets, Authority]);
    if matches!(
        scenario,
        "root_funding"
            | "bilateral_splice"
            | "factory_reduced_escape"
            | "factory_children"
            | "factory_terminal_materialisation"
            | "watch_service_reorg"
    ) {
        required.insert(Persistence);
    }
    if scenario == "watch_service_reorg" {
        required.insert(Reorg);
    }
    Ok(required)
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetStatefulSummary {
    pub schema: String,
    pub directory: String,
    pub manifest: BTreeMap<String, String>,
    pub scenarios: Vec<StatefulScenarioSummary>,
    pub audit_families: Vec<AuditFamilySummary>,
    pub unknown_coverage_tags: Vec<String>,
    pub wide_sponsor_policies: Vec<StatefulSponsorPolicyWindow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<DevnetSmokeSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatefulScenarioSummary {
    pub scenario_id: String,
    pub category: String,
    pub description: String,
    pub references: Vec<String>,
    pub required_committed_checks: Vec<String>,
    pub expected_failures: Vec<StatefulExpectedFailure>,
    pub coverage: Vec<String>,
    pub assertions: Vec<StatefulEvidenceAssertion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetStatefulAssertionReport {
    pub directory: String,
    pub git_commit: Option<String>,
    pub git_dirty: Option<String>,
    pub scenario_count: usize,
    pub required_scenarios: usize,
    pub audit_families: usize,
    pub audit_families_passed: usize,
    pub unknown_coverage_tags: Vec<String>,
    pub referenced_artifacts: usize,
    pub required_committed_checks: usize,
    pub expected_failures: usize,
    pub evidence_assertions: usize,
    pub sponsor_policy_windows: usize,
    pub wide_sponsor_policy_windows: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<DevnetSmokeAssertionReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatefulSponsorPolicyWindow {
    pub check: String,
    pub path: String,
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub state_number_span: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DevnetStatefulAssertionOptions<'a> {
    pub budget_limits: Option<&'a DevnetSmokeBudgetLimits>,
    pub audit_profile: Option<&'a DevnetAuditProfile>,
    pub contracts_dir: &'a Path,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetStatefulComparison {
    pub baseline_directory: String,
    pub candidate_directory: String,
    pub missing_scenarios: Vec<String>,
    pub added_scenarios: Vec<String>,
    pub audit_family_deltas: Vec<AuditFamilyStatusDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<smoke_report::DevnetSmokeComparison>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFamilySummary {
    pub id: String,
    pub severity: String,
    pub principle: String,
    pub passed: bool,
    pub missing_tags: Vec<String>,
    pub missing_scenarios: Vec<String>,
    pub missing_checks: Vec<String>,
    pub missing_failures: Vec<StatefulExpectedFailure>,
    pub evidence_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFamilyStatusDelta {
    pub id: String,
    pub baseline_passed: Option<bool>,
    pub candidate_passed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatefulScenarioFile {
    schema: String,
    scenario_id: String,
    category: String,
    description: String,
    references: Vec<String>,
    required_committed_checks: Vec<String>,
    expected_failures: Vec<StatefulExpectedFailure>,
    coverage: Vec<String>,
    assertions: Vec<StatefulEvidenceAssertion>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevnetAuditProfile {
    schema: String,
    pub families: Vec<AuditFamilyProfile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFamilyProfile {
    pub id: String,
    pub severity: String,
    pub principle: String,
    pub required_coverage_tags: Vec<String>,
    pub required_scenarios: Vec<String>,
    pub required_committed_checks: Vec<String>,
    pub required_expected_failures: Vec<StatefulExpectedFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatefulExpectedFailure {
    pub check: String,
    pub morph_error: String,
    pub error_code: i64,
}

#[derive(Debug, Clone)]
struct AuditFamilyEvaluation {
    families: Vec<AuditFamilySummary>,
    unknown_coverage_tags: Vec<String>,
}

pub fn summarize_devnet_stateful_with_audit(
    dir: &Path,
    audit_profile: Option<&DevnetAuditProfile>,
) -> Result<DevnetStatefulSummary> {
    ensure_directory(dir)?;
    let manifest = read_manifest(dir)?;
    let scenario_files = read_scenario_files(dir)?;
    let scenarios = scenario_files
        .iter()
        .map(|scenario| StatefulScenarioSummary {
            scenario_id: scenario.scenario_id.clone(),
            category: scenario.category.clone(),
            description: scenario.description.clone(),
            references: scenario.references.clone(),
            required_committed_checks: scenario.required_committed_checks.clone(),
            expected_failures: scenario.expected_failures.clone(),
            coverage: scenario.coverage.clone(),
            assertions: scenario.assertions.clone(),
        })
        .collect::<Vec<_>>();
    let smoke_dir = dir.join("smoke");
    let smoke = smoke_dir
        .is_dir()
        .then(|| smoke_report::summarize_devnet_smoke(&smoke_dir))
        .transpose()?;
    let wide_sponsor_policies = smoke
        .as_ref()
        .map(wide_sponsor_policy_windows)
        .unwrap_or_default();
    let mut summary = DevnetStatefulSummary {
        schema: "morph.current_stateful_summary.v1".to_string(),
        directory: dir.display().to_string(),
        manifest,
        scenarios,
        audit_families: Vec::new(),
        unknown_coverage_tags: Vec::new(),
        wide_sponsor_policies,
        smoke,
    };
    if let Some(profile) = audit_profile {
        let audit = audit_family_summaries(&summary, profile);
        summary.audit_families = audit.families;
        summary.unknown_coverage_tags = audit.unknown_coverage_tags;
    }
    Ok(summary)
}

pub fn read_audit_profile(path: &Path) -> Result<DevnetAuditProfile> {
    let raw = read_bounded(path, MAX_SCENARIO_BYTES)?;
    let profile: DevnetAuditProfile = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse devnet audit profile {}", path.display()))?;
    if profile.schema != DEVNET_AUDIT_PROFILE_SCHEMA {
        return Err(anyhow!(
            "unsupported devnet audit profile schema {}",
            profile.schema
        ));
    }
    ensure!(
        !profile.families.is_empty(),
        "devnet audit profile must contain at least one family"
    );
    let mut ids = BTreeSet::new();
    for family in &profile.families {
        ensure!(!family.id.is_empty(), "audit family id must not be empty");
        ensure!(
            ids.insert(family.id.clone()),
            "duplicate audit family id {}",
            family.id
        );
    }
    Ok(profile)
}

/// Stateful and ordinary matrix reports share one current budget schema and
/// parser. A stateful ledger adds scenario facts, not another resource model.
pub fn read_stateful_budget_profile(path: &Path) -> Result<DevnetSmokeBudgetLimits> {
    smoke_report::read_smoke_budget_profile(path).with_context(|| {
        format!(
            "invalid current stateful acceptance budget {}",
            path.display()
        )
    })
}

pub fn assert_default_devnet_stateful(
    dir: &Path,
    options: DevnetStatefulAssertionOptions<'_>,
) -> Result<DevnetStatefulAssertionReport> {
    let summary = summarize_devnet_stateful_with_audit(dir, options.audit_profile)?;
    assert_stateful_summary(&summary)?;
    assert_stateful_artifact_fresh(&summary)?;
    assert_audit_families(&summary, options.audit_profile, options.budget_limits)?;
    let smoke_report = if let Some(smoke) = &summary.smoke {
        let smoke_dir = dir.join("smoke");
        let report = smoke_report::assert_default_devnet_smoke_with_budget(
            &smoke_dir,
            options.contracts_dir,
            options.budget_limits,
        )?;
        ensure!(
            smoke.totals.transaction_count == report.transaction_count,
            "stateful smoke transaction count changed during assertion"
        );
        Some(report)
    } else {
        None
    };
    let referenced_artifacts = summary
        .scenarios
        .iter()
        .map(|scenario| scenario.references.len())
        .sum();
    let required_committed_checks = summary
        .scenarios
        .iter()
        .map(|scenario| scenario.required_committed_checks.len())
        .sum();
    let expected_failures = summary
        .scenarios
        .iter()
        .map(|scenario| scenario.expected_failures.len())
        .sum();
    let sponsor_policy_windows = summary
        .smoke
        .as_ref()
        .map(|smoke| smoke.sponsor_policies.len())
        .unwrap_or_default();
    Ok(DevnetStatefulAssertionReport {
        directory: summary.directory,
        git_commit: summary.manifest.get("git_commit").cloned(),
        git_dirty: summary.manifest.get("git_dirty").cloned(),
        scenario_count: summary.scenarios.len(),
        required_scenarios: REQUIRED_SCENARIOS.len(),
        audit_families: summary.audit_families.len(),
        audit_families_passed: summary
            .audit_families
            .iter()
            .filter(|family| family.passed)
            .count(),
        unknown_coverage_tags: summary.unknown_coverage_tags.clone(),
        referenced_artifacts,
        required_committed_checks,
        expected_failures,
        evidence_assertions: summary
            .scenarios
            .iter()
            .map(|scenario| scenario.assertions.len())
            .sum(),
        sponsor_policy_windows,
        wide_sponsor_policy_windows: summary.wide_sponsor_policies.len(),
        smoke: smoke_report,
    })
}

pub fn compare_devnet_stateful_with_audit(
    baseline_dir: &Path,
    candidate_dir: &Path,
    audit_profile: Option<&DevnetAuditProfile>,
) -> Result<DevnetStatefulComparison> {
    let baseline = summarize_devnet_stateful_with_audit(baseline_dir, audit_profile)?;
    let candidate = summarize_devnet_stateful_with_audit(candidate_dir, audit_profile)?;
    let baseline_ids = scenario_id_set(&baseline);
    let candidate_ids = scenario_id_set(&candidate);
    let missing_scenarios = baseline_ids
        .difference(&candidate_ids)
        .cloned()
        .collect::<Vec<_>>();
    let added_scenarios = candidate_ids
        .difference(&baseline_ids)
        .cloned()
        .collect::<Vec<_>>();
    let baseline_smoke = baseline_dir.join("smoke");
    let candidate_smoke = candidate_dir.join("smoke");
    let smoke = if baseline_smoke.is_dir() && candidate_smoke.is_dir() {
        Some(smoke_report::compare_devnet_smoke(
            &baseline_smoke,
            &candidate_smoke,
        )?)
    } else {
        None
    };
    let audit_family_deltas = audit_family_status_deltas(&baseline, &candidate);
    Ok(DevnetStatefulComparison {
        baseline_directory: baseline.directory,
        candidate_directory: candidate.directory,
        missing_scenarios,
        added_scenarios,
        audit_family_deltas,
        smoke,
    })
}

pub fn assert_stateful_comparison_limits(
    comparison: &DevnetStatefulComparison,
    fail_on_status_change: bool,
) -> Result<()> {
    if fail_on_status_change
        && (!comparison.missing_scenarios.is_empty() || !comparison.added_scenarios.is_empty())
    {
        return Err(anyhow!(
            "stateful scenario set changed: missing {:?}, added {:?}",
            comparison.missing_scenarios,
            comparison.added_scenarios
        ));
    }
    if fail_on_status_change && !comparison.audit_family_deltas.is_empty() {
        return Err(anyhow!(
            "stateful audit family status changed: {:?}",
            comparison.audit_family_deltas
        ));
    }
    if fail_on_status_change && let Some(smoke) = &comparison.smoke {
        let limits = smoke_report::DevnetSmokeComparisonLimits {
            fail_on_transaction_set_change: false,
            fail_on_status_change: true,
            max_abs_total_cycle_delta: None,
            max_abs_tx_cycle_delta: None,
            max_abs_total_byte_delta: None,
            max_abs_tx_byte_delta: None,
        };
        smoke_report::assert_comparison_limits(smoke, &limits)?;
    }
    Ok(())
}

pub fn render_markdown(summary: &DevnetStatefulSummary) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Stateful Summary\n\n");
    out.push_str(&format!("Directory: `{}`\n\n", summary.directory));
    if !summary.manifest.is_empty() {
        out.push_str("## Manifest\n\n");
        out.push_str("| Key | Value |\n| --- | --- |\n");
        for (key, value) in &summary.manifest {
            out.push_str(&format!(
                "| {} | {} |\n",
                table_cell(key),
                table_cell(value)
            ));
        }
        out.push('\n');
    }
    out.push_str("## Scenarios\n\n");
    out.push_str("| Scenario | Category | References | Required commits | Expected failures | Exact evidence assertions |\n");
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: |\n");
    for scenario in &summary.scenarios {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            table_cell(&scenario.scenario_id),
            table_cell(&scenario.category),
            scenario.references.len(),
            scenario.required_committed_checks.len(),
            scenario.expected_failures.len(),
            scenario.assertions.len()
        ));
    }
    out.push('\n');
    if !summary.audit_families.is_empty() || !summary.unknown_coverage_tags.is_empty() {
        out.push_str("## Audit Families\n\n");
        if !summary.unknown_coverage_tags.is_empty() {
            out.push_str(&format!(
                "Unknown coverage tags: `{}`\n\n",
                summary.unknown_coverage_tags.join("`, `")
            ));
        }
        out.push_str("| Family | Severity | Status | Missing tags | Missing scenarios | Missing checks | Missing failures | Invalid facts |\n");
        out.push_str("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |\n");
        for family in &summary.audit_families {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                table_cell(&family.id),
                table_cell(&family.severity),
                if family.passed { "passed" } else { "missing" },
                family.missing_tags.len(),
                family.missing_scenarios.len(),
                family.missing_checks.len(),
                family.missing_failures.len(),
                family.evidence_errors.len()
            ));
        }
        out.push('\n');
    }
    if let Some(smoke) = &summary.smoke {
        out.push_str("## Underlying Smoke Totals\n\n");
        out.push_str("| Transactions | Committed | Pending | Script failures | Watchtower alerts | Current Factory proofs | Cases | Sponsor policies | Wide sponsor policies |\n");
        out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n\n",
            smoke.totals.transaction_count,
            smoke.totals.committed_count,
            smoke.totals.pending_count,
            smoke.script_failures.len(),
            smoke.watchtower_alerts.len(),
            smoke.factory_proofs.len(),
            smoke.cases.len(),
            smoke.sponsor_policies.len(),
            summary.wide_sponsor_policies.len()
        ));
    }
    if !summary.wide_sponsor_policies.is_empty() {
        out.push_str("## Wide Sponsor Policies\n\n");
        out.push_str("| Check | Path | Min state | Max state | Span |\n");
        out.push_str("| --- | --- | ---: | ---: | ---: | ---: |\n");
        for policy in &summary.wide_sponsor_policies {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                table_cell(&policy.check),
                table_cell(&policy.path),
                policy.min_state_number,
                policy.max_state_number,
                policy.state_number_span
            ));
        }
        out.push('\n');
    }
    out
}

pub fn render_comparison_markdown(comparison: &DevnetStatefulComparison) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Stateful Comparison\n\n");
    out.push_str(&format!(
        "Baseline: `{}`\n\nCandidate: `{}`\n\n",
        comparison.baseline_directory, comparison.candidate_directory
    ));
    out.push_str("## Scenario Set\n\n");
    out.push_str(&format!(
        "- Missing from candidate: {}\n",
        comparison.missing_scenarios.len()
    ));
    for scenario in &comparison.missing_scenarios {
        out.push_str(&format!("  - `{scenario}`\n"));
    }
    out.push_str(&format!(
        "- Added in candidate: {}\n",
        comparison.added_scenarios.len()
    ));
    for scenario in &comparison.added_scenarios {
        out.push_str(&format!("  - `{scenario}`\n"));
    }
    if !comparison.audit_family_deltas.is_empty() {
        out.push_str("\n## Audit Family Status\n\n");
        out.push_str("| Family | Baseline | Candidate |\n| --- | --- | --- |\n");
        for delta in &comparison.audit_family_deltas {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                table_cell(&delta.id),
                audit_status_cell(delta.baseline_passed),
                audit_status_cell(delta.candidate_passed)
            ));
        }
    }
    if let Some(smoke) = &comparison.smoke {
        out.push('\n');
        out.push_str(&smoke_report::render_comparison_markdown(smoke));
    }
    out
}

fn assert_stateful_summary(summary: &DevnetStatefulSummary) -> Result<()> {
    ensure!(
        summary.manifest.get("status").map(String::as_str) == Some("passed"),
        "stateful manifest status is not passed"
    );
    ensure!(
        summary.manifest.get("schema").map(String::as_str)
            == Some("morph.current_stateful_matrix.v1"),
        "unsupported current stateful ledger manifest schema"
    );
    let scenario_ids = scenario_id_set(summary);
    ensure!(
        scenario_ids.len() == summary.scenarios.len(),
        "duplicate current stateful scenario id"
    );
    for required in REQUIRED_SCENARIOS {
        ensure!(
            scenario_ids.contains(*required),
            "missing required stateful scenario {required}"
        );
    }
    for scenario in &summary.scenarios {
        ensure!(
            !scenario.references.is_empty(),
            "scenario {} has no referenced artifacts",
            scenario.scenario_id
        );
        for reference in &scenario.references {
            artifact_path(Path::new(&summary.directory), reference)?;
        }
    }
    for scenario in &summary.scenarios {
        assert_scenario_evidence(summary, scenario)?;
    }
    let smoke = summary
        .smoke
        .as_ref()
        .ok_or_else(|| anyhow!("stateful directory is missing underlying smoke summary"))?;
    smoke_report::assert_devnet_smoke_summary(smoke)?;
    let wide_sponsor_policies = wide_sponsor_policy_windows(smoke);
    ensure!(
        wide_sponsor_policies.is_empty(),
        "stateful sponsor policy window exceeds {} states: {}",
        MAX_SPONSOR_STATE_NUMBER_SPAN,
        wide_sponsor_policy_message(&wide_sponsor_policies)
    );
    for scenario in &summary.scenarios {
        for check in &scenario.required_committed_checks {
            let found = smoke
                .transactions
                .iter()
                .any(|tx| tx.check == *check && tx.status.as_deref() == Some("Committed"));
            ensure!(
                found,
                "scenario {} missing committed transaction check {}",
                scenario.scenario_id,
                check
            );
        }
        for expected in &scenario.expected_failures {
            let found = smoke.script_failures.iter().any(|failure| {
                failure.check == expected.check
                    && failure.morph_error.as_deref() == Some(expected.morph_error.as_str())
                    && failure.error_code == Some(expected.error_code)
            });
            ensure!(
                found,
                "scenario {} missing expected failure {} {} {}",
                scenario.scenario_id,
                expected.check,
                expected.morph_error,
                expected.error_code
            );
        }
    }
    Ok(())
}

fn assert_scenario_evidence(
    summary: &DevnetStatefulSummary,
    scenario: &StatefulScenarioSummary,
) -> Result<()> {
    let dimensions = scenario
        .assertions
        .iter()
        .map(|assertion| assertion.dimension)
        .collect::<BTreeSet<_>>();
    let missing = required_dimensions(&scenario.scenario_id)?
        .difference(&dimensions)
        .copied()
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "scenario {} lacks current evidence dimensions: {:?}",
        scenario.scenario_id,
        missing
    );
    let mut unique = BTreeSet::new();
    let mut evidence = BTreeMap::new();
    for assertion in &scenario.assertions {
        ensure!(
            scenario.references.contains(&assertion.artifact),
            "scenario {} assertion artifact is not a declared reference: {}",
            scenario.scenario_id,
            assertion.artifact
        );
        ensure!(
            assertion.pointer.starts_with('/')
                && unique.insert((&assertion.artifact, &assertion.pointer)),
            "scenario {} requires unique explicit JSON pointers",
            scenario.scenario_id
        );
        if assertion.dimension == StatefulEvidenceDimension::Assets {
            ensure!(
                integral_asset_numbers(&assertion.expected),
                "scenario {} asset evidence contains floating-point quantities",
                scenario.scenario_id
            );
            let numeric = assertion.expected.as_str().is_some_and(|value| {
                !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && (value == "0" || !value.starts_with('0'))
            });
            ensure!(
                numeric
                    || assertion.expected.as_u64().is_some()
                    || assertion
                        .expected
                        .as_object()
                        .is_some_and(|value| !value.is_empty())
                    || assertion
                        .expected
                        .as_array()
                        .is_some_and(|value| !value.is_empty()),
                "scenario {} asset evidence must expose actual values or identities, not a boolean/empty placeholder",
                scenario.scenario_id
            );
        }
        if !evidence.contains_key(&assertion.artifact) {
            let path = artifact_path(Path::new(&summary.directory), &assertion.artifact)?;
            let raw = read_bounded(&path, MAX_EVIDENCE_BYTES)?;
            let value: serde_json::Value = serde_json::from_slice(&raw)
                .with_context(|| format!("invalid scenario evidence JSON {}", path.display()))?;
            evidence.insert(assertion.artifact.clone(), value);
        }
        let actual = evidence[&assertion.artifact]
            .pointer(&assertion.pointer)
            .ok_or_else(|| {
                anyhow!(
                    "scenario {} unresolved evidence pointer {} {}",
                    scenario.scenario_id,
                    assertion.artifact,
                    assertion.pointer
                )
            })?;
        ensure!(
            actual == &assertion.expected,
            "scenario {} evidence differs from expected: {} {}",
            scenario.scenario_id,
            assertion.artifact,
            assertion.pointer
        );
    }
    Ok(())
}
fn integral_asset_numbers(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Number(number) => number.is_u64() || number.is_i64(),
        serde_json::Value::Array(values) => values.iter().all(integral_asset_numbers),
        serde_json::Value::Object(values) => values.values().all(integral_asset_numbers),
        _ => true,
    }
}
fn artifact_path(directory: &Path, reference: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(reference);
    ensure!(
        !reference.is_empty()
            && path.is_relative()
            && path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "stateful reference must be a contained relative path: {reference}"
    );
    let directory = directory.canonicalize()?;
    let path = directory
        .join(path)
        .canonicalize()
        .with_context(|| format!("stateful artifact does not exist: {reference}"))?;
    ensure!(
        path.starts_with(&directory) && path.is_file(),
        "stateful artifact escapes its evidence directory: {reference}"
    );
    Ok(path)
}
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= max,
        "stateful artifact exceeds byte bound: {}",
        path.display()
    );
    Ok(raw)
}

fn assert_stateful_artifact_fresh(summary: &DevnetStatefulSummary) -> Result<()> {
    let current_git = current_git_state()?;
    assert_stateful_artifact_fresh_against(summary, &current_git)
}

#[derive(Debug, Clone)]
struct CurrentGitState {
    commit: String,
    dirty: bool,
}

fn assert_stateful_artifact_fresh_against(
    summary: &DevnetStatefulSummary,
    current_git: &CurrentGitState,
) -> Result<()> {
    ensure!(
        summary.manifest.get("provenance_phase").map(String::as_str) == Some("pre_build"),
        "stateful artifact lacks immutable pre-build source provenance"
    );
    ensure!(
        summary.manifest.get("source_unchanged").map(String::as_str) == Some("true"),
        "stateful artifact source changed during the run"
    );
    ensure!(
        summary.manifest.get("git_dirty").map(String::as_str) == Some("false"),
        "stateful artifact was produced from a dirty working tree"
    );
    ensure!(
        !current_git.dirty,
        "current working tree is dirty; rerun from a clean tree"
    );
    let artifact_commit = summary
        .manifest
        .get("git_commit")
        .ok_or_else(|| anyhow!("stateful artifact manifest is missing git_commit"))?;
    ensure!(
        artifact_commit == &current_git.commit,
        "stateful artifact commit {artifact_commit} does not match current HEAD {}",
        current_git.commit
    );
    Ok(())
}

fn current_git_state() -> Result<CurrentGitState> {
    let status = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .context("failed to inspect tracked git worktree state")?;
    ensure!(
        status.status.success(),
        "tracked git worktree inspection failed: {}",
        String::from_utf8_lossy(&status.stderr).trim()
    );
    let untracked = Command::new("git")
        .args([
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            "crates",
            "contracts",
            "scripts",
            "sdk",
            "ui",
            ".github",
            "Cargo.toml",
            "Cargo.lock",
            "Makefile",
            "rust-toolchain.toml",
            "AGENTS.md",
        ])
        .output()
        .context("failed to inspect untracked implementation files")?;
    ensure!(
        untracked.status.success(),
        "untracked implementation inspection failed"
    );
    Ok(CurrentGitState {
        commit: current_git_commit_short()?,
        dirty: !status.stdout.is_empty() || !untracked.stdout.is_empty(),
    })
}

fn current_git_commit_short() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .context("failed to run git rev-parse --short HEAD")?;
    ensure!(
        output.status.success(),
        "git rev-parse --short HEAD failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn assert_audit_families(
    summary: &DevnetStatefulSummary,
    audit_profile: Option<&DevnetAuditProfile>,
    budget_limits: Option<&DevnetSmokeBudgetLimits>,
) -> Result<()> {
    if audit_profile.is_none() {
        return Ok(());
    }
    ensure!(
        summary.unknown_coverage_tags.is_empty(),
        "stateful scenarios contain unknown coverage tags: {:?}",
        summary.unknown_coverage_tags
    );
    if summary
        .audit_families
        .iter()
        .any(|family| family.id == "budget_regression")
    {
        ensure!(
            budget_limits
                .map(DevnetSmokeBudgetLimits::has_any_limit)
                .unwrap_or(false),
            "budget_regression requires a stateful budget profile"
        );
    }
    for family in &summary.audit_families {
        ensure!(
            family.passed,
            "audit family {} missing evidence: tags {:?}, scenarios {:?}, checks {:?}, failures {:?}, invalid facts {:?}",
            family.id,
            family.missing_tags,
            family.missing_scenarios,
            family.missing_checks,
            family.missing_failures,
            family.evidence_errors
        );
    }
    Ok(())
}

fn audit_family_summaries(
    summary: &DevnetStatefulSummary,
    profile: &DevnetAuditProfile,
) -> AuditFamilyEvaluation {
    let scenario_ids = scenario_id_set(summary);
    let coverage_tags = coverage_tag_set(summary);
    let known_tags = profile
        .families
        .iter()
        .flat_map(|family| family.required_coverage_tags.iter().cloned())
        .collect::<BTreeSet<_>>();
    let unknown_coverage_tags = coverage_tags
        .difference(&known_tags)
        .cloned()
        .collect::<Vec<_>>();
    let families = profile
        .families
        .iter()
        .map(|family| {
            let missing_tags = missing_strings(&family.required_coverage_tags, &coverage_tags);
            let missing_scenarios = missing_strings(&family.required_scenarios, &scenario_ids);
            let missing_checks = family
                .required_committed_checks
                .iter()
                .filter(|check| !has_committed_check(summary, check))
                .cloned()
                .collect::<Vec<_>>();
            let missing_failures = family
                .required_expected_failures
                .iter()
                .filter(|failure| !has_exact_failure(summary, failure))
                .cloned()
                .collect::<Vec<_>>();
            let evidence_errors = family
                .required_scenarios
                .iter()
                .filter_map(|id| {
                    summary
                        .scenarios
                        .iter()
                        .find(|scenario| &scenario.scenario_id == id)
                })
                .filter_map(|scenario| {
                    assert_scenario_evidence(summary, scenario)
                        .err()
                        .map(|error| error.to_string())
                })
                .collect::<Vec<_>>();
            let passed = missing_tags.is_empty()
                && missing_scenarios.is_empty()
                && missing_checks.is_empty()
                && missing_failures.is_empty()
                && evidence_errors.is_empty();
            AuditFamilySummary {
                id: family.id.clone(),
                severity: family.severity.clone(),
                principle: family.principle.clone(),
                passed,
                missing_tags,
                missing_scenarios,
                missing_checks,
                missing_failures,
                evidence_errors,
            }
        })
        .collect();
    AuditFamilyEvaluation {
        families,
        unknown_coverage_tags,
    }
}

fn audit_family_status_deltas(
    baseline: &DevnetStatefulSummary,
    candidate: &DevnetStatefulSummary,
) -> Vec<AuditFamilyStatusDelta> {
    let baseline_status = audit_family_status_map(baseline);
    let candidate_status = audit_family_status_map(candidate);
    let ids = baseline_status
        .keys()
        .chain(candidate_status.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    ids.into_iter()
        .filter_map(|id| {
            let baseline_passed = baseline_status.get(&id).copied();
            let candidate_passed = candidate_status.get(&id).copied();
            (baseline_passed != candidate_passed).then_some(AuditFamilyStatusDelta {
                id,
                baseline_passed,
                candidate_passed,
            })
        })
        .collect()
}

fn audit_family_status_map(summary: &DevnetStatefulSummary) -> BTreeMap<String, bool> {
    summary
        .audit_families
        .iter()
        .map(|family| (family.id.clone(), family.passed))
        .collect()
}

fn missing_strings(required: &[String], actual: &BTreeSet<String>) -> Vec<String> {
    required
        .iter()
        .filter(|value| !actual.contains(*value))
        .cloned()
        .collect()
}

fn coverage_tag_set(summary: &DevnetStatefulSummary) -> BTreeSet<String> {
    summary
        .scenarios
        .iter()
        .flat_map(|scenario| scenario.coverage.iter().cloned())
        .collect()
}

fn has_committed_check(summary: &DevnetStatefulSummary, check: &str) -> bool {
    summary.smoke.as_ref().is_some_and(|smoke| {
        smoke
            .transactions
            .iter()
            .any(|tx| tx.check == check && tx.status.as_deref() == Some("Committed"))
    })
}

fn has_exact_failure(summary: &DevnetStatefulSummary, expected: &StatefulExpectedFailure) -> bool {
    summary.smoke.as_ref().is_some_and(|smoke| {
        smoke.script_failures.iter().any(|failure| {
            failure.check == expected.check
                && failure.morph_error.as_deref() == Some(expected.morph_error.as_str())
                && failure.error_code == Some(expected.error_code)
        })
    })
}

fn wide_sponsor_policy_windows(smoke: &DevnetSmokeSummary) -> Vec<StatefulSponsorPolicyWindow> {
    smoke
        .sponsor_policies
        .iter()
        .filter(|policy| policy.state_number_span > MAX_SPONSOR_STATE_NUMBER_SPAN)
        .map(|policy| StatefulSponsorPolicyWindow {
            check: policy.check.clone(),
            path: policy.path.clone(),
            min_state_number: policy.min_state_number,
            max_state_number: policy.max_state_number,
            state_number_span: policy.state_number_span,
        })
        .collect()
}

fn wide_sponsor_policy_message(policies: &[StatefulSponsorPolicyWindow]) -> String {
    policies
        .iter()
        .map(|policy| {
            format!(
                "{} {} {}..{} span {}",
                policy.check,
                policy.path,
                policy.min_state_number,
                policy.max_state_number,
                policy.state_number_span
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn read_scenario_files(dir: &Path) -> Result<Vec<StatefulScenarioFile>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("failed to list stateful directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list stateful directory {}", dir.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter(|path| {
            !matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("summary.json" | "summary-check.json" | "summary-budget-check.json")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    ensure!(
        paths.len() <= 32,
        "too many current stateful scenario files"
    );
    let mut scenarios = Vec::new();
    for path in paths {
        let raw = read_bounded(&path, MAX_SCENARIO_BYTES)?;
        let scenario: StatefulScenarioFile = serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse stateful scenario {}", path.display()))?;
        ensure!(
            scenario.schema == DEVNET_STATEFUL_SCENARIO_SCHEMA,
            "unsupported stateful scenario schema {} in {}",
            scenario.schema,
            path.display()
        );
        scenarios.push(scenario);
    }
    Ok(scenarios)
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
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            manifest.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(manifest)
}

fn ensure_directory(dir: &Path) -> Result<()> {
    ensure!(dir.is_dir(), "directory does not exist: {}", dir.display());
    Ok(())
}

fn scenario_id_set(summary: &DevnetStatefulSummary) -> BTreeSet<String> {
    summary
        .scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.clone())
        .collect()
}

fn audit_status_cell(status: Option<bool>) -> &'static str {
    match status {
        Some(true) => "passed",
        Some(false) => "missing",
        None => "absent",
    }
}

fn table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smoke_report::{
        DeployedScriptSummary, MetricTotals, SponsorPolicySummary, TransactionSummary,
        WatchtowerAlertSummary, WatchtowerServiceSummary,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_bad_audit_profile_schema() {
        let dir = temp_dir("bad-audit-profile-schema");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile.json");
        fs::write(
            &path,
            r#"{"schema":"wrong","families":[{"id":"f","severity":"P0","principle":"p","required_coverage_tags":[],"required_scenarios":[],"required_committed_checks":[],"required_expected_failures":[]}]}"#,
        )
        .unwrap();

        let err = read_audit_profile(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported devnet audit profile"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn current_example_audit_and_budget_only_name_current_scenarios_and_operations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
        let profile = read_audit_profile(&root.join("devnet-audit-profile.example.json")).unwrap();
        assert_eq!(profile.families.len(), 11);
        for family in profile.families {
            assert!(
                family
                    .required_scenarios
                    .iter()
                    .all(|id| REQUIRED_SCENARIOS.contains(&id.as_str()))
            );
        }
        let budget =
            read_stateful_budget_profile(&root.join("devnet-stateful-budget.example.json"))
                .unwrap();
        assert!(budget.has_any_limit());
        assert_eq!(budget.cases.len(), 6);
        for case in &budget.cases {
            if case.name == "deployment" {
                assert_eq!(case.max_tx_cycles, Some(2_000_000));
                assert_eq!(case.max_tx_bytes, Some(300_000));
            } else {
                assert_eq!(case.max_tx_cycles, Some(40_000_000));
                assert_eq!(case.max_tx_bytes, Some(100_000));
            }
        }
        assert_eq!(budget.proof_profiles.len(), 5);
        assert!(budget.proof_profiles.iter().all(|proof| {
            [
                "root_funding",
                "ReducedRelease",
                "ReducedDeposit",
                "ReducedChild",
                "materialisation",
            ]
            .contains(&proof.operation.as_str())
        }));
    }
    #[test]
    fn audit_family_summary_rejects_unknown_coverage_tag() {
        let summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec!["unknown_tag".to_string()],
            assertions: vec![],
        });
        let profile = audit_profile(vec![AuditFamilyProfile {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            required_coverage_tags: vec!["known_tag".to_string()],
            required_scenarios: vec![],
            required_committed_checks: vec![],
            required_expected_failures: vec![],
        }]);

        let audit = audit_family_summaries(&summary, &profile);
        assert_eq!(audit.unknown_coverage_tags, vec!["unknown_tag"]);
        let mut checked_summary = summary;
        checked_summary.audit_families = audit.families;
        checked_summary.unknown_coverage_tags = audit.unknown_coverage_tags;
        let err = assert_audit_families(&checked_summary, Some(&profile), None).unwrap_err();
        assert!(err.to_string().contains("unknown coverage tags"));
    }

    #[test]
    fn audit_family_summary_reports_missing_required_evidence() {
        let summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec!["family-a".to_string()],
            assertions: vec![],
        });
        let expected_failure = StatefulExpectedFailure {
            check: "negative-check".to_string(),
            morph_error: "ExpectedError".to_string(),
            error_code: 42,
        };
        let profile = audit_profile(vec![AuditFamilyProfile {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            required_coverage_tags: vec!["family-a".to_string()],
            required_scenarios: vec!["scenario-b".to_string()],
            required_committed_checks: vec!["committed-check".to_string()],
            required_expected_failures: vec![expected_failure.clone()],
        }]);

        let audit = audit_family_summaries(&summary, &profile);
        let family = &audit.families[0];
        assert!(!family.passed);
        assert_eq!(family.missing_scenarios, vec!["scenario-b"]);
        assert_eq!(family.missing_checks, vec!["committed-check"]);
        assert_eq!(family.missing_failures, vec![expected_failure]);
    }

    #[test]
    fn complete_audit_family_passes() {
        let directory = temp_dir("complete-current-audit");
        let mut scenario = current_evidence_scenario(&directory, "root_funding");
        scenario.coverage = vec!["family-a".to_string()];
        let mut summary = summary_with_scenario(scenario);
        summary.directory = directory.display().to_string();
        summary.smoke = Some(smoke_summary(
            vec![transaction("committed-check", "Committed")],
            vec![script_failure("negative-check", "ExpectedError", 42)],
        ));
        let profile = audit_profile(vec![AuditFamilyProfile {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            required_coverage_tags: vec!["family-a".to_string()],
            required_scenarios: vec!["root_funding".to_string()],
            required_committed_checks: vec!["committed-check".to_string()],
            required_expected_failures: vec![StatefulExpectedFailure {
                check: "negative-check".to_string(),
                morph_error: "ExpectedError".to_string(),
                error_code: 42,
            }],
        }]);

        let audit = audit_family_summaries(&summary, &profile);
        assert!(audit.unknown_coverage_tags.is_empty());
        assert!(audit.families[0].passed);
        summary.scenarios[0].assertions[0].expected = serde_json::json!("forged");
        let forged = audit_family_summaries(&summary, &profile);
        assert!(!forged.families[0].passed);
        assert!(!forged.families[0].evidence_errors.is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sponsor_policy_window_metric_flags_above_default_span() {
        let mut smoke = smoke_summary(vec![], vec![]);
        smoke.sponsor_policies = vec![
            sponsor_policy("default-window", 1, 1 + MAX_SPONSOR_STATE_NUMBER_SPAN),
            sponsor_policy("wide-window", 1, 2 + MAX_SPONSOR_STATE_NUMBER_SPAN),
        ];

        let wide = wide_sponsor_policy_windows(&smoke);

        assert_eq!(wide.len(), 1);
        assert_eq!(wide[0].check, "wide-window");
        assert_eq!(wide[0].state_number_span, MAX_SPONSOR_STATE_NUMBER_SPAN + 1);
        assert!(wide_sponsor_policy_message(&wide).contains("wide-window $.sponsor_policy"));
    }

    fn current_evidence_scenario(directory: &Path, id: &str) -> StatefulScenarioSummary {
        let evidence = serde_json::json!({"state":"settling","assets":{"ckb":"100"},"persistence":true,"reorg":true,"authority":true});
        fs::create_dir_all(directory).unwrap();
        fs::write(
            directory.join("evidence.json"),
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        StatefulScenarioSummary {
            scenario_id: id.to_string(),
            category: "current".to_string(),
            description: "current actual evidence assertions".to_string(),
            references: vec!["evidence.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec![],
            assertions: required_dimensions(id)
                .unwrap()
                .into_iter()
                .map(|dimension| {
                    let key = match dimension {
                        StatefulEvidenceDimension::State => "state",
                        StatefulEvidenceDimension::Assets => "assets",
                        StatefulEvidenceDimension::Persistence => "persistence",
                        StatefulEvidenceDimension::Reorg => "reorg",
                        StatefulEvidenceDimension::Authority => "authority",
                    };
                    StatefulEvidenceAssertion {
                        dimension,
                        artifact: "evidence.json".to_string(),
                        pointer: format!("/{key}"),
                        expected: evidence[key].clone(),
                    }
                })
                .collect(),
        }
    }
    #[test]
    fn current_scenarios_require_actual_values_and_every_safety_dimension() {
        let directory = temp_dir("current-dimensions");
        for id in REQUIRED_SCENARIOS {
            let scenario = current_evidence_scenario(&directory, id);
            let mut summary = summary_with_scenario(scenario.clone());
            summary.directory = directory.display().to_string();
            assert_scenario_evidence(&summary, &scenario).unwrap();
            for dimension in required_dimensions(id).unwrap() {
                let mut missing = scenario.clone();
                missing
                    .assertions
                    .retain(|assertion| assertion.dimension != dimension);
                assert!(
                    assert_scenario_evidence(&summary, &missing).is_err(),
                    "missing {dimension:?} for {id}"
                );
            }
        }
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn current_evidence_rejects_wrong_missing_duplicate_and_boolean_asset_facts() {
        let directory = temp_dir("current-forged-evidence");
        let scenario = current_evidence_scenario(&directory, "root_funding");
        let mut summary = summary_with_scenario(scenario.clone());
        summary.directory = directory.display().to_string();
        let mut wrong = scenario.clone();
        wrong.assertions[0].expected = serde_json::json!("wrong");
        assert!(
            assert_scenario_evidence(&summary, &wrong)
                .unwrap_err()
                .to_string()
                .contains("differs from expected")
        );
        let mut absent = scenario.clone();
        absent.assertions[0].pointer = "/missing".to_string();
        assert!(
            assert_scenario_evidence(&summary, &absent)
                .unwrap_err()
                .to_string()
                .contains("unresolved")
        );
        let mut duplicate = scenario.clone();
        duplicate.assertions.push(duplicate.assertions[0].clone());
        assert!(
            assert_scenario_evidence(&summary, &duplicate)
                .unwrap_err()
                .to_string()
                .contains("unique explicit")
        );
        let mut boolean = scenario.clone();
        boolean
            .assertions
            .iter_mut()
            .find(|assertion| assertion.dimension == StatefulEvidenceDimension::Assets)
            .unwrap()
            .expected = serde_json::json!(true);
        assert!(
            assert_scenario_evidence(&summary, &boolean)
                .unwrap_err()
                .to_string()
                .contains("actual values")
        );
        let mut rounded = scenario.clone();
        rounded
            .assertions
            .iter_mut()
            .find(|assertion| assertion.dimension == StatefulEvidenceDimension::Assets)
            .unwrap()
            .expected = serde_json::json!({"token_amount":1e38});
        assert!(
            assert_scenario_evidence(&summary, &rounded)
                .unwrap_err()
                .to_string()
                .contains("floating-point")
        );
        let mut undeclared = scenario.clone();
        undeclared.assertions[0].artifact = "elsewhere.json".to_string();
        assert!(
            assert_scenario_evidence(&summary, &undeclared)
                .unwrap_err()
                .to_string()
                .contains("declared reference")
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn current_evidence_rejects_escaping_paths_and_old_placeholder_schema() {
        let directory = temp_dir("current-contained-evidence");
        fs::create_dir_all(&directory).unwrap();
        assert!(artifact_path(&directory, "../outside.json").is_err());
        assert!(artifact_path(&directory, "/outside.json").is_err());
        let raw = serde_json::json!({"schema":DEVNET_STATEFUL_SCENARIO_SCHEMA,"scenario_id":"root_funding","category":"current","description":"evidence","references":[],"required_committed_checks":[],"expected_failures":[],"coverage":[],"assertions":[],"final_state_pointer":{},"asset_deltas":{}});
        assert!(serde_json::from_value::<StatefulScenarioFile>(raw).is_err());
        #[cfg(unix)]
        {
            let outside = temp_dir("outside-evidence");
            fs::create_dir_all(&outside).unwrap();
            fs::write(outside.join("outside.json"), b"{}").unwrap();
            std::os::unix::fs::symlink(outside.join("outside.json"), directory.join("link.json"))
                .unwrap();
            assert!(artifact_path(&directory, "link.json").is_err());
            fs::remove_dir_all(outside).unwrap();
        }
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn expected_failures_keep_exact_check_name_and_script_error_matching() {
        let mut summary = summary_with_scenarios(vec![]);
        summary.smoke = Some(smoke_summary(
            vec![],
            vec![script_failure("negative-check", "ExpectedError", 42)],
        ));
        let expected = StatefulExpectedFailure {
            check: "negative-check".to_string(),
            morph_error: "ExpectedError".to_string(),
            error_code: 42,
        };
        assert!(has_exact_failure(&summary, &expected));
        let mut wrong = expected.clone();
        wrong.error_code = 41;
        assert!(!has_exact_failure(&summary, &wrong));
        wrong = expected.clone();
        wrong.check = "other-case".to_string();
        assert!(!has_exact_failure(&summary, &wrong));
        wrong = expected;
        wrong.morph_error = "OtherError".to_string();
        assert!(!has_exact_failure(&summary, &wrong));
    }

    #[test]
    fn comparison_detects_audit_family_status_regression() {
        let mut baseline = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec![],
            assertions: vec![],
        });
        baseline.audit_families = vec![AuditFamilySummary {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            passed: true,
            missing_tags: vec![],
            missing_scenarios: vec![],
            missing_checks: vec![],
            missing_failures: vec![],
            evidence_errors: vec![],
        }];
        let mut candidate = baseline.clone();
        candidate.audit_families[0].passed = false;

        let deltas = audit_family_status_deltas(&baseline, &candidate);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].id, "family-a");
        assert_eq!(deltas[0].baseline_passed, Some(true));
        assert_eq!(deltas[0].candidate_passed, Some(false));
    }

    #[test]
    fn rejects_dirty_stateful_artifact_by_default() {
        let mut summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec![],
            assertions: vec![],
        });
        summary.manifest.insert(
            "git_commit".to_string(),
            current_git_commit_short().unwrap(),
        );
        summary
            .manifest
            .insert("git_dirty".to_string(), "true".to_string());

        let current_git = CurrentGitState {
            commit: "abc1234".to_string(),
            dirty: false,
        };
        let err = assert_stateful_artifact_fresh_against(&summary, &current_git).unwrap_err();
        assert!(err.to_string().contains("dirty working tree"));
    }

    #[test]
    fn rejects_stale_stateful_artifact_by_default() {
        let mut summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec![],
            assertions: vec![],
        });
        summary
            .manifest
            .insert("git_commit".to_string(), "0000000".to_string());
        summary
            .manifest
            .insert("git_dirty".to_string(), "false".to_string());

        let current_git = CurrentGitState {
            commit: current_git_commit_short().unwrap(),
            dirty: false,
        };
        let err = assert_stateful_artifact_fresh_against(&summary, &current_git).unwrap_err();
        assert!(err.to_string().contains("does not match current HEAD"));
    }

    #[test]
    fn rejects_dirty_current_worktree_by_default() {
        let mut summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec![],
            assertions: vec![],
        });
        summary
            .manifest
            .insert("git_commit".to_string(), "abc1234".to_string());
        summary
            .manifest
            .insert("git_dirty".to_string(), "false".to_string());
        let current_git = CurrentGitState {
            commit: "abc1234".to_string(),
            dirty: true,
        };

        let err = assert_stateful_artifact_fresh_against(&summary, &current_git).unwrap_err();
        assert!(err.to_string().contains("current working tree is dirty"));

        summary
            .manifest
            .insert("git_dirty".to_string(), "true".to_string());
        let err = assert_stateful_artifact_fresh_against(&summary, &current_git).unwrap_err();
        assert!(
            err.to_string()
                .contains("artifact was produced from a dirty")
        );
    }

    #[test]
    fn rejects_post_run_or_changed_source_even_when_head_and_worktree_are_clean() {
        let mut summary = summary_with_scenarios(vec![]);
        summary
            .manifest
            .insert("git_commit".into(), "abc1234".into());
        summary.manifest.insert("git_dirty".into(), "false".into());
        let current_git = CurrentGitState {
            commit: "abc1234".into(),
            dirty: false,
        };
        summary
            .manifest
            .insert("provenance_phase".into(), "post_run".into());
        let error = assert_stateful_artifact_fresh_against(&summary, &current_git).unwrap_err();
        assert!(error.to_string().contains("pre-build"));
        summary
            .manifest
            .insert("provenance_phase".into(), "pre_build".into());
        summary
            .manifest
            .insert("source_unchanged".into(), "false".into());
        let error = assert_stateful_artifact_fresh_against(&summary, &current_git).unwrap_err();
        assert!(error.to_string().contains("source changed"));
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "morph-stateful-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn audit_profile(families: Vec<AuditFamilyProfile>) -> DevnetAuditProfile {
        DevnetAuditProfile {
            schema: DEVNET_AUDIT_PROFILE_SCHEMA.to_string(),
            families,
        }
    }

    fn summary_with_scenario(scenario: StatefulScenarioSummary) -> DevnetStatefulSummary {
        summary_with_scenarios(vec![scenario])
    }

    fn summary_with_scenarios(scenarios: Vec<StatefulScenarioSummary>) -> DevnetStatefulSummary {
        let mut manifest = BTreeMap::new();
        manifest.insert("status".to_string(), "passed".to_string());
        manifest.insert("provenance_phase".to_string(), "pre_build".to_string());
        manifest.insert("source_unchanged".to_string(), "true".to_string());
        manifest.insert(
            "schema".to_string(),
            "morph.current_stateful_matrix.v1".to_string(),
        );
        DevnetStatefulSummary {
            schema: "morph.current_stateful_summary.v1".to_string(),
            directory: ".".to_string(),
            manifest,
            scenarios,
            audit_families: vec![],
            unknown_coverage_tags: vec![],
            wide_sponsor_policies: vec![],
            smoke: Some(smoke_summary(vec![], vec![])),
        }
    }

    fn smoke_summary(
        transactions: Vec<TransactionSummary>,
        script_failures: Vec<smoke_report::ScriptFailureSummary>,
    ) -> DevnetSmokeSummary {
        DevnetSmokeSummary {
            directory: ".".to_string(),
            schema: "morph.current_acceptance_summary.v1".to_string(),
            matrix: smoke_report::CurrentMatrix {
                schema: "morph.current_acceptance_matrix.v1".to_string(),
                cases: vec![],
            },
            cases: vec![],
            json_files: 0,
            publication_attempts: vec![],
            publication_reconciliations: vec![],
            factory_proofs: vec![],
            transaction_observations: transactions.clone(),
            transactions,
            script_failures,
            deployed_scripts: Vec::<DeployedScriptSummary>::new(),
            watchtower_alerts: Vec::<WatchtowerAlertSummary>::new(),
            watchtower_services: Vec::<WatchtowerServiceSummary>::new(),
            sponsor_policies: Vec::new(),
            totals: MetricTotals::default(),
        }
    }

    fn transaction(check: &str, status: &str) -> TransactionSummary {
        TransactionSummary {
            check: check.to_string(),
            path: "$.tx".to_string(),
            tx_hash: "0x00".to_string(),
            status: Some(status.to_string()),
            block_number: Some(1),
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn script_failure(
        check: &str,
        morph_error: &str,
        error_code: i64,
    ) -> smoke_report::ScriptFailureSummary {
        smoke_report::ScriptFailureSummary {
            check: check.to_string(),
            path: "$.failure".to_string(),
            source: Some("stderr".to_string()),
            error_code: Some(error_code),
            morph_error: Some(morph_error.to_string()),
        }
    }

    fn sponsor_policy(
        check: &str,
        min_state_number: u64,
        max_state_number: u64,
    ) -> SponsorPolicySummary {
        SponsorPolicySummary {
            check: check.to_string(),
            path: "$.sponsor_policy".to_string(),
            min_state_number,
            max_state_number,
            state_number_span: max_state_number.saturating_sub(min_state_number),
            max_fee_per_tx: 100,
            max_total_fee: 200,
        }
    }
}
