use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use morph_script_common::{
    CONDITIONAL_TRANSFER_MAX_COUNT, FACTORY_COMPACT_PROOF_MAX_SIBLINGS, FACTORY_MAX_PARTICIPANTS,
    FACTORY_MIN_PARTICIPANTS, FACTORY_SPARSE_MERKLE_DEPTH,
};
use morph_script_common::{
    factory_multi_asset::{
        FACTORY_MULTI_ASSET_MAX_CHILDREN, FACTORY_REDUCED_RELEASE_MAX_RIGHTS,
        FACTORY_TRANSITION_MAX_RIGHTS,
    },
    multi_asset::MULTI_ASSET_MAX_VAULTS,
};
use serde::{Deserialize, Serialize};

use crate::release::FACTORY_RELEASE_PROFILE;

pub const PREPRODUCTION_ENVELOPE_SCHEMA: &str = "morph.preproduction_envelope.v3";

const MAX_ACTIVE_FACTORIES: u32 = 4;
// Operator-maintained lifetime admission cap; no on-chain cumulative counter.
const MAX_CHILDREN_PER_FACTORY: u32 = 10;
// Native eight-Vault geometry is 3,536 CKB including the 464 CKB State carrier.
// A 4,000 CKB no-value experiment ceiling admits that measured shape.
const MAX_CHANNEL_CAPACITY_SHANNONS: u64 = 400_000_000_000;
const MAX_FACTORY_CAPACITY_SHANNONS: u64 = 1_000_000_000_000;
const MAX_SPONSOR_CAPACITY_SHANNONS: u64 = 50_000_000_000;
const MAX_FEE_PER_TRANSACTION_SHANNONS: u64 = 200_000_000;
const MAX_TOTAL_PILOT_CAPACITY_SHANNONS: u64 = 4_000_000_000_000;
const MAX_DEVNET_XUDT_UNITS_PER_CHANNEL: u128 = 1_000_000_000_000;
const MIN_WATCHTOWER_DETECTION_DEPTH: u64 = 3;
const MAX_CONDITIONAL_REFUND_BLOCK_DELTA: u64 = 2_016;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreproductionEnvelope {
    pub schema: String,
    pub release_profile: String,
    pub effective_date: String,
    pub review_by: String,
    pub approval_timezone: String,
    pub effective_unix: u64,
    pub review_by_unix: u64,
    pub approved_networks: Vec<String>,
    pub real_assets_allowed: bool,
    pub hub_chain_actions_allowed: bool,
    pub protocol_limits: ProtocolLimits,
    pub qualification: Qualification,
    pub operator_requirements: OperatorRequirements,
    pub factory: FactoryLimits,
    pub channel: ChannelLimits,
    pub conditional_batch: ConditionalBatchLimits,
    pub sponsor: SponsorLimits,
    pub xudt: XudtLimits,
    pub watchtower: WatchtowerLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLimits {
    pub factory_min_participant_count: u32,
    pub factory_max_participant_count: u32,
    pub max_children_per_transaction: u32,
    pub max_vaults_per_state: u32,
    pub max_metadata_rights_per_transition: u32,
    pub max_physical_claims_per_transition: u32,
    pub compact_proof_depth: u32,
    pub max_siblings_per_compact_proof: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub phase: String,
    pub release_admitted: bool,
    pub production_allowed: bool,
    pub pending_evidence_issues: Vec<u32>,
    pub exact_release_evidence_status: String,
    pub joint_protocol_maxima_native_qualified: bool,
    pub request_shape_enforcement: String,
    pub contract_manifest: String,
    pub acceptance_budget_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRequirements {
    pub lifetime_child_cap_mode: String,
    pub complete_rights_snapshot_required: bool,
    pub replacement_snapshot_delivery_required: bool,
    pub payout_and_retained_floor_geometry_required: bool,
    pub independent_carrier_and_fee_funding_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryLimits {
    pub participant_count: u32,
    pub asset_scope: String,
    pub reduced_right_counts: Vec<u32>,
    pub max_active_factories: u32,
    pub max_children_per_factory: u32,
    pub max_children_per_transaction: u32,
    pub max_vaults_per_state: u32,
    pub max_capacity_shannons: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelLimits {
    pub max_vaults_per_state: u32,
    pub asset_scope: String,
    pub max_capacity_shannons: u64,
    pub max_total_pilot_capacity_shannons: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalBatchLimits {
    pub enabled: bool,
    pub asset_scope: String,
    pub max_batches: u32,
    pub max_transfers: u32,
    pub max_refund_block_delta: u64,
    pub allowed_hash_algorithms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorLimits {
    pub max_capacity_shannons: u64,
    pub max_fee_per_transaction_shannons: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XudtLimits {
    pub allowed_scripts: Vec<String>,
    pub max_asset_types_per_factory: u32,
    pub max_units_per_factory: u128,
    pub max_asset_types_per_channel: u32,
    pub max_units_per_type_per_channel: u128,
    pub identity_rule: String,
    pub zero_quantity_rights_require_admission: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchtowerLimits {
    pub minimum_detection_depth: u64,
    pub reorg_mode: String,
    pub restart_scan_floor_required: bool,
    pub independent_operator_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreproductionEnvelopeVerification {
    pub schema: &'static str,
    pub envelope_path: String,
    pub release_profile: String,
    pub approved_networks: Vec<String>,
    pub real_assets_allowed: bool,
    pub factory_min_participant_count: u32,
    pub factory_max_participant_count: u32,
    pub protocol_limits: ProtocolLimits,
    pub qualification: Qualification,
    pub policy_verified: bool,
    pub release_admitted: bool,
    pub max_active_factories: u32,
    pub reorg_mode: String,
}

impl PreproductionEnvelope {
    pub fn validate(&self) -> Result<()> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        self.validate_at(now_unix)
    }

    fn validate_at(&self, now_unix: u64) -> Result<()> {
        ensure!(
            self.schema == PREPRODUCTION_ENVELOPE_SCHEMA,
            "unsupported pre-production envelope schema {}",
            self.schema
        );
        ensure!(
            self.release_profile == FACTORY_RELEASE_PROFILE,
            "pre-production release profile must be {FACTORY_RELEASE_PROFILE}"
        );
        ensure!(
            is_iso_date(&self.effective_date) && is_iso_date(&self.review_by),
            "effective_date and review_by must use YYYY-MM-DD"
        );
        ensure!(
            self.effective_date <= self.review_by,
            "effective_date must not be after review_by"
        );
        ensure!(
            self.approval_timezone == "Asia/Shanghai",
            "approval_timezone must be Asia/Shanghai for this dated envelope"
        );
        ensure!(
            self.effective_unix <= self.review_by_unix,
            "effective_unix must not be after review_by_unix"
        );
        ensure!(
            now_unix >= self.effective_unix,
            "pre-production envelope is not effective yet"
        );
        ensure!(
            now_unix <= self.review_by_unix,
            "pre-production envelope expired at review_by; release owner review is required"
        );
        ensure!(
            self.approved_networks == ["devnet"],
            "the current pre-production envelope is restricted to devnet"
        );
        ensure!(
            !self.real_assets_allowed,
            "real assets are prohibited by the current pre-production envelope"
        );
        ensure!(
            !self.hub_chain_actions_allowed,
            "Morph Hub chain actions must remain disabled until they submit and verify CKB transactions"
        );
        ensure!(
            self.protocol_limits
                == (ProtocolLimits {
                    factory_min_participant_count: FACTORY_MIN_PARTICIPANTS as u32,
                    factory_max_participant_count: FACTORY_MAX_PARTICIPANTS as u32,
                    max_children_per_transaction: FACTORY_MULTI_ASSET_MAX_CHILDREN as u32,
                    max_vaults_per_state: MULTI_ASSET_MAX_VAULTS as u32,
                    max_metadata_rights_per_transition: FACTORY_TRANSITION_MAX_RIGHTS as u32,
                    max_physical_claims_per_transition: FACTORY_REDUCED_RELEASE_MAX_RIGHTS as u32,
                    compact_proof_depth: FACTORY_SPARSE_MERKLE_DEPTH as u32,
                    max_siblings_per_compact_proof: FACTORY_COMPACT_PROOF_MAX_SIBLINGS as u32,
                }),
            "protocol_limits must match the executable parser/consensus maxima; they are not experiment admission"
        );
        ensure!(
            self.qualification.phase == "B_controlled_devnet_local"
                && !self.qualification.release_admitted
                && !self.qualification.production_allowed
                && self.qualification.pending_evidence_issues.is_empty()
                && self.qualification.exact_release_evidence_status
                    == "exact_local_candidate_verification_required"
                && !self.qualification.joint_protocol_maxima_native_qualified,
            "local controlled-devnet qualification requires exact candidate verification and cannot authorize publication, production or joint protocol maxima"
        );
        ensure!(
            self.qualification.request_shape_enforcement == "exact_request_and_durable_admission",
            "controlled-devnet operations require exact request and durable admission enforcement"
        );
        ensure!(
            self.qualification.contract_manifest == "release/factory-preproduction/contracts.json"
                && self.qualification.acceptance_budget_profile
                    == "docs/devnet-smoke-budget.example.json",
            "qualification must name the current contract identity manifest and native acceptance budget profile; validating this policy does not verify those artifacts"
        );
        ensure!(
            self.factory.participant_count == 2
                && self.factory.asset_scope == "plain_ckb_only"
                && self.factory.reduced_right_counts == [1, 4, 10]
                && self.factory.max_children_per_transaction == 1
                && self.factory.max_vaults_per_state == 1,
            "Factory experiment shape is two members, one plain-CKB Vault, one child per transaction and declared 1/4/10-right updates"
        );
        ensure!(
            (1..=MULTI_ASSET_MAX_VAULTS as u32).contains(&self.channel.max_vaults_per_state)
                && self.channel.asset_scope == "ckb_and_manifest_pinned_devnet_xudt",
            "bilateral experiment shape is at most eight Vaults with CKB and identity-pinned devnet xUDT only"
        );
        ensure!(
            self.operator_requirements.lifetime_child_cap_mode
                == "operator_admission_ledger_no_chain_counter"
                && self.operator_requirements.complete_rights_snapshot_required
                && self
                    .operator_requirements
                    .replacement_snapshot_delivery_required
                && self
                    .operator_requirements
                    .payout_and_retained_floor_geometry_required
                && self
                    .operator_requirements
                    .independent_carrier_and_fee_funding_required,
            "operator admission requires a lifetime child ledger, complete proof data, delivered replacement snapshots, payout/retained-floor geometry and independently funded carriers/fees"
        );
        ensure!(
            (1..=MAX_ACTIVE_FACTORIES).contains(&self.factory.max_active_factories),
            "max_active_factories exceeds the reviewed pilot cap {MAX_ACTIVE_FACTORIES}"
        );
        ensure!(
            (1..=MAX_CHILDREN_PER_FACTORY).contains(&self.factory.max_children_per_factory),
            "max_children_per_factory exceeds the operator lifetime cap {MAX_CHILDREN_PER_FACTORY}"
        );
        ensure_nonzero_at_most(
            self.factory.max_capacity_shannons,
            MAX_FACTORY_CAPACITY_SHANNONS,
            "factory max_capacity_shannons",
        )?;
        ensure_nonzero_at_most(
            self.channel.max_capacity_shannons,
            MAX_CHANNEL_CAPACITY_SHANNONS,
            "channel max_capacity_shannons",
        )?;
        ensure!(
            self.channel.max_capacity_shannons <= self.factory.max_capacity_shannons,
            "channel cap must not exceed factory cap"
        );
        ensure!(
            self.conditional_batch.enabled,
            "conditional batch profile must be explicitly enabled"
        );
        ensure!(
            self.conditional_batch.asset_scope == "ckb_and_manifest_pinned_devnet_xudt"
                && self.conditional_batch.max_batches
                    == morph_script_common::multi_asset::MULTI_ASSET_MAX_VAULTS as u32,
            "conditional batches must use the bounded admitted Vault asset set"
        );
        ensure!(
            self.conditional_batch.max_transfers == CONDITIONAL_TRANSFER_MAX_COUNT as u32,
            "conditional max_transfers must match the executable bound {}",
            CONDITIONAL_TRANSFER_MAX_COUNT
        );
        ensure!(
            (1..=MAX_CONDITIONAL_REFUND_BLOCK_DELTA)
                .contains(&self.conditional_batch.max_refund_block_delta),
            "conditional max_refund_block_delta exceeds reviewed cap {MAX_CONDITIONAL_REFUND_BLOCK_DELTA}"
        );
        ensure!(
            self.conditional_batch.allowed_hash_algorithms == ["ckb_blake2b", "sha256"],
            "conditional hash algorithms must be ckb_blake2b and sha256"
        );
        ensure_nonzero_at_most(
            self.channel.max_total_pilot_capacity_shannons,
            MAX_TOTAL_PILOT_CAPACITY_SHANNONS,
            "pilot max_total_pilot_capacity_shannons",
        )?;
        ensure!(
            self.channel.max_total_pilot_capacity_shannons >= self.factory.max_capacity_shannons,
            "total pilot cap must cover one permitted factory"
        );
        ensure_nonzero_at_most(
            self.sponsor.max_capacity_shannons,
            MAX_SPONSOR_CAPACITY_SHANNONS,
            "sponsor max_capacity_shannons",
        )?;
        ensure_nonzero_at_most(
            self.sponsor.max_fee_per_transaction_shannons,
            MAX_FEE_PER_TRANSACTION_SHANNONS,
            "sponsor max_fee_per_transaction_shannons",
        )?;
        ensure!(
            self.sponsor.max_fee_per_transaction_shannons <= self.sponsor.max_capacity_shannons,
            "sponsor fee cap must not exceed sponsor capacity cap"
        );
        ensure!(
            self.xudt.allowed_scripts == ["morph-devnet-xudt"],
            "only morph-devnet-xudt is admitted in the current envelope"
        );
        ensure!(
            self.xudt.max_asset_types_per_factory == 0 && self.xudt.max_units_per_factory == 0,
            "the declared Factory experiment is plain CKB; Factory token rights, including zero-quantity rights, are not admitted"
        );
        ensure!(
            (1..=self.channel.max_vaults_per_state)
                .contains(&self.xudt.max_asset_types_per_channel)
                && (1..=MAX_DEVNET_XUDT_UNITS_PER_CHANNEL)
                    .contains(&self.xudt.max_units_per_type_per_channel),
            "bilateral devnet xUDT admission exceeds its declared Vault or unit cap"
        );
        ensure!(
            self.xudt.identity_rule == "exact_type_hash_allowlist_and_manifest_code_hash"
                && self.xudt.zero_quantity_rights_require_admission,
            "every token identity, including zero-quantity committed rights, requires exact Type-hash admission and manifest code identity; a script name is insufficient"
        );
        ensure!(
            self.watchtower.minimum_detection_depth >= MIN_WATCHTOWER_DETECTION_DEPTH,
            "watchtower detection depth must be at least {MIN_WATCHTOWER_DETECTION_DEPTH}"
        );
        ensure!(
            self.watchtower.reorg_mode == "detect_reset_and_rescan",
            "watchtower reorg_mode must require canonical cursor reset and rescan"
        );
        ensure!(
            self.watchtower.restart_scan_floor_required,
            "watchtower configuration must retain an explicit rescan floor"
        );
        ensure!(
            !self.watchtower.independent_operator_required,
            "independent-operator qualification is outside the local controlled-devnet envelope"
        );
        Ok(())
    }
}

/// Identify the exact local admission policy and verified eight-script build.
/// This is an operator identity check, not release qualification: fresh source,
/// CI, native reports and the local bundle are verified separately by the
/// candidate workflow. In particular it cannot attest independent operation.
pub(crate) fn verify_admission_identity(
    envelope_path: &Path,
    contracts_dir: &Path,
) -> Result<morph_core::Bytes32> {
    let envelope_bytes = fs::read(envelope_path).context("cannot read admission envelope")?;
    ensure!(
        envelope_bytes.len() <= 1024 * 1024,
        "admission envelope is oversized"
    );
    let envelope: PreproductionEnvelope =
        serde_json::from_slice(&envelope_bytes).context("invalid admission envelope")?;
    envelope.validate()?;
    let manifest_path = envelope_path.with_file_name("contracts.json");
    crate::release::verify_contract_manifest(&manifest_path, contracts_dir)?;
    let manifest_bytes =
        fs::read(&manifest_path).context("cannot read admission contract manifest")?;
    let mut bytes = b"MORPH_LOCAL_ADMISSION_POLICY_AND_ELFS_V1".to_vec();
    bytes.extend_from_slice(&(envelope_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&envelope_bytes);
    bytes.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&manifest_bytes);
    Ok(morph_core::blake2b256(&bytes))
}

pub fn verify_preproduction_envelope(path: &Path) -> Result<PreproductionEnvelopeVerification> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read pre-production envelope {}", path.display()))?;
    let envelope: PreproductionEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse pre-production envelope {}", path.display()))?;
    envelope
        .validate()
        .with_context(|| format!("invalid pre-production envelope {}", path.display()))?;
    Ok(PreproductionEnvelopeVerification {
        schema: "morph.preproduction_envelope_verification.v2",
        envelope_path: path.display().to_string(),
        release_profile: envelope.release_profile,
        approved_networks: envelope.approved_networks,
        real_assets_allowed: envelope.real_assets_allowed,
        factory_min_participant_count: envelope.factory.participant_count,
        factory_max_participant_count: envelope.factory.participant_count,
        protocol_limits: envelope.protocol_limits,
        qualification: envelope.qualification,
        policy_verified: true,
        release_admitted: false,
        max_active_factories: envelope.factory.max_active_factories,
        reorg_mode: envelope.watchtower.reorg_mode,
    })
}

fn ensure_nonzero_at_most(value: u64, maximum: u64, label: &str) -> Result<()> {
    ensure!(value > 0, "{label} must be non-zero");
    ensure!(value <= maximum, "{label} exceeds reviewed cap {maximum}");
    Ok(())
}

fn is_iso_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PreproductionEnvelope {
        let mut envelope: PreproductionEnvelope = serde_json::from_str(include_str!(
            "../../../release/factory-preproduction/envelope.json"
        ))
        .unwrap();
        envelope.effective_unix = 1;
        envelope.review_by_unix = u64::MAX;
        envelope
    }

    #[test]
    fn accepts_local_devnet_rules_without_release_or_production_admission() {
        let envelope = fixture();
        envelope.validate_at(2).unwrap();
        assert_eq!(envelope.protocol_limits.factory_max_participant_count, 16);
        assert_eq!(envelope.protocol_limits.max_children_per_transaction, 4);
        assert_eq!(envelope.factory.participant_count, 2);
        assert_eq!(envelope.factory.max_children_per_transaction, 1);
        assert_eq!(envelope.channel.max_vaults_per_state, 8);
        assert!(!envelope.qualification.release_admitted);
    }

    fn rejects_mutation(field: &str, value: serde_json::Value, message: &str) {
        let mut envelope = serde_json::to_value(fixture()).unwrap();
        *envelope.pointer_mut(field).unwrap() = value;
        let envelope: PreproductionEnvelope = serde_json::from_value(envelope).unwrap();
        let error = envelope.validate_at(2).unwrap_err();
        assert!(error.to_string().contains(message), "{field}: {error:#}");
    }

    #[test]
    fn rejects_vm_maxima_as_factory_experiment_admission_and_undeclared_right_counts() {
        use serde_json::json;
        for (field, value) in [
            ("/factory/participant_count", json!(16)),
            ("/factory/max_children_per_transaction", json!(4)),
            ("/factory/max_vaults_per_state", json!(8)),
            ("/factory/asset_scope", json!("devnet_xudt")),
            ("/factory/reduced_right_counts", json!([1, 2, 4, 10])),
            ("/factory/reduced_right_counts", json!([])),
        ] {
            rejects_mutation(field, value, "Factory experiment shape");
        }
        rejects_mutation(
            "/protocol_limits/factory_max_participant_count",
            json!(2),
            "parser/consensus maxima",
        );
    }

    #[test]
    fn rejects_token_admission_by_name_zero_quantity_or_foreign_identity() {
        use serde_json::json;
        for (field, value, message) in [
            (
                "/xudt/allowed_scripts",
                json!(["external_xudt"]),
                "only morph-devnet-xudt",
            ),
            (
                "/xudt/identity_rule",
                json!("script_name_only"),
                "exact Type-hash admission",
            ),
            (
                "/xudt/zero_quantity_rights_require_admission",
                json!(false),
                "zero-quantity",
            ),
            // A zero unit ceiling cannot admit a token identity into the
            // plain-CKB Factory experiment, including a future zero claim.
            (
                "/xudt/max_asset_types_per_factory",
                json!(1),
                "zero-quantity rights",
            ),
            (
                "/xudt/max_asset_types_per_channel",
                json!(9),
                "bilateral devnet xUDT admission",
            ),
            (
                "/qualification/contract_manifest",
                json!("release/foreign/contracts.json"),
                "current contract identity manifest",
            ),
        ] {
            rejects_mutation(field, value, message);
        }
    }

    #[test]
    fn rejects_premature_release_approval_and_weaker_operator_obligations() {
        use serde_json::json;
        for (field, value) in [
            ("/qualification/release_admitted", json!(true)),
            ("/qualification/production_allowed", json!(true)),
            (
                "/qualification/pending_evidence_issues",
                json!([22, 28, 27]),
            ),
            (
                "/qualification/exact_release_evidence_status",
                json!("passed"),
            ),
            (
                "/qualification/joint_protocol_maxima_native_qualified",
                json!(true),
            ),
        ] {
            rejects_mutation(field, value, "local controlled-devnet qualification");
        }
        rejects_mutation(
            "/qualification/request_shape_enforcement",
            json!("enforced"),
            "require exact request and durable admission",
        );
        for (field, value) in [
            (
                "/operator_requirements/lifetime_child_cap_mode",
                json!("on_chain_counter"),
            ),
            (
                "/operator_requirements/complete_rights_snapshot_required",
                json!(false),
            ),
            (
                "/operator_requirements/replacement_snapshot_delivery_required",
                json!(false),
            ),
            (
                "/operator_requirements/payout_and_retained_floor_geometry_required",
                json!(false),
            ),
            (
                "/operator_requirements/independent_carrier_and_fee_funding_required",
                json!(false),
            ),
        ] {
            rejects_mutation(field, value, "operator admission requires");
        }
    }

    #[test]
    fn rejects_missing_declarations_unknown_fields_and_previous_policy_shape() {
        for field in ["protocol_limits", "qualification", "operator_requirements"] {
            let mut value = serde_json::to_value(fixture()).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<PreproductionEnvelope>(value).is_err());
        }
        for object in ["", "/factory", "/qualification", "/xudt"] {
            let mut value = serde_json::to_value(fixture()).unwrap();
            value
                .pointer_mut(object)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("undeclared_scope".to_string(), serde_json::json!(true));
            assert!(serde_json::from_value::<PreproductionEnvelope>(value).is_err());
        }
        rejects_mutation(
            "/schema",
            serde_json::json!("morph.preproduction_envelope"),
            "unsupported pre-production envelope schema",
        );
    }

    #[test]
    fn rejects_mainnet_or_real_assets() {
        let mut envelope = fixture();
        envelope.approved_networks = vec!["mainnet".to_string()];
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("devnet")
        );

        let mut envelope = fixture();
        envelope.real_assets_allowed = true;
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("real assets")
        );
    }

    #[test]
    fn rejects_unsupported_factory_shape_and_caps() {
        let mut envelope = fixture();
        envelope.factory.participant_count += 1;
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("Factory experiment shape")
        );

        let mut envelope = fixture();
        envelope.factory.max_active_factories = MAX_ACTIVE_FACTORIES + 1;
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("max_active_factories")
        );
    }

    #[test]
    fn rejects_missing_reorg_recovery() {
        let mut envelope = fixture();
        envelope.watchtower.reorg_mode = "best_effort".to_string();
        assert!(
            envelope
                .validate_at(2)
                .unwrap_err()
                .to_string()
                .contains("reorg_mode")
        );
    }

    #[test]
    fn rejects_an_expired_or_not_yet_effective_envelope() {
        let envelope = fixture();
        assert!(
            envelope
                .validate_at(0)
                .unwrap_err()
                .to_string()
                .contains("not effective")
        );

        let mut envelope = fixture();
        envelope.review_by_unix = 3;
        assert!(
            envelope
                .validate_at(4)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
    }
}
