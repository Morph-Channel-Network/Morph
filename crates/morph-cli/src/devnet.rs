#[cfg(feature = "devnet")]
use crate::canonical_fields::canonical_hex32;
use crate::watch_cursor::WatchCursor;
#[cfg(feature = "devnet")]
use crate::watch_cursor::{read_watch_cursor, write_watch_cursor};
#[cfg(feature = "devnet")]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use ckb_crypto::secp::Privkey;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::Status;
use ckb_types::{
    H256,
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionBuilder},
    packed::{CellDep, CellInput, CellOutput, OutPoint, OutPointVec, Script, WitnessArgs},
    prelude::*,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
#[cfg(feature = "devnet")]
use morph_core::{
    ParticipantSignature, VaultAsset, participants_commitment as core_participants_commitment,
};
#[cfg(any(feature = "devnet", test))]
use morph_script_common::SponsorPolicy as WireSponsorPolicy;
#[cfg(feature = "devnet")]
use morph_script_common::blake2b256 as script_blake2b256;
use morph_script_common::{
    BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN, ECDSA_SIGNATURE_LEN, PHASE_ACTIVE, PHASE_SETTLING,
    SPONSOR_POLICY_LEN, ScriptError,
};
use serde::Serialize;

use crate::publication::{
    FeeObservation, PublicationAttemptInput, PublicationProfile, append_publication_attempt,
    publication_attempt_record, replacement_fee, required_replacement_fee_from_error,
};
#[cfg(feature = "devnet")]
use crate::publication::{
    fee_for_rate, initial_fee_rate, read_publication_profile, reconcile_publication_attempts,
    verify_initial_fee_convergence,
};
use crate::rpc::CkbRpcClient;
#[cfg(feature = "devnet")]
use crate::watch_alert::append_watchtower_alert;
use crate::watch_alert::{WatchAlertEvent, WatchAlertSeverity, WatchtowerAlert};

use crate::multi_asset_funding::SECP_TYPE_HASH as DEFAULT_SECP_TYPE_HASH;
#[cfg(feature = "devnet")]
pub mod factory_acceptance;
#[cfg(feature = "devnet")]
pub mod factory_child_acceptance;
#[cfg(feature = "devnet")]
pub mod factory_operator;
#[cfg(feature = "devnet")]
pub mod factory_transitions_acceptance;
#[cfg(feature = "devnet")]
pub mod multi_asset;
#[cfg(feature = "devnet")]
pub mod multi_asset_funding_operator;
#[cfg(feature = "devnet")]
pub mod multi_asset_operator;
#[cfg(feature = "devnet")]
pub mod multi_asset_root_operator;
#[cfg(feature = "devnet")]
pub mod multi_asset_splice_acceptance;
#[cfg(feature = "devnet")]
pub mod multi_asset_splice_operator;
#[cfg(feature = "devnet")]
pub mod multi_asset_watch;
pub const DEFAULT_SPONSOR_MIN_STATE_NUMBER: u64 = 1;
pub const DEFAULT_SPONSOR_MAX_STATE_NUMBER: u64 = 1 << 20;
const CONTRACTS: [(&str, &str); 8] = [
    ("morph-state-lock", "morph-state-lock"),
    ("morph-state-type", "morph-state-type"),
    ("morph-factory-type", "morph-factory-type"),
    ("morph-factory-vault-lock", "morph-factory-vault-lock"),
    ("morph-vault-lock", "morph-vault-lock"),
    ("morph-batch-lock", "morph-batch-lock"),
    ("morph-sponsor-lock", "morph-sponsor-lock"),
    ("morph-devnet-xudt", "morph-devnet-xudt"),
];

#[derive(Debug, Clone)]
pub struct DeployContractsOptions {
    pub contracts_dir: PathBuf,
    pub private_key: morph_key_input::SecretString,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
struct PublicationRuntime {
    profile: PublicationProfile,
    attempt_log: Option<PathBuf>,
    deadline: Instant,
    intent_id: String,
    channel_id: String,
    funding_context_id: String,
    target_state_number: u64,
}

#[derive(Debug, Clone)]
pub struct FundSponsorOptions {
    pub contracts_dir: PathBuf,
    pub private_key: morph_key_input::SecretString,
    pub sponsor_change_pubkey: Option<String>,
    pub state_out_point: String,
    pub sponsor_capacity: u64,
    pub sponsor_min_state_number: u64,
    pub sponsor_max_state_number: u64,
    pub strict_sponsor_range: bool,
    pub sponsor_max_fee_per_tx: Option<u64>,
    pub sponsor_max_total_fee: Option<u64>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone, Copy)]
struct SponsorPolicySettings {
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: u64,
    max_total_fee: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionMetrics {
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SponsorPolicyReport {
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub max_fee_per_tx: u64,
    pub max_total_fee: u64,
    pub already_spent: u64,
    pub publication_state_type_hash: String,
    pub change_lock_hash: String,
}

#[derive(Debug, Serialize)]
pub struct DeployContractsReport {
    pub tx_hash: String,
    pub input_capacity: u64,
    pub deployed_capacity: u64,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub transactions: Vec<DeployContractTransactionReport>,
    pub scripts: Vec<DeployedScriptReport>,
}

#[derive(Debug, Serialize)]
pub struct DeployContractTransactionReport {
    pub tx_hash: String,
    pub input_capacity: u64,
    pub deployed_capacity: u64,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub script_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeployedScriptReport {
    pub name: String,
    pub out_point: PrintableOutPoint,
    pub data_hash: String,
    pub hash_type: String,
    pub data_len: usize,
    pub capacity: u64,
}

#[derive(Debug, Serialize)]
pub struct PrintableOutPoint {
    pub tx_hash: String,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedStateCellReport {
    pub block_number: u64,
    pub block_hash: String,
    pub tx_hash: String,
    pub output_index: u32,
    pub out_point: String,
    pub funding_anchor: String,
    pub funding_context_id: String,
    pub vault_set_commitment: String,
    pub state_number: u64,
    pub phase: String,
    pub settlement_descriptor_commitment: String,
    pub descriptor_version: u16,
    pub confirmations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchReorgRecoveryReport {
    pub reason: String,
    pub cursor_scanned_to_block: u64,
    pub expected_block_hash: Option<String>,
    pub canonical_block_hash: Option<String>,
    pub reset_from_block: u64,
}

#[derive(Debug, Serialize)]
pub struct FundSponsorReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub state_number: u64,
    pub sponsor_out_point: PrintableOutPoint,
    pub sponsor_capacity: u64,
    pub sponsor_policy: SponsorPolicyReport,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptFailureReport {
    pub source: Option<String>,
    pub error_code: Option<i16>,
    pub morph_error: Option<String>,
    pub raw: String,
}

struct LiveCell {
    out_point: OutPoint,
    capacity: u64,
}

pub(crate) struct LiveCellDetails {
    pub(crate) output: CellOutput,
    pub(crate) data: Bytes,
    pub(crate) capacity: u64,
}

struct SentTransactionReport {
    tx_hash: String,
    status: String,
    block_number: Option<u64>,
    block_hash: Option<String>,
    metrics: TransactionMetrics,
    mined_blocks: Vec<String>,
}

struct PublicationSentReport {
    report: SentTransactionReport,
    fee: u64,
    canonical_confirmed: bool,
}

struct ContractBinary {
    name: String,
    data: Bytes,
    data_hash: H256,
    capacity: u64,
    output: CellOutput,
}

struct ContractTarget {
    name: String,
    data_hash: H256,
    type_hash: Option<H256>,
}

#[derive(Debug, Clone)]
struct ResolvedContract {
    name: String,
    data_hash: H256,
    out_point: OutPoint,
    cell_dep: CellDep,
}

#[derive(Debug, Clone)]
struct StateCellDetectionFilter {
    state_type_code_hash: H256,
    state_lock_code_hash: H256,
}

pub fn deploy_contracts(
    rpc: &CkbRpcClient,
    options: DeployContractsOptions,
) -> Result<DeployContractsReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let privkey = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for devnet deploy")?;
    let owner_lock = secp256k1_lock(&privkey)?;
    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let mut funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = load_contracts(&options.contracts_dir, &owner_lock)?;
    ensure!(
        !contracts.is_empty(),
        "no contracts configured for deployment"
    );
    let input_capacity = funding_cell.capacity;

    let deployed_capacity = contracts
        .iter()
        .try_fold(0u64, |acc, contract| acc.checked_add(contract.capacity))
        .ok_or_else(|| anyhow!("deployed capacity overflow"))?;
    let total_fee = (contracts.len() as u64)
        .checked_mul(options.fee)
        .ok_or_else(|| anyhow!("deployment fee overflow"))?;
    let final_change_capacity = input_capacity
        .checked_sub(deployed_capacity)
        .and_then(|value| value.checked_sub(total_fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover deployed capacity {} and total fee {}",
                input_capacity,
                deployed_capacity,
                total_fee
            )
        })?;
    ensure_change_capacity(&owner_lock, final_change_capacity)?;

    let mut transactions = Vec::with_capacity(contracts.len());
    let mut scripts = Vec::with_capacity(contracts.len());
    let mut all_mined_blocks = Vec::new();

    for contract in contracts {
        let change_capacity = funding_cell
            .capacity
            .checked_sub(contract.capacity)
            .and_then(|value| value.checked_sub(options.fee))
            .ok_or_else(|| {
                anyhow!(
                    "funding cell capacity {} cannot deploy {} capacity {} and fee {}",
                    funding_cell.capacity,
                    contract.name,
                    contract.capacity,
                    options.fee
                )
            })?;
        ensure_change_capacity(&owner_lock, change_capacity)?;

        let unsigned = build_deploy_transaction(
            &funding_cell,
            secp_dep.clone(),
            &owner_lock,
            std::slice::from_ref(&contract),
            change_capacity,
        );
        let signed = sign_single_secp_input(unsigned, &privkey)?;
        let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
        all_mined_blocks.extend(sent.mined_blocks.iter().cloned());

        let tx_hash = parse_h256(&sent.tx_hash)?;
        let tx_hash_string = sent.tx_hash.clone();
        scripts.push(DeployedScriptReport {
            name: contract.name.clone(),
            out_point: PrintableOutPoint {
                tx_hash: tx_hash_string.clone(),
                index: 0,
            },
            data_hash: format!("{:#x}", contract.data_hash),
            hash_type: "data1".to_string(),
            data_len: contract.data.len(),
            capacity: contract.capacity,
        });
        transactions.push(DeployContractTransactionReport {
            tx_hash: tx_hash_string,
            input_capacity: funding_cell.capacity,
            deployed_capacity: contract.capacity,
            change_capacity,
            fee: options.fee,
            metrics: sent.metrics.clone(),
            mined_blocks: sent.mined_blocks,
            status: sent.status.clone(),
            block_number: sent.block_number,
            block_hash: sent.block_hash.clone(),
            script_names: vec![contract.name],
        });
        funding_cell = LiveCell {
            out_point: OutPoint::new(tx_hash.pack(), 1),
            capacity: change_capacity,
        };
    }

    let last = transactions
        .last()
        .ok_or_else(|| anyhow!("no deployment transactions were produced"))?;

    Ok(DeployContractsReport {
        tx_hash: last.tx_hash.clone(),
        input_capacity,
        deployed_capacity,
        change_capacity: final_change_capacity,
        fee: total_fee,
        metrics: last.metrics.clone(),
        mined_blocks: all_mined_blocks,
        status: last.status.clone(),
        block_number: last.block_number,
        block_hash: last.block_hash.clone(),
        transactions,
        scripts,
    })
}

fn publication_runtime_budget_blocks(
    profile: &PublicationProfile,
    observed_confirmations: u64,
) -> Result<u64> {
    profile.validate()?;
    let remaining_blocks = profile
        .window
        .configured_challenge_blocks
        .checked_sub(observed_confirmations)
        .ok_or_else(|| {
            anyhow!(
                "observed stale StateCell already has {observed_confirmations} confirmations, beyond the configured {}-block challenge window",
                profile.window.configured_challenge_blocks
            )
        })?;
    ensure!(
        remaining_blocks > 0,
        "observed stale StateCell has no remaining challenge-window budget"
    );
    let recovery_reserve = profile
        .window
        .reorg_budget_blocks
        .checked_add(profile.window.failover_budget_blocks)
        .and_then(|value| value.checked_add(profile.window.safety_margin_blocks))
        .ok_or_else(|| anyhow!("publication recovery reserve overflow"))?;
    let runtime_blocks = remaining_blocks
        .checked_sub(recovery_reserve)
        .ok_or_else(|| {
            anyhow!(
                "observed stale StateCell leaves fewer than {recovery_reserve} reserved reorg/failover/safety blocks"
            )
        })?;
    ensure!(
        runtime_blocks > profile.window.canonical_confirmation_blocks,
        "observed stale StateCell leaves no execution time beyond the configured {} canonical-confirmation blocks",
        profile.window.canonical_confirmation_blocks
    );
    Ok(runtime_blocks)
}

fn publication_deadline(
    profile: &PublicationProfile,
    observed_confirmations: u64,
) -> Result<Instant> {
    let runtime_blocks = publication_runtime_budget_blocks(profile, observed_confirmations)?;
    let remaining_ms = runtime_blocks
        .checked_mul(profile.window.conservative_block_ms)
        .ok_or_else(|| anyhow!("publication challenge deadline overflow"))?;
    Instant::now()
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or_else(|| anyhow!("publication challenge deadline exceeds platform clock range"))
}

fn watch_cursor_for_state(
    channel_id: &str,
    from_block: u64,
    next_block: u64,
    scanned_to_block: u64,
    scanned_to_block_hash: Option<&str>,
    observed: Option<&ObservedStateCellReport>,
    previous_cursor: Option<&WatchCursor>,
) -> Result<WatchCursor> {
    let mut cursor = WatchCursor::new(channel_id, from_block, next_block, scanned_to_block)?;
    if let Some(block_hash) = scanned_to_block_hash {
        cursor = cursor.with_scanned_block_hash(block_hash)?;
    } else if let Some(previous_cursor) =
        previous_cursor.filter(|previous| previous.scanned_to_block == scanned_to_block)
    {
        cursor.scanned_to_block_hash = previous_cursor.scanned_to_block_hash.clone();
    }
    if let Some(observed) = observed {
        cursor.with_observed_context_state(
            &observed.funding_anchor,
            &observed.funding_context_id,
            observed.state_number,
            &observed.out_point,
        )
    } else if let Some(previous_cursor) = previous_cursor {
        cursor.current_funding_anchor = previous_cursor.current_funding_anchor.clone();
        cursor.current_funding_context_id = previous_cursor.current_funding_context_id.clone();
        cursor.last_observed_state_number = previous_cursor.last_observed_state_number;
        cursor.last_observed_out_point = previous_cursor.last_observed_out_point.clone();
        cursor.validate()?;
        Ok(cursor)
    } else {
        Ok(cursor)
    }
}

fn assess_watch_cursor_canonicality(
    rpc: &CkbRpcClient,
    cursor: &WatchCursor,
    reset_from_block: u64,
) -> Result<Option<WatchReorgRecoveryReport>> {
    let canonical_hash = canonical_block_hash(rpc, cursor.scanned_to_block)?;
    Ok(watch_reorg_recovery_if_needed(
        cursor.scanned_to_block,
        cursor.scanned_to_block_hash.as_deref(),
        canonical_hash.as_deref(),
        reset_from_block,
    ))
}

fn canonical_block_hash(rpc: &CkbRpcClient, block_number: u64) -> Result<Option<String>> {
    Ok(rpc
        .block_by_number(block_number)?
        .map(|block| format!("{:#x}", block.header.hash)))
}

fn watch_reorg_recovery_if_needed(
    cursor_scanned_to_block: u64,
    expected_block_hash: Option<&str>,
    canonical_block_hash: Option<&str>,
    reset_from_block: u64,
) -> Option<WatchReorgRecoveryReport> {
    if expected_block_hash.is_some() && expected_block_hash == canonical_block_hash {
        return None;
    }
    Some(watch_reorg_recovery(
        cursor_scanned_to_block,
        expected_block_hash,
        canonical_block_hash,
        reset_from_block,
    ))
}

fn watch_reorg_recovery(
    cursor_scanned_to_block: u64,
    expected_block_hash: Option<&str>,
    canonical_block_hash: Option<&str>,
    reset_from_block: u64,
) -> WatchReorgRecoveryReport {
    let reason = match (expected_block_hash, canonical_block_hash) {
        (None, _) => "cursor_missing_block_hash",
        (Some(_), None) => "cursor_block_missing",
        (Some(_), Some(_)) => "cursor_block_hash_mismatch",
    };
    WatchReorgRecoveryReport {
        reason: reason.to_string(),
        cursor_scanned_to_block,
        expected_block_hash: expected_block_hash.map(str::to_string),
        canonical_block_hash: canonical_block_hash.map(str::to_string),
        reset_from_block,
    }
}

fn reorg_alert(
    channel_id: &str,
    selected_state_number: u64,
    recovery: &WatchReorgRecoveryReport,
    context: &str,
) -> Result<WatchtowerAlert> {
    WatchtowerAlert::new(
        channel_id.to_string(),
        WatchAlertSeverity::Critical,
        WatchAlertEvent::ChainReorgDetected,
        format!(
            "{context}; reason={}, cursor_block={}, expected_hash={}, canonical_hash={}, resetting scan to {}",
            recovery.reason,
            recovery.cursor_scanned_to_block,
            recovery.expected_block_hash.as_deref().unwrap_or("missing"),
            recovery
                .canonical_block_hash
                .as_deref()
                .unwrap_or("missing"),
            recovery.reset_from_block
        ),
        selected_state_number,
        recovery.cursor_scanned_to_block,
        recovery.reset_from_block,
    )
}

pub fn fund_sponsor(rpc: &CkbRpcClient, options: FundSponsorOptions) -> Result<FundSponsorReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.sponsor_capacity > 0,
        "sponsor capacity must be non-zero"
    );
    if options.strict_sponsor_range {
        ensure_strict_sponsor_range(
            options.sponsor_min_state_number,
            options.sponsor_max_state_number,
        )?;
    }

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for sponsor funding")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let state_cell = load_canonical_live_cell(rpc, state_out_point)?;
    let header = morph_script_common::multi_asset::MultiAssetStateHeader::parse(&state_cell.data)
        .map_err(|error| anyhow!("invalid current publication State: {error:?}"))?;
    let (channel, funding_anchor, state_number) = (
        header.channel_id(),
        header.funding_anchor(),
        header.state_number(),
    );
    let state_type_hash: [u8; 32] = state_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("state cell does not carry a type script"))?
        .calc_script_hash()
        .unpack();

    let tip_number = rpc.tip_header()?.number_value()?;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let state_type = state_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("missing State type"))?;
    let type_args = state_type.args().raw_data();
    let args = morph_script_common::multi_asset::MultiAssetStateTypeArgs::parse(&type_args)
        .map_err(|error| anyhow!("invalid current StateType sponsor authority: {error:?}"))?;
    ensure!(
        args.funding_anchor() == funding_anchor
            && state_cell.output.lock().args().raw_data().as_ref() == state_type_hash,
        "sponsor funding State authority arguments are inconsistent"
    );

    let sponsor_binary = fs::read(options.contracts_dir.join("morph-sponsor-lock"))?;
    ensure!(
        !sponsor_binary.is_empty(),
        "approved sponsor artifact is empty"
    );
    let sponsor_template = data1_script(H256::from(blake2b_256(&sponsor_binary)), Bytes::new());
    let targets = vec![
        contract_target_for_script(&options.contracts_dir, "morph-state-type", &state_type)?,
        contract_target_for_script(
            &options.contracts_dir,
            "morph-state-lock",
            &state_cell.output.lock(),
        )?,
        contract_target_for_script(
            &options.contracts_dir,
            "morph-sponsor-lock",
            &sponsor_template,
        )?,
    ];
    let contracts = find_deployed_targets(rpc, targets, tip_number)?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    let sponsor_change_lock = if let Some(pubkey) = options.sponsor_change_pubkey.as_deref() {
        let pubkey = parse_compressed_pubkey_hex(pubkey, "sponsor change pubkey")?;
        secp256k1_lock_from_pubkey(&pubkey)?
    } else {
        owner_lock.clone()
    };
    let change_lock_hash = sponsor_change_lock.calc_script_hash();
    let channel_id: &[u8; 32] = channel
        .try_into()
        .map_err(|_| anyhow!("state header channel id is not 32 bytes"))?;
    let sponsor_policy_settings = sponsor_policy_settings(
        options.sponsor_capacity,
        options.sponsor_min_state_number,
        options.sponsor_max_state_number,
        options.sponsor_max_fee_per_tx,
        options.sponsor_max_total_fee,
    )?;
    let change_lock_hash_array: [u8; 32] = change_lock_hash.unpack();
    let sponsor_policy = sponsor_policy_bytes(
        channel_id,
        sponsor_policy_settings,
        state_type_hash,
        change_lock_hash_array,
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );
    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("sponsor", &sponsor_output, 0)?;

    let change_capacity = funding_cell
        .capacity
        .checked_sub(options.sponsor_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover sponsor {} and fee {}",
                funding_cell.capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .input(CellInput::new(funding_cell.out_point.clone(), 0))
        .output(sponsor_output)
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(owner_lock.clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_single_secp_input(unsigned, &owner_key)?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;

    Ok(FundSponsorReport {
        tx_hash: sent.tx_hash.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(channel),
        state_number,
        sponsor_out_point: PrintableOutPoint {
            tx_hash: sent.tx_hash,
            index: 0,
        },
        sponsor_capacity: options.sponsor_capacity,
        sponsor_policy: sponsor_policy_report(
            sponsor_policy_settings,
            state_type_hash,
            change_lock_hash_array,
        ),
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
    })
}

fn decode_hex_len(value: &str, byte_len: usize, label: &str) -> Result<Vec<u8>> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        stripped.len() == byte_len * 2,
        "{label} must be {byte_len} bytes"
    );
    let bytes = hex::decode(stripped).with_context(|| format!("{label} is not valid hex"))?;
    ensure!(bytes.len() == byte_len, "{label} must be {byte_len} bytes");
    Ok(bytes)
}

fn parse_compressed_pubkey_hex(
    value: &str,
    label: &str,
) -> Result<[u8; COMPRESSED_SECP256K1_PUBKEY_LEN]> {
    let bytes = decode_hex_len(value, COMPRESSED_SECP256K1_PUBKEY_LEN, label)?;
    k256::PublicKey::from_sec1_bytes(&bytes)
        .map_err(|_| anyhow!("{label} is not a valid secp256k1 public key"))?;
    let mut pubkey = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    pubkey.copy_from_slice(&bytes);
    Ok(pubkey)
}

fn build_deploy_transaction(
    funding_cell: &LiveCell,
    secp_dep: CellDep,
    owner_lock: &Script,
    contracts: &[ContractBinary],
    change_capacity: u64,
) -> ckb_types::core::TransactionView {
    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .input(CellInput::new(funding_cell.out_point.clone(), 0));

    for contract in contracts {
        builder = builder
            .output(contract.output.clone())
            .output_data(contract.data.clone().pack());
    }

    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();

    builder
        .output(change_output)
        .output_data(Bytes::new().pack())
        .build()
}

fn sign_single_secp_input(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
) -> Result<ckb_types::core::TransactionView> {
    sign_single_secp_input_with_optional_input_type(tx, privkey, None)
}

fn sign_single_secp_input_with_optional_input_type(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Option<Bytes>,
) -> Result<ckb_types::core::TransactionView> {
    let unsigned_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .input_type(input_type.clone().pack())
        .build();
    let message = sighash_all_message(tx.hash(), &[unsigned_witness.as_bytes()]);
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB transaction")?;
    let witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .input_type(input_type.pack())
        .build();
    Ok(tx.as_advanced_builder().witness(witness.as_bytes()).build())
}

fn send_and_mine(
    rpc: &CkbRpcClient,
    tx: ckb_types::core::TransactionView,
    mine_blocks: u64,
) -> Result<SentTransactionReport> {
    let metrics = transaction_metrics(rpc, &tx)?;
    send_preflighted_and_mine(rpc, tx, mine_blocks, metrics)
}

/// The caller has just verified these exact witnesses and checked its
/// canonical checkpoint. Preserve that VM result across submission.
fn send_preflighted_and_mine(
    rpc: &CkbRpcClient,
    tx: ckb_types::core::TransactionView,
    mine_blocks: u64,
    metrics: TransactionMetrics,
) -> Result<SentTransactionReport> {
    let tx_hash = tx.hash();
    let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
    let sent_hash = rpc.send_transaction(json_tx)?;
    ensure!(
        sent_hash == tx_hash.clone().into(),
        "node returned tx hash {sent_hash:#x}, but locally built {:#x}",
        H256::from(tx_hash)
    );

    let status = if mine_blocks > 0 {
        let mined = mine_blocks_until_committed(rpc, sent_hash.clone(), mine_blocks)?;
        return Ok(SentTransactionReport {
            tx_hash: format!("{sent_hash:#x}"),
            status: format!("{:?}", mined.status.tx_status.status),
            block_number: mined
                .status
                .tx_status
                .block_number
                .map(|number| number.value()),
            block_hash: mined
                .status
                .tx_status
                .block_hash
                .map(|hash| format!("{hash:#x}")),
            metrics,
            mined_blocks: mined.blocks,
        });
    } else {
        rpc.transaction(sent_hash.clone())?
    };

    Ok(SentTransactionReport {
        tx_hash: format!("{sent_hash:#x}"),
        status: format!("{:?}", status.tx_status.status),
        block_number: status.tx_status.block_number.map(|number| number.value()),
        block_hash: status.tx_status.block_hash.map(|hash| format!("{hash:#x}")),
        metrics,
        mined_blocks: Vec::new(),
    })
}

fn transaction_confirmations(rpc: &CkbRpcClient, report: &SentTransactionReport) -> Result<u64> {
    if report.status != "Committed" {
        return Ok(0);
    }
    let block_number = report
        .block_number
        .context("committed transaction report has no block number")?;
    let block_hash = report
        .block_hash
        .as_deref()
        .context("committed transaction report has no block hash")?;
    let canonical = rpc
        .block_by_number(block_number)?
        .context("committed transaction block is no longer canonical")?;
    ensure!(
        format!("{:#x}", canonical.header.hash) == block_hash,
        "committed transaction block {block_hash} is no longer canonical"
    );
    let tip_number = rpc.tip_header()?.number_value()?;
    Ok(tip_number.saturating_sub(block_number).saturating_add(1))
}

fn send_publication_attempts<F>(
    rpc: &CkbRpcClient,
    initial_tx: ckb_types::core::TransactionView,
    initial_fee: u64,
    mine_blocks: u64,
    runtime: &PublicationRuntime,
    observation: &FeeObservation,
    build_transaction: &F,
) -> Result<PublicationSentReport>
where
    F: Fn(u64) -> Result<ckb_types::core::TransactionView>,
{
    runtime.profile.validate()?;
    let initial_metrics = transaction_metrics(rpc, &initial_tx)?;
    let mut tx = initial_tx;
    let mut fee = initial_fee;
    let mut replaces_tx_hash = None;
    let started = Instant::now();

    for attempt in 1..=runtime.profile.fee.max_attempts {
        ensure!(
            Instant::now() < runtime.deadline,
            "publication challenge deadline expired before attempt {attempt}"
        );
        let tx_size_bytes = tx.data().as_slice().len();
        let tx_hash = H256::from(tx.hash());
        let tx_hash_string = format!("{tx_hash:#x}");
        append_publication_attempt_if_requested(
            rpc,
            runtime,
            attempt,
            fee,
            tx_size_bytes,
            tx_hash_string.clone(),
            replaces_tx_hash.clone(),
            None,
            "built",
            None,
            observation,
            &started,
        )?;

        let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
        let sent_hash = match rpc.send_transaction(json_tx) {
            Ok(hash) => hash,
            Err(err) => {
                // A transport timeout, or a duplicate response after an internal
                // transport retry, does not prove that the node failed to accept
                // the transaction. Reconcile the locally known hash before
                // classifying the submission outcome.
                let observed_after_error = rpc.transaction(tx_hash.clone());
                if observed_after_error.as_ref().is_ok_and(|status| {
                    matches!(
                        status.tx_status.status,
                        Status::Pending | Status::Proposed | Status::Committed
                    )
                }) {
                    tx_hash.clone()
                } else {
                    let required_replacement_fee = required_replacement_fee_from_error(&err);
                    let failure_disposition = submission_failure_disposition(
                        required_replacement_fee,
                        observed_after_error
                            .as_ref()
                            .ok()
                            .map(|status| &status.tx_status.status),
                    );
                    let (authoritative_rejection, required_replacement_fee) =
                        match failure_disposition {
                            SubmissionFailureDisposition::ReplacementRequired(required_fee) => {
                                (true, Some(required_fee))
                            }
                            SubmissionFailureDisposition::ExplicitRejection => (true, None),
                            SubmissionFailureDisposition::Indeterminate => (false, None),
                        };
                    append_publication_attempt_if_requested(
                        rpc,
                        runtime,
                        attempt,
                        fee,
                        tx_size_bytes,
                        tx_hash_string,
                        replaces_tx_hash.clone(),
                        required_replacement_fee,
                        if authoritative_rejection {
                            "rejected"
                        } else {
                            "submission_unknown"
                        },
                        Some(if required_replacement_fee.is_some() {
                            "rbf_fee_too_low"
                        } else if authoritative_rejection {
                            "rpc_submission_rejected"
                        } else {
                            "rpc_submission_unknown"
                        }),
                        observation,
                        &started,
                    )?;
                    if let Some(required_fee) = required_replacement_fee
                        && attempt < runtime.profile.fee.max_attempts
                    {
                        fee = replacement_fee(
                            &runtime.profile.fee,
                            fee,
                            tx_size_bytes,
                            observation.pool_min_rbf_rate,
                            Some(required_fee),
                        )?;
                        tx = build_transaction(fee)?;
                        continue;
                    }
                    let reconciliation_context = observed_after_error
                        .err()
                        .map(|status_error| {
                            format!(
                                "; transaction-status reconciliation also failed: {status_error:#}"
                            )
                        })
                        .unwrap_or_default();
                    return Err(err).with_context(|| {
                        format!("publication transaction submission failed{reconciliation_context}")
                    });
                }
            }
        };
        ensure!(
            sent_hash == tx_hash,
            "node returned tx hash {sent_hash:#x}, but locally built {tx_hash:#x}"
        );

        let accepted = rpc.transaction(sent_hash.clone())?;
        let accepted_status = format!("{:?}", accepted.tx_status.status);
        append_publication_attempt_if_requested(
            rpc,
            runtime,
            attempt,
            fee,
            tx_size_bytes,
            format!("{sent_hash:#x}"),
            replaces_tx_hash.clone(),
            accepted.min_replace_fee.map(|value| value.value()),
            &accepted_status.to_ascii_lowercase(),
            None,
            observation,
            &started,
        )?;

        if mine_blocks > 0 {
            return wait_and_record_canonical_publication(
                rpc,
                runtime,
                attempt,
                fee,
                tx_size_bytes,
                sent_hash,
                replaces_tx_hash,
                observation,
                &started,
                mine_blocks,
                initial_metrics.estimated_cycles,
            );
        }
        match accepted.tx_status.status {
            Status::Rejected => {
                return Err(anyhow!(
                    "publication transaction {sent_hash:#x} rejected: {}",
                    accepted
                        .tx_status
                        .reason
                        .as_deref()
                        .unwrap_or("node did not report a rejection reason")
                ));
            }
            Status::Unknown => {
                return Err(anyhow!(
                    "publication transaction {sent_hash:#x} is unknown after submission"
                ));
            }
            Status::Proposed | Status::Committed => {
                return publication_report_from_status(
                    rpc,
                    sent_hash,
                    accepted,
                    fee,
                    tx_size_bytes,
                    initial_metrics.estimated_cycles,
                    runtime.profile.window.canonical_confirmation_blocks,
                );
            }
            Status::Pending if attempt == runtime.profile.fee.max_attempts => {
                return publication_report_from_status(
                    rpc,
                    sent_hash,
                    accepted,
                    fee,
                    tx_size_bytes,
                    initial_metrics.estimated_cycles,
                    runtime.profile.window.canonical_confirmation_blocks,
                );
            }
            Status::Pending => {}
        }

        let bump_delay = Duration::from_millis(runtime.profile.fee.bump_after_ms);
        ensure!(
            Instant::now()
                .checked_add(bump_delay)
                .is_some_and(|wake| wake < runtime.deadline),
            "publication retry delay would exceed the challenge deadline"
        );
        std::thread::sleep(bump_delay);
        let pending = rpc.transaction(sent_hash.clone())?;
        let pending_status = format!("{:?}", pending.tx_status.status);
        append_publication_attempt_if_requested(
            rpc,
            runtime,
            attempt,
            fee,
            tx_size_bytes,
            format!("{sent_hash:#x}"),
            replaces_tx_hash.clone(),
            pending.min_replace_fee.map(|value| value.value()),
            &pending_status.to_ascii_lowercase(),
            None,
            observation,
            &started,
        )?;
        if pending.tx_status.status != Status::Pending {
            return publication_report_from_status(
                rpc,
                sent_hash,
                pending,
                fee,
                tx_size_bytes,
                initial_metrics.estimated_cycles,
                runtime.profile.window.canonical_confirmation_blocks,
            );
        }
        let node_min_replace_fee = pending.min_replace_fee.map(|value| value.value());
        let next_fee = replacement_fee(
            &runtime.profile.fee,
            fee,
            tx_size_bytes,
            observation.pool_min_rbf_rate,
            node_min_replace_fee,
        )?;
        replaces_tx_hash = Some(format!("{sent_hash:#x}"));
        fee = next_fee;
        tx = build_transaction(fee)?;
    }

    Err(anyhow!("publication attempt loop ended without a result"))
}

fn publication_report_from_status(
    rpc: &CkbRpcClient,
    tx_hash: H256,
    status: ckb_jsonrpc_types::TransactionWithStatusResponse,
    fee: u64,
    tx_size_bytes: usize,
    estimated_cycles: u64,
    required_confirmations: u64,
) -> Result<PublicationSentReport> {
    if publication_status_disposition(&status.tx_status.status)
        == PublicationStatusDisposition::Failure
    {
        match status.tx_status.status {
            Status::Rejected => {
                return Err(anyhow!(
                    "publication transaction {tx_hash:#x} rejected: {}",
                    status
                        .tx_status
                        .reason
                        .as_deref()
                        .unwrap_or("node did not report a rejection reason")
                ));
            }
            Status::Unknown => {
                return Err(anyhow!(
                    "publication transaction {tx_hash:#x} is unknown after submission"
                ));
            }
            Status::Pending | Status::Proposed | Status::Committed => {
                unreachable!("non-failure status classified as a failure")
            }
        }
    }
    let report = SentTransactionReport {
        tx_hash: format!("{tx_hash:#x}"),
        status: format!("{:?}", status.tx_status.status),
        block_number: status.tx_status.block_number.map(|number| number.value()),
        block_hash: status.tx_status.block_hash.map(|hash| format!("{hash:#x}")),
        metrics: TransactionMetrics {
            estimated_cycles,
            tx_size_bytes,
        },
        mined_blocks: Vec::new(),
    };
    let canonical_confirmations = transaction_confirmations(rpc, &report)?;
    Ok(PublicationSentReport {
        report,
        fee,
        canonical_confirmed: canonical_confirmations >= required_confirmations,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationStatusDisposition {
    Nonterminal,
    CanonicalCandidate,
    Failure,
}

fn publication_status_disposition(status: &Status) -> PublicationStatusDisposition {
    match status {
        Status::Pending | Status::Proposed => PublicationStatusDisposition::Nonterminal,
        Status::Committed => PublicationStatusDisposition::CanonicalCandidate,
        Status::Rejected | Status::Unknown => PublicationStatusDisposition::Failure,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmissionFailureDisposition {
    ReplacementRequired(u64),
    ExplicitRejection,
    Indeterminate,
}

fn submission_failure_disposition(
    required_replacement_fee: Option<u64>,
    observed_status: Option<&Status>,
) -> SubmissionFailureDisposition {
    if let Some(required_fee) = required_replacement_fee {
        SubmissionFailureDisposition::ReplacementRequired(required_fee)
    } else if observed_status == Some(&Status::Rejected) {
        SubmissionFailureDisposition::ExplicitRejection
    } else {
        SubmissionFailureDisposition::Indeterminate
    }
}

struct CanonicalPublicationStatus {
    status: ckb_jsonrpc_types::TransactionWithStatusResponse,
    blocks: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn wait_and_record_canonical_publication(
    rpc: &CkbRpcClient,
    runtime: &PublicationRuntime,
    attempt: u16,
    fee: u64,
    tx_size_bytes: usize,
    sent_hash: H256,
    replaces_tx_hash: Option<String>,
    observation: &FeeObservation,
    started: &Instant,
    mine_blocks: u64,
    estimated_cycles: u64,
) -> Result<PublicationSentReport> {
    let confirmed = wait_for_canonical_publication(
        rpc,
        sent_hash.clone(),
        runtime.profile.window.canonical_confirmation_blocks,
        mine_blocks,
        runtime.deadline,
    )?;
    append_publication_attempt_if_requested(
        rpc,
        runtime,
        attempt,
        fee,
        tx_size_bytes,
        format!("{sent_hash:#x}"),
        replaces_tx_hash,
        confirmed.status.min_replace_fee.map(|value| value.value()),
        "committed",
        None,
        observation,
        started,
    )?;
    Ok(PublicationSentReport {
        report: SentTransactionReport {
            tx_hash: format!("{sent_hash:#x}"),
            status: format!("{:?}", confirmed.status.tx_status.status),
            block_number: confirmed
                .status
                .tx_status
                .block_number
                .map(|number| number.value()),
            block_hash: confirmed
                .status
                .tx_status
                .block_hash
                .map(|hash| format!("{hash:#x}")),
            metrics: TransactionMetrics {
                estimated_cycles,
                tx_size_bytes,
            },
            mined_blocks: confirmed.blocks,
        },
        fee,
        canonical_confirmed: true,
    })
}

fn wait_for_canonical_publication(
    rpc: &CkbRpcClient,
    tx_hash: H256,
    required_confirmations: u64,
    mine_blocks: u64,
    deadline: Instant,
) -> Result<CanonicalPublicationStatus> {
    ensure!(
        required_confirmations > 0,
        "canonical confirmation depth must be non-zero"
    );
    let mut blocks = Vec::new();
    loop {
        let status = rpc.transaction(tx_hash.clone())?;
        match status.tx_status.status {
            Status::Committed => {
                let block_number = status
                    .tx_status
                    .block_number
                    .as_ref()
                    .context("committed publication has no block number")?
                    .value();
                let block_hash = status
                    .tx_status
                    .block_hash
                    .as_ref()
                    .context("committed publication has no block hash")?;
                let canonical = rpc
                    .block_by_number(block_number)?
                    .context("committed publication block disappeared from the canonical chain")?;
                ensure!(
                    &canonical.header.hash == block_hash,
                    "committed publication block {block_hash:#x} is no longer canonical"
                );
                let tip_number = rpc.tip_header()?.number_value()?;
                let confirmations = tip_number.saturating_sub(block_number).saturating_add(1);
                if confirmations >= required_confirmations {
                    return Ok(CanonicalPublicationStatus { status, blocks });
                }
            }
            Status::Rejected => {
                return Err(anyhow!(
                    "publication transaction {tx_hash:#x} rejected: {}",
                    status
                        .tx_status
                        .reason
                        .as_deref()
                        .unwrap_or("node did not report a rejection reason")
                ));
            }
            Status::Unknown => {
                return Err(anyhow!(
                    "publication transaction {tx_hash:#x} is unknown; canonical confirmation cannot be established"
                ));
            }
            Status::Pending | Status::Proposed => {}
        }

        ensure!(
            Instant::now() < deadline,
            "publication transaction {tx_hash:#x} did not reach {required_confirmations} canonical confirmations before the challenge deadline"
        );
        if mine_blocks > 0 {
            for _ in 0..mine_blocks.max(1) {
                ensure!(
                    Instant::now() < deadline,
                    "publication challenge deadline expired while mining confirmations"
                );
                blocks.push(rpc.generate_block()?);
            }
        } else {
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(Duration::from_millis(500)));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn append_publication_attempt_if_requested(
    rpc: &CkbRpcClient,
    runtime: &PublicationRuntime,
    attempt: u16,
    fee: u64,
    tx_size_bytes: usize,
    tx_hash: String,
    replaces_tx_hash: Option<String>,
    node_min_replace_fee: Option<u64>,
    status: &str,
    error_class: Option<&str>,
    observation: &FeeObservation,
    started: &Instant,
) -> Result<()> {
    let Some(path) = runtime.attempt_log.as_ref() else {
        return Ok(());
    };
    let tip = rpc.tip_header()?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis())
        .context("publication attempt elapsed time exceeds u64")?;
    let record = publication_attempt_record(
        &runtime.profile,
        PublicationAttemptInput {
            fee_observation: observation.clone(),
            intent_id: runtime.intent_id.clone(),
            channel_id: runtime.channel_id.clone(),
            funding_context_id: runtime.funding_context_id.clone(),
            target_state_number: runtime.target_state_number,
            attempt,
            fee,
            tx_size_bytes,
            tx_hash,
            replaces_tx_hash,
            node_min_replace_fee,
            status: status.to_string(),
            error_class: error_class.map(str::to_string),
            elapsed_ms,
            tip_number: tip.number_value()?,
            tip_hash: tip.hash,
        },
    )?;
    append_publication_attempt(path, &record)
}

fn mine_relative_since_maturity(rpc: &CkbRpcClient, finalise_since: u64) -> Result<()> {
    for _ in 0..finalise_since {
        rpc.generate_block()?;
    }
    Ok(())
}

struct MinedTransactionStatus {
    status: ckb_jsonrpc_types::TransactionWithStatusResponse,
    blocks: Vec<String>,
}

fn mine_blocks_until_committed(
    rpc: &CkbRpcClient,
    tx_hash: H256,
    mine_blocks: u64,
) -> Result<MinedTransactionStatus> {
    let started = Instant::now();
    let timeout = Duration::from_secs(60);
    let batch = mine_blocks.max(1);
    let mut blocks = Vec::new();
    loop {
        for _ in 0..batch {
            blocks.push(rpc.generate_block()?);
            let status = rpc.transaction(tx_hash.clone())?;
            match status.tx_status.status {
                Status::Committed => return Ok(MinedTransactionStatus { status, blocks }),
                Status::Rejected => {
                    return Err(anyhow!(
                        "transaction {tx_hash:#x} rejected: {}",
                        status
                            .tx_status
                            .reason
                            .as_deref()
                            .unwrap_or("node did not report a rejection reason")
                    ));
                }
                _ => {}
            }
        }
        if started.elapsed() >= timeout {
            let status = rpc.transaction(tx_hash.clone())?;
            return Err(anyhow!(
                "timed out mining transaction {tx_hash:#x}; current status is {:?}",
                status.tx_status.status
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn transaction_metrics(
    rpc: &CkbRpcClient,
    tx: &ckb_types::core::TransactionView,
) -> Result<TransactionMetrics> {
    let json_tx: ckb_jsonrpc_types::Transaction = tx.data().into();
    let estimate = rpc.estimate_cycles(json_tx)?;
    Ok(TransactionMetrics {
        estimated_cycles: estimate.cycles.value(),
        tx_size_bytes: tx.data().as_slice().len(),
    })
}

struct StateObservation<'a> {
    channel_id: &'a [u8],
    funding_anchor: &'a [u8],
    vault_set_commitment: &'a [u8],
    state_number: u64,
    phase: u8,
    settlement_descriptor_commitment: &'a [u8],
    descriptor_version: u16,
}

fn parse_state_observation(
    raw: &[u8],
) -> std::result::Result<(StateObservation<'_>, String), ScriptError> {
    let header = morph_script_common::multi_asset::MultiAssetStateHeader::parse(raw)?;
    if !header.vaults_are_bound() {
        return Err(ScriptError::VaultActivationInvalid);
    }
    Ok((
        StateObservation {
            channel_id: header.channel_id(),
            funding_anchor: header.funding_anchor(),
            vault_set_commitment: header.content_root(),
            state_number: header.state_number(),
            phase: header.phase(),
            settlement_descriptor_commitment: header.settlement_descriptor_commitment(),
            descriptor_version: header.descriptor_version(),
        },
        hex32(&header.funding_context_id()?),
    ))
}

fn live_state_is_settling(rpc: &CkbRpcClient, point: OutPoint) -> Result<bool> {
    let live = rpc.canonical_live_cell(point.into(), true)?;
    if live.status != "live" {
        return Ok(false);
    }
    let data = live
        .cell
        .ok_or_else(|| anyhow!("canonical State cell missing"))?
        .data
        .ok_or_else(|| anyhow!("canonical State data missing"))?
        .content;
    let (header, _) = parse_state_observation(data.as_bytes())
        .map_err(|error| anyhow!("invalid cached State observation: {error:?}"))?;
    Ok(header.phase == PHASE_SETTLING)
}

fn stale_settling_state_requires_defense(
    observed: &ObservedStateCellReport,
    saved_number: u64,
) -> bool {
    observed.phase == "settling" && observed.state_number < saved_number
}

fn observed_state_cells(
    block: &ckb_jsonrpc_types::BlockView,
    channel_id: &str,
    tip_number: u64,
    filter: &StateCellDetectionFilter,
) -> Result<Vec<ObservedStateCellReport>> {
    let block_number = block.header.inner.number.value();
    let block_hash = format!("{:#x}", block.header.hash);
    let confirmations = block_confirmations(block_number, tip_number)?;
    let mut observed = Vec::new();
    for tx in &block.transactions {
        for (index, data) in tx.inner.outputs_data.iter().enumerate() {
            let Ok((header, context_id)) = parse_state_observation(data.as_bytes()) else {
                continue;
            };
            if hex32(header.channel_id) != channel_id {
                continue;
            }
            let Some(output) = tx.inner.outputs.get(index) else {
                continue;
            };
            let output: CellOutput = output.clone().into();
            if !is_authentic_observed_state_cell(&output, header.funding_anchor, filter) {
                continue;
            }
            let tx_hash = format!("{:#x}", tx.hash);
            observed.push(ObservedStateCellReport {
                block_number,
                block_hash: block_hash.clone(),
                tx_hash: tx_hash.clone(),
                output_index: index as u32,
                out_point: format!("{tx_hash}:{index}"),
                funding_anchor: hex32(header.funding_anchor),
                funding_context_id: context_id,
                vault_set_commitment: hex32(header.vault_set_commitment),
                state_number: header.state_number,
                phase: phase_label(header.phase).to_string(),
                settlement_descriptor_commitment: hex32(header.settlement_descriptor_commitment),
                descriptor_version: header.descriptor_version,
                confirmations,
            });
        }
    }
    Ok(observed)
}

fn block_confirmations(block_number: u64, tip_number: u64) -> Result<u64> {
    tip_number
        .checked_sub(block_number)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| {
            anyhow!("observed block {block_number} is above current canonical tip {tip_number}")
        })
}

fn is_authentic_observed_state_cell(
    output: &CellOutput,
    funding_anchor: &[u8],
    filter: &StateCellDetectionFilter,
) -> bool {
    let Some(type_script) = output.type_().to_opt() else {
        return false;
    };
    if !script_uses_data1_code_hash(&type_script, &filter.state_type_code_hash) {
        return false;
    }
    let type_args = type_script.args().raw_data();
    let Ok(args) = morph_script_common::multi_asset::MultiAssetStateTypeArgs::parse(&type_args)
    else {
        return false;
    };
    if args.funding_anchor() != funding_anchor {
        return false;
    }

    let lock = output.lock();
    if !script_uses_data1_code_hash(&lock, &filter.state_lock_code_hash) {
        return false;
    }
    let expected_lock_args: [u8; BYTE32_LEN] = type_script.calc_script_hash().unpack();
    lock.args().raw_data().as_ref() == expected_lock_args.as_slice()
}

fn type_bound_state_lock(state_lock_contract: &ResolvedContract, type_script: &Script) -> Script {
    data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(type_script.calc_script_hash().as_slice()),
    )
}

fn ensure_type_bound_state_lock(
    output: &CellOutput,
    type_script: &Script,
    state_lock_contract: &ResolvedContract,
    label: &str,
) -> Result<()> {
    ensure!(
        output.lock() == type_bound_state_lock(state_lock_contract, type_script),
        "{label} lock is not the deployed type-bound morph-state-lock"
    );
    Ok(())
}

fn script_uses_data1_code_hash(script: &Script, code_hash: &H256) -> bool {
    byte32_to_h256(script.code_hash()) == *code_hash
        && script.hash_type() == ScriptHashType::Data1.into()
}

fn phase_label(phase: u8) -> &'static str {
    match phase {
        PHASE_ACTIVE => "active",
        PHASE_SETTLING => "settling",
        _ => "unknown",
    }
}

fn sighash_all_message(
    tx_hash: ckb_types::packed::Byte32,
    witnesses: &[Bytes],
) -> ckb_crypto::secp::Message {
    let mut hasher = new_blake2b();
    hasher.update(tx_hash.as_slice());
    for witness in witnesses {
        let witness = witness.as_ref();
        let witness_len = witness.len() as u64;
        hasher.update(&witness_len.to_le_bytes());
        hasher.update(witness);
    }
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest.into()
}

fn load_contracts(contracts_dir: &Path, owner_lock: &Script) -> Result<Vec<ContractBinary>> {
    CONTRACTS
        .iter()
        .map(|(name, file_name)| {
            let path = contracts_dir.join(file_name);
            let data = fs::read(&path)
                .with_context(|| format!("failed to read contract binary {}", path.display()))?;
            ensure!(
                !data.is_empty(),
                "contract binary {} is empty",
                path.display()
            );
            let data_hash = H256::from(blake2b_256(&data));
            let data = Bytes::from(data);
            let output_for_capacity = CellOutput::new_builder().lock(owner_lock.clone()).build();
            let capacity = output_for_capacity
                .occupied_capacity(Capacity::bytes(data.len())?)?
                .as_u64();
            let output = CellOutput::new_builder()
                .capacity(capacity)
                .lock(owner_lock.clone())
                .build();
            Ok(ContractBinary {
                name: (*name).to_string(),
                data,
                data_hash,
                capacity,
                output,
            })
        })
        .collect()
}

fn load_contract_targets(contracts_dir: &Path) -> Result<Vec<ContractTarget>> {
    CONTRACTS
        .iter()
        .map(|(name, file_name)| {
            let path = contracts_dir.join(file_name);
            let data = fs::read(&path)
                .with_context(|| format!("failed to read contract binary {}", path.display()))?;
            ensure!(
                !data.is_empty(),
                "contract binary {} is empty",
                path.display()
            );
            Ok(ContractTarget {
                name: (*name).to_string(),
                data_hash: H256::from(blake2b_256(&data)),
                type_hash: None,
            })
        })
        .collect()
}

fn find_deployed_contracts(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    tip_number: u64,
) -> Result<Vec<ResolvedContract>> {
    find_deployed_targets(rpc, load_contract_targets(contracts_dir)?, tip_number)
}

fn contract_target_for_script(
    contracts_dir: &Path,
    name: &str,
    script: &Script,
) -> Result<ContractTarget> {
    let binary = fs::read(contracts_dir.join(name))?;
    ensure!(!binary.is_empty(), "approved contract artifact is empty");
    let data_hash = H256::from(blake2b_256(&binary));
    let type_hash = match script.hash_type().as_slice()[0] {
        0 | 2 | 4 => {
            ensure!(
                script.code_hash().as_slice() == data_hash.as_bytes(),
                "script does not match approved contract {name}"
            );
            None
        }
        1 => Some(byte32_to_h256(script.code_hash())),
        _ => return Err(anyhow!("unsupported script hash type")),
    };
    Ok(ContractTarget {
        name: name.to_string(),
        data_hash,
        type_hash,
    })
}

fn find_deployed_contract_by_script(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    name: &str,
    script: &Script,
    tip_number: u64,
) -> Result<ResolvedContract> {
    find_deployed_targets(
        rpc,
        vec![contract_target_for_script(contracts_dir, name, script)?],
        tip_number,
    )?
    .pop()
    .ok_or_else(|| anyhow!("approved contract {name} not found"))
}

fn find_deployed_targets(
    rpc: &CkbRpcClient,
    targets: Vec<ContractTarget>,
    tip_number: u64,
) -> Result<Vec<ResolvedContract>> {
    let mut found: Vec<Option<OutPoint>> = vec![None; targets.len()];

    for number in 0..=tip_number {
        let Some(block) = rpc.block_by_number(number)? else {
            continue;
        };
        for tx in block.transactions {
            for (index, data) in tx.inner.outputs_data.iter().enumerate() {
                let data_hash = H256::from(blake2b_256(data.as_bytes()));
                for (target_index, target) in targets.iter().enumerate() {
                    if data_hash != target.data_hash {
                        continue;
                    }
                    if let Some(expected_type) = &target.type_hash {
                        let Some(output) = tx.inner.outputs.get(index) else {
                            continue;
                        };
                        let output: CellOutput = output.clone().into();
                        if !output.type_().to_opt().is_some_and(|ty| {
                            byte32_to_h256(ty.calc_script_hash()) == *expected_type
                        }) {
                            continue;
                        }
                    }
                    let out_point = OutPoint::new(tx.hash.pack(), index as u32);
                    let live = rpc.live_cell(out_point.clone().into(), false)?;
                    if live.status == "live" {
                        found[target_index] = Some(out_point);
                    }
                }
            }
        }
    }

    targets
        .into_iter()
        .zip(found)
        .map(|(target, out_point)| {
            let out_point = out_point.ok_or_else(|| {
                anyhow!(
                    "contract {} with data hash {:#x} is not deployed as a live cell; run `morph devnet deploy-contracts` first",
                    target.name,
                    target.data_hash
                )
            })?;
            Ok(ResolvedContract {
                name: target.name,
                data_hash: target.data_hash,
                cell_dep: CellDep::new_builder()
                    .out_point(out_point.clone())
                    .dep_type(DepType::Code)
                    .build(),
                out_point,
            })
        })
        .collect()
}

fn contract_by_name(contracts: &[ResolvedContract], name: &str) -> Result<ResolvedContract> {
    contracts
        .iter()
        .find(|contract| contract.name == name)
        .cloned()
        .ok_or_else(|| anyhow!("resolved contract {name} is missing"))
}

fn state_cell_detection_filter(contracts_dir: &Path) -> Result<StateCellDetectionFilter> {
    let targets = load_contract_targets(contracts_dir)?;
    Ok(StateCellDetectionFilter {
        state_type_code_hash: contract_target_hash_by_name(&targets, "morph-state-type")?,
        state_lock_code_hash: contract_target_hash_by_name(&targets, "morph-state-lock")?,
    })
}

fn contract_target_hash_by_name(targets: &[ContractTarget], name: &str) -> Result<H256> {
    targets
        .iter()
        .find(|target| target.name == name)
        .map(|target| target.data_hash.clone())
        .ok_or_else(|| anyhow!("contract target {name} is missing"))
}

fn ensure_change_capacity(owner_lock: &Script, change_capacity: u64) -> Result<()> {
    let output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();
    let occupied = output.occupied_capacity(Capacity::zero())?.as_u64();
    ensure!(
        change_capacity >= occupied,
        "change capacity {} is below occupied capacity {}",
        change_capacity,
        occupied
    );
    Ok(())
}

fn find_largest_live_cell(
    rpc: &CkbRpcClient,
    owner_lock: &Script,
    tip_number: u64,
) -> Result<LiveCell> {
    let mut best: Option<LiveCell> = None;

    for number in 0..=tip_number {
        let Some(block) = rpc.block_by_number(number)? else {
            continue;
        };
        for tx in block.transactions {
            for (index, output) in tx.inner.outputs.iter().enumerate() {
                let packed_output: CellOutput = output.clone().into();
                if packed_output.lock() != *owner_lock {
                    continue;
                }
                if packed_output.type_().to_opt().is_some() {
                    continue;
                }
                let out_point = OutPoint::new(tx.hash.pack(), index as u32);
                let live = rpc.live_cell(out_point.clone().into(), true)?;
                if live.status != "live" {
                    continue;
                }
                let Some(cell) = &live.cell else {
                    continue;
                };
                if cell
                    .data
                    .as_ref()
                    .is_some_and(|data| !data.content.is_empty())
                {
                    continue;
                }
                let capacity = output.capacity.value();
                if best.as_ref().is_none_or(|cell| capacity > cell.capacity) {
                    best = Some(LiveCell {
                        out_point,
                        capacity,
                    });
                }
            }
        }
    }

    best.ok_or_else(|| anyhow!("no live devnet funding cell found for the derived secp256k1 lock"))
}

pub(crate) fn load_canonical_live_cell(
    rpc: &CkbRpcClient,
    out_point: OutPoint,
) -> Result<LiveCellDetails> {
    let live = rpc.canonical_live_cell(out_point.clone().into(), true)?;
    live_cell_details(out_point, live)
}

fn live_cell_details(
    out_point: OutPoint,
    live: ckb_jsonrpc_types::CellWithStatus,
) -> Result<LiveCellDetails> {
    ensure!(
        live.status == "live",
        "cell {} is not live; status={}",
        format_out_point(&out_point),
        live.status
    );
    let cell = live.cell.ok_or_else(|| {
        anyhow!(
            "RPC did not return live cell data for {}",
            format_out_point(&out_point)
        )
    })?;
    let output: CellOutput = cell.output.into();
    let data = cell
        .data
        .map(|data| data.content.into_bytes())
        .unwrap_or_default();
    let capacity = output.capacity().unpack();
    Ok(LiveCellDetails {
        output,
        data,
        capacity,
    })
}

fn find_secp256k1_cell_dep(rpc: &CkbRpcClient) -> Result<CellDep> {
    let secp_type_hash = parse_h256(DEFAULT_SECP_TYPE_HASH)?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;

    let mut secp_code_out_point = None;
    for tx in &genesis.transactions {
        for (index, output) in tx.inner.outputs.iter().enumerate() {
            let packed_output: CellOutput = output.clone().into();
            let Some(type_script) = packed_output.type_().to_opt() else {
                continue;
            };
            let type_hash = byte32_to_h256(type_script.calc_script_hash());
            if type_hash == secp_type_hash {
                secp_code_out_point = Some(OutPoint::new(tx.hash.pack(), index as u32));
                break;
            }
        }
    }

    let secp_code_out_point = secp_code_out_point
        .ok_or_else(|| anyhow!("could not find secp256k1_blake160_sighash_all system cell"))?;

    for tx in genesis.transactions {
        for (index, data) in tx.inner.outputs_data.iter().enumerate() {
            let raw = data.clone().into_bytes();
            let Ok(group) = OutPointVec::from_slice(raw.as_ref()) else {
                continue;
            };
            if group
                .into_iter()
                .any(|out_point| out_point == secp_code_out_point)
            {
                return Ok(CellDep::new_builder()
                    .out_point(OutPoint::new(tx.hash.pack(), index as u32))
                    .dep_type(DepType::DepGroup)
                    .build());
            }
        }
    }

    Ok(CellDep::new_builder()
        .out_point(secp_code_out_point)
        .dep_type(DepType::Code)
        .build())
}

fn secp256k1_lock(privkey: &Privkey) -> Result<Script> {
    let pubkey = privkey.pubkey().context("failed to derive public key")?;
    secp256k1_lock_from_pubkey(&pubkey.serialize())
}

fn secp256k1_lock_from_pubkey(pubkey_sec1: &[u8]) -> Result<Script> {
    crate::multi_asset_funding::funding_wallet_lock(pubkey_sec1)
}

fn compressed_pubkey(privkey: &Privkey) -> Result<[u8; 33]> {
    let pubkey = privkey.pubkey().context("failed to derive public key")?;
    let serialized = pubkey.serialize();
    let mut out = [0u8; 33];
    out.copy_from_slice(&serialized);
    Ok(out)
}

pub fn compressed_pubkey_hex_from_private(value: &str) -> Result<String> {
    let key = parse_privkey(value).context("invalid secp256k1 private key")?;
    Ok(hex_prefixed(&compressed_pubkey(&key)?))
}

pub fn canonical_state_challenge_blocks(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    state_out_point: &str,
) -> Result<u64> {
    let out_point = parse_out_point(state_out_point)?;
    let cell = load_canonical_live_cell(rpc, out_point)?;
    let state_type = cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("challenge-window StateCell has no type script"))?;
    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, contracts_dir, tip_number)?;
    let state_type_contract = contract_by_name(&contracts, "morph-state-type")?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    ensure!(
        script_uses_data1_code_hash(&state_type, &state_type_contract.data_hash),
        "challenge-window cell does not use the deployed morph-state-type"
    );
    ensure_type_bound_state_lock(
        &cell.output,
        &state_type,
        &state_lock_contract,
        "challenge-window StateCell",
    )?;
    let header = morph_script_common::multi_asset::MultiAssetStateHeader::parse(cell.data.as_ref())
        .map_err(|err| {
            anyhow!("challenge-window StateCell does not contain a valid StateHeader: {err:?}")
        })?;
    let raw_args = state_type.args().raw_data();
    let args = morph_script_common::multi_asset::MultiAssetStateTypeArgs::parse(&raw_args)
        .map_err(|error| anyhow!("invalid current StateType args: {error:?}"))?;
    ensure!(
        header.funding_anchor() == args.funding_anchor(),
        "challenge-window State funding anchor does not match its current Type args"
    );
    Ok(args.finalise_since() & 0x00ff_ffff_ffff_ffff)
}

fn k256_signing_key(value: &str) -> Result<SigningKey> {
    let raw = zeroize::Zeroizing::new(
        hex::decode(value.strip_prefix("0x").unwrap_or(value))
            .with_context(|| "private key must be hex encoded")?,
    );
    ensure!(raw.len() == 32, "private key must be 32 bytes");
    SigningKey::from_slice(&raw).map_err(|err| anyhow!("invalid secp256k1 private key: {err:?}"))
}

fn k256_pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_sec1_point(true);
    let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn ecdsa_signature(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; ECDSA_SIGNATURE_LEN]> {
    let sig: Signature = key
        .sign_prehash(digest)
        .map_err(|err| anyhow!("failed to sign state digest: {err:?}"))?;
    let mut out = [0u8; ECDSA_SIGNATURE_LEN];
    let signature_bytes = sig.to_bytes();
    out.copy_from_slice(signature_bytes.as_ref());
    Ok(out)
}

fn empty_witness() -> ckb_types::packed::Bytes {
    WitnessArgs::default().as_bytes().pack()
}

fn data1_script(code_hash: H256, args: Bytes) -> Script {
    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Data1)
        .args(args.pack())
        .build()
}

#[cfg(test)]
fn relative_block_since_arg(blocks: u64) -> Result<u64> {
    morph_script_common::relative_block_since(blocks)
        .map_err(|_| anyhow!("finalise_since must fit in the CKB since 56-bit value field"))
}

fn direct_cell_dep(out_point: OutPoint) -> CellDep {
    CellDep::new_builder()
        .out_point(out_point)
        .dep_type(DepType::Code)
        .build()
}

fn sponsor_policy_settings(
    sponsor_capacity: u64,
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: Option<u64>,
    max_total_fee: Option<u64>,
) -> Result<SponsorPolicySettings> {
    ensure!(
        min_state_number <= max_state_number,
        "sponsor min state number must be <= max state number"
    );
    let max_total_fee = max_total_fee.unwrap_or(sponsor_capacity);
    let default_max_fee_per_tx = (sponsor_capacity / 2).max(1);
    let max_fee_per_tx = max_fee_per_tx.unwrap_or(default_max_fee_per_tx);
    ensure!(
        max_fee_per_tx > 0,
        "sponsor max fee per tx must be non-zero"
    );
    ensure!(max_total_fee > 0, "sponsor max total fee must be non-zero");
    ensure!(
        max_fee_per_tx <= max_total_fee,
        "sponsor max fee per tx cannot exceed max total fee"
    );
    ensure!(
        max_total_fee <= sponsor_capacity,
        "sponsor max total fee cannot exceed sponsor capacity"
    );
    Ok(SponsorPolicySettings {
        min_state_number,
        max_state_number,
        max_fee_per_tx,
        max_total_fee,
    })
}

fn ensure_strict_sponsor_range(min_state_number: u64, max_state_number: u64) -> Result<()> {
    ensure!(
        min_state_number >= DEFAULT_SPONSOR_MIN_STATE_NUMBER,
        "strict sponsor range requires min_state_number >= {}",
        DEFAULT_SPONSOR_MIN_STATE_NUMBER
    );
    ensure!(
        max_state_number <= DEFAULT_SPONSOR_MAX_STATE_NUMBER,
        "strict sponsor range requires max_state_number <= {}",
        DEFAULT_SPONSOR_MAX_STATE_NUMBER
    );
    Ok(())
}

fn sponsor_policy_bytes(
    channel_id: &[u8; 32],
    settings: SponsorPolicySettings,
    publication_state_type_hash: [u8; 32],
    change_lock_hash: [u8; 32],
) -> [u8; SPONSOR_POLICY_LEN] {
    let mut raw = [0u8; SPONSOR_POLICY_LEN];
    raw[0..32].copy_from_slice(channel_id);
    put_u64(&mut raw, 32, settings.min_state_number);
    put_u64(&mut raw, 40, settings.max_state_number);
    put_u64(&mut raw, 48, settings.max_fee_per_tx);
    put_u64(&mut raw, 56, settings.max_total_fee);
    put_u64(&mut raw, 64, 0);
    raw[72..104].copy_from_slice(&publication_state_type_hash);
    raw[104..136].copy_from_slice(&change_lock_hash);
    raw
}

fn sponsor_policy_report(
    settings: SponsorPolicySettings,
    publication_state_type_hash: [u8; 32],
    change_lock_hash: [u8; 32],
) -> SponsorPolicyReport {
    SponsorPolicyReport {
        min_state_number: settings.min_state_number,
        max_state_number: settings.max_state_number,
        max_fee_per_tx: settings.max_fee_per_tx,
        max_total_fee: settings.max_total_fee,
        already_spent: 0,
        publication_state_type_hash: hex32(&publication_state_type_hash),
        change_lock_hash: hex32(&change_lock_hash),
    }
}

fn occupied_capacity(output: &CellOutput, data_len: usize) -> Result<u64> {
    Ok(output
        .occupied_capacity(Capacity::bytes(data_len)?)?
        .as_u64())
}

fn ensure_output_capacity(name: &str, output: &CellOutput, data_len: usize) -> Result<()> {
    let capacity: u64 = output.capacity().unpack();
    let occupied = occupied_capacity(output, data_len)?;
    ensure!(
        capacity >= occupied,
        "{name} capacity {} is below occupied capacity {}",
        capacity,
        occupied
    );
    Ok(())
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn printable_out_point(out_point: &OutPoint) -> PrintableOutPoint {
    PrintableOutPoint {
        tx_hash: format!("{:#x}", byte32_to_h256(out_point.tx_hash())),
        index: out_point.index().unpack(),
    }
}

fn printable_out_point_string(out_point: &PrintableOutPoint) -> String {
    format!("{}:{}", out_point.tx_hash, out_point.index)
}

fn parse_out_point(value: &str) -> Result<OutPoint> {
    let (tx_hash, index) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("out point must be formatted as <tx-hash>:<index>"))?;
    let tx_hash = parse_h256(tx_hash)?;
    let index = if let Some(hex) = index.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).with_context(|| format!("invalid out point index {index}"))?
    } else {
        index
            .parse::<u32>()
            .with_context(|| format!("invalid out point index {index}"))?
    };
    Ok(OutPoint::new(tx_hash.pack(), index))
}

fn format_out_point(out_point: &OutPoint) -> String {
    format!(
        "{}:{}",
        printable_out_point(out_point).tx_hash,
        printable_out_point(out_point).index
    )
}

fn hex32(raw: &[u8]) -> String {
    hex_prefixed(raw)
}

fn hex_prefixed(raw: &[u8]) -> String {
    format!("0x{}", hex::encode(raw))
}

pub(crate) fn parse_script_failure(raw: &str) -> ScriptFailureReport {
    let error_code = extract_error_code(raw);
    ScriptFailureReport {
        source: extract_between(raw, "source: ", ", cause:").map(str::to_string),
        error_code,
        morph_error: error_code
            .and_then(morph_script_error_name)
            .map(str::to_string),
        raw: raw.to_string(),
    }
}

fn extract_error_code(raw: &str) -> Option<i16> {
    let (_, tail) = raw.split_once("error code ")?;
    let digits: String = tail
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '-')
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

fn extract_between<'a>(raw: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let (_, tail) = raw.split_once(start)?;
    let (value, _) = tail.split_once(end)?;
    Some(value)
}

fn morph_script_error_name(code: i16) -> Option<&'static str> {
    match code {
        value if value == ScriptError::IndexOutOfBounds as i16 => Some("IndexOutOfBounds"),
        value if value == ScriptError::Encoding as i16 => Some("Encoding"),
        value if value == ScriptError::WrongArgsLength as i16 => Some("WrongArgsLength"),
        value if value == ScriptError::WrongGroupShape as i16 => Some("WrongGroupShape"),
        value if value == ScriptError::FundingAnchorMismatch as i16 => {
            Some("FundingAnchorMismatch")
        }
        value if value == ScriptError::NonMonotonicStateNumber as i16 => {
            Some("NonMonotonicStateNumber")
        }
        value if value == ScriptError::NewStateNotSettling as i16 => Some("NewStateNotSettling"),
        value if value == ScriptError::HeaderContextChanged as i16 => Some("HeaderContextChanged"),
        value if value == ScriptError::OutputBelowOccupiedCapacity as i16 => {
            Some("OutputBelowOccupiedCapacity")
        }
        value if value == ScriptError::StateCellMissing as i16 => Some("StateCellMissing"),
        value if value == ScriptError::StateCellAmbiguous as i16 => Some("StateCellAmbiguous"),
        value if value == ScriptError::StateSinceNotMature as i16 => Some("StateSinceNotMature"),
        value if value == ScriptError::SponsorFeeTooHigh as i16 => Some("SponsorFeeTooHigh"),
        value if value == ScriptError::SponsorBudgetExceeded as i16 => {
            Some("SponsorBudgetExceeded")
        }
        value if value == ScriptError::CapacityUnderflow as i16 => Some("CapacityUnderflow"),
        value if value == ScriptError::ParticipantWitnessMissing as i16 => {
            Some("ParticipantWitnessMissing")
        }
        value if value == ScriptError::ParticipantWitnessEncoding as i16 => {
            Some("ParticipantWitnessEncoding")
        }
        value if value == ScriptError::ParticipantCommitmentMismatch as i16 => {
            Some("ParticipantCommitmentMismatch")
        }
        value if value == ScriptError::InvalidParticipantSignature as i16 => {
            Some("InvalidParticipantSignature")
        }
        value if value == ScriptError::SettlementWitnessMissing as i16 => {
            Some("SettlementWitnessMissing")
        }
        value if value == ScriptError::SponsorStateOutOfRange as i16 => {
            Some("SponsorStateOutOfRange")
        }
        value if value == ScriptError::XudtAmountEncoding as i16 => Some("XudtAmountEncoding"),
        value if value == ScriptError::XudtMintUnauthorised as i16 => Some("XudtMintUnauthorised"),
        value if value == ScriptError::XudtConservationMismatch as i16 => {
            Some("XudtConservationMismatch")
        }
        value if value == ScriptError::FactoryIdMismatch as i16 => Some("FactoryIdMismatch"),
        value if value == ScriptError::StateTypeMismatch as i16 => Some("StateTypeMismatch"),
        value if value == ScriptError::FactoryReducedProofEncoding as i16 => {
            Some("FactoryReducedProofEncoding")
        }
        value if value == ScriptError::FactoryReducedProofMismatch as i16 => {
            Some("FactoryReducedProofMismatch")
        }
        value if value == ScriptError::StateCarrierMismatch as i16 => Some("StateCarrierMismatch"),
        value if value == ScriptError::MultiAssetEncoding as i16 => Some("MultiAssetEncoding"),
        value if value == ScriptError::MultiAssetCommitmentMismatch as i16 => {
            Some("MultiAssetCommitmentMismatch")
        }
        value if value == ScriptError::MultiAssetConservationMismatch as i16 => {
            Some("MultiAssetConservationMismatch")
        }
        value if value == ScriptError::MultiAssetCapacityMismatch as i16 => {
            Some("MultiAssetCapacityMismatch")
        }
        value if value == ScriptError::MultiAssetVaultSetIncomplete as i16 => {
            Some("MultiAssetVaultSetIncomplete")
        }
        _ => None,
    }
}

fn parse_h256(value: &str) -> Result<H256> {
    H256::from_str(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|err| anyhow!("invalid H256 {value}: {err:?}"))
}

pub(crate) fn parse_privkey(value: &str) -> Result<Privkey, ckb_crypto::secp::Error> {
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(value), bytes.as_mut())
        .map_err(|_| ckb_crypto::secp::Error::InvalidPrivKey)?;
    SigningKey::from_slice(bytes.as_ref()).map_err(|_| ckb_crypto::secp::Error::InvalidPrivKey)?;
    Ok(Privkey::from_slice(bytes.as_ref()))
}

fn byte32_to_h256(value: ckb_types::packed::Byte32) -> H256 {
    (&value).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state_type_args(anchor: &[u8; 32], since: u64) -> Bytes {
        Bytes::from([anchor.as_slice(), &since.to_le_bytes()].concat())
    }

    #[test]
    fn current_observer_uses_shared_40_and_72_byte_type_args() {
        let anchor = [3; 32];
        let origin = [7; 32];
        let since = morph_script_common::relative_block_since(4).unwrap();
        let filter = StateCellDetectionFilter {
            state_type_code_hash: H256([1; 32]),
            state_lock_code_hash: H256([2; 32]),
        };
        let make = |args: Vec<u8>| {
            let ty = data1_script(filter.state_type_code_hash.clone(), Bytes::from(args));
            let lock = data1_script(
                filter.state_lock_code_hash.clone(),
                ty.calc_script_hash().as_slice().to_vec().into(),
            );
            CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .type_(Some(ty).pack())
                .lock(lock)
                .build()
        };
        let direct = [anchor.as_slice(), &since.to_le_bytes()].concat();
        assert!(is_authentic_observed_state_cell(
            &make(direct),
            &anchor,
            &filter
        ));
        let child = [anchor.as_slice(), origin.as_slice(), &since.to_le_bytes()].concat();
        assert!(is_authentic_observed_state_cell(
            &make(child),
            &anchor,
            &filter
        ));
        let wrong_order = [anchor.as_slice(), &since.to_le_bytes(), origin.as_slice()].concat();
        assert!(!is_authentic_observed_state_cell(
            &make(wrong_order),
            &anchor,
            &filter
        ));
        let zero_origin = [anchor.as_slice(), [0; 32].as_slice(), &since.to_le_bytes()].concat();
        assert!(!is_authentic_observed_state_cell(
            &make(zero_origin),
            &anchor,
            &filter
        ));
        let invalid_since = [anchor.as_slice(), origin.as_slice(), &4u64.to_le_bytes()].concat();
        assert!(!is_authentic_observed_state_cell(
            &make(invalid_since),
            &anchor,
            &filter
        ));
    }

    #[test]
    fn publication_deadline_rejects_exhausted_challenge_window() {
        let profile = crate::publication::fixture_publication_profile();
        let error =
            publication_deadline(&profile, profile.window.configured_challenge_blocks).unwrap_err();
        assert!(error.to_string().contains("no remaining challenge-window"));
    }

    #[test]
    fn publication_deadline_reserves_reorg_failover_and_safety_blocks() {
        let profile = crate::publication::fixture_publication_profile();
        assert_eq!(publication_runtime_budget_blocks(&profile, 1).unwrap(), 8);

        let error = publication_runtime_budget_blocks(&profile, 5).unwrap_err();
        assert!(error.to_string().contains("no execution time"));
    }

    #[test]
    fn block_confirmations_follow_the_latest_tip() {
        assert_eq!(block_confirmations(100, 100).unwrap(), 1);
        assert_eq!(block_confirmations(100, 107).unwrap(), 8);

        let error = block_confirmations(108, 107).unwrap_err();
        assert!(error.to_string().contains("above current canonical tip"));
    }

    #[test]
    fn publication_statuses_have_explicit_terminal_dispositions() {
        assert_eq!(
            publication_status_disposition(&Status::Pending),
            PublicationStatusDisposition::Nonterminal
        );
        assert_eq!(
            publication_status_disposition(&Status::Proposed),
            PublicationStatusDisposition::Nonterminal
        );
        assert_eq!(
            publication_status_disposition(&Status::Committed),
            PublicationStatusDisposition::CanonicalCandidate
        );
        assert_eq!(
            publication_status_disposition(&Status::Rejected),
            PublicationStatusDisposition::Failure
        );
        assert_eq!(
            publication_status_disposition(&Status::Unknown),
            PublicationStatusDisposition::Failure
        );
    }

    #[test]
    fn generic_rpc_errors_remain_indeterminate() {
        assert_eq!(
            submission_failure_disposition(None, None),
            SubmissionFailureDisposition::Indeterminate
        );
        assert_eq!(
            submission_failure_disposition(None, Some(&Status::Unknown)),
            SubmissionFailureDisposition::Indeterminate
        );
        assert_eq!(
            submission_failure_disposition(None, Some(&Status::Rejected)),
            SubmissionFailureDisposition::ExplicitRejection
        );
        assert_eq!(
            submission_failure_disposition(Some(42), None),
            SubmissionFailureDisposition::ReplacementRequired(42)
        );
    }

    #[test]
    fn parses_ckb_script_failure() {
        let raw = "CKB RPC error -302 on estimate_cycles: TransactionFailedToVerify: Script(TransactionScriptError { source: Inputs[1].Lock, cause: ValidationFailure: see error code 29 on page https://example.invalid#29 })";

        let parsed = parse_script_failure(raw);

        assert_eq!(parsed.source.as_deref(), Some("Inputs[1].Lock"));
        assert_eq!(
            parsed.error_code,
            Some(ScriptError::SponsorStateOutOfRange as i16)
        );
        assert_eq!(
            parsed.morph_error.as_deref(),
            Some("SponsorStateOutOfRange")
        );
        assert_eq!(parsed.raw, raw);
    }

    #[test]
    fn participant_pubkey_lock_matches_private_key_lock() {
        let private_key = private_key_from_scalar(1);
        let key = parse_privkey(&private_key).unwrap();
        let lock_from_key = secp256k1_lock(&key).unwrap();
        let pubkey = key.pubkey().unwrap().serialize();
        let lock_from_pubkey = secp256k1_lock_from_pubkey(&pubkey).unwrap();

        assert_eq!(lock_from_pubkey, lock_from_key);
    }

    #[test]
    fn strict_sponsor_range_accepts_default_window() {
        ensure_strict_sponsor_range(
            DEFAULT_SPONSOR_MIN_STATE_NUMBER,
            DEFAULT_SPONSOR_MAX_STATE_NUMBER,
        )
        .unwrap();
    }

    #[test]
    fn strict_sponsor_range_rejects_unbounded_policy() {
        let err = ensure_strict_sponsor_range(0, u64::MAX).unwrap_err();

        assert!(
            err.to_string().contains("strict sponsor range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sponsor_owner_validation_uses_canonical_policy_layout() {
        let channel_id = [0x11; BYTE32_LEN];
        let change_lock = [0x22; BYTE32_LEN];
        let mut policy = [0u8; SPONSOR_POLICY_LEN];
        policy[0..32].copy_from_slice(&channel_id);
        policy[104..136].copy_from_slice(&change_lock);

        let parsed = WireSponsorPolicy::parse(&policy).unwrap();
        assert_eq!(parsed.channel_id(), channel_id);
        assert_eq!(parsed.change_lock(), change_lock);
    }

    #[test]
    fn sponsor_owner_validation_rejects_truncated_policy_without_panicking() {
        let channel_id = [0x11; BYTE32_LEN];
        let change_lock = [0x22; BYTE32_LEN];
        let truncated = [0u8; SPONSOR_POLICY_LEN - 1];

        assert!(WireSponsorPolicy::parse(&truncated).is_err());
        let _ = (channel_id, change_lock);
    }

    #[test]
    fn watch_cursor_for_state_records_observed_funding_anchor() {
        let channel_id = format!("0x{}", "33".repeat(BYTE32_LEN));
        let funding_anchor = format!("0x{}", "44".repeat(BYTE32_LEN));
        let funding_context_id = format!("0x{}", "45".repeat(BYTE32_LEN));
        let observed = ObservedStateCellReport {
            block_number: 10,
            block_hash: format!("0x{}", "55".repeat(BYTE32_LEN)),
            tx_hash: format!("0x{}", "66".repeat(BYTE32_LEN)),
            output_index: 0,
            out_point: format!("0x{}:0", "66".repeat(BYTE32_LEN)),
            funding_anchor: funding_anchor.clone(),
            funding_context_id: funding_context_id.clone(),
            vault_set_commitment: format!("0x{}", "46".repeat(BYTE32_LEN)),
            state_number: 7,
            phase: "active".to_string(),
            settlement_descriptor_commitment: format!("0x{}", "77".repeat(BYTE32_LEN)),
            descriptor_version: 1,
            confirmations: 4,
        };

        let scanned_hash = format!("0x{}", "88".repeat(BYTE32_LEN));
        let cursor = watch_cursor_for_state(
            &channel_id,
            0,
            12,
            11,
            Some(&scanned_hash),
            Some(&observed),
            None,
        )
        .unwrap();

        assert_eq!(cursor.channel_id, channel_id);
        assert_eq!(cursor.next_block, 12);
        assert_eq!(cursor.scanned_to_block, 11);
        assert_eq!(
            cursor.scanned_to_block_hash.as_deref(),
            Some(scanned_hash.as_str())
        );
        assert_eq!(
            cursor.current_funding_anchor.as_deref(),
            Some(funding_anchor.as_str())
        );
        assert_eq!(
            cursor.current_funding_context_id.as_deref(),
            Some(funding_context_id.as_str())
        );
        assert_eq!(cursor.last_observed_state_number, Some(7));
        assert_eq!(
            cursor.last_observed_out_point.as_deref(),
            Some(observed.out_point.as_str())
        );
    }

    #[test]
    fn watch_cursor_for_state_preserves_previous_observation_when_idle() {
        let channel_id = format!("0x{}", "33".repeat(BYTE32_LEN));
        let funding_anchor = format!("0x{}", "44".repeat(BYTE32_LEN));
        let funding_context_id = format!("0x{}", "45".repeat(BYTE32_LEN));
        let previous = WatchCursor::new(&channel_id, 0, 10, 9)
            .unwrap()
            .with_observed_context_state(&funding_anchor, &funding_context_id, 5, "0xabc:0")
            .unwrap();

        let cursor =
            watch_cursor_for_state(&channel_id, 0, 12, 11, None, None, Some(&previous)).unwrap();

        assert_eq!(cursor.next_block, 12);
        assert_eq!(cursor.scanned_to_block, 11);
        assert_eq!(
            cursor.current_funding_anchor.as_deref(),
            Some(funding_anchor.as_str())
        );
        assert_eq!(
            cursor.current_funding_context_id.as_deref(),
            Some(funding_context_id.as_str())
        );
        assert_eq!(cursor.last_observed_state_number, Some(5));
        assert_eq!(cursor.last_observed_out_point.as_deref(), Some("0xabc:0"));
    }

    #[test]
    fn watch_cursor_canonicality_accepts_matching_hash() {
        let hash = format!("0x{}", "55".repeat(BYTE32_LEN));
        assert_eq!(
            watch_reorg_recovery_if_needed(42, Some(&hash), Some(&hash), 10),
            None
        );
    }

    #[test]
    fn watch_cursor_canonicality_resets_on_reorg() {
        let expected = format!("0x{}", "55".repeat(BYTE32_LEN));
        let canonical = format!("0x{}", "66".repeat(BYTE32_LEN));
        let recovery =
            watch_reorg_recovery_if_needed(42, Some(&expected), Some(&canonical), 10).unwrap();

        assert_eq!(recovery.reason, "cursor_block_hash_mismatch");
        assert_eq!(recovery.cursor_scanned_to_block, 42);
        assert_eq!(
            recovery.expected_block_hash.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(
            recovery.canonical_block_hash.as_deref(),
            Some(canonical.as_str())
        );
        assert_eq!(recovery.reset_from_block, 10);
    }

    #[test]
    fn uninitialized_cursor_without_hash_is_rescanned() {
        let canonical = format!("0x{}", "66".repeat(BYTE32_LEN));
        let recovery = watch_reorg_recovery_if_needed(42, None, Some(&canonical), 10).unwrap();

        assert_eq!(recovery.reason, "cursor_missing_block_hash");
        assert_eq!(recovery.reset_from_block, 10);
    }

    #[test]
    fn watchtower_state_detection_requires_authentic_state_scripts() {
        let filter = StateCellDetectionFilter {
            state_type_code_hash: H256::from([0x11; BYTE32_LEN]),
            state_lock_code_hash: H256::from([0x22; BYTE32_LEN]),
        };
        let funding_anchor = [0x33; BYTE32_LEN];
        let mut state = crate::multi_asset_packages::fixture_package()
            .unwrap()
            .recovery()
            .unwrap()
            .state;
        state.header.funding_anchor = funding_anchor;
        let header_bytes = state.encode().unwrap();
        let header =
            morph_script_common::multi_asset::MultiAssetStateHeader::parse(&header_bytes).unwrap();
        let state_type = data1_script(
            filter.state_type_code_hash.clone(),
            state_type_args(&funding_anchor, relative_block_since_arg(4).unwrap()),
        );
        let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
        let state_lock = data1_script(
            filter.state_lock_code_hash.clone(),
            Bytes::copy_from_slice(&state_type_hash),
        );
        let state_output = CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build();

        assert!(is_authentic_observed_state_cell(
            &state_output,
            header.funding_anchor(),
            &filter
        ));

        let fake_data_only_output = CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(state_lock.clone())
            .build();
        assert!(!is_authentic_observed_state_cell(
            &fake_data_only_output,
            header.funding_anchor(),
            &filter
        ));

        let mismatched_lock = data1_script(
            filter.state_lock_code_hash.clone(),
            Bytes::copy_from_slice(&[0xff; BYTE32_LEN]),
        );
        let mismatched_lock_output = CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(mismatched_lock)
            .type_(Some(state_type.clone()).pack())
            .build();
        assert!(!is_authentic_observed_state_cell(
            &mismatched_lock_output,
            header.funding_anchor(),
            &filter
        ));

        let wrong_anchor_type = data1_script(
            filter.state_type_code_hash.clone(),
            state_type_args(&[0x99; BYTE32_LEN], relative_block_since_arg(4).unwrap()),
        );
        let wrong_anchor_type_hash: [u8; BYTE32_LEN] =
            wrong_anchor_type.calc_script_hash().unpack();
        let wrong_anchor_lock = data1_script(
            filter.state_lock_code_hash.clone(),
            Bytes::copy_from_slice(&wrong_anchor_type_hash),
        );
        let wrong_anchor_output = CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(wrong_anchor_lock)
            .type_(Some(wrong_anchor_type).pack())
            .build();
        assert!(!is_authentic_observed_state_cell(
            &wrong_anchor_output,
            header.funding_anchor(),
            &filter
        ));
    }

    fn private_key_from_scalar(value: u8) -> String {
        let mut bytes = [0u8; BYTE32_LEN];
        bytes[BYTE32_LEN - 1] = value;
        format!("0x{}", hex::encode(bytes))
    }
}
