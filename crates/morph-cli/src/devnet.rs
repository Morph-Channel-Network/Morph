use std::cmp::Ordering;
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
use morph_core::types::{
    AssetRegistry, FactoryMerkleSibling, FactoryReducedSpliceTransition,
    FactoryReducedSpliceWitness, FactoryRight, FactoryRightId, FactoryRightKind,
    FactorySingleRightMerkleUpdate, FactorySpliceHeader, FactorySpliceKind,
    FactorySpliceTransition, FactoryUpdate, FactoryVaultDelta, FactoryVaultDescriptor, Mode,
    ParticipantSignature, Phase, SpliceAssetDelta, SpliceHeader, SpliceKind, SpliceTransition,
    SpliceWitness, StateCell as CoreStateCell, StateHeader, VaultAsset, VaultAssetAmount,
    VaultDescriptor,
};
use morph_core::validation::{factory_right_sparse_proof, factory_right_sparse_root};
use morph_core::{
    asset_registry_commitment, factory_vault_delta_commitment,
    participants_commitment as core_participants_commitment, splice_asset_delta_commitment,
    vault_descriptor_commitment, vault_outpoint_commitment,
};
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT,
    BILATERAL_CKB_DESCRIPTOR_VERSION, BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT,
    BILATERAL_CKB_XUDT_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
    BILATERAL_SIGNATURE_COUNT, BILATERAL_SIGNATURE_THRESHOLD, BILATERAL_SIGNATURE_WITNESS_LEN,
    BILATERAL_SIGNATURE_WITNESS_VERSION, BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN,
    ECDSA_SIGNATURE_LEN, FACTORY_LOCAL_EXIT_WITNESS_VERSION, FACTORY_MAX_PARTICIPANTS,
    FACTORY_MERKLE_UPDATE_RIGHT_COUNT, FACTORY_MERKLE_UPDATE_WITNESS_VERSION,
    FACTORY_MIN_PARTICIPANTS, FACTORY_REDUCED_EXIT_RIGHTS_COUNT,
    FACTORY_REDUCED_EXIT_WITNESS_VERSION, FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN, FACTORY_RIGHT_KIND_RESERVE_CLAIM,
    FACTORY_RIGHT_LEN, FACTORY_SIGNATURE_WITNESS_VERSION, FACTORY_SPARSE_MERKLE_DEPTH,
    FACTORY_STATE_HEADER_LEN, FACTORY_STATE_LAYOUT_VERSION, FactoryMerkleUpdateWitness,
    FactoryReducedExitWitness, FactoryStateHeader, MORPH_PROTOCOL_VERSION, PHASE_ACTIVE,
    PHASE_SETTLING, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B, SPONSOR_POLICY_LEN,
    STATE_CARRIER_ACTIVATION_FEE, STATE_HEADER_LEN, STATE_LAYOUT_VERSION,
    STATE_MODE_BILATERAL_PLAINTEXT, STATE_MODE_FACTORY_PROOF, ScriptError,
    SponsorPolicy as WireSponsorPolicy, StateHeader as WireStateHeader, StateHeaderInput,
    WITNESS_ENVELOPE_FORMAT, WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
    WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE, WITNESS_ENVELOPE_LEN, WITNESS_ENVELOPE_MAGIC,
    WitnessEnvelope, blake2b256 as script_blake2b256, encode_state_header,
    factory_local_exit_digest, factory_participants_commitment, participants_commitment,
    relative_block_since, settlement_descriptor_commitment, vault_cell_commitment,
    verify_factory_merkle_update, verify_factory_reduced_exit_update,
    witness_envelope_body_commitment,
};
use serde::Serialize;

use crate::factory_packages::{
    StoredFactoryReducedSplicePackage, StoredFactorySplicePackage,
    read_factory_reduced_splice_package, read_factory_splice_package,
    write_factory_reduced_splice_package, write_factory_splice_package,
};
use crate::packages::{
    FactoryStateCellPackageRecord, PackageOutPoint, StatePackageRecord,
    StoredFactoryLocalExitPackage, StoredFactoryMerkleUpdateStatePackage,
    StoredFactoryReducedRightsPackage, StoredFactoryStateCellPackage, StoredStatePackage,
    WatchCursor, canonical_hex32, default_watch_cursor_path,
    fixture_factory_reduced_rights_package, funding_context_id_for_header,
    latest_factory_state_cell_package, latest_package, list_packages,
    read_factory_state_cell_update_package, read_package, read_watch_cursor,
    reduced_rights_package_from_factory_header, write_factory_merkle_update_package,
    write_factory_reduced_rights_package, write_factory_state_cell_package, write_package,
    write_watch_cursor,
};
use crate::publication::{
    FeeObservation, PublicationAttemptInput, PublicationProfile, PublicationReconciliationReport,
    append_publication_attempt, fee_for_rate, initial_fee_rate, publication_attempt_record,
    read_publication_profile, reconcile_publication_attempts, replacement_fee,
    required_replacement_fee_from_error, verify_initial_fee_convergence,
};
use crate::rpc::CkbRpcClient;
use crate::splice_packages::{StoredSplicePackage, read_splice_package, write_splice_package};
use crate::watch_alert::{
    WatchAlertEvent, WatchAlertSeverity, WatchtowerAlert, append_watchtower_alert,
    post_watchtower_alert_webhook_with_secret,
};
use crate::watch_policy::{WatchPolicyRun, read_watchtower_policy};

const DEFAULT_SECP_TYPE_HASH: &str =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
#[cfg(feature = "devnet")]
pub mod multi_asset;
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
    pub private_key: String,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct OpenChannelOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub sponsor_min_state_number: u64,
    pub sponsor_max_state_number: u64,
    pub strict_sponsor_range: bool,
    pub sponsor_max_fee_per_tx: Option<u64>,
    pub sponsor_max_total_fee: Option<u64>,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct OpenFactoryOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub factory_vault_xudt_amount: Option<u128>,
    pub state_root: Option<String>,
    pub access_manifest_root: Option<String>,
    pub non_interference_digest: Option<String>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct UpdateFactoryOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub state_root: Option<String>,
    pub access_manifest_root: Option<String>,
    pub non_interference_digest: Option<String>,
    pub factory_state_package: Option<PathBuf>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SaveFactoryStatePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub state_root: Option<String>,
    pub access_manifest_root: Option<String>,
    pub non_interference_digest: Option<String>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SaveFactoryReducedRightsPackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub touched_after_balance: u128,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SaveFactorySplicePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_out_point: String,
    pub factory_vault_out_point: String,
    pub kind: DevnetSpliceKind,
    pub asset: DevnetSpliceAsset,
    pub ckb_amount: u64,
    pub xudt_amount: Option<u128>,
    pub update_number: Option<u64>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SaveFactoryReducedSplicePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_out_point: String,
    pub factory_vault_out_point: String,
    pub kind: DevnetSpliceKind,
    pub asset: DevnetSpliceAsset,
    pub ckb_amount: u64,
    pub xudt_amount: Option<u128>,
    pub update_number: Option<u64>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ApplyFactorySpliceOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub factory_out_point: String,
    pub factory_vault_out_point: String,
    pub factory_splice_package: PathBuf,
    pub xudt_input_out_point: Option<String>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct ApplyFactoryReducedSpliceOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub factory_out_point: String,
    pub factory_vault_out_point: String,
    pub factory_reduced_splice_package: PathBuf,
    pub xudt_input_out_point: Option<String>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SaveFactoryMerkleUpdatePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub additional_participant_private_keys: Vec<String>,
    pub factory_out_point: String,
    pub update_number: Option<u64>,
    pub touched_after_balance: u128,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactorySmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub fee: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryReducedRightsSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub touched_after_balance: u128,
    pub fee: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactorySpliceSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub kind: DevnetSpliceKind,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub splice_amount: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryXudtSpliceSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub kind: DevnetSpliceKind,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub splice_xudt_amount: u128,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryMerkleUpdateSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub touched_after_balance: u128,
    pub fee: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryReducedExitSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct FactoryReducedXudtExitSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub factory_vault_xudt_surplus: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct FactoryReducedXudtNegativeExitSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct FactoryXudtSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryXudtNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub child_vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FactoryExitChannelOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: Option<String>,
    pub additional_participant_private_keys: Vec<String>,
    pub additional_participant_public_keys: Vec<String>,
    pub bob_public_key: Option<String>,
    pub factory_out_point: String,
    pub factory_vault_out_point: String,
    pub update_number: Option<u64>,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: Option<u128>,
    pub bob_xudt_amount: Option<u128>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub tamper: FactoryExitChannelTamper,
    pub authorisation: FactoryExitAuthorisation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryExitChannelTamper {
    None,
    ChildXudtAmountMinusOnePreserveFactoryChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryExitAuthorisation {
    FullParticipants,
    ReducedReserveClaim,
}

#[derive(Debug, Clone)]
pub struct PublishStateOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub sponsor_out_point: String,
    pub state_number: Option<u64>,
    pub state_package: Option<PathBuf>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SaveStatePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub state_number: Option<u64>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct SettlementDescriptorUpdate {
    alice_capacity: u64,
    bob_capacity: u64,
    xudt: Option<SettlementXudtUpdate>,
}

#[derive(Debug, Clone)]
struct SettlementXudtUpdate {
    type_hash: [u8; BYTE32_LEN],
    alice_amount: u128,
    bob_amount: u128,
}

#[derive(Debug, Clone)]
pub struct PublishLatestStatePackageOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub state_out_point: String,
    pub sponsor_out_point: String,
    pub store_dir: PathBuf,
    pub channel_id: String,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct WatchLatestStatePackageOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub sponsor_out_point: Option<String>,
    pub store_dir: PathBuf,
    pub channel_id: String,
    pub from_block: u64,
    pub cursor_file: Option<PathBuf>,
    pub watch_policy: Option<PathBuf>,
    pub publication_profile: Option<PathBuf>,
    pub publication_attempt_log: Option<PathBuf>,
    pub alert_file: Option<PathBuf>,
    pub alert_webhook_url: Option<String>,
    pub ignore_cursor: bool,
    pub detection_depth: u64,
    pub timeout_secs: u64,
    pub poll_ms: u64,
    pub fee: u64,
    pub mine_blocks: u64,
    pub auto_fund_sponsor: bool,
    pub auto_sponsor_capacity: u64,
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
    pub private_key: String,
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

#[derive(Debug, Clone)]
pub struct FinaliseChannelOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub vault_out_point: String,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub finalise_since: u64,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum DevnetSpliceKind {
    SpliceIn,
    SpliceOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevnetSpliceAsset {
    Ckb,
    Xudt,
}

#[derive(Debug, Clone)]
pub struct SaveSplicePackageOptions {
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub state_out_point: String,
    pub vault_out_point: String,
    pub kind: DevnetSpliceKind,
    pub asset: DevnetSpliceAsset,
    pub ckb_amount: u64,
    pub xudt_amount: Option<u128>,
    pub signed_fee: u64,
    pub old_funding_epoch: u64,
    pub new_funding_epoch: Option<u64>,
    pub splice_number: Option<u64>,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ApplySpliceOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub state_out_point: String,
    pub vault_out_point: String,
    pub splice_package: PathBuf,
    pub xudt_input_out_point: Option<String>,
    pub fee: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SpliceSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub kind: DevnetSpliceKind,
    pub vault_capacity: u64,
    pub splice_amount: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct XudtSpliceSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub splice_xudt_amount: u128,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SpliceNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub splice_amount: u64,
    pub splice_xudt_amount: u128,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SupersedeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct FinaliseSinceNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SponsorPolicyNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct SponsorBudgetNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct CompetingSpendSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct XudtSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct XudtNegativeSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub vault_capacity: u64,
    pub alice_capacity: Option<u64>,
    pub bob_capacity: Option<u64>,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub sponsor_capacity: u64,
    pub fee: u64,
    pub finalise_since: u64,
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

#[derive(Debug, Serialize)]
pub struct OpenChannelReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub finalise_since: u64,
    pub input_capacity: u64,
    pub state_capacity: u64,
    pub vault_capacity: u64,
    pub sponsor_capacity: u64,
    pub sponsor_policy: SponsorPolicyReport,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub activation_tx_hash: String,
    pub activation_status: String,
    pub activation_block_number: Option<u64>,
    pub activation_block_hash: Option<String>,
    pub activation_fee: u64,
    pub activation_metrics: TransactionMetrics,
    pub activation_mined_blocks: Vec<String>,
    pub participants: Vec<ParticipantReport>,
    pub scripts: Vec<ResolvedScriptReport>,
    pub cells: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct OpenFactoryReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub factory_id: String,
    pub input_capacity: u64,
    pub factory_capacity: u64,
    pub factory_vault_capacity: u64,
    pub factory_vault_xudt_amount: Option<u128>,
    pub xudt_type_hash: Option<String>,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub activation_tx_hash: String,
    pub activation_status: String,
    pub activation_block_number: Option<u64>,
    pub activation_block_hash: Option<String>,
    pub activation_fee: u64,
    pub activation_metrics: TransactionMetrics,
    pub activation_mined_blocks: Vec<String>,
    pub participants: Vec<FactoryParticipantReport>,
    pub scripts: Vec<ResolvedScriptReport>,
    pub cells: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct FactoryExitChannelReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub authorisation: String,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub channel_id: String,
    pub funding_anchor: String,
    pub finalise_since: u64,
    pub factory_out_point: PrintableOutPoint,
    pub state_out_point: PrintableOutPoint,
    pub vault_out_point: PrintableOutPoint,
    pub factory_vault_out_point: PrintableOutPoint,
    pub sponsor_out_point: PrintableOutPoint,
    pub factory_activation_tx_hash: String,
    pub factory_activation_status: String,
    pub factory_activation_block_number: Option<u64>,
    pub factory_activation_block_hash: Option<String>,
    pub factory_activation_metrics: TransactionMetrics,
    pub factory_activation_mined_blocks: Vec<String>,
    pub state_activation_tx_hash: String,
    pub state_activation_status: String,
    pub state_activation_block_number: Option<u64>,
    pub state_activation_block_hash: Option<String>,
    pub state_activation_metrics: TransactionMetrics,
    pub state_activation_mined_blocks: Vec<String>,
    pub activation_fee: u64,
    pub state_capacity: u64,
    pub vault_capacity: u64,
    pub child_xudt_amount: Option<u128>,
    pub alice_xudt_amount: Option<u128>,
    pub bob_xudt_amount: Option<u128>,
    pub factory_vault_input_capacity: u64,
    pub factory_vault_change_capacity: u64,
    pub factory_vault_input_xudt_amount: Option<u128>,
    pub factory_vault_change_xudt_amount: Option<u128>,
    pub xudt_type_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_exit_package: Option<StoredFactoryLocalExitPackage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduced_exit: Option<FactoryReducedExitEvidenceReport>,
    pub sponsor_capacity: u64,
    pub fee_change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub participants: Vec<ParticipantReport>,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedExitEvidenceReport {
    pub release_quantity: u128,
    pub old_state_root: String,
    pub new_state_root: String,
    pub old_access_manifest_root: String,
    pub new_access_manifest_root: String,
    pub non_interference_digest: String,
    pub local_exit_digest: String,
    pub witness_len: usize,
}

#[derive(Debug, Serialize)]
pub struct UpdateFactoryReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub factory_out_point: PrintableOutPoint,
    pub factory_capacity: u64,
    pub fee_input_capacity: u64,
    pub fee_change_capacity: u64,
    pub fee: u64,
    pub state_root: String,
    pub access_manifest_root: String,
    pub non_interference_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_state_package: Option<String>,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SaveFactoryStatePackageReport {
    pub path: String,
    pub package: StoredFactoryStateCellPackage,
}

#[derive(Debug, Serialize)]
pub struct SaveFactoryReducedRightsPackageReport {
    pub path: String,
    pub package: StoredFactoryReducedRightsPackage,
}

#[derive(Debug, Serialize)]
pub struct SaveFactorySplicePackageReport {
    pub path: String,
    pub kind: String,
    pub asset: String,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_vault_amount: u128,
    pub new_vault_amount: u128,
    pub external_input: u128,
    pub withdrawal: u128,
    pub contract_witness_len: usize,
    pub package: StoredFactorySplicePackage,
}

#[derive(Debug, Serialize)]
pub struct SaveFactoryReducedSplicePackageReport {
    pub path: String,
    pub kind: String,
    pub asset: String,
    pub factory_id: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub old_vault_amount: u128,
    pub new_vault_amount: u128,
    pub external_input: u128,
    pub withdrawal: u128,
    pub proof_siblings: usize,
    pub contract_witness_len: usize,
    pub package: StoredFactoryReducedSplicePackage,
}

#[derive(Debug, Serialize)]
pub struct ApplyFactorySpliceReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub factory_id: String,
    pub kind: String,
    pub asset: String,
    pub old_update_number: u64,
    pub new_update_number: u64,
    pub factory_out_point: PrintableOutPoint,
    pub factory_vault_out_point: PrintableOutPoint,
    pub withdrawal_out_point: Option<PrintableOutPoint>,
    pub fee_change_capacity: u64,
    pub fee: u64,
    pub factory_splice_package: String,
    pub contract_witness_len: usize,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub activation_tx_hash: String,
    pub activation_status: String,
    pub activation_block_number: Option<u64>,
    pub activation_block_hash: Option<String>,
    pub activation_fee: u64,
    pub activation_metrics: TransactionMetrics,
    pub activation_mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SaveFactoryMerkleUpdatePackageReport {
    pub path: String,
    pub package: StoredFactoryMerkleUpdateStatePackage,
}

#[derive(Debug, Serialize)]
pub struct FactorySmokeReport {
    pub open: OpenFactoryReport,
    pub saved_package: SaveFactoryStatePackageReport,
    pub selected_package: FactoryStateCellPackageRecord,
    pub update: UpdateFactoryReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedRightsSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryReducedRightsPackageReport,
    pub update: UpdateFactoryReport,
}

#[derive(Debug, Serialize)]
pub struct FactorySpliceSmokeReport {
    pub kind: String,
    pub open: OpenFactoryReport,
    pub package: SaveFactorySplicePackageReport,
    pub apply: ApplyFactorySpliceReport,
    pub exit: FactoryExitChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedSpliceSmokeReport {
    pub kind: String,
    pub open: OpenFactoryReport,
    pub package: SaveFactoryReducedSplicePackageReport,
    pub apply: ApplyFactorySpliceReport,
    pub exit: FactoryExitChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryXudtSpliceSmokeReport {
    pub kind: String,
    pub open: OpenFactoryReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_xudt: Option<MintXudtCellReport>,
    pub package: SaveFactorySplicePackageReport,
    pub apply: ApplyFactorySpliceReport,
    pub exit: FactoryExitChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedXudtSpliceSmokeReport {
    pub kind: String,
    pub open: OpenFactoryReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_xudt: Option<MintXudtCellReport>,
    pub package: SaveFactoryReducedSplicePackageReport,
    pub apply: ApplyFactorySpliceReport,
    pub exit: FactoryExitChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryMerkleUpdateSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryMerkleUpdatePackageReport,
    pub update: UpdateFactoryReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedExitSmokeReport {
    pub open: OpenFactoryReport,
    pub exit: FactoryExitChannelReport,
    pub publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedXudtExitSmokeReport {
    pub open: OpenFactoryReport,
    pub exit: FactoryExitChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryReducedXudtNegativeExitSmokeReport {
    pub open: OpenFactoryReport,
    pub expected_child_xudt_amount: u128,
    pub rejected_child_xudt_amount: u128,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
}

#[derive(Debug, Serialize)]
pub struct ParticipantReport {
    pub role: String,
    pub lock_hash: String,
    pub pubkey_sec1: String,
    pub capacity: u64,
}

#[derive(Debug, Serialize)]
pub struct FactoryParticipantReport {
    pub role: String,
    pub participant_id: String,
    pub pubkey_sec1: String,
}

#[derive(Debug, Serialize)]
pub struct ResolvedScriptReport {
    pub name: String,
    pub out_point: PrintableOutPoint,
    pub data_hash: String,
    pub hash_type: String,
}

#[derive(Debug, Serialize)]
pub struct ChannelCellReport {
    pub role: String,
    pub out_point: PrintableOutPoint,
    pub capacity: u64,
    pub lock_hash: String,
    pub type_hash: Option<String>,
    pub data_len: usize,
}

#[derive(Debug, Serialize)]
pub struct PublishStateReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub canonical_confirmations: u64,
    pub canonical_confirmed: bool,
    pub channel_id: String,
    pub funding_anchor: String,
    pub old_state_number: u64,
    pub new_state_number: u64,
    pub state_out_point: PrintableOutPoint,
    pub sponsor_change_capacity: u64,
    pub fee: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_package: Option<String>,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SaveStatePackageReport {
    pub path: String,
    pub package: StoredStatePackage,
}

#[derive(Debug, Serialize)]
pub struct SaveSplicePackageReport {
    pub path: String,
    pub kind: String,
    pub asset: String,
    pub ckb_amount: u64,
    pub xudt_amount: Option<u128>,
    pub xudt_type_hash: Option<String>,
    pub old_vault_capacity: u64,
    pub new_vault_capacity: u64,
    pub old_xudt_amount: Option<u128>,
    pub new_xudt_amount: Option<u128>,
    pub old_funding_epoch: u64,
    pub new_funding_epoch: u64,
    pub splice_number: u64,
    pub contract_witness_len: usize,
    pub package: StoredSplicePackage,
}

#[derive(Debug, Serialize)]
pub struct PublishLatestStatePackageReport {
    pub selected_package: StatePackageRecord,
    pub publication: PublishStateReport,
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
pub struct WatchLatestStatePackageReport {
    pub channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    pub from_block: u64,
    pub effective_from_block: u64,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
    pub detection_depth: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_profile: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_attempt_log: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_reconciliation: Option<PublicationReconciliationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_cursor: Option<WatchCursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reorg_recovery: Option<WatchReorgRecoveryReport>,
    pub publication_retry_rescan: bool,
    pub selected_package: StatePackageRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor_top_up: Option<FundSponsorReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<ObservedStateCellReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication: Option<PublishStateReport>,
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

#[derive(Debug, Serialize)]
pub struct FinaliseChannelReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub state_number: u64,
    pub alice_capacity: u64,
    pub bob_capacity: u64,
    pub state_refund_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub outputs: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct ApplySpliceReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub old_funding_anchor: String,
    pub new_funding_anchor: String,
    pub old_funding_epoch: u64,
    pub new_funding_epoch: u64,
    pub splice_number: u64,
    pub old_state_number: u64,
    pub new_state_number: u64,
    pub state_out_point: PrintableOutPoint,
    pub vault_out_point: PrintableOutPoint,
    pub withdrawal_out_point: Option<PrintableOutPoint>,
    pub withdrawal_payout_policy: String,
    pub withdrawal_participant_pubkey_sec1: Option<String>,
    pub withdrawal_lock_hash: Option<String>,
    pub fee_change_capacity: u64,
    pub fee: u64,
    pub splice_package: String,
    pub contract_witness_len: usize,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub activation_tx_hash: String,
    pub activation_status: String,
    pub activation_block_number: Option<u64>,
    pub activation_block_hash: Option<String>,
    pub activation_fee: u64,
    pub activation_metrics: TransactionMetrics,
    pub activation_mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SpliceSmokeReport {
    pub kind: String,
    pub open: OpenChannelReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_xudt: Option<MintXudtCellReport>,
    pub package: SaveSplicePackageReport,
    pub apply: ApplySpliceReport,
    pub post_splice_sponsor: FundSponsorReport,
    pub publish: PublishStateReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalise: Option<FinaliseChannelReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xudt_finalise: Option<XudtFinaliseReport>,
}

#[derive(Debug, Serialize)]
pub struct SpliceNegativeCaseReport {
    pub case: String,
    pub stage: String,
    pub rejected_package: String,
    pub rejection: String,
}

#[derive(Debug, Serialize)]
pub struct SpliceNegativeSmokeReport {
    pub ckb_open: OpenChannelReport,
    pub xudt_open: OpenChannelReport,
    pub ckb_package: SaveSplicePackageReport,
    pub xudt_package: SaveSplicePackageReport,
    pub signed_fee_package: SaveSplicePackageReport,
    pub rejections: Vec<SpliceNegativeCaseReport>,
}

#[derive(Debug, Serialize)]
pub struct MintXudtCellReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub xudt_type_hash: String,
    pub amount: u128,
    pub cell_out_point: PrintableOutPoint,
    pub cell_capacity: u64,
    pub change_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct XudtFinaliseReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub channel_id: String,
    pub funding_anchor: String,
    pub state_number: u64,
    pub xudt_type_hash: String,
    pub alice_capacity: u64,
    pub bob_capacity: u64,
    pub alice_xudt_amount: u128,
    pub bob_xudt_amount: u128,
    pub state_refund_capacity: u64,
    pub fee: u64,
    pub metrics: TransactionMetrics,
    pub mined_blocks: Vec<String>,
    pub outputs: Vec<ChannelCellReport>,
}

#[derive(Debug, Serialize)]
pub struct XudtSmokeReport {
    pub open: OpenChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryXudtSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryStatePackageReport,
    pub latest_package: FactoryStateCellPackageRecord,
    pub update: UpdateFactoryReport,
    pub exit: FactoryExitChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct FactoryXudtNegativeSmokeReport {
    pub open: OpenFactoryReport,
    pub package: SaveFactoryStatePackageReport,
    pub latest_package: FactoryStateCellPackageRecord,
    pub update: UpdateFactoryReport,
    pub expected_child_xudt_amount: u128,
    pub rejected_child_xudt_amount: u128,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub exit: FactoryExitChannelReport,
    pub publish: PublishStateReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct XudtNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub publish: PublishStateReport,
    pub rejected_alice_xudt_amount: u128,
    pub rejected_bob_xudt_amount: u128,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub finalise: XudtFinaliseReport,
}

#[derive(Debug, Serialize)]
pub struct SupersedeSmokeReport {
    pub open: OpenChannelReport,
    pub stale_publish: PublishStateReport,
    pub sponsor_top_up: FundSponsorReport,
    pub supersede_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct FinaliseSinceNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub publish: PublishStateReport,
    pub rejected_input_since: u64,
    pub required_finalise_since: u64,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub maturity_blocks: Vec<String>,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct SponsorPolicyNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub rejected_state_number: u64,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub allowed_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct SponsorBudgetNegativeSmokeReport {
    pub open: OpenChannelReport,
    pub rejected_fee: u64,
    pub sponsor_max_fee_per_tx: u64,
    pub rejection: String,
    pub script_failure: ScriptFailureReport,
    pub replacement_sponsor: FundSponsorReport,
    pub allowed_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
}

#[derive(Debug, Serialize)]
pub struct PendingCommitReport {
    pub tx_hash: String,
    pub status: String,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub mined_blocks: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CompetingSpendSmokeReport {
    pub open: OpenChannelReport,
    pub spare_sponsor: FundSponsorReport,
    pub pending_publish: PublishStateReport,
    pub pending_commit: PendingCommitReport,
    pub rejected_state_number: u64,
    pub rejected_against_state_out_point: String,
    pub rejection: String,
    pub rebuilt_publish: PublishStateReport,
    pub finalise: FinaliseChannelReport,
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

struct LiveCellDetails {
    output: CellOutput,
    data: Bytes,
    capacity: u64,
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
    canonical_confirmations: u64,
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

pub fn open_channel(rpc: &CkbRpcClient, options: OpenChannelOptions) -> Result<OpenChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.vault_capacity > 0,
        "vault capacity must be non-zero"
    );
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
        .with_context(|| "invalid secp256k1 private key for devnet channel opener")?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;

    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let batch_contract = contract_by_name(&contracts, "morph-batch-lock")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    let channel_input = CellInput::new(funding_cell.out_point.clone(), 0);
    let funding_anchor = derive_funding_anchor(&channel_input, 0);
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID", &funding_anchor]);
    let finalise_since = relative_block_since_arg(options.finalise_since)?;

    let state_type = data1_script(
        state_contract.data_hash.clone(),
        state_type_args(&funding_anchor, finalise_since),
    );
    let state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(state_type.calc_script_hash().as_slice()),
    );

    let vault_lock = data1_script(
        vault_contract.data_hash.clone(),
        vault_lock_args(
            &funding_anchor,
            finalise_since,
            &state_type,
            &state_lock,
            &batch_contract.data_hash,
            ScriptHashType::Data1,
        ),
    );

    let change_lock_hash = owner_lock.calc_script_hash();
    let sponsor_policy_settings = sponsor_policy_settings(
        options.sponsor_capacity,
        options.sponsor_min_state_number,
        options.sponsor_max_state_number,
        options.sponsor_max_fee_per_tx,
        options.sponsor_max_total_fee,
    )?;
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        sponsor_policy_settings,
        state_type.calc_script_hash().unpack(),
        change_lock_hash.unpack(),
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );

    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();
    let (alice_capacity, bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .build(),
        0,
    )?;
    ensure_output_capacity(
        "bob settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .build(),
        0,
    )?;
    let descriptor =
        bilateral_ckb_descriptor(alice_lock_hash, alice_capacity, bob_lock_hash, bob_capacity);
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let vault_set_commitment = vault_descriptor_commitment(&VaultDescriptor {
        funding_anchor,
        assets: live_vault_assets(u128::from(options.vault_capacity), None, None),
    });

    let alice_pubkey = compressed_pubkey(&alice_key)?;
    let bob_pubkey = compressed_pubkey(&bob_key)?;
    let mut participant_pubkeys = [alice_pubkey, bob_pubkey];
    participant_pubkeys.sort();
    let participants_commitment =
        participants_commitment(2, &[&participant_pubkeys[0], &participant_pubkeys[1]]);
    let challenge_policy_commitment =
        script_blake2b256(&[b"CKB_MORPH_CHALLENGE_POLICY", &finalise_since.to_le_bytes()]);
    let mut state_header = initial_state_header(InitialStateHeader {
        chain_id,
        channel_id,
        funding_anchor,
        vault_set_commitment,
        participants_commitment,
        asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
            xudt_types: BTreeSet::new(),
        }),
        settlement_descriptor_commitment: descriptor_commitment,
        descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
        challenge_policy_commitment,
    });
    let state_output_for_capacity = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let state_capacity = occupied_capacity(&state_output_for_capacity, state_header.len())?;
    let funding_state_capacity = state_capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("StateCell activation capacity overflow"))?;
    let funding_state_output = CellOutput::new_builder()
        .capacity(funding_state_capacity)
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();

    let vault_output = CellOutput::new_builder()
        .capacity(options.vault_capacity)
        .lock(vault_lock)
        .build();
    ensure_output_capacity("vault", &vault_output, 0)?;
    set_state_vault_materialisation_root(
        &mut state_header,
        vault_cell_commitment_from_output(&vault_output, &[]),
    );

    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("sponsor", &sponsor_output, 0)?;

    let fixed_output_capacity = funding_state_capacity
        .checked_add(options.vault_capacity)
        .and_then(|value| value.checked_add(options.sponsor_capacity))
        .ok_or_else(|| anyhow!("channel output capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(fixed_output_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover state {}, vault {}, sponsor {}, and fee {}",
                funding_cell.capacity,
                state_capacity,
                options.vault_capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();
    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .cell_dep(vault_contract.cell_dep.clone())
        .cell_dep(sponsor_contract.cell_dep.clone())
        .input(channel_input)
        .output(funding_state_output.clone())
        .output(vault_output.clone())
        .output(sponsor_output.clone())
        .output(change_output.clone())
        .output_data(Bytes::copy_from_slice(&state_header).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_bilateral_state_creation(
        unsigned,
        &owner_key,
        &state_header,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let (activation, state_output, state_header) = activate_state_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_state_output,
        &state_header,
        &state_lock_contract,
        &state_contract,
        0,
        1,
        options.mine_blocks,
    )?;

    let funding_tx_hash_string = sent.tx_hash.clone();
    let activation_tx_hash_string = activation.tx_hash.clone();
    let cell = |role: &str,
                tx_hash: &str,
                index: u32,
                output: &CellOutput,
                data_len: usize|
     -> ChannelCellReport {
        ChannelCellReport {
            role: role.to_string(),
            out_point: PrintableOutPoint {
                tx_hash: tx_hash.to_string(),
                index,
            },
            capacity: output.capacity().unpack(),
            lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
            type_hash: output
                .type_()
                .to_opt()
                .map(|script| hex32(script.calc_script_hash().as_slice())),
            data_len,
        }
    };

    Ok(OpenChannelReport {
        tx_hash: funding_tx_hash_string.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(&channel_id),
        funding_anchor: hex32(&funding_anchor),
        finalise_since: options.finalise_since,
        input_capacity: funding_cell.capacity,
        state_capacity,
        vault_capacity: options.vault_capacity,
        sponsor_capacity: options.sponsor_capacity,
        sponsor_policy: sponsor_policy_report(
            sponsor_policy_settings,
            state_type.calc_script_hash().unpack(),
            change_lock_hash.unpack(),
        ),
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        activation_tx_hash: activation_tx_hash_string.clone(),
        activation_status: activation.status,
        activation_block_number: activation.block_number,
        activation_block_hash: activation.block_hash,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE,
        activation_metrics: activation.metrics,
        activation_mined_blocks: activation.mined_blocks,
        participants: vec![
            ParticipantReport {
                role: "alice".to_string(),
                lock_hash: hex32(&alice_lock_hash),
                pubkey_sec1: hex_prefixed(&alice_pubkey),
                capacity: alice_capacity,
            },
            ParticipantReport {
                role: "bob".to_string(),
                lock_hash: hex32(&bob_lock_hash),
                pubkey_sec1: hex_prefixed(&bob_pubkey),
                capacity: bob_capacity,
            },
        ],
        scripts: contracts
            .into_iter()
            .map(|contract| ResolvedScriptReport {
                name: contract.name,
                out_point: printable_out_point(&contract.out_point),
                data_hash: format!("{:#x}", contract.data_hash),
                hash_type: "data1".to_string(),
            })
            .collect(),
        cells: vec![
            cell(
                "state",
                &activation_tx_hash_string,
                0,
                &state_output,
                state_header.len(),
            ),
            cell("vault", &funding_tx_hash_string, 1, &vault_output, 0),
            cell("sponsor", &funding_tx_hash_string, 2, &sponsor_output, 0),
            cell("change", &funding_tx_hash_string, 3, &change_output, 0),
        ],
    })
}

pub fn open_factory(rpc: &CkbRpcClient, options: OpenFactoryOptions) -> Result<OpenFactoryReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.factory_capacity > 0,
        "factory capacity must be non-zero"
    );
    ensure!(
        options.factory_vault_capacity > 0,
        "factory vault capacity must be non-zero"
    );
    if let Some(amount) = options.factory_vault_xudt_amount {
        ensure!(amount > 0, "factory vault xUDT amount must be non-zero");
    }

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory opener")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let participant_entries = factory_signing_entries(
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;

    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    let factory_vault_contract = contract_by_name(&contracts, "morph-factory-vault-lock")?;
    let xudt_contract = if options.factory_vault_xudt_amount.is_some() {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };

    let factory_input = CellInput::new(funding_cell.out_point.clone(), 0);
    let factory_id = derive_funding_anchor(&factory_input, 0);
    let factory_type = data1_script(
        factory_contract.data_hash.clone(),
        Bytes::copy_from_slice(&factory_id),
    );
    let factory_state_lock = type_bound_state_lock(&state_lock_contract, &factory_type);
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = factory_id.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock = data1_script(
        factory_vault_contract.data_hash.clone(),
        Bytes::from(factory_vault_args),
    );
    let owner_lock_hash = owner_lock.calc_script_hash();
    let xudt_type = xudt_contract.as_ref().map(|contract| {
        data1_script(
            contract.data_hash.clone(),
            Bytes::copy_from_slice(owner_lock_hash.as_slice()),
        )
    });
    let xudt_type_hash = xudt_type
        .as_ref()
        .map(|script| hex32(script.calc_script_hash().as_slice()));

    let state_root = parse_optional_hex32("state root", options.state_root.as_deref())?
        .unwrap_or_else(|| script_blake2b256(&[b"CKB_MORPH_EMPTY_FACTORY_STATE_ROOT"]));
    let access_manifest_root = parse_optional_hex32(
        "access manifest root",
        options.access_manifest_root.as_deref(),
    )?
    .unwrap_or_else(|| script_blake2b256(&[b"CKB_MORPH_EMPTY_FACTORY_ACCESS_MANIFEST"]));
    let non_interference_digest = parse_optional_hex32(
        "non-interference digest",
        options.non_interference_digest.as_deref(),
    )?
    .unwrap_or_else(|| script_blake2b256(&[b"CKB_MORPH_INITIAL_FACTORY_NON_INTERFERENCE"]));
    let participants_commitment =
        factory_participants_commitment_from_entries(&participant_entries);
    let challenge_policy_commitment = script_blake2b256(&[b"CKB_MORPH_FACTORY_CHALLENGE_POLICY"]);
    let funding_factory_capacity = options
        .factory_capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("FactoryStateCell activation capacity overflow"))?;
    let funding_factory_output = CellOutput::new_builder()
        .capacity(funding_factory_capacity)
        .lock(factory_state_lock)
        .type_(Some(factory_type.clone()).pack())
        .build();
    ensure_output_capacity("factory", &funding_factory_output, FACTORY_STATE_HEADER_LEN)?;

    let factory_vault_output = CellOutput::new_builder()
        .capacity(options.factory_vault_capacity)
        .lock(factory_vault_lock)
        .type_(xudt_type.clone().pack())
        .build();
    let factory_vault_data = options
        .factory_vault_xudt_amount
        .map(xudt_amount_bytes)
        .unwrap_or_default();
    ensure_output_capacity(
        "factory vault",
        &factory_vault_output,
        factory_vault_data.len(),
    )?;
    let factory_header = factory_state_header(FactoryHeaderInput {
        chain_id,
        factory_id,
        update_number: 0,
        state_root,
        participants_commitment,
        access_manifest_root,
        non_interference_digest,
        challenge_policy_commitment,
        vault_materialisation_root: vault_cell_commitment_from_output(
            &factory_vault_output,
            factory_vault_data.as_ref(),
        ),
    });

    let fixed_output_capacity = funding_factory_capacity
        .checked_add(options.factory_vault_capacity)
        .ok_or_else(|| anyhow!("factory output capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(fixed_output_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover factory capacity {}, factory vault capacity {}, and fee {}",
                funding_cell.capacity,
                options.factory_capacity,
                options.factory_vault_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;
    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();

    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep.clone())
        .cell_dep(factory_contract.cell_dep.clone())
        .cell_dep(factory_vault_contract.cell_dep.clone());
    if let Some(contract) = xudt_contract.as_ref() {
        builder = builder.cell_dep(contract.cell_dep.clone());
    }
    let unsigned = builder
        .input(factory_input)
        .output(funding_factory_output.clone())
        .output(factory_vault_output.clone())
        .output(change_output.clone())
        .output_data(Bytes::copy_from_slice(&factory_header).pack())
        .output_data(factory_vault_data.clone().pack())
        .output_data(Bytes::new().pack())
        .build();
    let initial_signature_witness = factory_signature_witness(
        &factory_header,
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;
    let initial_contract_witness = factory_witness_envelope(
        factory_signature_envelope_kind(&initial_signature_witness)?,
        &initial_signature_witness,
    )?;
    let signed = sign_single_secp_input_with_input_type(
        unsigned,
        &owner_key,
        Bytes::from(initial_contract_witness),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let (activation, factory_output, factory_header) = activate_factory_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_factory_output,
        &factory_header,
        &state_lock_contract,
        &factory_contract,
        0,
        1,
        options.mine_blocks,
    )?;
    let funding_tx_hash_string = sent.tx_hash.clone();
    let activation_tx_hash_string = activation.tx_hash.clone();

    let cell = |role: &str,
                tx_hash: &str,
                index: u32,
                output: &CellOutput,
                data_len: usize|
     -> ChannelCellReport {
        ChannelCellReport {
            role: role.to_string(),
            out_point: PrintableOutPoint {
                tx_hash: tx_hash.to_string(),
                index,
            },
            capacity: output.capacity().unpack(),
            lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
            type_hash: output
                .type_()
                .to_opt()
                .map(|script| hex32(script.calc_script_hash().as_slice())),
            data_len,
        }
    };

    Ok(OpenFactoryReport {
        tx_hash: funding_tx_hash_string.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(&factory_id),
        input_capacity: funding_cell.capacity,
        factory_capacity: options.factory_capacity,
        factory_vault_capacity: options.factory_vault_capacity,
        factory_vault_xudt_amount: options.factory_vault_xudt_amount,
        xudt_type_hash,
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        activation_tx_hash: activation_tx_hash_string.clone(),
        activation_status: activation.status,
        activation_block_number: activation.block_number,
        activation_block_hash: activation.block_hash,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE,
        activation_metrics: activation.metrics,
        activation_mined_blocks: activation.mined_blocks,
        participants: factory_participant_reports(&participant_entries),
        scripts: contracts
            .into_iter()
            .map(|contract| ResolvedScriptReport {
                name: contract.name,
                out_point: printable_out_point(&contract.out_point),
                data_hash: format!("{:#x}", contract.data_hash),
                hash_type: "data1".to_string(),
            })
            .collect(),
        cells: vec![
            cell(
                "factory",
                &activation_tx_hash_string,
                0,
                &factory_output,
                factory_header.len(),
            ),
            cell(
                "factory-vault",
                &funding_tx_hash_string,
                1,
                &factory_vault_output,
                factory_vault_data.len(),
            ),
            cell("change", &funding_tx_hash_string, 2, &change_output, 0),
        ],
    })
}

pub fn update_factory(
    rpc: &CkbRpcClient,
    options: UpdateFactoryOptions,
) -> Result<UpdateFactoryReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory updater")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        factory_type.args().raw_data().as_ref() == old_header.factory_id(),
        "factory type args do not match the factory id in cell data"
    );
    let old_update_number = old_header.update_number();
    let (
        new_factory_data,
        signature_witness,
        new_update_number,
        state_root,
        access_manifest_root,
        non_interference_digest,
        factory_state_package,
    ) = if let Some(path) = &options.factory_state_package {
        ensure!(
            options.update_number.is_none()
                && options.state_root.is_none()
                && options.access_manifest_root.is_none()
                && options.non_interference_digest.is_none(),
            "factory_state_package cannot be combined with update_number or root overrides"
        );
        let package = read_factory_state_cell_update_package(path)?;
        package.validate_against_current_header(&old_header)?;
        let header_bytes = package.new_header_bytes()?;
        let witness_bytes = package.contract_witness_bytes()?;
        let package_header = FactoryStateHeader::parse(&header_bytes)
            .map_err(|err| anyhow!("factory state package header is invalid: {err:?}"))?;
        ensure!(
            package.factory_id() == hex32(old_header.factory_id()),
            "factory state package is for factory {}, not {}",
            package.factory_id(),
            hex32(old_header.factory_id())
        );
        ensure!(
            old_header.same_context_except_progress(&package_header),
            "factory state package does not match the current factory context"
        );
        ensure!(
            old_header.vault_materialisation_root() == package_header.vault_materialisation_root(),
            "ordinary factory state packages cannot change the FactoryVault materialisation"
        );
        ensure!(
            package_header.update_number() > old_update_number,
            "factory state package number {} must be greater than old update number {}",
            package_header.update_number(),
            old_update_number
        );
        let package_update_number = package_header.update_number();
        ensure!(
            package.update_number() == package_update_number,
            "factory state package update number metadata does not match header"
        );
        let package_state_root =
            bytes32_from_slice("factory package state root", package_header.state_root())?;
        ensure!(
            package.state_root() == hex32(&package_state_root),
            "factory state package state root metadata does not match header"
        );
        let package_access_manifest_root = bytes32_from_slice(
            "factory package access manifest root",
            package_header.access_manifest_root(),
        )?;
        ensure!(
            package.access_manifest_root() == hex32(&package_access_manifest_root),
            "factory state package access manifest metadata does not match header"
        );
        let package_non_interference_digest = bytes32_from_slice(
            "factory package non-interference digest",
            package_header.non_interference_digest(),
        )?;
        ensure!(
            package.non_interference_digest() == hex32(&package_non_interference_digest),
            "factory state package non-interference metadata does not match header"
        );
        (
            header_bytes,
            witness_bytes,
            package_update_number,
            package_state_root,
            package_access_manifest_root,
            package_non_interference_digest,
            Some(path.display().to_string()),
        )
    } else {
        let new_update_number = options
            .update_number
            .unwrap_or_else(|| old_update_number.saturating_add(1));
        ensure!(
            new_update_number > old_update_number,
            "new update number must be greater than old update number {}",
            old_update_number
        );
        let state_root = parse_optional_hex32("state root", options.state_root.as_deref())?
            .unwrap_or_else(|| {
                derived_factory_update_digest(
                    b"CKB_MORPH_FACTORY_STATE_ROOT_UPDATE",
                    old_header.state_root(),
                    new_update_number,
                )
            });
        let access_manifest_root = parse_optional_hex32(
            "access manifest root",
            options.access_manifest_root.as_deref(),
        )?
        .unwrap_or_else(|| {
            derived_factory_update_digest(
                b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_UPDATE",
                old_header.access_manifest_root(),
                new_update_number,
            )
        });
        let non_interference_digest = parse_optional_hex32(
            "non-interference digest",
            options.non_interference_digest.as_deref(),
        )?
        .unwrap_or_else(|| {
            derived_factory_update_digest(
                b"CKB_MORPH_FACTORY_NON_INTERFERENCE_UPDATE",
                old_header.non_interference_digest(),
                new_update_number,
            )
        });

        let mut new_factory_data = factory_cell.data.to_vec();
        put_u64(&mut new_factory_data, 68, new_update_number);
        new_factory_data[76..108].copy_from_slice(&state_root);
        new_factory_data[140..172].copy_from_slice(&access_manifest_root);
        new_factory_data[172..204].copy_from_slice(&non_interference_digest);
        let signature_witness = factory_signature_witness(
            &new_factory_data,
            &options.alice_private_key,
            &options.bob_private_key,
            &options.additional_participant_private_keys,
        )?;
        let contract_witness = factory_witness_envelope(
            factory_signature_envelope_kind(&signature_witness)?,
            &signature_witness,
        )?;
        (
            new_factory_data,
            contract_witness,
            new_update_number,
            state_root,
            access_manifest_root,
            non_interference_digest,
            None,
        )
    };

    let tip_number = rpc.tip_header()?.number_value()?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    ensure!(
        byte32_to_h256(factory_type.code_hash()) == factory_contract.data_hash,
        "factory cell type script does not use the deployed morph-factory-type code hash"
    );
    ensure_type_bound_state_lock(
        &factory_cell.output,
        &factory_type,
        &state_lock_contract,
        "FactoryStateCell",
    )?;

    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    ensure!(
        fee_cell.out_point != factory_out_point,
        "fee input cannot be the FactoryStateCell itself"
    );
    let fee_change_capacity = fee_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("fee input capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    ensure_output_capacity("factory", &factory_cell.output, new_factory_data.len())?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock)
        .build();

    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(factory_contract.cell_dep)
        .input(CellInput::new(factory_out_point, 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0))
        .output(factory_cell.output.clone())
        .output(fee_change_output)
        .output_data(Bytes::from(new_factory_data).pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_factory_update_transaction(
        unsigned,
        &owner_key,
        Bytes::copy_from_slice(&signature_witness),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let new_factory_tx_hash = sent.tx_hash.clone();

    Ok(UpdateFactoryReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(old_header.factory_id()),
        old_update_number,
        new_update_number,
        factory_out_point: PrintableOutPoint {
            tx_hash: new_factory_tx_hash,
            index: 0,
        },
        factory_capacity: factory_cell.capacity,
        fee_input_capacity: fee_cell.capacity,
        fee_change_capacity,
        fee: options.fee,
        state_root: hex32(&state_root),
        access_manifest_root: hex32(&access_manifest_root),
        non_interference_digest: hex32(&non_interference_digest),
        factory_state_package,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
    })
}

pub fn save_factory_state_package(
    rpc: &CkbRpcClient,
    options: SaveFactoryStatePackageOptions,
) -> Result<SaveFactoryStatePackageReport> {
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    let new_update_number = options
        .update_number
        .unwrap_or_else(|| old_header.update_number().saturating_add(1));
    ensure!(
        new_update_number > old_header.update_number(),
        "new update number must be greater than old update number {}",
        old_header.update_number()
    );
    let state_root = parse_optional_hex32("state root", options.state_root.as_deref())?
        .unwrap_or_else(|| {
            derived_factory_update_digest(
                b"CKB_MORPH_FACTORY_STATE_ROOT_UPDATE",
                old_header.state_root(),
                new_update_number,
            )
        });
    let access_manifest_root = parse_optional_hex32(
        "access manifest root",
        options.access_manifest_root.as_deref(),
    )?
    .unwrap_or_else(|| {
        derived_factory_update_digest(
            b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_UPDATE",
            old_header.access_manifest_root(),
            new_update_number,
        )
    });
    let non_interference_digest = parse_optional_hex32(
        "non-interference digest",
        options.non_interference_digest.as_deref(),
    )?
    .unwrap_or_else(|| {
        derived_factory_update_digest(
            b"CKB_MORPH_FACTORY_NON_INTERFERENCE_UPDATE",
            old_header.non_interference_digest(),
            new_update_number,
        )
    });

    let mut new_factory_data = factory_cell.data.to_vec();
    put_u64(&mut new_factory_data, 68, new_update_number);
    new_factory_data[76..108].copy_from_slice(&state_root);
    new_factory_data[140..172].copy_from_slice(&access_manifest_root);
    new_factory_data[172..204].copy_from_slice(&non_interference_digest);
    let signature_witness = factory_signature_witness(
        &new_factory_data,
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;

    let printable = printable_out_point(&factory_out_point);
    let package = StoredFactoryStateCellPackage::from_signed_factory_state(
        &new_factory_data,
        &signature_witness,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )?;
    let path = write_factory_state_cell_package(&options.store_dir, &package)?;

    Ok(SaveFactoryStatePackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn save_factory_reduced_rights_package(
    rpc: &CkbRpcClient,
    options: SaveFactoryReducedRightsPackageOptions,
) -> Result<SaveFactoryReducedRightsPackageReport> {
    ensure!(
        options.touched_after_balance < 100,
        "touched_after_balance must decrease the fixture balance below 100"
    );
    let participant_entries = factory_signing_entries(
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;
    let participant_keys = participant_entries
        .iter()
        .map(|(_, _, key)| key.clone())
        .collect::<Vec<_>>();
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    let printable = printable_out_point(&factory_out_point);
    let package = reduced_rights_package_from_factory_header(
        factory_cell.data.as_ref(),
        &participant_keys,
        options.update_number,
        options.touched_after_balance,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )
    .with_context(|| {
        format!(
            "factory {} at update {} is not compatible with the reduced-rights proof shape",
            hex32(old_header.factory_id()),
            old_header.update_number()
        )
    })?;
    let path = write_factory_reduced_rights_package(&options.store_dir, &package)?;

    Ok(SaveFactoryReducedRightsPackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn save_factory_splice_package(
    rpc: &CkbRpcClient,
    options: SaveFactorySplicePackageOptions,
) -> Result<SaveFactorySplicePackageReport> {
    let participant_entries = factory_signing_entries(
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;
    let participant_signing_keys = participant_entries
        .iter()
        .map(|(participant, _, key)| (*participant, key.clone()))
        .collect::<Vec<_>>();
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_vault_out_point = parse_out_point(&options.factory_vault_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_vault_cell = load_live_cell(rpc, factory_vault_out_point.clone())?;
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        factory_type.args().raw_data().as_ref() == old_header.factory_id(),
        "factory type args do not match the factory id in cell data"
    );
    let expected_participants = factory_participants_commitment_from_entries(&participant_entries);
    ensure!(
        old_header.participants_commitment() == expected_participants.as_slice(),
        "live factory participant commitment does not match supplied participant keys"
    );
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let factory_vault_args = factory_vault_cell.output.lock().args().raw_data();
    ensure!(
        factory_vault_args.len() == 2 * BYTE32_LEN,
        "factory vault lock args must be 64 bytes"
    );
    ensure!(
        &factory_vault_args.as_ref()[..BYTE32_LEN] == old_header.factory_id(),
        "factory vault lock is for a different factory id"
    );
    ensure!(
        &factory_vault_args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN] == factory_type_hash.as_slice(),
        "factory vault lock is for a different factory type hash"
    );

    let live_xudt = live_vault_xudt_asset(&factory_vault_cell)?;
    let old_update_number = old_header.update_number();
    let new_update_number = options
        .update_number
        .unwrap_or_else(|| old_update_number.saturating_add(1));
    ensure!(
        new_update_number > old_update_number,
        "new update number must be greater than old update number {}",
        old_update_number
    );

    let old_ckb_amount = u128::from(factory_vault_cell.capacity);
    let mut new_ckb_amount = old_ckb_amount;
    let old_xudt_amount = live_xudt.as_ref().map(|asset| asset.amount);
    let mut new_xudt_amount = old_xudt_amount;
    let splice_kind = match options.kind {
        DevnetSpliceKind::SpliceIn => FactorySpliceKind::In,
        DevnetSpliceKind::SpliceOut => FactorySpliceKind::Out,
    };
    let withdrawal_lock_hash = match splice_kind {
        FactorySpliceKind::In => [0; BYTE32_LEN],
        FactorySpliceKind::Out => {
            let (_, pubkey, _) = participant_entries
                .first()
                .ok_or_else(|| anyhow!("factory splice requires a touched participant"))?;
            secp256k1_lock_from_pubkey(pubkey)?
                .calc_script_hash()
                .unpack()
        }
    };
    let (asset, old_amount, new_amount, external_input, withdrawal) = match options.asset {
        DevnetSpliceAsset::Ckb => {
            ensure!(options.ckb_amount > 0, "ckb_amount must be non-zero");
            let amount = u128::from(options.ckb_amount);
            match options.kind {
                DevnetSpliceKind::SpliceIn => {
                    new_ckb_amount = old_ckb_amount
                        .checked_add(amount)
                        .ok_or_else(|| anyhow!("post-splice factory vault capacity overflows"))?;
                    (VaultAsset::Ckb, old_ckb_amount, new_ckb_amount, amount, 0)
                }
                DevnetSpliceKind::SpliceOut => {
                    ensure!(
                        amount < old_ckb_amount,
                        "factory splice-out amount must be below live vault capacity {}",
                        factory_vault_cell.capacity
                    );
                    new_ckb_amount = old_ckb_amount - amount;
                    (VaultAsset::Ckb, old_ckb_amount, new_ckb_amount, 0, amount)
                }
            }
        }
        DevnetSpliceAsset::Xudt => {
            let amount = options
                .xudt_amount
                .ok_or_else(|| anyhow!("xudt_amount is required for xUDT factory splices"))?;
            ensure!(amount > 0, "xudt_amount must be non-zero");
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("live FactoryVaultCell does not carry xUDT"))?;
            match options.kind {
                DevnetSpliceKind::SpliceIn => {
                    let post_splice_amount = live_xudt
                        .amount
                        .checked_add(amount)
                        .ok_or_else(|| anyhow!("post-splice factory xUDT amount overflows"))?;
                    new_xudt_amount = Some(post_splice_amount);
                    (
                        VaultAsset::Xudt(live_xudt.type_hash),
                        live_xudt.amount,
                        post_splice_amount,
                        amount,
                        0,
                    )
                }
                DevnetSpliceKind::SpliceOut => {
                    ensure!(
                        amount < live_xudt.amount,
                        "factory xUDT splice-out amount must be below live vault amount {}",
                        live_xudt.amount
                    );
                    let post_splice_amount = live_xudt.amount - amount;
                    new_xudt_amount = Some(post_splice_amount);
                    (
                        VaultAsset::Xudt(live_xudt.type_hash),
                        live_xudt.amount,
                        post_splice_amount,
                        0,
                        amount,
                    )
                }
            }
        }
    };

    let asset_type = match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(type_hash) => Some(type_hash),
    };
    let (before, after) = factory_splice_reserve_rights(asset_type, old_amount, new_amount);
    let old_state_root = factory_right_sparse_root(&before)
        .map_err(|err| anyhow!("failed to compute factory splice old root: {err:?}"))?;
    ensure!(
        old_header.state_root() == old_state_root.as_slice(),
        "live factory state_root does not match the conservative factory-splice reserve shape"
    );
    let new_state_root = factory_right_sparse_root(&after)
        .map_err(|err| anyhow!("failed to compute factory splice new root: {err:?}"))?;
    let old_access_manifest_root = bytes32_from_slice(
        "factory access_manifest_root",
        old_header.access_manifest_root(),
    )?;
    let new_access_manifest_root = derived_factory_update_digest(
        b"CKB_MORPH_FACTORY_SPLICE_ACCESS_MANIFEST",
        old_header.access_manifest_root(),
        new_update_number,
    );
    let factory_id = bytes32_from_slice("factory id", old_header.factory_id())?;
    let xudt_type_hash = live_xudt.as_ref().map(|asset| asset.type_hash);
    let old_vault = FactoryVaultDescriptor {
        factory_id,
        assets: live_vault_assets(old_ckb_amount, xudt_type_hash, old_xudt_amount),
    };
    let new_vault = FactoryVaultDescriptor {
        factory_id,
        assets: live_vault_assets(new_ckb_amount, xudt_type_hash, new_xudt_amount),
    };
    let deltas = vec![FactoryVaultDelta {
        asset: asset.clone(),
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    }];
    let old_vault_materialisation_root = vault_cell_commitment_from_output(
        &factory_vault_cell.output,
        factory_vault_cell.data.as_ref(),
    );
    let new_vault_capacity = u64::try_from(new_ckb_amount)
        .map_err(|_| anyhow!("new FactoryVault CKB amount exceeds u64 capacity"))?;
    let new_vault_output = CellOutput::new_builder()
        .capacity(new_vault_capacity)
        .lock(factory_vault_cell.output.lock())
        .type_(factory_vault_cell.output.type_())
        .build();
    let new_vault_data = new_xudt_amount.map(xudt_amount_bytes).unwrap_or_default();
    let new_vault_materialisation_root =
        vault_cell_commitment_from_output(&new_vault_output, new_vault_data.as_ref());
    let header = FactorySpliceHeader {
        protocol_version: old_header.protocol_version(),
        chain_id: bytes32_from_slice("factory chain id", old_header.chain_id())?,
        signature_scheme_id: old_header.signature_scheme_id(),
        factory_id,
        old_update_number,
        new_update_number,
        old_state_root,
        new_state_root,
        old_access_manifest_root,
        new_access_manifest_root,
        kind: splice_kind,
        vault_delta_commitment: factory_vault_delta_commitment(&deltas),
        non_interference_digest: [0u8; BYTE32_LEN],
        participants_commitment: expected_participants,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        old_vault_outpoint_commitment: bytes32_from_slice(
            "factory vault_outpoint_commitment",
            old_header.vault_outpoint_commitment(),
        )?,
        new_vault_outpoint_commitment: [0; BYTE32_LEN],
        withdrawal_lock_hash,
    };
    let transition = FactorySpliceTransition {
        header,
        witness: SpliceWitness {
            threshold: 0,
            signatures: Vec::new(),
        },
        update: FactoryUpdate {
            before,
            after,
            touched_participants: BTreeSet::from([[1u8; BYTE32_LEN]]),
            authorised_participants: BTreeSet::from([[1u8; BYTE32_LEN]]),
        },
        old_vault,
        new_vault,
        deltas,
        asset_registry: AssetRegistry {
            xudt_types: xudt_type_hash.into_iter().collect(),
        },
    };
    let package =
        StoredFactorySplicePackage::from_transition(transition, &participant_signing_keys)?;
    let summary = package.summary()?;
    let path = write_factory_splice_package(&options.store_dir, &package)?;

    Ok(SaveFactorySplicePackageReport {
        path: path.display().to_string(),
        kind: summary.kind,
        asset: match options.asset {
            DevnetSpliceAsset::Ckb => "ckb",
            DevnetSpliceAsset::Xudt => "xudt",
        }
        .to_string(),
        factory_id: summary.factory_id,
        old_update_number: summary.old_update_number,
        new_update_number: summary.new_update_number,
        old_vault_amount: summary.vault_old_amount,
        new_vault_amount: summary.vault_new_amount,
        external_input: summary.external_input,
        withdrawal: summary.withdrawal,
        contract_witness_len: summary.contract_witness_len,
        package,
    })
}

pub fn save_factory_reduced_splice_package(
    rpc: &CkbRpcClient,
    options: SaveFactoryReducedSplicePackageOptions,
) -> Result<SaveFactoryReducedSplicePackageReport> {
    let participant_entries = factory_signing_entries(
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;
    let participant_signing_keys = participant_entries
        .iter()
        .map(|(participant, _, key)| (*participant, key.clone()))
        .collect::<Vec<_>>();
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_vault_out_point = parse_out_point(&options.factory_vault_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_vault_cell = load_live_cell(rpc, factory_vault_out_point)?;
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        factory_type.args().raw_data().as_ref() == old_header.factory_id(),
        "factory type args do not match the factory id in cell data"
    );
    let expected_participants = factory_participants_commitment_from_entries(&participant_entries);
    ensure!(
        old_header.participants_commitment() == expected_participants.as_slice(),
        "live factory participant commitment does not match supplied participant keys"
    );
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let factory_vault_args = factory_vault_cell.output.lock().args().raw_data();
    ensure!(
        factory_vault_args.len() == 2 * BYTE32_LEN,
        "factory vault lock args must be 64 bytes"
    );
    ensure!(
        &factory_vault_args.as_ref()[..BYTE32_LEN] == old_header.factory_id(),
        "factory vault lock is for a different factory id"
    );
    ensure!(
        &factory_vault_args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN] == factory_type_hash.as_slice(),
        "factory vault lock is for a different factory type hash"
    );

    let live_xudt = live_vault_xudt_asset(&factory_vault_cell)?;
    let old_update_number = old_header.update_number();
    let new_update_number = options
        .update_number
        .unwrap_or_else(|| old_update_number.saturating_add(1));
    ensure!(
        new_update_number > old_update_number,
        "new update number must be greater than old update number {}",
        old_update_number
    );

    let old_ckb_amount = u128::from(factory_vault_cell.capacity);
    let mut new_ckb_amount = old_ckb_amount;
    let old_xudt_amount = live_xudt.as_ref().map(|asset| asset.amount);
    let mut new_xudt_amount = old_xudt_amount;
    let splice_kind = match options.kind {
        DevnetSpliceKind::SpliceIn => FactorySpliceKind::In,
        DevnetSpliceKind::SpliceOut => FactorySpliceKind::Out,
    };
    let withdrawal_lock_hash = match splice_kind {
        FactorySpliceKind::In => [0; BYTE32_LEN],
        FactorySpliceKind::Out => {
            let (_, pubkey, _) = participant_entries
                .first()
                .ok_or_else(|| anyhow!("reduced factory splice requires a touched participant"))?;
            secp256k1_lock_from_pubkey(pubkey)?
                .calc_script_hash()
                .unpack()
        }
    };
    let (asset, old_amount, new_amount, external_input, withdrawal) = match options.asset {
        DevnetSpliceAsset::Ckb => {
            ensure!(options.ckb_amount > 0, "ckb_amount must be non-zero");
            let amount = u128::from(options.ckb_amount);
            match options.kind {
                DevnetSpliceKind::SpliceIn => {
                    new_ckb_amount = old_ckb_amount
                        .checked_add(amount)
                        .ok_or_else(|| anyhow!("post-splice factory vault capacity overflows"))?;
                    (VaultAsset::Ckb, old_ckb_amount, new_ckb_amount, amount, 0)
                }
                DevnetSpliceKind::SpliceOut => {
                    ensure!(
                        amount < old_ckb_amount,
                        "factory splice-out amount must be below live vault capacity {}",
                        factory_vault_cell.capacity
                    );
                    new_ckb_amount = old_ckb_amount - amount;
                    (VaultAsset::Ckb, old_ckb_amount, new_ckb_amount, 0, amount)
                }
            }
        }
        DevnetSpliceAsset::Xudt => {
            let amount = options
                .xudt_amount
                .ok_or_else(|| anyhow!("xudt_amount is required for xUDT factory splices"))?;
            ensure!(amount > 0, "xudt_amount must be non-zero");
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("live FactoryVaultCell does not carry xUDT"))?;
            match options.kind {
                DevnetSpliceKind::SpliceIn => {
                    let post_splice_amount = live_xudt
                        .amount
                        .checked_add(amount)
                        .ok_or_else(|| anyhow!("post-splice factory xUDT amount overflows"))?;
                    new_xudt_amount = Some(post_splice_amount);
                    (
                        VaultAsset::Xudt(live_xudt.type_hash),
                        live_xudt.amount,
                        post_splice_amount,
                        amount,
                        0,
                    )
                }
                DevnetSpliceKind::SpliceOut => {
                    ensure!(
                        amount < live_xudt.amount,
                        "factory xUDT splice-out amount must be below live vault amount {}",
                        live_xudt.amount
                    );
                    let post_splice_amount = live_xudt.amount - amount;
                    new_xudt_amount = Some(post_splice_amount);
                    (
                        VaultAsset::Xudt(live_xudt.type_hash),
                        live_xudt.amount,
                        post_splice_amount,
                        0,
                        amount,
                    )
                }
            }
        }
    };

    let asset_type = match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(type_hash) => Some(type_hash),
    };
    let (before, after) = factory_splice_reserve_rights(asset_type, old_amount, new_amount);
    let changed_id = before[0].id.clone();
    let old_state_root = factory_right_sparse_root(&before)
        .map_err(|err| anyhow!("failed to compute reduced factory splice old root: {err:?}"))?;
    ensure!(
        old_header.state_root() == old_state_root.as_slice(),
        "live factory state_root does not match the reduced factory-splice reserve shape"
    );
    let new_state_root = factory_right_sparse_root(&after)
        .map_err(|err| anyhow!("failed to compute reduced factory splice new root: {err:?}"))?;
    let before_proof = factory_right_sparse_proof(&before, &changed_id).map_err(|err| {
        anyhow!("failed to build reduced factory splice old sparse proof: {err:?}")
    })?;
    let after_proof = factory_right_sparse_proof(&after, &changed_id).map_err(|err| {
        anyhow!("failed to build reduced factory splice new sparse proof: {err:?}")
    })?;
    ensure!(
        before_proof.siblings == after_proof.siblings,
        "reduced factory splice proof must keep the sibling frontier unchanged"
    );

    let old_access_manifest_root = bytes32_from_slice(
        "factory access_manifest_root",
        old_header.access_manifest_root(),
    )?;
    let factory_id = bytes32_from_slice("factory id", old_header.factory_id())?;
    let xudt_type_hash = live_xudt.as_ref().map(|asset| asset.type_hash);
    let old_vault = FactoryVaultDescriptor {
        factory_id,
        assets: live_vault_assets(old_ckb_amount, xudt_type_hash, old_xudt_amount),
    };
    let new_vault = FactoryVaultDescriptor {
        factory_id,
        assets: live_vault_assets(new_ckb_amount, xudt_type_hash, new_xudt_amount),
    };
    let deltas = vec![FactoryVaultDelta {
        asset: asset.clone(),
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    }];
    let old_vault_materialisation_root = vault_cell_commitment_from_output(
        &factory_vault_cell.output,
        factory_vault_cell.data.as_ref(),
    );
    let new_vault_capacity = u64::try_from(new_ckb_amount)
        .map_err(|_| anyhow!("new FactoryVault CKB amount exceeds u64 capacity"))?;
    let new_vault_output = CellOutput::new_builder()
        .capacity(new_vault_capacity)
        .lock(factory_vault_cell.output.lock())
        .type_(factory_vault_cell.output.type_())
        .build();
    let new_vault_data = new_xudt_amount.map(xudt_amount_bytes).unwrap_or_default();
    let new_vault_materialisation_root =
        vault_cell_commitment_from_output(&new_vault_output, new_vault_data.as_ref());
    let header = FactorySpliceHeader {
        protocol_version: old_header.protocol_version(),
        chain_id: bytes32_from_slice("factory chain id", old_header.chain_id())?,
        signature_scheme_id: old_header.signature_scheme_id(),
        factory_id,
        old_update_number,
        new_update_number,
        old_state_root,
        new_state_root,
        old_access_manifest_root,
        new_access_manifest_root: old_access_manifest_root,
        kind: splice_kind,
        vault_delta_commitment: factory_vault_delta_commitment(&deltas),
        non_interference_digest: [0u8; BYTE32_LEN],
        participants_commitment: expected_participants,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        old_vault_outpoint_commitment: bytes32_from_slice(
            "factory vault_outpoint_commitment",
            old_header.vault_outpoint_commitment(),
        )?,
        new_vault_outpoint_commitment: [0; BYTE32_LEN],
        withdrawal_lock_hash,
    };
    let update = FactorySingleRightMerkleUpdate {
        before_root: old_state_root,
        after_root: new_state_root,
        touched_participants: BTreeSet::from([[1u8; BYTE32_LEN]]),
        authorised_participants: BTreeSet::from([[1u8; BYTE32_LEN]]),
        before: before_proof,
        after: after_proof,
    };
    let transition = FactoryReducedSpliceTransition {
        header,
        witness: FactoryReducedSpliceWitness {
            participant_threshold: 0,
            participant_keys: Vec::new(),
            signatures: Vec::new(),
        },
        update,
        old_vault,
        new_vault,
        deltas,
        asset_registry: AssetRegistry {
            xudt_types: xudt_type_hash.into_iter().collect(),
        },
    };
    let package =
        StoredFactoryReducedSplicePackage::from_transition(transition, &participant_signing_keys)?;
    let summary = package.summary()?;
    let path = write_factory_reduced_splice_package(&options.store_dir, &package)?;

    Ok(SaveFactoryReducedSplicePackageReport {
        path: path.display().to_string(),
        kind: summary.kind,
        asset: match options.asset {
            DevnetSpliceAsset::Ckb => "ckb",
            DevnetSpliceAsset::Xudt => "xudt",
        }
        .to_string(),
        factory_id: summary.factory_id,
        old_update_number: summary.old_update_number,
        new_update_number: summary.new_update_number,
        old_vault_amount: summary.vault_old_amount,
        new_vault_amount: summary.vault_new_amount,
        external_input: summary.external_input,
        withdrawal: summary.withdrawal,
        proof_siblings: summary.proof_siblings,
        contract_witness_len: summary.contract_witness_len,
        package,
    })
}

pub fn apply_factory_splice(
    rpc: &CkbRpcClient,
    options: ApplyFactorySpliceOptions,
) -> Result<ApplyFactorySpliceReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory splice fee/change")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let package = read_factory_splice_package(&options.factory_splice_package)?;
    let transition = package.validate()?;
    let contract_witness = package.contract_witness_bytes()?;
    let delta = transition
        .deltas
        .first()
        .ok_or_else(|| anyhow!("factory splice package has no vault delta"))?;

    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_vault_out_point = parse_out_point(&options.factory_vault_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_vault_cell = load_live_cell(rpc, factory_vault_out_point.clone())?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        old_header.factory_id() == transition.header.factory_id.as_slice(),
        "factory splice package is for a different factory id"
    );
    ensure!(
        old_header.update_number() == transition.header.old_update_number
            && old_header.state_root() == transition.header.old_state_root.as_slice()
            && old_header.access_manifest_root()
                == transition.header.old_access_manifest_root.as_slice(),
        "factory splice package old header does not match the live FactoryStateCell"
    );
    ensure_vault_outpoint_binding(
        "--factory-vault-out-point",
        old_header.vault_outpoint_commitment(),
        &factory_vault_out_point,
    )?;

    let tip_number = rpc.tip_header()?.number_value()?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    let factory_vault_contract = contract_by_name(&contracts, "morph-factory-vault-lock")?;
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    ensure!(
        byte32_to_h256(factory_type.code_hash()) == factory_contract.data_hash,
        "FactoryStateCell type script does not use deployed morph-factory-type"
    );
    ensure_type_bound_state_lock(
        &factory_cell.output,
        &factory_type,
        &state_lock_contract,
        "FactoryStateCell",
    )?;
    ensure!(
        factory_type.args().raw_data().as_ref() == transition.header.factory_id.as_slice(),
        "factory type args do not match the factory splice package"
    );
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let factory_vault_lock = factory_vault_cell.output.lock();
    ensure!(
        byte32_to_h256(factory_vault_lock.code_hash()) == factory_vault_contract.data_hash,
        "FactoryVaultCell lock does not use deployed morph-factory-vault-lock"
    );
    let factory_vault_args = factory_vault_lock.args().raw_data();
    ensure!(
        factory_vault_args.len() == 2 * BYTE32_LEN,
        "factory vault lock args must be 64 bytes"
    );
    ensure!(
        &factory_vault_args.as_ref()[..BYTE32_LEN] == transition.header.factory_id.as_slice(),
        "factory vault lock is for a different factory id"
    );
    ensure!(
        &factory_vault_args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN] == factory_type_hash.as_slice(),
        "factory vault lock is for a different factory type hash"
    );

    let old_descriptor_ckb =
        factory_vault_amount(&transition.old_vault, &VaultAsset::Ckb).unwrap_or_default();
    let new_descriptor_ckb =
        factory_vault_amount(&transition.new_vault, &VaultAsset::Ckb).unwrap_or_default();
    ensure!(
        u128::from(factory_vault_cell.capacity) == old_descriptor_ckb,
        "live FactoryVaultCell capacity {} does not match old factory vault descriptor {}",
        factory_vault_cell.capacity,
        old_descriptor_ckb
    );
    let new_vault_capacity: u64 = new_descriptor_ckb
        .try_into()
        .context("new factory vault CKB amount does not fit in u64 capacity")?;

    let live_xudt = live_vault_xudt_asset(&factory_vault_cell)?;
    let xudt_contract = if live_xudt.is_some() || matches!(delta.asset, VaultAsset::Xudt(_)) {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };
    if let Some(live_xudt) = &live_xudt
        && let Some(xudt_contract) = &xudt_contract
    {
        ensure!(
            byte32_to_h256(live_xudt.type_script.code_hash()) == xudt_contract.data_hash,
            "FactoryVaultCell xUDT type script does not use deployed morph-devnet-xudt"
        );
    }

    match &delta.asset {
        VaultAsset::Ckb => {
            ensure!(
                factory_vault_cell.output.type_().to_opt().is_none()
                    && factory_vault_cell.data.is_empty(),
                "CKB factory splice package requires a plain FactoryVaultCell"
            );
        }
        VaultAsset::Xudt(type_hash) => {
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("xUDT factory splice package requires a typed vault"))?;
            ensure!(
                &live_xudt.type_hash == type_hash,
                "live FactoryVaultCell xUDT type hash does not match factory splice package"
            );
            ensure!(
                live_xudt.amount == delta.old_amount,
                "live FactoryVaultCell xUDT amount {} does not match signed old amount {}",
                live_xudt.amount,
                delta.old_amount
            );
        }
    }

    let external_xudt_input = if let VaultAsset::Xudt(_) = &delta.asset {
        if delta.external_input > 0 {
            let out_point = options
                .xudt_input_out_point
                .as_deref()
                .ok_or_else(|| {
                    anyhow!("--xudt-input-out-point is required for xUDT factory splice-in")
                })
                .and_then(parse_out_point)?;
            let external_cell = load_live_cell(rpc, out_point.clone())?;
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("xUDT factory splice package requires a typed vault"))?;
            ensure!(
                external_cell.output.lock() == owner_lock,
                "external xUDT input must be locked by the factory splice owner key"
            );
            let external_type = external_cell
                .output
                .type_()
                .to_opt()
                .ok_or_else(|| anyhow!("external xUDT input does not carry a type script"))?;
            ensure!(
                external_type == live_xudt.type_script,
                "external xUDT input type does not match the live FactoryVaultCell type"
            );
            ensure!(
                xudt_amount_from_data(&external_cell.data)? == delta.external_input,
                "external xUDT input amount does not match the signed factory splice delta"
            );
            Some((out_point, external_cell))
        } else {
            ensure!(
                options.xudt_input_out_point.is_none(),
                "--xudt-input-out-point is only used for xUDT factory splice-in"
            );
            None
        }
    } else {
        ensure!(
            options.xudt_input_out_point.is_none(),
            "--xudt-input-out-point requires an xUDT factory splice package"
        );
        None
    };

    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    ensure!(
        fee_cell.out_point != factory_out_point,
        "fee input cannot be the FactoryStateCell itself"
    );
    ensure!(
        fee_cell.out_point != factory_vault_out_point,
        "fee input cannot be the FactoryVaultCell itself"
    );
    if let Some((out_point, _)) = &external_xudt_input {
        ensure!(
            fee_cell.out_point != *out_point,
            "fee input cannot also be the external xUDT input"
        );
    }

    let mut new_factory_data = factory_cell.data.to_vec();
    ensure!(
        old_header.vault_materialisation_root()
            == transition.header.old_vault_materialisation_root.as_slice(),
        "live FactoryState commitment does not match the signed factory splice old root"
    );
    ensure!(
        vault_cell_commitment_from_output(
            &factory_vault_cell.output,
            factory_vault_cell.data.as_ref(),
        ) == transition.header.old_vault_materialisation_root,
        "live FactoryVaultCell does not match the signed factory splice old root"
    );
    put_u64(
        &mut new_factory_data,
        68,
        transition.header.new_update_number,
    );
    new_factory_data[76..108].copy_from_slice(&transition.header.new_state_root);
    new_factory_data[140..172].copy_from_slice(&transition.header.new_access_manifest_root);
    new_factory_data[172..204].copy_from_slice(&transition.header.non_interference_digest);
    new_factory_data[238..270].copy_from_slice(&transition.header.new_vault_materialisation_root);
    new_factory_data[270..302].copy_from_slice(&transition.header.new_vault_outpoint_commitment);
    let parsed_new_header = FactoryStateHeader::parse(&new_factory_data)
        .map_err(|err| anyhow!("constructed factory splice header is invalid: {err:?}"))?;
    ensure!(
        parsed_new_header.update_number() == transition.header.new_update_number,
        "constructed factory splice header update number mismatch"
    );

    let funding_factory_capacity = factory_cell
        .capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("post-splice FactoryStateCell activation capacity overflow"))?;
    let funding_factory_output = factory_cell
        .output
        .clone()
        .as_builder()
        .capacity(funding_factory_capacity)
        .build();
    ensure_output_capacity("factory", &funding_factory_output, new_factory_data.len())?;

    let mut new_vault_builder = CellOutput::new_builder()
        .capacity(new_vault_capacity)
        .lock(factory_vault_lock.clone());
    let new_vault_data = if let Some(live_xudt) = &live_xudt {
        let expected_amount = factory_vault_amount(
            &transition.new_vault,
            &VaultAsset::Xudt(live_xudt.type_hash),
        )
        .ok_or_else(|| anyhow!("new factory vault descriptor omits live xUDT asset"))?;
        new_vault_builder = new_vault_builder.type_(Some(live_xudt.type_script.clone()).pack());
        xudt_amount_bytes(expected_amount)
    } else {
        Bytes::new()
    };
    let new_vault_output = new_vault_builder.build();
    ensure!(
        vault_cell_commitment_from_output(&new_vault_output, new_vault_data.as_ref())
            == transition.header.new_vault_materialisation_root,
        "constructed FactoryVault output does not match the signed factory splice new root"
    );
    ensure_output_capacity(
        "post-splice factory vault",
        &new_vault_output,
        new_vault_data.len(),
    )?;

    let withdrawal_target = factory_splice_participant_withdrawal_target(&package, &transition)?;
    let withdrawal_lock_hash: [u8; BYTE32_LEN] = withdrawal_target.lock.calc_script_hash().unpack();
    if matches!(transition.header.kind, FactorySpliceKind::Out) {
        ensure!(
            transition.header.withdrawal_lock_hash == withdrawal_lock_hash,
            "factory splice payout lock does not match the signed withdrawal_lock_hash"
        );
    }
    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep.clone())
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(factory_contract.cell_dep.clone())
        .cell_dep(factory_vault_contract.cell_dep);
    if let Some(xudt_contract) = &xudt_contract {
        builder = builder.cell_dep(xudt_contract.cell_dep.clone());
    }
    builder = builder
        .input(CellInput::new(factory_out_point, 0))
        .input(CellInput::new(factory_vault_out_point, 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0));
    if let Some((out_point, _)) = &external_xudt_input {
        builder = builder.input(CellInput::new(out_point.clone(), 0));
    }
    builder = builder
        .output(funding_factory_output.clone())
        .output(new_vault_output)
        .output_data(Bytes::copy_from_slice(&new_factory_data).pack())
        .output_data(new_vault_data.pack());

    let mut withdrawal_out_point = None;
    let mut withdrawal_output_capacity = 0u64;
    match &delta.asset {
        VaultAsset::Ckb if delta.withdrawal > 0 => {
            let withdrawal_capacity: u64 = delta
                .withdrawal
                .try_into()
                .context("factory splice CKB withdrawal does not fit in u64 capacity")?;
            let withdrawal_output = CellOutput::new_builder()
                .capacity(withdrawal_capacity)
                .lock(withdrawal_target.lock.clone())
                .build();
            ensure_output_capacity("factory splice withdrawal", &withdrawal_output, 0)?;
            withdrawal_output_capacity = withdrawal_capacity;
            builder = builder
                .output(withdrawal_output)
                .output_data(Bytes::new().pack());
            withdrawal_out_point = Some(2u32);
        }
        VaultAsset::Xudt(_) if delta.withdrawal > 0 => {
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("xUDT factory splice package requires a typed vault"))?;
            let withdrawal_output_for_capacity = CellOutput::new_builder()
                .lock(withdrawal_target.lock.clone())
                .type_(Some(live_xudt.type_script.clone()).pack())
                .build();
            let withdrawal_capacity = occupied_capacity(&withdrawal_output_for_capacity, 16)?;
            let withdrawal_output = CellOutput::new_builder()
                .capacity(withdrawal_capacity)
                .lock(withdrawal_target.lock.clone())
                .type_(Some(live_xudt.type_script.clone()).pack())
                .build();
            ensure_output_capacity("factory xUDT splice withdrawal", &withdrawal_output, 16)?;
            withdrawal_output_capacity = withdrawal_capacity;
            builder = builder
                .output(withdrawal_output)
                .output_data(xudt_amount_bytes(delta.withdrawal).pack());
            withdrawal_out_point = Some(2u32);
        }
        _ => {}
    }

    let external_input_capacity = external_xudt_input
        .as_ref()
        .map(|(_, cell)| cell.capacity)
        .unwrap_or_default();
    let fixed_output_delta = new_vault_capacity
        .checked_add(withdrawal_output_capacity)
        .and_then(|value| value.checked_sub(factory_vault_cell.capacity))
        .ok_or_else(|| anyhow!("factory splice package would create excess input capacity"))?;
    if matches!(&delta.asset, VaultAsset::Ckb) {
        let expected_delta: u64 = delta
            .external_input
            .try_into()
            .context("factory splice CKB external input does not fit in u64")?;
        ensure!(
            fixed_output_delta == expected_delta,
            "factory splice output delta {} does not match signed external CKB delta {}",
            fixed_output_delta,
            expected_delta
        );
    }
    let fee_change_capacity = fee_cell
        .capacity
        .checked_add(external_input_capacity)
        .ok_or_else(|| anyhow!("fee and external input capacity overflow"))?
        .checked_sub(fixed_output_delta)
        .and_then(|value| value.checked_sub(STATE_CARRIER_ACTIVATION_FEE))
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "fee cell capacity {} plus external input capacity {} cannot cover factory splice output delta {} and fee {}",
                fee_cell.capacity,
                external_input_capacity,
                fixed_output_delta,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock)
        .build();

    let unsigned = builder
        .output(fee_change_output)
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_factory_splice_transaction(
        unsigned,
        &owner_key,
        Bytes::from(contract_witness.clone()),
        usize::from(external_xudt_input.is_some()),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let tx_hash = sent.tx_hash.clone();
    let (activation, _, _) = activate_factory_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_factory_output,
        new_factory_data
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("post-splice FactoryStateHeader has an invalid length"))?,
        &state_lock_contract,
        &factory_contract,
        0,
        1,
        options.mine_blocks,
    )?;
    let activation_tx_hash = activation.tx_hash.clone();

    Ok(ApplyFactorySpliceReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(&transition.header.factory_id),
        kind: match transition.header.kind {
            FactorySpliceKind::In => "splice_in",
            FactorySpliceKind::Out => "splice_out",
        }
        .to_string(),
        asset: match &delta.asset {
            VaultAsset::Ckb => "ckb".to_string(),
            VaultAsset::Xudt(type_hash) => format!("xudt:{}", hex32(type_hash)),
        },
        old_update_number: transition.header.old_update_number,
        new_update_number: transition.header.new_update_number,
        factory_out_point: PrintableOutPoint {
            tx_hash: activation_tx_hash.clone(),
            index: 0,
        },
        factory_vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: 1,
        },
        withdrawal_out_point: withdrawal_out_point.map(|index| PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        }),
        fee_change_capacity,
        fee: options.fee,
        factory_splice_package: options.factory_splice_package.display().to_string(),
        contract_witness_len: contract_witness.len(),
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        activation_tx_hash,
        activation_status: activation.status,
        activation_block_number: activation.block_number,
        activation_block_hash: activation.block_hash,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE,
        activation_metrics: activation.metrics,
        activation_mined_blocks: activation.mined_blocks,
    })
}

pub fn apply_factory_reduced_splice(
    rpc: &CkbRpcClient,
    options: ApplyFactoryReducedSpliceOptions,
) -> Result<ApplyFactorySpliceReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory splice fee/change")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let package = read_factory_reduced_splice_package(&options.factory_reduced_splice_package)?;
    let transition = package.validate()?;
    let contract_witness = package.contract_witness_bytes()?;
    let delta = transition
        .deltas
        .first()
        .ok_or_else(|| anyhow!("reduced factory splice package has no vault delta"))?;

    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_vault_out_point = parse_out_point(&options.factory_vault_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_vault_cell = load_live_cell(rpc, factory_vault_out_point.clone())?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        old_header.factory_id() == transition.header.factory_id.as_slice(),
        "reduced factory splice package is for a different factory id"
    );
    ensure!(
        old_header.update_number() == transition.header.old_update_number
            && old_header.state_root() == transition.header.old_state_root.as_slice()
            && old_header.access_manifest_root()
                == transition.header.old_access_manifest_root.as_slice(),
        "reduced factory splice package old header does not match the live FactoryStateCell"
    );
    ensure_vault_outpoint_binding(
        "--factory-vault-out-point",
        old_header.vault_outpoint_commitment(),
        &factory_vault_out_point,
    )?;

    let tip_number = rpc.tip_header()?.number_value()?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    let factory_vault_contract = contract_by_name(&contracts, "morph-factory-vault-lock")?;
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    ensure!(
        byte32_to_h256(factory_type.code_hash()) == factory_contract.data_hash,
        "FactoryStateCell type script does not use deployed morph-factory-type"
    );
    ensure_type_bound_state_lock(
        &factory_cell.output,
        &factory_type,
        &state_lock_contract,
        "FactoryStateCell",
    )?;
    ensure!(
        factory_type.args().raw_data().as_ref() == transition.header.factory_id.as_slice(),
        "factory type args do not match the reduced factory splice package"
    );
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let factory_vault_lock = factory_vault_cell.output.lock();
    ensure!(
        byte32_to_h256(factory_vault_lock.code_hash()) == factory_vault_contract.data_hash,
        "FactoryVaultCell lock does not use deployed morph-factory-vault-lock"
    );
    let factory_vault_args = factory_vault_lock.args().raw_data();
    ensure!(
        factory_vault_args.len() == 2 * BYTE32_LEN,
        "factory vault lock args must be 64 bytes"
    );
    ensure!(
        &factory_vault_args.as_ref()[..BYTE32_LEN] == transition.header.factory_id.as_slice(),
        "factory vault lock is for a different factory id"
    );
    ensure!(
        &factory_vault_args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN] == factory_type_hash.as_slice(),
        "factory vault lock is for a different factory type hash"
    );

    let old_descriptor_ckb =
        factory_vault_amount(&transition.old_vault, &VaultAsset::Ckb).unwrap_or_default();
    let new_descriptor_ckb =
        factory_vault_amount(&transition.new_vault, &VaultAsset::Ckb).unwrap_or_default();
    ensure!(
        u128::from(factory_vault_cell.capacity) == old_descriptor_ckb,
        "live FactoryVaultCell capacity {} does not match old reduced factory vault descriptor {}",
        factory_vault_cell.capacity,
        old_descriptor_ckb
    );
    let new_vault_capacity: u64 = new_descriptor_ckb
        .try_into()
        .context("new reduced factory vault CKB amount does not fit in u64 capacity")?;

    let live_xudt = live_vault_xudt_asset(&factory_vault_cell)?;
    let xudt_contract = if live_xudt.is_some() || matches!(delta.asset, VaultAsset::Xudt(_)) {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };
    if let Some(live_xudt) = &live_xudt
        && let Some(xudt_contract) = &xudt_contract
    {
        ensure!(
            byte32_to_h256(live_xudt.type_script.code_hash()) == xudt_contract.data_hash,
            "FactoryVaultCell xUDT type script does not use deployed morph-devnet-xudt"
        );
    }

    match &delta.asset {
        VaultAsset::Ckb => {
            ensure!(
                factory_vault_cell.output.type_().to_opt().is_none()
                    && factory_vault_cell.data.is_empty(),
                "CKB reduced factory splice package requires a plain FactoryVaultCell"
            );
        }
        VaultAsset::Xudt(type_hash) => {
            let live_xudt = live_xudt.as_ref().ok_or_else(|| {
                anyhow!("xUDT reduced factory splice package requires a typed vault")
            })?;
            ensure!(
                &live_xudt.type_hash == type_hash,
                "live FactoryVaultCell xUDT type hash does not match reduced factory splice package"
            );
            ensure!(
                live_xudt.amount == delta.old_amount,
                "live FactoryVaultCell xUDT amount {} does not match signed old amount {}",
                live_xudt.amount,
                delta.old_amount
            );
        }
    }

    let external_xudt_input = if let VaultAsset::Xudt(_) = &delta.asset {
        if delta.external_input > 0 {
            let out_point = options
                .xudt_input_out_point
                .as_deref()
                .ok_or_else(|| {
                    anyhow!("--xudt-input-out-point is required for xUDT reduced factory splice-in")
                })
                .and_then(parse_out_point)?;
            let external_cell = load_live_cell(rpc, out_point.clone())?;
            let live_xudt = live_xudt.as_ref().ok_or_else(|| {
                anyhow!("xUDT reduced factory splice package requires a typed vault")
            })?;
            ensure!(
                external_cell.output.lock() == owner_lock,
                "external xUDT input must be locked by the factory splice owner key"
            );
            let external_type = external_cell
                .output
                .type_()
                .to_opt()
                .ok_or_else(|| anyhow!("external xUDT input does not carry a type script"))?;
            ensure!(
                external_type == live_xudt.type_script,
                "external xUDT input type does not match the live FactoryVaultCell type"
            );
            ensure!(
                xudt_amount_from_data(&external_cell.data)? == delta.external_input,
                "external xUDT input amount does not match the signed reduced factory splice delta"
            );
            Some((out_point, external_cell))
        } else {
            ensure!(
                options.xudt_input_out_point.is_none(),
                "--xudt-input-out-point is only used for xUDT reduced factory splice-in"
            );
            None
        }
    } else {
        ensure!(
            options.xudt_input_out_point.is_none(),
            "--xudt-input-out-point requires an xUDT reduced factory splice package"
        );
        None
    };

    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    ensure!(
        fee_cell.out_point != factory_out_point,
        "fee input cannot be the FactoryStateCell itself"
    );
    ensure!(
        fee_cell.out_point != factory_vault_out_point,
        "fee input cannot be the FactoryVaultCell itself"
    );
    if let Some((out_point, _)) = &external_xudt_input {
        ensure!(
            fee_cell.out_point != *out_point,
            "fee input cannot also be the external xUDT input"
        );
    }

    let mut new_factory_data = factory_cell.data.to_vec();
    ensure!(
        old_header.vault_materialisation_root()
            == transition.header.old_vault_materialisation_root.as_slice(),
        "live FactoryState commitment does not match the signed reduced splice old root"
    );
    ensure!(
        vault_cell_commitment_from_output(
            &factory_vault_cell.output,
            factory_vault_cell.data.as_ref(),
        ) == transition.header.old_vault_materialisation_root,
        "live FactoryVaultCell does not match the signed reduced splice old root"
    );
    put_u64(
        &mut new_factory_data,
        68,
        transition.header.new_update_number,
    );
    new_factory_data[76..108].copy_from_slice(&transition.header.new_state_root);
    new_factory_data[140..172].copy_from_slice(&transition.header.new_access_manifest_root);
    new_factory_data[172..204].copy_from_slice(&transition.header.non_interference_digest);
    new_factory_data[238..270].copy_from_slice(&transition.header.new_vault_materialisation_root);
    new_factory_data[270..302].copy_from_slice(&transition.header.new_vault_outpoint_commitment);
    let parsed_new_header = FactoryStateHeader::parse(&new_factory_data)
        .map_err(|err| anyhow!("constructed reduced factory splice header is invalid: {err:?}"))?;
    ensure!(
        parsed_new_header.update_number() == transition.header.new_update_number,
        "constructed reduced factory splice header update number mismatch"
    );

    let funding_factory_capacity = factory_cell
        .capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("post-splice FactoryStateCell activation capacity overflow"))?;
    let funding_factory_output = factory_cell
        .output
        .clone()
        .as_builder()
        .capacity(funding_factory_capacity)
        .build();
    ensure_output_capacity("factory", &funding_factory_output, new_factory_data.len())?;

    let mut new_vault_builder = CellOutput::new_builder()
        .capacity(new_vault_capacity)
        .lock(factory_vault_lock.clone());
    let new_vault_data = if let Some(live_xudt) = &live_xudt {
        let expected_amount = factory_vault_amount(
            &transition.new_vault,
            &VaultAsset::Xudt(live_xudt.type_hash),
        )
        .ok_or_else(|| anyhow!("new reduced factory vault descriptor omits live xUDT asset"))?;
        new_vault_builder = new_vault_builder.type_(Some(live_xudt.type_script.clone()).pack());
        xudt_amount_bytes(expected_amount)
    } else {
        Bytes::new()
    };
    let new_vault_output = new_vault_builder.build();
    ensure!(
        vault_cell_commitment_from_output(&new_vault_output, new_vault_data.as_ref())
            == transition.header.new_vault_materialisation_root,
        "constructed FactoryVault output does not match the signed reduced splice new root"
    );
    ensure_output_capacity(
        "post-splice factory vault",
        &new_vault_output,
        new_vault_data.len(),
    )?;

    let withdrawal_target =
        factory_reduced_splice_participant_withdrawal_target(&package, &transition)?;
    let withdrawal_lock_hash: [u8; BYTE32_LEN] = withdrawal_target.lock.calc_script_hash().unpack();
    if matches!(transition.header.kind, FactorySpliceKind::Out) {
        ensure!(
            transition.header.withdrawal_lock_hash == withdrawal_lock_hash,
            "reduced factory splice payout lock does not match the signed withdrawal_lock_hash"
        );
    }
    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep.clone())
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(factory_contract.cell_dep.clone())
        .cell_dep(factory_vault_contract.cell_dep);
    if let Some(xudt_contract) = &xudt_contract {
        builder = builder.cell_dep(xudt_contract.cell_dep.clone());
    }
    builder = builder
        .input(CellInput::new(factory_out_point, 0))
        .input(CellInput::new(factory_vault_out_point, 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0));
    if let Some((out_point, _)) = &external_xudt_input {
        builder = builder.input(CellInput::new(out_point.clone(), 0));
    }
    builder = builder
        .output(funding_factory_output.clone())
        .output(new_vault_output)
        .output_data(Bytes::copy_from_slice(&new_factory_data).pack())
        .output_data(new_vault_data.pack());

    let mut withdrawal_out_point = None;
    let mut withdrawal_output_capacity = 0u64;
    match &delta.asset {
        VaultAsset::Ckb if delta.withdrawal > 0 => {
            let withdrawal_capacity: u64 = delta
                .withdrawal
                .try_into()
                .context("reduced factory splice CKB withdrawal does not fit in u64 capacity")?;
            let withdrawal_output = CellOutput::new_builder()
                .capacity(withdrawal_capacity)
                .lock(withdrawal_target.lock.clone())
                .build();
            ensure_output_capacity("reduced factory splice withdrawal", &withdrawal_output, 0)?;
            withdrawal_output_capacity = withdrawal_capacity;
            builder = builder
                .output(withdrawal_output)
                .output_data(Bytes::new().pack());
            withdrawal_out_point = Some(2u32);
        }
        VaultAsset::Xudt(_) if delta.withdrawal > 0 => {
            let live_xudt = live_xudt.as_ref().ok_or_else(|| {
                anyhow!("xUDT reduced factory splice package requires a typed vault")
            })?;
            let withdrawal_output_for_capacity = CellOutput::new_builder()
                .lock(withdrawal_target.lock.clone())
                .type_(Some(live_xudt.type_script.clone()).pack())
                .build();
            let withdrawal_capacity = occupied_capacity(&withdrawal_output_for_capacity, 16)?;
            let withdrawal_output = CellOutput::new_builder()
                .capacity(withdrawal_capacity)
                .lock(withdrawal_target.lock.clone())
                .type_(Some(live_xudt.type_script.clone()).pack())
                .build();
            ensure_output_capacity(
                "reduced factory xUDT splice withdrawal",
                &withdrawal_output,
                16,
            )?;
            withdrawal_output_capacity = withdrawal_capacity;
            builder = builder
                .output(withdrawal_output)
                .output_data(xudt_amount_bytes(delta.withdrawal).pack());
            withdrawal_out_point = Some(2u32);
        }
        _ => {}
    }

    let external_input_capacity = external_xudt_input
        .as_ref()
        .map(|(_, cell)| cell.capacity)
        .unwrap_or_default();
    let fixed_output_delta = new_vault_capacity
        .checked_add(withdrawal_output_capacity)
        .and_then(|value| value.checked_sub(factory_vault_cell.capacity))
        .ok_or_else(|| {
            anyhow!("reduced factory splice package would create excess input capacity")
        })?;
    if matches!(&delta.asset, VaultAsset::Ckb) {
        let expected_delta: u64 = delta
            .external_input
            .try_into()
            .context("reduced factory splice CKB external input does not fit in u64")?;
        ensure!(
            fixed_output_delta == expected_delta,
            "reduced factory splice output delta {} does not match signed external CKB delta {}",
            fixed_output_delta,
            expected_delta
        );
    }
    let fee_change_capacity = fee_cell
        .capacity
        .checked_add(external_input_capacity)
        .ok_or_else(|| anyhow!("fee and external input capacity overflow"))?
        .checked_sub(fixed_output_delta)
        .and_then(|value| value.checked_sub(STATE_CARRIER_ACTIVATION_FEE))
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "fee cell capacity {} plus external input capacity {} cannot cover reduced factory splice output delta {} and fee {}",
                fee_cell.capacity,
                external_input_capacity,
                fixed_output_delta,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock)
        .build();

    let unsigned = builder
        .output(fee_change_output)
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_factory_splice_transaction(
        unsigned,
        &owner_key,
        Bytes::from(contract_witness.clone()),
        usize::from(external_xudt_input.is_some()),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let tx_hash = sent.tx_hash.clone();
    let (activation, _, _) = activate_factory_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_factory_output,
        new_factory_data
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("post-splice reduced FactoryStateHeader has an invalid length"))?,
        &state_lock_contract,
        &factory_contract,
        0,
        1,
        options.mine_blocks,
    )?;
    let activation_tx_hash = activation.tx_hash.clone();

    Ok(ApplyFactorySpliceReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        factory_id: hex32(&transition.header.factory_id),
        kind: match transition.header.kind {
            FactorySpliceKind::In => "splice_in",
            FactorySpliceKind::Out => "splice_out",
        }
        .to_string(),
        asset: match &delta.asset {
            VaultAsset::Ckb => "ckb".to_string(),
            VaultAsset::Xudt(type_hash) => format!("xudt:{}", hex32(type_hash)),
        },
        old_update_number: transition.header.old_update_number,
        new_update_number: transition.header.new_update_number,
        factory_out_point: PrintableOutPoint {
            tx_hash: activation_tx_hash.clone(),
            index: 0,
        },
        factory_vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: 1,
        },
        withdrawal_out_point: withdrawal_out_point.map(|index| PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        }),
        fee_change_capacity,
        fee: options.fee,
        factory_splice_package: options.factory_reduced_splice_package.display().to_string(),
        contract_witness_len: contract_witness.len(),
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        activation_tx_hash,
        activation_status: activation.status,
        activation_block_number: activation.block_number,
        activation_block_hash: activation.block_hash,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE,
        activation_metrics: activation.metrics,
        activation_mined_blocks: activation.mined_blocks,
    })
}

pub fn save_factory_merkle_update_package(
    rpc: &CkbRpcClient,
    options: SaveFactoryMerkleUpdatePackageOptions,
) -> Result<SaveFactoryMerkleUpdatePackageReport> {
    ensure!(
        options.touched_after_balance < 1_000,
        "touched_after_balance must decrease the fixture balance below 1000"
    );
    let participant_entries = factory_signing_entries(
        &options.alice_private_key,
        &options.bob_private_key,
        &options.additional_participant_private_keys,
    )?;
    let participant_keys = participant_entries
        .iter()
        .map(|(_, _, key)| key.clone())
        .collect::<Vec<_>>();
    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    let printable = printable_out_point(&factory_out_point);
    let package = merkle_update_package_from_factory_header(
        factory_cell.data.as_ref(),
        &participant_keys,
        options.update_number,
        options.touched_after_balance,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )
    .with_context(|| {
        format!(
            "factory {} at update {} is not compatible with the sparse Merkle proof shape",
            hex32(old_header.factory_id()),
            old_header.update_number()
        )
    })?;
    let path = write_factory_merkle_update_package(&options.store_dir, &package)?;

    Ok(SaveFactoryMerkleUpdatePackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn factory_smoke(
    rpc: &CkbRpcClient,
    options: FactorySmokeOptions,
) -> Result<FactorySmokeReport> {
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let saved_package = save_factory_state_package(
        rpc,
        SaveFactoryStatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let selected_package = latest_factory_state_cell_package(&options.store_dir, &open.factory_id)?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            additional_participant_private_keys: Vec::new(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(selected_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FactorySmokeReport {
        open,
        saved_package,
        selected_package,
        update,
    })
}

pub fn factory_reduced_rights_smoke(
    rpc: &CkbRpcClient,
    options: FactoryReducedRightsSmokeOptions,
) -> Result<FactoryReducedRightsSmokeReport> {
    let roots = fixture_factory_reduced_rights_package()?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: Some(roots.old_state_root),
            access_manifest_root: Some(roots.old_access_manifest_root),
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let package = save_factory_reduced_rights_package(
        rpc,
        SaveFactoryReducedRightsPackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            touched_after_balance: options.touched_after_balance,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            additional_participant_private_keys: Vec::new(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(PathBuf::from(&package.path)),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FactoryReducedRightsSmokeReport {
        open,
        package,
        update,
    })
}

pub fn factory_splice_smoke(
    rpc: &CkbRpcClient,
    options: FactorySpliceSmokeOptions,
) -> Result<FactorySpliceSmokeReport> {
    ensure!(options.splice_amount > 0, "splice_amount must be non-zero");
    let old_amount = u128::from(options.factory_vault_capacity);
    let new_amount = match options.kind {
        DevnetSpliceKind::SpliceIn => old_amount
            .checked_add(u128::from(options.splice_amount))
            .ok_or_else(|| anyhow!("post-splice factory vault capacity overflows"))?,
        DevnetSpliceKind::SpliceOut => {
            ensure!(
                u128::from(options.splice_amount) < old_amount,
                "splice-out amount must be below factory vault capacity {}",
                options.factory_vault_capacity
            );
            old_amount - u128::from(options.splice_amount)
        }
    };
    ensure!(
        u128::from(options.child_vault_capacity) < new_amount,
        "child vault capacity must be below post-splice factory vault capacity {}",
        new_amount
    );
    let (before, _) = factory_splice_reserve_rights(None, old_amount, new_amount);
    let old_state_root = factory_right_sparse_root(&before)
        .map_err(|err| anyhow!("failed to compute factory splice smoke root: {err:?}"))?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let package = save_factory_splice_package(
        rpc,
        SaveFactorySplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            factory_vault_out_point: factory_vault_out_point.clone(),
            kind: options.kind,
            asset: DevnetSpliceAsset::Ckb,
            ckb_amount: options.splice_amount,
            xudt_amount: None,
            update_number: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let apply = apply_factory_splice(
        rpc,
        ApplyFactorySpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            factory_out_point,
            factory_vault_out_point,
            factory_splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: Some(options.bob_private_key),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: format!(
                "{}:{}",
                apply.factory_out_point.tx_hash, apply.factory_out_point.index
            ),
            factory_vault_out_point: format!(
                "{}:{}",
                apply.factory_vault_out_point.tx_hash, apply.factory_vault_out_point.index
            ),
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: None,
            bob_xudt_amount: None,
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    )?;

    Ok(FactorySpliceSmokeReport {
        kind: match options.kind {
            DevnetSpliceKind::SpliceIn => "splice_in",
            DevnetSpliceKind::SpliceOut => "splice_out",
        }
        .to_string(),
        open,
        package,
        apply,
        exit,
    })
}

pub fn factory_reduced_splice_smoke(
    rpc: &CkbRpcClient,
    options: FactorySpliceSmokeOptions,
) -> Result<FactoryReducedSpliceSmokeReport> {
    ensure!(options.splice_amount > 0, "splice_amount must be non-zero");
    let old_amount = u128::from(options.factory_vault_capacity);
    let new_amount = match options.kind {
        DevnetSpliceKind::SpliceIn => old_amount
            .checked_add(u128::from(options.splice_amount))
            .ok_or_else(|| anyhow!("post-splice factory vault capacity overflows"))?,
        DevnetSpliceKind::SpliceOut => {
            ensure!(
                u128::from(options.splice_amount) < old_amount,
                "splice-out amount must be below factory vault capacity {}",
                options.factory_vault_capacity
            );
            old_amount - u128::from(options.splice_amount)
        }
    };
    ensure!(
        u128::from(options.child_vault_capacity) < new_amount,
        "child vault capacity must be below post-splice factory vault capacity {}",
        new_amount
    );
    let (before, _) = factory_splice_reserve_rights(None, old_amount, new_amount);
    let old_state_root = factory_right_sparse_root(&before)
        .map_err(|err| anyhow!("failed to compute reduced factory splice smoke root: {err:?}"))?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let package = save_factory_reduced_splice_package(
        rpc,
        SaveFactoryReducedSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            factory_vault_out_point: factory_vault_out_point.clone(),
            kind: options.kind,
            asset: DevnetSpliceAsset::Ckb,
            ckb_amount: options.splice_amount,
            xudt_amount: None,
            update_number: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let apply = apply_factory_reduced_splice(
        rpc,
        ApplyFactoryReducedSpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            factory_out_point,
            factory_vault_out_point,
            factory_reduced_splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: Some(options.bob_private_key),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: format!(
                "{}:{}",
                apply.factory_out_point.tx_hash, apply.factory_out_point.index
            ),
            factory_vault_out_point: format!(
                "{}:{}",
                apply.factory_vault_out_point.tx_hash, apply.factory_vault_out_point.index
            ),
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: None,
            bob_xudt_amount: None,
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    )?;

    Ok(FactoryReducedSpliceSmokeReport {
        kind: match options.kind {
            DevnetSpliceKind::SpliceIn => "splice_in",
            DevnetSpliceKind::SpliceOut => "splice_out",
        }
        .to_string(),
        open,
        package,
        apply,
        exit,
    })
}

pub fn factory_xudt_splice_smoke(
    rpc: &CkbRpcClient,
    options: FactoryXudtSpliceSmokeOptions,
) -> Result<FactoryXudtSpliceSmokeReport> {
    ensure!(
        options.splice_xudt_amount > 0,
        "splice xUDT amount must be non-zero"
    );
    let old_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("factory xUDT amount overflow"))?;
    ensure!(old_xudt_amount > 0, "factory xUDT amount must be non-zero");
    let new_xudt_amount = match options.kind {
        DevnetSpliceKind::SpliceIn => old_xudt_amount
            .checked_add(options.splice_xudt_amount)
            .ok_or_else(|| anyhow!("post-splice factory xUDT amount overflows"))?,
        DevnetSpliceKind::SpliceOut => {
            ensure!(
                options.splice_xudt_amount < old_xudt_amount,
                "splice xUDT amount must be below the live vault amount {}",
                old_xudt_amount
            );
            old_xudt_amount - options.splice_xudt_amount
        }
    };
    ensure!(
        options.child_vault_capacity < options.factory_vault_capacity,
        "child vault capacity must be below factory vault capacity {}",
        options.factory_vault_capacity
    );

    let xudt_type_hash =
        devnet_owner_xudt_type_hash(rpc, &options.contracts_dir, &options.private_key)?;
    let (before, _) =
        factory_splice_reserve_rights(Some(xudt_type_hash), old_xudt_amount, new_xudt_amount);
    let old_state_root = factory_right_sparse_root(&before)
        .map_err(|err| anyhow!("failed to compute factory xUDT splice smoke root: {err:?}"))?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(old_xudt_amount),
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;

    let external_xudt = if matches!(options.kind, DevnetSpliceKind::SpliceIn) {
        Some(mint_owner_xudt_cell(
            rpc,
            &options.contracts_dir,
            &options.private_key,
            options.splice_xudt_amount,
            options.fee,
            options.mine_blocks,
        )?)
    } else {
        None
    };
    let external_xudt_out_point = external_xudt
        .as_ref()
        .map(|report| printable_out_point_string(&report.cell_out_point));

    let package = save_factory_splice_package(
        rpc,
        SaveFactorySplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            factory_vault_out_point: factory_vault_out_point.clone(),
            kind: options.kind,
            asset: DevnetSpliceAsset::Xudt,
            ckb_amount: 0,
            xudt_amount: Some(options.splice_xudt_amount),
            update_number: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let apply = apply_factory_splice(
        rpc,
        ApplyFactorySpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            factory_out_point,
            factory_vault_out_point,
            factory_splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: external_xudt_out_point,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    let (post_alice_xudt_amount, post_bob_xudt_amount) = proportional_xudt_split(
        new_xudt_amount,
        options.alice_xudt_amount,
        options.bob_xudt_amount,
    )?;
    ensure!(
        post_alice_xudt_amount.checked_add(post_bob_xudt_amount) == Some(new_xudt_amount),
        "post-splice factory xUDT settlement split does not match new vault amount"
    );
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: Some(options.bob_private_key),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: format!(
                "{}:{}",
                apply.factory_out_point.tx_hash, apply.factory_out_point.index
            ),
            factory_vault_out_point: format!(
                "{}:{}",
                apply.factory_vault_out_point.tx_hash, apply.factory_vault_out_point.index
            ),
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(post_alice_xudt_amount),
            bob_xudt_amount: Some(post_bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    )?;

    Ok(FactoryXudtSpliceSmokeReport {
        kind: match options.kind {
            DevnetSpliceKind::SpliceIn => "xudt_splice_in",
            DevnetSpliceKind::SpliceOut => "xudt_splice_out",
        }
        .to_string(),
        open,
        external_xudt,
        package,
        apply,
        exit,
    })
}

pub fn factory_reduced_xudt_splice_smoke(
    rpc: &CkbRpcClient,
    options: FactoryXudtSpliceSmokeOptions,
) -> Result<FactoryReducedXudtSpliceSmokeReport> {
    ensure!(
        options.splice_xudt_amount > 0,
        "splice xUDT amount must be non-zero"
    );
    let old_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("factory xUDT amount overflow"))?;
    ensure!(old_xudt_amount > 0, "factory xUDT amount must be non-zero");
    let new_xudt_amount = match options.kind {
        DevnetSpliceKind::SpliceIn => old_xudt_amount
            .checked_add(options.splice_xudt_amount)
            .ok_or_else(|| anyhow!("post-splice factory xUDT amount overflows"))?,
        DevnetSpliceKind::SpliceOut => {
            ensure!(
                options.splice_xudt_amount < old_xudt_amount,
                "splice xUDT amount must be below the live vault amount {}",
                old_xudt_amount
            );
            old_xudt_amount - options.splice_xudt_amount
        }
    };
    ensure!(
        options.child_vault_capacity < options.factory_vault_capacity,
        "child vault capacity must be below factory vault capacity {}",
        options.factory_vault_capacity
    );

    let xudt_type_hash =
        devnet_owner_xudt_type_hash(rpc, &options.contracts_dir, &options.private_key)?;
    let (before, _) =
        factory_splice_reserve_rights(Some(xudt_type_hash), old_xudt_amount, new_xudt_amount);
    let old_state_root = factory_right_sparse_root(&before).map_err(|err| {
        anyhow!("failed to compute reduced factory xUDT splice smoke root: {err:?}")
    })?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(old_xudt_amount),
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;

    let external_xudt = if matches!(options.kind, DevnetSpliceKind::SpliceIn) {
        Some(mint_owner_xudt_cell(
            rpc,
            &options.contracts_dir,
            &options.private_key,
            options.splice_xudt_amount,
            options.fee,
            options.mine_blocks,
        )?)
    } else {
        None
    };
    let external_xudt_out_point = external_xudt
        .as_ref()
        .map(|report| printable_out_point_string(&report.cell_out_point));

    let package = save_factory_reduced_splice_package(
        rpc,
        SaveFactoryReducedSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            factory_vault_out_point: factory_vault_out_point.clone(),
            kind: options.kind,
            asset: DevnetSpliceAsset::Xudt,
            ckb_amount: 0,
            xudt_amount: Some(options.splice_xudt_amount),
            update_number: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let apply = apply_factory_reduced_splice(
        rpc,
        ApplyFactoryReducedSpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            factory_out_point,
            factory_vault_out_point,
            factory_reduced_splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: external_xudt_out_point,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    let (post_alice_xudt_amount, post_bob_xudt_amount) = proportional_xudt_split(
        new_xudt_amount,
        options.alice_xudt_amount,
        options.bob_xudt_amount,
    )?;
    ensure!(
        post_alice_xudt_amount.checked_add(post_bob_xudt_amount) == Some(new_xudt_amount),
        "post-splice factory xUDT settlement split does not match new vault amount"
    );
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: Some(options.bob_private_key),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: format!(
                "{}:{}",
                apply.factory_out_point.tx_hash, apply.factory_out_point.index
            ),
            factory_vault_out_point: format!(
                "{}:{}",
                apply.factory_vault_out_point.tx_hash, apply.factory_vault_out_point.index
            ),
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(post_alice_xudt_amount),
            bob_xudt_amount: Some(post_bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    )?;

    Ok(FactoryReducedXudtSpliceSmokeReport {
        kind: match options.kind {
            DevnetSpliceKind::SpliceIn => "reduced_xudt_splice_in",
            DevnetSpliceKind::SpliceOut => "reduced_xudt_splice_out",
        }
        .to_string(),
        open,
        external_xudt,
        package,
        apply,
        exit,
    })
}

pub fn factory_merkle_update_smoke(
    rpc: &CkbRpcClient,
    options: FactoryMerkleUpdateSmokeOptions,
) -> Result<FactoryMerkleUpdateSmokeReport> {
    ensure!(
        options.touched_after_balance < 1_000,
        "touched_after_balance must decrease the fixture balance below 1000"
    );
    let (old_state_root, old_access_manifest_root) = merkle_update_initial_roots()?;
    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: Some(hex32(&old_access_manifest_root)),
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let package = save_factory_merkle_update_package(
        rpc,
        SaveFactoryMerkleUpdatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            touched_after_balance: options.touched_after_balance,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            additional_participant_private_keys: Vec::new(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(PathBuf::from(&package.path)),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FactoryMerkleUpdateSmokeReport {
        open,
        package,
        update,
    })
}

pub fn factory_reduced_exit_smoke(
    rpc: &CkbRpcClient,
    options: FactoryReducedExitSmokeOptions,
) -> Result<FactoryReducedExitSmokeReport> {
    ensure!(
        options.child_vault_capacity > 0,
        "child vault capacity must be non-zero"
    );
    let alice_key = k256_signing_key(&options.alice_private_key)
        .with_context(|| "invalid Alice factory private key")?;
    let bob_key = k256_signing_key(&options.bob_private_key)
        .with_context(|| "invalid Bob factory private key")?;
    let (old_state_root, old_access_manifest_root) =
        reduced_exit_initial_roots(&alice_key, &bob_key, options.child_vault_capacity as u128)?;

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: None,
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: Some(hex32(&old_access_manifest_root)),
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: Some(options.bob_private_key.clone()),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point,
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: None,
            bob_xudt_amount: None,
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::ReducedReserveClaim,
        },
    )?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: printable_out_point_string(&exit.state_out_point),
            sponsor_out_point: printable_out_point_string(&exit.sponsor_out_point),
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: printable_out_point_string(&publish.state_out_point),
            vault_out_point: printable_out_point_string(&exit.vault_out_point),
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FactoryReducedExitSmokeReport {
        open,
        exit,
        publish,
        finalise,
    })
}

pub fn factory_reduced_xudt_exit_smoke(
    rpc: &CkbRpcClient,
    options: FactoryReducedXudtExitSmokeOptions,
) -> Result<FactoryReducedXudtExitSmokeReport> {
    let child_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("child xUDT amount overflow"))?;
    ensure!(child_xudt_amount > 0, "child xUDT amount must be non-zero");
    let factory_vault_xudt_amount = child_xudt_amount
        .checked_add(options.factory_vault_xudt_surplus)
        .ok_or_else(|| anyhow!("factory vault xUDT amount overflow"))?;
    let xudt_type_hash =
        devnet_owner_xudt_type_hash(rpc, &options.contracts_dir, &options.private_key)?;
    let alice_key = k256_signing_key(&options.alice_private_key)
        .with_context(|| "invalid Alice factory private key")?;
    let bob_key = k256_signing_key(&options.bob_private_key)
        .with_context(|| "invalid Bob factory private key")?;
    let (old_state_root, old_access_manifest_root) = reduced_xudt_exit_initial_roots(
        &alice_key,
        &bob_key,
        child_xudt_amount,
        factory_vault_xudt_amount,
        options.factory_vault_xudt_surplus,
        xudt_type_hash,
        options.child_vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
        options.alice_xudt_amount,
        options.bob_xudt_amount,
    )?;

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(factory_vault_xudt_amount),
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: Some(hex32(&old_access_manifest_root)),
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: Some(options.bob_private_key.clone()),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point,
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::ReducedReserveClaim,
        },
    )?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: printable_out_point_string(&exit.state_out_point),
            sponsor_out_point: printable_out_point_string(&exit.sponsor_out_point),
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.child_vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&exit.vault_out_point),
    );

    Ok(FactoryReducedXudtExitSmokeReport {
        open,
        exit,
        publish,
        finalise: finalise?,
    })
}

pub fn factory_reduced_xudt_negative_exit_smoke(
    rpc: &CkbRpcClient,
    options: FactoryReducedXudtNegativeExitSmokeOptions,
) -> Result<FactoryReducedXudtNegativeExitSmokeReport> {
    let child_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("child xUDT amount overflow"))?;
    ensure!(
        child_xudt_amount > 1,
        "negative xUDT reduced-exit smoke needs at least two token units"
    );
    let xudt_type_hash =
        devnet_owner_xudt_type_hash(rpc, &options.contracts_dir, &options.private_key)?;
    let alice_key = k256_signing_key(&options.alice_private_key)
        .with_context(|| "invalid Alice factory private key")?;
    let bob_key = k256_signing_key(&options.bob_private_key)
        .with_context(|| "invalid Bob factory private key")?;
    let (old_state_root, old_access_manifest_root) = reduced_xudt_exit_initial_roots(
        &alice_key,
        &bob_key,
        child_xudt_amount,
        child_xudt_amount,
        0,
        xudt_type_hash,
        options.child_vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
        options.alice_xudt_amount,
        options.bob_xudt_amount,
    )?;

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(child_xudt_amount),
            state_root: Some(hex32(&old_state_root)),
            access_manifest_root: Some(hex32(&old_access_manifest_root)),
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let rejected_child_xudt_amount = child_xudt_amount - 1;
    let rejection = match factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: Some(options.bob_private_key.clone()),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point,
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: 0,
            tamper: FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange,
            authorisation: FactoryExitAuthorisation::ReducedReserveClaim,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "xUDT reduced factory exit unexpectedly accepted tampered child vault amount in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SettlementOutputMismatch as i16),
        "expected SettlementOutputMismatch from xUDT reduced factory exit, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    Ok(FactoryReducedXudtNegativeExitSmokeReport {
        open,
        expected_child_xudt_amount: child_xudt_amount,
        rejected_child_xudt_amount,
        rejection,
        script_failure,
    })
}

pub fn factory_xudt_smoke(
    rpc: &CkbRpcClient,
    options: FactoryXudtSmokeOptions,
) -> Result<FactoryXudtSmokeReport> {
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("factory xUDT amount overflow"))?;
    ensure!(
        total_xudt_amount > 0,
        "factory xUDT amount must be non-zero"
    );

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(total_xudt_amount),
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let package = save_factory_state_package(
        rpc,
        SaveFactoryStatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let latest_package = latest_factory_state_cell_package(&options.store_dir, &open.factory_id)?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(latest_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: Some(options.bob_private_key.clone()),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: printable_out_point_string(&update.factory_out_point),
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    )?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: printable_out_point_string(&exit.state_out_point),
            sponsor_out_point: printable_out_point_string(&exit.sponsor_out_point),
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.child_vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&exit.vault_out_point),
    )?;

    Ok(FactoryXudtSmokeReport {
        open,
        package,
        latest_package,
        update,
        exit,
        publish,
        finalise,
    })
}

pub fn factory_xudt_negative_smoke(
    rpc: &CkbRpcClient,
    options: FactoryXudtNegativeSmokeOptions,
) -> Result<FactoryXudtNegativeSmokeReport> {
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("factory xUDT amount overflow"))?;
    ensure!(
        total_xudt_amount > 0,
        "factory xUDT amount must be non-zero"
    );
    ensure!(
        total_xudt_amount > 1,
        "factory xUDT negative smoke needs at least two units"
    );

    let open = open_factory(
        rpc,
        OpenFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_capacity: options.factory_capacity,
            factory_vault_capacity: options.factory_vault_capacity,
            factory_vault_xudt_amount: Some(total_xudt_amount),
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let factory_out_point = factory_cell_out_point(&open, "factory")?;
    let factory_vault_out_point = factory_cell_out_point(&open, "factory-vault")?;
    let package = save_factory_state_package(
        rpc,
        SaveFactoryStatePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point: factory_out_point.clone(),
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            store_dir: options.store_dir.clone(),
        },
    )?;
    let latest_package = latest_factory_state_cell_package(&options.store_dir, &open.factory_id)?;
    let update = update_factory(
        rpc,
        UpdateFactoryOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            additional_participant_private_keys: Vec::new(),
            factory_out_point,
            update_number: None,
            state_root: None,
            access_manifest_root: None,
            non_interference_digest: None,
            factory_state_package: Some(latest_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    let live_factory_out_point = printable_out_point_string(&update.factory_out_point);
    let rejected_child_xudt_amount = total_xudt_amount
        .checked_sub(1)
        .ok_or_else(|| anyhow!("factory xUDT negative smoke underflow"))?;
    let rejection = match factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: Some(options.bob_private_key.clone()),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: live_factory_out_point.clone(),
            factory_vault_out_point: factory_vault_out_point.clone(),
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: 0,
            tamper: FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "factory xUDT local exit unexpectedly accepted tampered child vault amount in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SettlementOutputMismatch as i16),
        "expected SettlementOutputMismatch from factory xUDT local exit, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let exit = factory_exit_channel(
        rpc,
        FactoryExitChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: Some(options.bob_private_key.clone()),
            additional_participant_private_keys: Vec::new(),
            additional_participant_public_keys: Vec::new(),
            bob_public_key: None,
            factory_out_point: live_factory_out_point,
            factory_vault_out_point,
            update_number: None,
            vault_capacity: options.child_vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            alice_xudt_amount: Some(options.alice_xudt_amount),
            bob_xudt_amount: Some(options.bob_xudt_amount),
            sponsor_capacity: options.sponsor_capacity,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
            tamper: FactoryExitChannelTamper::None,
            authorisation: FactoryExitAuthorisation::FullParticipants,
        },
    )?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: printable_out_point_string(&exit.state_out_point),
            sponsor_out_point: printable_out_point_string(&exit.sponsor_out_point),
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.child_vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&exit.vault_out_point),
    )?;

    Ok(FactoryXudtNegativeSmokeReport {
        open,
        package,
        latest_package,
        update,
        expected_child_xudt_amount: total_xudt_amount,
        rejected_child_xudt_amount,
        rejection,
        script_failure,
        exit,
        publish,
        finalise,
    })
}

pub fn factory_exit_channel(
    rpc: &CkbRpcClient,
    options: FactoryExitChannelOptions,
) -> Result<FactoryExitChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.vault_capacity > 0,
        "child channel vault capacity must be non-zero"
    );
    ensure!(
        options.sponsor_capacity > 0,
        "child channel sponsor capacity must be non-zero"
    );

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for factory exit")?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_private_pubkey = options
        .bob_private_key
        .as_deref()
        .map(|value| {
            let key = parse_privkey(value).with_context(|| "invalid Bob channel private key")?;
            compressed_pubkey(&key)
        })
        .transpose()?;
    let bob_explicit_pubkey = options
        .bob_public_key
        .as_deref()
        .map(|value| parse_compressed_pubkey_hex(value, "Bob channel public key"))
        .transpose()?;
    let bob_pubkey = match (bob_private_pubkey, bob_explicit_pubkey) {
        (Some(from_private), Some(explicit)) => {
            ensure!(
                from_private == explicit,
                "Bob private and public keys identify different participants"
            );
            from_private
        }
        (Some(from_private), None) => from_private,
        (None, Some(explicit)) => explicit,
        (None, None) => {
            return Err(anyhow!(
                "Bob private key or compressed public key is required for factory membership"
            ));
        }
    };
    ensure!(
        options.additional_participant_private_keys.is_empty()
            || options.additional_participant_public_keys.is_empty(),
        "additional factory participants must be supplied as either private keys or public keys, not both"
    );
    let mut factory_participant_pubkeys = Vec::with_capacity(
        2 + options.additional_participant_private_keys.len()
            + options.additional_participant_public_keys.len(),
    );
    factory_participant_pubkeys.push(compressed_pubkey(&alice_key)?);
    factory_participant_pubkeys.push(bob_pubkey);
    for (index, private_key) in options
        .additional_participant_private_keys
        .iter()
        .enumerate()
    {
        let key = k256_signing_key(private_key)
            .with_context(|| format!("invalid factory participant {} private key", index + 3))?;
        factory_participant_pubkeys.push(k256_pubkey(&key));
    }
    for (index, public_key) in options
        .additional_participant_public_keys
        .iter()
        .enumerate()
    {
        factory_participant_pubkeys.push(parse_compressed_pubkey_hex(
            public_key,
            &format!("factory participant {} public key", index + 3),
        )?);
    }
    ensure!(
        factory_participant_pubkeys.len() >= FACTORY_MIN_PARTICIPANTS as usize
            && factory_participant_pubkeys.len() <= FACTORY_MAX_PARTICIPANTS as usize,
        "factory exit requires {}-{} participants",
        FACTORY_MIN_PARTICIPANTS,
        FACTORY_MAX_PARTICIPANTS
    );
    ensure!(
        factory_participant_pubkeys
            .iter()
            .enumerate()
            .all(|(index, key)| factory_participant_pubkeys[..index]
                .iter()
                .all(|other| other != key)),
        "factory participant public keys must be unique"
    );
    if options.authorisation == FactoryExitAuthorisation::FullParticipants {
        ensure!(
            options.bob_private_key.is_some(),
            "full-participant factory exit requires Bob's private key"
        );
        ensure!(
            options.additional_participant_public_keys.is_empty(),
            "full-participant factory exit requires private keys for every additional participant"
        );
    }
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock_from_pubkey(&bob_pubkey)?;

    let factory_out_point = parse_out_point(&options.factory_out_point)?;
    let factory_vault_out_point = parse_out_point(&options.factory_vault_out_point)?;
    let factory_cell = load_live_cell(rpc, factory_out_point.clone())?;
    let factory_vault_cell = load_live_cell(rpc, factory_vault_out_point.clone())?;
    let factory_type = factory_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("factory cell has no type script"))?;
    let old_header = FactoryStateHeader::parse(factory_cell.data.as_ref()).map_err(|err| {
        anyhow!("factory cell does not contain a valid FactoryStateHeader: {err:?}")
    })?;
    ensure!(
        factory_type.args().raw_data().as_ref() == old_header.factory_id(),
        "factory type args do not match the factory id in cell data"
    );
    ensure_vault_outpoint_binding(
        "--factory-vault-out-point",
        old_header.vault_outpoint_commitment(),
        &factory_vault_out_point,
    )?;
    let old_update_number = old_header.update_number();
    let new_update_number = options
        .update_number
        .unwrap_or_else(|| old_update_number.saturating_add(1));
    ensure!(
        new_update_number > old_update_number,
        "new update number must be greater than old update number {}",
        old_update_number
    );

    let tip_number = rpc.tip_header()?.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let factory_contract = contract_by_name(&contracts, "morph-factory-type")?;
    let factory_vault_contract = contract_by_name(&contracts, "morph-factory-vault-lock")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let batch_contract = contract_by_name(&contracts, "morph-batch-lock")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;
    ensure!(
        byte32_to_h256(factory_type.code_hash()) == factory_contract.data_hash,
        "factory cell type script does not use the deployed morph-factory-type code hash"
    );
    ensure_type_bound_state_lock(
        &factory_cell.output,
        &factory_type,
        &state_lock_contract,
        "FactoryStateCell",
    )?;
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let factory_vault_lock = factory_vault_cell.output.lock();
    ensure!(
        byte32_to_h256(factory_vault_lock.code_hash()) == factory_vault_contract.data_hash,
        "factory vault cell lock does not use the deployed morph-factory-vault-lock code hash"
    );
    let factory_vault_args = factory_vault_lock.args().raw_data();
    ensure!(
        factory_vault_args.len() == 2 * BYTE32_LEN,
        "factory vault lock args must be 64 bytes"
    );
    ensure!(
        &factory_vault_args.as_ref()[..BYTE32_LEN] == old_header.factory_id(),
        "factory vault lock is for a different factory id"
    );
    ensure!(
        &factory_vault_args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN] == factory_type_hash.as_slice(),
        "factory vault lock is for a different factory type hash"
    );
    let factory_vault_type = factory_vault_cell.output.type_().to_opt();
    let factory_vault_xudt_amount = if factory_vault_type.is_some() {
        Some(xudt_amount_from_data(&factory_vault_cell.data)?)
    } else {
        ensure!(
            factory_vault_cell.data.is_empty(),
            "plain factory vault cell must not carry data"
        );
        None
    };
    let child_xudt = match factory_vault_xudt_amount {
        Some(total_amount) => {
            let alice_amount = options.alice_xudt_amount.ok_or_else(|| {
                anyhow!("--alice-xudt-amount is required when the FactoryVaultCell carries xUDT")
            })?;
            let bob_amount = options.bob_xudt_amount.ok_or_else(|| {
                anyhow!("--bob-xudt-amount is required when the FactoryVaultCell carries xUDT")
            })?;
            let child_amount = alice_amount
                .checked_add(bob_amount)
                .ok_or_else(|| anyhow!("child xUDT amount overflow"))?;
            ensure!(child_amount > 0, "child xUDT amount must be non-zero");
            ensure!(
                child_amount <= total_amount,
                "child xUDT amount {} exceeds factory vault amount {}",
                child_amount,
                total_amount
            );
            let xudt_type = factory_vault_type
                .clone()
                .ok_or_else(|| anyhow!("factory vault xUDT type script missing"))?;
            let xudt_type_hash: [u8; BYTE32_LEN] = xudt_type.calc_script_hash().unpack();
            Some((
                xudt_type,
                xudt_type_hash,
                total_amount,
                alice_amount,
                bob_amount,
                child_amount,
            ))
        }
        None => {
            ensure!(
                options.alice_xudt_amount.is_none() && options.bob_xudt_amount.is_none(),
                "xUDT settlement amounts require a typed FactoryVaultCell"
            );
            None
        }
    };
    let xudt_contract = if child_xudt.is_some() {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };
    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let channel_input = CellInput::new(factory_out_point.clone(), 0);
    let funding_anchor = derive_funding_anchor(&channel_input, state_output_index as u64);
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID", &funding_anchor]);
    let finalise_since = relative_block_since_arg(options.finalise_since)?;

    let state_type = data1_script(
        state_contract.data_hash.clone(),
        factory_state_type_args(&funding_anchor, &factory_type_hash, finalise_since),
    );
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(&state_type_hash),
    );
    let state_lock_hash: [u8; BYTE32_LEN] = state_lock.calc_script_hash().unpack();
    let vault_lock = data1_script(
        vault_contract.data_hash.clone(),
        vault_lock_args(
            &funding_anchor,
            finalise_since,
            &state_type,
            &state_lock,
            &batch_contract.data_hash,
            ScriptHashType::Data1,
        ),
    );
    let vault_lock_hash: [u8; BYTE32_LEN] = vault_lock.calc_script_hash().unpack();

    let owner_lock_hash = owner_lock.calc_script_hash();
    let sponsor_policy_settings = sponsor_policy_settings(
        options.sponsor_capacity,
        DEFAULT_SPONSOR_MIN_STATE_NUMBER,
        DEFAULT_SPONSOR_MAX_STATE_NUMBER,
        None,
        None,
    )?;
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        sponsor_policy_settings,
        state_type_hash,
        owner_lock_hash.unpack(),
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );

    let alice_lock_hash: [u8; BYTE32_LEN] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; BYTE32_LEN] = bob_lock.calc_script_hash().unpack();
    let (alice_capacity, bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    let descriptor;
    let descriptor_version;
    if let Some((xudt_type, xudt_type_hash, _, alice_amount, bob_amount, _)) = &child_xudt {
        ensure_output_capacity(
            "alice xUDT settlement",
            &CellOutput::new_builder()
                .capacity(alice_capacity)
                .lock(alice_lock.clone())
                .type_(Some(xudt_type.clone()).pack())
                .build(),
            16,
        )?;
        ensure_output_capacity(
            "bob xUDT settlement",
            &CellOutput::new_builder()
                .capacity(bob_capacity)
                .lock(bob_lock.clone())
                .type_(Some(xudt_type.clone()).pack())
                .build(),
            16,
        )?;
        descriptor = bilateral_ckb_xudt_descriptor(
            *xudt_type_hash,
            alice_lock_hash,
            alice_capacity,
            *alice_amount,
            bob_lock_hash,
            bob_capacity,
            *bob_amount,
        )
        .to_vec();
        descriptor_version = BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION;
    } else {
        ensure_output_capacity(
            "alice settlement",
            &CellOutput::new_builder()
                .capacity(alice_capacity)
                .lock(alice_lock.clone())
                .build(),
            0,
        )?;
        ensure_output_capacity(
            "bob settlement",
            &CellOutput::new_builder()
                .capacity(bob_capacity)
                .lock(bob_lock.clone())
                .build(),
            0,
        )?;
        descriptor =
            bilateral_ckb_descriptor(alice_lock_hash, alice_capacity, bob_lock_hash, bob_capacity)
                .to_vec();
        descriptor_version = BILATERAL_CKB_DESCRIPTOR_VERSION;
    }
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let child_vault_xudt_amount = match (&child_xudt, options.tamper) {
        (
            Some((_, _, _, _, _, child_amount)),
            FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange,
        ) => {
            let tampered_amount = child_amount
                .checked_sub(1)
                .ok_or_else(|| anyhow!("tampered child xUDT amount underflow"))?;
            ensure!(
                tampered_amount > 0,
                "tampered child xUDT amount must remain non-zero"
            );
            Some(tampered_amount)
        }
        (Some((_, _, _, _, _, child_amount)), FactoryExitChannelTamper::None) => {
            Some(*child_amount)
        }
        (None, FactoryExitChannelTamper::None) => None,
        (None, FactoryExitChannelTamper::ChildXudtAmountMinusOnePreserveFactoryChange) => {
            return Err(anyhow!(
                "factory exit xUDT tamper requires a typed FactoryVaultCell"
            ));
        }
    };
    let vault_set_commitment = vault_descriptor_commitment(&VaultDescriptor {
        funding_anchor,
        assets: live_vault_assets(
            u128::from(options.vault_capacity),
            child_xudt
                .as_ref()
                .map(|(_, xudt_type_hash, _, _, _, _)| *xudt_type_hash),
            child_vault_xudt_amount,
        ),
    });

    let alice_pubkey = compressed_pubkey(&alice_key)?;
    let mut participant_pubkeys = [alice_pubkey, bob_pubkey];
    participant_pubkeys.sort();
    let participants_commitment =
        participants_commitment(2, &[&participant_pubkeys[0], &participant_pubkeys[1]]);
    let challenge_policy_commitment =
        script_blake2b256(&[b"CKB_MORPH_CHALLENGE_POLICY", &finalise_since.to_le_bytes()]);
    let mut state_header = initial_state_header(InitialStateHeader {
        chain_id,
        channel_id,
        funding_anchor,
        vault_set_commitment,
        participants_commitment,
        asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
            xudt_types: child_xudt
                .iter()
                .map(|(_, type_hash, _, _, _, _)| *type_hash)
                .collect(),
        }),
        settlement_descriptor_commitment: descriptor_commitment,
        descriptor_version,
        challenge_policy_commitment,
    });
    state_header[148] = STATE_MODE_FACTORY_PROOF;

    let state_output_for_capacity = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let state_capacity = occupied_capacity(&state_output_for_capacity, state_header.len())?;
    let funding_state_capacity = state_capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("child StateCell activation capacity overflow"))?;
    let funding_state_output = CellOutput::new_builder()
        .capacity(funding_state_capacity)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let (child_vault_type, child_vault_data) = match (&child_xudt, child_vault_xudt_amount) {
        (Some((xudt_type, _, _, _, _, _)), Some(amount)) => {
            (Some(xudt_type.clone()), xudt_amount_bytes(amount))
        }
        (None, None) => (None, Bytes::new()),
        _ => return Err(anyhow!("child xUDT type and amount are inconsistent")),
    };
    let vault_output = CellOutput::new_builder()
        .capacity(options.vault_capacity)
        .lock(vault_lock)
        .type_(child_vault_type.pack())
        .build();
    ensure_output_capacity("child vault", &vault_output, child_vault_data.len())?;
    set_state_vault_materialisation_root(
        &mut state_header,
        vault_cell_commitment_from_output(&vault_output, child_vault_data.as_ref()),
    );
    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("child sponsor", &sponsor_output, 0)?;

    let factory_vault_change_capacity = factory_vault_cell
        .capacity
        .checked_sub(options.vault_capacity)
        .ok_or_else(|| {
            anyhow!(
                "factory vault capacity {} cannot release child vault capacity {}",
                factory_vault_cell.capacity,
                options.vault_capacity
            )
        })?;
    let factory_vault_change_xudt_amount = match (&child_xudt, child_vault_xudt_amount) {
        (Some((_, _, total_amount, _, _, _)), Some(child_amount)) => {
            Some(total_amount.checked_sub(child_amount).ok_or_else(|| {
                anyhow!(
                    "child xUDT amount {} exceeds factory vault amount {}",
                    child_amount,
                    total_amount
                )
            })?)
        }
        (None, None) => None,
        _ => return Err(anyhow!("child xUDT type and amount are inconsistent")),
    };
    let factory_vault_change_type = match (&factory_vault_type, factory_vault_change_xudt_amount) {
        (Some(xudt_type), Some(amount)) if amount > 0 => Some(xudt_type.clone()),
        _ => None,
    };
    let factory_vault_change_data = factory_vault_change_xudt_amount
        .filter(|amount| *amount > 0)
        .map(xudt_amount_bytes)
        .unwrap_or_default();
    let factory_vault_change_output = CellOutput::new_builder()
        .capacity(factory_vault_change_capacity)
        .lock(factory_vault_lock.clone())
        .type_(factory_vault_change_type.pack())
        .build();
    ensure_output_capacity(
        "factory vault change",
        &factory_vault_change_output,
        factory_vault_change_data.len(),
    )?;
    let old_factory_vault_materialisation_root = vault_cell_commitment_from_output(
        &factory_vault_cell.output,
        factory_vault_cell.data.as_ref(),
    );
    ensure!(
        old_header.vault_materialisation_root()
            == old_factory_vault_materialisation_root.as_slice(),
        "live FactoryVaultCell does not match the FactoryStateHeader commitment"
    );
    let new_factory_vault_materialisation_root = vault_cell_commitment_from_output(
        &factory_vault_change_output,
        factory_vault_change_data.as_ref(),
    );

    ensure_output_capacity("factory", &factory_cell.output, FACTORY_STATE_HEADER_LEN)?;
    let (new_factory_data, factory_exit_witness, local_exit_package, reduced_exit, authorisation) =
        match options.authorisation {
            FactoryExitAuthorisation::FullParticipants => {
                let exit_digest = factory_local_exit_digest(
                    state_output_index,
                    vault_output_index,
                    &state_type_hash,
                    &vault_lock_hash,
                    &state_lock_hash,
                    &state_header,
                    &descriptor,
                );
                let state_root = derived_factory_update_digest(
                    b"CKB_MORPH_FACTORY_STATE_ROOT_EXIT",
                    old_header.state_root(),
                    new_update_number,
                );
                let access_manifest_root = derived_factory_update_digest(
                    b"CKB_MORPH_FACTORY_ACCESS_MANIFEST_EXIT",
                    old_header.access_manifest_root(),
                    new_update_number,
                );
                let mut new_factory_data = factory_cell.data.to_vec();
                put_u64(&mut new_factory_data, 68, new_update_number);
                new_factory_data[76..108].copy_from_slice(&state_root);
                new_factory_data[140..172].copy_from_slice(&access_manifest_root);
                new_factory_data[172..204].copy_from_slice(&exit_digest);
                new_factory_data[238..270].copy_from_slice(&new_factory_vault_materialisation_root);
                new_factory_data[270..302].fill(0);
                let factory_signature = factory_signature_witness(
                    &new_factory_data,
                    &options.alice_private_key,
                    options.bob_private_key.as_deref().ok_or_else(|| {
                        anyhow!("full-participant factory exit requires Bob's private key")
                    })?,
                    &options.additional_participant_private_keys,
                )?;
                let local_exit_witness = factory_local_exit_witness(
                    &factory_signature,
                    state_output_index,
                    vault_output_index,
                    &state_type_hash,
                    &vault_lock_hash,
                    &state_lock_hash,
                    &state_header,
                    &descriptor,
                )?;
                let local_exit_package = StoredFactoryLocalExitPackage::from_factory_local_exit(
                    &new_factory_data,
                    &local_exit_witness,
                )
                .context("constructed factory local-exit package is invalid")?;
                let contract_witness = local_exit_package.contract_witness_bytes()?;
                (
                    new_factory_data,
                    contract_witness,
                    Some(local_exit_package),
                    None,
                    "full-participants".to_string(),
                )
            }
            FactoryExitAuthorisation::ReducedReserveClaim => {
                let alice_factory_key = k256_signing_key(&options.alice_private_key)
                    .with_context(|| "invalid Alice factory private key")?;
                let reserve_claim = match &child_xudt {
                    Some((_, xudt_type_hash, total_amount, _, _, child_amount)) => {
                        ReducedExitReserveClaim {
                            release_quantity: *child_amount,
                            before_quantity: *total_amount,
                            after_quantity: total_amount.checked_sub(*child_amount).ok_or_else(
                                || anyhow!("child xUDT amount exceeds factory vault amount"),
                            )?,
                            asset_type: Some(*xudt_type_hash),
                            ckb_before_quantity: options.vault_capacity as u128,
                            ckb_after_quantity: 0,
                        }
                    }
                    None => ReducedExitReserveClaim {
                        release_quantity: options.vault_capacity as u128,
                        before_quantity: options.vault_capacity as u128,
                        after_quantity: 0,
                        asset_type: None,
                        ckb_before_quantity: 100,
                        ckb_after_quantity: 100,
                    },
                };
                let reduced = reduced_exit_from_factory_header(
                    factory_cell.data.as_ref(),
                    &alice_factory_key,
                    &factory_participant_pubkeys,
                    new_update_number,
                    reserve_claim,
                    state_output_index,
                    vault_output_index,
                    &state_type_hash,
                    &vault_lock_hash,
                    &state_lock_hash,
                    &state_header,
                    &descriptor,
                    new_factory_vault_materialisation_root,
                )?;
                let contract_witness = factory_witness_envelope(
                    WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
                    &reduced.witness,
                )?;
                (
                    reduced.new_header,
                    contract_witness,
                    None,
                    Some(reduced.report),
                    "reduced-reserve-claim".to_string(),
                )
            }
        };

    let funding_factory_capacity = factory_cell
        .capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("post-exit FactoryStateCell activation capacity overflow"))?;
    let funding_factory_output = factory_cell
        .output
        .clone()
        .as_builder()
        .capacity(funding_factory_capacity)
        .build();
    ensure_output_capacity(
        "post-exit factory",
        &funding_factory_output,
        new_factory_data.len(),
    )?;

    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    ensure!(
        fee_cell.out_point != factory_out_point,
        "fee input cannot be the FactoryStateCell itself"
    );
    ensure!(
        fee_cell.out_point != factory_vault_out_point,
        "fee input cannot be the FactoryVaultCell itself"
    );
    let fixed_fee_cell_capacity = funding_state_capacity
        .checked_add(options.sponsor_capacity)
        .and_then(|value| value.checked_add(STATE_CARRIER_ACTIVATION_FEE))
        .and_then(|value| value.checked_add(options.fee))
        .ok_or_else(|| anyhow!("factory exit fee-side output capacity overflow"))?;
    let fee_change_capacity = fee_cell
        .capacity
        .checked_sub(fixed_fee_cell_capacity)
        .ok_or_else(|| {
            anyhow!(
                "fee input capacity {} cannot cover state {}, sponsor {}, and fee {}",
                fee_cell.capacity,
                state_capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock)
        .build();

    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep.clone())
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .cell_dep(factory_contract.cell_dep.clone())
        .cell_dep(factory_vault_contract.cell_dep)
        .cell_dep(vault_contract.cell_dep)
        .cell_dep(sponsor_contract.cell_dep);
    if let Some(contract) = xudt_contract {
        builder = builder.cell_dep(contract.cell_dep);
    }
    let unsigned = builder
        .input(channel_input)
        .input(CellInput::new(factory_vault_out_point.clone(), 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0))
        .output(funding_factory_output.clone())
        .output(funding_state_output.clone())
        .output(vault_output.clone())
        .output(factory_vault_change_output.clone())
        .output(sponsor_output.clone())
        .output(fee_change_output)
        .output_data(Bytes::copy_from_slice(&new_factory_data).pack())
        .output_data(Bytes::copy_from_slice(&state_header).pack())
        .output_data(child_vault_data.pack())
        .output_data(factory_vault_change_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_factory_exit_transaction(
        unsigned,
        &owner_key,
        Bytes::copy_from_slice(&factory_exit_witness),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let tx_hash = sent.tx_hash.clone();
    let (factory_activation, _, _) = activate_factory_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_factory_output,
        new_factory_data
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("post-exit FactoryStateHeader has an invalid length"))?,
        &state_lock_contract,
        &factory_contract,
        0,
        3,
        options.mine_blocks,
    )?;
    let (state_activation, _, _) = activate_state_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_state_output,
        &state_header,
        &state_lock_contract,
        &state_contract,
        state_output_index,
        vault_output_index,
        options.mine_blocks,
    )?;
    let factory_activation_tx_hash = factory_activation.tx_hash.clone();
    let state_activation_tx_hash = state_activation.tx_hash.clone();

    Ok(FactoryExitChannelReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        authorisation,
        factory_id: hex32(old_header.factory_id()),
        old_update_number,
        new_update_number,
        channel_id: hex32(&channel_id),
        funding_anchor: hex32(&funding_anchor),
        finalise_since: options.finalise_since,
        factory_out_point: PrintableOutPoint {
            tx_hash: factory_activation_tx_hash.clone(),
            index: 0,
        },
        state_out_point: PrintableOutPoint {
            tx_hash: state_activation_tx_hash.clone(),
            index: 0,
        },
        vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: vault_output_index,
        },
        factory_vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: 3,
        },
        sponsor_out_point: PrintableOutPoint { tx_hash, index: 4 },
        factory_activation_tx_hash,
        factory_activation_status: factory_activation.status,
        factory_activation_block_number: factory_activation.block_number,
        factory_activation_block_hash: factory_activation.block_hash,
        factory_activation_metrics: factory_activation.metrics,
        factory_activation_mined_blocks: factory_activation.mined_blocks,
        state_activation_tx_hash,
        state_activation_status: state_activation.status,
        state_activation_block_number: state_activation.block_number,
        state_activation_block_hash: state_activation.block_hash,
        state_activation_metrics: state_activation.metrics,
        state_activation_mined_blocks: state_activation.mined_blocks,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE * 2,
        state_capacity,
        vault_capacity: options.vault_capacity,
        child_xudt_amount: child_xudt
            .as_ref()
            .map(|(_, _, _, _, _, child_amount)| *child_amount),
        alice_xudt_amount: child_xudt
            .as_ref()
            .map(|(_, _, _, alice_amount, _, _)| *alice_amount),
        bob_xudt_amount: child_xudt
            .as_ref()
            .map(|(_, _, _, _, bob_amount, _)| *bob_amount),
        factory_vault_input_capacity: factory_vault_cell.capacity,
        factory_vault_change_capacity,
        factory_vault_input_xudt_amount: factory_vault_xudt_amount,
        factory_vault_change_xudt_amount,
        xudt_type_hash: child_xudt
            .as_ref()
            .map(|(_, xudt_type_hash, _, _, _, _)| hex32(xudt_type_hash)),
        local_exit_package,
        reduced_exit,
        sponsor_capacity: options.sponsor_capacity,
        fee_change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        participants: vec![
            ParticipantReport {
                role: "alice".to_string(),
                lock_hash: hex32(&alice_lock_hash),
                pubkey_sec1: hex_prefixed(&alice_pubkey),
                capacity: alice_capacity,
            },
            ParticipantReport {
                role: "bob".to_string(),
                lock_hash: hex32(&bob_lock_hash),
                pubkey_sec1: hex_prefixed(&bob_pubkey),
                capacity: bob_capacity,
            },
        ],
    })
}

fn open_xudt_channel(rpc: &CkbRpcClient, options: &XudtSmokeOptions) -> Result<OpenChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");
    ensure!(
        options.vault_capacity > 0,
        "vault capacity must be non-zero"
    );
    ensure!(
        options.sponsor_capacity > 0,
        "sponsor capacity must be non-zero"
    );
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    ensure!(total_xudt_amount > 0, "xUDT amount must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for devnet xUDT channel opener")?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;

    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let tip = rpc.tip_header()?;
    let tip_number = tip.number_value()?;
    let genesis = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is not available from CKB RPC"))?;
    let chain_id = genesis.header.hash.0;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let batch_contract = contract_by_name(&contracts, "morph-batch-lock")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;
    let xudt_contract = contract_by_name(&contracts, "morph-devnet-xudt")?;

    let channel_input = CellInput::new(funding_cell.out_point.clone(), 0);
    let funding_anchor = derive_funding_anchor(&channel_input, 0);
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID", &funding_anchor]);
    let finalise_since = relative_block_since_arg(options.finalise_since)?;

    let state_type = data1_script(
        state_contract.data_hash.clone(),
        state_type_args(&funding_anchor, finalise_since),
    );
    let state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(state_type.calc_script_hash().as_slice()),
    );

    let vault_lock = data1_script(
        vault_contract.data_hash.clone(),
        vault_lock_args(
            &funding_anchor,
            finalise_since,
            &state_type,
            &state_lock,
            &batch_contract.data_hash,
            ScriptHashType::Data1,
        ),
    );

    let owner_lock_hash = owner_lock.calc_script_hash();
    let xudt_type = data1_script(
        xudt_contract.data_hash.clone(),
        Bytes::copy_from_slice(owner_lock_hash.as_slice()),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();

    let sponsor_policy_settings = sponsor_policy_settings(
        options.sponsor_capacity,
        DEFAULT_SPONSOR_MIN_STATE_NUMBER,
        DEFAULT_SPONSOR_MAX_STATE_NUMBER,
        None,
        None,
    )?;
    let sponsor_policy = sponsor_policy_bytes(
        &channel_id,
        sponsor_policy_settings,
        state_type.calc_script_hash().unpack(),
        owner_lock_hash.unpack(),
    );
    let sponsor_lock = data1_script(
        sponsor_contract.data_hash.clone(),
        Bytes::copy_from_slice(&sponsor_policy),
    );

    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();
    let (alice_capacity, bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice xUDT settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        16,
    )?;
    ensure_output_capacity(
        "bob xUDT settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        16,
    )?;
    let descriptor = bilateral_ckb_xudt_descriptor(
        xudt_type_hash,
        alice_lock_hash,
        alice_capacity,
        options.alice_xudt_amount,
        bob_lock_hash,
        bob_capacity,
        options.bob_xudt_amount,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let vault_set_commitment = vault_descriptor_commitment(&VaultDescriptor {
        funding_anchor,
        assets: live_vault_assets(
            u128::from(options.vault_capacity),
            Some(xudt_type_hash),
            Some(total_xudt_amount),
        ),
    });

    let alice_pubkey = compressed_pubkey(&alice_key)?;
    let bob_pubkey = compressed_pubkey(&bob_key)?;
    let mut participant_pubkeys = [alice_pubkey, bob_pubkey];
    participant_pubkeys.sort();
    let participants_commitment =
        participants_commitment(2, &[&participant_pubkeys[0], &participant_pubkeys[1]]);
    let challenge_policy_commitment =
        script_blake2b256(&[b"CKB_MORPH_CHALLENGE_POLICY", &finalise_since.to_le_bytes()]);
    let mut state_header = initial_state_header(InitialStateHeader {
        chain_id,
        channel_id,
        funding_anchor,
        vault_set_commitment,
        participants_commitment,
        asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
            xudt_types: BTreeSet::from([xudt_type_hash]),
        }),
        settlement_descriptor_commitment: descriptor_commitment,
        descriptor_version: BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
        challenge_policy_commitment,
    });

    let state_output_for_capacity = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let state_capacity = occupied_capacity(&state_output_for_capacity, state_header.len())?;
    let funding_state_capacity = state_capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("StateCell activation capacity overflow"))?;
    let funding_state_output = CellOutput::new_builder()
        .capacity(funding_state_capacity)
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();

    let vault_output = CellOutput::new_builder()
        .capacity(options.vault_capacity)
        .lock(vault_lock)
        .type_(Some(xudt_type).pack())
        .build();
    ensure_output_capacity("xUDT vault", &vault_output, 16)?;
    let vault_data = xudt_amount_bytes(total_xudt_amount);
    set_state_vault_materialisation_root(
        &mut state_header,
        vault_cell_commitment_from_output(&vault_output, vault_data.as_ref()),
    );

    let sponsor_output = CellOutput::new_builder()
        .capacity(options.sponsor_capacity)
        .lock(sponsor_lock)
        .build();
    ensure_output_capacity("sponsor", &sponsor_output, 0)?;

    let fixed_output_capacity = funding_state_capacity
        .checked_add(options.vault_capacity)
        .and_then(|value| value.checked_add(options.sponsor_capacity))
        .ok_or_else(|| anyhow!("channel output capacity overflow"))?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(fixed_output_capacity)
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover state {}, vault {}, sponsor {}, and fee {}",
                funding_cell.capacity,
                state_capacity,
                options.vault_capacity,
                options.sponsor_capacity,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock.clone())
        .build();
    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .cell_dep(vault_contract.cell_dep.clone())
        .cell_dep(sponsor_contract.cell_dep.clone())
        .cell_dep(xudt_contract.cell_dep.clone())
        .input(channel_input)
        .output(funding_state_output.clone())
        .output(vault_output.clone())
        .output(sponsor_output.clone())
        .output(change_output.clone())
        .output_data(Bytes::copy_from_slice(&state_header).pack())
        .output_data(vault_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_bilateral_state_creation(
        unsigned,
        &owner_key,
        &state_header,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let (activation, state_output, state_header) = activate_state_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_state_output,
        &state_header,
        &state_lock_contract,
        &state_contract,
        0,
        1,
        options.mine_blocks,
    )?;

    let funding_tx_hash_string = sent.tx_hash.clone();
    let activation_tx_hash_string = activation.tx_hash.clone();
    let cell = |role: &str,
                tx_hash: &str,
                index: u32,
                output: &CellOutput,
                data_len: usize|
     -> ChannelCellReport {
        ChannelCellReport {
            role: role.to_string(),
            out_point: PrintableOutPoint {
                tx_hash: tx_hash.to_string(),
                index,
            },
            capacity: output.capacity().unpack(),
            lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
            type_hash: output
                .type_()
                .to_opt()
                .map(|script| hex32(script.calc_script_hash().as_slice())),
            data_len,
        }
    };

    Ok(OpenChannelReport {
        tx_hash: funding_tx_hash_string.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(&channel_id),
        funding_anchor: hex32(&funding_anchor),
        finalise_since: options.finalise_since,
        input_capacity: funding_cell.capacity,
        state_capacity,
        vault_capacity: options.vault_capacity,
        sponsor_capacity: options.sponsor_capacity,
        sponsor_policy: sponsor_policy_report(
            sponsor_policy_settings,
            state_type.calc_script_hash().unpack(),
            owner_lock_hash.unpack(),
        ),
        change_capacity,
        fee: options.fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        activation_tx_hash: activation_tx_hash_string.clone(),
        activation_status: activation.status,
        activation_block_number: activation.block_number,
        activation_block_hash: activation.block_hash,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE,
        activation_metrics: activation.metrics,
        activation_mined_blocks: activation.mined_blocks,
        participants: vec![
            ParticipantReport {
                role: "alice".to_string(),
                lock_hash: hex32(&alice_lock_hash),
                pubkey_sec1: hex_prefixed(&alice_pubkey),
                capacity: alice_capacity,
            },
            ParticipantReport {
                role: "bob".to_string(),
                lock_hash: hex32(&bob_lock_hash),
                pubkey_sec1: hex_prefixed(&bob_pubkey),
                capacity: bob_capacity,
            },
        ],
        scripts: contracts
            .into_iter()
            .map(|contract| ResolvedScriptReport {
                name: contract.name,
                out_point: printable_out_point(&contract.out_point),
                data_hash: format!("{:#x}", contract.data_hash),
                hash_type: "data1".to_string(),
            })
            .collect(),
        cells: vec![
            cell(
                "state",
                &activation_tx_hash_string,
                0,
                &state_output,
                state_header.len(),
            ),
            cell("xudt-vault", &funding_tx_hash_string, 1, &vault_output, 16),
            cell("sponsor", &funding_tx_hash_string, 2, &sponsor_output, 0),
            cell("change", &funding_tx_hash_string, 3, &change_output, 0),
        ],
    })
}

fn mint_owner_xudt_cell(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    private_key: &str,
    amount: u128,
    fee: u64,
    mine_blocks: u64,
) -> Result<MintXudtCellReport> {
    ensure!(amount > 0, "xUDT mint amount must be non-zero");
    ensure!(fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(private_key)
        .with_context(|| "invalid secp256k1 private key for xUDT mint")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let tip_number = rpc.tip_header()?.number_value()?;
    let funding_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, contracts_dir, tip_number)?;
    let xudt_contract = contract_by_name(&contracts, "morph-devnet-xudt")?;

    let owner_lock_hash = owner_lock.calc_script_hash();
    let xudt_type = data1_script(
        xudt_contract.data_hash.clone(),
        Bytes::copy_from_slice(owner_lock_hash.as_slice()),
    );
    let xudt_type_hash: [u8; BYTE32_LEN] = xudt_type.calc_script_hash().unpack();
    let xudt_output_for_capacity = CellOutput::new_builder()
        .lock(owner_lock.clone())
        .type_(Some(xudt_type.clone()).pack())
        .build();
    let xudt_cell_capacity = occupied_capacity(&xudt_output_for_capacity, 16)?;
    let change_capacity = funding_cell
        .capacity
        .checked_sub(xudt_cell_capacity)
        .and_then(|value| value.checked_sub(fee))
        .ok_or_else(|| {
            anyhow!(
                "funding cell capacity {} cannot cover xUDT cell {} and fee {}",
                funding_cell.capacity,
                xudt_cell_capacity,
                fee
            )
        })?;
    ensure_change_capacity(&owner_lock, change_capacity)?;

    let xudt_output = CellOutput::new_builder()
        .capacity(xudt_cell_capacity)
        .lock(owner_lock.clone())
        .type_(Some(xudt_type).pack())
        .build();
    let change_output = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(owner_lock)
        .build();
    let unsigned = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(xudt_contract.cell_dep)
        .input(CellInput::new(funding_cell.out_point.clone(), 0))
        .output(xudt_output)
        .output(change_output)
        .output_data(xudt_amount_bytes(amount).pack())
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_single_secp_input(unsigned, &owner_key)?;
    let sent = send_and_mine(rpc, signed, mine_blocks)?;
    let tx_hash = sent.tx_hash.clone();

    Ok(MintXudtCellReport {
        tx_hash: sent.tx_hash,
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        xudt_type_hash: hex32(&xudt_type_hash),
        amount,
        cell_out_point: PrintableOutPoint { tx_hash, index: 0 },
        cell_capacity: xudt_cell_capacity,
        change_capacity,
        fee,
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
    })
}

fn devnet_owner_xudt_type_hash(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    private_key: &str,
) -> Result<[u8; BYTE32_LEN]> {
    let owner_key = parse_privkey(private_key)
        .with_context(|| "invalid secp256k1 private key for xUDT type hash")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, contracts_dir, tip_number)?;
    let xudt_contract = contract_by_name(&contracts, "morph-devnet-xudt")?;
    let owner_lock_hash = owner_lock.calc_script_hash();
    let xudt_type = data1_script(
        xudt_contract.data_hash.clone(),
        Bytes::copy_from_slice(owner_lock_hash.as_slice()),
    );
    Ok(xudt_type.calc_script_hash().unpack())
}

pub fn publish_state(
    rpc: &CkbRpcClient,
    options: PublishStateOptions,
) -> Result<PublishStateReport> {
    publish_state_with_descriptor_update_and_runtime(rpc, options, None, None)
}

fn validate_sponsor_policy_owner(
    sponsor_args: &[u8],
    expected_channel_id: &[u8],
    expected_change_lock: &[u8],
) -> Result<()> {
    let policy = WireSponsorPolicy::parse(sponsor_args)
        .map_err(|err| anyhow!("sponsor lock args are not a valid SponsorPolicy: {err:?}"))?;
    ensure!(
        policy.channel_id() == expected_channel_id,
        "sponsor policy is for a different channel"
    );
    ensure!(
        policy.change_lock() == expected_change_lock,
        "private key does not control the sponsor change lock"
    );
    Ok(())
}

fn publish_state_with_descriptor_update(
    rpc: &CkbRpcClient,
    options: PublishStateOptions,
    descriptor_update: Option<&SettlementDescriptorUpdate>,
) -> Result<PublishStateReport> {
    publish_state_with_descriptor_update_and_runtime(rpc, options, descriptor_update, None)
}

fn publish_state_with_publication_runtime(
    rpc: &CkbRpcClient,
    options: PublishStateOptions,
    runtime: PublicationRuntime,
) -> Result<PublishStateReport> {
    publish_state_with_descriptor_update_and_runtime(rpc, options, None, Some(runtime))
}

fn publish_state_with_descriptor_update_and_runtime(
    rpc: &CkbRpcClient,
    options: PublishStateOptions,
    descriptor_update: Option<&SettlementDescriptorUpdate>,
    publication_runtime: Option<PublicationRuntime>,
) -> Result<PublishStateReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for sponsor change")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let sponsor_out_point = parse_out_point(&options.sponsor_out_point)?;
    // Publication and replacement are built from the canonical chain view. A pending
    // transaction makes these cells appear dead in the pool-aware view even though a
    // higher-fee conflicting transaction is exactly how CKB RBF is requested.
    let state_cell = load_canonical_live_cell(rpc, state_out_point.clone())?;
    let sponsor_cell = load_canonical_live_cell(rpc, sponsor_out_point.clone())?;
    let old_header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    let new_state_number = options
        .state_number
        .unwrap_or_else(|| old_header.state_number().saturating_add(1));
    ensure!(
        new_state_number > old_header.state_number(),
        "new state number must be greater than old state number {}",
        old_header.state_number()
    );

    let sponsor_args = sponsor_cell.output.lock().args().raw_data();
    validate_sponsor_policy_owner(
        sponsor_args.as_ref(),
        old_header.channel_id(),
        owner_lock.calc_script_hash().as_slice(),
    )?;
    let sponsor_policy = WireSponsorPolicy::parse(sponsor_args.as_ref())
        .map_err(|err| anyhow!("sponsor lock args are not a valid SponsorPolicy: {err:?}"))?;
    let sponsor_remaining_budget = sponsor_policy
        .max_total_fee()
        .checked_sub(sponsor_policy.already_spent())
        .ok_or_else(|| anyhow!("sponsor policy already_spent exceeds max_total_fee"))?;

    let (new_state_data, signature_witness, new_state_number, state_package) =
        if let Some(path) = &options.state_package {
            ensure!(
                descriptor_update.is_none(),
                "state package already defines the signed settlement descriptor"
            );
            let package = read_package(path)?;
            let header_bytes = package.header_bytes()?;
            let witness_bytes = package.witness_bytes()?;
            let package_state_number = {
                let package_header = WireStateHeader::parse(&header_bytes)
                    .map_err(|err| anyhow!("state package header is invalid: {err:?}"))?;
                ensure!(
                    old_header.same_context_except_progress(&package_header),
                    "state package does not match the current channel context"
                );
                ensure!(
                    package_header.state_number() > old_header.state_number(),
                    "state package number {} must be greater than old state number {}",
                    package_header.state_number(),
                    old_header.state_number()
                );
                ensure!(
                    package_header.phase() == PHASE_SETTLING,
                    "state package must publish a settling state"
                );
                package_header.state_number()
            };
            (
                header_bytes,
                witness_bytes,
                package_state_number,
                Some(path.display().to_string()),
            )
        } else {
            let mut new_state_data = state_cell.data.to_vec();
            put_u64(&mut new_state_data, 140, new_state_number);
            new_state_data[149] = PHASE_SETTLING;
            if let Some(update) = descriptor_update {
                apply_settlement_descriptor_update(
                    &mut new_state_data,
                    &options.alice_private_key,
                    &options.bob_private_key,
                    update,
                )?;
            }
            let signature_witness = bilateral_signature_witness(
                &new_state_data,
                &options.alice_private_key,
                &options.bob_private_key,
            )?;
            (
                new_state_data,
                signature_witness.to_vec(),
                new_state_number,
                None,
            )
        };

    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    ensure_output_capacity("state", &state_cell.output, new_state_data.len())?;
    let build_transaction = |fee: u64| -> Result<ckb_types::core::TransactionView> {
        ensure!(
            fee <= sponsor_policy.max_fee_per_tx(),
            "fee {fee} exceeds SponsorPolicy max_fee_per_tx {}",
            sponsor_policy.max_fee_per_tx()
        );
        ensure!(
            fee <= sponsor_remaining_budget,
            "fee {fee} exceeds remaining SponsorPolicy budget {sponsor_remaining_budget}"
        );
        let sponsor_change_capacity = sponsor_cell
            .capacity
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("sponsor capacity cannot cover fee {fee}"))?;
        ensure_change_capacity(&owner_lock, sponsor_change_capacity)?;
        Ok(TransactionBuilder::default()
            .cell_dep(state_lock_contract.cell_dep.clone())
            .cell_dep(state_contract.cell_dep.clone())
            .cell_dep(sponsor_contract.cell_dep.clone())
            .input(CellInput::new(state_out_point.clone(), 0))
            .input(CellInput::new(sponsor_out_point.clone(), 0))
            .output(state_cell.output.clone())
            .output(
                CellOutput::new_builder()
                    .capacity(sponsor_change_capacity)
                    .lock(owner_lock.clone())
                    .build(),
            )
            .output_data(Bytes::copy_from_slice(&new_state_data).pack())
            .output_data(Bytes::new().pack())
            .witness(witness_with_input_type(Bytes::copy_from_slice(
                &signature_witness,
            )))
            .witness(empty_witness())
            .build())
    };

    let (sent_hash, actual_fee, canonical_confirmations, canonical_confirmed) =
        if let Some(runtime) = publication_runtime.as_ref() {
            let observation = runtime.profile.observe_fee_market(rpc)?;
            // The provisional transaction exists only to determine the fixed-layout
            // serialized size. It must not inherit the legacy absolute fee because
            // that value may legitimately exceed a tighter production profile.
            let provisional = build_transaction(1)?;
            let rate = initial_fee_rate(&runtime.profile.fee, &observation)?;
            let dynamic_fee = fee_for_rate(rate, provisional.data().as_slice().len())?;
            ensure!(
                dynamic_fee <= runtime.profile.fee.max_fee,
                "initial fee {dynamic_fee} exceeds operator maximum {}",
                runtime.profile.fee.max_fee
            );
            let initial = build_transaction(dynamic_fee)?;
            verify_initial_fee_convergence(rate, dynamic_fee, initial.data().as_slice().len())?;
            let sent = send_publication_attempts(
                rpc,
                initial,
                dynamic_fee,
                options.mine_blocks,
                runtime,
                &observation,
                &build_transaction,
            )?;
            (
                sent.report,
                sent.fee,
                sent.canonical_confirmations,
                sent.canonical_confirmed,
            )
        } else {
            let tx = build_transaction(options.fee)?;
            let sent = send_and_mine(rpc, tx, options.mine_blocks)?;
            let confirmations = transaction_confirmations(rpc, &sent)?;
            (sent, options.fee, confirmations, confirmations > 0)
        };
    let sponsor_change_capacity = sponsor_cell
        .capacity
        .checked_sub(actual_fee)
        .ok_or_else(|| anyhow!("sponsor capacity cannot cover fee {actual_fee}"))?;
    let new_state_tx_hash = sent_hash.tx_hash.clone();

    Ok(PublishStateReport {
        tx_hash: sent_hash.tx_hash,
        status: sent_hash.status,
        block_number: sent_hash.block_number,
        block_hash: sent_hash.block_hash,
        canonical_confirmations,
        canonical_confirmed,
        channel_id: hex32(old_header.channel_id()),
        funding_anchor: hex32(old_header.funding_anchor()),
        old_state_number: old_header.state_number(),
        new_state_number,
        state_out_point: PrintableOutPoint {
            tx_hash: new_state_tx_hash,
            index: 0,
        },
        sponsor_change_capacity,
        fee: actual_fee,
        state_package,
        metrics: sent_hash.metrics,
        mined_blocks: sent_hash.mined_blocks,
    })
}

fn apply_settlement_descriptor_update(
    state_data: &mut [u8],
    alice_private_key: &str,
    bob_private_key: &str,
    update: &SettlementDescriptorUpdate,
) -> Result<()> {
    ensure!(
        state_data.len() == STATE_HEADER_LEN,
        "state descriptor update requires a fixed-layout StateHeader"
    );
    let alice_key = parse_privkey(alice_private_key)
        .with_context(|| "invalid Alice channel private key for descriptor update")?;
    let bob_key = parse_privkey(bob_private_key)
        .with_context(|| "invalid Bob channel private key for descriptor update")?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let alice_lock_hash: [u8; BYTE32_LEN] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; BYTE32_LEN] = bob_lock.calc_script_hash().unpack();

    let (descriptor_commitment, descriptor_version) = if let Some(xudt) = &update.xudt {
        let descriptor = bilateral_ckb_xudt_descriptor(
            xudt.type_hash,
            alice_lock_hash,
            update.alice_capacity,
            xudt.alice_amount,
            bob_lock_hash,
            update.bob_capacity,
            xudt.bob_amount,
        );
        (
            settlement_descriptor_commitment(&descriptor),
            BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
        )
    } else {
        let descriptor = bilateral_ckb_descriptor(
            alice_lock_hash,
            update.alice_capacity,
            bob_lock_hash,
            update.bob_capacity,
        );
        (
            settlement_descriptor_commitment(&descriptor),
            BILATERAL_CKB_DESCRIPTOR_VERSION,
        )
    };
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    put_u16(state_data, 246, descriptor_version);
    Ok(())
}

pub fn save_state_package(
    rpc: &CkbRpcClient,
    options: SaveStatePackageOptions,
) -> Result<SaveStatePackageReport> {
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let old_header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    let new_state_number = options
        .state_number
        .unwrap_or_else(|| old_header.state_number().saturating_add(1));
    ensure!(
        new_state_number > old_header.state_number(),
        "new state number must be greater than old state number {}",
        old_header.state_number()
    );

    let mut new_state_data = state_cell.data.to_vec();
    put_u64(&mut new_state_data, 140, new_state_number);
    new_state_data[149] = PHASE_SETTLING;
    let signature_witness = bilateral_signature_witness(
        &new_state_data,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;

    let printable = printable_out_point(&state_out_point);
    let package = StoredStatePackage::from_signed_state(
        &new_state_data,
        &signature_witness,
        Some(PackageOutPoint {
            tx_hash: printable.tx_hash,
            index: printable.index,
        }),
    )?;
    let path = write_package(&options.store_dir, &package)?;

    Ok(SaveStatePackageReport {
        path: path.display().to_string(),
        package,
    })
}

pub fn save_splice_package(
    rpc: &CkbRpcClient,
    options: SaveSplicePackageOptions,
) -> Result<SaveSplicePackageReport> {
    let state_out_point = parse_out_point(&options.state_out_point)?;
    let vault_out_point = parse_out_point(&options.vault_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let vault_cell = load_live_cell(rpc, vault_out_point.clone())?;
    let live_xudt = live_vault_xudt_asset(&vault_cell)?;

    let old_header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    ensure!(
        old_header.phase() == PHASE_ACTIVE,
        "splice packages can only be generated from an active StateCell"
    );
    let current_state = core_state_cell_from_live(&old_header, &state_cell)?;
    ensure!(
        current_state.header.signature_scheme_id == SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
        "unsupported StateCell signature scheme {}",
        current_state.header.signature_scheme_id
    );

    let new_funding_epoch = options
        .new_funding_epoch
        .unwrap_or_else(|| options.old_funding_epoch.saturating_add(1));
    ensure!(
        new_funding_epoch > options.old_funding_epoch,
        "new funding epoch must be greater than old funding epoch {}",
        options.old_funding_epoch
    );
    let splice_number = options.splice_number.unwrap_or(new_funding_epoch);
    if matches!(options.kind, DevnetSpliceKind::SpliceOut) {
        ensure!(
            options.signed_fee == 0,
            "splice-out packages cannot carry signed_fee"
        );
    }

    let old_ckb_amount = u128::from(vault_cell.capacity);
    let mut new_ckb_amount = old_ckb_amount;
    let mut new_xudt_amount = live_xudt.as_ref().map(|asset| asset.amount);
    let mut deltas = Vec::new();
    let mut withdrawals = Vec::new();
    let splice_kind = match options.kind {
        DevnetSpliceKind::SpliceIn => SpliceKind::In,
        DevnetSpliceKind::SpliceOut => SpliceKind::Out,
    };
    let withdrawal_lock_hash = match splice_kind {
        SpliceKind::In => [0; BYTE32_LEN],
        SpliceKind::Out => splice_withdrawal_lock_hash_from_keys(
            &options.alice_private_key,
            &options.bob_private_key,
        )?,
    };

    match options.asset {
        DevnetSpliceAsset::Ckb => {
            ensure!(options.ckb_amount > 0, "ckb_amount must be non-zero");
            let requested_amount = u128::from(options.ckb_amount);
            let signed_fee = u128::from(options.signed_fee);
            match options.kind {
                DevnetSpliceKind::SpliceIn => {
                    new_ckb_amount = old_ckb_amount
                        .checked_add(requested_amount)
                        .ok_or_else(|| anyhow!("post-splice vault capacity overflows u128"))?;
                    let external_input = requested_amount
                        .checked_add(signed_fee)
                        .ok_or_else(|| anyhow!("splice external input overflows u128"))?;
                    deltas.push(SpliceAssetDelta {
                        asset: VaultAsset::Ckb,
                        old_amount: old_ckb_amount,
                        new_amount: new_ckb_amount,
                        external_input,
                        withdrawal: 0,
                        signed_fee,
                    });
                }
                DevnetSpliceKind::SpliceOut => {
                    ensure!(
                        requested_amount < old_ckb_amount,
                        "splice-out amount must be below the live vault capacity {}",
                        vault_cell.capacity
                    );
                    new_ckb_amount = old_ckb_amount - requested_amount;
                    deltas.push(SpliceAssetDelta {
                        asset: VaultAsset::Ckb,
                        old_amount: old_ckb_amount,
                        new_amount: new_ckb_amount,
                        external_input: 0,
                        withdrawal: requested_amount,
                        signed_fee,
                    });
                    withdrawals.push(VaultAssetAmount {
                        asset: VaultAsset::Ckb,
                        amount: requested_amount,
                    });
                }
            }
        }
        DevnetSpliceAsset::Xudt => {
            ensure!(
                options.signed_fee == 0,
                "xUDT splice packages cannot carry signed_fee"
            );
            let requested_amount = options
                .xudt_amount
                .ok_or_else(|| anyhow!("xudt_amount is required for xUDT splice packages"))?;
            ensure!(requested_amount > 0, "xudt_amount must be non-zero");
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("live VaultCell does not carry a devnet xUDT type"))?;
            match options.kind {
                DevnetSpliceKind::SpliceIn => {
                    let post_splice_amount = live_xudt
                        .amount
                        .checked_add(requested_amount)
                        .ok_or_else(|| anyhow!("post-splice xUDT amount overflows u128"))?;
                    new_xudt_amount = Some(post_splice_amount);
                    deltas.push(SpliceAssetDelta {
                        asset: VaultAsset::Xudt(live_xudt.type_hash),
                        old_amount: live_xudt.amount,
                        new_amount: post_splice_amount,
                        external_input: requested_amount,
                        withdrawal: 0,
                        signed_fee: 0,
                    });
                }
                DevnetSpliceKind::SpliceOut => {
                    ensure!(
                        requested_amount < live_xudt.amount,
                        "xUDT splice-out amount must be below the live vault amount {}",
                        live_xudt.amount
                    );
                    let post_splice_amount = live_xudt.amount - requested_amount;
                    new_xudt_amount = Some(post_splice_amount);
                    deltas.push(SpliceAssetDelta {
                        asset: VaultAsset::Xudt(live_xudt.type_hash),
                        old_amount: live_xudt.amount,
                        new_amount: post_splice_amount,
                        external_input: 0,
                        withdrawal: requested_amount,
                        signed_fee: 0,
                    });
                    withdrawals.push(VaultAssetAmount {
                        asset: VaultAsset::Xudt(live_xudt.type_hash),
                        amount: requested_amount,
                    });
                }
            }
        }
    }

    let new_vault_capacity: u64 = new_ckb_amount
        .try_into()
        .context("post-splice CKB vault amount does not fit in u64 capacity")?;

    let xudt_type_hash = live_xudt.as_ref().map(|asset| asset.type_hash);
    let new_funding_anchor = derive_splice_funding_anchor(
        &current_state.header.funding_anchor,
        &state_out_point,
        &vault_out_point,
        options.old_funding_epoch,
        new_funding_epoch,
        splice_number,
        options.kind,
        options.asset,
        xudt_type_hash.as_ref(),
        match options.asset {
            DevnetSpliceAsset::Ckb => u128::from(options.ckb_amount),
            DevnetSpliceAsset::Xudt => options.xudt_amount.unwrap_or_default(),
        },
    );
    ensure!(
        new_funding_anchor != current_state.header.funding_anchor,
        "derived splice funding anchor unexpectedly matches the current anchor"
    );

    let old_xudt_amount = live_xudt.as_ref().map(|asset| asset.amount);
    let old_vault = VaultDescriptor {
        funding_anchor: current_state.header.funding_anchor,
        assets: live_vault_assets(old_ckb_amount, xudt_type_hash, old_xudt_amount),
    };
    let new_vault = VaultDescriptor {
        funding_anchor: new_funding_anchor,
        assets: live_vault_assets(new_ckb_amount, xudt_type_hash, new_xudt_amount),
    };
    let remaining_settlement = new_vault.assets.clone();

    let old_state_type = state_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("StateCell does not carry a type script"))?;
    let old_state_args = old_state_type.args().raw_data();
    ensure!(
        old_state_args.len() >= BYTE32_LEN
            && old_state_args.as_ref()[..BYTE32_LEN] == current_state.header.funding_anchor,
        "StateCell type args do not match splice old funding anchor"
    );
    let old_vault_lock = vault_cell.output.lock();
    let old_vault_args = old_vault_lock.args().raw_data();
    ensure!(
        old_vault_args.len() >= BYTE32_LEN
            && old_vault_args.as_ref()[..BYTE32_LEN] == current_state.header.funding_anchor,
        "VaultCell lock args do not match splice old funding anchor"
    );
    let mut new_vault_args = new_funding_anchor.to_vec();
    new_vault_args.extend_from_slice(&old_vault_args.as_ref()[BYTE32_LEN..]);
    let new_vault_lock = Script::new_builder()
        .code_hash(old_vault_lock.code_hash())
        .hash_type(old_vault_lock.hash_type())
        .args(Bytes::from(new_vault_args).pack())
        .build();
    let mut new_vault_builder = CellOutput::new_builder()
        .capacity(new_vault_capacity)
        .lock(new_vault_lock);
    let new_vault_data = match (&live_xudt, new_xudt_amount) {
        (Some(live_xudt), Some(amount)) => {
            new_vault_builder = new_vault_builder.type_(Some(live_xudt.type_script.clone()).pack());
            xudt_amount_bytes(amount)
        }
        (None, None) => Bytes::new(),
        _ => {
            return Err(anyhow!(
                "live xUDT type and post-splice amount are inconsistent"
            ));
        }
    };
    let new_vault_output = new_vault_builder.build();
    ensure_output_capacity("post-splice vault", &new_vault_output, new_vault_data.len())?;
    let new_vault_materialisation_root =
        vault_cell_commitment_from_output(&new_vault_output, new_vault_data.as_ref());

    let mut header = SpliceHeader {
        protocol_version: current_state.header.protocol_version,
        chain_id: current_state.header.chain_id,
        signature_scheme_id: current_state.header.signature_scheme_id,
        channel_id: current_state.header.channel_id,
        old_funding_anchor: current_state.header.funding_anchor,
        new_funding_anchor,
        old_funding_epoch: options.old_funding_epoch,
        new_funding_epoch,
        base_state_number: current_state.header.state_number,
        splice_number,
        kind: splice_kind,
        old_vault_commitment: [0u8; BYTE32_LEN],
        new_vault_commitment: [0u8; BYTE32_LEN],
        asset_delta_commitment: [0u8; BYTE32_LEN],
        participants_commitment: current_state.header.participants_commitment,
        vault_materialisation_root: current_state.header.vault_materialisation_root,
        new_vault_materialisation_root,
        old_vault_outpoint_commitment: current_state.header.vault_outpoint_commitment,
        new_vault_outpoint_commitment: [0; BYTE32_LEN],
        withdrawal_lock_hash,
        challenge_policy_commitment: current_state.header.challenge_policy_commitment,
    };
    header.old_vault_commitment = vault_descriptor_commitment(&old_vault);
    header.new_vault_commitment = vault_descriptor_commitment(&new_vault);
    header.asset_delta_commitment = splice_asset_delta_commitment(&deltas);

    let witness = splice_witness_from_keys(
        &header,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    let mut next_state = current_state.clone();
    next_state.header.funding_epoch = header.new_funding_epoch;
    next_state.header.funding_anchor = header.new_funding_anchor;
    next_state.header.vault_set_commitment = header.new_vault_commitment;
    next_state.header.vault_materialisation_root = header.new_vault_materialisation_root;
    next_state.header.vault_outpoint_commitment = header.new_vault_outpoint_commitment;
    let transition = SpliceTransition {
        current_state,
        next_state,
        header,
        witness,
        old_vault,
        new_vault,
        deltas,
        withdrawals,
        remaining_settlement,
        asset_registry: AssetRegistry {
            xudt_types: xudt_type_hash.into_iter().collect(),
        },
    };

    let state_printable = printable_out_point(&state_out_point);
    let vault_printable = printable_out_point(&vault_out_point);
    let package = StoredSplicePackage::from_transition(
        &transition,
        Some(PackageOutPoint {
            tx_hash: state_printable.tx_hash,
            index: state_printable.index,
        }),
        Some(PackageOutPoint {
            tx_hash: vault_printable.tx_hash,
            index: vault_printable.index,
        }),
        None,
    )?;
    let contract_witness_len = package.contract_witness_bytes()?.len();
    let path = write_splice_package(&options.store_dir, &package)?;

    Ok(SaveSplicePackageReport {
        path: path.display().to_string(),
        kind: match options.kind {
            DevnetSpliceKind::SpliceIn => "splice_in",
            DevnetSpliceKind::SpliceOut => "splice_out",
        }
        .to_string(),
        asset: match options.asset {
            DevnetSpliceAsset::Ckb => "ckb",
            DevnetSpliceAsset::Xudt => "xudt",
        }
        .to_string(),
        ckb_amount: if options.asset == DevnetSpliceAsset::Ckb {
            options.ckb_amount
        } else {
            0
        },
        xudt_amount: if options.asset == DevnetSpliceAsset::Xudt {
            options.xudt_amount
        } else {
            None
        },
        xudt_type_hash: xudt_type_hash.map(|type_hash| hex32(&type_hash)),
        old_vault_capacity: vault_cell.capacity,
        new_vault_capacity,
        old_xudt_amount,
        new_xudt_amount,
        old_funding_epoch: options.old_funding_epoch,
        new_funding_epoch,
        splice_number,
        contract_witness_len,
        package,
    })
}

pub fn publish_latest_state_package(
    rpc: &CkbRpcClient,
    options: PublishLatestStatePackageOptions,
) -> Result<PublishLatestStatePackageReport> {
    let selected_package = latest_package(&options.store_dir, &options.channel_id)?;
    let publication = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: String::new(),
            bob_private_key: String::new(),
            state_out_point: options.state_out_point,
            sponsor_out_point: options.sponsor_out_point,
            state_number: None,
            state_package: Some(selected_package.path.clone()),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    Ok(PublishLatestStatePackageReport {
        selected_package,
        publication,
    })
}

fn authorized_watch_fee(
    publication_max_fee: Option<u64>,
    funding_fee: u64,
    auto_fund_sponsor: bool,
) -> u64 {
    let publication_fee = publication_max_fee.unwrap_or(funding_fee);
    if auto_fund_sponsor {
        publication_fee.max(funding_fee)
    } else {
        publication_fee
    }
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

pub fn watch_latest_state_package(
    rpc: &CkbRpcClient,
    options: WatchLatestStatePackageOptions,
) -> Result<WatchLatestStatePackageReport> {
    ensure!(
        options.detection_depth > 0,
        "detection depth must be at least one block"
    );
    ensure!(
        options.sponsor_out_point.is_some() || options.auto_fund_sponsor,
        "watch-latest-package requires --sponsor-out-point unless --auto-fund-sponsor is set"
    );
    ensure!(
        options.sponsor_out_point.is_none() || !options.auto_fund_sponsor,
        "pass either --sponsor-out-point or --auto-fund-sponsor, not both"
    );
    ensure!(
        !options.auto_fund_sponsor || options.mine_blocks > 0,
        "auto sponsor funding requires --mine-blocks greater than zero on devnet"
    );
    let publication_profile = options
        .publication_profile
        .as_ref()
        .map(|path| read_publication_profile(path))
        .transpose()?;
    ensure!(
        publication_profile.is_none() || options.publication_attempt_log.is_some(),
        "a publication profile requires a durable publication attempt log"
    );
    let publication_reconciliation = if let (Some(profile), Some(path)) = (
        publication_profile.as_ref(),
        options.publication_attempt_log.as_ref(),
    ) {
        Some(reconcile_publication_attempts(rpc, path, profile)?)
    } else {
        None
    };
    if let Some(path) = &options.watch_policy {
        let policy = read_watchtower_policy(path)?;
        policy.validate_run(&WatchPolicyRun {
            channel_id: &options.channel_id,
            detection_depth: options.detection_depth,
            timeout_secs: options.timeout_secs,
            poll_ms: options.poll_ms,
            fee: authorized_watch_fee(
                publication_profile
                    .as_ref()
                    .map(|profile| profile.fee.max_fee),
                options.fee,
                options.auto_fund_sponsor,
            ),
            mine_blocks: options.mine_blocks,
            sponsor_out_point_present: options.sponsor_out_point.is_some(),
            auto_fund_sponsor: options.auto_fund_sponsor,
            auto_sponsor_capacity: options.auto_sponsor_capacity,
            alert_webhook_present: options.alert_webhook_url.is_some(),
        })?;
    }
    let channel_id = canonical_hex32(&options.channel_id)?;
    let package_records = list_packages(&options.store_dir, Some(&channel_id))?;
    let selected_package = latest_state_package_record(&package_records)
        .ok_or_else(|| anyhow!("no state package found for channel {channel_id}"))?;
    let selected_state_number = selected_package.package.state_number;
    let state_cell_filter = state_cell_detection_filter(&options.contracts_dir)?;
    let cursor_file = options
        .cursor_file
        .clone()
        .map(Ok)
        .unwrap_or_else(|| default_watch_cursor_path(&options.store_dir, &channel_id))?;
    let loaded_cursor = if options.ignore_cursor {
        None
    } else {
        match read_watch_cursor(&cursor_file)? {
            Some(cursor) => {
                ensure!(
                    cursor.channel_id == channel_id,
                    "watch cursor {} belongs to channel {}, not {}",
                    cursor_file.display(),
                    cursor.channel_id,
                    channel_id
                );
                Some(cursor)
            }
            None => None,
        }
    };
    let mut reorg_recovery = loaded_cursor
        .as_ref()
        .map(|cursor| assess_watch_cursor_canonicality(rpc, cursor, options.from_block))
        .transpose()?
        .flatten();
    if let Some(recovery) = &reorg_recovery {
        append_watch_alert_if_requested(
            &options.alert_file,
            &options.alert_webhook_url,
            reorg_alert(
                &channel_id,
                selected_state_number,
                recovery,
                "persisted watch cursor is no longer on the canonical chain",
            )?,
        )?;
    }
    let publication_retry_rescan = if reorg_recovery.is_none() {
        loaded_cursor
            .as_ref()
            .map(|cursor| cursor_requires_publication_retry(rpc, cursor, &package_records))
            .transpose()?
            .unwrap_or(false)
    } else {
        false
    };
    let active_cursor = if reorg_recovery.is_some() || publication_retry_rescan {
        None
    } else {
        loaded_cursor.as_ref()
    };
    let effective_from_block = active_cursor
        .map(|cursor| options.from_block.max(cursor.next_block))
        .unwrap_or(options.from_block);
    let mut cursor_context = active_cursor.cloned();
    let started = Instant::now();
    let timeout = Duration::from_secs(options.timeout_secs);
    let poll_interval = Duration::from_millis(options.poll_ms);
    let mut next_block = effective_from_block;
    let mut scanned_to_block = effective_from_block.saturating_sub(1);
    let mut last_observed = None;
    let mut scanned_to_block_hash = active_cursor
        .filter(|cursor| cursor.scanned_to_block == scanned_to_block)
        .and_then(|cursor| cursor.scanned_to_block_hash.clone());
    let mut current_funding_anchor =
        active_cursor.and_then(|cursor| cursor.current_funding_anchor.clone());
    let mut current_funding_context_id =
        active_cursor.and_then(|cursor| cursor.current_funding_context_id.clone());

    loop {
        if let Some(expected_hash) = scanned_to_block_hash.as_deref() {
            let canonical_hash = canonical_block_hash(rpc, scanned_to_block)?;
            if canonical_hash.as_deref() != Some(expected_hash) {
                let recovery = watch_reorg_recovery(
                    scanned_to_block,
                    Some(expected_hash),
                    canonical_hash.as_deref(),
                    options.from_block,
                );
                append_watch_alert_if_requested(
                    &options.alert_file,
                    &options.alert_webhook_url,
                    reorg_alert(
                        &channel_id,
                        selected_state_number,
                        &recovery,
                        "canonical chain changed while the watch scan was running",
                    )?,
                )?;
                reorg_recovery = Some(recovery);
                next_block = options.from_block;
                scanned_to_block = options.from_block.saturating_sub(1);
                scanned_to_block_hash = None;
                last_observed = None;
                current_funding_anchor = None;
                current_funding_context_id = None;
                cursor_context = None;
                continue;
            }
        }
        let tip_number = rpc.tip_header()?.number_value()?;
        if tip_number.saturating_add(1) >= options.detection_depth {
            let mature_tip = tip_number + 1 - options.detection_depth;
            while next_block <= mature_tip {
                let current_block = next_block;
                let block = rpc.block_by_number(next_block)?.ok_or_else(|| {
                    anyhow!(
                        "canonical block {next_block} disappeared while scanning; retry so reorg recovery can restart from block {}",
                        options.from_block
                    )
                })?;
                scanned_to_block = current_block;
                scanned_to_block_hash = Some(format!("{:#x}", block.header.hash));
                for observed in
                    observed_state_cells(&block, &channel_id, tip_number, &state_cell_filter)?
                {
                    let observed_out_point = parse_out_point(&observed.out_point)?;
                    let canonical_cell =
                        rpc.canonical_live_cell(observed_out_point.into(), false)?;
                    if canonical_cell.status != "live" {
                        continue;
                    }
                    let previous_funding_anchor = current_funding_anchor.clone();
                    let previous_funding_context_id = current_funding_context_id.clone();
                    let splice_detected = previous_funding_context_id
                        .as_ref()
                        .is_some_and(|context_id| context_id != &observed.funding_context_id)
                        || (previous_funding_context_id.is_none()
                            && previous_funding_anchor
                                .as_ref()
                                .is_some_and(|anchor| anchor != &observed.funding_anchor));
                    if splice_detected {
                        append_watch_alert_if_requested(
                            &options.alert_file,
                            &options.alert_webhook_url,
                            WatchtowerAlert::new(
                                channel_id.clone(),
                                WatchAlertSeverity::Warning,
                                WatchAlertEvent::SpliceDetected,
                                format!(
                                    "confirmed StateCell funding anchor changed from {} to {}",
                                    previous_funding_anchor.as_deref().unwrap_or_default(),
                                    observed.funding_anchor
                                ),
                                selected_state_number,
                                scanned_to_block,
                                current_block.saturating_add(1),
                            )?
                            .with_observed(observed.state_number, observed.out_point.clone())
                            .with_funding_anchors(
                                previous_funding_anchor.unwrap_or_default(),
                                observed.funding_anchor.clone(),
                            )
                            .with_optional_funding_contexts(
                                previous_funding_context_id,
                                Some(observed.funding_context_id.clone()),
                            ),
                        )?;
                    }
                    current_funding_anchor = Some(observed.funding_anchor.clone());
                    current_funding_context_id = Some(observed.funding_context_id.clone());

                    let selected_for_context = latest_package_for_funding_context(
                        &package_records,
                        &observed.funding_context_id,
                    )
                    .or_else(|| {
                        latest_package_for_funding_anchor(
                            &package_records,
                            &observed.funding_anchor,
                        )
                    });
                    let Some(selected_for_context) = selected_for_context else {
                        append_watch_alert_if_requested(
                            &options.alert_file,
                            &options.alert_webhook_url,
                            WatchtowerAlert::new(
                                channel_id.clone(),
                                WatchAlertSeverity::Warning,
                                WatchAlertEvent::SplicePackageStale,
                                format!(
                                    "no saved state package matches confirmed funding anchor {}",
                                    observed.funding_anchor
                                ),
                                selected_state_number,
                                scanned_to_block,
                                current_block.saturating_add(1),
                            )?
                            .with_observed(observed.state_number, observed.out_point.clone())
                            .with_funding_anchors(
                                selected_package.package.funding_anchor.clone(),
                                observed.funding_anchor.clone(),
                            )
                            .with_optional_funding_contexts(
                                state_package_funding_context_id(&selected_package),
                                Some(observed.funding_context_id.clone()),
                            ),
                        )?;
                        last_observed = Some(observed);
                        continue;
                    };

                    if selected_package.package.funding_anchor != observed.funding_anchor
                        && selected_package.package.state_number > observed.state_number
                    {
                        append_watch_alert_if_requested(
                                &options.alert_file,
                                &options.alert_webhook_url,
                                WatchtowerAlert::new(
                                    channel_id.clone(),
                                    WatchAlertSeverity::Warning,
                                    WatchAlertEvent::SplicePackageStale,
                                    format!(
                                        "newest saved state {} belongs to funding anchor {}, while confirmed StateCell uses {}",
                                        selected_package.package.state_number,
                                        selected_package.package.funding_anchor,
                                        observed.funding_anchor
                                    ),
                                    selected_package.package.state_number,
                                    scanned_to_block,
                                    current_block.saturating_add(1),
                                )?
                                .with_observed(observed.state_number, observed.out_point.clone())
                                .with_funding_anchors(
                                    selected_package.package.funding_anchor.clone(),
                                    observed.funding_anchor.clone(),
                                )
                                .with_optional_funding_contexts(
                                    state_package_funding_context_id(&selected_package),
                                    Some(observed.funding_context_id.clone()),
                                ),
                            )?;
                    }

                    let selected_for_context_state_number =
                        selected_for_context.package.state_number;
                    if observed.state_number < selected_for_context_state_number {
                        append_watch_alert_if_requested(
                            &options.alert_file,
                            &options.alert_webhook_url,
                            WatchtowerAlert::new(
                                channel_id.clone(),
                                WatchAlertSeverity::Warning,
                                WatchAlertEvent::OlderStateDetected,
                                format!(
                                    "confirmed StateCell {} is older than saved state {}",
                                    observed.state_number, selected_for_context_state_number
                                ),
                                selected_for_context_state_number,
                                scanned_to_block,
                                current_block.saturating_add(1),
                            )?
                            .with_observed(observed.state_number, observed.out_point.clone())
                            .with_funding_anchors(
                                selected_for_context.package.funding_anchor.clone(),
                                observed.funding_anchor.clone(),
                            )
                            .with_optional_funding_contexts(
                                state_package_funding_context_id(&selected_for_context),
                                Some(observed.funding_context_id.clone()),
                            ),
                        )?;
                        let (sponsor_out_point, sponsor_top_up) = sponsor_for_watch_publication(
                            rpc,
                            &options,
                            &observed,
                            selected_for_context_state_number,
                        )?;
                        let publication_options = PublishStateOptions {
                            contracts_dir: options.contracts_dir.clone(),
                            private_key: options.private_key.clone(),
                            alice_private_key: String::new(),
                            bob_private_key: String::new(),
                            state_out_point: observed.out_point.clone(),
                            sponsor_out_point,
                            state_number: None,
                            state_package: Some(selected_for_context.path.clone()),
                            fee: options.fee,
                            mine_blocks: options.mine_blocks,
                        };
                        let publication = if let Some(profile) = publication_profile.clone() {
                            let current_tip_number = rpc.tip_header()?.number_value()?;
                            let current_confirmations =
                                block_confirmations(observed.block_number, current_tip_number)?;
                            let deadline = publication_deadline(&profile, current_confirmations)?;
                            publish_state_with_publication_runtime(
                                rpc,
                                publication_options,
                                PublicationRuntime {
                                    profile,
                                    attempt_log: options.publication_attempt_log.clone(),
                                    deadline,
                                    intent_id: selected_for_context.package.signing_digest.clone(),
                                    channel_id: channel_id.clone(),
                                    funding_context_id: selected_for_context
                                        .package
                                        .funding_context_id
                                        .clone(),
                                    target_state_number: selected_for_context_state_number,
                                },
                            )?
                        } else {
                            publish_state(rpc, publication_options)?
                        };
                        let publication_event = if splice_detected
                            || selected_for_context.package.funding_anchor
                                != selected_package.package.funding_anchor
                        {
                            WatchAlertEvent::SplicePublicationSubmitted
                        } else {
                            WatchAlertEvent::PublicationSubmitted
                        };
                        append_watch_alert_if_requested(
                            &options.alert_file,
                            &options.alert_webhook_url,
                            WatchtowerAlert::new(
                                channel_id.clone(),
                                WatchAlertSeverity::Warning,
                                publication_event,
                                format!(
                                    "published saved state {} against older StateCell {}",
                                    selected_for_context_state_number, observed.state_number
                                ),
                                selected_for_context_state_number,
                                scanned_to_block,
                                current_block.saturating_add(1),
                            )?
                            .with_observed(observed.state_number, observed.out_point.clone())
                            .with_funding_anchors(
                                selected_for_context.package.funding_anchor.clone(),
                                observed.funding_anchor.clone(),
                            )
                            .with_optional_funding_contexts(
                                state_package_funding_context_id(&selected_for_context),
                                Some(observed.funding_context_id.clone()),
                            )
                            .with_publication(publication.tx_hash.clone()),
                        )?;
                        let next_from_block = current_block.saturating_add(1);
                        write_watch_cursor(
                            &cursor_file,
                            &watch_cursor_for_state(
                                &channel_id,
                                next_from_block,
                                scanned_to_block,
                                scanned_to_block_hash.as_deref(),
                                Some(&observed),
                                cursor_context.as_ref(),
                            )?,
                        )?;
                        return Ok(WatchLatestStatePackageReport {
                            channel_id,
                            operator_id: publication_profile
                                .as_ref()
                                .map(|profile| profile.operator_id.clone()),
                            from_block: options.from_block,
                            effective_from_block,
                            scanned_to_block,
                            next_from_block,
                            detection_depth: options.detection_depth,
                            publication_profile: options.publication_profile.clone(),
                            publication_attempt_log: options.publication_attempt_log.clone(),
                            publication_reconciliation,
                            cursor_file: Some(cursor_file),
                            alert_file: options.alert_file.clone(),
                            alert_webhook_url: options.alert_webhook_url.clone(),
                            loaded_cursor,
                            reorg_recovery,
                            publication_retry_rescan,
                            selected_package: selected_for_context,
                            sponsor_top_up,
                            observed: Some(observed),
                            publication: Some(publication),
                        });
                    }
                    last_observed = Some(observed);
                }
                next_block = current_block.saturating_add(1);
                write_watch_cursor(
                    &cursor_file,
                    &watch_cursor_for_state(
                        &channel_id,
                        next_block,
                        scanned_to_block,
                        scanned_to_block_hash.as_deref(),
                        last_observed.as_ref(),
                        cursor_context.as_ref(),
                    )?,
                )?;
            }
        }

        if started.elapsed() >= timeout {
            write_watch_cursor(
                &cursor_file,
                &watch_cursor_for_state(
                    &channel_id,
                    next_block,
                    scanned_to_block,
                    scanned_to_block_hash.as_deref(),
                    last_observed.as_ref(),
                    cursor_context.as_ref(),
                )?,
            )?;
            append_watch_alert_if_requested(
                &options.alert_file,
                &options.alert_webhook_url,
                WatchtowerAlert::new(
                    channel_id.clone(),
                    WatchAlertSeverity::Info,
                    WatchAlertEvent::ScanIdle,
                    "scan reached timeout without publishing a newer state".to_string(),
                    selected_state_number,
                    scanned_to_block,
                    next_block,
                )?,
            )?;
            return Ok(WatchLatestStatePackageReport {
                channel_id,
                operator_id: publication_profile
                    .as_ref()
                    .map(|profile| profile.operator_id.clone()),
                from_block: options.from_block,
                effective_from_block,
                scanned_to_block,
                next_from_block: next_block,
                detection_depth: options.detection_depth,
                publication_profile: options.publication_profile.clone(),
                publication_attempt_log: options.publication_attempt_log.clone(),
                publication_reconciliation,
                cursor_file: Some(cursor_file),
                alert_file: options.alert_file.clone(),
                alert_webhook_url: options.alert_webhook_url.clone(),
                loaded_cursor,
                reorg_recovery,
                publication_retry_rescan,
                selected_package,
                sponsor_top_up: None,
                observed: last_observed,
                publication: None,
            });
        }
        std::thread::sleep(poll_interval);
    }
}

fn latest_state_package_record(records: &[StatePackageRecord]) -> Option<StatePackageRecord> {
    records
        .iter()
        .cloned()
        .max_by(compare_state_package_records)
}

fn latest_package_for_funding_context(
    records: &[StatePackageRecord],
    funding_context_id: &str,
) -> Option<StatePackageRecord> {
    records
        .iter()
        .filter(|record| {
            record
                .package
                .funding_context_id()
                .is_ok_and(|context_id| context_id == funding_context_id)
        })
        .cloned()
        .max_by(compare_state_package_records)
}

fn state_package_funding_context_id(record: &StatePackageRecord) -> Option<String> {
    record.package.funding_context_id().ok()
}

fn latest_package_for_funding_anchor(
    records: &[StatePackageRecord],
    funding_anchor: &str,
) -> Option<StatePackageRecord> {
    records
        .iter()
        .filter(|record| record.package.funding_anchor == funding_anchor)
        .cloned()
        .max_by(compare_state_package_records)
}

fn cursor_requires_publication_retry(
    rpc: &CkbRpcClient,
    cursor: &WatchCursor,
    records: &[StatePackageRecord],
) -> Result<bool> {
    let Some(observed_state_number) = cursor.last_observed_state_number else {
        return Ok(false);
    };
    let Some(observed_out_point) = cursor.last_observed_out_point.as_deref() else {
        return Ok(false);
    };
    let selected = cursor
        .current_funding_context_id
        .as_deref()
        .and_then(|context_id| latest_package_for_funding_context(records, context_id))
        .or_else(|| {
            cursor
                .current_funding_anchor
                .as_deref()
                .and_then(|anchor| latest_package_for_funding_anchor(records, anchor))
        });
    let Some(selected) = selected else {
        return Ok(false);
    };
    if selected.package.state_number <= observed_state_number {
        return Ok(false);
    }
    let out_point = parse_out_point(observed_out_point).with_context(|| {
        format!("watch cursor contains invalid last_observed_out_point {observed_out_point}")
    })?;
    let canonical = rpc.canonical_live_cell(out_point.into(), false)?;
    Ok(canonical.status == "live")
}

fn compare_state_package_records(
    left: &StatePackageRecord,
    right: &StatePackageRecord,
) -> Ordering {
    left.package
        .state_number
        .cmp(&right.package.state_number)
        .then_with(|| {
            left.package
                .created_unix_ms
                .cmp(&right.package.created_unix_ms)
        })
        .then_with(|| {
            left.package
                .signing_digest
                .cmp(&right.package.signing_digest)
        })
}

fn watch_cursor_for_state(
    channel_id: &str,
    next_block: u64,
    scanned_to_block: u64,
    scanned_to_block_hash: Option<&str>,
    observed: Option<&ObservedStateCellReport>,
    previous_cursor: Option<&WatchCursor>,
) -> Result<WatchCursor> {
    let mut cursor = WatchCursor::new(channel_id, next_block, scanned_to_block)?;
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

fn append_watch_alert_if_requested(
    alert_file: &Option<PathBuf>,
    alert_webhook_url: &Option<String>,
    alert: WatchtowerAlert,
) -> Result<()> {
    if let Some(path) = alert_file {
        append_watchtower_alert(path, &alert)?;
    }
    if let Some(url) = alert_webhook_url {
        let secret = std::env::var("MORPH_WATCHTOWER_WEBHOOK_SECRET").ok();
        post_watchtower_alert_webhook_with_secret(url, &alert, secret.as_deref())?;
    }
    Ok(())
}

fn sponsor_for_watch_publication(
    rpc: &CkbRpcClient,
    options: &WatchLatestStatePackageOptions,
    observed: &ObservedStateCellReport,
    selected_state_number: u64,
) -> Result<(String, Option<FundSponsorReport>)> {
    if let Some(out_point) = &options.sponsor_out_point {
        return Ok((out_point.clone(), None));
    }

    let policy_fee = if let Some(path) = options.publication_profile.as_ref() {
        read_publication_profile(path)?.fee.max_fee
    } else {
        options
            .fee
            .checked_mul(2)
            .ok_or_else(|| anyhow!("fee overflow while building auto sponsor policy"))?
    };
    ensure!(
        policy_fee <= options.auto_sponsor_capacity,
        "auto sponsor capacity must cover the emergency policy budget"
    );
    let sponsor_top_up = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: observed.out_point.clone(),
            sponsor_capacity: options.auto_sponsor_capacity,
            sponsor_min_state_number: selected_state_number,
            sponsor_max_state_number: selected_state_number,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let sponsor_out_point = printable_out_point_string(&sponsor_top_up.sponsor_out_point);
    Ok((sponsor_out_point, Some(sponsor_top_up)))
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
    let state_cell = load_live_cell(rpc, state_out_point)?;
    let header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
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
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let sponsor_contract = contract_by_name(&contracts, "morph-sponsor-lock")?;

    let sponsor_change_lock = if let Some(pubkey) = options.sponsor_change_pubkey.as_deref() {
        let pubkey = parse_compressed_pubkey_hex(pubkey, "sponsor change pubkey")?;
        secp256k1_lock_from_pubkey(&pubkey)?
    } else {
        owner_lock.clone()
    };
    let change_lock_hash = sponsor_change_lock.calc_script_hash();
    let channel_id: &[u8; 32] = header
        .channel_id()
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
        channel_id: hex32(header.channel_id()),
        state_number: header.state_number(),
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

pub fn finalise_channel(
    rpc: &CkbRpcClient,
    options: FinaliseChannelOptions,
) -> Result<FinaliseChannelReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for state refund")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();

    let state_out_point = parse_out_point(&options.state_out_point)?;
    let vault_out_point = parse_out_point(&options.vault_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let vault_cell = load_live_cell(rpc, vault_out_point.clone())?;
    let header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    ensure!(
        header.phase() == PHASE_SETTLING,
        "only a settling state can be finalised"
    );

    let (alice_capacity, bob_capacity) = settlement_split(
        vault_cell.capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    ensure_output_capacity(
        "alice settlement",
        &CellOutput::new_builder()
            .capacity(alice_capacity)
            .lock(alice_lock.clone())
            .build(),
        0,
    )?;
    ensure_output_capacity(
        "bob settlement",
        &CellOutput::new_builder()
            .capacity(bob_capacity)
            .lock(bob_lock.clone())
            .build(),
        0,
    )?;
    let descriptor =
        bilateral_ckb_descriptor(alice_lock_hash, alice_capacity, bob_lock_hash, bob_capacity);
    ensure!(
        settlement_descriptor_commitment(&descriptor).as_slice()
            == header.settlement_descriptor_commitment(),
        "reconstructed settlement descriptor does not match the state commitment"
    );
    ensure!(
        vault_cell_commitment_from_output(&vault_cell.output, vault_cell.data.as_ref()).as_slice()
            == header.vault_materialisation_root(),
        "StateHeader payload commitment does not match the live VaultCell"
    );

    let state_refund_capacity = state_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("state carrier capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, state_refund_capacity)?;

    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;

    let refund_output = CellOutput::new_builder()
        .capacity(state_refund_capacity)
        .lock(owner_lock)
        .build();
    let finalise_since = relative_block_since_arg(options.finalise_since)?;
    mine_relative_since_maturity(rpc, options.finalise_since)?;
    let tx = TransactionBuilder::default()
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(state_contract.cell_dep)
        .cell_dep(vault_contract.cell_dep)
        .input(CellInput::new(state_out_point, finalise_since))
        .input(CellInput::new(vault_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(alice_capacity)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(bob_capacity)
                .lock(bob_lock)
                .build(),
        )
        .output(refund_output.clone())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(Bytes::copy_from_slice(&descriptor)))
        .build();
    let sent_hash = send_and_mine(rpc, tx, options.mine_blocks)?;
    let tx_hash = sent_hash.tx_hash.clone();

    let output_report = |role: &str, index: u32, lock: Script, capacity: u64| ChannelCellReport {
        role: role.to_string(),
        out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        },
        capacity,
        lock_hash: hex32(lock.calc_script_hash().as_slice()),
        type_hash: None,
        data_len: 0,
    };

    Ok(FinaliseChannelReport {
        tx_hash: sent_hash.tx_hash,
        status: sent_hash.status,
        block_number: sent_hash.block_number,
        block_hash: sent_hash.block_hash,
        channel_id: hex32(header.channel_id()),
        funding_anchor: hex32(header.funding_anchor()),
        state_number: header.state_number(),
        alice_capacity,
        bob_capacity,
        state_refund_capacity,
        fee: options.fee,
        metrics: sent_hash.metrics,
        mined_blocks: sent_hash.mined_blocks,
        outputs: vec![
            output_report("alice", 0, secp256k1_lock(&alice_key)?, alice_capacity),
            output_report("bob", 1, secp256k1_lock(&bob_key)?, bob_capacity),
            output_report(
                "state-refund",
                2,
                refund_output.lock(),
                state_refund_capacity,
            ),
        ],
    })
}

pub fn apply_splice(rpc: &CkbRpcClient, options: ApplySpliceOptions) -> Result<ApplySpliceReport> {
    ensure!(options.fee > 0, "fee must be non-zero");

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for splice fee/change")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let package = read_splice_package(&options.splice_package)?;
    let transition = package.validate()?;
    let splice_assets = splice_application_assets(&transition)?;
    let current_state_header = package.current_state_header_bytes()?;
    let mut next_state_header = package.next_state_header_bytes()?;
    let splice_witness = package.contract_witness_bytes()?;
    let participant_withdrawal_target = splice_participant_withdrawal_target(&transition)?;
    let withdrawal_lock_hash: [u8; BYTE32_LEN] = participant_withdrawal_target
        .lock
        .calc_script_hash()
        .unpack();
    if matches!(transition.header.kind, SpliceKind::Out) {
        ensure!(
            transition.header.withdrawal_lock_hash == withdrawal_lock_hash,
            "splice payout lock does not match the signed withdrawal_lock_hash"
        );
    }

    let state_out_point = parse_out_point(&options.state_out_point)?;
    let vault_out_point = parse_out_point(&options.vault_out_point)?;
    if let Some(package_out_point) = &package.current_state_out_point {
        ensure!(
            package_out_point.tx_hash == printable_out_point(&state_out_point).tx_hash
                && package_out_point.index == printable_out_point(&state_out_point).index,
            "splice package current_state_out_point does not match --state-out-point"
        );
    }
    if let Some(package_out_point) = &package.old_vault_out_point {
        ensure!(
            package_out_point.tx_hash == printable_out_point(&vault_out_point).tx_hash
                && package_out_point.index == printable_out_point(&vault_out_point).index,
            "splice package old_vault_out_point does not match --vault-out-point"
        );
    }

    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let vault_cell = load_live_cell(rpc, vault_out_point.clone())?;
    ensure!(
        state_cell.data.as_ref() == current_state_header,
        "splice package current StateHeader bytes do not match the live StateCell"
    );
    let old_header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    ensure!(
        old_header.phase() == PHASE_ACTIVE,
        "splice can only consume an active StateCell"
    );
    ensure_vault_outpoint_binding(
        "--vault-out-point",
        old_header.vault_outpoint_commitment(),
        &vault_out_point,
    )?;

    ensure!(
        vault_cell.capacity == splice_assets.old_vault_capacity,
        "live VaultCell capacity {} does not match old vault descriptor {}",
        vault_cell.capacity,
        splice_assets.old_vault_capacity
    );
    let live_xudt = live_vault_xudt_asset(&vault_cell)?;
    match (&splice_assets.xudt, &live_xudt) {
        (Some(delta), Some(asset)) => {
            ensure!(
                asset.type_hash == delta.type_hash,
                "live VaultCell xUDT type hash does not match splice package"
            );
            ensure!(
                asset.amount == delta.old_amount,
                "live VaultCell xUDT amount {} does not match old vault descriptor {}",
                asset.amount,
                delta.old_amount
            );
        }
        (Some(_), None) => return Err(anyhow!("splice package expects an xUDT VaultCell")),
        (None, Some(asset)) => {
            let old_descriptor_xudt = xudt_vault_amount(&transition.old_vault)?;
            ensure!(
                old_descriptor_xudt == Some((asset.type_hash, asset.amount)),
                "live VaultCell xUDT asset does not match old vault descriptor"
            );
        }
        (None, None) => {}
    }
    let external_xudt_input = if let Some(delta) = &splice_assets.xudt {
        if delta.external_input > 0 {
            let out_point = options
                .xudt_input_out_point
                .as_deref()
                .ok_or_else(|| {
                    anyhow!("--xudt-input-out-point is required for xUDT splice-in packages")
                })
                .and_then(parse_out_point)?;
            let external_cell = load_live_cell(rpc, out_point.clone())?;
            let live_xudt = live_xudt
                .as_ref()
                .ok_or_else(|| anyhow!("xUDT splice package requires a live xUDT VaultCell"))?;
            ensure!(
                external_cell.output.lock() == owner_lock,
                "external xUDT input must be locked by the splice owner key"
            );
            let external_type = external_cell
                .output
                .type_()
                .to_opt()
                .ok_or_else(|| anyhow!("external xUDT input does not carry a type script"))?;
            ensure!(
                external_type == live_xudt.type_script,
                "external xUDT input type does not match the live VaultCell type"
            );
            ensure!(
                xudt_amount_from_data(&external_cell.data)? == delta.external_input,
                "external xUDT input amount does not match the signed splice delta"
            );
            Some((out_point, external_cell))
        } else {
            ensure!(
                options.xudt_input_out_point.is_none(),
                "--xudt-input-out-point is only used for xUDT splice-in packages"
            );
            None
        }
    } else {
        ensure!(
            options.xudt_input_out_point.is_none(),
            "--xudt-input-out-point requires an xUDT splice package"
        );
        None
    };

    let tip_number = rpc.tip_header()?.number_value()?;
    let fee_cell = find_largest_live_cell(rpc, &owner_lock, tip_number)?;
    let secp_dep = find_secp256k1_cell_dep(rpc)?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let xudt_contract = if live_xudt.is_some() {
        Some(contract_by_name(&contracts, "morph-devnet-xudt")?)
    } else {
        None
    };

    let old_state_type = state_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("StateCell does not carry a type script"))?;
    ensure!(
        byte32_to_h256(old_state_type.code_hash()) == state_contract.data_hash,
        "StateCell type script does not use deployed morph-state-type"
    );
    let old_state_args = old_state_type.args().raw_data();
    ensure!(
        old_state_args.len() >= BYTE32_LEN
            && old_state_args.as_ref()[..BYTE32_LEN] == transition.header.old_funding_anchor,
        "StateCell type args do not match splice old funding anchor"
    );
    let mut new_state_args = transition.header.new_funding_anchor.to_vec();
    new_state_args.extend_from_slice(&old_state_args.as_ref()[BYTE32_LEN..]);
    let new_state_type = data1_script(
        state_contract.data_hash.clone(),
        Bytes::from(new_state_args),
    );
    let new_state_lock = data1_script(
        state_lock_contract.data_hash.clone(),
        Bytes::copy_from_slice(new_state_type.calc_script_hash().as_slice()),
    );
    let funding_state_capacity = state_cell
        .capacity
        .checked_add(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("post-splice StateCell activation capacity overflow"))?;
    let funding_state_output = CellOutput::new_builder()
        .capacity(funding_state_capacity)
        .lock(new_state_lock)
        .type_(Some(new_state_type).pack())
        .build();
    ensure_output_capacity(
        "post-splice state",
        &funding_state_output,
        next_state_header.len(),
    )?;

    let old_vault_lock = vault_cell.output.lock();
    ensure!(
        byte32_to_h256(old_vault_lock.code_hash()) == vault_contract.data_hash,
        "VaultCell lock does not use deployed morph-vault-lock"
    );
    let old_vault_args = old_vault_lock.args().raw_data();
    ensure!(
        old_vault_args.len() >= BYTE32_LEN
            && old_vault_args.as_ref()[..BYTE32_LEN] == transition.header.old_funding_anchor,
        "VaultCell lock args do not match splice old funding anchor"
    );
    let mut new_vault_args = transition.header.new_funding_anchor.to_vec();
    new_vault_args.extend_from_slice(&old_vault_args.as_ref()[BYTE32_LEN..]);
    let new_vault_lock = data1_script(
        vault_contract.data_hash.clone(),
        Bytes::from(new_vault_args),
    );
    let mut new_vault_builder = CellOutput::new_builder()
        .capacity(splice_assets.new_vault_capacity)
        .lock(new_vault_lock);
    let new_vault_data = if let Some(live_xudt) = &live_xudt {
        if let Some(xudt_contract) = &xudt_contract {
            ensure!(
                byte32_to_h256(live_xudt.type_script.code_hash()) == xudt_contract.data_hash,
                "VaultCell xUDT type script does not use deployed morph-devnet-xudt"
            );
        }
        let expected_amount = splice_assets
            .xudt
            .as_ref()
            .map(|delta| delta.new_amount)
            .unwrap_or(live_xudt.amount);
        new_vault_builder = new_vault_builder.type_(Some(live_xudt.type_script.clone()).pack());
        xudt_amount_bytes(expected_amount)
    } else {
        Bytes::new()
    };
    let new_vault_output = new_vault_builder.build();
    ensure_output_capacity("post-splice vault", &new_vault_output, new_vault_data.len())?;
    set_state_vault_materialisation_root(
        &mut next_state_header,
        vault_cell_commitment_from_output(&new_vault_output, new_vault_data.as_ref()),
    );

    let signed_fee = splice_assets
        .ckb_delta
        .as_ref()
        .map(|delta| delta.signed_fee)
        .unwrap_or_default();
    ensure!(
        options.fee >= signed_fee,
        "transaction fee {} is below signed splice fee {}",
        options.fee,
        signed_fee
    );

    let mut builder = TransactionBuilder::default()
        .cell_dep(secp_dep)
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .cell_dep(vault_contract.cell_dep);
    if let Some(xudt_contract) = &xudt_contract {
        builder = builder.cell_dep(xudt_contract.cell_dep.clone());
    }
    builder = builder
        .input(CellInput::new(state_out_point, 0))
        .input(CellInput::new(vault_out_point, 0))
        .input(CellInput::new(fee_cell.out_point.clone(), 0));
    if let Some((out_point, _)) = &external_xudt_input {
        builder = builder.input(CellInput::new(out_point.clone(), 0));
    }
    builder = builder
        .output(funding_state_output.clone())
        .output(new_vault_output.clone())
        .output_data(Bytes::copy_from_slice(&next_state_header).pack())
        .output_data(new_vault_data.pack());

    let mut withdrawal_out_point = None;
    let mut withdrawal_output_capacity = 0u64;
    if splice_assets.ckb_withdrawal > 0 {
        let withdrawal_output = CellOutput::new_builder()
            .capacity(splice_assets.ckb_withdrawal)
            .lock(participant_withdrawal_target.lock.clone())
            .build();
        ensure_output_capacity("splice withdrawal", &withdrawal_output, 0)?;
        withdrawal_output_capacity = withdrawal_output_capacity
            .checked_add(splice_assets.ckb_withdrawal)
            .ok_or_else(|| anyhow!("splice withdrawal capacity overflow"))?;
        builder = builder
            .output(withdrawal_output)
            .output_data(Bytes::new().pack());
        withdrawal_out_point = Some(2u32);
    }
    if let Some(xudt_delta) = &splice_assets.xudt {
        let live_xudt = live_xudt
            .as_ref()
            .ok_or_else(|| anyhow!("xUDT splice package requires a live xUDT VaultCell"))?;
        if xudt_delta.withdrawal > 0 {
            let withdrawal_output_for_capacity = CellOutput::new_builder()
                .lock(participant_withdrawal_target.lock.clone())
                .type_(Some(live_xudt.type_script.clone()).pack())
                .build();
            let withdrawal_capacity = occupied_capacity(&withdrawal_output_for_capacity, 16)?;
            let withdrawal_output = CellOutput::new_builder()
                .capacity(withdrawal_capacity)
                .lock(participant_withdrawal_target.lock.clone())
                .type_(Some(live_xudt.type_script.clone()).pack())
                .build();
            ensure_output_capacity("xUDT splice withdrawal", &withdrawal_output, 16)?;
            withdrawal_output_capacity = withdrawal_output_capacity
                .checked_add(withdrawal_capacity)
                .ok_or_else(|| anyhow!("splice withdrawal capacity overflow"))?;
            builder = builder
                .output(withdrawal_output)
                .output_data(xudt_amount_bytes(xudt_delta.withdrawal).pack());
            withdrawal_out_point = Some(2u32);
        }
    }

    let required_output_delta = splice_assets
        .new_vault_capacity
        .checked_add(withdrawal_output_capacity)
        .and_then(|value| value.checked_sub(splice_assets.old_vault_capacity))
        .ok_or_else(|| anyhow!("splice package would create excess input capacity"))?;
    if let Some(ckb_delta) = &splice_assets.ckb_delta {
        let expected_delta = ckb_delta
            .external_input
            .checked_sub(ckb_delta.signed_fee)
            .ok_or_else(|| anyhow!("signed CKB splice fee exceeds external input"))?;
        ensure!(
            required_output_delta == expected_delta,
            "CKB splice package capacity delta {} does not match signed external delta {}",
            required_output_delta,
            expected_delta
        );
    }
    let external_input_capacity = external_xudt_input
        .as_ref()
        .map(|(_, cell)| cell.capacity)
        .unwrap_or_default();
    let fee_change_capacity = fee_cell
        .capacity
        .checked_add(external_input_capacity)
        .ok_or_else(|| anyhow!("fee and external input capacity overflow"))?
        .checked_sub(required_output_delta)
        .and_then(|value| value.checked_sub(STATE_CARRIER_ACTIVATION_FEE))
        .and_then(|value| value.checked_sub(options.fee))
        .ok_or_else(|| {
            anyhow!(
                "fee cell capacity {} plus external input capacity {} cannot cover splice output capacity delta {} and fee {}",
                fee_cell.capacity,
                external_input_capacity,
                required_output_delta,
                options.fee
            )
        })?;
    ensure_change_capacity(&owner_lock, fee_change_capacity)?;
    let fee_change_output = CellOutput::new_builder()
        .capacity(fee_change_capacity)
        .lock(owner_lock.clone())
        .build();

    let unsigned = builder
        .output(fee_change_output)
        .output_data(Bytes::new().pack())
        .build();
    let signed = sign_splice_transaction(
        unsigned,
        &owner_key,
        Bytes::from(splice_witness.clone()),
        usize::from(external_xudt_input.is_some()),
    )?;
    let sent = send_and_mine(rpc, signed, options.mine_blocks)?;
    let tx_hash = sent.tx_hash.clone();
    let (activation, _, _) = activate_state_vault_binding(
        rpc,
        &sent.tx_hash,
        &funding_state_output,
        next_state_header
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("post-splice StateHeader has an invalid length"))?,
        &state_lock_contract,
        &state_contract,
        0,
        1,
        options.mine_blocks,
    )?;
    let activation_tx_hash = activation.tx_hash.clone();

    Ok(ApplySpliceReport {
        tx_hash: sent.tx_hash.clone(),
        status: sent.status,
        block_number: sent.block_number,
        block_hash: sent.block_hash,
        channel_id: hex32(&transition.header.channel_id),
        old_funding_anchor: hex32(&transition.header.old_funding_anchor),
        new_funding_anchor: hex32(&transition.header.new_funding_anchor),
        old_funding_epoch: transition.header.old_funding_epoch,
        new_funding_epoch: transition.header.new_funding_epoch,
        splice_number: transition.header.splice_number,
        old_state_number: old_header.state_number(),
        new_state_number: old_header.state_number(),
        state_out_point: PrintableOutPoint {
            tx_hash: activation_tx_hash.clone(),
            index: 0,
        },
        vault_out_point: PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index: 1,
        },
        withdrawal_out_point: withdrawal_out_point.map(|index| PrintableOutPoint {
            tx_hash: tx_hash.clone(),
            index,
        }),
        withdrawal_payout_policy: if transition.withdrawals.is_empty() {
            "none".to_string()
        } else {
            "participant_signature_pubkey".to_string()
        },
        withdrawal_participant_pubkey_sec1: if transition.withdrawals.is_empty() {
            None
        } else {
            Some(hex_prefixed(&participant_withdrawal_target.pubkey_sec1))
        },
        withdrawal_lock_hash: if transition.withdrawals.is_empty() {
            None
        } else {
            Some(hex32(
                participant_withdrawal_target
                    .lock
                    .calc_script_hash()
                    .as_slice(),
            ))
        },
        fee_change_capacity,
        fee: options.fee,
        splice_package: options.splice_package.display().to_string(),
        contract_witness_len: splice_witness.len(),
        metrics: sent.metrics,
        mined_blocks: sent.mined_blocks,
        activation_tx_hash,
        activation_status: activation.status,
        activation_block_number: activation.block_number,
        activation_block_hash: activation.block_hash,
        activation_fee: STATE_CARRIER_ACTIVATION_FEE,
        activation_metrics: activation.metrics,
        activation_mined_blocks: activation.mined_blocks,
    })
}

pub fn splice_smoke(rpc: &CkbRpcClient, options: SpliceSmokeOptions) -> Result<SpliceSmokeReport> {
    ensure!(options.splice_amount > 0, "splice amount must be non-zero");
    let sponsor_policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building post-splice sponsor policy"))?;
    ensure!(
        sponsor_policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the post-splice policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(sponsor_policy_fee),
            sponsor_max_total_fee: Some(sponsor_policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let initial_vault_out_point = channel_cell_out_point(&open, "vault")?;

    let package = save_splice_package(
        rpc,
        SaveSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            vault_out_point: initial_vault_out_point.clone(),
            kind: options.kind,
            asset: DevnetSpliceAsset::Ckb,
            ckb_amount: options.splice_amount,
            xudt_amount: None,
            signed_fee: 0,
            old_funding_epoch: 0,
            new_funding_epoch: Some(1),
            splice_number: Some(1),
            store_dir: options.store_dir,
        },
    )?;

    let apply = apply_splice(
        rpc,
        ApplySpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: initial_state_out_point,
            vault_out_point: initial_vault_out_point,
            splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let post_splice_state_out_point = printable_out_point_string(&apply.state_out_point);

    let post_splice_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: post_splice_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(sponsor_policy_fee),
            sponsor_max_total_fee: Some(sponsor_policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let post_splice_sponsor_out_point =
        printable_out_point_string(&post_splice_sponsor.sponsor_out_point);

    let (initial_alice_capacity, initial_bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    let (post_alice_capacity, post_bob_capacity) = proportional_capacity_split(
        package.new_vault_capacity,
        initial_alice_capacity,
        initial_bob_capacity,
    )?;
    ensure!(
        post_alice_capacity.checked_add(post_bob_capacity) == Some(package.new_vault_capacity),
        "post-splice settlement split does not match new vault capacity"
    );
    let descriptor_update = SettlementDescriptorUpdate {
        alice_capacity: post_alice_capacity,
        bob_capacity: post_bob_capacity,
        xudt: None,
    };

    let publish = publish_state_with_descriptor_update(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: post_splice_state_out_point.clone(),
            sponsor_out_point: post_splice_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
        Some(&descriptor_update),
    )?;
    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: printable_out_point_string(&publish.state_out_point),
            vault_out_point: printable_out_point_string(&apply.vault_out_point),
            alice_capacity: Some(post_alice_capacity),
            bob_capacity: Some(post_bob_capacity),
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SpliceSmokeReport {
        kind: match options.kind {
            DevnetSpliceKind::SpliceIn => "splice_in",
            DevnetSpliceKind::SpliceOut => "splice_out",
        }
        .to_string(),
        open,
        external_xudt: None,
        package,
        apply,
        post_splice_sponsor,
        publish,
        finalise: Some(finalise),
        xudt_finalise: None,
    })
}

pub fn xudt_splice_in_smoke(
    rpc: &CkbRpcClient,
    options: XudtSpliceSmokeOptions,
) -> Result<SpliceSmokeReport> {
    ensure!(
        options.splice_xudt_amount > 0,
        "splice xUDT amount must be non-zero"
    );
    options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    let sponsor_policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building post-splice sponsor policy"))?;
    ensure!(
        sponsor_policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the post-splice policy budget"
    );

    let xudt_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir.clone(),
        private_key: options.private_key.clone(),
        alice_private_key: options.alice_private_key.clone(),
        bob_private_key: options.bob_private_key.clone(),
        vault_capacity: options.vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let open = open_xudt_channel(rpc, &xudt_options)?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let initial_vault_out_point = channel_cell_out_point(&open, "xudt-vault")?;

    let external_xudt = mint_owner_xudt_cell(
        rpc,
        &options.contracts_dir,
        &options.private_key,
        options.splice_xudt_amount,
        options.fee,
        options.mine_blocks,
    )?;
    let external_xudt_out_point = printable_out_point_string(&external_xudt.cell_out_point);

    let package = save_splice_package(
        rpc,
        SaveSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            vault_out_point: initial_vault_out_point.clone(),
            kind: DevnetSpliceKind::SpliceIn,
            asset: DevnetSpliceAsset::Xudt,
            ckb_amount: 0,
            xudt_amount: Some(options.splice_xudt_amount),
            signed_fee: 0,
            old_funding_epoch: 0,
            new_funding_epoch: Some(1),
            splice_number: Some(1),
            store_dir: options.store_dir,
        },
    )?;

    let apply = apply_splice(
        rpc,
        ApplySpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: initial_state_out_point,
            vault_out_point: initial_vault_out_point,
            splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: Some(external_xudt_out_point),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let post_splice_state_out_point = printable_out_point_string(&apply.state_out_point);

    let post_splice_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: post_splice_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(sponsor_policy_fee),
            sponsor_max_total_fee: Some(sponsor_policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let post_splice_sponsor_out_point =
        printable_out_point_string(&post_splice_sponsor.sponsor_out_point);

    let (post_alice_capacity, post_bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    let post_xudt_amount = package
        .new_xudt_amount
        .ok_or_else(|| anyhow!("xUDT splice package report is missing new_xudt_amount"))?;
    let (post_alice_xudt_amount, post_bob_xudt_amount) = proportional_xudt_split(
        post_xudt_amount,
        options.alice_xudt_amount,
        options.bob_xudt_amount,
    )?;
    ensure!(
        post_alice_xudt_amount.checked_add(post_bob_xudt_amount) == Some(post_xudt_amount),
        "post-splice xUDT settlement split does not match new vault amount"
    );
    let xudt_type_hash = parse_hex32_array(
        "xudt_type_hash",
        package
            .xudt_type_hash
            .as_deref()
            .ok_or_else(|| anyhow!("xUDT splice package report is missing xudt_type_hash"))?,
    )?;
    let descriptor_update = SettlementDescriptorUpdate {
        alice_capacity: post_alice_capacity,
        bob_capacity: post_bob_capacity,
        xudt: Some(SettlementXudtUpdate {
            type_hash: xudt_type_hash,
            alice_amount: post_alice_xudt_amount,
            bob_amount: post_bob_xudt_amount,
        }),
    };

    let publish = publish_state_with_descriptor_update(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: post_splice_state_out_point.clone(),
            sponsor_out_point: post_splice_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
        Some(&descriptor_update),
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.vault_capacity,
        alice_capacity: Some(post_alice_capacity),
        bob_capacity: Some(post_bob_capacity),
        alice_xudt_amount: post_alice_xudt_amount,
        bob_xudt_amount: post_bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let xudt_finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&apply.vault_out_point),
    )?;

    Ok(SpliceSmokeReport {
        kind: "xudt_splice_in".to_string(),
        open,
        external_xudt: Some(external_xudt),
        package,
        apply,
        post_splice_sponsor,
        publish,
        finalise: None,
        xudt_finalise: Some(xudt_finalise),
    })
}

pub fn xudt_splice_out_smoke(
    rpc: &CkbRpcClient,
    options: XudtSpliceSmokeOptions,
) -> Result<SpliceSmokeReport> {
    ensure!(
        options.splice_xudt_amount > 0,
        "splice xUDT amount must be non-zero"
    );
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    ensure!(
        options.splice_xudt_amount < total_xudt_amount,
        "splice xUDT amount must be below the live vault amount {}",
        total_xudt_amount
    );
    let sponsor_policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building post-splice sponsor policy"))?;
    ensure!(
        sponsor_policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the post-splice policy budget"
    );

    let xudt_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir.clone(),
        private_key: options.private_key.clone(),
        alice_private_key: options.alice_private_key.clone(),
        bob_private_key: options.bob_private_key.clone(),
        vault_capacity: options.vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let open = open_xudt_channel(rpc, &xudt_options)?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let initial_vault_out_point = channel_cell_out_point(&open, "xudt-vault")?;

    let package = save_splice_package(
        rpc,
        SaveSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            vault_out_point: initial_vault_out_point.clone(),
            kind: DevnetSpliceKind::SpliceOut,
            asset: DevnetSpliceAsset::Xudt,
            ckb_amount: 0,
            xudt_amount: Some(options.splice_xudt_amount),
            signed_fee: 0,
            old_funding_epoch: 0,
            new_funding_epoch: Some(1),
            splice_number: Some(1),
            store_dir: options.store_dir,
        },
    )?;

    let apply = apply_splice(
        rpc,
        ApplySpliceOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            state_out_point: initial_state_out_point,
            vault_out_point: initial_vault_out_point,
            splice_package: PathBuf::from(&package.path),
            xudt_input_out_point: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let post_splice_state_out_point = printable_out_point_string(&apply.state_out_point);

    let post_splice_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: post_splice_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(sponsor_policy_fee),
            sponsor_max_total_fee: Some(sponsor_policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let post_splice_sponsor_out_point =
        printable_out_point_string(&post_splice_sponsor.sponsor_out_point);

    let (post_alice_capacity, post_bob_capacity) = settlement_split(
        options.vault_capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    let post_xudt_amount = package
        .new_xudt_amount
        .ok_or_else(|| anyhow!("xUDT splice package report is missing new_xudt_amount"))?;
    let (post_alice_xudt_amount, post_bob_xudt_amount) = proportional_xudt_split(
        post_xudt_amount,
        options.alice_xudt_amount,
        options.bob_xudt_amount,
    )?;
    ensure!(
        post_alice_xudt_amount.checked_add(post_bob_xudt_amount) == Some(post_xudt_amount),
        "post-splice xUDT settlement split does not match new vault amount"
    );
    let xudt_type_hash = parse_hex32_array(
        "xudt_type_hash",
        package
            .xudt_type_hash
            .as_deref()
            .ok_or_else(|| anyhow!("xUDT splice package report is missing xudt_type_hash"))?,
    )?;
    let descriptor_update = SettlementDescriptorUpdate {
        alice_capacity: post_alice_capacity,
        bob_capacity: post_bob_capacity,
        xudt: Some(SettlementXudtUpdate {
            type_hash: xudt_type_hash,
            alice_amount: post_alice_xudt_amount,
            bob_amount: post_bob_xudt_amount,
        }),
    };

    let publish = publish_state_with_descriptor_update(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: post_splice_state_out_point.clone(),
            sponsor_out_point: post_splice_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
        Some(&descriptor_update),
    )?;
    let finalise_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.vault_capacity,
        alice_capacity: Some(post_alice_capacity),
        bob_capacity: Some(post_bob_capacity),
        alice_xudt_amount: post_alice_xudt_amount,
        bob_xudt_amount: post_bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let xudt_finalise = finalise_xudt_channel(
        rpc,
        &finalise_options,
        printable_out_point_string(&publish.state_out_point),
        printable_out_point_string(&apply.vault_out_point),
    )?;

    Ok(SpliceSmokeReport {
        kind: "xudt_splice_out".to_string(),
        open,
        external_xudt: None,
        package,
        apply,
        post_splice_sponsor,
        publish,
        finalise: None,
        xudt_finalise: Some(xudt_finalise),
    })
}

pub fn splice_negative_smoke(
    rpc: &CkbRpcClient,
    options: SpliceNegativeSmokeOptions,
) -> Result<SpliceNegativeSmokeReport> {
    ensure!(options.splice_amount > 0, "splice amount must be non-zero");
    ensure!(
        options.splice_amount < options.vault_capacity,
        "splice amount must be below the live vault capacity {}",
        options.vault_capacity
    );
    ensure!(
        options.splice_xudt_amount > 0,
        "splice xUDT amount must be non-zero"
    );
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    ensure!(
        options.splice_xudt_amount < total_xudt_amount,
        "splice xUDT amount must be below the live xUDT amount {}",
        total_xudt_amount
    );
    let rejected_signed_fee = options
        .fee
        .checked_add(1)
        .ok_or_else(|| anyhow!("fee overflow while building signed-fee negative splice"))?;

    let ckb_open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(options.fee),
            sponsor_max_total_fee: Some(options.fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let ckb_state_out_point = channel_cell_out_point(&ckb_open, "state")?;
    let ckb_vault_out_point = channel_cell_out_point(&ckb_open, "vault")?;

    let ckb_package = save_splice_package(
        rpc,
        SaveSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: ckb_state_out_point.clone(),
            vault_out_point: ckb_vault_out_point.clone(),
            kind: DevnetSpliceKind::SpliceOut,
            asset: DevnetSpliceAsset::Ckb,
            ckb_amount: options.splice_amount,
            xudt_amount: None,
            signed_fee: 0,
            old_funding_epoch: 0,
            new_funding_epoch: Some(1),
            splice_number: Some(1),
            store_dir: options.store_dir.clone(),
        },
    )?;
    let signed_fee_package = save_splice_package(
        rpc,
        SaveSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: ckb_state_out_point.clone(),
            vault_out_point: ckb_vault_out_point.clone(),
            kind: DevnetSpliceKind::SpliceIn,
            asset: DevnetSpliceAsset::Ckb,
            ckb_amount: options.splice_amount,
            xudt_amount: None,
            signed_fee: rejected_signed_fee,
            old_funding_epoch: 0,
            new_funding_epoch: Some(2),
            splice_number: Some(2),
            store_dir: options.store_dir.clone(),
        },
    )?;

    let xudt_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir.clone(),
        private_key: options.private_key.clone(),
        alice_private_key: options.alice_private_key.clone(),
        bob_private_key: options.bob_private_key.clone(),
        vault_capacity: options.vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };
    let xudt_open = open_xudt_channel(rpc, &xudt_options)?;
    let xudt_state_out_point = channel_cell_out_point(&xudt_open, "state")?;
    let xudt_vault_out_point = channel_cell_out_point(&xudt_open, "xudt-vault")?;
    let xudt_package = save_splice_package(
        rpc,
        SaveSplicePackageOptions {
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: xudt_state_out_point,
            vault_out_point: xudt_vault_out_point.clone(),
            kind: DevnetSpliceKind::SpliceOut,
            asset: DevnetSpliceAsset::Xudt,
            ckb_amount: 0,
            xudt_amount: Some(options.splice_xudt_amount),
            signed_fee: 0,
            old_funding_epoch: 0,
            new_funding_epoch: Some(1),
            splice_number: Some(1),
            store_dir: options.store_dir.clone(),
        },
    )?;

    let mut rejections = Vec::new();

    let mut stale_epoch = ckb_package.package.validate()?;
    stale_epoch.header.new_funding_epoch = stale_epoch.header.old_funding_epoch;
    rejections.push(expect_splice_apply_rejection(
        rpc,
        &options,
        SpliceApplyRejectionCheck {
            case: "stale_funding_epoch",
            stage: "package_validation",
            package: negative_splice_package_from_transition(
                &stale_epoch,
                &ckb_package.package,
                &options,
            )?,
            state_out_point: &ckb_state_out_point,
            vault_out_point: &ckb_vault_out_point,
            xudt_input_out_point: None,
            fee: options.fee,
            expected: "splice funding epoch must advance",
        },
    )?);

    let mut wrong_channel = ckb_package.package.validate()?;
    wrong_channel.header.channel_id = [99u8; BYTE32_LEN];
    rejections.push(expect_splice_apply_rejection(
        rpc,
        &options,
        SpliceApplyRejectionCheck {
            case: "wrong_channel_id",
            stage: "package_validation",
            package: negative_splice_package_from_transition(
                &wrong_channel,
                &ckb_package.package,
                &options,
            )?,
            state_out_point: &ckb_state_out_point,
            vault_out_point: &ckb_vault_out_point,
            xudt_input_out_point: None,
            fee: options.fee,
            expected: "splice header does not match",
        },
    )?);

    let mut shortfall = ckb_package.package.validate()?;
    let ckb_remaining = shortfall
        .remaining_settlement
        .iter_mut()
        .find(|amount| amount.asset == VaultAsset::Ckb)
        .ok_or_else(|| anyhow!("CKB splice package is missing remaining CKB settlement"))?;
    ckb_remaining.amount = shortfall
        .new_vault
        .assets
        .iter()
        .find(|amount| amount.asset == VaultAsset::Ckb)
        .ok_or_else(|| anyhow!("CKB splice package is missing new CKB vault amount"))?
        .amount
        .checked_add(1)
        .ok_or_else(|| anyhow!("remaining settlement overflow"))?;
    rejections.push(expect_splice_apply_rejection(
        rpc,
        &options,
        SpliceApplyRejectionCheck {
            case: "insufficient_remaining_vault_value",
            stage: "package_validation",
            package: negative_splice_package_from_transition(
                &shortfall,
                &ckb_package.package,
                &options,
            )?,
            state_out_point: &ckb_state_out_point,
            vault_out_point: &ckb_vault_out_point,
            xudt_input_out_point: None,
            fee: options.fee,
            expected: "post-splice vault does not cover",
        },
    )?);

    let mut tampered_xudt = xudt_package.package.validate()?;
    let xudt_delta = tampered_xudt
        .deltas
        .iter_mut()
        .find(|delta| matches!(delta.asset, VaultAsset::Xudt(_)))
        .ok_or_else(|| anyhow!("xUDT splice package is missing an xUDT delta"))?;
    xudt_delta.new_amount = xudt_delta
        .new_amount
        .checked_add(1)
        .ok_or_else(|| anyhow!("xUDT delta overflow"))?;
    tampered_xudt.header.asset_delta_commitment =
        splice_asset_delta_commitment(&tampered_xudt.deltas);
    rejections.push(expect_splice_apply_rejection(
        rpc,
        &options,
        SpliceApplyRejectionCheck {
            case: "tampered_xudt_amount",
            stage: "package_validation",
            package: negative_splice_package_from_transition(
                &tampered_xudt,
                &xudt_package.package,
                &options,
            )?,
            state_out_point: &ckb_state_out_point,
            vault_out_point: &ckb_vault_out_point,
            xudt_input_out_point: None,
            fee: options.fee,
            expected: "splice vault descriptor does not match",
        },
    )?);

    let mut wrong_vault_outpoint = ckb_package.package.clone();
    wrong_vault_outpoint.old_vault_out_point = None;
    rejections.push(expect_splice_apply_rejection(
        rpc,
        &options,
        SpliceApplyRejectionCheck {
            case: "wrong_vault_outpoint",
            stage: "apply_preflight",
            package: wrong_vault_outpoint,
            state_out_point: &ckb_state_out_point,
            vault_out_point: &xudt_vault_out_point,
            xudt_input_out_point: None,
            fee: options.fee,
            expected: "does not match the exact VaultCell OutPoint",
        },
    )?);

    rejections.push(expect_splice_apply_rejection(
        rpc,
        &options,
        SpliceApplyRejectionCheck {
            case: "sponsor_fee_leakage",
            stage: "apply_preflight",
            package: signed_fee_package.package.clone(),
            state_out_point: &ckb_state_out_point,
            vault_out_point: &ckb_vault_out_point,
            xudt_input_out_point: None,
            fee: options.fee,
            expected: "below signed splice fee",
        },
    )?);

    Ok(SpliceNegativeSmokeReport {
        ckb_open,
        xudt_open,
        ckb_package,
        xudt_package,
        signed_fee_package,
        rejections,
    })
}

fn negative_splice_package_from_transition(
    transition: &SpliceTransition,
    template: &StoredSplicePackage,
    options: &SpliceNegativeSmokeOptions,
) -> Result<StoredSplicePackage> {
    let mut transition = transition.clone();
    transition.witness = splice_witness_from_keys(
        &transition.header,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    StoredSplicePackage::from_transition_unchecked(
        &transition,
        template.current_state_out_point.clone(),
        template.old_vault_out_point.clone(),
        template.sponsor_policy_hint.clone(),
    )
}

struct SpliceApplyRejectionCheck<'a> {
    case: &'a str,
    stage: &'a str,
    package: StoredSplicePackage,
    state_out_point: &'a str,
    vault_out_point: &'a str,
    xudt_input_out_point: Option<String>,
    fee: u64,
    expected: &'a str,
}

fn expect_splice_apply_rejection(
    rpc: &CkbRpcClient,
    options: &SpliceNegativeSmokeOptions,
    check: SpliceApplyRejectionCheck<'_>,
) -> Result<SpliceNegativeCaseReport> {
    let rejected_package =
        write_negative_splice_package(&options.store_dir, check.case, &check.package)?;
    let rejection = if check.stage == "package_validation" {
        match check.package.validate() {
            Ok(_) => {
                return Err(anyhow!(
                    "splice negative case {} unexpectedly passed package validation",
                    check.case
                ));
            }
            Err(err) => format!("{err:#}"),
        }
    } else {
        match apply_splice(
            rpc,
            ApplySpliceOptions {
                contracts_dir: options.contracts_dir.clone(),
                private_key: options.private_key.clone(),
                state_out_point: check.state_out_point.to_string(),
                vault_out_point: check.vault_out_point.to_string(),
                splice_package: rejected_package.clone(),
                xudt_input_out_point: check.xudt_input_out_point,
                fee: check.fee,
                mine_blocks: 0,
            },
        ) {
            Ok(report) => {
                return Err(anyhow!(
                    "splice negative case {} was unexpectedly accepted in tx {}",
                    check.case,
                    report.tx_hash
                ));
            }
            Err(err) => format!("{err:#}"),
        }
    };
    ensure!(
        rejection.contains(check.expected),
        "splice negative case {} expected rejection containing {:?}, got: {}",
        check.case,
        check.expected,
        rejection
    );
    Ok(SpliceNegativeCaseReport {
        case: check.case.to_string(),
        stage: check.stage.to_string(),
        rejected_package: rejected_package.display().to_string(),
        rejection,
    })
}

fn write_negative_splice_package(
    dir: &Path,
    case: &str,
    package: &StoredSplicePackage,
) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| {
        format!(
            "failed to create splice negative package directory {}",
            dir.display()
        )
    })?;
    let path = dir.join(format!("splice-negative-{case}.json"));
    let tmp = crate::packages::atomic_json_tmp_path(&path);
    let json = serde_json::to_vec_pretty(package)?;
    fs::write(&tmp, json).with_context(|| {
        format!(
            "failed to write temporary splice negative package {}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, &path).with_context(|| {
        format!(
            "failed to atomically move splice negative package {} to {}",
            tmp.display(),
            path.display()
        )
    })?;
    Ok(path)
}

fn finalise_xudt_channel(
    rpc: &CkbRpcClient,
    options: &XudtSmokeOptions,
    state_out_point: String,
    vault_out_point: String,
) -> Result<XudtFinaliseReport> {
    let build = build_xudt_finalise_transaction(
        rpc,
        options,
        state_out_point,
        vault_out_point,
        (options.alice_xudt_amount, options.bob_xudt_amount),
    )?;
    mine_relative_since_maturity(rpc, options.finalise_since)?;
    let sent = send_and_mine(rpc, build.tx.clone(), options.mine_blocks)?;
    Ok(xudt_finalise_report(build, sent))
}

struct SpliceParticipantWithdrawalTarget {
    pubkey_sec1: Vec<u8>,
    lock: Script,
}

fn splice_participant_withdrawal_target(
    transition: &SpliceTransition,
) -> Result<SpliceParticipantWithdrawalTarget> {
    let signature = transition
        .witness
        .signatures
        .first()
        .ok_or_else(|| anyhow!("splice witness does not contain a participant payout key"))?;
    ensure!(
        signature.pubkey_sec1.len() == COMPRESSED_SECP256K1_PUBKEY_LEN,
        "splice participant payout key must be compressed secp256k1"
    );
    let lock = secp256k1_lock_from_pubkey(&signature.pubkey_sec1)?;
    Ok(SpliceParticipantWithdrawalTarget {
        pubkey_sec1: signature.pubkey_sec1.clone(),
        lock,
    })
}

fn factory_splice_participant_withdrawal_target(
    package: &StoredFactorySplicePackage,
    transition: &FactorySpliceTransition,
) -> Result<SpliceParticipantWithdrawalTarget> {
    let participant = transition
        .update
        .touched_participants
        .iter()
        .next()
        .ok_or_else(|| anyhow!("factory splice package has no touched participant"))?;
    let participant_hex = hex32(participant);
    let signature = package
        .signatures
        .iter()
        .find(|signature| signature.participant == participant_hex)
        .ok_or_else(|| {
            anyhow!("factory splice package has no signature for touched participant")
        })?;
    let pubkey_sec1 = decode_hex_len(
        &signature.pubkey_sec1,
        COMPRESSED_SECP256K1_PUBKEY_LEN,
        "factory splice participant pubkey",
    )?;
    let lock = secp256k1_lock_from_pubkey(&pubkey_sec1)?;
    Ok(SpliceParticipantWithdrawalTarget { pubkey_sec1, lock })
}

fn factory_reduced_splice_participant_withdrawal_target(
    package: &StoredFactoryReducedSplicePackage,
    transition: &FactoryReducedSpliceTransition,
) -> Result<SpliceParticipantWithdrawalTarget> {
    let participant = transition
        .update
        .touched_participants
        .iter()
        .next()
        .ok_or_else(|| anyhow!("reduced factory splice package has no touched participant"))?;
    let participant_hex = hex32(participant);
    let signature = package
        .signatures
        .iter()
        .find(|signature| signature.participant == participant_hex)
        .ok_or_else(|| {
            anyhow!("reduced factory splice package has no signature for touched participant")
        })?;
    let pubkey_sec1 = decode_hex_len(
        &signature.pubkey_sec1,
        COMPRESSED_SECP256K1_PUBKEY_LEN,
        "reduced factory splice participant pubkey",
    )?;
    let lock = secp256k1_lock_from_pubkey(&pubkey_sec1)?;
    Ok(SpliceParticipantWithdrawalTarget { pubkey_sec1, lock })
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

struct BuiltXudtFinalise {
    tx: ckb_types::core::TransactionView,
    channel_id: String,
    funding_anchor: String,
    state_number: u64,
    xudt_type_hash: String,
    alice_capacity: u64,
    bob_capacity: u64,
    alice_xudt_amount: u128,
    bob_xudt_amount: u128,
    state_refund_capacity: u64,
    fee: u64,
    alice_output: CellOutput,
    bob_output: CellOutput,
    refund_output: CellOutput,
    alice_output_data_len: usize,
    bob_output_data_len: usize,
}

fn xudt_settlement_output(
    lock: Script,
    xudt_type: &Script,
    capacity: u64,
    descriptor_amount: u128,
    output_amount: u128,
) -> (CellOutput, Bytes) {
    if descriptor_amount == 0 && output_amount == 0 {
        let output = CellOutput::new_builder()
            .capacity(capacity)
            .lock(lock)
            .build();
        (output, Bytes::new())
    } else {
        let output = CellOutput::new_builder()
            .capacity(capacity)
            .lock(lock)
            .type_(Some(xudt_type.clone()).pack())
            .build();
        (output, xudt_amount_bytes(output_amount))
    }
}

fn build_xudt_finalise_transaction(
    rpc: &CkbRpcClient,
    options: &XudtSmokeOptions,
    state_out_point: String,
    vault_out_point: String,
    output_amounts: (u128, u128),
) -> Result<BuiltXudtFinalise> {
    ensure!(options.fee > 0, "fee must be non-zero");
    let total_xudt_amount = options
        .alice_xudt_amount
        .checked_add(options.bob_xudt_amount)
        .ok_or_else(|| anyhow!("xUDT amount overflow"))?;
    output_amounts
        .0
        .checked_add(output_amounts.1)
        .ok_or_else(|| anyhow!("xUDT output amount overflow"))?;

    let owner_key = parse_privkey(&options.private_key)
        .with_context(|| "invalid secp256k1 private key for state refund")?;
    let owner_lock = secp256k1_lock(&owner_key)?;
    let alice_key = parse_privkey(&options.alice_private_key)
        .with_context(|| "invalid Alice channel private key")?;
    let bob_key = parse_privkey(&options.bob_private_key)
        .with_context(|| "invalid Bob channel private key")?;
    let alice_lock = secp256k1_lock(&alice_key)?;
    let bob_lock = secp256k1_lock(&bob_key)?;
    let alice_lock_hash: [u8; 32] = alice_lock.calc_script_hash().unpack();
    let bob_lock_hash: [u8; 32] = bob_lock.calc_script_hash().unpack();

    let state_out_point = parse_out_point(&state_out_point)?;
    let vault_out_point = parse_out_point(&vault_out_point)?;
    let state_cell = load_live_cell(rpc, state_out_point.clone())?;
    let vault_cell = load_live_cell(rpc, vault_out_point.clone())?;
    let header = WireStateHeader::parse(state_cell.data.as_ref())
        .map_err(|err| anyhow!("state cell does not contain a valid Morph StateHeader: {err:?}"))?;
    ensure!(
        header.phase() == PHASE_SETTLING,
        "only a settling state can be finalised"
    );
    ensure!(
        header.descriptor_version() == BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
        "state descriptor version is not xUDT-capable"
    );
    ensure!(
        xudt_amount_from_data(&vault_cell.data)? == total_xudt_amount,
        "vault xUDT amount does not match requested split"
    );
    let xudt_type = vault_cell
        .output
        .type_()
        .to_opt()
        .ok_or_else(|| anyhow!("xUDT vault cell has no type script"))?;
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();

    let (alice_capacity, bob_capacity) = settlement_split(
        vault_cell.capacity,
        options.alice_capacity,
        options.bob_capacity,
    )?;
    let (alice_output, alice_output_data) = xudt_settlement_output(
        alice_lock,
        &xudt_type,
        alice_capacity,
        options.alice_xudt_amount,
        output_amounts.0,
    );
    let (bob_output, bob_output_data) = xudt_settlement_output(
        bob_lock,
        &xudt_type,
        bob_capacity,
        options.bob_xudt_amount,
        output_amounts.1,
    );
    ensure_output_capacity(
        "alice xUDT settlement",
        &alice_output,
        alice_output_data.len(),
    )?;
    ensure_output_capacity("bob xUDT settlement", &bob_output, bob_output_data.len())?;
    let descriptor = bilateral_ckb_xudt_descriptor(
        xudt_type_hash,
        alice_lock_hash,
        alice_capacity,
        options.alice_xudt_amount,
        bob_lock_hash,
        bob_capacity,
        options.bob_xudt_amount,
    );
    ensure!(
        settlement_descriptor_commitment(&descriptor).as_slice()
            == header.settlement_descriptor_commitment(),
        "reconstructed xUDT settlement descriptor does not match the state commitment"
    );
    ensure!(
        vault_cell_commitment_from_output(&vault_cell.output, vault_cell.data.as_ref()).as_slice()
            == header.vault_materialisation_root(),
        "StateHeader payload commitment does not match the live xUDT VaultCell"
    );

    let state_refund_capacity = state_cell
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("state carrier capacity cannot cover fee {}", options.fee))?;
    ensure_change_capacity(&owner_lock, state_refund_capacity)?;

    let tip_number = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip_number)?;
    let state_lock_contract = contract_by_name(&contracts, "morph-state-lock")?;
    let state_contract = contract_by_name(&contracts, "morph-state-type")?;
    let vault_contract = contract_by_name(&contracts, "morph-vault-lock")?;
    let xudt_contract = contract_by_name(&contracts, "morph-devnet-xudt")?;

    let refund_output = CellOutput::new_builder()
        .capacity(state_refund_capacity)
        .lock(owner_lock)
        .build();
    let finalise_since = relative_block_since_arg(options.finalise_since)?;
    let tx = TransactionBuilder::default()
        .cell_dep(state_lock_contract.cell_dep)
        .cell_dep(state_contract.cell_dep)
        .cell_dep(vault_contract.cell_dep)
        .cell_dep(xudt_contract.cell_dep)
        .input(CellInput::new(state_out_point, finalise_since))
        .input(CellInput::new(vault_out_point, 0))
        .output(alice_output.clone())
        .output(bob_output.clone())
        .output(refund_output.clone())
        .output_data(alice_output_data.clone().pack())
        .output_data(bob_output_data.clone().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(Bytes::copy_from_slice(&descriptor)))
        .build();

    Ok(BuiltXudtFinalise {
        tx,
        channel_id: hex32(header.channel_id()),
        funding_anchor: hex32(header.funding_anchor()),
        state_number: header.state_number(),
        xudt_type_hash: hex32(&xudt_type_hash),
        alice_capacity,
        bob_capacity,
        alice_xudt_amount: output_amounts.0,
        bob_xudt_amount: output_amounts.1,
        state_refund_capacity,
        fee: options.fee,
        alice_output,
        bob_output,
        refund_output,
        alice_output_data_len: alice_output_data.len(),
        bob_output_data_len: bob_output_data.len(),
    })
}

fn xudt_finalise_report(
    build: BuiltXudtFinalise,
    sent_hash: SentTransactionReport,
) -> XudtFinaliseReport {
    let tx_hash = sent_hash.tx_hash.clone();
    let output_report =
        |role: &str, index: u32, output: &CellOutput, data_len: usize| -> ChannelCellReport {
            ChannelCellReport {
                role: role.to_string(),
                out_point: PrintableOutPoint {
                    tx_hash: tx_hash.clone(),
                    index,
                },
                capacity: output.capacity().unpack(),
                lock_hash: hex32(output.lock().calc_script_hash().as_slice()),
                type_hash: output
                    .type_()
                    .to_opt()
                    .map(|script| hex32(script.calc_script_hash().as_slice())),
                data_len,
            }
        };

    XudtFinaliseReport {
        tx_hash: sent_hash.tx_hash,
        status: sent_hash.status,
        block_number: sent_hash.block_number,
        block_hash: sent_hash.block_hash,
        channel_id: build.channel_id,
        funding_anchor: build.funding_anchor,
        state_number: build.state_number,
        xudt_type_hash: build.xudt_type_hash,
        alice_capacity: build.alice_capacity,
        bob_capacity: build.bob_capacity,
        alice_xudt_amount: build.alice_xudt_amount,
        bob_xudt_amount: build.bob_xudt_amount,
        state_refund_capacity: build.state_refund_capacity,
        fee: build.fee,
        metrics: sent_hash.metrics,
        mined_blocks: sent_hash.mined_blocks,
        outputs: vec![
            output_report("alice", 0, &build.alice_output, build.alice_output_data_len),
            output_report("bob", 1, &build.bob_output, build.bob_output_data_len),
            output_report("state-refund", 2, &build.refund_output, 0),
        ],
    }
}

pub fn xudt_smoke(rpc: &CkbRpcClient, options: XudtSmokeOptions) -> Result<XudtSmokeReport> {
    let open = open_xudt_channel(rpc, &options)?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "xudt-vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&publish.state_out_point);
    let finalise = finalise_xudt_channel(rpc, &options, settling_state_out_point, vault_out_point)?;

    Ok(XudtSmokeReport {
        open,
        publish,
        finalise,
    })
}

pub fn xudt_negative_smoke(
    rpc: &CkbRpcClient,
    options: XudtNegativeSmokeOptions,
) -> Result<XudtNegativeSmokeReport> {
    ensure!(
        options.bob_xudt_amount > 0,
        "Bob xUDT amount must be non-zero so the negative smoke can preserve total supply"
    );
    let smoke_options = XudtSmokeOptions {
        contracts_dir: options.contracts_dir,
        private_key: options.private_key,
        alice_private_key: options.alice_private_key,
        bob_private_key: options.bob_private_key,
        vault_capacity: options.vault_capacity,
        alice_capacity: options.alice_capacity,
        bob_capacity: options.bob_capacity,
        alice_xudt_amount: options.alice_xudt_amount,
        bob_xudt_amount: options.bob_xudt_amount,
        sponsor_capacity: options.sponsor_capacity,
        fee: options.fee,
        finalise_since: options.finalise_since,
        mine_blocks: options.mine_blocks,
    };

    let open = open_xudt_channel(rpc, &smoke_options)?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "xudt-vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;
    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: smoke_options.contracts_dir.clone(),
            private_key: smoke_options.private_key.clone(),
            alice_private_key: smoke_options.alice_private_key.clone(),
            bob_private_key: smoke_options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: smoke_options.fee,
            mine_blocks: smoke_options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&publish.state_out_point);

    let rejected_alice_xudt_amount = smoke_options
        .alice_xudt_amount
        .checked_add(1)
        .ok_or_else(|| anyhow!("Alice xUDT amount overflow in negative smoke"))?;
    let rejected_bob_xudt_amount = smoke_options
        .bob_xudt_amount
        .checked_sub(1)
        .ok_or_else(|| anyhow!("Bob xUDT amount underflow in negative smoke"))?;
    let rejected_build = build_xudt_finalise_transaction(
        rpc,
        &smoke_options,
        settling_state_out_point.clone(),
        vault_out_point.clone(),
        (rejected_alice_xudt_amount, rejected_bob_xudt_amount),
    )?;
    mine_relative_since_maturity(rpc, smoke_options.finalise_since)?;
    let rejection = match send_and_mine(rpc, rejected_build.tx, 0) {
        Ok(report) => {
            return Err(anyhow!(
                "xUDT descriptor unexpectedly accepted tampered settlement in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SettlementOutputMismatch as i16),
        "expected SettlementOutputMismatch from vault lock, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let finalise = finalise_xudt_channel(
        rpc,
        &smoke_options,
        settling_state_out_point,
        vault_out_point,
    )?;

    Ok(XudtNegativeSmokeReport {
        open,
        publish,
        rejected_alice_xudt_amount,
        rejected_bob_xudt_amount,
        rejection,
        script_failure,
        finalise,
    })
}

pub fn supersede_smoke(
    rpc: &CkbRpcClient,
    options: SupersedeSmokeOptions,
) -> Result<SupersedeSmokeReport> {
    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: DEFAULT_SPONSOR_MIN_STATE_NUMBER,
            sponsor_max_state_number: DEFAULT_SPONSOR_MAX_STATE_NUMBER,
            strict_sponsor_range: true,
            sponsor_max_fee_per_tx: None,
            sponsor_max_total_fee: None,
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let initial_sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let stale_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point: initial_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let stale_state_out_point = printable_out_point_string(&stale_publish.state_out_point);

    let sponsor_top_up = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: stale_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: DEFAULT_SPONSOR_MIN_STATE_NUMBER,
            sponsor_max_state_number: DEFAULT_SPONSOR_MAX_STATE_NUMBER,
            strict_sponsor_range: true,
            sponsor_max_fee_per_tx: None,
            sponsor_max_total_fee: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let top_up_sponsor_out_point = printable_out_point_string(&sponsor_top_up.sponsor_out_point);

    let supersede_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: stale_state_out_point,
            sponsor_out_point: top_up_sponsor_out_point,
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let newer_state_out_point = printable_out_point_string(&supersede_publish.state_out_point);

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: newer_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SupersedeSmokeReport {
        open,
        stale_publish,
        sponsor_top_up,
        supersede_publish,
        finalise,
    })
}

pub fn finalise_since_negative_smoke(
    rpc: &CkbRpcClient,
    options: FinaliseSinceNegativeSmokeOptions,
) -> Result<FinaliseSinceNegativeSmokeReport> {
    ensure!(
        options.finalise_since > 0,
        "finalise-since negative smoke needs a non-zero finalise since"
    );
    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building sponsor policy"))?;
    ensure!(
        policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the smoke policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&publish.state_out_point);

    let rejected_input_since = options.finalise_since - 1;
    let rejection = match finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: settling_state_out_point.clone(),
            vault_out_point: vault_out_point.clone(),
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: rejected_input_since,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "finalise unexpectedly accepted input since {} in tx {}",
                rejected_input_since,
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::StateSinceNotMature as i16),
        "expected StateSinceNotMature from finalise path, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let mut maturity_blocks = Vec::new();
    for _ in 0..options.finalise_since {
        maturity_blocks.push(rpc.generate_block()?);
    }

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: settling_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(FinaliseSinceNegativeSmokeReport {
        open,
        publish,
        rejected_input_since,
        required_finalise_since: options.finalise_since,
        rejection,
        script_failure,
        maturity_blocks,
        finalise,
    })
}

pub fn sponsor_policy_negative_smoke(
    rpc: &CkbRpcClient,
    options: SponsorPolicyNegativeSmokeOptions,
) -> Result<SponsorPolicyNegativeSmokeReport> {
    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building sponsor policy"))?;
    ensure!(
        policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the negative-smoke policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let rejection = match publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: sponsor_out_point.clone(),
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "sponsor policy unexpectedly accepted out-of-range state in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SponsorStateOutOfRange as i16),
        "expected SponsorStateOutOfRange from sponsor lock, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let allowed_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&allowed_publish.state_out_point);

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: settling_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SponsorPolicyNegativeSmokeReport {
        open,
        rejected_state_number: 2,
        rejection,
        script_failure,
        allowed_publish,
        finalise,
    })
}

pub fn sponsor_budget_negative_smoke(
    rpc: &CkbRpcClient,
    options: SponsorBudgetNegativeSmokeOptions,
) -> Result<SponsorBudgetNegativeSmokeReport> {
    ensure!(
        options.fee > 1,
        "sponsor-budget negative smoke needs a fee greater than one shannon"
    );
    let rejected_max_fee = options.fee - 1;
    let replacement_policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building replacement sponsor policy"))?;
    ensure!(
        replacement_policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the replacement sponsor policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(rejected_max_fee),
            sponsor_max_total_fee: Some(rejected_max_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let underfunded_sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let rejection = match publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: underfunded_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "sponsor budget unexpectedly accepted fee {} in tx {}",
                options.fee,
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };
    let script_failure = parse_script_failure(&rejection);
    ensure!(
        script_failure.error_code == Some(ScriptError::SponsorFeeTooHigh as i16),
        "expected SponsorFeeTooHigh from sponsor lock, got {:?}: {}",
        script_failure.error_code,
        rejection
    );

    let replacement_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: initial_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(replacement_policy_fee),
            sponsor_max_total_fee: Some(replacement_policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let replacement_sponsor_out_point =
        printable_out_point_string(&replacement_sponsor.sponsor_out_point);
    let allowed_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point,
            sponsor_out_point: replacement_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let settling_state_out_point = printable_out_point_string(&allowed_publish.state_out_point);

    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: settling_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(SponsorBudgetNegativeSmokeReport {
        open,
        rejected_fee: options.fee,
        sponsor_max_fee_per_tx: rejected_max_fee,
        rejection,
        script_failure,
        replacement_sponsor,
        allowed_publish,
        finalise,
    })
}

pub fn competing_spend_smoke(
    rpc: &CkbRpcClient,
    options: CompetingSpendSmokeOptions,
) -> Result<CompetingSpendSmokeReport> {
    ensure!(
        options.mine_blocks > 0,
        "competing-spend smoke needs --mine-blocks greater than zero to commit the pending tx"
    );
    let policy_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow while building spare sponsor policy"))?;
    ensure!(
        policy_fee <= options.sponsor_capacity,
        "sponsor capacity must cover the spare sponsor policy budget"
    );

    let open = open_channel(
        rpc,
        OpenChannelOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            vault_capacity: options.vault_capacity,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 1,
            sponsor_max_state_number: 1,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            finalise_since: options.finalise_since,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let initial_state_out_point = channel_cell_out_point(&open, "state")?;
    let vault_out_point = channel_cell_out_point(&open, "vault")?;
    let initial_sponsor_out_point = channel_cell_out_point(&open, "sponsor")?;

    let spare_sponsor = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            sponsor_change_pubkey: None,
            state_out_point: initial_state_out_point.clone(),
            sponsor_capacity: options.sponsor_capacity,
            sponsor_min_state_number: 2,
            sponsor_max_state_number: 2,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(policy_fee),
            sponsor_max_total_fee: Some(policy_fee),
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let spare_sponsor_out_point = printable_out_point_string(&spare_sponsor.sponsor_out_point);

    let pending_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: initial_sponsor_out_point,
            state_number: Some(1),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    )?;
    ensure!(
        pending_publish.status != "Committed",
        "pending publication unexpectedly committed before a block was generated"
    );

    let rejection = match publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: initial_state_out_point.clone(),
            sponsor_out_point: spare_sponsor_out_point.clone(),
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: 0,
        },
    ) {
        Ok(report) => {
            return Err(anyhow!(
                "competing state publication unexpectedly entered tx-pool in tx {}",
                report.tx_hash
            ));
        }
        Err(err) => err.to_string(),
    };

    let pending_commit =
        mine_pending_transaction(rpc, &pending_publish.tx_hash, options.mine_blocks)?;
    let live_settling_state_out_point =
        printable_out_point_string(&pending_publish.state_out_point);
    let rebuilt_publish = publish_state(
        rpc,
        PublishStateOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: options.private_key.clone(),
            alice_private_key: options.alice_private_key.clone(),
            bob_private_key: options.bob_private_key.clone(),
            state_out_point: live_settling_state_out_point.clone(),
            sponsor_out_point: spare_sponsor_out_point,
            state_number: Some(2),
            state_package: None,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    let finalise_state_out_point = printable_out_point_string(&rebuilt_publish.state_out_point);
    let finalise = finalise_channel(
        rpc,
        FinaliseChannelOptions {
            contracts_dir: options.contracts_dir,
            private_key: options.private_key,
            alice_private_key: options.alice_private_key,
            bob_private_key: options.bob_private_key,
            state_out_point: finalise_state_out_point,
            vault_out_point,
            alice_capacity: options.alice_capacity,
            bob_capacity: options.bob_capacity,
            finalise_since: options.finalise_since,
            fee: options.fee,
            mine_blocks: options.mine_blocks,
        },
    )?;

    Ok(CompetingSpendSmokeReport {
        open,
        spare_sponsor,
        pending_publish,
        pending_commit,
        rejected_state_number: 2,
        rejected_against_state_out_point: initial_state_out_point,
        rejection,
        rebuilt_publish,
        finalise,
    })
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

fn sign_single_secp_input_with_input_type(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Bytes,
) -> Result<ckb_types::core::TransactionView> {
    sign_single_secp_input_with_optional_input_type(tx, privkey, Some(input_type))
}

fn sign_bilateral_state_creation(
    tx: ckb_types::core::TransactionView,
    owner_key: &Privkey,
    state_header: &[u8],
    alice_private_key: &str,
    bob_private_key: &str,
) -> Result<ckb_types::core::TransactionView> {
    let participant_witness =
        bilateral_signature_witness(state_header, alice_private_key, bob_private_key)?;
    sign_single_secp_input_with_input_type(
        tx,
        owner_key,
        Bytes::copy_from_slice(&participant_witness),
    )
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

fn sign_factory_update_transaction(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Bytes,
) -> Result<ckb_types::core::TransactionView> {
    let factory_witness = WitnessArgs::new_builder()
        .input_type(Some(input_type.clone()).pack())
        .build();
    let unsigned_fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .build();
    let message = sighash_all_message(tx.hash(), &[unsigned_fee_witness.as_bytes()]);
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB factory update transaction")?;
    let fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .build();
    Ok(tx
        .as_advanced_builder()
        .witness(factory_witness.as_bytes())
        .witness(fee_witness.as_bytes())
        .build())
}

fn sign_factory_exit_transaction(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Bytes,
) -> Result<ckb_types::core::TransactionView> {
    let factory_witness = WitnessArgs::new_builder()
        .input_type(Some(input_type.clone()).pack())
        .build();
    let factory_vault_witness = WitnessArgs::new_builder()
        .input_type(Some(input_type.clone()).pack())
        .build();
    let unsigned_fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .build();
    let message = sighash_all_message(tx.hash(), &[unsigned_fee_witness.as_bytes()]);
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB factory exit transaction")?;
    let fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .build();
    Ok(tx
        .as_advanced_builder()
        .witness(factory_witness.as_bytes())
        .witness(factory_vault_witness.as_bytes())
        .witness(fee_witness.as_bytes())
        .build())
}

fn sign_factory_splice_transaction(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    input_type: Bytes,
    extra_owner_inputs: usize,
) -> Result<ckb_types::core::TransactionView> {
    let factory_witness = WitnessArgs::new_builder()
        .input_type(Some(input_type.clone()).pack())
        .build();
    let factory_vault_witness = WitnessArgs::new_builder()
        .input_type(Some(input_type.clone()).pack())
        .build();
    let unsigned_fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .build();
    let extra_owner_witness = WitnessArgs::default();
    let mut owner_witnesses = vec![unsigned_fee_witness.as_bytes()];
    for _ in 0..extra_owner_inputs {
        owner_witnesses.push(extra_owner_witness.as_bytes());
    }
    let message = sighash_all_message(tx.hash(), &owner_witnesses);
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB factory splice transaction")?;
    let fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .build();
    let mut builder = tx
        .as_advanced_builder()
        .witness(factory_witness.as_bytes())
        .witness(factory_vault_witness.as_bytes())
        .witness(fee_witness.as_bytes());
    for _ in 0..extra_owner_inputs {
        builder = builder.witness(extra_owner_witness.as_bytes());
    }
    Ok(builder.build())
}

fn sign_splice_transaction(
    tx: ckb_types::core::TransactionView,
    privkey: &Privkey,
    splice_witness: Bytes,
    extra_owner_inputs: usize,
) -> Result<ckb_types::core::TransactionView> {
    let state_witness = WitnessArgs::new_builder()
        .input_type(Some(splice_witness).pack())
        .build();
    let vault_witness = WitnessArgs::default();
    let unsigned_fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])))
        .build();
    let extra_owner_witness = WitnessArgs::default();
    let mut owner_witnesses = vec![unsigned_fee_witness.as_bytes()];
    for _ in 0..extra_owner_inputs {
        owner_witnesses.push(extra_owner_witness.as_bytes());
    }
    let message = sighash_all_message(tx.hash(), &owner_witnesses);
    let signature = privkey
        .sign_recoverable(&message)
        .context("failed to sign CKB splice fee transaction")?;
    let fee_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature.serialize())))
        .build();
    let mut builder = tx
        .as_advanced_builder()
        .witness(state_witness.as_bytes())
        .witness(vault_witness.as_bytes())
        .witness(fee_witness.as_bytes());
    for _ in 0..extra_owner_inputs {
        builder = builder.witness(extra_owner_witness.as_bytes());
    }
    Ok(builder.build())
}

fn send_and_mine(
    rpc: &CkbRpcClient,
    tx: ckb_types::core::TransactionView,
    mine_blocks: u64,
) -> Result<SentTransactionReport> {
    let metrics = transaction_metrics(rpc, &tx)?;
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
        canonical_confirmations,
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
    confirmations: u64,
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
        canonical_confirmations: confirmed.confirmations,
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
                    return Ok(CanonicalPublicationStatus {
                        status,
                        confirmations,
                        blocks,
                    });
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

fn mine_pending_transaction(
    rpc: &CkbRpcClient,
    tx_hash: &str,
    mine_blocks: u64,
) -> Result<PendingCommitReport> {
    let parsed = parse_h256(tx_hash)?;
    let mined = mine_blocks_until_committed(rpc, parsed, mine_blocks)?;
    Ok(PendingCommitReport {
        tx_hash: tx_hash.to_string(),
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
        mined_blocks: mined.blocks,
    })
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
            let Ok(header) = WireStateHeader::parse(data.as_bytes()) else {
                continue;
            };
            if hex32(header.channel_id()) != channel_id {
                continue;
            }
            let Some(output) = tx.inner.outputs.get(index) else {
                continue;
            };
            let output: CellOutput = output.clone().into();
            if !is_authentic_observed_state_cell(&output, &header, filter) {
                continue;
            }
            let tx_hash = format!("{:#x}", tx.hash);
            observed.push(ObservedStateCellReport {
                block_number,
                block_hash: block_hash.clone(),
                tx_hash: tx_hash.clone(),
                output_index: index as u32,
                out_point: format!("{tx_hash}:{index}"),
                funding_anchor: hex32(header.funding_anchor()),
                funding_context_id: funding_context_id_for_header(&header),
                vault_set_commitment: hex32(header.vault_set_commitment()),
                state_number: header.state_number(),
                phase: phase_label(header.phase()).to_string(),
                settlement_descriptor_commitment: hex32(header.settlement_descriptor_commitment()),
                descriptor_version: header.descriptor_version(),
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
    header: &WireStateHeader,
    filter: &StateCellDetectionFilter,
) -> bool {
    let Some(type_script) = output.type_().to_opt() else {
        return false;
    };
    if !script_uses_data1_code_hash(&type_script, &filter.state_type_code_hash) {
        return false;
    }
    let type_args = type_script.args().raw_data();
    if type_args.len() < BYTE32_LEN || &type_args.as_ref()[..BYTE32_LEN] != header.funding_anchor()
    {
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
            })
        })
        .collect()
}

fn find_deployed_contracts(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    tip_number: u64,
) -> Result<Vec<ResolvedContract>> {
    let targets = load_contract_targets(contracts_dir)?;
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

fn load_live_cell(rpc: &CkbRpcClient, out_point: OutPoint) -> Result<LiveCellDetails> {
    let live = rpc.live_cell(out_point.clone().into(), true)?;
    live_cell_details(out_point, live)
}

fn load_canonical_live_cell(rpc: &CkbRpcClient, out_point: OutPoint) -> Result<LiveCellDetails> {
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
    ensure!(
        pubkey_sec1.len() == COMPRESSED_SECP256K1_PUBKEY_LEN,
        "secp256k1 lock pubkey must be compressed"
    );
    let args = blake160(pubkey_sec1);
    Ok(Script::new_builder()
        .code_hash(parse_h256(DEFAULT_SECP_TYPE_HASH)?.pack())
        .hash_type(ScriptHashType::Type)
        .args(Bytes::copy_from_slice(&args).pack())
        .build())
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
    let header = WireStateHeader::parse(cell.data.as_ref()).map_err(|err| {
        anyhow!("challenge-window StateCell does not contain a valid StateHeader: {err:?}")
    })?;
    let args = state_type.args().raw_data();
    ensure!(
        matches!(args.len(), 40 | 72),
        "challenge-window StateType args must be bilateral or FactoryProof layout"
    );
    ensure!(
        header.funding_anchor() == &args[..BYTE32_LEN],
        "challenge-window StateHeader funding anchor does not match StateType args"
    );
    let since_offset = args.len() - 8;
    let mut since_bytes = [0u8; 8];
    since_bytes.copy_from_slice(&args[since_offset..]);
    let encoded_since = u64::from_le_bytes(since_bytes);
    let blocks = encoded_since & 0x00ff_ffff_ffff_ffff;
    ensure!(
        relative_block_since_arg(blocks)? == encoded_since,
        "StateType finalise_since is not canonical relative-block since"
    );
    Ok(blocks)
}

fn k256_signing_key(value: &str) -> Result<SigningKey> {
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| "private key must be hex encoded")?;
    ensure!(raw.len() == 32, "private key must be 32 bytes");
    SigningKey::from_slice(&raw).map_err(|err| anyhow!("invalid secp256k1 private key: {err:?}"))
}

fn k256_pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_encoded_point(true);
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

fn bilateral_signature_witness(
    state_header: &[u8],
    alice_private_key: &str,
    bob_private_key: &str,
) -> Result<[u8; BILATERAL_SIGNATURE_WITNESS_LEN]> {
    let header = WireStateHeader::parse(state_header)
        .map_err(|err| anyhow!("new state header is invalid: {err:?}"))?;
    let alice_key = k256_signing_key(alice_private_key)?;
    let bob_key = k256_signing_key(bob_private_key)?;
    let mut entries = [
        (k256_pubkey(&alice_key), alice_key),
        (k256_pubkey(&bob_key), bob_key),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let digest = header.signing_digest();
    let mut witness = [0u8; BILATERAL_SIGNATURE_WITNESS_LEN];
    put_u16(&mut witness, 0, BILATERAL_SIGNATURE_WITNESS_VERSION);
    witness[2] = BILATERAL_SIGNATURE_THRESHOLD;
    witness[3] = BILATERAL_SIGNATURE_COUNT;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&ecdsa_signature(key, &digest)?);
    }
    Ok(witness)
}

fn splice_witness_from_keys(
    header: &SpliceHeader,
    alice_private_key: &str,
    bob_private_key: &str,
) -> Result<SpliceWitness> {
    let alice_key = k256_signing_key(alice_private_key)?;
    let bob_key = k256_signing_key(bob_private_key)?;
    let mut entries = [
        (k256_pubkey(&alice_key), alice_key),
        (k256_pubkey(&bob_key), bob_key),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let pubkeys = [entries[0].0.as_slice(), entries[1].0.as_slice()];
    ensure!(
        core_participants_commitment(2, &pubkeys) == header.participants_commitment,
        "Alice/Bob keys do not match the live StateCell participants commitment"
    );

    let digest = header.signing_digest();
    let signatures = entries
        .iter()
        .map(|(pubkey, key)| {
            Ok(ParticipantSignature {
                pubkey_sec1: pubkey.to_vec(),
                signature: ecdsa_signature(key, &digest)?.to_vec(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SpliceWitness {
        threshold: 2,
        signatures,
    })
}

fn splice_withdrawal_lock_hash_from_keys(
    alice_private_key: &str,
    bob_private_key: &str,
) -> Result<[u8; BYTE32_LEN]> {
    let alice_key = k256_signing_key(alice_private_key)?;
    let bob_key = k256_signing_key(bob_private_key)?;
    let mut participant_pubkeys = [k256_pubkey(&alice_key), k256_pubkey(&bob_key)];
    participant_pubkeys.sort();
    secp256k1_lock_hash(&participant_pubkeys[0])
}

fn secp256k1_lock_hash(pubkey: &[u8; COMPRESSED_SECP256K1_PUBKEY_LEN]) -> Result<[u8; BYTE32_LEN]> {
    Ok(secp256k1_lock_from_pubkey(pubkey)?
        .calc_script_hash()
        .unpack())
}

fn factory_signature_witness(
    factory_header: &[u8],
    alice_private_key: &str,
    bob_private_key: &str,
    additional_participant_private_keys: &[String],
) -> Result<Vec<u8>> {
    let header = FactoryStateHeader::parse(factory_header)
        .map_err(|err| anyhow!("new factory header is invalid: {err:?}"))?;
    let entries = factory_signing_entries(
        alice_private_key,
        bob_private_key,
        additional_participant_private_keys,
    )?;

    let digest = header.signing_digest();
    let mut witness =
        vec![0u8; morph_script_common::factory_signature_witness_len(entries.len() as u8)];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    witness[2] = entries.len() as u8;
    witness[3] = entries.len() as u8;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&ecdsa_signature(key, &digest)?);
    }
    Ok(witness)
}

fn factory_signature_envelope_kind(raw: &[u8]) -> Result<u16> {
    morph_script_common::FactorySignatureWitness::parse(raw)
        .map_err(|err| anyhow!("invalid factory signature witness: {err:?}"))?;
    Ok(WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE)
}

fn merkle_update_initial_roots() -> Result<([u8; BYTE32_LEN], [u8; BYTE32_LEN])> {
    let (before, _) = merkle_update_rights(900);
    Ok((
        factory_right_sparse_root(&before)
            .map_err(|err| anyhow!("failed to compute Merkle update initial root: {err:?}"))?,
        merkle_update_access_manifest_root(),
    ))
}

fn merkle_update_package_from_factory_header(
    old_header_bytes: &[u8],
    participant_keys: &[SigningKey],
    new_update_number: Option<u64>,
    touched_after_balance: u128,
    source_factory_out_point: Option<PackageOutPoint>,
) -> Result<StoredFactoryMerkleUpdateStatePackage> {
    let old_header = FactoryStateHeader::parse(old_header_bytes)
        .map_err(|err| anyhow!("old factory header is invalid: {err:?}"))?;
    let update_number = new_update_number.unwrap_or_else(|| old_header.update_number() + 1);
    ensure!(
        update_number > old_header.update_number(),
        "new update number must be greater than old update number {}",
        old_header.update_number()
    );

    ensure!(
        participant_keys.len() >= FACTORY_MIN_PARTICIPANTS as usize
            && participant_keys.len() <= FACTORY_MAX_PARTICIPANTS as usize,
        "factory Merkle update requires {}-{} participant keys",
        FACTORY_MIN_PARTICIPANTS,
        FACTORY_MAX_PARTICIPANTS
    );
    let commitment_entries = participant_keys
        .iter()
        .enumerate()
        .map(|(index, key)| ([(index + 1) as u8; BYTE32_LEN], k256_pubkey(key)))
        .collect::<Vec<_>>();
    let commitment_refs = commitment_entries
        .iter()
        .map(|(participant, pubkey)| (participant.as_slice(), pubkey.as_slice()))
        .collect::<Vec<_>>();
    let participants_commitment =
        factory_participants_commitment(participant_keys.len() as u8, &commitment_refs);
    ensure!(
        old_header.participants_commitment() == participants_commitment.as_slice(),
        "live factory participant commitment does not match supplied participant keys"
    );

    let (before_rights, after_rights) = merkle_update_rights(touched_after_balance);
    let changed_id = before_rights[0].id.clone();
    let before_root = factory_right_sparse_root(&before_rights)
        .map_err(|err| anyhow!("failed to compute Merkle update old root: {err:?}"))?;
    ensure!(
        old_header.state_root() == before_root.as_slice(),
        "live factory state_root does not match Merkle update old root"
    );
    let access_manifest_root = merkle_update_access_manifest_root();
    ensure!(
        old_header.access_manifest_root() == access_manifest_root.as_slice(),
        "live factory access_manifest_root does not match Merkle update access root"
    );
    let before_proof = factory_right_sparse_proof(&before_rights, &changed_id)
        .map_err(|err| anyhow!("failed to build Merkle update old proof: {err:?}"))?;
    let after_proof = factory_right_sparse_proof(&after_rights, &changed_id)
        .map_err(|err| anyhow!("failed to build Merkle update new proof: {err:?}"))?;
    ensure!(
        before_proof.siblings == after_proof.siblings,
        "Merkle update proof must keep the sibling frontier unchanged"
    );

    let mut witness = merkle_update_witness_bytes(
        &before_proof.right,
        &after_proof.right,
        &before_proof.siblings,
        participant_keys,
    )?;
    let new_state_root = merkle_update_rights_root(&witness, true)?;

    let mut new_header = old_header_bytes.to_vec();
    put_u64(&mut new_header, 68, update_number);
    new_header[76..108].copy_from_slice(&new_state_root);
    new_header[140..172].copy_from_slice(&access_manifest_root);
    let preliminary_new = FactoryStateHeader::parse(&new_header)
        .map_err(|err| anyhow!("preliminary Merkle update header is invalid: {err:?}"))?;
    let non_interference_digest =
        merkle_update_non_interference_digest(&witness, &old_header, &preliminary_new)?;
    new_header[172..204].copy_from_slice(&non_interference_digest);
    let new_header_parsed = FactoryStateHeader::parse(&new_header)
        .map_err(|err| anyhow!("new Merkle update header is invalid: {err:?}"))?;
    sign_merkle_update_witness(
        &mut witness,
        [1u8; BYTE32_LEN],
        &participant_keys[0],
        &new_header_parsed.signing_digest(),
    )?;
    verify_merkle_update_witness_any(&old_header, &new_header_parsed, &witness)?;

    StoredFactoryMerkleUpdateStatePackage::from_merkle_update(
        old_header_bytes,
        &new_header,
        &witness,
        source_factory_out_point,
    )
}

fn merkle_update_access_manifest_root() -> [u8; BYTE32_LEN] {
    script_blake2b256(&[b"CKB_MORPH_FACTORY_MERKLE_ACCESS_MANIFEST"])
}

fn merkle_update_rights(touched_after_balance: u128) -> (Vec<FactoryRight>, Vec<FactoryRight>) {
    let mut before = Vec::new();
    for participant in 1u8..=8 {
        for subchannel in 10u8..=13 {
            for (kind, quantity) in [
                (FactoryRightKind::Balance, 1_000u128),
                (FactoryRightKind::ReserveClaim, 250u128),
                (FactoryRightKind::ExitPath, 1u128),
            ] {
                before.push(FactoryRight {
                    id: FactoryRightId {
                        participant: [participant; BYTE32_LEN],
                        subchannel: [subchannel; BYTE32_LEN],
                        kind,
                        asset_type: None,
                    },
                    quantity,
                });
            }
        }
    }
    let mut after = before.clone();
    after[0].quantity = touched_after_balance;
    (before, after)
}

fn merkle_update_witness_bytes(
    before: &FactoryRight,
    after: &FactoryRight,
    siblings: &[FactoryMerkleSibling],
    participant_keys: &[SigningKey],
) -> Result<Vec<u8>> {
    ensure!(
        siblings.len() == FACTORY_SPARSE_MERKLE_DEPTH,
        "Merkle update proof must contain {} sibling hashes",
        FACTORY_SPARSE_MERKLE_DEPTH
    );
    ensure!(
        before.id == after.id && before.quantity != after.quantity,
        "Merkle update must prove one changed right"
    );
    ensure!(
        participant_keys.len() >= FACTORY_MIN_PARTICIPANTS as usize
            && participant_keys.len() <= FACTORY_MAX_PARTICIPANTS as usize,
        "factory Merkle update requires {}-{} participant keys",
        FACTORY_MIN_PARTICIPANTS,
        FACTORY_MAX_PARTICIPANTS
    );
    let touched = before.id.participant;
    let mut raw =
        vec![
            0u8;
            morph_script_common::factory_merkle_update_witness_len(participant_keys.len() as u8)
        ];
    put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
    raw[2] = participant_keys.len() as u8;
    raw[3] = participant_keys.len() as u8;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT;
    for (index, key) in participant_keys.iter().enumerate() {
        let participant = [(index + 1) as u8; BYTE32_LEN];
        let pubkey = k256_pubkey(key);
        let offset = merkle_update_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(&pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant.as_slice() == touched.as_slice());
    }
    let touched_offset = merkle_update_touched_offset_for_count(participant_keys.len());
    raw[touched_offset..touched_offset + BYTE32_LEN].copy_from_slice(&touched);
    let before_offset = merkle_update_right_offset_for_count(participant_keys.len(), false);
    raw[before_offset..before_offset + FACTORY_RIGHT_LEN]
        .copy_from_slice(&core_factory_right_bytes(before));
    let after_offset = merkle_update_right_offset_for_count(participant_keys.len(), true);
    raw[after_offset..after_offset + FACTORY_RIGHT_LEN]
        .copy_from_slice(&core_factory_right_bytes(after));
    for (depth, sibling) in siblings.iter().enumerate() {
        let offset = merkle_update_sibling_offset_for_count(participant_keys.len(), depth);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&sibling.hash);
    }
    Ok(raw)
}

fn core_factory_right_bytes(right: &FactoryRight) -> [u8; FACTORY_RIGHT_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_LEN];
    raw[0..BYTE32_LEN].copy_from_slice(&right.id.participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].copy_from_slice(&right.id.subchannel);
    raw[2 * BYTE32_LEN] = factory_right_kind_byte(right.id.kind);
    if let Some(asset_type) = right.id.asset_type {
        raw[2 * BYTE32_LEN + 1] = 1;
        raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
    }
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, right.quantity);
    raw
}

fn factory_right_kind_byte(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    }
}

fn sign_merkle_update_witness(
    witness: &mut [u8],
    participant: [u8; BYTE32_LEN],
    key: &SigningKey,
    digest: &[u8; BYTE32_LEN],
) -> Result<()> {
    let sig = ecdsa_signature(key, digest)?;
    let participant_count = usize::from(
        *witness
            .get(3)
            .ok_or_else(|| anyhow!("factory Merkle update witness is truncated"))?,
    );
    for index in 0..participant_count {
        let offset = merkle_update_participant_offset(index);
        if &witness[offset..offset + BYTE32_LEN] == participant.as_slice() {
            let signature_offset = offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            witness[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
            return Ok(());
        }
    }
    Err(anyhow!(
        "participant not present in factory Merkle update witness"
    ))
}

fn merkle_update_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn merkle_update_touched_offset_for_count(participant_count: usize) -> usize {
    8 + participant_count * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn merkle_update_right_offset_for_count(participant_count: usize, after: bool) -> usize {
    let before_offset = merkle_update_touched_offset_for_count(participant_count) + BYTE32_LEN;
    if after {
        before_offset + FACTORY_RIGHT_LEN
    } else {
        before_offset
    }
}

fn merkle_update_sibling_offset_for_count(participant_count: usize, depth: usize) -> usize {
    merkle_update_right_offset_for_count(participant_count, true)
        + FACTORY_RIGHT_LEN
        + depth * BYTE32_LEN
}

fn merkle_update_rights_root(raw: &[u8], after: bool) -> Result<[u8; BYTE32_LEN]> {
    FactoryMerkleUpdateWitness::parse(raw)
        .map_err(|err| anyhow!("invalid Merkle update witness: {err:?}"))?
        .rights_root(after)
        .map_err(|err| anyhow!("failed to compute Merkle update root: {err:?}"))
}

fn merkle_update_non_interference_digest(
    raw: &[u8],
    old_header: &FactoryStateHeader<'_>,
    new_header: &FactoryStateHeader<'_>,
) -> Result<[u8; BYTE32_LEN]> {
    FactoryMerkleUpdateWitness::parse(raw)
        .map_err(|err| anyhow!("invalid Merkle update witness: {err:?}"))?
        .non_interference_digest(old_header, new_header)
        .map_err(|err| anyhow!("failed to compute Merkle update digest: {err:?}"))
}

fn verify_merkle_update_witness_any(
    old_header: &FactoryStateHeader<'_>,
    new_header: &FactoryStateHeader<'_>,
    raw: &[u8],
) -> Result<()> {
    let witness = FactoryMerkleUpdateWitness::parse(raw)
        .map_err(|err| anyhow!("invalid Merkle update witness: {err:?}"))?;
    verify_factory_merkle_update(old_header, new_header, &witness)
        .map_err(|err| anyhow!("constructed Merkle update is invalid: {err:?}"))
}

struct BuiltReducedExit {
    new_header: Vec<u8>,
    witness: Vec<u8>,
    report: FactoryReducedExitEvidenceReport,
}

#[derive(Debug, Clone, Copy)]
struct ReducedExitReserveClaim {
    release_quantity: u128,
    before_quantity: u128,
    after_quantity: u128,
    asset_type: Option<[u8; BYTE32_LEN]>,
    ckb_before_quantity: u128,
    ckb_after_quantity: u128,
}

fn reduced_exit_initial_roots(
    alice: &SigningKey,
    bob: &SigningKey,
    release_quantity: u128,
) -> Result<([u8; BYTE32_LEN], [u8; BYTE32_LEN])> {
    let descriptor = bilateral_ckb_descriptor([1u8; BYTE32_LEN], 1, [2u8; BYTE32_LEN], 2);
    reduced_exit_initial_roots_with_descriptor(
        alice,
        bob,
        ReducedExitReserveClaim {
            release_quantity,
            before_quantity: release_quantity,
            after_quantity: 0,
            asset_type: None,
            ckb_before_quantity: 100,
            ckb_after_quantity: 100,
        },
        &descriptor,
    )
}

#[allow(clippy::too_many_arguments)]
fn reduced_xudt_exit_initial_roots(
    alice: &SigningKey,
    bob: &SigningKey,
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    reserve_asset_type: [u8; BYTE32_LEN],
    child_vault_capacity: u64,
    alice_capacity: Option<u64>,
    bob_capacity: Option<u64>,
    alice_xudt_amount: u128,
    bob_xudt_amount: u128,
) -> Result<([u8; BYTE32_LEN], [u8; BYTE32_LEN])> {
    let (alice_capacity, bob_capacity) =
        settlement_split(child_vault_capacity, alice_capacity, bob_capacity)?;
    let descriptor = bilateral_ckb_xudt_descriptor(
        reserve_asset_type,
        [1u8; BYTE32_LEN],
        alice_capacity,
        alice_xudt_amount,
        [2u8; BYTE32_LEN],
        bob_capacity,
        bob_xudt_amount,
    );
    reduced_exit_initial_roots_with_descriptor(
        alice,
        bob,
        ReducedExitReserveClaim {
            release_quantity,
            before_quantity: reserve_claim_before_quantity,
            after_quantity: reserve_claim_after_quantity,
            asset_type: Some(reserve_asset_type),
            ckb_before_quantity: child_vault_capacity as u128,
            ckb_after_quantity: 0,
        },
        &descriptor,
    )
}

fn reduced_exit_initial_roots_with_descriptor(
    alice: &SigningKey,
    bob: &SigningKey,
    reserve_claim: ReducedExitReserveClaim,
    descriptor: &[u8],
) -> Result<([u8; BYTE32_LEN], [u8; BYTE32_LEN])> {
    let mut state_header = [0u8; STATE_HEADER_LEN];
    put_u16(&mut state_header, 0, 1);
    put_u16(
        &mut state_header,
        34,
        SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
    );
    state_header[149] = PHASE_ACTIVE;
    let descriptor_version = match descriptor.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => BILATERAL_CKB_DESCRIPTOR_VERSION,
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
        _ => return Err(anyhow!("unsupported reduced-exit descriptor length")),
    };
    put_u16(&mut state_header, 246, descriptor_version);
    state_header[214..246].copy_from_slice(&settlement_descriptor_commitment(descriptor));
    let witness = reduced_exit_witness_bytes(
        alice,
        bob,
        reserve_claim,
        1,
        2,
        &[3u8; BYTE32_LEN],
        &[4u8; BYTE32_LEN],
        &[5u8; BYTE32_LEN],
        &state_header,
        descriptor,
    )?;
    let parsed = FactoryReducedExitWitness::parse(&witness)
        .map_err(|err| anyhow!("constructed reduced-exit fixture is invalid: {err:?}"))?;
    Ok((
        parsed
            .rights_root(false)
            .map_err(|err| anyhow!("failed to compute reduced-exit initial root: {err:?}"))?,
        parsed.access_manifest_root(false).map_err(|err| {
            anyhow!("failed to compute reduced-exit initial access root: {err:?}")
        })?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn reduced_exit_from_factory_header(
    old_header_bytes: &[u8],
    alice: &SigningKey,
    participant_pubkeys: &[[u8; COMPRESSED_SECP256K1_PUBKEY_LEN]],
    new_update_number: u64,
    reserve_claim: ReducedExitReserveClaim,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    state_header: &[u8],
    descriptor: &[u8],
    new_factory_vault_materialisation_root: [u8; BYTE32_LEN],
) -> Result<BuiltReducedExit> {
    ensure!(
        reserve_claim.release_quantity > 0,
        "reduced factory exit release quantity must be non-zero"
    );
    ensure!(
        reserve_claim.before_quantity >= reserve_claim.release_quantity,
        "reduced factory exit claim before quantity must cover the release"
    );
    ensure!(
        reserve_claim.before_quantity - reserve_claim.release_quantity
            == reserve_claim.after_quantity,
        "reduced factory exit claim delta must equal the release quantity"
    );
    let old_header = FactoryStateHeader::parse(old_header_bytes)
        .map_err(|err| anyhow!("old factory header is invalid: {err:?}"))?;
    ensure!(
        new_update_number > old_header.update_number(),
        "new update number must be greater than old update number {}",
        old_header.update_number()
    );

    let mut witness = reduced_exit_witness_bytes_from_pubkeys(
        participant_pubkeys,
        reserve_claim,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        state_header,
        descriptor,
    )?;
    let participants_commitment = reduced_exit_participants_commitment(&witness)?;
    ensure!(
        old_header.participants_commitment() == participants_commitment.as_slice(),
        "live factory participant commitment does not match supplied participant keys"
    );

    let old_state_root = reduced_exit_rights_root(&witness, false)?;
    ensure!(
        old_header.state_root() == old_state_root.as_slice(),
        "live factory state_root does not match reduced-exit old root"
    );
    let old_access_manifest_root = reduced_exit_access_manifest_root(&witness, false)?;
    ensure!(
        old_header.access_manifest_root() == old_access_manifest_root.as_slice(),
        "live factory access_manifest_root does not match reduced-exit old access root"
    );
    let new_state_root = reduced_exit_rights_root(&witness, true)?;
    let new_access_manifest_root = reduced_exit_access_manifest_root(&witness, true)?;

    let mut new_header = old_header_bytes.to_vec();
    put_u64(&mut new_header, 68, new_update_number);
    new_header[76..108].copy_from_slice(&new_state_root);
    new_header[140..172].copy_from_slice(&new_access_manifest_root);
    new_header[238..270].copy_from_slice(&new_factory_vault_materialisation_root);
    new_header[270..302].fill(0);
    let preliminary_new = FactoryStateHeader::parse(&new_header)
        .map_err(|err| anyhow!("preliminary reduced-exit header is invalid: {err:?}"))?;
    let non_interference_digest =
        reduced_exit_non_interference_digest(&witness, &old_header, &preliminary_new)?;
    new_header[172..204].copy_from_slice(&non_interference_digest);
    let new_header_parsed = FactoryStateHeader::parse(&new_header)
        .map_err(|err| anyhow!("new reduced-exit header is invalid: {err:?}"))?;
    sign_reduced_exit_witness(
        &mut witness,
        [1u8; BYTE32_LEN],
        alice,
        &new_header_parsed.signing_digest(),
    )?;
    verify_reduced_exit_witness_any(&old_header, &new_header_parsed, &witness)?;
    let local_exit_digest = reduced_exit_local_exit_digest(&witness)?;
    let witness_len = witness.len();

    Ok(BuiltReducedExit {
        new_header,
        witness,
        report: FactoryReducedExitEvidenceReport {
            release_quantity: reserve_claim.release_quantity,
            old_state_root: hex32(&old_state_root),
            new_state_root: hex32(&new_state_root),
            old_access_manifest_root: hex32(&old_access_manifest_root),
            new_access_manifest_root: hex32(&new_access_manifest_root),
            non_interference_digest: hex32(&non_interference_digest),
            local_exit_digest: hex32(&local_exit_digest),
            witness_len,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn reduced_exit_witness_bytes(
    alice: &SigningKey,
    bob: &SigningKey,
    reserve_claim: ReducedExitReserveClaim,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    state_header: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>> {
    reduced_exit_witness_bytes_from_pubkeys(
        &[k256_pubkey(alice), k256_pubkey(bob)],
        reserve_claim,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        state_header,
        descriptor,
    )
}

#[allow(clippy::too_many_arguments)]
fn reduced_exit_witness_bytes_from_pubkeys(
    participant_pubkeys: &[[u8; COMPRESSED_SECP256K1_PUBKEY_LEN]],
    reserve_claim: ReducedExitReserveClaim,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    state_header: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        participant_pubkeys.len() >= FACTORY_MIN_PARTICIPANTS as usize
            && participant_pubkeys.len() <= FACTORY_MAX_PARTICIPANTS as usize,
        "factory reduced exit requires {}-{} participant public keys",
        FACTORY_MIN_PARTICIPANTS,
        FACTORY_MAX_PARTICIPANTS
    );
    ensure!(
        participant_pubkeys
            .iter()
            .enumerate()
            .all(|(index, key)| participant_pubkeys[..index]
                .iter()
                .all(|other| other != key)),
        "factory participant public keys must be unique"
    );
    ensure!(
        state_type_hash.len() == BYTE32_LEN,
        "state type hash must be 32 bytes"
    );
    ensure!(
        vault_lock_hash.len() == BYTE32_LEN,
        "vault lock hash must be 32 bytes"
    );
    ensure!(
        state_lock_hash.len() == BYTE32_LEN,
        "state lock hash must be 32 bytes"
    );
    ensure!(
        state_header.len() == STATE_HEADER_LEN,
        "exit state header must be {} bytes",
        STATE_HEADER_LEN
    );
    let witness_len = match descriptor.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => morph_script_common::factory_reduced_exit_witness_len(
            participant_pubkeys.len() as u8,
            BILATERAL_CKB_DESCRIPTOR_LEN,
        ),
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => morph_script_common::factory_reduced_exit_witness_len(
            participant_pubkeys.len() as u8,
            BILATERAL_CKB_XUDT_DESCRIPTOR_LEN,
        ),
        _ => {
            return Err(anyhow!(
                "settlement descriptor must be {} or {} bytes",
                BILATERAL_CKB_DESCRIPTOR_LEN,
                BILATERAL_CKB_XUDT_DESCRIPTOR_LEN
            ));
        }
    };
    let (before, after) = reduced_exit_rights_pair(reserve_claim);

    let mut raw = vec![0u8; witness_len];
    put_u16(&mut raw, 0, FACTORY_REDUCED_EXIT_WITNESS_VERSION);
    raw[2] = participant_pubkeys.len() as u8;
    raw[3] = participant_pubkeys.len() as u8;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = FACTORY_REDUCED_EXIT_RIGHTS_COUNT;
    for (index, pubkey) in participant_pubkeys.iter().enumerate() {
        let participant = [(index + 1) as u8; BYTE32_LEN];
        let offset = reduced_exit_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] = u8::from(index == 0);
    }
    let touched_offset = reduced_exit_touched_offset_for_count(participant_pubkeys.len());
    raw[touched_offset..touched_offset + BYTE32_LEN].copy_from_slice(&[1u8; BYTE32_LEN]);
    put_u128(
        &mut raw,
        reduced_exit_release_quantity_offset_for_count(participant_pubkeys.len()),
        reserve_claim.release_quantity,
    );
    put_u32(
        &mut raw,
        reduced_exit_state_output_index_offset_for_count(participant_pubkeys.len()),
        state_output_index,
    );
    put_u32(
        &mut raw,
        reduced_exit_vault_output_index_offset_for_count(participant_pubkeys.len()),
        vault_output_index,
    );
    let state_type_offset =
        reduced_exit_state_type_hash_offset_for_count(participant_pubkeys.len());
    raw[state_type_offset..state_type_offset + BYTE32_LEN].copy_from_slice(state_type_hash);
    let vault_lock_offset =
        reduced_exit_vault_lock_hash_offset_for_count(participant_pubkeys.len());
    raw[vault_lock_offset..vault_lock_offset + BYTE32_LEN].copy_from_slice(vault_lock_hash);
    let state_lock_offset =
        reduced_exit_state_lock_hash_offset_for_count(participant_pubkeys.len());
    raw[state_lock_offset..state_lock_offset + BYTE32_LEN].copy_from_slice(state_lock_hash);
    let state_header_offset = reduced_exit_state_header_offset_for_count(participant_pubkeys.len());
    raw[state_header_offset..state_header_offset + STATE_HEADER_LEN].copy_from_slice(state_header);
    let descriptor_offset = reduced_exit_descriptor_offset_for_count(participant_pubkeys.len());
    raw[descriptor_offset..descriptor_offset + descriptor.len()].copy_from_slice(descriptor);
    for index in 0..FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize {
        let before_offset = reduced_exit_right_offset_for_count(
            participant_pubkeys.len(),
            false,
            descriptor.len(),
            index,
        );
        raw[before_offset..before_offset + FACTORY_RIGHT_LEN].copy_from_slice(&before[index]);
        let after_offset = reduced_exit_right_offset_for_count(
            participant_pubkeys.len(),
            true,
            descriptor.len(),
            index,
        );
        raw[after_offset..after_offset + FACTORY_RIGHT_LEN].copy_from_slice(&after[index]);
    }
    Ok(raw)
}

fn reduced_exit_rights_pair(
    reserve_claim: ReducedExitReserveClaim,
) -> (
    [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
    [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
) {
    let before = [
        factory_right_bytes(1, 10, 0, 100),
        factory_right_bytes_with_asset(
            1,
            10,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim.before_quantity,
            reserve_claim.asset_type,
        ),
        factory_right_bytes(1, 10, 2, 1),
        factory_right_bytes(1, 10, 3, 1),
        factory_right_bytes(1, 10, 4, 20),
        factory_right_bytes_with_asset(
            1,
            11,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim.ckb_before_quantity,
            None,
        ),
        factory_right_bytes(2, 10, 0, 100),
        factory_right_bytes(2, 10, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 50),
        factory_right_bytes(2, 10, 2, 1),
        factory_right_bytes(2, 10, 3, 1),
        factory_right_bytes(2, 10, 4, 20),
        factory_right_bytes_with_asset(
            2,
            11,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim.ckb_before_quantity,
            None,
        ),
    ];
    let mut after = before;
    after[1] = factory_right_bytes_with_asset(
        1,
        10,
        FACTORY_RIGHT_KIND_RESERVE_CLAIM,
        reserve_claim.after_quantity,
        reserve_claim.asset_type,
    );
    after[5] = factory_right_bytes_with_asset(
        1,
        11,
        FACTORY_RIGHT_KIND_RESERVE_CLAIM,
        reserve_claim.ckb_after_quantity,
        None,
    );
    (before, after)
}

fn factory_right_bytes(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
) -> [u8; FACTORY_RIGHT_LEN] {
    factory_right_bytes_with_asset(participant, subchannel, kind, quantity, None)
}

fn factory_right_bytes_with_asset(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
    asset_type: Option<[u8; BYTE32_LEN]>,
) -> [u8; FACTORY_RIGHT_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_LEN];
    raw[0..BYTE32_LEN].fill(participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].fill(subchannel);
    raw[2 * BYTE32_LEN] = kind;
    if let Some(asset_type) = asset_type {
        raw[2 * BYTE32_LEN + 1] = 1;
        raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
    }
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, quantity);
    raw
}

fn sign_reduced_exit_witness(
    witness: &mut [u8],
    participant: [u8; BYTE32_LEN],
    key: &SigningKey,
    digest: &[u8; BYTE32_LEN],
) -> Result<()> {
    let sig = ecdsa_signature(key, digest)?;
    let participant_count = usize::from(
        *witness
            .get(3)
            .ok_or_else(|| anyhow!("factory reduced-exit witness is truncated"))?,
    );
    for index in 0..participant_count {
        let offset = reduced_exit_participant_offset(index);
        if &witness[offset..offset + BYTE32_LEN] == participant.as_slice() {
            let signature_offset = offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            witness[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
            return Ok(());
        }
    }
    Err(anyhow!(
        "participant not present in reduced factory exit witness"
    ))
}

fn reduced_exit_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn reduced_exit_touched_offset_for_count(participant_count: usize) -> usize {
    8 + participant_count * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn reduced_exit_release_quantity_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_touched_offset_for_count(participant_count) + BYTE32_LEN
}

fn reduced_exit_state_output_index_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_release_quantity_offset_for_count(participant_count) + 16
}

fn reduced_exit_vault_output_index_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_state_output_index_offset_for_count(participant_count) + 4
}

fn reduced_exit_state_type_hash_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_vault_output_index_offset_for_count(participant_count) + 4
}

fn reduced_exit_vault_lock_hash_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_state_type_hash_offset_for_count(participant_count) + BYTE32_LEN
}

fn reduced_exit_state_lock_hash_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_vault_lock_hash_offset_for_count(participant_count) + BYTE32_LEN
}

fn reduced_exit_state_header_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_state_lock_hash_offset_for_count(participant_count) + BYTE32_LEN
}

fn reduced_exit_descriptor_offset_for_count(participant_count: usize) -> usize {
    reduced_exit_state_header_offset_for_count(participant_count) + STATE_HEADER_LEN
}

fn reduced_exit_right_offset_for_count(
    participant_count: usize,
    after: bool,
    descriptor_len: usize,
    index: usize,
) -> usize {
    let before_offset =
        reduced_exit_descriptor_offset_for_count(participant_count) + descriptor_len;
    if after {
        before_offset
            + FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN
            + index * FACTORY_RIGHT_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_LEN
    }
}

fn reduced_exit_participants_commitment(raw: &[u8]) -> Result<[u8; BYTE32_LEN]> {
    FactoryReducedExitWitness::parse(raw)
        .map(|witness| witness.participants_commitment())
        .map_err(|err| anyhow!("invalid reduced-exit witness: {err:?}"))
}

fn reduced_exit_rights_root(raw: &[u8], after: bool) -> Result<[u8; BYTE32_LEN]> {
    FactoryReducedExitWitness::parse(raw)
        .map_err(|err| anyhow!("invalid reduced-exit witness: {err:?}"))?
        .rights_root(after)
        .map_err(|err| anyhow!("failed to compute reduced-exit root: {err:?}"))
}

fn reduced_exit_access_manifest_root(raw: &[u8], after: bool) -> Result<[u8; BYTE32_LEN]> {
    FactoryReducedExitWitness::parse(raw)
        .map_err(|err| anyhow!("invalid reduced-exit witness: {err:?}"))?
        .access_manifest_root(after)
        .map_err(|err| anyhow!("failed to compute reduced-exit access root: {err:?}"))
}

fn reduced_exit_non_interference_digest(
    raw: &[u8],
    old_header: &FactoryStateHeader<'_>,
    new_header: &FactoryStateHeader<'_>,
) -> Result<[u8; BYTE32_LEN]> {
    FactoryReducedExitWitness::parse(raw)
        .map_err(|err| anyhow!("invalid reduced-exit witness: {err:?}"))?
        .non_interference_digest(old_header, new_header)
        .map_err(|err| anyhow!("failed to compute reduced-exit digest: {err:?}"))
}

fn reduced_exit_local_exit_digest(raw: &[u8]) -> Result<[u8; BYTE32_LEN]> {
    FactoryReducedExitWitness::parse(raw)
        .map(|witness| witness.local_exit_digest())
        .map_err(|err| anyhow!("invalid reduced-exit witness: {err:?}"))
}

fn verify_reduced_exit_witness_any(
    old_header: &FactoryStateHeader<'_>,
    new_header: &FactoryStateHeader<'_>,
    raw: &[u8],
) -> Result<()> {
    let witness = FactoryReducedExitWitness::parse(raw)
        .map_err(|err| anyhow!("invalid reduced-exit witness: {err:?}"))?;
    verify_factory_reduced_exit_update(old_header, new_header, &witness)
        .map_err(|err| anyhow!("constructed reduced-exit update is invalid: {err:?}"))
}

#[allow(clippy::too_many_arguments)]
fn factory_local_exit_witness(
    factory_signature: &[u8],
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    state_header: &[u8],
    descriptor: &[u8],
) -> Result<Vec<u8>> {
    morph_script_common::FactorySignatureWitness::parse(factory_signature)
        .map_err(|err| anyhow!("invalid factory signature witness: {err:?}"))?;
    ensure!(
        state_type_hash.len() == BYTE32_LEN,
        "state type hash must be 32 bytes"
    );
    ensure!(
        vault_lock_hash.len() == BYTE32_LEN,
        "vault lock hash must be 32 bytes"
    );
    ensure!(
        state_lock_hash.len() == BYTE32_LEN,
        "state lock hash must be 32 bytes"
    );
    ensure!(
        state_header.len() == STATE_HEADER_LEN,
        "exit state header must be {} bytes",
        STATE_HEADER_LEN
    );
    ensure!(
        descriptor.len() == BILATERAL_CKB_DESCRIPTOR_LEN
            || descriptor.len() == BILATERAL_CKB_XUDT_DESCRIPTOR_LEN,
        "settlement descriptor must be {} or {} bytes",
        BILATERAL_CKB_DESCRIPTOR_LEN,
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN
    );

    let mut witness =
        vec![
            0u8;
            2 + factory_signature.len() + 8 + 3 * BYTE32_LEN + STATE_HEADER_LEN + descriptor.len()
        ];
    put_u16(&mut witness, 0, FACTORY_LOCAL_EXIT_WITNESS_VERSION);
    let mut offset = 2;
    witness[offset..offset + factory_signature.len()].copy_from_slice(factory_signature);
    offset += factory_signature.len();
    put_u32(&mut witness, offset, state_output_index);
    offset += 4;
    put_u32(&mut witness, offset, vault_output_index);
    offset += 4;
    witness[offset..offset + BYTE32_LEN].copy_from_slice(state_type_hash);
    offset += BYTE32_LEN;
    witness[offset..offset + BYTE32_LEN].copy_from_slice(vault_lock_hash);
    offset += BYTE32_LEN;
    witness[offset..offset + BYTE32_LEN].copy_from_slice(state_lock_hash);
    offset += BYTE32_LEN;
    witness[offset..offset + STATE_HEADER_LEN].copy_from_slice(state_header);
    offset += STATE_HEADER_LEN;
    witness[offset..offset + descriptor.len()].copy_from_slice(descriptor);
    Ok(witness)
}

fn witness_with_input_type(input_type: Bytes) -> ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .input_type(Some(input_type).pack())
        .build()
        .as_bytes()
        .pack()
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

fn relative_block_since_arg(blocks: u64) -> Result<u64> {
    relative_block_since(blocks)
        .map_err(|_| anyhow!("finalise_since must fit in the CKB since 56-bit value field"))
}

fn state_type_args(funding_anchor: &[u8; BYTE32_LEN], finalise_since: u64) -> Bytes {
    let mut args = funding_anchor.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    Bytes::from(args)
}

fn factory_state_type_args(
    funding_anchor: &[u8; BYTE32_LEN],
    factory_type_hash: &[u8; BYTE32_LEN],
    finalise_since: u64,
) -> Bytes {
    let mut args = funding_anchor.to_vec();
    args.extend_from_slice(factory_type_hash);
    args.extend_from_slice(&finalise_since.to_le_bytes());
    Bytes::from(args)
}

fn vault_lock_args(
    funding_anchor: &[u8; BYTE32_LEN],
    finalise_since: u64,
    state_type: &Script,
    state_lock: &Script,
    batch_lock_code_hash: &H256,
    batch_lock_hash_type: ScriptHashType,
) -> Bytes {
    let mut args = funding_anchor.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args.extend_from_slice(state_type.code_hash().as_slice());
    args.push(state_type.hash_type().as_slice()[0]);
    args.extend_from_slice(state_lock.code_hash().as_slice());
    args.push(state_lock.hash_type().as_slice()[0]);
    args.extend_from_slice(batch_lock_code_hash.as_bytes());
    args.push(batch_lock_hash_type as u8);
    Bytes::from(args)
}

fn set_state_vault_materialisation_root(state_header: &mut [u8], commitment: [u8; BYTE32_LEN]) {
    state_header[248..280].copy_from_slice(&commitment);
}

fn set_state_vault_outpoint_commitment(
    state_header: &mut [u8],
    tx_hash: &[u8; BYTE32_LEN],
    index: u32,
) {
    state_header[314..346].copy_from_slice(&vault_outpoint_commitment(tx_hash, index));
}

fn set_factory_vault_outpoint_commitment(
    factory_header: &mut [u8],
    tx_hash: &[u8; BYTE32_LEN],
    index: u32,
) {
    factory_header[270..302].copy_from_slice(&vault_outpoint_commitment(tx_hash, index));
}

fn ensure_vault_outpoint_binding(
    label: &str,
    expected_commitment: &[u8],
    out_point: &OutPoint,
) -> Result<()> {
    let tx_hash = out_point.tx_hash();
    let mut tx_hash_bytes = [0u8; BYTE32_LEN];
    tx_hash_bytes.copy_from_slice(tx_hash.as_slice());
    let index: u32 = out_point.index().unpack();
    ensure!(
        expected_commitment == vault_outpoint_commitment(&tx_hash_bytes, index),
        "{label} does not match the exact VaultCell OutPoint committed by the live state"
    );
    Ok(())
}

fn direct_cell_dep(out_point: OutPoint) -> CellDep {
    CellDep::new_builder()
        .out_point(out_point)
        .dep_type(DepType::Code)
        .build()
}

fn funding_out_points(
    tx_hash: &str,
    state_output_index: u32,
    vault_output_index: u32,
) -> Result<(OutPoint, OutPoint, [u8; BYTE32_LEN])> {
    let tx_hash = parse_h256(tx_hash)?;
    let mut tx_hash_bytes = [0u8; BYTE32_LEN];
    tx_hash_bytes.copy_from_slice(tx_hash.as_bytes());
    Ok((
        OutPoint::new(tx_hash.clone().pack(), state_output_index),
        OutPoint::new(tx_hash.pack(), vault_output_index),
        tx_hash_bytes,
    ))
}

#[allow(clippy::too_many_arguments)]
fn activate_state_vault_binding(
    rpc: &CkbRpcClient,
    funding_tx_hash: &str,
    funding_state_output: &CellOutput,
    state_header: &[u8; STATE_HEADER_LEN],
    state_lock_contract: &ResolvedContract,
    state_contract: &ResolvedContract,
    state_output_index: u32,
    vault_output_index: u32,
    mine_blocks: u64,
) -> Result<(SentTransactionReport, CellOutput, [u8; STATE_HEADER_LEN])> {
    let (state_out_point, vault_out_point, tx_hash_bytes) =
        funding_out_points(funding_tx_hash, state_output_index, vault_output_index)?;
    let funding_capacity: u64 = funding_state_output.capacity().unpack();
    let state_capacity = funding_capacity
        .checked_sub(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("StateCell cannot fund vault activation"))?;
    let state_output = funding_state_output
        .clone()
        .as_builder()
        .capacity(state_capacity)
        .build();
    ensure_output_capacity("activated state", &state_output, state_header.len())?;
    let mut activated_header = *state_header;
    set_state_vault_outpoint_commitment(&mut activated_header, &tx_hash_bytes, vault_output_index);
    let tx = TransactionBuilder::default()
        .cell_dep(direct_cell_dep(vault_out_point))
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(state_contract.cell_dep.clone())
        .input(CellInput::new(state_out_point, 0))
        .output(state_output.clone())
        .output_data(Bytes::copy_from_slice(&activated_header).pack())
        .build();
    let sent = send_and_mine(rpc, tx, mine_blocks)?;
    Ok((sent, state_output, activated_header))
}

#[allow(clippy::too_many_arguments)]
fn activate_factory_vault_binding(
    rpc: &CkbRpcClient,
    funding_tx_hash: &str,
    funding_factory_output: &CellOutput,
    factory_header: &[u8; FACTORY_STATE_HEADER_LEN],
    state_lock_contract: &ResolvedContract,
    factory_contract: &ResolvedContract,
    factory_output_index: u32,
    vault_output_index: u32,
    mine_blocks: u64,
) -> Result<(
    SentTransactionReport,
    CellOutput,
    [u8; FACTORY_STATE_HEADER_LEN],
)> {
    let (factory_out_point, vault_out_point, tx_hash_bytes) =
        funding_out_points(funding_tx_hash, factory_output_index, vault_output_index)?;
    let funding_capacity: u64 = funding_factory_output.capacity().unpack();
    let factory_capacity = funding_capacity
        .checked_sub(STATE_CARRIER_ACTIVATION_FEE)
        .ok_or_else(|| anyhow!("FactoryStateCell cannot fund vault activation"))?;
    let factory_output = funding_factory_output
        .clone()
        .as_builder()
        .capacity(factory_capacity)
        .build();
    ensure_output_capacity("activated factory", &factory_output, factory_header.len())?;
    let mut activated_header = *factory_header;
    set_factory_vault_outpoint_commitment(
        &mut activated_header,
        &tx_hash_bytes,
        vault_output_index,
    );
    let tx = TransactionBuilder::default()
        .cell_dep(direct_cell_dep(vault_out_point))
        .cell_dep(state_lock_contract.cell_dep.clone())
        .cell_dep(factory_contract.cell_dep.clone())
        .input(CellInput::new(factory_out_point, 0))
        .output(factory_output.clone())
        .output_data(Bytes::copy_from_slice(&activated_header).pack())
        .build();
    let sent = send_and_mine(rpc, tx, mine_blocks)?;
    Ok((sent, factory_output, activated_header))
}

fn vault_cell_commitment_from_output(output: &CellOutput, data: &[u8]) -> [u8; BYTE32_LEN] {
    let type_hash = output.type_().to_opt().map(|script| {
        let hash: [u8; BYTE32_LEN] = script.calc_script_hash().unpack();
        hash
    });
    vault_cell_commitment(
        output.lock().calc_script_hash().as_slice(),
        output.capacity().unpack(),
        type_hash.as_ref().map(|hash| hash.as_slice()),
        data,
    )
}

fn derive_funding_anchor(input: &CellInput, output_index: u64) -> [u8; 32] {
    script_blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
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

fn bilateral_ckb_descriptor(
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
) -> [u8; BILATERAL_CKB_DESCRIPTOR_LEN] {
    let mut entries = [
        (left_lock_hash, left_capacity),
        (right_lock_hash, right_capacity),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_DESCRIPTOR_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_DESCRIPTOR_VERSION);
    raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
    raw[3] = 0;
    for (index, (lock_hash, capacity)) in entries.iter().enumerate() {
        let offset = 4 + index * (BYTE32_LEN + 8);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
    }
    raw
}

fn bilateral_ckb_xudt_descriptor(
    xudt_type_hash: [u8; 32],
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    left_amount: u128,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
    right_amount: u128,
) -> [u8; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN] {
    let mut entries = [
        (left_lock_hash, left_capacity, left_amount),
        (right_lock_hash, right_capacity, right_amount),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
    raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT;
    raw[4..36].copy_from_slice(&xudt_type_hash);
    for (index, (lock_hash, capacity, amount)) in entries.iter().enumerate() {
        let offset = 36 + index * (BYTE32_LEN + 8 + 16);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
        put_u128(&mut raw, offset + BYTE32_LEN + 8, *amount);
    }
    raw
}

fn xudt_amount_bytes(amount: u128) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes())
}

fn xudt_amount_from_data(data: &Bytes) -> Result<u128> {
    ensure!(data.len() == 16, "xUDT cell data must be exactly 16 bytes");
    let mut raw = [0u8; 16];
    raw.copy_from_slice(data.as_ref());
    Ok(u128::from_le_bytes(raw))
}

fn settlement_split(
    vault_capacity: u64,
    alice_capacity: Option<u64>,
    bob_capacity: Option<u64>,
) -> Result<(u64, u64)> {
    match (alice_capacity, bob_capacity) {
        (None, None) => {
            let alice = vault_capacity / 2;
            let bob = vault_capacity
                .checked_sub(alice)
                .ok_or_else(|| anyhow!("vault capacity split underflow"))?;
            Ok((alice, bob))
        }
        (Some(alice), Some(bob)) => {
            ensure!(
                alice.checked_add(bob) == Some(vault_capacity),
                "alice capacity plus bob capacity must equal vault capacity"
            );
            Ok((alice, bob))
        }
        _ => Err(anyhow!(
            "alice and bob capacities must either both be provided or both be omitted"
        )),
    }
}

fn proportional_capacity_split(new_total: u64, old_alice: u64, old_bob: u64) -> Result<(u64, u64)> {
    let old_total = old_alice
        .checked_add(old_bob)
        .ok_or_else(|| anyhow!("old settlement capacity overflows"))?;
    ensure!(old_total > 0, "old settlement capacity must be non-zero");
    let alice = (u128::from(new_total) * u128::from(old_alice) / u128::from(old_total))
        .try_into()
        .context("post-splice Alice capacity does not fit in u64")?;
    let bob = new_total
        .checked_sub(alice)
        .ok_or_else(|| anyhow!("post-splice capacity split underflows"))?;
    Ok((alice, bob))
}

fn proportional_xudt_split(
    new_total: u128,
    old_alice: u128,
    old_bob: u128,
) -> Result<(u128, u128)> {
    let old_total = old_alice
        .checked_add(old_bob)
        .ok_or_else(|| anyhow!("old xUDT settlement amount overflows"))?;
    ensure!(old_total > 0, "old xUDT settlement amount must be non-zero");
    let alice = new_total
        .checked_mul(old_alice)
        .ok_or_else(|| anyhow!("post-splice Alice xUDT amount overflows"))?
        / old_total;
    let bob = new_total
        .checked_sub(alice)
        .ok_or_else(|| anyhow!("post-splice xUDT split underflows"))?;
    Ok((alice, bob))
}

#[derive(Debug, Clone, Copy)]
struct CkbSpliceDelta {
    external_input: u64,
    signed_fee: u64,
}

#[derive(Debug, Clone)]
struct LiveXudtAsset {
    type_script: Script,
    type_hash: [u8; BYTE32_LEN],
    amount: u128,
}

#[derive(Debug, Clone, Copy)]
struct XudtSpliceDelta {
    type_hash: [u8; BYTE32_LEN],
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
}

#[derive(Debug, Clone)]
struct SpliceApplicationAssets {
    old_vault_capacity: u64,
    new_vault_capacity: u64,
    ckb_delta: Option<CkbSpliceDelta>,
    ckb_withdrawal: u64,
    xudt: Option<XudtSpliceDelta>,
}

fn live_vault_xudt_asset(cell: &LiveCellDetails) -> Result<Option<LiveXudtAsset>> {
    match cell.output.type_().to_opt() {
        Some(type_script) => {
            let type_hash: [u8; BYTE32_LEN] = type_script.calc_script_hash().unpack();
            Ok(Some(LiveXudtAsset {
                type_script,
                type_hash,
                amount: xudt_amount_from_data(&cell.data)?,
            }))
        }
        None => {
            ensure!(
                cell.data.is_empty(),
                "plain CKB VaultCell must not carry data"
            );
            Ok(None)
        }
    }
}

fn live_vault_assets(
    ckb_amount: u128,
    xudt_type_hash: Option<[u8; BYTE32_LEN]>,
    xudt_amount: Option<u128>,
) -> Vec<VaultAssetAmount> {
    let mut assets = vec![VaultAssetAmount {
        asset: VaultAsset::Ckb,
        amount: ckb_amount,
    }];
    if let (Some(type_hash), Some(amount)) = (xudt_type_hash, xudt_amount) {
        assets.push(VaultAssetAmount {
            asset: VaultAsset::Xudt(type_hash),
            amount,
        });
    }
    assets
}

fn factory_vault_amount(descriptor: &FactoryVaultDescriptor, asset: &VaultAsset) -> Option<u128> {
    descriptor
        .assets
        .iter()
        .find(|amount| &amount.asset == asset)
        .map(|amount| amount.amount)
}

fn core_state_cell_from_live(
    header: &WireStateHeader<'_>,
    cell: &LiveCellDetails,
) -> Result<CoreStateCell> {
    Ok(CoreStateCell {
        header: StateHeader {
            protocol_version: header.protocol_version(),
            chain_id: bytes32_from_slice("state chain_id", header.chain_id())?,
            signature_scheme_id: header.signature_scheme_id(),
            channel_id: bytes32_from_slice("state channel_id", header.channel_id())?,
            funding_epoch: header.funding_epoch(),
            funding_anchor: bytes32_from_slice("state funding_anchor", header.funding_anchor())?,
            vault_set_commitment: bytes32_from_slice(
                "state vault_set_commitment",
                header.vault_set_commitment(),
            )?,
            state_number: header.state_number(),
            mode: core_mode_from_wire(header.mode())?,
            phase: core_phase_from_wire(header.phase())?,
            participants_commitment: bytes32_from_slice(
                "state participants_commitment",
                header.participants_commitment(),
            )?,
            asset_registry_commitment: bytes32_from_slice(
                "state asset_registry_commitment",
                header.asset_registry_commitment(),
            )?,
            settlement_descriptor_commitment: bytes32_from_slice(
                "state settlement_descriptor_commitment",
                header.settlement_descriptor_commitment(),
            )?,
            descriptor_version: header.descriptor_version(),
            vault_materialisation_root: bytes32_from_slice(
                "state vault_materialisation_root",
                header.vault_materialisation_root(),
            )?,
            vault_outpoint_commitment: bytes32_from_slice(
                "state vault_outpoint_commitment",
                header.vault_outpoint_commitment(),
            )?,
            challenge_policy_commitment: bytes32_from_slice(
                "state challenge_policy_commitment",
                header.challenge_policy_commitment(),
            )?,
            state_layout_version: header.state_layout_version(),
        },
        capacity: cell.capacity,
        occupied_capacity: occupied_capacity(&cell.output, cell.data.len())?,
    })
}

fn core_mode_from_wire(value: u8) -> Result<Mode> {
    match value {
        1 => Ok(Mode::BilateralPlain),
        2 => Ok(Mode::FactoryProof),
        other => Err(anyhow!("unsupported StateHeader mode byte {other}")),
    }
}

fn core_phase_from_wire(value: u8) -> Result<Phase> {
    match value {
        0 => Ok(Phase::Funding),
        1 => Ok(Phase::Active),
        2 => Ok(Phase::Settling),
        3 => Ok(Phase::Closed),
        other => Err(anyhow!("unsupported StateHeader phase byte {other}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_splice_funding_anchor(
    old_funding_anchor: &[u8; BYTE32_LEN],
    state_out_point: &OutPoint,
    vault_out_point: &OutPoint,
    old_funding_epoch: u64,
    new_funding_epoch: u64,
    splice_number: u64,
    kind: DevnetSpliceKind,
    asset: DevnetSpliceAsset,
    xudt_type_hash: Option<&[u8; BYTE32_LEN]>,
    amount: u128,
) -> [u8; BYTE32_LEN] {
    let state = format_out_point(state_out_point);
    let vault = format_out_point(vault_out_point);
    let old_epoch = old_funding_epoch.to_le_bytes();
    let new_epoch = new_funding_epoch.to_le_bytes();
    let splice = splice_number.to_le_bytes();
    let kind = [match kind {
        DevnetSpliceKind::SpliceIn => 0,
        DevnetSpliceKind::SpliceOut => 1,
    }];
    let asset = [match asset {
        DevnetSpliceAsset::Ckb => 0,
        DevnetSpliceAsset::Xudt => 1,
    }];
    let empty_xudt_type_hash = [0u8; BYTE32_LEN];
    let xudt_type_hash = xudt_type_hash.unwrap_or(&empty_xudt_type_hash);
    let amount = amount.to_le_bytes();
    script_blake2b256(&[
        b"CKB_MORPH_DEVNET_SPLICE_ANCHOR",
        old_funding_anchor,
        state.as_bytes(),
        vault.as_bytes(),
        &old_epoch,
        &new_epoch,
        &splice,
        &kind,
        &asset,
        xudt_type_hash,
        &amount,
    ])
}

fn ckb_vault_amount(descriptor: &morph_core::types::VaultDescriptor) -> Result<u64> {
    let amount = descriptor
        .assets
        .iter()
        .find(|amount| matches!(amount.asset, VaultAsset::Ckb))
        .ok_or_else(|| anyhow!("splice vault descriptor does not contain CKB"))?
        .amount;
    u64::try_from(amount).context("CKB vault amount does not fit in u64 capacity")
}

fn ckb_withdrawal_amount(transition: &SpliceTransition) -> Result<u64> {
    let amount = transition
        .withdrawals
        .iter()
        .find(|amount| matches!(amount.asset, VaultAsset::Ckb))
        .map(|amount| amount.amount)
        .unwrap_or_default();
    u64::try_from(amount).context("CKB withdrawal amount does not fit in u64 capacity")
}

fn ckb_splice_delta(transition: &SpliceTransition) -> Result<CkbSpliceDelta> {
    let delta = transition
        .deltas
        .iter()
        .find(|delta| matches!(delta.asset, VaultAsset::Ckb))
        .ok_or_else(|| anyhow!("splice package does not contain a CKB delta"))?;
    Ok(CkbSpliceDelta {
        external_input: u64::try_from(delta.external_input)
            .context("CKB external input does not fit in u64 capacity")?,
        signed_fee: u64::try_from(delta.signed_fee)
            .context("CKB signed fee does not fit in u64 capacity")?,
    })
}

fn splice_application_assets(transition: &SpliceTransition) -> Result<SpliceApplicationAssets> {
    ensure!(
        transition.deltas.len() == 1,
        "devnet apply-splice currently supports exactly one CKB or xUDT asset delta"
    );
    let old_vault_capacity = ckb_vault_amount(&transition.old_vault)?;
    let new_vault_capacity = ckb_vault_amount(&transition.new_vault)?;
    let ckb_withdrawal = ckb_withdrawal_amount(transition)?;
    let old_xudt = xudt_vault_amount(&transition.old_vault)?;
    let new_xudt = xudt_vault_amount(&transition.new_vault)?;

    let mut ckb_delta = None;
    let mut xudt = None;
    let delta = &transition.deltas[0];
    match &delta.asset {
        VaultAsset::Ckb => {
            ensure!(
                old_xudt == new_xudt,
                "devnet apply-splice cannot change xUDT amounts without an xUDT delta"
            );
            ckb_delta = Some(ckb_splice_delta(transition)?);
        }
        VaultAsset::Xudt(type_hash) => {
            ensure!(
                delta.signed_fee == 0,
                "xUDT splice deltas cannot carry signed CKB fees"
            );
            match transition.header.kind {
                SpliceKind::In => ensure!(
                    delta.external_input > 0
                        && delta.withdrawal == 0
                        && delta.new_amount > delta.old_amount,
                    "xUDT splice-in must increase the vault amount with an external typed input"
                ),
                SpliceKind::Out => ensure!(
                    delta.external_input == 0
                        && delta.withdrawal > 0
                        && delta.new_amount < delta.old_amount,
                    "xUDT splice-out must decrease the vault amount with a typed withdrawal"
                ),
            }
            ensure!(
                old_vault_capacity == new_vault_capacity && ckb_withdrawal == 0,
                "xUDT-only splice must not change CKB vault capacity"
            );
            let old_xudt =
                old_xudt.ok_or_else(|| anyhow!("old vault descriptor does not contain xUDT"))?;
            let new_xudt =
                new_xudt.ok_or_else(|| anyhow!("new vault descriptor does not contain xUDT"))?;
            ensure!(
                old_xudt.0 == *type_hash && new_xudt.0 == *type_hash,
                "xUDT delta type hash does not match vault descriptors"
            );
            ensure!(
                old_xudt.1 == delta.old_amount && new_xudt.1 == delta.new_amount,
                "xUDT delta amounts do not match vault descriptors"
            );
            xudt = Some(XudtSpliceDelta {
                type_hash: *type_hash,
                old_amount: delta.old_amount,
                new_amount: delta.new_amount,
                external_input: delta.external_input,
                withdrawal: delta.withdrawal,
            });
        }
    }

    Ok(SpliceApplicationAssets {
        old_vault_capacity,
        new_vault_capacity,
        ckb_delta,
        ckb_withdrawal,
        xudt,
    })
}

fn xudt_vault_amount(
    descriptor: &morph_core::types::VaultDescriptor,
) -> Result<Option<([u8; BYTE32_LEN], u128)>> {
    let mut found = None;
    for amount in &descriptor.assets {
        if let VaultAsset::Xudt(type_hash) = &amount.asset {
            ensure!(
                found.is_none(),
                "splice vault descriptor contains multiple xUDT assets"
            );
            found = Some((*type_hash, amount.amount));
        }
    }
    Ok(found)
}

struct InitialStateHeader {
    chain_id: [u8; 32],
    channel_id: [u8; 32],
    funding_anchor: [u8; 32],
    vault_set_commitment: [u8; 32],
    participants_commitment: [u8; 32],
    asset_registry_commitment: [u8; 32],
    settlement_descriptor_commitment: [u8; 32],
    descriptor_version: u16,
    challenge_policy_commitment: [u8; 32],
}

struct FactoryHeaderInput {
    chain_id: [u8; 32],
    factory_id: [u8; 32],
    update_number: u64,
    state_root: [u8; 32],
    participants_commitment: [u8; 32],
    access_manifest_root: [u8; 32],
    non_interference_digest: [u8; 32],
    challenge_policy_commitment: [u8; 32],
    vault_materialisation_root: [u8; 32],
}

fn initial_state_header(input: InitialStateHeader) -> [u8; STATE_HEADER_LEN] {
    encode_state_header(&StateHeaderInput {
        protocol_version: MORPH_PROTOCOL_VERSION,
        chain_id: input.chain_id,
        signature_scheme_id: SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
        channel_id: input.channel_id,
        funding_epoch: 0,
        funding_anchor: input.funding_anchor,
        vault_set_commitment: input.vault_set_commitment,
        state_number: 0,
        mode: STATE_MODE_BILATERAL_PLAINTEXT,
        phase: PHASE_ACTIVE,
        participants_commitment: input.participants_commitment,
        asset_registry_commitment: input.asset_registry_commitment,
        settlement_descriptor_commitment: input.settlement_descriptor_commitment,
        descriptor_version: input.descriptor_version,
        vault_materialisation_root: script_blake2b256(&[b"CKB_MORPH_EMPTY_BILATERAL_PAYLOAD"]),
        vault_outpoint_commitment: [0; BYTE32_LEN],
        challenge_policy_commitment: input.challenge_policy_commitment,
        state_layout_version: STATE_LAYOUT_VERSION,
    })
}

fn factory_state_header(input: FactoryHeaderInput) -> [u8; FACTORY_STATE_HEADER_LEN] {
    let mut raw = [0u8; FACTORY_STATE_HEADER_LEN];
    put_u16(&mut raw, 0, MORPH_PROTOCOL_VERSION);
    raw[2..34].copy_from_slice(&input.chain_id);
    put_u16(&mut raw, 34, SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B);
    raw[36..68].copy_from_slice(&input.factory_id);
    put_u64(&mut raw, 68, input.update_number);
    raw[76..108].copy_from_slice(&input.state_root);
    raw[108..140].copy_from_slice(&input.participants_commitment);
    raw[140..172].copy_from_slice(&input.access_manifest_root);
    raw[172..204].copy_from_slice(&input.non_interference_digest);
    raw[204..236].copy_from_slice(&input.challenge_policy_commitment);
    put_u16(&mut raw, 236, FACTORY_STATE_LAYOUT_VERSION);
    raw[238..270].copy_from_slice(&input.vault_materialisation_root);
    raw[270..302].fill(0);
    raw
}

type FactorySigningEntry = (
    [u8; BYTE32_LEN],
    [u8; COMPRESSED_SECP256K1_PUBKEY_LEN],
    SigningKey,
);

fn factory_signing_entries(
    alice_private_key: &str,
    bob_private_key: &str,
    additional_participant_private_keys: &[String],
) -> Result<Vec<FactorySigningEntry>> {
    let participant_count = 2usize
        .checked_add(additional_participant_private_keys.len())
        .ok_or_else(|| anyhow!("factory participant count overflow"))?;
    ensure!(
        participant_count >= FACTORY_MIN_PARTICIPANTS as usize
            && participant_count <= FACTORY_MAX_PARTICIPANTS as usize,
        "factory requires {}-{} participants, got {}",
        FACTORY_MIN_PARTICIPANTS,
        FACTORY_MAX_PARTICIPANTS,
        participant_count
    );
    let mut private_keys = Vec::with_capacity(participant_count);
    private_keys.push(alice_private_key);
    private_keys.push(bob_private_key);
    private_keys.extend(
        additional_participant_private_keys
            .iter()
            .map(String::as_str),
    );
    let mut entries = private_keys
        .into_iter()
        .enumerate()
        .map(|(index, private_key)| {
            let key = k256_signing_key(private_key).with_context(|| {
                format!("invalid factory participant {} private key", index + 1)
            })?;
            let participant_byte = u8::try_from(index + 1)
                .map_err(|_| anyhow!("factory participant index overflow"))?;
            Ok(([participant_byte; BYTE32_LEN], k256_pubkey(&key), key))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    ensure!(
        entries
            .iter()
            .enumerate()
            .all(|(index, entry)| entries[..index].iter().all(|other| other.1 != entry.1)),
        "factory participant public keys must be unique"
    );
    Ok(entries)
}

fn factory_participants_commitment_from_entries(entries: &[FactorySigningEntry]) -> [u8; 32] {
    let commitment_entries = entries
        .iter()
        .map(|(participant, pubkey, _)| (participant.as_slice(), pubkey.as_slice()))
        .collect::<Vec<_>>();
    factory_participants_commitment(entries.len() as u8, &commitment_entries)
}

fn factory_participant_reports(entries: &[FactorySigningEntry]) -> Vec<FactoryParticipantReport> {
    entries
        .iter()
        .enumerate()
        .map(
            |(index, (participant_id, pubkey, _))| FactoryParticipantReport {
                role: match index {
                    0 => "alice".to_string(),
                    1 => "bob".to_string(),
                    _ => format!("participant-{}", index + 1),
                },
                participant_id: hex32(participant_id),
                pubkey_sec1: hex_prefixed(pubkey),
            },
        )
        .collect()
}

fn factory_splice_reserve_rights(
    asset_type: Option<[u8; BYTE32_LEN]>,
    old_amount: u128,
    new_amount: u128,
) -> (Vec<FactoryRight>, Vec<FactoryRight>) {
    let before = vec![
        factory_splice_reserve_right([1u8; BYTE32_LEN], asset_type, old_amount),
        factory_splice_reserve_right([2u8; BYTE32_LEN], asset_type, 0),
    ];
    let mut after = before.clone();
    after[0].quantity = new_amount;
    (before, after)
}

fn factory_splice_reserve_right(
    participant: [u8; BYTE32_LEN],
    asset_type: Option<[u8; BYTE32_LEN]>,
    quantity: u128,
) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant,
            subchannel: [10u8; BYTE32_LEN],
            kind: FactoryRightKind::ReserveClaim,
            asset_type,
        },
        quantity,
    }
}

fn derived_factory_update_digest(
    domain: &[u8],
    previous_value: &[u8],
    update_number: u64,
) -> [u8; 32] {
    script_blake2b256(&[domain, previous_value, &update_number.to_le_bytes()])
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

fn factory_witness_envelope(kind: u16, body: &[u8]) -> Result<Vec<u8>> {
    let body_len: u32 = body
        .len()
        .try_into()
        .context("factory witness body length does not fit in u32")?;
    let mut raw = vec![0u8; WITNESS_ENVELOPE_LEN + body.len()];
    raw[0..WITNESS_ENVELOPE_MAGIC.len()].copy_from_slice(WITNESS_ENVELOPE_MAGIC);
    put_u16(&mut raw, 8, WITNESS_ENVELOPE_FORMAT);
    put_u16(&mut raw, 10, kind);
    put_u16(&mut raw, 12, 0);
    put_u32(&mut raw, 14, body_len);
    raw[18..50].copy_from_slice(&witness_envelope_body_commitment(kind, body));
    raw[WITNESS_ENVELOPE_LEN..].copy_from_slice(body);
    WitnessEnvelope::parse(&raw)
        .map_err(|err| anyhow!("encoded factory witness envelope is invalid: {err:?}"))?;
    Ok(raw)
}

fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

fn printable_out_point(out_point: &OutPoint) -> PrintableOutPoint {
    PrintableOutPoint {
        tx_hash: format!("{:#x}", byte32_to_h256(out_point.tx_hash())),
        index: out_point.index().unpack(),
    }
}

fn channel_cell_out_point(report: &OpenChannelReport, role: &str) -> Result<String> {
    report
        .cells
        .iter()
        .find(|cell| cell.role == role)
        .map(|cell| printable_out_point_string(&cell.out_point))
        .ok_or_else(|| anyhow!("open-channel report does not contain {role} cell"))
}

fn factory_cell_out_point(report: &OpenFactoryReport, role: &str) -> Result<String> {
    report
        .cells
        .iter()
        .find(|cell| cell.role == role)
        .map(|cell| printable_out_point_string(&cell.out_point))
        .ok_or_else(|| anyhow!("open-factory report does not contain {role} cell"))
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

fn parse_script_failure(raw: &str) -> ScriptFailureReport {
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
        value if value == ScriptError::NewStateNotActive as i16 => Some("NewStateNotActive"),
        value if value == ScriptError::VaultCellMissing as i16 => Some("VaultCellMissing"),
        value if value == ScriptError::VaultCellAmbiguous as i16 => Some("VaultCellAmbiguous"),
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
        value if value == ScriptError::SponsorChangeLockMismatch as i16 => {
            Some("SponsorChangeLockMismatch")
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
        value if value == ScriptError::SettlementDescriptorEncoding as i16 => {
            Some("SettlementDescriptorEncoding")
        }
        value if value == ScriptError::SettlementDescriptorMismatch as i16 => {
            Some("SettlementDescriptorMismatch")
        }
        value if value == ScriptError::SettlementOutputMismatch as i16 => {
            Some("SettlementOutputMismatch")
        }
        value if value == ScriptError::SponsorStateOutOfRange as i16 => {
            Some("SponsorStateOutOfRange")
        }
        value if value == ScriptError::XudtAmountEncoding as i16 => Some("XudtAmountEncoding"),
        value if value == ScriptError::XudtMintUnauthorised as i16 => Some("XudtMintUnauthorised"),
        value if value == ScriptError::XudtConservationMismatch as i16 => {
            Some("XudtConservationMismatch")
        }
        value if value == ScriptError::XudtTypeMismatch as i16 => Some("XudtTypeMismatch"),
        value if value == ScriptError::FactoryIdMismatch as i16 => Some("FactoryIdMismatch"),
        value if value == ScriptError::FactoryLocalExitMismatch as i16 => {
            Some("FactoryLocalExitMismatch")
        }
        value if value == ScriptError::FactoryReserveMismatch as i16 => {
            Some("FactoryReserveMismatch")
        }
        value if value == ScriptError::StateTypeMismatch as i16 => Some("StateTypeMismatch"),
        value if value == ScriptError::FactoryReducedProofEncoding as i16 => {
            Some("FactoryReducedProofEncoding")
        }
        value if value == ScriptError::FactoryReducedProofMismatch as i16 => {
            Some("FactoryReducedProofMismatch")
        }
        value if value == ScriptError::SponsorPolicyUnsupported as i16 => {
            Some("SponsorPolicyUnsupported")
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

fn parse_optional_hex32(label: &str, value: Option<&str>) -> Result<Option<[u8; 32]>> {
    value
        .map(|value| parse_hex32_array(label, value))
        .transpose()
}

fn parse_hex32_array(label: &str, value: &str) -> Result<[u8; 32]> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        stripped.len() == 64,
        "{label} must be a 32-byte hex string, got {} hex characters",
        stripped.len()
    );
    let decoded = hex::decode(stripped).with_context(|| format!("{label} is not valid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn bytes32_from_slice(label: &str, value: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 32,
        "{label} must be 32 bytes, got {}",
        value.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(value);
    Ok(out)
}

fn parse_h256(value: &str) -> Result<H256> {
    H256::from_str(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|err| anyhow!("invalid H256 {value}: {err:?}"))
}

fn parse_privkey(value: &str) -> Result<Privkey, ckb_crypto::secp::Error> {
    Privkey::from_str(value.strip_prefix("0x").unwrap_or(value))
}

fn blake160(data: &[u8]) -> [u8; 20] {
    let hash = blake2b_256(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[..20]);
    out
}

fn byte32_to_h256(value: ckb_types::packed::Byte32) -> H256 {
    (&value).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn watch_policy_covers_auto_funding_and_publication_fees() {
        assert_eq!(authorized_watch_fee(Some(20), 30, true), 30);
        assert_eq!(authorized_watch_fee(Some(40), 30, true), 40);
        assert_eq!(authorized_watch_fee(Some(20), 30, false), 20);
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
    fn splice_withdrawal_target_uses_canonical_participant_order() {
        let alice = private_key_from_scalar(1);
        let bob = private_key_from_scalar(2);
        let target = splice_withdrawal_lock_hash_from_keys(&alice, &bob).unwrap();
        let reversed = splice_withdrawal_lock_hash_from_keys(&bob, &alice).unwrap();

        assert_eq!(target, reversed);
    }

    #[test]
    fn reduced_exit_witness_needs_only_counterparty_public_key() {
        let alice = k256_signing_key(&private_key_from_scalar(1)).unwrap();
        let bob = k256_signing_key(&private_key_from_scalar(2)).unwrap();
        let alice_pubkey = k256_pubkey(&alice);
        let bob_pubkey = k256_pubkey(&bob);
        let descriptor = bilateral_ckb_descriptor([3u8; 32], 60, [4u8; 32], 40);
        let state_header = [0u8; STATE_HEADER_LEN];
        let reserve_claim = ReducedExitReserveClaim {
            release_quantity: 10,
            before_quantity: 50,
            after_quantity: 40,
            asset_type: None,
            ckb_before_quantity: 100,
            ckb_after_quantity: 100,
        };

        let from_keys = reduced_exit_witness_bytes(
            &alice,
            &bob,
            reserve_claim,
            1,
            2,
            &[5u8; 32],
            &[6u8; 32],
            &[7u8; 32],
            &state_header,
            &descriptor,
        )
        .unwrap();
        let from_public_keys = reduced_exit_witness_bytes_from_pubkeys(
            &[alice_pubkey, bob_pubkey],
            reserve_claim,
            1,
            2,
            &[5u8; 32],
            &[6u8; 32],
            &[7u8; 32],
            &state_header,
            &descriptor,
        )
        .unwrap();

        assert_eq!(from_public_keys, from_keys);
    }

    #[test]
    fn three_party_dynamic_factory_witnesses_round_trip() {
        let private_keys = [
            private_key_from_scalar(1),
            private_key_from_scalar(2),
            private_key_from_scalar(3),
        ];
        let entries = factory_signing_entries(
            &private_keys[0],
            &private_keys[1],
            &[private_keys[2].clone()],
        )
        .unwrap();
        let header = factory_state_header(FactoryHeaderInput {
            chain_id: [7u8; BYTE32_LEN],
            factory_id: [8u8; BYTE32_LEN],
            update_number: 1,
            state_root: [9u8; BYTE32_LEN],
            participants_commitment: factory_participants_commitment_from_entries(&entries),
            access_manifest_root: [10u8; BYTE32_LEN],
            non_interference_digest: [11u8; BYTE32_LEN],
            challenge_policy_commitment: [12u8; BYTE32_LEN],
            vault_materialisation_root: [13u8; BYTE32_LEN],
        });
        let signature = factory_signature_witness(
            &header,
            &private_keys[0],
            &private_keys[1],
            &[private_keys[2].clone()],
        )
        .unwrap();
        let parsed_header = FactoryStateHeader::parse(&header).unwrap();
        let parsed_signature =
            morph_script_common::FactorySignatureWitness::parse(&signature).unwrap();
        morph_script_common::verify_factory_state_signatures(&parsed_header, &parsed_signature)
            .unwrap();

        let descriptor = bilateral_ckb_descriptor([21u8; BYTE32_LEN], 60, [22u8; BYTE32_LEN], 40);
        let state_header = initial_state_header(InitialStateHeader {
            chain_id: [7u8; BYTE32_LEN],
            channel_id: [31u8; BYTE32_LEN],
            funding_anchor: [32u8; BYTE32_LEN],
            vault_set_commitment: [33u8; BYTE32_LEN],
            participants_commitment: [34u8; BYTE32_LEN],
            asset_registry_commitment: [35u8; BYTE32_LEN],
            settlement_descriptor_commitment: settlement_descriptor_commitment(&descriptor),
            descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
            challenge_policy_commitment: [36u8; BYTE32_LEN],
        });
        let exit_digest = factory_local_exit_digest(
            1,
            2,
            &[41u8; BYTE32_LEN],
            &[42u8; BYTE32_LEN],
            &[43u8; BYTE32_LEN],
            &state_header,
            &descriptor,
        );
        let exit_header = factory_state_header(FactoryHeaderInput {
            chain_id: [7u8; BYTE32_LEN],
            factory_id: [8u8; BYTE32_LEN],
            update_number: 2,
            state_root: [9u8; BYTE32_LEN],
            participants_commitment: factory_participants_commitment_from_entries(&entries),
            access_manifest_root: [10u8; BYTE32_LEN],
            non_interference_digest: exit_digest,
            challenge_policy_commitment: [12u8; BYTE32_LEN],
            vault_materialisation_root: [13u8; BYTE32_LEN],
        });
        let exit_signature = factory_signature_witness(
            &exit_header,
            &private_keys[0],
            &private_keys[1],
            &[private_keys[2].clone()],
        )
        .unwrap();
        let local_exit = factory_local_exit_witness(
            &exit_signature,
            1,
            2,
            &[41u8; BYTE32_LEN],
            &[42u8; BYTE32_LEN],
            &[43u8; BYTE32_LEN],
            &state_header,
            &descriptor,
        )
        .unwrap();
        assert!(morph_script_common::FactoryLocalExitWitness::parse(&local_exit).is_ok());
        let package =
            StoredFactoryLocalExitPackage::from_factory_local_exit(&exit_header, &local_exit)
                .unwrap();
        assert_eq!(
            package.contract_witness_bytes().unwrap()[10..12],
            morph_script_common::WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT.to_le_bytes()
        );
    }

    #[test]
    fn verifies_three_party_dynamic_reduced_exit_from_operator_builder() {
        let keys = [
            k256_signing_key(&private_key_from_scalar(1)).unwrap(),
            k256_signing_key(&private_key_from_scalar(2)).unwrap(),
            k256_signing_key(&private_key_from_scalar(3)).unwrap(),
        ];
        let pubkeys = [
            k256_pubkey(&keys[0]),
            k256_pubkey(&keys[1]),
            k256_pubkey(&keys[2]),
        ];
        let descriptor = bilateral_ckb_descriptor([21u8; BYTE32_LEN], 60, [22u8; BYTE32_LEN], 40);
        let state_header = initial_state_header(InitialStateHeader {
            chain_id: [7u8; BYTE32_LEN],
            channel_id: [31u8; BYTE32_LEN],
            funding_anchor: [32u8; BYTE32_LEN],
            vault_set_commitment: [33u8; BYTE32_LEN],
            participants_commitment: [34u8; BYTE32_LEN],
            asset_registry_commitment: [35u8; BYTE32_LEN],
            settlement_descriptor_commitment: settlement_descriptor_commitment(&descriptor),
            descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
            challenge_policy_commitment: [36u8; BYTE32_LEN],
        });
        let reserve_claim = ReducedExitReserveClaim {
            release_quantity: 100,
            before_quantity: 100,
            after_quantity: 0,
            asset_type: None,
            ckb_before_quantity: 100,
            ckb_after_quantity: 100,
        };
        let unsigned = reduced_exit_witness_bytes_from_pubkeys(
            &pubkeys,
            reserve_claim,
            1,
            2,
            &[41u8; BYTE32_LEN],
            &[42u8; BYTE32_LEN],
            &[43u8; BYTE32_LEN],
            &state_header,
            &descriptor,
        )
        .unwrap();
        let participants = reduced_exit_participants_commitment(&unsigned).unwrap();
        let old = factory_state_header(FactoryHeaderInput {
            chain_id: [7u8; BYTE32_LEN],
            factory_id: [8u8; BYTE32_LEN],
            update_number: 1,
            state_root: reduced_exit_rights_root(&unsigned, false).unwrap(),
            participants_commitment: participants,
            access_manifest_root: reduced_exit_access_manifest_root(&unsigned, false).unwrap(),
            non_interference_digest: [0u8; BYTE32_LEN],
            challenge_policy_commitment: [12u8; BYTE32_LEN],
            vault_materialisation_root: [13u8; BYTE32_LEN],
        })
        .to_vec();
        let mut new = old.clone();
        put_u64(&mut new, 68, 2);
        new[76..108].copy_from_slice(&reduced_exit_rights_root(&unsigned, true).unwrap());
        new[140..172].copy_from_slice(&reduced_exit_access_manifest_root(&unsigned, true).unwrap());
        let old_header = FactoryStateHeader::parse(&old).unwrap();
        let non_interference_digest = {
            let preliminary = FactoryStateHeader::parse(&new).unwrap();
            reduced_exit_non_interference_digest(&unsigned, &old_header, &preliminary).unwrap()
        };
        new[172..204].copy_from_slice(&non_interference_digest);
        let new_header = FactoryStateHeader::parse(&new).unwrap();
        let mut signed = unsigned;
        sign_reduced_exit_witness(
            &mut signed,
            [1u8; BYTE32_LEN],
            &keys[0],
            &new_header.signing_digest(),
        )
        .unwrap();
        verify_reduced_exit_witness_any(&old_header, &new_header, &signed).unwrap();
    }

    #[test]
    fn builds_three_party_dynamic_merkle_update_package() {
        let keys = vec![
            k256_signing_key(&private_key_from_scalar(1)).unwrap(),
            k256_signing_key(&private_key_from_scalar(2)).unwrap(),
            k256_signing_key(&private_key_from_scalar(3)).unwrap(),
        ];
        let participant_records = keys
            .iter()
            .enumerate()
            .map(|(index, key)| ([(index + 1) as u8; BYTE32_LEN], k256_pubkey(key)))
            .collect::<Vec<_>>();
        let participant_refs = participant_records
            .iter()
            .map(|(participant, pubkey)| (participant.as_slice(), pubkey.as_slice()))
            .collect::<Vec<_>>();
        let (state_root, access_manifest_root) = merkle_update_initial_roots().unwrap();
        let old_header = factory_state_header(FactoryHeaderInput {
            chain_id: [7u8; BYTE32_LEN],
            factory_id: [8u8; BYTE32_LEN],
            update_number: 1,
            state_root,
            participants_commitment: factory_participants_commitment(3, &participant_refs),
            access_manifest_root,
            non_interference_digest: [11u8; BYTE32_LEN],
            challenge_policy_commitment: [12u8; BYTE32_LEN],
            vault_materialisation_root: [13u8; BYTE32_LEN],
        });

        let package =
            merkle_update_package_from_factory_header(&old_header, &keys, Some(2), 900, None)
                .unwrap();
        let witness = package.witness_bytes().unwrap();
        assert!(FactoryMerkleUpdateWitness::parse(&witness).is_ok());
        assert_eq!(package.summary().unwrap().witness_len, witness.len());
    }

    #[test]
    fn factory_fee_signature_does_not_gate_the_factory_state_witness() {
        let key = parse_privkey(&private_key_from_scalar(1)).unwrap();
        let tx = TransactionBuilder::default()
            .input(CellInput::new(OutPoint::default(), 0))
            .input(CellInput::new(OutPoint::default(), 0))
            .build();
        let input_type = Bytes::from(vec![7u8; 32]);

        let signed = sign_factory_update_transaction(tx, &key, input_type.clone()).unwrap();
        let factory_witness =
            WitnessArgs::from_slice(signed.witnesses().get(0).unwrap().raw_data().as_ref())
                .unwrap();
        let fee_witness =
            WitnessArgs::from_slice(signed.witnesses().get(1).unwrap().raw_data().as_ref())
                .unwrap();

        assert!(factory_witness.lock().to_opt().is_none());
        assert_eq!(
            factory_witness.input_type().to_opt().unwrap().raw_data(),
            input_type
        );
        assert_eq!(fee_witness.lock().to_opt().unwrap().raw_data().len(), 65);
        assert!(fee_witness.input_type().to_opt().is_none());
    }

    #[test]
    fn xudt_settlement_output_uses_plain_cell_for_zero_descriptor_amount() {
        let private_key = private_key_from_scalar(2);
        let key = parse_privkey(&private_key).unwrap();
        let lock = secp256k1_lock(&key).unwrap();
        let xudt_type = data1_script(H256::from([0x42; BYTE32_LEN]), Bytes::new());

        let (zero_output, zero_data) =
            xudt_settlement_output(lock.clone(), &xudt_type, 10_000_000_000, 0, 0);
        assert!(zero_output.type_().to_opt().is_none());
        assert!(zero_data.is_empty());

        let (positive_output, positive_data) =
            xudt_settlement_output(lock.clone(), &xudt_type, 10_000_000_000, 1, 1);
        assert!(positive_output.type_().to_opt().is_some());
        assert_eq!(positive_data.as_ref(), &1u128.to_le_bytes());

        let (tampered_output, tampered_data) =
            xudt_settlement_output(lock, &xudt_type, 10_000_000_000, 0, 1);
        assert!(tampered_output.type_().to_opt().is_some());
        assert_eq!(tampered_data.as_ref(), &1u128.to_le_bytes());
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

        validate_sponsor_policy_owner(&policy, &channel_id, &change_lock).unwrap();
    }

    #[test]
    fn sponsor_owner_validation_rejects_truncated_policy_without_panicking() {
        let channel_id = [0x11; BYTE32_LEN];
        let change_lock = [0x22; BYTE32_LEN];
        let truncated = [0u8; SPONSOR_POLICY_LEN - 1];

        let err = validate_sponsor_policy_owner(&truncated, &channel_id, &change_lock).unwrap_err();

        assert!(
            err.to_string().contains("valid SponsorPolicy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn bilateral_state_creation_signer_carries_participant_witness() {
        let owner_key = parse_privkey(&private_key_from_scalar(3)).unwrap();
        let alice_private_key = private_key_from_scalar(1);
        let bob_private_key = private_key_from_scalar(2);
        let alice_key = k256_signing_key(&alice_private_key).unwrap();
        let bob_key = k256_signing_key(&bob_private_key).unwrap();
        let mut participant_pubkeys = [k256_pubkey(&alice_key), k256_pubkey(&bob_key)];
        participant_pubkeys.sort();
        let header = initial_state_header(InitialStateHeader {
            chain_id: [0x10; BYTE32_LEN],
            channel_id: [0x11; BYTE32_LEN],
            funding_anchor: [0x12; BYTE32_LEN],
            vault_set_commitment: [0x13; BYTE32_LEN],
            participants_commitment: participants_commitment(
                2,
                &[&participant_pubkeys[0], &participant_pubkeys[1]],
            ),
            asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
                xudt_types: BTreeSet::new(),
            }),
            settlement_descriptor_commitment: [0x14; BYTE32_LEN],
            descriptor_version: BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
            challenge_policy_commitment: [0x15; BYTE32_LEN],
        });

        let signed = sign_bilateral_state_creation(
            TransactionBuilder::default().build(),
            &owner_key,
            &header,
            &alice_private_key,
            &bob_private_key,
        )
        .unwrap();
        let witness = signed.witnesses().get(0).unwrap().raw_data();
        let witness_args = WitnessArgs::from_slice(witness.as_ref()).unwrap();
        let input_type = witness_args.input_type().to_opt().unwrap().raw_data();

        assert_eq!(input_type.len(), BILATERAL_SIGNATURE_WITNESS_LEN);
    }

    #[test]
    fn selects_latest_state_package_for_funding_anchor() {
        let old_anchor = format!("0x{}", "11".repeat(BYTE32_LEN));
        let new_anchor = format!("0x{}", "22".repeat(BYTE32_LEN));
        let new_context = format!("0x{}", "aa".repeat(BYTE32_LEN));
        let records = vec![
            state_package_record(&old_anchor, 2, 10, 1),
            {
                let mut record = state_package_record(&new_anchor, 1, 20, 2);
                record.package.funding_context_id = new_context.clone();
                record
            },
            state_package_record(&old_anchor, 3, 30, 3),
        ];

        let global = latest_state_package_record(&records).unwrap();
        assert_eq!(global.package.state_number, 3);
        assert_eq!(global.package.funding_anchor, old_anchor);

        let selected = latest_package_for_funding_anchor(&records, &new_anchor).unwrap();
        assert_eq!(selected.package.state_number, 1);
        assert_eq!(selected.package.funding_anchor, new_anchor);

        let selected = latest_package_for_funding_context(&records, &new_context).unwrap();
        assert_eq!(selected.package.state_number, 1);
        assert_eq!(selected.package.funding_context_id, new_context);
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
        let previous = WatchCursor::new(&channel_id, 10, 9)
            .unwrap()
            .with_observed_context_state(&funding_anchor, &funding_context_id, 5, "0xabc:0")
            .unwrap();

        let cursor =
            watch_cursor_for_state(&channel_id, 12, 11, None, None, Some(&previous)).unwrap();

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
        let header_bytes = initial_state_header(InitialStateHeader {
            chain_id: [0x44; BYTE32_LEN],
            channel_id: [0x55; BYTE32_LEN],
            funding_anchor,
            vault_set_commitment: [0x99; BYTE32_LEN],
            participants_commitment: [0x66; BYTE32_LEN],
            asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
                xudt_types: BTreeSet::new(),
            }),
            settlement_descriptor_commitment: [0x77; BYTE32_LEN],
            descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
            challenge_policy_commitment: [0x88; BYTE32_LEN],
        });
        let header = WireStateHeader::parse(&header_bytes).unwrap();
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
            &header,
            &filter
        ));

        let fake_data_only_output = CellOutput::new_builder()
            .capacity(10_000_000_000u64)
            .lock(state_lock.clone())
            .build();
        assert!(!is_authentic_observed_state_cell(
            &fake_data_only_output,
            &header,
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
            &header,
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
            &header,
            &filter
        ));
    }

    #[test]
    fn factory_signing_entries_reject_nonadjacent_duplicate_public_keys() {
        let alice = private_key_from_scalar(1);
        let bob = private_key_from_scalar(2);
        let error =
            factory_signing_entries(&alice, &bob, std::slice::from_ref(&alice)).unwrap_err();

        assert!(error.to_string().contains("public keys must be unique"));
    }

    fn state_package_record(
        funding_anchor: &str,
        state_number: u64,
        created_unix_ms: u64,
        digest_byte: u8,
    ) -> StatePackageRecord {
        StatePackageRecord {
            path: PathBuf::from(format!("state-{state_number}.json")),
            package: StoredStatePackage {
                schema: "morph.state_package".to_string(),
                created_unix_ms,
                channel_id: format!("0x{}", "99".repeat(BYTE32_LEN)),
                funding_anchor: funding_anchor.to_string(),
                funding_context_id: format!("0x{}", "00".repeat(BYTE32_LEN)),
                funding_epoch: 0,
                state_number,
                phase: "settling".to_string(),
                settlement_descriptor_commitment: format!("0x{}", "00".repeat(BYTE32_LEN)),
                descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
                signing_digest: format!("0x{}", format!("{digest_byte:02x}").repeat(BYTE32_LEN)),
                header_hex: "0x".to_string(),
                witness_hex: "0x".to_string(),
                source_state_out_point: None,
            },
        }
    }

    fn private_key_from_scalar(value: u8) -> String {
        let mut bytes = [0u8; BYTE32_LEN];
        bytes[BYTE32_LEN - 1] = value;
        format!("0x{}", hex::encode(bytes))
    }
}
