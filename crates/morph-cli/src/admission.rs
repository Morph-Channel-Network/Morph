//! Controlled-devnet Factory admission. This is operator authority, never a
//! consensus counter or production approval. Keep one stable ledger per pilot.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::*;
use morph_script_common::factory_multi_asset as wire;
use serde::{Deserialize, Serialize};

use crate::canonical_fields::hash;
#[cfg(any(feature = "devnet", test))]
use crate::multi_asset_packages::canonical_hex;
use crate::multi_asset_packages::read_bounded_json;
use crate::persistence::write_private_atomic;
use crate::persistence::{lock_private_path, require_private_file};
use crate::preproduction::PreproductionEnvelope;

const CONFIG_SCHEMA: &str = "morph.factory_experiment_admission.v1";
const LEDGER_SCHEMA: &str = "morph.factory_admission_ledger.v1";
const MAX_LEDGER_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionConfig {
    pub schema: String,
    pub envelope: PathBuf,
    pub ledger: PathBuf,
    pub artifact_identity: String,
    pub genesis_hash: String,
    pub rpc_url: String,
    pub no_real_assets: bool,
    pub admitted_asset_types: Vec<String>,
}

#[cfg(feature = "devnet")]
#[derive(Debug, clap::Args)]
pub(crate) struct ConfigOptions {
    #[arg(long, default_value = "release/factory-preproduction/envelope.json")]
    pub envelope: PathBuf,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub ledger: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long = "admitted-asset-type")]
    pub admitted_asset_types: Vec<String>,
    #[arg(long)]
    pub no_real_assets: bool,
}

#[cfg(feature = "devnet")]
pub(crate) fn create_config(
    rpc: &crate::rpc::CkbRpcClient,
    options: ConfigOptions,
) -> Result<serde_json::Value> {
    ensure!(
        options.no_real_assets && rpc.chain_info()?.chain.to_lowercase().contains("dev"),
        "admission configuration requires explicit --no-real-assets on controlled devnet"
    );
    let envelope = fs::canonicalize(options.envelope)?;
    let identity =
        crate::preproduction::verify_admission_identity(&envelope, &options.contracts_dir)?;
    let parent = options
        .ledger
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::persistence::create_private_directories(parent)?;
    let ledger = fs::canonicalize(parent)?.join(
        options
            .ledger
            .file_name()
            .context("ledger requires a stable filename")?,
    );
    let mut types = options
        .admitted_asset_types
        .iter()
        .map(|value| hash(value))
        .collect::<Result<Vec<_>>>()?;
    types.sort();
    ensure!(
        types.windows(2).all(|pair| pair[0] < pair[1]) && !types.contains(&[0; 32]),
        "admitted Type hashes must be nonzero and unique"
    );
    let config = AdmissionConfig {
        schema: CONFIG_SCHEMA.to_string(),
        envelope,
        ledger,
        artifact_identity: canonical_hex(&identity),
        genesis_hash: canonical_hex(
            &rpc.genesis_block_hash()?
                .context("canonical genesis unavailable")?
                .0,
        ),
        rpc_url: crate::multi_asset_session_chain::rpc_endpoint(rpc.endpoint())?.to_string(),
        no_real_assets: true,
        admitted_asset_types: types.iter().map(|value| canonical_hex(value)).collect(),
    };
    crate::persistence::write_private_immutable(
        &options.output,
        &serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(
        serde_json::json!({"schema":"morph.factory_admission_configuration.v1","configuration":options.output,"artifact_policy_identity":config.artifact_identity,"no_real_assets":true,"production_approval":false}),
    )
}

struct Admission {
    config: AdmissionConfig,
    identity: Bytes32,
    envelope: PreproductionEnvelope,
}

impl Admission {
    fn load(path: &Path, contracts: &Path) -> Result<Self> {
        let config: AdmissionConfig = read_bounded_json(path, 64 * 1024)?;
        ensure!(
            config.schema == CONFIG_SCHEMA,
            "unsupported Factory admission configuration"
        );
        ensure!(
            config.envelope.is_absolute() && config.ledger.is_absolute(),
            "admission envelope and stable ledger paths must be absolute"
        );
        ensure!(
            config.no_real_assets,
            "Factory experiment requires an explicit no-real-assets declaration"
        );
        ensure!(
            crate::multi_asset_session_chain::rpc_endpoint(&config.rpc_url)?.as_str()
                == config.rpc_url,
            "admission RPC endpoint must be canonical HTTP(S) without credentials"
        );
        let types = config
            .admitted_asset_types
            .iter()
            .map(|value| hash(value))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            types.iter().all(|value| *value != [0; 32])
                && types.windows(2).all(|pair| pair[0] < pair[1]),
            "admitted asset Type identities must be nonzero, sorted and unique"
        );
        let identity =
            crate::preproduction::verify_admission_identity(&config.envelope, contracts)?;
        ensure!(
            hash(&config.artifact_identity)? == identity,
            "Factory admission artifact identity changed; review the exact envelope and ELFs"
        );
        let envelope: PreproductionEnvelope = read_bounded_json(&config.envelope, 64 * 1024)?;
        envelope.validate()?;
        Ok(Self {
            config,
            identity,
            envelope,
        })
    }

    fn load_ledger(&self) -> Result<Ledger> {
        let marker = self.config.ledger.with_extension("identity.json");
        if !self.config.ledger.exists() {
            ensure!(
                !marker.exists(),
                "Factory admission ledger is missing; recover its complete monotonic history, never reset it"
            );
            return Ok(Ledger::new(self.identity, hash(&self.config.genesis_hash)?));
        }
        require_private_file(&fs::File::open(&self.config.ledger)?)?;
        let ledger: Ledger = read_bounded_json(&self.config.ledger, MAX_LEDGER_BYTES)?;
        ledger.validate(self.identity, hash(&self.config.genesis_hash)?)?;
        let marker_identity: (Bytes32, Bytes32) = read_bounded_json(&marker, 4096)?;
        ensure!(
            marker_identity == (ledger.identity, ledger.genesis),
            "admission ledger identity marker differs"
        );
        Ok(ledger)
    }

    fn save(&self, ledger: &Ledger) -> Result<()> {
        ledger.validate(self.identity, hash(&self.config.genesis_hash)?)?;
        let bytes = serde_json::to_vec_pretty(ledger)?;
        ensure!(
            bytes.len() <= MAX_LEDGER_BYTES,
            "admission ledger full; retain history and stop admission"
        );
        let marker = self.config.ledger.with_extension("identity.json");
        crate::persistence::write_private_immutable(
            &marker,
            &serde_json::to_vec(&(ledger.identity, ledger.genesis))?,
        )?;
        write_private_atomic(&self.config.ledger, &bytes)
    }
}

fn verify_rpc_identity(config: &AdmissionConfig, rpc: &crate::rpc::CkbRpcClient) -> Result<()> {
    ensure!(
        crate::multi_asset_session_chain::rpc_endpoint(rpc.endpoint())?.as_str() == config.rpc_url,
        "admission RPC endpoint differs from the reviewed configuration"
    );
    ensure!(
        rpc.genesis_block_hash()?
            .is_some_and(|genesis| hash(&config.genesis_hash).ok() == Some(genesis.0))
            && rpc.chain_info()?.chain.to_lowercase().contains("dev"),
        "admission requires the configured controlled devnet genesis"
    );
    Ok(())
}

pub(crate) fn read_verified_config(path: &Path, contracts: &Path) -> Result<AdmissionConfig> {
    Ok(Admission::load(path, contracts)?.config)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: String,
    identity: Bytes32,
    genesis: Bytes32,
    factories: Vec<FactoryHistory>,
    channels: Vec<ChannelHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelHistory {
    channel_id: Bytes32,
    reservations: Vec<ChannelReservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelReservation {
    transaction_hash: Bytes32,
    capacity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactoryHistory {
    factory_id: Bytes32,
    root_request: Bytes32,
    requests: Vec<FactorySigningRequest>,
    /// Includes activation and canonical reconciliation observations; never pruned.
    observed: Vec<FactoryCustody>,
    /// Terminal requests remain reserved across closure and orphaning.
    canonical_closures: Vec<Bytes32>,
    active: bool,
}

impl Ledger {
    fn new(identity: Bytes32, genesis: Bytes32) -> Self {
        Self {
            schema: LEDGER_SCHEMA.to_string(),
            identity,
            genesis,
            factories: vec![],
            channels: vec![],
        }
    }

    fn validate(&self, identity: Bytes32, genesis: Bytes32) -> Result<()> {
        ensure!(
            self.schema == LEDGER_SCHEMA && self.identity == identity && self.genesis == genesis,
            "Factory ledger belongs to another experiment identity or chain"
        );
        let mut factories = BTreeSet::new();
        for history in &self.factories {
            ensure!(
                factories.insert(history.factory_id),
                "duplicate Factory ledger identity"
            );
            let root = history
                .requests
                .first()
                .context("Factory ledger lost its root request")?;
            ensure!(
                root.role == FactorySigningRole::RootFunding
                    && root.request_id()? == history.root_request
                    && request_factory_id(root)? == history.factory_id,
                "Factory ledger root history differs"
            );
            let mut requests = BTreeSet::new();
            for request in &history.requests {
                request.validate_for_review(&request.members()?)?;
                ensure!(
                    requests.insert(request.request_id()?)
                        && request_factory_id(request)? == history.factory_id,
                    "duplicate or foreign Factory admission request"
                );
                ensure!(
                    request
                        .source
                        .iter()
                        .chain(&request.target)
                        .all(|custody| custody
                            .state()
                            .is_ok_and(|state| state.chain_id() == genesis)),
                    "admission request chain differs"
                );
            }
            for custody in &history.observed {
                custody.validate()?;
            }
            for id in &history.canonical_closures {
                ensure!(
                    history
                        .requests
                        .iter()
                        .any(|request| request.request_id().ok() == Some(*id)
                            && request.target.is_none()),
                    "closure has no reserved exact request"
                );
            }
        }
        let mut channels = BTreeSet::new();
        for channel in &self.channels {
            ensure!(
                channel.channel_id != [0; 32]
                    && channels.insert(channel.channel_id)
                    && !channel.reservations.is_empty(),
                "invalid or duplicate bilateral admission history"
            );
            let mut transactions = BTreeSet::new();
            for reservation in &channel.reservations {
                ensure!(
                    reservation.transaction_hash != [0; 32]
                        && reservation.capacity > 0
                        && transactions.insert(reservation.transaction_hash),
                    "invalid or duplicate bilateral request reservation"
                );
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "devnet", test))]
    fn reserve(
        &mut self,
        request: &FactorySigningRequest,
        envelope: &PreproductionEnvelope,
    ) -> Result<()> {
        let id = request.request_id()?;
        let factory_id = request_factory_id(request)?;
        let existing = self
            .factories
            .iter()
            .position(|history| history.factory_id == factory_id);
        if let Some(index) = existing {
            let history = &self.factories[index];
            if let Some(saved) = history
                .requests
                .iter()
                .find(|saved| saved.request_id().ok() == Some(id))
            {
                ensure!(
                    same_request(saved, request),
                    "admission request identity has conflicting complete evidence"
                );
                ensure!(
                    request.role != FactorySigningRole::RootFunding
                        || self
                            .factories
                            .iter()
                            .filter(|history| history.active)
                            .count()
                            <= envelope.factory.max_active_factories as usize,
                    "canonical reorg restored an active Factory slot; stop new root authority until pilot admission is reconciled"
                );
                ensure!(
                    request.target.is_none()
                        || self.pilot_capacity()?
                            <= envelope.channel.max_total_pilot_capacity_shannons,
                    "canonical reorg restored pilot exposure beyond the cap; terminal closure remains available"
                );
                return Ok(());
            }
            ensure!(
                history.active,
                "closed Factory cannot acquire new authority"
            );
            let source = request
                .source
                .as_ref()
                .context("Factory identity already has immutable root authority")?;
            ensure!(
                history.observed.iter().any(|observed| observed == source)
                    || history
                        .requests
                        .iter()
                        .any(|saved| saved.target.as_ref() == Some(source)),
                "Factory source is absent from retained canonical admission history; reconcile the exact admitted transition first"
            );
        } else {
            ensure!(
                request.role == FactorySigningRole::RootFunding && request.source.is_none(),
                "new Factory admission requires its complete initial root history"
            );
            ensure!(
                self.factories
                    .iter()
                    .filter(|history| history.active)
                    .count()
                    < envelope.factory.max_active_factories as usize,
                "active Factory admission limit reached"
            );
        }
        let mut next = self.clone();
        let index = existing.unwrap_or(next.factories.len());
        if existing.is_none() {
            next.factories.push(FactoryHistory {
                factory_id,
                root_request: id,
                requests: vec![],
                observed: vec![],
                canonical_closures: vec![],
                active: true,
            });
        }
        next.factories[index].requests.push(request.clone());
        let lifetime_children =
            next.factories[index]
                .requests
                .iter()
                .try_fold(0usize, |sum, item| -> Result<_> {
                    sum.checked_add(item.child_count()?)
                        .context("child reservation overflow")
                })?;
        ensure!(
            lifetime_children <= envelope.factory.max_children_per_factory as usize,
            "Factory lifetime child admission cap reached; cancellation, replacement, closure and reorg never refund a reservation"
        );
        ensure!(
            next.pilot_capacity()? <= envelope.channel.max_total_pilot_capacity_shannons,
            "combined pilot Factory/child/bilateral capacity admission limit reached"
        );
        *self = next;
        Ok(())
    }

    fn pilot_capacity(&self) -> Result<u64> {
        let mut pilot_capacity = 0u64;
        for history in &self.factories {
            // Charge the peak Factory plus every reserved child, including
            // alternative spends. Conservative overlap cannot hide real value.
            let mut peak = 0u64;
            let mut children = 0u64;
            for item in &history.requests {
                for custody in item.source.iter().chain(&item.target) {
                    peak = peak.max(custody_capacity(custody)?);
                }
                for index in 0..item.child_count()? {
                    children = children
                        .checked_add(child_capacity(item, index)?)
                        .context("pilot child capacity overflow")?;
                }
            }
            pilot_capacity = pilot_capacity
                .checked_add(if history.active { peak } else { 0 })
                .and_then(|sum| sum.checked_add(children))
                .context("pilot capacity overflow")?;
        }
        for channel in &self.channels {
            pilot_capacity = pilot_capacity
                .checked_add(
                    channel
                        .reservations
                        .iter()
                        .map(|reservation| reservation.capacity)
                        .max()
                        .context("channel reservation lost")?,
                )
                .context("bilateral pilot capacity overflow")?;
        }
        Ok(pilot_capacity)
    }

    fn reserve_bilateral(
        &mut self,
        channel_id: Bytes32,
        transaction_hash: Bytes32,
        capacity: u64,
        envelope: &PreproductionEnvelope,
    ) -> Result<()> {
        ensure!(
            channel_id != [0; 32]
                && transaction_hash != [0; 32]
                && capacity > 0
                && capacity <= envelope.channel.max_capacity_shannons,
            "bilateral admission identity or channel capacity is outside the experiment"
        );
        let mut next = self.clone();
        let index = next
            .channels
            .iter()
            .position(|channel| channel.channel_id == channel_id)
            .unwrap_or(next.channels.len());
        if index == next.channels.len() {
            next.channels.push(ChannelHistory {
                channel_id,
                reservations: vec![],
            });
        }
        if let Some(saved) = next.channels[index]
            .reservations
            .iter()
            .find(|reservation| reservation.transaction_hash == transaction_hash)
        {
            ensure!(
                saved.capacity == capacity,
                "bilateral exact transaction reservation changed capacity"
            );
            ensure!(
                next.pilot_capacity()? <= envelope.channel.max_total_pilot_capacity_shannons,
                "canonical reorg restored pilot exposure beyond the cap"
            );
            return Ok(());
        }
        next.channels[index].reservations.push(ChannelReservation {
            transaction_hash,
            capacity,
        });
        ensure!(
            next.pilot_capacity()? <= envelope.channel.max_total_pilot_capacity_shannons,
            "combined pilot Factory/child/bilateral capacity admission limit reached"
        );
        *self = next;
        Ok(())
    }

    fn reconcile_closures(
        &mut self,
        mut canonical: impl FnMut(&FactorySigningRequest) -> Result<bool>,
    ) -> Result<()> {
        for history in &mut self.factories {
            let mut closed = false;
            for id in &history.canonical_closures {
                let request = history
                    .requests
                    .iter()
                    .find(|request| request.request_id().ok() == Some(*id))
                    .context("closure request lost")?;
                closed |= canonical(request)?;
            }
            history.active = !closed;
        }
        Ok(())
    }
}

fn request_factory_id(request: &FactorySigningRequest) -> Result<Bytes32> {
    Ok(request
        .source
        .as_ref()
        .or(request.target.as_ref())
        .context("Factory request has no identity")?
        .state()?
        .factory_id()
        .try_into()?)
}

fn same_request(left: &FactorySigningRequest, right: &FactorySigningRequest) -> bool {
    left.role == right.role
        && left.source == right.source
        && left.target == right.target
        && left.transaction == right.transaction
        && left.witness == right.witness
        && left.target_rights == right.target_rights
}

fn custody_capacity(custody: &FactoryCustody) -> Result<u64> {
    custody
        .manifest
        .vaults
        .iter()
        .try_fold(custody.state_carrier_capacity, |sum, vault| {
            sum.checked_add(vault.value.capacity()?)
                .context("Factory capacity overflow")
        })
}

fn child_capacity(request: &FactorySigningRequest, index: usize) -> Result<u64> {
    let child = request.expected_child_recovery(index.try_into()?)?;
    child
        .manifest
        .vaults
        .iter()
        .try_fold(child.state_carrier_capacity, |sum, vault| {
            sum.checked_add(vault.value.capacity()?)
                .context("child capacity overflow")
        })
}

fn validate_shape(
    request: &FactorySigningRequest,
    envelope: &PreproductionEnvelope,
    review: bool,
) -> Result<()> {
    let members = request.members()?;
    if review {
        request.validate_for_review(&members)?;
    } else {
        request.validate(&members)?;
    }
    ensure!(
        members.len() == envelope.factory.participant_count as usize,
        "Factory experiment admits exactly two members"
    );
    ensure!(
        request.child_count()? <= envelope.factory.max_children_per_transaction as usize,
        "Factory experiment child-per-transaction limit exceeded"
    );
    ensure!(
        request
            .target_rights
            .iter()
            .all(|right| right.id.asset_type.is_none()),
        "Factory experiment excludes all token rights, including zero-quantity rights"
    );
    for custody in request.source.iter().chain(&request.target) {
        ensure!(
            custody.manifest.vaults.len() <= envelope.factory.max_vaults_per_state as usize
                && custody
                    .manifest
                    .vaults
                    .iter()
                    .all(|vault| vault.asset == VaultAsset::Ckb)
                && custody.type_scripts.is_empty(),
            "Factory experiment requires one plain-CKB Vault"
        );
        ensure!(
            custody_capacity(custody)? <= envelope.factory.max_capacity_shannons,
            "Factory experiment capacity cap exceeded"
        );
    }
    if request.role == FactorySigningRole::Transition {
        let frame = wire::FactoryReducedReleaseWitness::parse(&request.witness)
            .map_err(|error| anyhow::anyhow!("Factory admission frame: {error:?}"))?;
        if frame.operation() == FactoryTransitionOperation::ReducedRights {
            ensure!(
                envelope
                    .factory
                    .reduced_right_counts
                    .contains(&(frame.right_count() as u32)),
                "Factory experiment admits only 1/4/10-right metadata transitions"
            );
        }
    }
    if let Some(target) = &request.target {
        validate_exit_floor(target, &members, &request.target_rights)?;
    }
    for index in 0..request.child_count()? {
        let child = request.expected_child_recovery(index.try_into()?)?;
        ensure!(
            child.manifest.vaults.len() <= envelope.factory.max_vaults_per_state as usize
                && child
                    .manifest
                    .vaults
                    .iter()
                    .all(|vault| vault.asset == VaultAsset::Ckb),
            "Factory child experiment requires one plain-CKB Vault"
        );
        ensure!(
            child_capacity(request, index)? <= envelope.channel.max_capacity_shannons,
            "Factory child experiment capacity cap exceeded"
        );
        for script in child
            .scripts
            .participant_locks
            .iter()
            .chain(std::iter::once(&child.scripts.carrier_refund_lock))
        {
            ensure!(
                is_standard_wallet(&packed::Script::from_slice(script)?)?,
                "Factory child experiment requires standard wallet payout/refund scripts"
            );
        }
    }
    // The live-chain guard additionally checks every dependency, ownership,
    // conservation lane and actual fee. Recheck static payout geometry here.
    let raw = request.raw_transaction()?;
    let mut protocol_locks = request
        .source
        .iter()
        .chain(&request.target)
        .flat_map(|custody| [custody.state_lock.clone(), custody.vault_lock.clone()])
        .collect::<Vec<_>>();
    let mut protocol_types = request
        .source
        .iter()
        .chain(&request.target)
        .map(|custody| custody.state_type.clone())
        .collect::<Vec<_>>();
    for index in 0..request.child_count()? {
        let child = request.expected_child_recovery(index.try_into()?)?;
        protocol_locks.extend([child.scripts.state_lock, child.scripts.vault_lock]);
        protocol_types.push(child.scripts.state_type);
    }
    for (output, data) in raw.outputs().into_iter().zip(raw.outputs_data()) {
        ensure!(
            u64::from(output.capacity())
                >= output
                    .occupied_capacity(ckb_types::core::Capacity::bytes(data.raw_data().len())?)?
                    .as_u64(),
            "Factory admission output is below occupied capacity"
        );
        ensure!(
            protocol_locks
                .iter()
                .any(|script| script.as_slice() == output.lock().as_slice())
                || is_standard_wallet(&output.lock())?,
            "Factory experiment output uses an unadmitted lock script"
        );
        ensure!(
            output.type_().to_opt().is_none_or(|ty| protocol_types
                .iter()
                .any(|script| script.as_slice() == ty.as_slice())),
            "Factory experiment output uses an unadmitted Type script"
        );
    }
    Ok(())
}

pub(crate) fn is_standard_wallet(script: &packed::Script) -> Result<bool> {
    Ok(script.hash_type().as_slice() == [1]
        && script.code_hash().as_slice() == hash(crate::multi_asset_funding::SECP_TYPE_HASH)?
        && script.args().raw_data().len() == 20)
}

fn validate_exit_floor(
    custody: &FactoryCustody,
    members: &[FactoryParticipantKey],
    rights: &[FactoryRight],
) -> Result<()> {
    validate_factory_initial_rights(members, &custody.manifest, rights)?;
    let floor = morph_script_common::multi_asset::multi_asset_occupied_capacity(
        &custody.vault_lock,
        None,
        0,
    )
    .map_err(|error| anyhow::anyhow!("retained floor: {error:?}"))?;
    let total = custody
        .manifest
        .vaults
        .iter()
        .try_fold(0u64, |sum, vault| {
            sum.checked_add(vault.value.capacity()?)
                .context("Factory floor capacity overflow")
        })?;
    let mut claims = 0u128;
    for right in rights
        .iter()
        .filter(|right| right.id.kind == FactoryRightKind::ReserveClaim && right.quantity > 0)
    {
        let member = members
            .iter()
            .find(|member| member.participant == right.id.participant)
            .context("missing claim member")?;
        let lock = crate::multi_asset_funding::funding_wallet_lock(&member.pubkey_sec1)?;
        let payout_floor = packed::CellOutput::new_builder()
            .lock(lock)
            .build()
            .occupied_capacity(ckb_types::core::Capacity::bytes(0)?)?
            .as_u64();
        ensure!(
            right.quantity >= u128::from(payout_floor),
            "ReserveClaim cannot fund its independent standard-wallet payout geometry"
        );
        claims = claims
            .checked_add(right.quantity)
            .context("Factory exit claims overflow")?;
    }
    ensure!(
        claims
            <= u128::from(
                total
                    .checked_sub(floor)
                    .context("Factory has no retained custody floor")?
            ),
        "ReserveClaims consume the last collective retained Factory floor; revise the complete allocation"
    );
    Ok(())
}

/// Offline signer operations may only consume requests already admitted by a
/// canonical-chain prepare path. A new journal/config cannot import late history.
pub(crate) fn require_reserved(
    config: &Path,
    contracts: &Path,
    request: &FactorySigningRequest,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    validate_shape(request, &admission.envelope, false)?;
    for index in 0..request.child_count()? {
        crate::admission_channel::validate_recovery_shape(
            config,
            contracts,
            &request.expected_child_recovery(index.try_into()?)?,
        )?;
    }
    let _lock = lock_private_path(&admission.config.ledger)?;
    let ledger = admission.load_ledger()?;
    ensure!(
        ledger
            .factories
            .iter()
            .flat_map(|history| &history.requests)
            .any(|saved| same_request(saved, request)),
        "exact Factory request has no durable experiment admission reservation"
    );
    Ok(())
}

#[cfg(feature = "devnet")]
pub(crate) fn reserve_native(
    rpc: &crate::rpc::CkbRpcClient,
    config: &Path,
    contracts: &Path,
    request: &FactorySigningRequest,
    review: bool,
    max_fee: u64,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    verify_rpc_identity(&admission.config, rpc)?;
    ensure!(
        max_fee > 0 && max_fee <= admission.envelope.sponsor.max_fee_per_transaction_shannons,
        "Factory experiment fee cap exceeded"
    );
    let genesis = rpc
        .genesis_block_hash()?
        .context("admission requires canonical genesis")?;
    ensure!(
        genesis.0 == hash(&admission.config.genesis_hash)?
            && request
                .source
                .iter()
                .chain(&request.target)
                .all(|custody| custody
                    .state()
                    .is_ok_and(|state| state.chain_id() == genesis.0)),
        "Factory admission configuration belongs to another canonical chain"
    );
    ensure!(
        rpc.chain_info()?.chain.to_lowercase().contains("dev"),
        "Factory admission permits controlled devnet only"
    );
    validate_shape(request, &admission.envelope, review)?;
    let height = rpc.tip_header()?.number_value()?;
    for index in 0..request.child_count()? {
        crate::admission_channel::validate_recovery_shape_at(
            config,
            contracts,
            &request.expected_child_recovery(index.try_into()?)?,
            height,
        )?;
    }
    let _lock = lock_private_path(&admission.config.ledger)?;
    let mut ledger = admission.load_ledger()?;
    reconcile_closures(rpc, &mut ledger)?;
    ledger.reserve(request, &admission.envelope)?;
    admission.save(&ledger)
}

#[cfg(feature = "devnet")]
pub(crate) fn validate_fee(config: &Path, contracts: &Path, fee: u64) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    ensure!(
        fee > 0 && fee <= admission.envelope.sponsor.max_fee_per_transaction_shannons,
        "Factory experiment fee cap exceeded"
    );
    Ok(())
}

fn reconcile_closures(rpc: &crate::rpc::CkbRpcClient, ledger: &mut Ledger) -> Result<()> {
    ledger.reconcile_closures(|request| {
        if let Ok((transaction, _)) =
            crate::rpc::canonical_transaction(rpc, request.transaction_hash()?.into(), 1)
        {
            request.verify_authorized_transaction(&transaction)?;
            Ok(true)
        } else {
            // Missing, orphaned or unverifiable closure reserves its slot.
            Ok(false)
        }
    })
}

/// Call only after the existing canonical confirmation/activation verifier.
/// Observations add history; they never erase requests or child reservations.
#[cfg(feature = "devnet")]
pub(crate) fn observe(
    config: &Path,
    contracts: &Path,
    request: &FactorySigningRequest,
    custody: Option<&FactoryCustody>,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    let _lock = lock_private_path(&admission.config.ledger)?;
    let mut ledger = admission.load_ledger()?;
    let factory_id = request_factory_id(request)?;
    let history = ledger
        .factories
        .iter_mut()
        .find(|history| history.factory_id == factory_id)
        .context("Factory has no admission history")?;
    ensure!(
        history
            .requests
            .iter()
            .any(|saved| same_request(saved, request)),
        "canonical request was not reserved by this admission ledger"
    );
    if let Some(custody) = custody {
        let target = request
            .target
            .as_ref()
            .context("terminal Factory has no successor")?;
        let mut expected = target.clone();
        expected.state_out_point = custody.state_out_point.clone();
        ensure!(
            &expected == custody,
            "canonical successor differs from admitted target"
        );
        if !history.observed.contains(custody) {
            history.observed.push(custody.clone());
        }
        history.active = true;
    } else {
        ensure!(
            request.target.is_none(),
            "retained Factory cannot be recorded closed"
        );
        let id = request.request_id()?;
        if !history.canonical_closures.contains(&id) {
            history.canonical_closures.push(id);
        }
        history.active = false;
    }
    admission.save(&ledger)
}

#[cfg(feature = "devnet")]
pub(crate) fn observe_custody(
    config: &Path,
    contracts: &Path,
    custody: &FactoryCustody,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    let _lock = lock_private_path(&admission.config.ledger)?;
    let mut ledger = admission.load_ledger()?;
    let history = ledger
        .factories
        .iter_mut()
        .find(|history| {
            custody
                .state()
                .is_ok_and(|state| state.factory_id() == history.factory_id)
        })
        .context("canonical Factory has no initial admission history")?;
    ensure!(
        history
            .requests
            .iter()
            .any(|request| request.target.as_ref().is_some_and(|target| {
                let mut expected = target.clone();
                expected.state_out_point = custody.state_out_point.clone();
                &expected == custody
            })),
        "canonical custody was not reserved by this pilot; recover the complete initial admission ledger"
    );
    if !history.observed.contains(custody) {
        history.observed.push(custody.clone());
    }
    history.active = true;
    admission.save(&ledger)
}

/// The isolated native harness declares no-value assets and pins current code;
/// this creates no release or independent-operator approval.
#[cfg(feature = "devnet")]
pub(crate) fn create_harness_config(
    rpc: &crate::rpc::CkbRpcClient,
    directory: &Path,
    contracts: &Path,
) -> Result<PathBuf> {
    let envelope = fs::canonicalize("release/factory-preproduction/envelope.json")?;
    let identity = crate::preproduction::verify_admission_identity(&envelope, contracts)?;
    let config = AdmissionConfig {
        schema: CONFIG_SCHEMA.to_string(),
        envelope,
        ledger: directory.join("admission-ledger.json"),
        artifact_identity: canonical_hex(&identity),
        genesis_hash: canonical_hex(
            &rpc.genesis_block_hash()?
                .context("harness genesis unavailable")?
                .0,
        ),
        rpc_url: crate::multi_asset_session_chain::rpc_endpoint(rpc.endpoint())?.to_string(),
        no_real_assets: true,
        admitted_asset_types: vec![],
    };
    let path = directory.join("admission-config.json");
    crate::persistence::write_private_immutable(&path, &serde_json::to_vec_pretty(&config)?)?;
    Ok(path)
}

pub(crate) fn reserve_bilateral(
    rpc: &crate::rpc::CkbRpcClient,
    config: &Path,
    contracts: &Path,
    chain_id: Bytes32,
    channel_id: Bytes32,
    transaction_hash: Bytes32,
    capacity: u64,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    verify_rpc_identity(&admission.config, rpc)?;
    ensure!(
        chain_id == hash(&admission.config.genesis_hash)?,
        "bilateral admission chain differs"
    );
    let _lock = lock_private_path(&admission.config.ledger)?;
    let mut ledger = admission.load_ledger()?;
    reconcile_closures(rpc, &mut ledger)?;
    ledger.reserve_bilateral(channel_id, transaction_hash, capacity, &admission.envelope)?;
    admission.save(&ledger)
}

pub(crate) fn require_bilateral_reserved(
    config: &Path,
    contracts: &Path,
    chain_id: Bytes32,
    channel_id: Bytes32,
    transaction_hash: Bytes32,
    capacity: u64,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    ensure!(
        chain_id == hash(&admission.config.genesis_hash)?,
        "bilateral admission chain differs"
    );
    let _lock = lock_private_path(&admission.config.ledger)?;
    let ledger = admission.load_ledger()?;
    ensure!(
        ledger
            .channels
            .iter()
            .any(|channel| channel.channel_id == channel_id
                && channel
                    .reservations
                    .iter()
                    .any(
                        |reservation| reservation.transaction_hash == transaction_hash
                            && reservation.capacity == capacity
                    )),
        "bilateral exact body has no durable shared pilot admission reservation"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn reserve_bilateral_for_test(
    config: &Path,
    contracts: &Path,
    chain_id: Bytes32,
    channel_id: Bytes32,
    transaction_hash: Bytes32,
    capacity: u64,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    ensure!(
        chain_id == hash(&admission.config.genesis_hash)?,
        "test admission chain differs"
    );
    let _lock = lock_private_path(&admission.config.ledger)?;
    let mut ledger = admission.load_ledger()?;
    ledger.reserve_bilateral(channel_id, transaction_hash, capacity, &admission.envelope)?;
    admission.save(&ledger)
}

#[cfg(feature = "devnet")]
pub(crate) fn reconcile_native(
    rpc: &crate::rpc::CkbRpcClient,
    config: &Path,
    contracts: &Path,
) -> Result<()> {
    let admission = Admission::load(config, contracts)?;
    verify_rpc_identity(&admission.config, rpc)?;
    ensure!(
        rpc.genesis_block_hash()?
            .is_some_and(|genesis| hash(&admission.config.genesis_hash).ok() == Some(genesis.0)),
        "admission reconciliation chain differs"
    );
    let _lock = lock_private_path(&admission.config.ledger)?;
    let mut ledger = admission.load_ledger()?;
    reconcile_closures(rpc, &mut ledger)?;
    admission.save(&ledger)
}

#[cfg(feature = "devnet")]
pub(crate) fn facts(config: &Path, contracts: &Path) -> Result<serde_json::Value> {
    let admission = Admission::load(config, contracts)?;
    let _lock = lock_private_path(&admission.config.ledger)?;
    let ledger = admission.load_ledger()?;
    let mut lifetime_children = 0usize;
    let mut retained_children = 0usize;
    let mut terminal_children = 0usize;
    let mut request_count = 0usize;
    for history in &ledger.factories {
        for request in &history.requests {
            let children = request.child_count()?;
            lifetime_children += children;
            if request.target.is_some() {
                retained_children += children;
            } else {
                terminal_children += children;
            }
            request_count += 1;
            // Check idempotency against retained history after restart. This
            // does not grant a fresh source or create a second reservation.
            let mut replay = ledger.clone();
            replay.reserve(request, &admission.envelope)?;
            ensure!(
                serde_json::to_vec(&replay)? == serde_json::to_vec(&ledger)?,
                "exact request replay changed admission history"
            );
        }
    }
    Ok(serde_json::json!({
        "schema":"morph.factory_admission_facts.v1",
        "mandatory_exact_request_admission":true,
        "artifact_policy_identity":canonical_hex(&ledger.identity),
        "canonical_genesis":canonical_hex(&ledger.genesis),
        "factory_count":ledger.factories.len(),
        "active_factories":ledger.factories.iter().filter(|history| history.active).count(),
        "request_reservations":request_count,
        "lifetime_child_reservations":lifetime_children,
        "retained_child_reservations":retained_children,
        "terminal_child_reservations":terminal_children,
        "bilateral_channel_reservations":ledger.channels.len(),
        "conservative_pilot_capacity_shannons":ledger.pilot_capacity()?.to_string(),
        "same_request_reservation_idempotent":true,
        "complete_history_revalidated_after_reload":true,
        "child_reservations_never_refunded":true,
        "production_approval":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_packets::FactoryRightTerms;

    fn envelope() -> PreproductionEnvelope {
        serde_json::from_str(include_str!(
            "../../../release/factory-preproduction/envelope.json"
        ))
        .unwrap()
    }
    fn root() -> FactorySigningRequest {
        let (terms, authority, cells) = crate::factory_root_transaction::tests::fixture();
        terms
            .build([77; 32], authority, &cells, 1_000_000_000)
            .unwrap()
            .signing_request()
            .unwrap()
    }

    #[test]
    fn exact_shape_rejects_zero_token_rights_and_unwithdrawable_allocations() {
        let envelope = envelope();
        validate_shape(&root(), &envelope, false).unwrap();
        let (mut terms, authority, cells) = crate::factory_root_transaction::tests::fixture();
        terms.rights.push(FactoryRightTerms {
            participant: terms.members[0].participant.clone(),
            subchannel: canonical_hex(&[255; 32]),
            kind: FactoryRightKind::Balance,
            asset_type: Some(canonical_hex(&[91; 32])),
            quantity: "0".to_string(),
        });
        terms.rights.sort_by_key(|right| right.decode().unwrap().id);
        let zero = terms
            .build([77; 32], authority, &cells, 1_000_000_000)
            .unwrap()
            .signing_request()
            .unwrap();
        assert!(
            validate_shape(&zero, &envelope, false)
                .unwrap_err()
                .to_string()
                .contains("zero-quantity")
        );

        let (mut terms, authority, cells) = crate::factory_root_transaction::tests::fixture();
        terms.rights[0].quantity = "3000000000".to_string();
        let dust = terms
            .build([77; 32], authority, &cells, 1_000_000_000)
            .unwrap()
            .signing_request()
            .unwrap();
        assert!(
            validate_shape(&dust, &envelope, false)
                .unwrap_err()
                .to_string()
                .contains("payout geometry")
        );

        let (mut terms, authority, cells) = crate::factory_root_transaction::tests::fixture();
        terms.rights[0].quantity = "20000000000".to_string();
        let overallocated = terms
            .build([77; 32], authority, &cells, 1_000_000_000)
            .unwrap()
            .signing_request()
            .unwrap();
        assert!(
            validate_shape(&overallocated, &envelope, false)
                .unwrap_err()
                .to_string()
                .contains("retained Factory floor")
        );
    }

    #[test]
    fn executable_experiment_rejects_an_undeclared_two_right_shape() {
        let envelope = envelope();
        for count in [1, 2, 4, 10] {
            let (mut terms, cells) = crate::factory_transaction::tests::reduced_rights_fixture();
            crate::factory_transaction::tests::reduce_value_rights(&mut terms, count);
            let request = terms.build(&cells, 1000).unwrap();
            assert_eq!(
                validate_shape(&request, &envelope, false).is_ok(),
                count != 2
            );
        }
    }

    fn child_root() -> FactorySigningRequest {
        let (mut terms, authority, cells) = crate::factory_root_transaction::tests::fixture();
        terms.rights[0].quantity = "20000000000".to_string();
        terms
            .build([77; 32], authority, &cells, 1_000_000_000)
            .unwrap()
            .signing_request()
            .unwrap()
    }

    #[test]
    fn lifetime_reservations_survive_restart_alternatives_closure_and_reorg() {
        let envelope = envelope();
        let root = child_root();
        let mut ledger = Ledger::new([8; 32], [77; 32]);
        ledger.reserve(&root, &envelope).unwrap();
        let (base, cells) = crate::factory_transaction::tests::native_child_fixture(None);
        let mut requests = Vec::new();
        for index in 0..10u64 {
            let mut terms = base.clone();
            if index == 9 {
                let crate::factory_transaction::FactoryPreparationOperation::ReducedChild {
                    mut children,
                    ..
                } = terms.intent
                else {
                    panic!()
                };
                let raw = crate::multi_asset_packages::decode_hex(
                    &children[0].channel.descriptor_hex,
                    16 * 1024,
                )
                .unwrap();
                let mut descriptor = MultiAssetSettlement::decode(&raw).unwrap();
                for value in &mut descriptor.payouts[0].values {
                    value.reserve = 15_000_000_000;
                    value.business_ckb = 5_000_000_000;
                }
                children[0].channel.descriptor_hex = canonical_hex(&descriptor.encode().unwrap());
                terms.intent =
                    crate::factory_transaction::FactoryPreparationOperation::Materialise {
                        retained: None,
                        children,
                        carrier_refund_lock_hex: canonical_hex(cells[0].output.lock().as_slice()),
                        access_manifest_root: canonical_hex(&[7; 32]),
                    };
                terms.target_rights.clear();
            }
            terms.funders[0].fee_contribution = (1_000 + index).to_string();
            let request = terms.build(&cells, 1_000_000).unwrap();
            ledger.reserve(&request, &envelope).unwrap();
            ledger.reserve(&request, &envelope).unwrap();
            requests.push(request);
            // Deserialize/revalidate the complete durable representation after
            // every retained/alternative request, as a restarted process does.
            ledger = serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
            ledger.validate([8; 32], [77; 32]).unwrap();
        }
        assert_eq!(ledger.factories[0].requests.len(), 11);
        let mut terms = base;
        terms.funders[0].fee_contribution = "1011".to_string();
        let eleventh = terms.build(&cells, 1_000_000).unwrap();
        assert!(
            ledger
                .reserve(&eleventh, &envelope)
                .unwrap_err()
                .to_string()
                .contains("lifetime child")
        );
        let lifetime = |ledger: &Ledger| {
            ledger.factories[0]
                .requests
                .iter()
                .map(|request| request.child_count().unwrap())
                .sum::<usize>()
        };
        assert_eq!(lifetime(&ledger), 10);

        // Closure observation is a separate canonical fact. Losing it to a
        // reorg reoccupies the active slot and leaves every reservation intact.
        let terminal_id = requests[9].request_id().unwrap();
        ledger.factories[0].canonical_closures.push(terminal_id);
        ledger.reconcile_closures(|_| Ok(true)).unwrap();
        ledger.validate([8; 32], [77; 32]).unwrap();
        assert!(!ledger.factories[0].active);
        ledger.reconcile_closures(|_| Ok(false)).unwrap();
        assert!(ledger.factories[0].active);
        assert_eq!(lifetime(&ledger), 10);
        assert!(ledger.reserve(&eleventh, &envelope).is_err());
    }

    #[test]
    fn late_history_import_and_combined_pilot_capacity_fail_closed() {
        let envelope = envelope();
        let (terms, cells) = crate::factory_transaction::tests::native_child_fixture(None);
        let child = terms.build(&cells, 1000).unwrap();
        let mut ledger = Ledger::new([8; 32], [77; 32]);
        assert!(
            ledger
                .reserve(&child, &envelope)
                .unwrap_err()
                .to_string()
                .contains("initial root history")
        );
        let root = child_root();
        ledger.reserve(&root, &envelope).unwrap();
        let mut restricted = envelope;
        restricted.channel.max_total_pilot_capacity_shannons =
            custody_capacity(root.target.as_ref().unwrap()).unwrap();
        assert!(
            ledger
                .reserve(&child, &restricted)
                .unwrap_err()
                .to_string()
                .contains("combined pilot")
        );
        assert_eq!(ledger.factories[0].requests.len(), 1);
        ledger.reserve(&root, &restricted).unwrap();
    }

    #[test]
    fn bilateral_splice_peaks_and_factory_children_share_one_atomic_budget() {
        let mut envelope = envelope();
        let mut ledger = Ledger::new([8; 32], [77; 32]);
        ledger.reserve(&child_root(), &envelope).unwrap();
        let (terms, cells) = crate::factory_transaction::tests::native_child_fixture(None);
        ledger
            .reserve(&terms.build(&cells, 1000).unwrap(), &envelope)
            .unwrap();
        let factory_and_child = ledger.pilot_capacity().unwrap();
        envelope.channel.max_total_pilot_capacity_shannons = factory_and_child + 70_000_000_000;
        ledger
            .reserve_bilateral([9; 32], [10; 32], 60_000_000_000, &envelope)
            .unwrap();
        ledger
            .reserve_bilateral([9; 32], [10; 32], 60_000_000_000, &envelope)
            .unwrap();
        ledger
            .reserve_bilateral([9; 32], [11; 32], 50_000_000_000, &envelope)
            .unwrap();
        assert_eq!(
            ledger.pilot_capacity().unwrap(),
            factory_and_child + 60_000_000_000
        );
        assert!(
            ledger
                .reserve_bilateral([9; 32], [12; 32], 80_000_000_000, &envelope)
                .is_err()
        );
        assert!(
            ledger
                .reserve_bilateral([13; 32], [14; 32], 20_000_000_000, &envelope)
                .is_err()
        );
        assert!(
            ledger
                .reserve_bilateral([9; 32], [10; 32], 59_000_000_000, &envelope)
                .is_err()
        );
        ledger.validate([8; 32], [77; 32]).unwrap();
        ledger.factories[0].active = false;
        let child_only = child_capacity(&ledger.factories[0].requests[1], 0).unwrap();
        assert_eq!(
            ledger.pilot_capacity().unwrap(),
            child_only + 60_000_000_000,
            "parent closure must retain every child obligation"
        );
    }

    #[test]
    fn four_distinct_root_factories_exhaust_the_shared_active_slot_limit() {
        let envelope = envelope();
        let mut ledger = Ledger::new([8; 32], [77; 32]);
        for seed in 1u8..=5 {
            let (mut terms, authority, mut cells) =
                crate::factory_root_transaction::tests::fixture();
            let input = &mut terms.funders[0].inputs[0];
            let cell = cells
                .iter_mut()
                .find(|cell| {
                    canonical_hex(cell.point.tx_hash().as_slice()) == input.tx_hash
                        && u32::from(cell.point.index()) == input.index
                })
                .unwrap();
            cell.point = cell
                .point
                .clone()
                .as_builder()
                .tx_hash([seed; 32].pack())
                .build();
            input.tx_hash = canonical_hex(&[seed; 32]);
            let request = terms
                .build([77; 32], authority, &cells, 1_000_000_000)
                .unwrap()
                .signing_request()
                .unwrap();
            validate_shape(&request, &envelope, false).unwrap();
            let result = ledger.reserve(&request, &envelope);
            if seed <= 4 {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().to_string().contains("active Factory"));
            }
        }
        assert_eq!(ledger.factories.len(), 4);
        ledger.validate([8; 32], [77; 32]).unwrap();
    }

    #[test]
    fn stable_private_ledger_restarts_and_missing_history_cannot_reinitialize() {
        let directory = std::env::temp_dir().join(format!(
            "morph-admission-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::persistence::create_private_directories(&directory).unwrap();
        let admission = Admission {
            config: AdmissionConfig {
                schema: CONFIG_SCHEMA.to_string(),
                envelope: directory.join("unused-envelope.json"),
                ledger: directory.join("ledger.json"),
                artifact_identity: canonical_hex(&[8; 32]),
                genesis_hash: canonical_hex(&[77; 32]),
                rpc_url: "http://127.0.0.1:18114/".to_string(),
                no_real_assets: true,
                admitted_asset_types: vec![],
            },
            identity: [8; 32],
            envelope: envelope(),
        };
        let mut ledger = admission.load_ledger().unwrap();
        ledger.reserve(&root(), &admission.envelope).unwrap();
        {
            let _lock = lock_private_path(&admission.config.ledger).unwrap();
            assert!(
                crate::persistence::try_lock_private_path(&admission.config.ledger)
                    .unwrap()
                    .is_none()
            );
            admission.save(&ledger).unwrap();
        }
        let restarted = admission.load_ledger().unwrap();
        assert_eq!(
            serde_json::to_vec(&ledger).unwrap(),
            serde_json::to_vec(&restarted).unwrap()
        );
        fs::remove_file(&admission.config.ledger).unwrap();
        assert!(
            admission
                .load_ledger()
                .unwrap_err()
                .to_string()
                .contains("never reset")
        );
        assert!(
            admission
                .config
                .ledger
                .with_extension("identity.json")
                .is_file()
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn fresh_bilateral_signing_reconciles_orphaned_parent_closure_before_reusing_reservation() {
        let directory = std::env::temp_dir().join(format!(
            "morph-bilateral-closure-reorg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::persistence::create_private_directories(&directory).unwrap();
        let mock = crate::admission_channel::tests::MockRpc::start([77; 32], 100);
        let draft = crate::admission_channel::tests::root_draft(None, [77; 32]);
        let (_, recovery) = draft.evidence().unwrap();
        let transaction = draft.transaction().unwrap();
        let (configuration, contracts) =
            crate::admission_channel::tests::configuration(&directory, &recovery, &transaction);
        crate::admission_channel::tests::set_rpc(&configuration, &mock.url);
        let admission = Admission::load(&configuration, &contracts).unwrap();
        let mut ledger = admission.load_ledger().unwrap();
        let root = child_root();
        ledger.reserve(&root, &admission.envelope).unwrap();
        let (mut terms, cells) = crate::factory_transaction::tests::native_child_fixture(None);
        let crate::factory_transaction::FactoryPreparationOperation::ReducedChild {
            mut children,
            ..
        } = terms.intent.clone()
        else {
            panic!()
        };
        let raw =
            crate::multi_asset_packages::decode_hex(&children[0].channel.descriptor_hex, 16 * 1024)
                .unwrap();
        let mut descriptor = MultiAssetSettlement::decode(&raw).unwrap();
        for value in &mut descriptor.payouts[0].values {
            value.reserve = 15_000_000_000;
            value.business_ckb = 5_000_000_000;
        }
        children[0].channel.descriptor_hex = canonical_hex(&descriptor.encode().unwrap());
        terms.intent = crate::factory_transaction::FactoryPreparationOperation::Materialise {
            retained: None,
            children,
            carrier_refund_lock_hex: canonical_hex(cells[0].output.lock().as_slice()),
            access_manifest_root: canonical_hex(&[7; 32]),
        };
        terms.target_rights.clear();
        let terminal = terms.build(&cells, 1_000_000).unwrap();
        ledger.reserve(&terminal, &admission.envelope).unwrap();
        ledger.factories[0]
            .canonical_closures
            .push(terminal.request_id().unwrap());
        ledger.reconcile_closures(|_| Ok(true)).unwrap();
        let mut remaining = admission.envelope.channel.max_total_pilot_capacity_shannons
            - ledger.pilot_capacity().unwrap();
        for seed in 100u8..150 {
            if remaining == 0 {
                break;
            }
            let capacity = remaining.min(admission.envelope.channel.max_capacity_shannons);
            ledger
                .reserve_bilateral([seed; 32], [seed + 50; 32], capacity, &admission.envelope)
                .unwrap();
            remaining -= capacity;
        }
        assert_eq!(remaining, 0);
        admission.save(&ledger).unwrap();
        let binding = crate::admission_channel::Binding::new(
            &configuration,
            &contracts,
            &recovery,
            &transaction,
        )
        .unwrap();
        let before = fs::read(&admission.config.ledger).unwrap();
        // The mock reports the terminal transaction as unknown after rollback.
        // Restored parent exposure must make even this old exact reservation
        // ineligible for another participant signature.
        let error = binding.require_fresh(&recovery, &transaction).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical reorg restored pilot exposure"),
            "{error:#}"
        );
        assert_eq!(fs::read(&admission.config.ledger).unwrap(), before);
        fs::remove_dir_all(directory).unwrap();
    }
}
