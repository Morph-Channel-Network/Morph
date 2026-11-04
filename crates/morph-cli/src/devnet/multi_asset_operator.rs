//! Transactions reconstructed from signed recovery evidence, with no issuer or
//! participant secrets. Fee inputs are independent of channel value.
use super::*;
use crate::multi_asset_packages::{StoredMultiAssetPackage, read_package, write_package};
use morph_script_common::multi_asset as wire;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Operation {
    Activate,
    Publish,
    Finalise,
}

/// Fee roles have different authorities. A sponsor has no private signer;
/// its immutable consensus policy controls the exact return lock and budget.
#[derive(Clone, clap::Subcommand)]
pub enum FeeAuthorization {
    Wallet {
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
    },
    Sponsor {
        #[arg(long)]
        change_pubkey: String,
    },
}

impl std::fmt::Debug for FeeAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wallet { .. } => "Wallet",
            Self::Sponsor { .. } => "Sponsor",
        })
    }
}

impl FeeAuthorization {
    fn identity(&self) -> Result<(Script, Option<Privkey>)> {
        match self {
            Self::Wallet { private_key } => {
                let key =
                    parse_privkey(private_key).map_err(|_| anyhow!("invalid fee signing key"))?;
                Ok((secp256k1_lock(&key)?, Some(key)))
            }
            Self::Sponsor { change_pubkey } => {
                let pubkey =
                    parse_compressed_pubkey_hex(change_pubkey, "sponsor change public key")?;
                Ok((secp256k1_lock_from_pubkey(&pubkey)?, None))
            }
        }
    }
    pub(super) fn change_lock(&self) -> Result<Script> {
        Ok(self.identity()?.0)
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Wallet { .. } => "wallet",
            Self::Sponsor { .. } => "sponsor",
        }
    }
}

pub struct Options {
    pub operation: Operation,
    pub package: PathBuf,
    pub state_out_point: String,
    pub fee_out_point: String,
    pub fee_authorization: FeeAuthorization,
    pub contracts_dir: PathBuf,
    pub store_dir: PathBuf,
    pub fee: u64,
    pub max_fee: u64,
    pub mine_blocks: u64,
    pub publication_profile: Option<PathBuf>,
    pub attempt_log: Option<PathBuf>,
    pub dry_run: bool,
}

fn invalid(error: ScriptError) -> anyhow::Error {
    anyhow!("invalid multi-asset package: {error:?}")
}

fn script(witness: &wire::MultiAssetWitness<'_>, index: usize) -> Result<Script> {
    Script::from_slice(witness.scripts().script(index).map_err(invalid)?)
        .context("invalid committed script")
}

pub(super) fn code_matches(script: &Script, cell: &LiveCellDetails) -> bool {
    match script.hash_type().as_slice()[0] {
        0 | 2 | 4 => script.code_hash().as_slice() == blake2b_256(&cell.data),
        1 => cell
            .output
            .type_()
            .to_opt()
            .is_some_and(|ty| ty.calc_script_hash() == script.code_hash()),
        _ => false,
    }
}

/// Resolve code and dep-group cells from the canonical view. A package's list
/// is metadata, not evidence that code is live or actually matches a script.
pub(super) struct ResolvedDependencies {
    pub(super) cells: Vec<LiveCellDetails>,
    pub(super) out_points: BTreeSet<Vec<u8>>,
}

pub(super) fn live_dependencies(
    rpc: &CkbRpcClient,
    deps: &[CellDep],
) -> Result<ResolvedDependencies> {
    let mut resolved = Vec::new();
    let mut seen = BTreeSet::new();
    for dep in deps {
        let cell = load_canonical_live_cell(rpc, dep.out_point())?;
        if dep.dep_type().as_slice()[0] == 0 {
            ensure!(
                seen.insert(dep.out_point().as_slice().to_vec()),
                "duplicate resolved code dependency"
            );
            resolved.push(cell);
        } else {
            let members =
                OutPointVec::from_slice(&cell.data).context("invalid dependency group")?;
            ensure!(!members.is_empty(), "empty dependency group");
            for point in members {
                ensure!(resolved.len() < 64, "too many resolved code dependencies");
                ensure!(
                    seen.insert(point.as_slice().to_vec()),
                    "duplicate resolved code dependency"
                );
                resolved.push(load_canonical_live_cell(rpc, point)?);
            }
        }
        ensure!(resolved.len() <= 64, "too many resolved code dependencies");
    }
    Ok(ResolvedDependencies {
        cells: resolved,
        out_points: seen,
    })
}

pub(super) fn validate_code(
    rpc: &CkbRpcClient,
    contracts_dir: &Path,
    witness: &wire::MultiAssetWitness<'_>,
    deps: &[CellDep],
    fee_lock: &Script,
) -> Result<()> {
    let cells = live_dependencies(rpc, deps)?;
    validate_resolved_code(contracts_dir, witness, &cells.cells, fee_lock)
}

pub(super) fn validate_resolved_code(
    contracts_dir: &Path,
    witness: &wire::MultiAssetWitness<'_>,
    cells: &[LiveCellDetails],
    fee_lock: &Script,
) -> Result<()> {
    // Check all payout/refund/authority and asset scripts, including those
    // whose code is not executed until a future withdrawal.
    let typed_count = (0..witness.manifest().count()).try_fold(0, |count, i| {
        Ok::<_, anyhow::Error>(
            count + usize::from(witness.manifest().entry(i).map_err(invalid)?.asset.kind == 1),
        )
    })?;
    for index in 0..6 + typed_count {
        let committed = script(witness, index)?;
        ensure!(
            cells.iter().any(|cell| code_matches(&committed, cell)),
            "no live dependency resolves committed script {index}"
        );
    }
    ensure!(
        cells.iter().any(|cell| code_matches(fee_lock, cell)),
        "fee lock code dependency missing"
    );
    // Authority code is approved from the selected local artifact set, not
    // merely from hashes supplied by the package itself.
    for (index, name) in [
        (3, "morph-vault-lock"),
        (4, "morph-state-type"),
        (5, "morph-state-lock"),
    ] {
        let committed = script(witness, index)?;
        let binary = fs::read(contracts_dir.join(name))
            .with_context(|| format!("missing approved contract {name}"))?;
        let approved_hash = blake2b_256(&binary);
        ensure!(
            cells
                .iter()
                .any(|cell| code_matches(&committed, cell)
                    && blake2b_256(&cell.data) == approved_hash),
            "committed {name} does not match approved contract artifact"
        );
    }
    Ok(())
}

pub(super) fn validate_vaults(
    rpc: &CkbRpcClient,
    witness: &wire::MultiAssetWitness<'_>,
) -> Result<Vec<OutPoint>> {
    let vault_lock = script(witness, 3)?;
    let mut points = Vec::new();
    let mut type_index = 6;
    for index in 0..witness.manifest().count() {
        let raw = witness.outpoint(index).map_err(invalid)?;
        let point = OutPoint::from_slice(raw).context("invalid Vault OutPoint")?;
        let cell = load_canonical_live_cell(rpc, point.clone())?;
        let entry = witness.manifest().entry(index).map_err(invalid)?;
        let expected_type = if entry.asset.kind == 1 {
            let ty = script(witness, type_index)?;
            type_index += 1;
            Some(ty)
        } else {
            None
        };
        ensure!(
            cell.output.lock() == vault_lock
                && cell.output.type_().to_opt() == expected_type
                && cell.capacity == entry.allocation.capacity().map_err(invalid)?,
            "Vault {index} does not match signed contents"
        );
        let expected_data = if entry.asset.kind == 1 {
            entry.allocation.amount.to_le_bytes().to_vec()
        } else {
            vec![]
        };
        ensure!(
            cell.data.as_ref() == expected_data,
            "Vault {index} data does not match signed quantity"
        );
        points.push(point);
    }
    Ok(points)
}

fn recovery_witness(stored: &StoredMultiAssetPackage, signed: bool) -> Result<Bytes> {
    let decoded = stored.decode()?;
    Ok(WitnessArgs::new_builder()
        .input_type(signed.then(|| Bytes::from(decoded.signatures)).pack())
        .output_type(Some(Bytes::from(decoded.witness)).pack())
        .build()
        .as_bytes())
}

struct ActivationEvidence {
    header: Vec<u8>,
    witness: Bytes,
}

/// Recover the original funding descriptor from authenticated creation
/// evidence, even when the retained unilateral state has different payouts.
fn activation_evidence(
    initial_header: &[u8],
    funding_witness: &[u8],
    funding_hash: &[u8; 32],
    recovery: &morph_core::MultiAssetRecoveryPackage,
) -> Result<ActivationEvidence> {
    recovery.validate()?;
    let header = wire::MultiAssetStateHeader::parse(initial_header).map_err(invalid)?;
    ensure!(
        !header.vaults_are_bound() && header.phase() == PHASE_ACTIVE && header.state_number() == 0,
        "activation requires the original unbound Active state zero"
    );
    ensure!(
        recovery
            .outpoints
            .iter()
            .all(|point| &point.tx_hash == funding_hash),
        "activation Vaults must come from the State funding transaction"
    );
    let witness = WitnessArgs::from_slice(funding_witness).context("invalid funding witness")?;
    let evidence = witness
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("funding recovery evidence missing"))?
        .raw_data();
    let signatures = witness
        .input_type()
        .to_opt()
        .ok_or_else(|| anyhow!("funding participant signatures missing"))?
        .raw_data();
    let splice;
    let creation_evidence = if evidence
        .starts_with(morph_script_common::multi_asset_splice::MULTI_ASSET_SPLICE_MAGIC)
    {
        splice = morph_script_common::multi_asset_splice::MultiAssetSpliceWitness::parse(&evidence)
            .map_err(invalid)?;
        ensure!(
            splice.new_header().as_bytes() == initial_header,
            "splice creation header differs from funding State"
        );
        splice.new_evidence().as_bytes()
    } else {
        evidence.as_ref()
    };
    let mut original = if header.funding_epoch() == 0 {
        header
            .verify_root_funding_signatures(
                funding_hash,
                &morph_script_common::BilateralSignatureWitness::parse(&signatures)
                    .map_err(invalid)?,
            )
            .map_err(invalid)?;
        morph_core::MultiAssetRecoveryPackage::decode_contents(
            initial_header,
            creation_evidence,
            recovery.state_carrier_capacity,
        )?
    } else {
        morph_core::MultiAssetRecoveryPackage::decode(
            initial_header,
            creation_evidence,
            &signatures,
            recovery.state_carrier_capacity,
        )?
    };
    original.outpoints = recovery.outpoints.clone();
    original.state.vault_outpoint_set_root = recovery.state.vault_outpoint_set_root;
    // The old signatures authenticate the unbound creation only; activation
    // is authorised by complete direct provenance, not by reusing them.
    original.validate_contents()?;
    let bound = original.state.encode()?.to_vec();
    let activated = wire::MultiAssetStateHeader::parse(&bound).map_err(invalid)?;
    let target = recovery.state.encode()?;
    let target = wire::MultiAssetStateHeader::parse(&target).map_err(invalid)?;
    ensure!(
        header.is_activation_to(&activated) && activated.same_context_except_progress(&target),
        "activation recovery package belongs to a different funding context"
    );
    let evidence = morph_core::encode_multi_asset_witness(
        &original.manifest,
        &original.settlement,
        &original.outpoints,
        &original.scripts,
    )?;
    Ok(ActivationEvidence {
        header: bound,
        witness: WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(evidence)).pack())
            .build()
            .as_bytes(),
    })
}

fn recover_activation(
    rpc: &CkbRpcClient,
    state_point: &OutPoint,
    initial_header: &[u8],
    stored: &StoredMultiAssetPackage,
) -> Result<ActivationEvidence> {
    let response = rpc.transaction(H256::from(state_point.tx_hash()))?;
    ensure!(
        response.tx_status.status == Status::Committed,
        "funding transaction is not committed"
    );
    let transaction = response
        .transaction
        .ok_or_else(|| anyhow!("funding transaction body missing"))?;
    let ckb_jsonrpc_types::Either::Left(transaction) = transaction.inner else {
        return Err(anyhow!("expected the requested JSON funding transaction"));
    };
    let transaction: ckb_types::packed::Transaction = transaction.inner.into();
    ensure!(
        transaction.calc_tx_hash() == state_point.tx_hash(),
        "funding transaction hash differs from live State"
    );
    let witness = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("funding witness zero missing"))?;
    activation_evidence(
        initial_header,
        &witness.raw_data(),
        &state_point.tx_hash().unpack(),
        &stored.recovery()?,
    )
}

fn state_confirmations(rpc: &CkbRpcClient, point: &OutPoint) -> Result<u64> {
    let status = rpc.transaction(H256::from(point.tx_hash()))?;
    ensure!(
        status.tx_status.status == Status::Committed,
        "State transaction is not committed"
    );
    let number = status
        .tx_status
        .block_number
        .ok_or_else(|| anyhow!("State has no inclusion block"))?
        .value();
    let block_hash = status
        .tx_status
        .block_hash
        .ok_or_else(|| anyhow!("State has no inclusion block hash"))?;
    ensure!(
        canonical_block_hash(rpc, number)?.as_deref() == Some(format!("{block_hash:#x}").as_str()),
        "State inclusion block is no longer canonical"
    );
    block_confirmations(number, rpc.tip_header()?.number_value()?)
}

fn validate_publication_sponsor<'a>(
    args: &'a [u8],
    channel: &[u8],
    state_type: &[u8],
    state_number: u64,
    change_lock: &[u8],
) -> Result<WireSponsorPolicy<'a>> {
    let policy = WireSponsorPolicy::parse(args).map_err(invalid)?;
    ensure!(
        policy.channel_id() == channel,
        "sponsor belongs to a different channel"
    );
    ensure!(
        policy.publication_state_type_hash() == state_type,
        "sponsor belongs to a different State type"
    );
    ensure!(
        policy.change_lock() == change_lock,
        "sponsor change lock differs from the selected return key"
    );
    ensure!(
        state_number >= policy.min_state_number() && state_number <= policy.max_state_number(),
        "publication state is outside sponsor range"
    );
    ensure!(
        policy.already_spent() <= policy.max_total_fee(),
        "sponsor budget is exhausted or malformed"
    );
    Ok(policy)
}

fn validate_sponsor_fee(policy: &WireSponsorPolicy<'_>, fee: u64) -> Result<()> {
    ensure!(
        fee <= policy.max_fee_per_tx(),
        "fee exceeds sponsor per-transaction cap"
    );
    ensure!(
        policy
            .already_spent()
            .checked_add(fee)
            .is_some_and(|spent| spent <= policy.max_total_fee()),
        "fee exceeds remaining sponsor budget"
    );
    Ok(())
}

pub(super) fn verify_chain_id(rpc: &CkbRpcClient, expected: &[u8]) -> Result<()> {
    let genesis = rpc
        .genesis_block_hash()?
        .ok_or_else(|| anyhow!("canonical genesis hash unavailable"))?;
    ensure!(
        genesis.as_bytes() == expected,
        "funding chain ID differs from RPC genesis"
    );
    Ok(())
}

pub fn transact(rpc: &CkbRpcClient, options: Options) -> Result<Value> {
    ensure!(
        !matches!(options.fee_authorization, FeeAuthorization::Sponsor { .. })
            || matches!(options.operation, Operation::Publish),
        "sponsor policy admits publication only"
    );
    ensure!(
        options.fee > 0 && options.fee <= options.max_fee,
        "fee must be positive and within max_fee"
    );
    ensure!(
        matches!(options.operation, Operation::Publish) || options.publication_profile.is_none(),
        "publication profile applies only to publication"
    );
    ensure!(
        options.publication_profile.is_some() == options.attempt_log.is_some(),
        "publication profile and attempt log must be supplied together"
    );
    let stored = read_package(&options.package)?;
    let summary = stored.validate()?;
    ensure!(
        summary.vaults_bound && summary.phase == "settling",
        "requires bound settling recovery package"
    );
    let decoded = stored.decode()?;
    let header = wire::MultiAssetStateHeader::parse(&decoded.header).map_err(invalid)?;
    verify_chain_id(rpc, header.chain_id())?;
    let witness = wire::MultiAssetWitness::parse(&decoded.witness).map_err(invalid)?;
    let (fee_lock, key) = options.fee_authorization.identity()?;
    let state_point = parse_out_point(&options.state_out_point)?;
    let fee_point = parse_out_point(&options.fee_out_point)?;
    let vault_points = validate_vaults(rpc, &witness)?;
    ensure!(
        state_point != fee_point
            && !vault_points.contains(&state_point)
            && !vault_points.contains(&fee_point),
        "fee, State and Vault inputs must be distinct"
    );
    let state = load_canonical_live_cell(rpc, state_point.clone())?;
    let old_header = wire::MultiAssetStateHeader::parse(&state.data).map_err(invalid)?;
    ensure!(
        state.output.lock() == script(&witness, 5)?
            && state.output.type_().to_opt() == Some(script(&witness, 4)?)
            && state.capacity == decoded.carrier_capacity,
        "State authority/carrier does not match recovery package"
    );
    let activation = if matches!(options.operation, Operation::Activate) {
        Some(recover_activation(rpc, &state_point, &state.data, &stored)?)
    } else {
        ensure!(
            old_header.same_context_except_progress(&header),
            "recovery package funding context differs from live State"
        );
        None
    };
    let fee_cell = load_canonical_live_cell(rpc, fee_point.clone())?;
    ensure!(
        fee_cell.output.type_().is_none() && fee_cell.data.is_empty(),
        "fee source cannot contain typed assets or data"
    );
    let mut dependencies = decoded.cell_deps.clone();
    let resolved_deps = live_dependencies(rpc, &dependencies)?;
    let mut resolved = resolved_deps.cells;
    let mut resolved_points = resolved_deps.out_points;
    let sponsor_args = fee_cell.output.lock().args().raw_data();
    let sponsor_policy = match &options.fee_authorization {
        FeeAuthorization::Wallet { .. } => {
            ensure!(
                fee_cell.output.lock() == fee_lock,
                "fee input is not controlled by the wallet signer"
            );
            None
        }
        FeeAuthorization::Sponsor { .. } => {
            let policy = validate_publication_sponsor(
                &sponsor_args,
                header.channel_id(),
                state
                    .output
                    .type_()
                    .to_opt()
                    .ok_or_else(|| anyhow!("missing State type"))?
                    .calc_script_hash()
                    .as_slice(),
                header.state_number(),
                fee_lock.calc_script_hash().as_slice(),
            )?;
            let binary = fs::read(options.contracts_dir.join("morph-sponsor-lock"))?;
            let hash = blake2b_256(&binary);
            if !resolved.iter().any(|cell| {
                code_matches(&fee_cell.output.lock(), cell) && blake2b_256(&cell.data) == hash
            }) {
                let deployed = find_deployed_contract_by_script(
                    rpc,
                    &options.contracts_dir,
                    "morph-sponsor-lock",
                    &fee_cell.output.lock(),
                    rpc.tip_header()?.number_value()?,
                )?;
                ensure!(
                    dependencies.len() < 64 && resolved.len() < 64,
                    "sponsor dependency exceeds transaction dependency bound"
                );
                resolved.push(load_canonical_live_cell(rpc, deployed.out_point)?);
                dependencies.push(deployed.cell_dep);
            }
            Some(policy)
        }
    };
    validate_resolved_code(
        &options.contracts_dir,
        &witness,
        &resolved,
        &fee_cell.output.lock(),
    )?;
    if activation.is_some() {
        resolved_points.extend(vault_points.iter().map(|point| point.as_slice().to_vec()));
        ensure!(
            resolved_points.len() <= 64,
            "activation exceeds resolved dependency bound"
        );
        let code_deps = std::mem::take(&mut dependencies);
        dependencies.extend(vault_points.iter().cloned().map(direct_cell_dep));
        dependencies.extend(
            code_deps
                .into_iter()
                .filter(|dep| !vault_points.contains(&dep.out_point())),
        );
        ensure!(
            dependencies.len() <= 64,
            "activation exceeds transaction dependency bound"
        );
    }
    let since = wire::MultiAssetVaultArgs::parse(&script(&witness, 3)?.args().raw_data())
        .map_err(invalid)?
        .finalise_since();
    let finalise = matches!(options.operation, Operation::Finalise);
    if finalise {
        ensure!(
            state.data.as_ref() == decoded.header,
            "finalisation requires the exact published state"
        );
        ensure!(
            state_confirmations(rpc, &state_point)? >= (since & 0x00ff_ffff_ffff_ffff),
            "State challenge delay has not matured"
        );
    } else if activation.is_none() {
        ensure!(
            header.state_number() > old_header.state_number(),
            "publication must advance the state number"
        );
    }
    let proof = if let Some(activation) = &activation {
        activation.witness.clone()
    } else {
        recovery_witness(&stored, !finalise)?
    };
    let output_header = activation
        .as_ref()
        .map_or(decoded.header.as_slice(), |activation| {
            activation.header.as_slice()
        });
    let operation = match options.operation {
        Operation::Activate => "activate",
        Operation::Publish => "publish",
        Operation::Finalise => "finalise",
    };
    let resulting_state = if finalise {
        None
    } else {
        let state = wire::MultiAssetStateHeader::parse(output_header).map_err(invalid)?;
        Some(json!({"state_number": state.state_number().to_string(),
            "phase": if state.phase() == PHASE_ACTIVE { "active" } else { "settling" }}))
    };
    let build = |fee: u64| -> Result<ckb_types::core::TransactionView> {
        ensure!(fee <= options.max_fee, "fee exceeds max_fee");
        if let Some(policy) = &sponsor_policy {
            validate_sponsor_fee(policy, fee)?;
        }
        let change = fee_cell
            .capacity
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("fee cell capacity exhausted"))?;
        ensure_change_capacity(&fee_lock, change)?;
        let mut tx = TransactionBuilder::default()
            .set_cell_deps(dependencies.clone())
            .input(CellInput::new(
                state_point.clone(),
                if finalise { since } else { 0 },
            ))
            .witness(proof.clone());
        if finalise {
            for point in &vault_points {
                tx = tx.input(CellInput::new(point.clone(), 0));
            }
            let mut type_index = 6;
            for index in 0..witness.descriptor().count() {
                let payout = witness.descriptor().entry(index).map_err(invalid)?;
                let ty = if payout.asset.kind == 1 {
                    let ty = script(&witness, type_index)?;
                    type_index += 1;
                    Some(ty)
                } else {
                    None
                };
                for participant in 0..2 {
                    let value = payout.allocations[participant];
                    let capacity = value.capacity().map_err(invalid)?;
                    if capacity == 0 {
                        continue;
                    }
                    let output_type = if value.amount > 0 { ty.clone() } else { None };
                    let data = if output_type.is_some() {
                        value.amount.to_le_bytes().to_vec()
                    } else {
                        vec![]
                    };
                    tx = tx
                        .output(
                            CellOutput::new_builder()
                                .capacity(capacity)
                                .lock(script(&witness, participant)?)
                                .type_(output_type.pack())
                                .build(),
                        )
                        .output_data(Bytes::from(data).pack());
                }
            }
            tx = tx
                .output(
                    CellOutput::new_builder()
                        .capacity(decoded.carrier_capacity)
                        .lock(script(&witness, 2)?)
                        .build(),
                )
                .output_data(Bytes::new().pack());
        } else {
            tx = tx
                .output(state.output.clone())
                .output_data(Bytes::copy_from_slice(output_header).pack());
        }
        let fee_index = if finalise { 1 + vault_points.len() } else { 1 };
        tx = tx
            .input(CellInput::new(fee_point.clone(), 0))
            .output(
                CellOutput::new_builder()
                    .capacity(change)
                    .lock(fee_lock.clone())
                    .build(),
            )
            .output_data(Bytes::new().pack());
        if let Some(key) = &key {
            super::multi_asset::sign_group(tx.build(), key, &[fee_index])
        } else {
            Ok(tx.witness(empty_witness()).build())
        }
    };
    // Recovery evidence must survive restart before any network mutation.
    let durable = write_package(&options.store_dir, &stored)?;
    let runtime = if let Some(path) = &options.publication_profile {
        let profile = read_publication_profile(path)?;
        ensure!(
            profile.window.configured_challenge_blocks == (since & 0x00ff_ffff_ffff_ffff),
            "publication profile challenge blocks differ from committed Vault policy"
        );
        let observed_confirmations = if old_header.phase() == PHASE_SETTLING {
            state_confirmations(rpc, &state_point)?
        } else {
            0
        };
        Some(PublicationRuntime {
            deadline: publication_deadline(&profile, observed_confirmations)?,
            profile,
            attempt_log: options.attempt_log.clone(),
            intent_id: summary.package_id.clone(),
            channel_id: summary.channel_id.clone(),
            funding_context_id: summary.funding_context_id.clone(),
            target_state_number: header.state_number(),
        })
    } else {
        None
    };
    let (tx, fee, observation) = if let Some(runtime) = &runtime {
        let observation = runtime.profile.observe_fee_market(rpc)?;
        let rate = initial_fee_rate(&runtime.profile.fee, &observation)?;
        let provisional = build(1)?;
        let fee = fee_for_rate(rate, provisional.data().as_slice().len())?;
        ensure!(
            fee <= runtime.profile.fee.max_fee,
            "fee exceeds publication profile cap"
        );
        let tx = build(fee)?;
        verify_initial_fee_convergence(rate, fee, tx.data().as_slice().len())?;
        (tx, fee, Some(observation))
    } else {
        (build(options.fee)?, options.fee, None)
    };
    // Both paths execute VM preflight before any submission.
    if options.dry_run {
        let metrics = transaction_metrics(rpc, &tx)?;
        return Ok(
            json!({"schema":"morph.multi_asset_transaction.v1", "operation":operation, "resulting_state":resulting_state, "dry_run":true,
            "package":summary,"durable_package":durable,"fee":fee.to_string(),"fee_source":options.fee_authorization.name(),"metrics":metrics,
            "transaction": ckb_jsonrpc_types::Transaction::from(tx.data())}),
        );
    }
    let (sent, actual_fee, canonical_confirmed) =
        if let (Some(runtime), Some(observation)) = (&runtime, &observation) {
            let sent = send_publication_attempts(
                rpc,
                tx,
                fee,
                options.mine_blocks,
                runtime,
                observation,
                &build,
            )?;
            (sent.report, sent.fee, sent.canonical_confirmed)
        } else {
            let sent = send_and_mine(rpc, tx, options.mine_blocks)?;
            let confirmed = transaction_confirmations(rpc, &sent)? > 0;
            (sent, fee, confirmed)
        };
    Ok(
        json!({"schema":"morph.multi_asset_transaction.v1", "operation":operation, "resulting_state":resulting_state, "dry_run":false,
        "package":summary,"durable_package":durable,"fee":actual_fee.to_string(),"fee_source":options.fee_authorization.name(),
        "tx_hash":sent.tx_hash,"status":sent.status,"block_number":sent.block_number,
        "block_hash":sent.block_hash,"canonical_confirmed":canonical_confirmed,
        "metrics":sent.metrics,"mined_blocks":sent.mined_blocks}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_resolution_distinguishes_code_data_hash_from_type_identity() {
        let binary = Bytes::from(vec![1, 2, 3]);
        let type_script = Script::new_builder()
            .code_hash([7u8; 32].pack())
            .hash_type(1u8)
            .args(Bytes::from(vec![8; 32]).pack())
            .build();
        let cell = LiveCellDetails {
            output: CellOutput::new_builder()
                .type_(Some(type_script.clone()).pack())
                .build(),
            capacity: 0,
            data: binary.clone(),
        };
        let by_data = Script::new_builder()
            .code_hash(blake2b_256(&binary).pack())
            .hash_type(2u8)
            .build();
        let by_type = Script::new_builder()
            .code_hash(type_script.calc_script_hash())
            .hash_type(1u8)
            .build();
        assert!(code_matches(&by_data, &cell));
        assert!(code_matches(&by_type, &cell));
        assert!(!code_matches(
            &by_data.as_builder().hash_type(1u8).build(),
            &cell
        ));
        assert!(!code_matches(
            &by_type.as_builder().hash_type(2u8).build(),
            &cell
        ));
        let replacement = LiveCellDetails {
            data: Bytes::from(vec![9]),
            ..cell
        };
        assert!(!code_matches(
            &Script::new_builder()
                .code_hash(blake2b_256(&binary).pack())
                .hash_type(0u8)
                .build(),
            &replacement
        ));
    }
}

#[cfg(test)]
mod sponsor_tests {
    use super::*;

    fn policy() -> [u8; SPONSOR_POLICY_LEN] {
        let mut args = [0; SPONSOR_POLICY_LEN];
        args[..32].fill(1);
        put_u64(&mut args, 32, 2);
        put_u64(&mut args, 40, 4);
        put_u64(&mut args, 48, 10);
        put_u64(&mut args, 56, 20);
        put_u64(&mut args, 64, 5);
        args[72..104].fill(2);
        args[104..136].fill(3);
        args
    }
    fn view(args: &[u8]) -> Result<WireSponsorPolicy<'_>> {
        validate_publication_sponsor(args, &[1; 32], &[2; 32], 3, &[3; 32])
    }

    #[test]
    fn sponsor_fee_authority_checks_identity_range_and_both_budget_bounds() {
        let args = policy();
        let valid = view(&args).unwrap();
        validate_sponsor_fee(&valid, 10).unwrap();
        assert!(
            validate_sponsor_fee(&valid, 11)
                .unwrap_err()
                .to_string()
                .contains("per-transaction")
        );
        for offset in [0, 72, 104] {
            let mut corrupted = args;
            corrupted[offset] ^= 1;
            assert!(view(&corrupted).is_err());
        }
        assert!(validate_publication_sponsor(&args, &[1; 32], &[2; 32], 5, &[3; 32]).is_err());
        let mut spent = args;
        put_u64(&mut spent, 64, 19);
        assert!(
            validate_sponsor_fee(&view(&spent).unwrap(), 2)
                .unwrap_err()
                .to_string()
                .contains("remaining sponsor")
        );
        put_u64(&mut spent, 64, 21);
        assert!(view(&spent).is_err());
        let mut overflow = args;
        for offset in [48, 56, 64] {
            put_u64(&mut overflow, offset, u64::MAX);
        }
        assert!(validate_sponsor_fee(&view(&overflow).unwrap(), 1).is_err());
    }

    #[test]
    fn sponsor_mode_needs_only_public_change_identity_and_redacts_wallet_debug() {
        let key = parse_privkey(&hex::encode([1u8; 32])).unwrap();
        let pubkey = k256_pubkey(&k256_signing_key(&hex::encode([1u8; 32])).unwrap());
        let public = FeeAuthorization::Sponsor {
            change_pubkey: hex32_or_pubkey(&pubkey),
        };
        let (change, private) = public.identity().unwrap();
        assert!(private.is_none());
        assert_eq!(change, secp256k1_lock(&key).unwrap());
        let wallet = FeeAuthorization::Wallet {
            private_key: hex::encode([1u8; 32]),
        };
        assert_eq!(format!("{wallet:?}"), "Wallet");
    }

    fn hex32_or_pubkey(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    use morph_core::{MultiAssetRecoveryPackage, ParticipantSignature, Phase};

    fn signatures(digest: &[u8; 32]) -> Vec<ParticipantSignature> {
        let mut signatures = [1, 2]
            .map(|seed| {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                let signature: Signature = key.sign_prehash(digest).unwrap();
                ParticipantSignature {
                    pubkey_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .to_vec();
        signatures.sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        signatures
    }
    fn sign(package: &mut MultiAssetRecoveryPackage) {
        package.authorization.signatures = signatures(&package.state.signing_digest().unwrap());
    }

    fn fixture() -> (MultiAssetRecoveryPackage, MultiAssetRecoveryPackage, Bytes) {
        let stored = crate::multi_asset_packages::fixture_package().unwrap();
        let target = stored.recovery().unwrap();
        let mut initial = target.clone();
        initial.state.header.phase = Phase::Active;
        initial.state.header.state_number = 0;
        initial.state.vault_outpoint_set_root = [0; 32];
        initial.outpoints.clear();
        initial.settlement.payouts[0].values[0].amount -= 1;
        initial.settlement.payouts[0].values[1].amount += 1;
        initial.state.header.settlement_descriptor_commitment =
            initial.settlement.commitment().unwrap();
        let digest = initial
            .state
            .root_funding_signing_digest(&[44; 32])
            .unwrap();
        initial.authorization.signatures = signatures(&digest);
        let evidence = morph_core::encode_multi_asset_witness(
            &initial.manifest,
            &initial.settlement,
            &initial.outpoints,
            &initial.scripts,
        )
        .unwrap();
        let witness = WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    morph_core::encode_multi_asset_signatures(&initial.authorization)
                        .unwrap()
                        .to_vec(),
                ))
                .pack(),
            )
            .output_type(Some(Bytes::from(evidence)).pack())
            .build()
            .as_bytes();
        (initial, target, witness)
    }

    #[test]
    fn activation_recovers_original_descriptor_without_reusing_creation_signatures() {
        let (initial, target, witness) = fixture();
        let raw = initial.state.encode().unwrap();
        let recovered = activation_evidence(&raw, &witness, &[44; 32], &target).unwrap();
        let before = wire::MultiAssetStateHeader::parse(&raw).unwrap();
        let after = wire::MultiAssetStateHeader::parse(&recovered.header).unwrap();
        assert!(before.is_activation_to(&after));
        assert_eq!(after.state_number(), 0);
        assert_eq!(after.phase(), PHASE_ACTIVE);
        assert_eq!(
            after.settlement_descriptor_commitment(),
            initial.state.header.settlement_descriptor_commitment
        );
        assert_ne!(
            after.settlement_descriptor_commitment(),
            target.state.header.settlement_descriptor_commitment
        );
        let args = WitnessArgs::from_slice(&recovered.witness).unwrap();
        assert!(args.input_type().to_opt().is_none());
        assert!(args.lock().to_opt().is_none());
        let evidence = args.output_type().to_opt().unwrap().raw_data();
        wire::MultiAssetWitness::parse(&evidence)
            .unwrap()
            .validate_header(&after)
            .unwrap();
    }

    #[test]
    fn activation_rejects_foreign_context_provenance_and_missing_creation_evidence() {
        let (initial, target, witness) = fixture();
        let raw = initial.state.encode().unwrap();
        assert!(activation_evidence(&raw, &witness, &[45; 32], &target).is_err());
        assert!(
            activation_evidence(&raw, &WitnessArgs::default().as_bytes(), &[44; 32], &target)
                .is_err()
        );
        assert!(
            activation_evidence(
                &target.state.encode().unwrap(),
                &witness,
                &[44; 32],
                &target
            )
            .is_err()
        );
        let mut foreign = target;
        foreign.state.header.funding_epoch += 1;
        sign(&mut foreign);
        assert!(
            activation_evidence(&raw, &witness, &[44; 32], &foreign)
                .err()
                .unwrap()
                .to_string()
                .contains("different funding context")
        );
    }
    #[test]
    fn activation_recovers_creation_evidence_from_a_splice_funding_witness() {
        use morph_core::*;
        let current = crate::multi_asset_packages::fixture_package()
            .unwrap()
            .recovery()
            .unwrap();
        let point = MultiAssetOutPoint {
            tx_hash: [88; 32],
            index: 0,
        };
        let anchor = multi_asset_splice_funding_anchor(&point);
        let mut next = current.clone();
        let since = wire::MultiAssetVaultArgs::parse(&current.scripts.vault_lock[53..])
            .unwrap()
            .finalise_since();
        let mut args = anchor.to_vec();
        args.extend_from_slice(&since.to_le_bytes());
        let ty = Script::from_slice(&current.scripts.state_type)
            .unwrap()
            .as_builder()
            .args(Bytes::from(args).pack())
            .build();
        let lock = Script::from_slice(&current.scripts.state_lock)
            .unwrap()
            .as_builder()
            .args(ty.calc_script_hash().as_bytes().pack())
            .build();
        let vault = Script::from_slice(&current.scripts.vault_lock)
            .unwrap()
            .as_builder()
            .args(
                Bytes::from(
                    wire::encode_multi_asset_vault_args(
                        &anchor,
                        since,
                        &ty.calc_script_hash().unpack(),
                        &lock.calc_script_hash().unpack(),
                    )
                    .unwrap()
                    .to_vec(),
                )
                .pack(),
            )
            .build();
        next.scripts.state_type = ty.as_slice().to_vec();
        next.scripts.state_lock = lock.as_slice().to_vec();
        next.scripts.vault_lock = vault.as_slice().to_vec();
        for entry in &mut next.manifest.vaults {
            entry.lock_hash = vault.calc_script_hash().unpack();
        }
        next.state.vault_content_set_root = next.manifest.commitment().unwrap();
        next.state.header.funding_anchor = anchor;
        next.state.header.funding_epoch += 1;
        next.state.header.state_number = 0;
        next.state.header.phase = Phase::Active;
        next.state.vault_outpoint_set_root = [0; 32];
        next.outpoints.clear();
        sign(&mut next);
        let mut recovery = next.clone();
        recovery.state.header.phase = Phase::Settling;
        recovery.state.header.state_number = 1;
        recovery.outpoints = (0..recovery.manifest.vaults.len())
            .map(|index| MultiAssetOutPoint {
                tx_hash: [99; 32],
                index: index as u32 + 1,
            })
            .collect();
        recovery.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
        sign(&mut recovery);
        let plan = MultiAssetSpliceProposal {
            base_state_digest: current.state.signing_digest().unwrap(),
            old_state_outpoint: point,
            transaction_hash: [99; 32],
            new_state_authorization: next.authorization.clone(),
            initial_recovery_authorization: recovery.authorization.clone(),
            new_state: next.state.clone(),
            new_manifest: next.manifest,
            new_settlement: next.settlement,
            new_scripts: next.scripts,
            flows: current
                .manifest
                .vaults
                .iter()
                .map(|entry| MultiAssetSpliceFlow {
                    asset: entry.asset.clone(),
                    deposit: MultiAssetValue::default(),
                    withdrawal: MultiAssetValue::default(),
                })
                .collect(),
            withdrawal_lock: vec![],
        };
        let authorization = StateAuthorization {
            threshold: 2,
            signatures: signatures(&plan.signing_digest(&current).unwrap()),
        };
        let witness = WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&plan.new_state_authorization)
                        .unwrap()
                        .to_vec(),
                ))
                .pack(),
            )
            .output_type(
                Some(Bytes::from(
                    plan.encode_witness(&current, &authorization).unwrap(),
                ))
                .pack(),
            )
            .build();
        let header = next.state.encode().unwrap();
        let recovered =
            activation_evidence(&header, &witness.as_bytes(), &[99; 32], &recovery).unwrap();
        assert!(
            wire::MultiAssetStateHeader::parse(&header)
                .unwrap()
                .is_activation_to(&wire::MultiAssetStateHeader::parse(&recovered.header).unwrap())
        );
    }
}

/// Complete registered-Type and CKB accounting shared by root/splice funding.
pub(super) fn validate_funding_balances(
    transaction: &ckb_types::packed::Transaction,
    inputs: &[LiveCellDetails],
    registered: &BTreeSet<[u8; 32]>,
    max_fee: u64,
) -> Result<u64> {
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    fn add(
        amounts: &mut BTreeMap<[u8; 32], u128>,
        registered: &BTreeSet<[u8; 32]>,
        output: &CellOutput,
        data: &[u8],
    ) -> Result<()> {
        if let Some(ty) = output.type_().to_opt() {
            let hash: [u8; 32] = ty.calc_script_hash().unpack();
            if registered.contains(&hash) {
                let amount = u128::from_le_bytes(
                    data.try_into()
                        .map_err(|_| anyhow!("registered token data must be 16 bytes"))?,
                );
                let sum = amounts.entry(hash).or_default();
                *sum = sum
                    .checked_add(amount)
                    .ok_or_else(|| anyhow!("token total overflow"))?;
            }
        }
        Ok(())
    }
    let mut input_capacity = 0u64;
    for cell in inputs {
        input_capacity = input_capacity
            .checked_add(cell.capacity)
            .ok_or_else(|| anyhow!("input capacity overflow"))?;
        add(&mut before, registered, &cell.output, &cell.data)?;
    }
    let mut output_capacity = 0u64;
    for (index, output) in transaction.raw().outputs().into_iter().enumerate() {
        output_capacity = output_capacity
            .checked_add(output.capacity().unpack())
            .ok_or_else(|| anyhow!("output capacity overflow"))?;
        let data = transaction
            .raw()
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("missing output data"))?
            .raw_data();
        add(&mut after, registered, &output, &data)?;
    }
    for hash in registered {
        ensure!(
            before.get(hash).copied().unwrap_or(0) == after.get(hash).copied().unwrap_or(0),
            "registered token is not conserved"
        );
    }
    let fee = input_capacity
        .checked_sub(output_capacity)
        .ok_or_else(|| anyhow!("funding creates CKB capacity"))?;
    ensure!(
        fee > 0 && fee <= max_fee,
        "funding fee is zero or exceeds max_fee"
    );
    Ok(fee)
}
