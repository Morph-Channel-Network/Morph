//! Native current Factory lifecycle. All input authority and code dependencies
//! are verified against the canonical chain before a local key is invoked.
use super::multi_asset_operator as operator;
use super::multi_asset_splice_operator::{canonical_checkpoint, canonical_transaction};
use super::*;
use crate::factory_packets::{StoredFactoryCustody, StoredFactoryRequest, read_request};
use crate::factory_root_transaction::{
    FactoryAuthorityHashes, FactoryRootTerms, PreparedFactoryRoot,
};
use crate::funding_wallets::FundingCell;
use crate::multi_asset_packages::{canonical_hex, read_bounded_json};
use crate::persistence::write_private_immutable;
use ckb_types::packed;
use morph_core::{
    FactoryCustody, FactoryParticipantSignature, FactorySigningRequest, MultiAssetOutPoint,
    ValueSubject,
};
use morph_script_common::factory_multi_asset as wire;
use serde_json::{Value, json};

#[derive(Debug, clap::Args)]
pub(crate) struct PrepareOptions {
    #[arg(long)]
    pub terms: PathBuf,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub admission_config: PathBuf,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub max_fee: u64,
    #[arg(long)]
    pub output: PathBuf,
}
#[derive(Debug, clap::Args)]
pub(crate) struct WalletSignOptions {
    #[arg(long)]
    pub terms: PathBuf,
    #[arg(long)]
    pub request: PathBuf,
    #[arg(long)]
    pub transaction: PathBuf,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub admission_config: PathBuf,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub max_fee: u64,
    #[arg(long)]
    pub store_dir: PathBuf,
    #[arg(long = "private-key-file", env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::secp256k1_file)]
    pub private_key: morph_key_input::SecretString,
}
#[derive(Debug, clap::Args)]
pub(crate) struct SubmitOptions {
    #[arg(long)]
    pub request: PathBuf,
    #[arg(long)]
    pub transaction: PathBuf,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub admission_config: PathBuf,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub max_fee: u64,
    #[arg(long, default_value_t = 4)]
    pub mine_blocks: u64,
    #[arg(long)]
    pub store_dir: PathBuf,
    #[arg(long)]
    pub dry_run: bool,
}
#[derive(Debug, clap::Args)]
pub(crate) struct ActivateOptions {
    #[arg(long)]
    pub request: PathBuf,
    #[arg(long)]
    pub fee_out_point: String,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub admission_config: PathBuf,
    #[arg(long)]
    pub store_dir: PathBuf,
    #[arg(long)]
    pub fee: u64,
    #[arg(long)]
    pub max_fee: u64,
    #[arg(long, default_value_t = 4)]
    pub mine_blocks: u64,
    #[arg(long = "private-key-file", env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::secp256k1_file)]
    pub private_key: morph_key_input::SecretString,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum FactoryCommand {
    /// Pin a no-value experiment's exact policy/code and one shared lifetime ledger.
    AdmissionConfig(crate::admission::ConfigOptions),
    /// Construct a typed metadata, rights or custody request from current evidence.
    Prepare(crate::factory_transaction::PrepareOptions),
    /// Run actual-node acceptance using independent Factory participant journals.
    Smoke(super::factory_acceptance::Options),
    /// Construct exact current Factory funding terms without any participant key.
    RootPrepare(PrepareOptions),
    /// Reconstruct funding terms and sign only the explicit wallet's input group.
    RootWalletSign(WalletSignOptions),
    /// Reconstruct typed operation terms and sign only the explicit external wallet group.
    WalletSign(WalletSignOptions),
    /// Keyless submission of a completely signed, VM-verified exact request.
    Submit(SubmitOptions),
    /// Bind a newly created complete Vault set using an independent fee wallet.
    Activate(ActivateOptions),
}

pub(crate) fn run(rpc: &CkbRpcClient, command: FactoryCommand) -> Result<Value> {
    match command {
        FactoryCommand::AdmissionConfig(options) => crate::admission::create_config(rpc, options),
        FactoryCommand::Prepare(options) => crate::factory_transaction::prepare(rpc, options),
        FactoryCommand::Smoke(options) => super::factory_acceptance::run(rpc, options),
        FactoryCommand::RootPrepare(options) => prepare(rpc, options),
        FactoryCommand::RootWalletSign(options) => sign_wallet(rpc, options),
        FactoryCommand::WalletSign(options) => sign_preparation_wallet(rpc, options),
        FactoryCommand::Submit(options) => submit(rpc, options),
        FactoryCommand::Activate(options) => activate(rpc, options),
    }
}

pub(crate) fn verify_checkpoint(
    rpc: &CkbRpcClient,
    checkpoint: &crate::rpc::HeaderView,
) -> Result<()> {
    ensure!(
        canonical_checkpoint(rpc, checkpoint)?,
        "chain reorganized during Factory authorization"
    );
    Ok(())
}

fn point(value: &MultiAssetOutPoint) -> OutPoint {
    OutPoint::new(value.tx_hash.pack(), value.index)
}

pub(crate) fn validate_live_custody(
    rpc: &CkbRpcClient,
    custody: &FactoryCustody,
    directory: &Path,
) -> Result<()> {
    crate::factory_artifacts::validate_custody_artifacts(custody, directory)?;
    operator::verify_chain_id(rpc, custody.state()?.chain_id())?;
    let state = load_canonical_live_cell(rpc, point(&custody.state_out_point))?;
    ensure!(
        state.data.as_ref() == custody.header
            && state.capacity == custody.state_carrier_capacity
            && state.output.lock().as_slice() == custody.state_lock
            && state
                .output
                .type_()
                .to_opt()
                .is_some_and(|ty| ty.as_slice() == custody.state_type),
        "live Factory State differs from authenticated source custody"
    );
    validate_live_vaults(rpc, custody)
}

fn validate_live_vaults(rpc: &CkbRpcClient, custody: &FactoryCustody) -> Result<()> {
    for (vault, outpoint) in custody.manifest.vaults.iter().zip(&custody.vault_outpoints) {
        let cell = load_canonical_live_cell(rpc, point(outpoint))?;
        let capacity = vault
            .value
            .reserve
            .checked_add(vault.value.business_ckb)
            .ok_or_else(|| anyhow!("Factory Vault capacity overflow"))?;
        let (ty, data) = match vault.asset {
            VaultAsset::Ckb => (None, vec![]),
            VaultAsset::Xudt(hash) => (
                Some(
                    custody
                        .type_scripts
                        .iter()
                        .find(|entry| entry.type_hash == hash)
                        .ok_or_else(|| anyhow!("missing committed Factory Type script"))?
                        .script
                        .as_slice(),
                ),
                vault.value.amount.to_le_bytes().to_vec(),
            ),
        };
        ensure!(
            cell.capacity == capacity
                && cell.output.lock().as_slice() == custody.vault_lock
                && cell
                    .output
                    .type_()
                    .to_opt()
                    .as_ref()
                    .map(|value| value.as_slice())
                    == ty
                && cell.data.as_ref() == data,
            "live Factory Vault differs from complete committed source"
        );
    }
    Ok(())
}

/// Signing-grade chain guard. A public packet alone cannot establish these facts.
pub(crate) fn verify_request(
    rpc: &CkbRpcClient,
    request: &FactorySigningRequest,
    directory: &Path,
    max_fee: u64,
) -> Result<crate::rpc::HeaderView> {
    request.validate(&request.members()?)?;
    verify_request_for_review(rpc, request, directory, max_fee)
}

/// Public child preparation can precede possession attestations. This performs
/// the same chain/body/code checks, but it never grants signing authority.
pub(crate) fn verify_request_for_review(
    rpc: &CkbRpcClient,
    request: &FactorySigningRequest,
    directory: &Path,
    max_fee: u64,
) -> Result<crate::rpc::HeaderView> {
    request.validate_for_review(&request.members()?)?;
    crate::factory_artifacts::validate_request_artifacts_for_review(request, directory)?;
    let anchor = request
        .source
        .as_ref()
        .or(request.target.as_ref())
        .ok_or_else(|| anyhow!("Factory request has no identity"))?;
    operator::verify_chain_id(rpc, anchor.state()?.chain_id())?;
    let checkpoint = rpc.tip_header()?;
    if let Some(source) = &request.source {
        validate_live_custody(rpc, source, directory)?;
    }
    let raw = request.raw_transaction()?;
    let deps = raw.cell_deps().into_iter().collect::<Vec<_>>();
    let resolved = operator::live_dependencies(rpc, &deps)?;
    let mut unique = BTreeSet::new();
    let mut live = Vec::new();
    for input in raw.inputs() {
        let previous = input.previous_output();
        ensure!(
            unique.insert(previous.as_slice().to_vec())
                && !resolved.out_points.contains(previous.as_slice())
                && !deps.iter().any(|dep| dep.out_point() == previous),
            "duplicate Factory input or consumed code dependency"
        );
        let custody_input = request.source.as_ref().is_some_and(|source| {
            previous == point(&source.state_out_point)
                || source
                    .vault_outpoints
                    .iter()
                    .any(|outpoint| previous == point(outpoint))
        });
        let cell = load_canonical_live_cell(rpc, previous)?;
        ensure!(
            custody_input
                || (crate::admission::is_standard_wallet(&cell.output.lock())?
                    && cell.output.type_().to_opt().is_none()
                    && cell.data.is_empty()),
            "Factory experiment external inputs must be independent plain standard-wallet cells"
        );
        check_code(&cell.output, &resolved.cells)?;
        live.push(cell);
    }
    for (index, output) in raw.outputs().into_iter().enumerate() {
        check_code(&output, &resolved.cells)?;
        let data = raw
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("missing Factory output data"))?
            .raw_data();
        ensure!(
            u64::from(output.capacity())
                >= output
                    .occupied_capacity(Capacity::bytes(data.len())?)?
                    .as_u64(),
            "Factory output is below occupied capacity"
        );
    }
    let registered = request
        .source
        .iter()
        .chain(&request.target)
        .flat_map(|custody| custody.type_scripts.iter().map(|ty| ty.type_hash))
        .collect();
    let transaction = packed::Transaction::new_builder().raw(raw).build();
    operator::validate_funding_balances(&transaction, &live, &registered, max_fee)?;
    verify_checkpoint(rpc, &checkpoint)?;
    Ok(checkpoint)
}

fn check_code(output: &CellOutput, code: &[LiveCellDetails]) -> Result<()> {
    for script in std::iter::once(output.lock()).chain(output.type_().to_opt()) {
        ensure!(
            code.iter()
                .any(|cell| operator::code_matches(&script, cell)),
            "Factory input/output script has no canonical code dependency"
        );
    }
    Ok(())
}

fn resolve_root(
    rpc: &CkbRpcClient,
    terms_path: &Path,
    directory: &Path,
    max_fee: u64,
) -> Result<(FactoryRootTerms, PreparedFactoryRoot)> {
    let terms: FactoryRootTerms = read_bounded_json(terms_path, 1024 * 1024)?;
    let genesis = rpc
        .genesis_block_hash()?
        .ok_or_else(|| anyhow!("canonical genesis unavailable"))?;
    let hash =
        |name: &str| -> Result<[u8; 32]> { Ok(blake2b_256(&fs::read(directory.join(name))?)) };
    let authority = FactoryAuthorityHashes {
        factory_type: hash("morph-factory-type")?,
        state_lock: hash("morph-state-lock")?,
        vault_lock: hash("morph-factory-vault-lock")?,
    };
    let cells = terms
        .points()?
        .into_iter()
        .map(|point| {
            let live = load_canonical_live_cell(rpc, point.clone())?;
            Ok(FundingCell {
                point,
                output: live.output,
                data: live.data,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let prepared = terms.build(genesis.0, authority, &cells, max_fee)?;
    Ok((terms, prepared))
}

pub(crate) fn prepare(rpc: &CkbRpcClient, options: PrepareOptions) -> Result<Value> {
    let (terms, prepared) =
        resolve_root(rpc, &options.terms, &options.contracts_dir, options.max_fee)?;
    let request = prepared.signing_request()?;
    crate::value_limit::read_value_limit_policy(&options.policy)?
        .enforce(&ValueSubject::from_factory_request(&request)?)?;
    let checkpoint = verify_request(rpc, &request, &options.contracts_dir, options.max_fee)?;
    crate::admission::reserve_native(
        rpc,
        &options.admission_config,
        &options.contracts_dir,
        &request,
        false,
        options.max_fee,
    )?;
    let packet = StoredFactoryRequest::from_core(&request)?;
    verify_checkpoint(rpc, &checkpoint)?;
    write_private_immutable(&options.output, &serde_json::to_vec_pretty(&packet)?)?;
    Ok(
        json!({"schema":"morph.factory_root_preparation.v1","request":options.output,"review":terms.review(&prepared)?,
        "request_id":canonical_hex(&request.request_id()?),"signing_digest":canonical_hex(&request.signing_digest()?),"broadcast":false}),
    )
}

fn read_transaction(path: &Path) -> Result<packed::Transaction> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(morph_core::FACTORY_MAX_TRANSACTION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= morph_core::FACTORY_MAX_TRANSACTION_BYTES,
        "Factory transaction exceeds byte bound"
    );
    Ok(packed::Transaction::from_slice(&bytes)?)
}

pub(crate) fn sign_wallet(rpc: &CkbRpcClient, options: WalletSignOptions) -> Result<Value> {
    let (terms, prepared) =
        resolve_root(rpc, &options.terms, &options.contracts_dir, options.max_fee)?;
    sign_exact_wallet(rpc, options, prepared.signing_request()?, &terms.funders, 0)
}

pub(crate) fn sign_preparation_wallet(
    rpc: &CkbRpcClient,
    options: WalletSignOptions,
) -> Result<Value> {
    let (terms, expected) =
        crate::factory_transaction::resolve_request(rpc, &options.terms, options.max_fee)?;
    let source = expected
        .source
        .as_ref()
        .ok_or_else(|| anyhow!("prepared request has no Factory source"))?;
    let offset = match expected.role {
        morph_core::FactorySigningRole::MetadataUpdate => 1,
        morph_core::FactorySigningRole::Materialisation => 1 + source.manifest.vaults.len(),
        morph_core::FactorySigningRole::Transition => {
            let frame = wire::FactoryReducedReleaseWitness::parse(&expected.witness)
                .map_err(|e| anyhow!("invalid Factory preparation: {e:?}"))?;
            if frame.operation().moves_custody() {
                1 + source.manifest.vaults.len()
            } else {
                1
            }
        }
        _ => return Err(anyhow!("use root-wallet-sign for initial funding")),
    };
    sign_exact_wallet(rpc, options, expected, &terms.funders, offset)
}

fn sign_exact_wallet(
    rpc: &CkbRpcClient,
    options: WalletSignOptions,
    expected: FactorySigningRequest,
    funders: &[crate::funding_wallets::FundingWallet],
    wallet_input_offset: usize,
) -> Result<Value> {
    let request = read_request(&options.request)?.decode()?;
    ensure!(
        expected.role == request.role
            && expected.transaction == request.transaction
            && expected.witness == request.witness
            && expected.source == request.source
            && expected.target == request.target
            && expected.target_rights == request.target_rights,
        "Factory wallet terms differ from exact approved request"
    );
    crate::value_limit::read_value_limit_policy(&options.policy)?
        .enforce(&ValueSubject::from_factory_request(&request)?)?;
    let transaction = read_transaction(&options.transaction)?;
    request.verify_authorized_transaction(&transaction)?;
    let checkpoint = verify_request(rpc, &request, &options.contracts_dir, options.max_fee)?;
    crate::admission::reserve_native(
        rpc,
        &options.admission_config,
        &options.contracts_dir,
        &request,
        false,
        options.max_fee,
    )?;
    let key =
        parse_privkey(&options.private_key).map_err(|_| anyhow!("invalid Factory funding key"))?;
    let public = canonical_hex(&compressed_pubkey(&key)?);
    let mut offset = wallet_input_offset;
    let mut indices = None;
    for funder in funders {
        if funder.pubkey == public {
            indices = Some((offset..offset + funder.inputs.len()).collect::<Vec<_>>());
        }
        offset += funder.inputs.len();
    }
    let indices = indices.ok_or_else(|| anyhow!("wallet key is not an explicit Factory funder"))?;
    verify_checkpoint(rpc, &checkpoint)?;
    let signed = super::multi_asset::sign_group(transaction.into_view(), &key, &indices)?.data();
    request.verify_authorized_transaction(&signed)?;
    let path = options
        .store_dir
        .join(hex::encode(blake2b_256(signed.as_slice())))
        .join("wallet-signed.tx");
    write_private_immutable(&path, signed.as_slice())?;
    verify_checkpoint(rpc, &checkpoint)?;
    Ok(
        json!({"schema":"morph.factory_wallet_signature.v1","transaction":path,"transaction_hash":canonical_hex(signed.calc_tx_hash().as_slice()),"signed_funder":public,"input_indices":indices,"broadcast":false}),
    )
}

pub(crate) fn submit(rpc: &CkbRpcClient, options: SubmitOptions) -> Result<Value> {
    let request = read_request(&options.request)?.decode()?;
    let tx = read_transaction(&options.transaction)?;
    request.verify_authorized_transaction(&tx)?;
    crate::value_limit::read_value_limit_policy(&options.policy)?
        .enforce(&ValueSubject::from_factory_request(&request)?)?;
    crate::admission::require_reserved(
        &options.admission_config,
        &options.contracts_dir,
        &request,
    )?;
    if rpc
        .transaction(request.transaction_hash()?.into())?
        .tx_status
        .status
        == Status::Committed
    {
        let (committed, _) = canonical_transaction(rpc, request.transaction_hash()?.into(), 1)?;
        ensure!(
            committed.as_slice() == tx.as_slice(),
            "canonical Factory witnesses differ from exact replay"
        );
        crate::factory_artifacts::validate_request_artifacts(&request, &options.contracts_dir)?;
        if request.target.is_none() {
            crate::admission::observe(
                &options.admission_config,
                &options.contracts_dir,
                &request,
                None,
            )?;
        }
        let path = options.store_dir.join(format!(
            "factory-{}.tx",
            hex::encode(tx.calc_tx_hash().as_slice())
        ));
        write_private_immutable(&path, tx.as_slice())?;
        return Ok(
            json!({"schema":"morph.factory_submission.v1","transaction":path,"broadcast":false,
            "canonical_replay":true,"transaction_hash":canonical_hex(tx.calc_tx_hash().as_slice()),"status":"Committed"}),
        );
    }
    let checkpoint = verify_request(rpc, &request, &options.contracts_dir, options.max_fee)?;
    crate::admission::reserve_native(
        rpc,
        &options.admission_config,
        &options.contracts_dir,
        &request,
        false,
        options.max_fee,
    )?;
    // Only a complete transaction that passes the VM may occupy its immutable
    // submission path. A partial wallet packet cannot poison a later replay.
    let view = tx.clone().into_view();
    let metrics = transaction_metrics(rpc, &view)?;
    verify_checkpoint(rpc, &checkpoint)?;
    let path = options.store_dir.join(format!(
        "factory-{}.tx",
        hex::encode(tx.calc_tx_hash().as_slice())
    ));
    write_private_immutable(&path, tx.as_slice())?;
    if options.dry_run {
        return Ok(
            json!({"schema":"morph.factory_submission.v1","transaction":path,"broadcast":false,"metrics":metrics}),
        );
    }
    let report = send_preflighted_and_mine(rpc, view, options.mine_blocks, metrics)?;
    if report.status == "Committed" && request.target.is_none() {
        confirm_request(rpc, &request, None, 1, &options.contracts_dir)?;
        crate::admission::observe(
            &options.admission_config,
            &options.contracts_dir,
            &request,
            None,
        )?;
    }
    Ok(
        json!({"schema":"morph.factory_submission.v1","transaction":path,"broadcast":true,"report":report_json(&report)}),
    )
}

/// Prove the exact signed request canonical, then verify its bound successor
/// against the actual permissionless activation transaction and every Vault.
pub(crate) fn confirm_request(
    rpc: &CkbRpcClient,
    request: &FactorySigningRequest,
    state_point: Option<&str>,
    depth: u64,
    directory: &Path,
) -> Result<(Option<FactoryCustody>, Vec<FactoryParticipantSignature>)> {
    let checkpoint = rpc.tip_header()?;
    crate::factory_artifacts::validate_request_artifacts(request, directory)?;
    let (committed, _) = canonical_transaction(rpc, request.transaction_hash()?.into(), depth)?;
    let signatures = request.authorization_from_transaction(&committed)?;
    let observed =
        if let Some(target) = &request.target {
            let supplied = parse_out_point(state_point.ok_or_else(|| {
                anyhow!("retained Factory confirmation requires --state-out-point")
            })?)?;
            let mut actual = target.clone();
            actual.state_out_point = MultiAssetOutPoint {
                tx_hash: supplied.tx_hash().unpack(),
                index: supplied.index().unpack(),
            };
            if request.requires_activation()? {
                ensure!(
                    actual.state_out_point.index == 0,
                    "Factory activation State must be output zero"
                );
                let (activation, _) =
                    canonical_transaction(rpc, actual.state_out_point.tx_hash.into(), depth)?;
                ensure!(
                    activation.raw().inputs().get(0).is_some_and(
                        |input| input.previous_output() == point(&target.state_out_point)
                    ),
                    "Factory activation does not consume exact request successor"
                );
            } else {
                ensure!(
                    actual.state_out_point == target.state_out_point,
                    "metadata successor differs from exact request"
                );
            }
            validate_live_custody(rpc, &actual, directory)?;
            Some(actual)
        } else {
            ensure!(
                state_point.is_none(),
                "closed Factory has no retained State"
            );
            None
        };
    verify_checkpoint(rpc, &checkpoint)?;
    Ok((observed, signatures))
}

pub(crate) struct RefreshOptions<'a> {
    pub source: &'a FactoryCustody,
    pub rights: &'a [morph_core::FactoryRight],
    pub transaction_hash: &'a str,
    pub state_out_point: &'a str,
    pub min_confirmations: u64,
    pub contracts_dir: &'a Path,
    pub full_request: Option<&'a FactorySigningRequest>,
}

/// An uninvolved member can follow a reduced spend and refresh every proof
/// using its retained complete tree and the publicly revealed changed leaves.
/// Full-consent replacement roots require the already-delivered full snapshot.
pub(crate) fn refresh_custody(
    rpc: &CkbRpcClient,
    options: RefreshOptions<'_>,
) -> Result<(FactoryCustody, Vec<morph_core::FactoryRight>)> {
    let checkpoint = rpc.tip_header()?;
    let (transaction, _) = canonical_transaction(
        rpc,
        parse_h256(options.transaction_hash)?,
        options.min_confirmations,
    )?;
    let (mut target, rights, moves) = if let Some(request) = options.full_request {
        ensure!(
            request.source.as_ref() == Some(options.source),
            "Factory refresh packet is based on another source"
        );
        request.verify_authorized_transaction(&transaction)?;
        let target = request
            .target
            .clone()
            .ok_or_else(|| anyhow!("fully closed Factory has no retained custody"))?;
        (
            target,
            request.target_rights.clone(),
            request.requires_activation()?,
        )
    } else {
        let view = morph_core::FactoryTransactionView::parse(transaction.as_slice())?;
        let target = view.retained_custody(options.source)?;
        let fields = options.source.state()?.fields();
        let snapshot = morph_core::FactoryRightsSnapshot {
            chain_id: fields.chain_id,
            factory_id: fields.factory_id,
            update_number: fields.update_number,
            state_root: fields.state_root,
            rights: options.rights.to_vec(),
        };
        let next = snapshot.apply_transition(view.witness()?.as_bytes())?;
        (
            target,
            next.rights,
            view.witness()?.operation().moves_custody(),
        )
    };
    let state = parse_out_point(options.state_out_point)?;
    let supplied = MultiAssetOutPoint {
        tx_hash: state.tx_hash().unpack(),
        index: state.index().unpack(),
    };
    if moves {
        ensure!(
            supplied.index == 0,
            "Factory activation State must be output zero"
        );
        let (activation, _) =
            canonical_transaction(rpc, supplied.tx_hash.into(), options.min_confirmations)?;
        ensure!(
            activation
                .raw()
                .inputs()
                .get(0)
                .is_some_and(|input| input.previous_output() == point(&target.state_out_point)),
            "Factory refresh activation does not consume exact retained successor"
        );
    } else {
        ensure!(
            supplied == target.state_out_point,
            "Factory metadata refresh differs from exact successor"
        );
    }
    target.state_out_point = supplied;
    validate_live_custody(rpc, &target, options.contracts_dir)?;
    verify_checkpoint(rpc, &checkpoint)?;
    Ok((target, rights))
}

pub(crate) fn activate(rpc: &CkbRpcClient, options: ActivateOptions) -> Result<Value> {
    crate::admission::validate_fee(
        &options.admission_config,
        &options.contracts_dir,
        options.fee,
    )?;
    ensure!(
        options.fee > 0 && options.fee <= options.max_fee,
        "invalid Factory activation fee"
    );
    let request = read_request(&options.request)?.decode()?;
    crate::admission::require_reserved(
        &options.admission_config,
        &options.contracts_dir,
        &request,
    )?;
    ensure!(
        request.requires_activation()?,
        "Factory request does not require activation"
    );
    let checkpoint = rpc.tip_header()?;
    let (committed, _) = canonical_transaction(rpc, request.transaction_hash()?.into(), 1)?;
    request.verify_authorized_transaction(&committed)?;
    let target = request
        .target
        .as_ref()
        .ok_or_else(|| anyhow!("Factory has no retained successor"))?;
    crate::factory_artifacts::validate_request_artifacts(&request, &options.contracts_dir)?;
    operator::verify_chain_id(rpc, target.state()?.chain_id())?;
    let unbound = load_canonical_live_cell(rpc, point(&target.state_out_point))?;
    let before = wire::FactoryMultiAssetStateHeader::parse(&unbound.data)
        .map_err(|error| anyhow!("invalid unbound Factory: {error:?}"))?;
    ensure!(
        before.is_activation_to(&target.state()?),
        "Factory successor is not the exact unbound creation"
    );
    ensure!(
        unbound.capacity == target.state_carrier_capacity
            && unbound.output.lock().as_slice() == target.state_lock
            && unbound
                .output
                .type_()
                .to_opt()
                .is_some_and(|ty| ty.as_slice() == target.state_type),
        "Factory activation source authority mismatch"
    );
    validate_live_vaults(rpc, target)?;
    let key =
        parse_privkey(&options.private_key).map_err(|_| anyhow!("invalid activation fee key"))?;
    let fee_lock = secp256k1_lock(&key)?;
    let fee_point = parse_out_point(&options.fee_out_point)?;
    let fee = load_canonical_live_cell(rpc, fee_point.clone())?;
    ensure!(
        fee.output.lock() == fee_lock
            && fee.output.type_().to_opt().is_none()
            && fee.data.is_empty(),
        "Factory activation fee must be an independent plain wallet cell"
    );
    let deps = committed.raw().cell_deps().into_iter().collect::<Vec<_>>();
    let resolved = operator::live_dependencies(rpc, &deps)?;
    ensure!(
        fee_point != point(&target.state_out_point)
            && !target
                .vault_outpoints
                .iter()
                .any(|value| point(value) == fee_point)
            && !resolved.out_points.contains(fee_point.as_slice())
            && !deps.iter().any(|dep| dep.out_point() == fee_point),
        "Factory fee consumes custody or a code dependency"
    );
    check_code(&unbound.output, &resolved.cells)?;
    check_code(&fee.output, &resolved.cells)?;
    let change_capacity = fee
        .capacity
        .checked_sub(options.fee)
        .ok_or_else(|| anyhow!("insufficient activation fee capacity"))?;
    let change = CellOutput::new_builder()
        .capacity(change_capacity)
        .lock(fee_lock)
        .build();
    ensure!(
        change_capacity >= change.occupied_capacity(Capacity::bytes(0)?)?.as_u64(),
        "activation fee change is dust"
    );
    let frame = morph_core::encode_factory_multi_asset_state_witness(
        wire::FACTORY_STATE_WITNESS_ACTIVATE,
        &target.manifest,
        &target.vault_outpoints,
        &[],
    )?;
    let first = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(frame)).pack())
        .build();
    // Activation authenticates each original Vault as the leading exact code
    // dependency. Remaining dependencies retain the approved executable code.
    let mut activation_deps = target
        .vault_outpoints
        .iter()
        .map(|value| {
            CellDep::new_builder()
                .out_point(point(value))
                .dep_type(DepType::Code)
                .build()
        })
        .collect::<Vec<_>>();
    activation_deps.extend(deps);
    let tx = TransactionBuilder::default()
        .set_cell_deps(activation_deps)
        .input(
            CellInput::new_builder()
                .previous_output(point(&target.state_out_point))
                .build(),
        )
        .input(CellInput::new_builder().previous_output(fee_point).build())
        .output(unbound.output)
        .output_data(Bytes::from(target.header.clone()).pack())
        .output(change)
        .output_data(Bytes::new().pack())
        .witness(first.as_bytes())
        .witness(Bytes::new())
        .build();
    verify_checkpoint(rpc, &checkpoint)?;
    let signed = super::multi_asset::sign_group(tx, &key, &[1])?;
    let metrics = transaction_metrics(rpc, &signed)?;
    verify_checkpoint(rpc, &checkpoint)?;
    let path = options.store_dir.join(format!(
        "factory-activation-{}.tx",
        hex::encode(signed.hash().as_slice())
    ));
    write_private_immutable(&path, signed.data().as_slice())?;
    let report = send_preflighted_and_mine(rpc, signed.clone(), options.mine_blocks, metrics)?;
    let mut custody = target.clone();
    custody.state_out_point = MultiAssetOutPoint {
        tx_hash: signed.hash().unpack(),
        index: 0,
    };
    if report.status == "Committed" {
        validate_live_custody(rpc, &custody, &options.contracts_dir)?;
        crate::admission::observe(
            &options.admission_config,
            &options.contracts_dir,
            &request,
            Some(&custody),
        )?;
    }
    let stored = StoredFactoryCustody::from_core(&custody)?;
    let custody_path = options.store_dir.join(format!(
        "factory-custody-{}.json",
        hex::encode(signed.hash().as_slice())
    ));
    write_private_immutable(&custody_path, &serde_json::to_vec_pretty(&stored)?)?;
    Ok(
        json!({"schema":"morph.factory_activation.v1","transaction":path,"custody":custody_path,"state_out_point":format_out_point(&point(&custody.state_out_point)),"report":report_json(&report)}),
    )
}

fn report_json(report: &SentTransactionReport) -> Value {
    json!({"tx_hash":report.tx_hash,"status":report.status,"block_number":report.block_number.map(|value|value.to_string()),
        "block_hash":report.block_hash,"metrics":report.metrics,"mined_blocks":report.mined_blocks})
}
