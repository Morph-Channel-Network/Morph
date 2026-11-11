//! Exact cooperative closure with independent wallet fees. Participant authority
//! comes only from the saved close frame; this module never signs channel votes.
use super::multi_asset_operator as operator;
use super::multi_asset_splice_operator::canonical_checkpoint;
use super::*;
use crate::multi_asset_packages::{
    canonical_hex, decode_dependency_records, read_package, write_package,
};
use ckb_types::packed;
use morph_core::{MultiAssetCloseProposal, MultiAssetRecoveryPackage};
use morph_packages::multi_asset_close::CloseDraft;
use morph_script_common::{multi_asset as wire, multi_asset_close as close};
use serde_json::{Value, json};
use std::io::Read;

const MAX_ARTIFACT_BYTES: usize = 512 * 1024;

#[derive(Debug, clap::Args)]
pub(crate) struct Context {
    #[arg(long)]
    pub package: PathBuf,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: PathBuf,
    #[arg(long)]
    pub max_fee: u64,
    #[arg(long, default_value_t = 1)]
    pub min_confirmations: u64,
}
#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Infer every custody payout from the complete saved exit, using one explicit fee input.
    Prepare {
        #[command(flatten)]
        context: Context,
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        fee_out_point: String,
        #[arg(long)]
        fee_pubkey: String,
        #[arg(long)]
        fee: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Review both close signatures, then sign only the external wallet fee input.
    WalletSign {
        #[command(flatten)]
        context: Context,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long = "private-key-file", env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::secp256k1_file)]
        private_key: morph_key_input::SecretString,
        #[arg(long)]
        output: PathBuf,
    },
    /// Preflight and persist the exact fully signed transaction before keyless publication.
    Submit {
        #[command(flatten)]
        context: Context,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        store_dir: PathBuf,
        /// Private runtime database, separate from the transaction evidence directory.
        #[arg(long)]
        operation_store: PathBuf,
        /// Previously registered close operation; does not revoke its approval.
        #[arg(long)]
        replaces_operation: Option<String>,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u64,
        #[arg(long)]
        dry_run: bool,
    },
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES,
        "close artifact exceeds byte budget"
    );
    Ok(bytes)
}
fn invalid(error: ScriptError) -> anyhow::Error {
    anyhow!("invalid close evidence: {error:?}")
}
fn payouts(package: &MultiAssetRecoveryPackage) -> Result<Vec<(CellOutput, Bytes)>> {
    let header = package.state.encode()?;
    let inner = morph_core::encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )?;
    Ok(morph_core::multi_asset_settlement_outputs(
        &wire::MultiAssetWitness::parse(&inner).map_err(invalid)?,
        &wire::MultiAssetStateHeader::parse(&header).map_err(invalid)?,
        package.state_carrier_capacity,
    )?)
}

/// Native wallet shape is deliberately bounded to one plain input and its sole
/// owner change. Consensus permits more general independently authorized fees.
fn fee_shape(
    rpc: &CkbRpcClient,
    package: &MultiAssetRecoveryPackage,
    proposal: &MultiAssetCloseProposal,
    max_fee: u64,
) -> Result<(usize, Script, u64)> {
    ensure!(max_fee > 0, "max_fee must be positive");
    proposal.validate(package)?;
    let raw = proposal.raw_transaction()?;
    let index = 1 + package.outpoints.len();
    let count = payouts(package)?.len();
    ensure!(
        raw.inputs().len() == index + 1 && raw.outputs().len() == count + 1,
        "native close requires one external fee input and one owner change"
    );
    let input = raw
        .inputs()
        .get(index)
        .ok_or_else(|| anyhow!("missing fee input"))?;
    ensure!(
        u64::from(input.since()) == 0,
        "native fee input since must be zero"
    );
    let cell = load_canonical_live_cell(rpc, input.previous_output())?;
    let change = raw
        .outputs()
        .get(count)
        .ok_or_else(|| anyhow!("missing fee change"))?;
    ensure!(
        cell.output.type_().to_opt().is_none()
            && cell.data.is_empty()
            && change.lock() == cell.output.lock(),
        "fee change must return to the plain input owner"
    );
    let fee = cell
        .capacity
        .checked_sub(u64::from(change.capacity()))
        .ok_or_else(|| anyhow!("fee change exceeds external input"))?;
    ensure!(
        fee > 0 && fee <= max_fee,
        "close fee outside declared bound"
    );
    Ok((index, cell.output.lock(), fee))
}

fn authorized_transaction(
    context: &Context,
    draft_path: &Path,
    transaction_path: &Path,
) -> Result<(
    MultiAssetRecoveryPackage,
    MultiAssetCloseProposal,
    packed::Transaction,
)> {
    ensure!(
        context.min_confirmations > 0,
        "confirmation depth must be positive"
    );
    let package = read_package(&context.package)?.recovery()?;
    let draft: CloseDraft = serde_json::from_slice(&read(draft_path)?)?;
    let proposal = draft.proposal(&package)?;
    let transaction = packed::Transaction::from_slice(&read(transaction_path)?)?;
    ensure!(
        transaction.raw().as_slice() == proposal.raw_transaction()?.as_slice(),
        "authorized transaction differs from exact close draft"
    );
    let first = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing close authorization"))?
        .raw_data();
    let args = WitnessArgs::from_slice(&first)?;
    ensure!(
        args.lock().to_opt().is_none() && args.input_type().to_opt().is_none(),
        "unexpected close State witness fields"
    );
    let frame_bytes = args
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing close frame"))?
        .raw_data();
    let frame = close::MultiAssetCloseWitness::parse(&frame_bytes).map_err(invalid)?;
    ensure!(
        frame.transaction_hash() == proposal.transaction_hash()?
            && frame.target().as_bytes() == package.state.encode()?,
        "close frame targets another body or allocation"
    );
    let source = proposal.source_state.encode()?;
    frame
        .validate_source(&wire::MultiAssetStateHeader::parse(&source).map_err(invalid)?)
        .map_err(invalid)?;
    Ok((package, proposal, transaction))
}
fn reviewed_transaction(
    rpc: &CkbRpcClient,
    context: &Context,
    draft_path: &Path,
    transaction_path: &Path,
) -> Result<(
    MultiAssetRecoveryPackage,
    packed::Transaction,
    usize,
    Script,
    u64,
)> {
    let (package, proposal, transaction) =
        authorized_transaction(context, draft_path, transaction_path)?;
    let (index, lock, fee) = validate_live(rpc, context, &package, &proposal, &transaction)?;
    Ok((package, transaction, index, lock, fee))
}
fn validate_live(
    rpc: &CkbRpcClient,
    context: &Context,
    package: &MultiAssetRecoveryPackage,
    proposal: &MultiAssetCloseProposal,
    transaction: &packed::Transaction,
) -> Result<(usize, Script, u64)> {
    operator::validate_close_proposal(
        rpc,
        package,
        proposal,
        &context.contracts_dir,
        context.min_confirmations,
    )?;
    let (index, lock, fee) = fee_shape(rpc, package, proposal, context.max_fee)?;
    ensure!(
        transaction.witnesses().len() <= transaction.raw().inputs().len(),
        "native close has unexpected extra witnesses"
    );
    for (position, witness) in transaction.witnesses().into_iter().enumerate().skip(1) {
        ensure!(
            position == index || witness.raw_data().is_empty(),
            "native close has unexpected custody witness"
        );
    }
    Ok((index, lock, fee))
}

pub(crate) fn run(rpc: &CkbRpcClient, command: Command) -> Result<Value> {
    let checkpoint = rpc.tip_header()?;
    match command {
        Command::Prepare {
            context,
            state_out_point,
            fee_out_point,
            fee_pubkey,
            fee,
            output,
        } => {
            ensure!(
                context.min_confirmations > 0 && fee > 0 && fee <= context.max_fee,
                "invalid close fee/depth bound"
            );
            let stored = read_package(&context.package)?;
            let package = stored.recovery()?;
            let source = parse_out_point(&state_out_point)?;
            let source_cell = load_canonical_live_cell(rpc, source.clone())?;
            let fee_point = parse_out_point(&fee_out_point)?;
            let fee_cell = load_canonical_live_cell(rpc, fee_point.clone())?;
            let pubkey = parse_compressed_pubkey_hex(&fee_pubkey, "fee public key")?;
            let lock = secp256k1_lock_from_pubkey(&pubkey)?;
            ensure!(
                fee_cell.output.lock() == lock
                    && fee_cell.output.type_().to_opt().is_none()
                    && fee_cell.data.is_empty(),
                "fee input is not owned plain wallet capacity"
            );
            let change = fee_cell
                .capacity
                .checked_sub(fee)
                .ok_or_else(|| anyhow!("fee input exhausted"))?;
            ensure_change_capacity(&lock, change)?;
            let mut tx = TransactionBuilder::default()
                .cell_deps(decode_dependency_records(&stored.cell_deps)?)
                .input(CellInput::new(source, 0));
            for point in &package.outpoints {
                tx = tx.input(CellInput::new(
                    OutPoint::new(point.tx_hash.pack(), point.index),
                    0,
                ));
            }
            tx = tx.input(CellInput::new(fee_point, 0));
            for (out, data) in payouts(&package)? {
                tx = tx.output(out).output_data(data.pack());
            }
            let tx = tx
                .output(
                    CellOutput::new_builder()
                        .capacity(change)
                        .lock(lock)
                        .build(),
                )
                .output_data(Bytes::new().pack())
                .build();
            let draft = CloseDraft {
                source_header_hex: canonical_hex(&source_cell.data),
                raw_transaction_hex: canonical_hex(tx.data().raw().as_slice()),
            };
            let proposal = draft.proposal(&package)?;
            operator::validate_close_proposal(
                rpc,
                &package,
                &proposal,
                &context.contracts_dir,
                context.min_confirmations,
            )?;
            fee_shape(rpc, &package, &proposal, context.max_fee)?;
            ensure!(
                canonical_checkpoint(rpc, &checkpoint)?,
                "chain reorganized during close construction"
            );
            crate::persistence::write_private_immutable(
                &output,
                &serde_json::to_vec_pretty(&draft)?,
            )?;
            Ok(
                json!({"draft":output,"transaction_hash":canonical_hex(&proposal.transaction_hash()?),"signing_digest":canonical_hex(&proposal.signing_digest(&package)?),"fee":fee.to_string()}),
            )
        }
        Command::WalletSign {
            context,
            draft,
            transaction,
            private_key,
            output,
        } => {
            let (_, transaction, index, lock, fee) =
                reviewed_transaction(rpc, &context, &draft, &transaction)?;
            let key = parse_privkey(&private_key).map_err(|_| anyhow!("invalid wallet key"))?;
            ensure!(
                secp256k1_lock(&key)? == lock,
                "wallet key does not own close fee input"
            );
            ensure!(
                canonical_checkpoint(rpc, &checkpoint)?,
                "chain reorganized during close wallet review"
            );
            let signed = super::multi_asset::sign_group(transaction.into_view(), &key, &[index])?;
            // Do not reserve an immutable filename for an incomplete or rejected body.
            let metrics = transaction_metrics(rpc, &signed)?;
            ensure!(
                canonical_checkpoint(rpc, &checkpoint)?,
                "chain reorganized during close preflight"
            );
            crate::persistence::write_private_immutable(&output, signed.data().as_slice())?;
            Ok(
                json!({"signed_transaction":output,"transaction_hash":canonical_hex(signed.hash().as_slice()),"fee":fee.to_string(),"metrics":metrics}),
            )
        }
        Command::Submit {
            context,
            draft,
            transaction,
            store_dir,
            operation_store,
            replaces_operation,
            mine_blocks,
            dry_run,
        } => {
            use crate::operation_runtime::{Kind, Preflight, Spec, Status, Tracker};
            ensure!(mine_blocks <= 1024, "close mining budget exceeded");
            let (package, proposal, transaction) =
                authorized_transaction(&context, &draft, &transaction)?;
            let spec = Spec {
                kind: Kind::CooperativeClose,
                genesis: hex::encode(package.state.header.chain_id),
                rpc_url: rpc.endpoint().to_owned(),
                context_id: hex::encode(package.state.header.channel_id),
                evidence_digest: hex::encode(morph_core::blake2b256(&package.state.encode()?)),
                transaction_hex: hex::encode(transaction.as_slice()),
                required_depth: context.min_confirmations,
                replaces: replaces_operation,
            };
            let mut tracker = Tracker::open(&operation_store, spec)?;
            if tracker.exists() {
                let report = tracker.reconcile()?;
                ensure!(
                    report.preflight.fee <= context.max_fee,
                    "saved close fee exceeds current bound"
                );
                if !matches!(report.status, Status::Unknown | Status::Reorged) {
                    let (path, saved) = persist_artifacts(&store_dir, &package, &transaction)?;
                    let report =
                        advance_operation(rpc, &mut tracker, report, mine_blocks, dry_run)?;
                    return Ok(operation_result(&report, dry_run, &path, &saved));
                }
            }
            let (_, _, fee) = validate_live(rpc, &context, &package, &proposal, &transaction)?;
            let tx = transaction.into_view();
            let metrics = transaction_metrics(rpc, &tx)?;
            ensure!(
                canonical_checkpoint(rpc, &checkpoint)?,
                "chain reorganized during close preflight"
            );
            tracker.register(Preflight {
                fee,
                estimated_cycles: metrics.estimated_cycles,
                tx_size_bytes: metrics.tx_size_bytes,
            })?;
            let (path, saved) = persist_artifacts(&store_dir, &package, &tx.data())?;
            let mut report = tracker.reconcile()?;
            if !dry_run && matches!(report.status, Status::Unknown | Status::Reorged) {
                report = tracker.broadcast()?;
            }
            let report = advance_operation(rpc, &mut tracker, report, mine_blocks, dry_run)?;
            Ok(operation_result(&report, dry_run, &path, &saved))
        }
    }
}

fn persist_artifacts(
    directory: &Path,
    package: &MultiAssetRecoveryPackage,
    transaction: &packed::Transaction,
) -> Result<(PathBuf, PathBuf)> {
    let saved = write_package(
        directory,
        &crate::multi_asset_packages::StoredMultiAssetPackage::from_recovery(
            package,
            &transaction
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>(),
        )?,
    )?;
    let path = directory.join(format!(
        "close-{}.tx",
        hex::encode(transaction.calc_tx_hash().as_slice())
    ));
    crate::persistence::write_private_immutable(&path, transaction.as_slice())?;
    Ok((path, saved))
}

fn operation_result(
    report: &crate::operation_runtime::Report,
    dry_run: bool,
    path: &Path,
    saved: &Path,
) -> Value {
    json!({"dry_run":dry_run,"transaction_hash":report.transaction_hash,"status":report.status,"canonical_confirmations":report.canonical_confirmations,"operation":report,
        "signed_transaction":path,"durable_package":saved,"fee":report.preflight.fee.to_string(),"metrics":{"estimated_cycles":report.preflight.estimated_cycles,"tx_size_bytes":report.preflight.tx_size_bytes}})
}

fn advance_operation(
    rpc: &CkbRpcClient,
    tracker: &mut crate::operation_runtime::Tracker,
    mut report: crate::operation_runtime::Report,
    mine_blocks: u64,
    dry_run: bool,
) -> Result<crate::operation_runtime::Report> {
    use crate::operation_runtime::Status;
    if !dry_run {
        for _ in 0..mine_blocks {
            if matches!(
                report.status,
                Status::Finalised { .. }
                    | Status::OperatorAction
                    | Status::RpcUnavailable
                    | Status::Rejected
                    | Status::Replaced { .. }
            ) {
                break;
            }
            rpc.generate_block()?;
            report = tracker.reconcile()?;
        }
    }
    Ok(report)
}
