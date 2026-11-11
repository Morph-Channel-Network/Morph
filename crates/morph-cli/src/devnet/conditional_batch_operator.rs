//! Exact asset-bound Batch withdrawal. Participant keys are never used here:
//! source signatures authorize the terms, a preimage or mature since resolves
//! them, and the wallet signs only a separate plain CKB fee input.
use super::multi_asset::sign_group;
use super::multi_asset_operator as operator;
use super::multi_asset_splice_operator::canonical_checkpoint;
use super::*;
use crate::conditional_packages::{StoredConditionalBatchPackage, decimal_u64, read_package};
use crate::multi_asset_packages::{decode_dependency_records, decode_hex, read_bounded_json};
use ckb_types::{core::TransactionView, packed};
use morph_script_common::multi_asset as wire;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;

const DRAFT_SCHEMA: &str = "morph.conditional_batch_draft.v1";
const MAX_BYTES: usize = 512 * 1024;

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
    /// Infer the exact asset and both payouts from saved authenticated terms.
    Prepare {
        #[command(flatten)]
        context: Context,
        #[arg(long)]
        batch_out_point: String,
        #[arg(long)]
        fee_out_point: String,
        #[arg(long)]
        fee_pubkey: String,
        #[arg(long)]
        fee: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Reconstruct the complete body; sign only the independent fee input.
    WalletSign {
        #[command(flatten)]
        context: Context,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long = "private-key-file", env = "MORPH_DEVNET_PRIVATE_KEY_FILE", hide_env_values = true, value_name = "PATH", value_parser = morph_key_input::secp256k1_file)]
        private_key: morph_key_input::SecretString,
        #[arg(long)]
        output: PathBuf,
    },
    /// VM-preflight, persist and track exact bytes before keyless publication.
    Submit {
        #[command(flatten)]
        context: Context,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        transaction: PathBuf,
        #[arg(long)]
        store_dir: PathBuf,
        #[arg(long)]
        operation_store: PathBuf,
        #[arg(long, default_value_t = 0)]
        mine_blocks: u64,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    schema: String,
    batch_id: String,
    batch_input_hex: String,
    fee_input_hex: String,
    fee_pubkey: String,
    fee_capacity: String,
    fee: String,
    raw_transaction_hex: String,
}

fn decode_point(value: &str) -> Result<OutPoint> {
    let bytes = hex::decode(value)?;
    ensure!(hex::encode(&bytes) == value, "noncanonical draft input");
    Ok(OutPoint::from_slice(&bytes)?)
}

impl Draft {
    fn body(
        &self,
        package: &StoredConditionalBatchPackage,
        max_fee: u64,
    ) -> Result<TransactionView> {
        ensure!(
            self.schema == DRAFT_SCHEMA && self.batch_id == package.batch_id,
            "draft selects a different signed Batch"
        );
        let fee = decimal_u64("fee", &self.fee)?;
        let fee_capacity = decimal_u64("fee_capacity", &self.fee_capacity)?;
        ensure!(fee > 0 && fee <= max_fee, "Batch fee exceeds bound");
        let input = decode_point(&self.batch_input_hex)?;
        let fee_input = decode_point(&self.fee_input_hex)?;
        ensure!(input != fee_input, "Batch and fee inputs must be distinct");
        let pubkey = parse_compressed_pubkey_hex(&self.fee_pubkey, "fee public key")?;
        let owner = secp256k1_lock_from_pubkey(&pubkey)?;
        let change = super::multi_asset::wallet_change(fee_capacity, 0, fee, &owner)?;
        let cells = package.cells()?;
        let since = decimal_u64("input_since", &package.input_since)?;
        let witness = WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(decode_hex(
                    &package.resolution_witness_hex,
                    morph_script_common::CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN,
                )?))
                .pack(),
            )
            .build();
        let mut tx = TransactionBuilder::default()
            .set_cell_deps(decode_dependency_records(
                &package.source_package.cell_deps,
            )?)
            .input(CellInput::new(input, since))
            .input(CellInput::new(fee_input, 0))
            .witness(witness.as_bytes());
        for (output, data) in cells.outputs {
            tx = tx.output(output).output_data(data.pack());
        }
        Ok(tx.output(change).output_data(Bytes::new().pack()).build())
    }
    fn checked_body(
        &self,
        package: &StoredConditionalBatchPackage,
        max_fee: u64,
    ) -> Result<TransactionView> {
        let tx = self.body(package, max_fee)?;
        ensure!(
            hex::encode(tx.data().raw().as_slice()) == self.raw_transaction_hex,
            "draft body differs from authenticated Batch payouts and declared fee"
        );
        Ok(tx)
    }
}

fn validate_live(
    rpc: &CkbRpcClient,
    context: &Context,
    package: &StoredConditionalBatchPackage,
    draft: &Draft,
) -> Result<()> {
    let recovery = package.source_package.recovery()?;
    operator::verify_chain_id(rpc, &recovery.state.header.chain_id)?;
    let cells = package.cells()?;
    let input = load_canonical_live_cell(rpc, decode_point(&draft.batch_input_hex)?)?;
    ensure!(
        input.output == cells.input.0 && input.data == cells.input.1,
        "live Batch differs from exact signed asset/quantity/context"
    );
    let pubkey = parse_compressed_pubkey_hex(&draft.fee_pubkey, "fee public key")?;
    let fee = load_canonical_live_cell(rpc, decode_point(&draft.fee_input_hex)?)?;
    ensure!(
        fee.output.lock() == secp256k1_lock_from_pubkey(&pubkey)?
            && fee.output.type_().to_opt().is_none()
            && fee.data.is_empty()
            && fee.capacity == decimal_u64("fee_capacity", &draft.fee_capacity)?,
        "fee input differs from owned plain CKB"
    );
    let since = decimal_u64("input_since", &package.input_since)?;
    if since != 0 {
        morph_script_common::validate_absolute_block_since(since, since)
            .map_err(|error| anyhow!("invalid refund since: {error:?}"))?;
        ensure!(
            rpc.tip_header()?.number_value()? >= since,
            "Batch refund has not matured"
        );
    }
    let decoded = package.source_package.decode()?;
    let witness = wire::MultiAssetWitness::parse(&decoded.witness)
        .map_err(|error| anyhow!("invalid saved custody: {error:?}"))?;
    operator::validate_code(
        rpc,
        &context.contracts_dir,
        &witness,
        &decode_dependency_records(&package.source_package.cell_deps)?,
        &fee.output.lock(),
    )?;
    Ok(())
}

fn read_transaction(path: &Path) -> Result<packed::Transaction> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BYTES,
        "Batch transaction exceeds byte limit"
    );
    Ok(packed::Transaction::from_slice(&bytes)?)
}

fn checked_transaction(
    package: &StoredConditionalBatchPackage,
    draft: &Draft,
    tx: &packed::Transaction,
    max_fee: u64,
) -> Result<()> {
    let expected = draft.checked_body(package, max_fee)?.data();
    ensure!(
        tx.raw().as_slice() == expected.raw().as_slice()
            && tx.witnesses().len() == 2
            && tx.witnesses().get(0) == expected.witnesses().get(0),
        "signed Batch transaction changes reviewed body or resolution witness"
    );
    Ok(())
}

pub(crate) fn run(rpc: &CkbRpcClient, command: Command) -> Result<Value> {
    match command {
        Command::Prepare {
            context,
            batch_out_point,
            fee_out_point,
            fee_pubkey,
            fee,
            output,
        } => {
            let package = read_package(&context.package)?;
            let checkpoint = rpc.tip_header()?;
            let fee_point = parse_out_point(&fee_out_point)?;
            let capacity = load_canonical_live_cell(rpc, fee_point.clone())?.capacity;
            let mut draft = Draft {
                schema: DRAFT_SCHEMA.into(),
                batch_id: package.batch_id.clone(),
                batch_input_hex: hex::encode(parse_out_point(&batch_out_point)?.as_slice()),
                fee_input_hex: hex::encode(fee_point.as_slice()),
                fee_pubkey,
                fee_capacity: capacity.to_string(),
                fee: fee.to_string(),
                raw_transaction_hex: String::new(),
            };
            let tx = draft.body(&package, context.max_fee)?;
            draft.raw_transaction_hex = hex::encode(tx.data().raw().as_slice());
            validate_live(rpc, &context, &package, &draft)?;
            ensure!(
                canonical_checkpoint(rpc, &checkpoint)?,
                "chain reorganized during Batch preparation"
            );
            crate::persistence::write_private_immutable(
                &output,
                &serde_json::to_vec_pretty(&draft)?,
            )?;
            Ok(
                json!({"schema":DRAFT_SCHEMA,"draft":output,"transaction_hash":format!("{:#x}",tx.hash()),"summary":package.validate()?}),
            )
        }
        Command::WalletSign {
            context,
            draft,
            private_key,
            output,
        } => {
            let package = read_package(&context.package)?;
            let draft: Draft = read_bounded_json(&draft, MAX_BYTES)?;
            let checkpoint = rpc.tip_header()?;
            let tx = draft.checked_body(&package, context.max_fee)?;
            validate_live(rpc, &context, &package, &draft)?;
            let key = parse_privkey(&private_key)?;
            let pubkey = parse_compressed_pubkey_hex(&draft.fee_pubkey, "fee public key")?;
            ensure!(
                secp256k1_lock(&key)? == secp256k1_lock_from_pubkey(&pubkey)?,
                "wallet does not own declared fee input"
            );
            let signed = sign_group(tx, &key, &[1])?;
            checked_transaction(&package, &draft, &signed.data(), context.max_fee)?;
            let metrics = transaction_metrics(rpc, &signed)?;
            ensure!(
                canonical_checkpoint(rpc, &checkpoint)?,
                "chain reorganized during Batch wallet preflight"
            );
            crate::persistence::write_private_immutable(&output, signed.data().as_slice())?;
            Ok(
                json!({"transaction_hash":format!("{:#x}",signed.hash()),"signed_transaction":output,"preflight":metrics,"summary":package.validate()?}),
            )
        }
        Command::Submit {
            context,
            draft,
            transaction,
            store_dir,
            operation_store,
            mine_blocks,
            dry_run,
        } => {
            use crate::operation_runtime::{Kind, Preflight, Spec, Status, Tracker};
            ensure!(
                mine_blocks <= 1024 && (1..=1024).contains(&context.min_confirmations),
                "Batch execution budget exceeds bounds"
            );
            let package = read_package(&context.package)?;
            let recovery = package.source_package.recovery()?;
            let draft: Draft = read_bounded_json(&draft, MAX_BYTES)?;
            let tx = read_transaction(&transaction)?;
            checked_transaction(&package, &draft, &tx, context.max_fee)?;
            let spec = Spec {
                kind: Kind::ConditionalResolution,
                genesis: hex::encode(recovery.state.header.chain_id),
                rpc_url: rpc.endpoint().into(),
                context_id: hex::encode(recovery.state.funding_context_id()?),
                evidence_digest: hex::encode(morph_core::blake2b256(&serde_json::to_vec(
                    &package,
                )?)),
                transaction_hex: hex::encode(tx.as_slice()),
                required_depth: context.min_confirmations,
                replaces: None,
            };
            let mut tracker = Tracker::open(&operation_store, spec)?;
            if !tracker.exists() {
                let checkpoint = rpc.tip_header()?;
                validate_live(rpc, &context, &package, &draft)?;
                let metrics = transaction_metrics(rpc, &tx.clone().into_view())?;
                ensure!(
                    canonical_checkpoint(rpc, &checkpoint)?,
                    "chain reorganized during Batch submission preflight"
                );
                tracker.register(Preflight {
                    fee: decimal_u64("fee", &draft.fee)?,
                    estimated_cycles: metrics.estimated_cycles,
                    tx_size_bytes: metrics.tx_size_bytes,
                })?;
            }
            let saved = store_dir.join(format!(
                "batch-{}.bin",
                hex::encode(tx.calc_tx_hash().as_slice())
            ));
            crate::persistence::write_private_immutable(&saved, tx.as_slice())?;
            let mut report = tracker.reconcile()?;
            if !dry_run && matches!(report.status, Status::Unknown | Status::Reorged) {
                report = tracker.broadcast()?;
            }
            if !dry_run {
                for _ in 0..mine_blocks {
                    if matches!(
                        report.status,
                        Status::Finalised { .. }
                            | Status::Rejected
                            | Status::OperatorAction
                            | Status::RpcUnavailable
                    ) {
                        break;
                    }
                    rpc.generate_block()?;
                    report = tracker.reconcile()?;
                }
            }
            Ok(
                json!({"schema":"morph.conditional_batch_execution.v1","operation":report,"signed_transaction":saved,"dry_run":dry_run,"summary":package.validate()?}),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditional_packages::{
        StoredConditionalResolution, fixture_package, fixture_typed_source_package,
    };
    use crate::multi_asset_packages::canonical_hex;

    fn draft(package: &StoredConditionalBatchPackage) -> Draft {
        let recovery = package.source_package.recovery().unwrap();
        let mut draft = Draft {
            schema: DRAFT_SCHEMA.into(),
            batch_id: package.batch_id.clone(),
            batch_input_hex: hex::encode(OutPoint::new([1; 32].pack(), 0).as_slice()),
            fee_input_hex: hex::encode(OutPoint::new([2; 32].pack(), 0).as_slice()),
            fee_pubkey: hex::encode(&recovery.authorization.signatures[0].pubkey_sec1),
            fee_capacity: "20000000000".into(),
            fee: "100000".into(),
            raw_transaction_hex: String::new(),
        };
        draft.raw_transaction_hex =
            hex::encode(draft.body(package, 100000).unwrap().data().raw().as_slice());
        draft
    }

    #[test]
    fn batch_draft_reconstructs_every_payout_and_cannot_spend_the_batch_for_fees() {
        let package = fixture_package().unwrap();
        let original = draft(&package);
        let tx = original.checked_body(&package, 100000).unwrap();
        let input = package.cells().unwrap().input;
        assert_eq!(
            u64::from(tx.outputs().get(0).unwrap().capacity())
                + u64::from(tx.outputs().get(1).unwrap().capacity()),
            u64::from(input.0.capacity())
        );
        assert_eq!(
            u64::from(tx.outputs().get(2).unwrap().capacity()),
            20000000000 - 100000
        );
        for mutation in 0..4 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.fee = "100001".into(),
                1 => changed.fee_capacity = "20000000001".into(),
                2 => changed.batch_input_hex = changed.fee_input_hex.clone(),
                _ => changed.batch_id = canonical_hex(&[99; 32]),
            }
            assert!(changed.checked_body(&package, 100000).is_err());
        }
    }

    #[test]
    fn typed_batch_draft_preserves_full_u128_quantity_and_independent_capacities() {
        let source = fixture_typed_source_package().unwrap();
        let package = StoredConditionalBatchPackage::from_source(
            source,
            [31; 32],
            vec![StoredConditionalResolution::Fulfill {
                transfer_id: canonical_hex(&[33; 32]),
                preimage: canonical_hex(&[34; 32]),
            }],
            0,
        )
        .unwrap();
        let draft = draft(&package);
        let tx = draft.checked_body(&package, 100000).unwrap();
        let cells = package.cells().unwrap();
        assert!(cells.input.0.type_().to_opt().is_some());
        let input_amount = u128::from_le_bytes(cells.input.1.as_ref().try_into().unwrap());
        assert!(input_amount > u64::MAX as u128);
        let mut sum = 0;
        for index in 0..2 {
            assert_eq!(
                tx.outputs().get(index).unwrap().type_(),
                cells.input.0.type_()
            );
            sum += u128::from_le_bytes(
                tx.outputs_data()
                    .get(index)
                    .unwrap()
                    .raw_data()
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );
        }
        assert_eq!(sum, input_amount);
        assert_eq!(
            package.validate().unwrap().resolved_values[0].capacity,
            "26000000000"
        );
        let mut altered = package.clone();
        altered.resolved_values[0].amount = "0".into();
        assert!(altered.cells().is_err());
    }
}
