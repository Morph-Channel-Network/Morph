//! Initial funding and exact root replay from complete signed evidence. No
//! participant signer or replacement funding body is accepted by this command.
//! Wallet mode signs only an explicitly reviewed single-owner funding group.
use super::multi_asset_operator as operator;
use super::multi_asset_splice_operator::FeeAuthorization;
use super::*;
use crate::multi_asset_funding::{MAX_FUNDING_BYTES, validate_root_funding};
use crate::multi_asset_packages::{StoredMultiAssetPackage, read_package, write_package};
use crate::multi_asset_splice_transaction::{TransactionKind, write_transaction};
use morph_script_common::multi_asset as wire;
use serde_json::{Value, json};
use std::io::Read;

pub struct Options {
    pub transaction: PathBuf,
    pub package: PathBuf,
    pub contracts_dir: PathBuf,
    pub store_dir: PathBuf,
    pub max_fee: u64,
    pub mine_blocks: u64,
    pub dry_run: bool,
    pub fee_authorization: FeeAuthorization,
}
pub fn submit(rpc: &CkbRpcClient, options: Options) -> Result<Value> {
    ensure!(options.max_fee > 0, "max_fee must be positive");
    let mut bytes = Vec::new();
    fs::File::open(&options.transaction)?
        .take(MAX_FUNDING_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_FUNDING_BYTES,
        "root funding exceeds byte limit"
    );
    let transaction = ckb_types::packed::Transaction::from_slice(&bytes)?;
    let stored = read_package(&options.package)?;
    let recovery = stored.recovery()?;
    operator::verify_chain_id(rpc, &recovery.state.header.chain_id)?;
    validate_root_funding(&recovery, &transaction)?;
    let deps = transaction
        .raw()
        .cell_deps()
        .into_iter()
        .collect::<Vec<_>>();
    ensure!(
        StoredMultiAssetPackage::from_recovery(&recovery, &deps)? == stored,
        "root recovery dependencies differ from signed funding body"
    );
    let checkpoint = rpc.tip_header()?;
    let resolved = operator::live_dependencies(rpc, &deps)?;
    let decoded = stored.decode()?;
    let evidence = wire::MultiAssetWitness::parse(&decoded.witness)
        .map_err(|error| anyhow!("invalid root evidence: {error:?}"))?;
    let mut live_inputs = Vec::new();
    let mut inputs = BTreeSet::new();
    let mut first_lock = None;
    for input in transaction.raw().inputs() {
        let point = input.previous_output();
        ensure!(
            inputs.insert(point.as_slice().to_vec())
                && !resolved.out_points.contains(point.as_slice())
                && !deps.iter().any(|dep| dep.out_point() == point),
            "duplicate input or consumed root code dependency"
        );
        let cell = load_canonical_live_cell(rpc, point)?;
        for script in std::iter::once(cell.output.lock()).chain(cell.output.type_().to_opt()) {
            ensure!(
                resolved
                    .cells
                    .iter()
                    .any(|code| operator::code_matches(&script, code)),
                "root input script code is unavailable"
            );
        }
        if first_lock.is_none() {
            first_lock = Some(cell.output.lock());
        }
        live_inputs.push(cell);
    }
    let first_lock = first_lock.ok_or_else(|| anyhow!("missing root funding input"))?;
    operator::validate_resolved_code(
        &options.contracts_dir,
        &evidence,
        &resolved.cells,
        &first_lock,
    )?;
    for (index, output) in transaction.raw().outputs().into_iter().enumerate() {
        for script in std::iter::once(output.lock()).chain(output.type_().to_opt()) {
            ensure!(
                resolved
                    .cells
                    .iter()
                    .any(|code| operator::code_matches(&script, code)),
                "root output script code is unavailable"
            );
        }
        let data = transaction
            .raw()
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("missing root output data"))?
            .raw_data();
        ensure!(
            u64::from(output.capacity())
                >= output
                    .occupied_capacity(Capacity::bytes(data.len())?)?
                    .as_u64(),
            "root output below occupied capacity"
        );
    }
    let registered = recovery
        .manifest
        .vaults
        .iter()
        .filter_map(|vault| match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(hash),
        })
        .collect::<BTreeSet<_>>();
    let capacity = operator::validate_funding_balances(
        &transaction,
        &live_inputs,
        &registered,
        options.max_fee,
    )?;
    let wallet = match &options.fee_authorization {
        FeeAuthorization::Presigned => None,
        FeeAuthorization::Wallet { private_key } => {
            let key =
                parse_privkey(private_key).map_err(|_| anyhow!("invalid funding wallet key"))?;
            let lock = secp256k1_lock(&key)?;
            for cell in &live_inputs {
                ensure!(
                    cell.output.lock() == lock,
                    "funding input is not owned by wallet signer"
                );
                if let Some(ty) = cell.output.type_().to_opt() {
                    ensure!(
                        registered.contains::<[u8; 32]>(&ty.calc_script_hash().unpack())
                            && cell.data.len() == 16,
                        "wallet funding input has an unregistered asset"
                    );
                } else {
                    ensure!(
                        cell.data.is_empty(),
                        "wallet funding input has unexpected data"
                    );
                }
            }
            let state_lock = Script::from_slice(&recovery.scripts.state_lock)?;
            let vault_lock = Script::from_slice(&recovery.scripts.vault_lock)?;
            for (index, output) in transaction.raw().outputs().into_iter().enumerate() {
                ensure!(
                    output.lock() == lock
                        || output.lock() == state_lock
                        || output.lock() == vault_lock,
                    "funding change does not return to wallet signer"
                );
                if output.lock() == lock {
                    let data = transaction
                        .raw()
                        .outputs_data()
                        .get(index)
                        .ok_or_else(|| anyhow!("missing wallet change data"))?
                        .raw_data();
                    if let Some(ty) = output.type_().to_opt() {
                        ensure!(
                            registered.contains::<[u8; 32]>(&ty.calc_script_hash().unpack())
                                && data.len() == 16,
                            "wallet funding change has an unregistered asset"
                        );
                    } else {
                        ensure!(data.is_empty(), "wallet funding change has unexpected data");
                    }
                }
            }
            Some(key)
        }
    };
    ensure!(
        super::multi_asset_splice_operator::canonical_checkpoint(rpc, &checkpoint)?,
        "chain reorganized during root input validation"
    );
    let durable = write_package(&options.store_dir, &stored)?;
    let tx = transaction.into_view();
    let tx = if let Some(key) = wallet {
        super::multi_asset::sign_group(tx, &key, &(0..live_inputs.len()).collect::<Vec<_>>())?
    } else {
        tx
    };
    let signed_path = write_transaction(
        &options.store_dir.join("submitted-funding"),
        &tx.data(),
        TransactionKind::Root,
    )?;
    let metrics = transaction_metrics(rpc, &tx)?;
    ensure!(
        super::multi_asset_splice_operator::canonical_checkpoint(rpc, &checkpoint)?,
        "chain reorganized during root VM preflight"
    );
    if options.dry_run {
        return Ok(
            json!({"schema":"morph.multi_asset_funding_transaction.v1","dry_run":true,"tx_hash":format!("{:#x}", H256::from(tx.hash())),"fee":capacity.to_string(),"metrics":metrics,"durable_package":durable,"signed_transaction":signed_path}),
        );
    }
    let sent = send_preflighted_and_mine(rpc, tx, options.mine_blocks, metrics)?;
    let confirmed = transaction_confirmations(rpc, &sent)?;
    Ok(
        json!({"schema":"morph.multi_asset_funding_transaction.v1","dry_run":false,"tx_hash":sent.tx_hash,"status":sent.status,"block_number":sent.block_number,"block_hash":sent.block_hash,"fee":capacity.to_string(),"metrics":sent.metrics,"mined_blocks":sent.mined_blocks,"canonical_confirmations":confirmed,"durable_package":durable,"signed_transaction":signed_path}),
    )
}
