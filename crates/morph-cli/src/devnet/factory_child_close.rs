//! Factory-origin close through ordinary bilateral authority. Controlled forks
//! keep the existing stale-publication/watch/unilateral acceptance branch intact.
use super::factory_transitions_acceptance::Context;
use super::multi_asset::sign_group;
use super::multi_asset_close_operator::{self as close, Command};
use super::*;
use crate::multi_asset_packages::{canonical_hex, read_package};
use crate::multi_asset_session::{CloseCommand, SessionCommand, run as session};
use anyhow::Context as _;
use serde_json::{Value, json};

pub(super) fn run(
    rpc: &CkbRpcClient,
    parent: &Context<'_>,
    directory: &Path,
    sessions: &[PathBuf],
    package_path: &Path,
    source: &str,
) -> Result<Value> {
    use std::os::unix::fs::DirBuilderExt;
    ensure!(sessions.len() == 2, "close requires two child journals");
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    let mut random = [0; 8];
    getrandom::fill(&mut random).map_err(|_| anyhow!("cannot allocate child close runtime"))?;
    let runtime = std::env::temp_dir().canonicalize()?.join(format!(
        "morph-child-close-{}-{}",
        std::process::id(),
        hex::encode(random)
    ));
    fs::DirBuilder::new().mode(0o700).create(&runtime)?;
    let operation_store = runtime.join("operations.db");
    let stored = read_package(package_path)?;
    let package = stored.recovery()?;
    let options = parent.options;
    let owner = parse_privkey(&options.private_key)?;
    let lock = secp256k1_lock(&owner)?;
    let fees = find_largest_live_cell(rpc, &lock, rpc.tip_header()?.number_value()?)?;
    let context = || close::Context {
        package: package_path.to_path_buf(),
        contracts_dir: options.contracts_dir.clone(),
        max_fee: options.fee,
        min_confirmations: 4,
    };
    let draft = directory.join("draft.json");
    let prepared = close::run(
        rpc,
        Command::Prepare {
            context: context(),
            state_out_point: source.to_owned(),
            fee_out_point: format_out_point(&fees.out_point),
            fee_pubkey: canonical_hex(&compressed_pubkey(&owner)?),
            fee: options.fee,
            output: draft.clone(),
        },
    )?;
    let hash = crate::canonical_fields::hash(
        prepared["transaction_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("missing child close hash"))?,
    )?;
    for path in sessions {
        session(
            path,
            SessionCommand::CooperativeClose {
                operation: CloseCommand::Prepare {
                    draft: draft.clone(),
                },
            },
        )?;
    }
    for (index, key) in [&options.alice_private_key, &options.bob_private_key]
        .into_iter()
        .enumerate()
    {
        let receipt = crate::participant_signer::acceptance::sign_close(
            rpc,
            &sessions[index],
            key,
            &package,
            true,
            &hash,
        )?;
        let path = directory.join(format!("receipt-{index}.json"));
        crate::persistence::write_private_immutable(&path, &serde_json::to_vec(&receipt)?)?;
        session(
            &sessions[1 - index],
            SessionCommand::CooperativeClose {
                operation: CloseCommand::AddSignature {
                    transaction_hash: canonical_hex(&hash),
                    signature: path,
                },
            },
        )?;
    }
    let authorized = directory.join("authorized.tx");
    session(
        &sessions[0],
        SessionCommand::CooperativeClose {
            operation: CloseCommand::Export {
                transaction_hash: canonical_hex(&hash),
                output: authorized.clone(),
            },
        },
    )?;
    let signed = directory.join("wallet-signed.tx");
    close::run(
        rpc,
        Command::WalletSign {
            context: context(),
            draft: draft.clone(),
            transaction: authorized,
            private_key: options.private_key.clone(),
            output: signed.clone(),
        },
    )?;
    let before = rpc.tip_header()?;
    let journals = sessions
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;
    let parent_journals = parent
        .sessions
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;
    let submitted = close::run(
        rpc,
        Command::Submit {
            context: context(),
            draft,
            transaction: signed.clone(),
            store_dir: directory.join("submitted"),
            operation_store: operation_store.clone(),
            replaces_operation: None,
            mine_blocks: 8,
            dry_run: false,
        },
    )?;
    crate::persistence::write_private_immutable(
        &directory.join("submitted.json"),
        &serde_json::to_vec(&submitted)?,
    )?;
    ensure!(
        submitted["status"]["state"] == "finalised",
        "child close did not finalize"
    );
    let tx = ckb_types::packed::Transaction::from_slice(&fs::read(&signed)?)?;
    for input in tx
        .raw()
        .inputs()
        .into_iter()
        .take(1 + package.outpoints.len())
    {
        let since: u64 = input.since().unpack();
        ensure!(since == 0, "cooperative close used a challenge delay");
        ensure!(
            rpc.live_cell(input.previous_output().into(), false)?.status != "live",
            "child custody remains live"
        );
    }
    for (index, output) in tx.raw().outputs().into_iter().enumerate() {
        let cell = load_canonical_live_cell(rpc, OutPoint::new(tx.calc_tx_hash(), index as u32))?;
        ensure!(
            cell.output == output
                && tx
                    .raw()
                    .outputs_data()
                    .get(index)
                    .is_some_and(|data| data.raw_data() == cell.data),
            "child close payout differs"
        );
    }
    let batch = match &package.settlement.capability {
        morph_core::MultiAssetSettlementCapability::Ordinary => None,
        morph_core::MultiAssetSettlementCapability::Conditional { batches, .. } => {
            ensure!(
                batches.len() == 1,
                "this child scenario declares exactly one Batch"
            );
            Some(resolve_batch(rpc, parent, &package, &tx, &batches[0])?)
        }
    };
    // No journal restore: the close approval remains authority on every fork.
    let fork = CkbRpcClient::new_supervision(rpc.endpoint(), Duration::from_secs(30))?;
    fork.truncate(parse_h256(&before.hash)?)?;
    wait_for_tip(&fork, &before.hash)?;
    ensure!(
        rpc.canonical_live_cell(parse_out_point(source)?.into(), false)?
            .status
            == "live",
        "child source not restored by controlled fork"
    );
    ensure!(
        sessions
            .iter()
            .map(fs::read)
            .collect::<std::io::Result<Vec<_>>>()?
            == journals,
        "chain rollback changed child close authority"
    );
    ensure!(
        parent
            .sessions
            .iter()
            .map(fs::read)
            .collect::<std::io::Result<Vec<_>>>()?
            == parent_journals,
        "independent child close changed parent authority"
    );
    Ok(
        json!({"operation_store":operation_store,"submitted": submitted, "zero_since":true, "all_payouts_verified":true,
        "parent_journals_unchanged":true, "child_journals_unchanged_after_rollback":true,
        "batch":batch, "branch":"cooperative_branch_orphaned_before_existing_unilateral_acceptance"}),
    )
}

fn resolve_batch(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    package: &morph_core::MultiAssetRecoveryPackage,
    close: &ckb_types::packed::Transaction,
    batch: &morph_core::ConditionalBatch,
) -> Result<Value> {
    use morph_core::ConditionalResolution;
    use std::collections::BTreeMap;
    ensure!(
        batch.transfers.len() == 1,
        "conditional acceptance uses one pending claim"
    );
    let raw = package.settlement.encode()?;
    let descriptor = morph_script_common::multi_asset::MultiAssetSettlementDescriptor::parse(&raw)
        .map_err(|e| anyhow!("invalid descriptor: {e:?}"))?;
    let conditional = descriptor
        .conditional()
        .map_err(|e| anyhow!("invalid capability: {e:?}"))?
        .ok_or_else(|| anyhow!("missing Batch"))?;
    let expected = Script::from_slice(
        &conditional
            .batch_script(
                conditional
                    .index_of(match batch.asset {
                        morph_core::VaultAsset::Ckb => {
                            morph_script_common::multi_asset::MultiAssetId::CKB
                        }
                        morph_core::VaultAsset::Xudt(hash) => {
                            morph_script_common::multi_asset::MultiAssetId::xudt(hash)
                        }
                    })
                    .map_err(|e| anyhow!("invalid Batch asset: {e:?}"))?
                    .context("Batch asset absent")?,
                &package.state.header.channel_id,
                &package.state.funding_context_id()?,
                package.state.header.state_number,
            )
            .map_err(|e| anyhow!("invalid Batch script: {e:?}"))?,
    )?;
    let slots = close
        .raw()
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, output)| output.lock() == expected)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(slots.len() == 1, "close must preserve one exact Batch");
    let point = OutPoint::new(close.calc_tx_hash(), slots[0] as u32);
    let base = rpc.tip_header()?;
    let key = parse_privkey(&context.options.private_key)?;
    let owner = secp256k1_lock(&key)?;
    let locks = [
        Script::from_slice(&package.scripts.participant_locks[0])?,
        Script::from_slice(&package.scripts.participant_locks[1])?,
    ];
    let deps = crate::multi_asset_packages::decode_dependency_records(context.cell_deps)?;
    let transfer = &batch.transfers[0];
    let build = |refund: bool| -> Result<ckb_types::core::TransactionView> {
        let since = if refund {
            morph_script_common::absolute_block_since(transfer.refund_after_block)
                .map_err(|e| anyhow!("invalid refund since: {e:?}"))?
        } else {
            0
        };
        let resolution = if refund {
            ConditionalResolution::Refund
        } else {
            ConditionalResolution::Fulfill { preimage: [34; 32] }
        };
        let resolutions = BTreeMap::from([(transfer.transfer_id, resolution)]);
        let amounts = batch.resolve(&resolutions, since)?;
        let fees = find_largest_live_cell(rpc, &owner, rpc.tip_header()?.number_value()?)?;
        let witness = WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    batch.encode_resolution_witness(&resolutions)?.to_vec(),
                ))
                .pack(),
            )
            .build();
        let mut builder = TransactionBuilder::default()
            .set_cell_deps(deps.clone())
            .input(CellInput::new(point.clone(), since))
            .input(CellInput::new(fees.out_point, 0))
            .witness(witness.as_bytes());
        for (lock, amount) in locks.iter().zip(amounts) {
            let ty = match batch.asset {
                morph_core::VaultAsset::Xudt(hash) if amount.amount > 0 => Some(
                    package
                        .scripts
                        .type_scripts
                        .iter()
                        .map(|raw| Script::from_slice(&raw.script))
                        .collect::<std::result::Result<Vec<_>, _>>()?
                        .into_iter()
                        .find(|script| script.calc_script_hash().as_slice() == hash)
                        .context("missing exact Batch Type")?,
                ),
                _ => None,
            };
            let data = if ty.is_some() {
                Bytes::from(amount.amount.to_le_bytes().to_vec())
            } else {
                Bytes::new()
            };
            builder = builder
                .output(
                    CellOutput::new_builder()
                        .capacity(amount.capacity)
                        .lock(lock.clone())
                        .type_(ty.pack())
                        .build(),
                )
                .output_data(data.pack());
        }
        builder = builder
            .output(super::multi_asset::wallet_change(
                fees.capacity,
                0,
                context.options.fee,
                &owner,
            )?)
            .output_data(Bytes::new().pack());
        sign_group(builder.build(), &key, &[1])
    };
    let fulfil = build(false)?;
    let fulfilled = send_and_mine(rpc, fulfil.clone(), 4)?;
    for index in 0..2 {
        let cell = load_canonical_live_cell(rpc, OutPoint::new(fulfil.hash(), index as u32))?;
        ensure!(
            Some(cell.output) == fulfil.outputs().get(index)
                && fulfil
                    .outputs_data()
                    .get(index)
                    .is_some_and(|data| data.raw_data() == cell.data),
            "fulfilled Batch payout differs"
        );
    }
    let fork = CkbRpcClient::new_supervision(rpc.endpoint(), Duration::from_secs(30))?;
    fork.truncate(parse_h256(&base.hash)?)?;
    wait_for_tip(&fork, &base.hash)?;
    let remaining = transfer
        .refund_after_block
        .saturating_sub(rpc.tip_header()?.number_value()?);
    ensure!(remaining <= 64, "refund exceeds bounded acceptance horizon");
    for _ in 0..remaining {
        let hash = fork.generate_block()?;
        wait_for_tip(&fork, &hash)?;
    }
    ensure!(
        rpc.tip_header()?.number_value()? >= transfer.refund_after_block,
        "refund height did not advance"
    );
    let refund = build(true)?;
    let refunded = send_and_mine(rpc, refund.clone(), 4)?;
    for index in 0..2 {
        let cell = load_canonical_live_cell(rpc, OutPoint::new(refund.hash(), index as u32))?;
        ensure!(
            Some(cell.output) == refund.outputs().get(index)
                && refund
                    .outputs_data()
                    .get(index)
                    .is_some_and(|data| data.raw_data() == cell.data),
            "refunded Batch payout differs"
        );
    }
    Ok(
        json!({"fulfilled":batch_report(&fulfilled),"refunded":batch_report(&refunded),"canonical_payouts_verified":true,
        "branches":"fulfilment_orphaned_then_refund_before_outer_close_rollback"}),
    )
}

fn wait_for_tip(rpc: &CkbRpcClient, expected: &str) -> Result<()> {
    loop {
        ensure!(!expected.is_empty(), "missing controlled-fork tip");
        if rpc.tip_header()?.hash == expected {
            return Ok(());
        }
        // The caller supplies one total RPC budget for the complete fork/mining
        // sequence. An RPC acknowledgement is not canonical-chain progress.
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn batch_report(report: &SentTransactionReport) -> Value {
    json!({"tx_hash":report.tx_hash,"status":report.status,"block_number":report.block_number,
        "block_hash":report.block_hash,"metrics":report.metrics,"mined_blocks":report.mined_blocks})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controlled_fork_waits_for_canonical_tip_and_keeps_one_total_deadline() {
        let server = crate::admission_channel::tests::MockRpc::start([7; 32], 5);
        let rpc = CkbRpcClient::new_supervision(&server.url, Duration::from_secs(2)).unwrap();
        let header = rpc.tip_header().unwrap();
        let old = json!({"hash":header.hash,"number":header.number,
            "parent_hash":header.parent_hash,"timestamp":header.timestamp,"epoch":header.epoch});
        let mut next = old.clone();
        let hash = canonical_hex(&[43; 32]);
        next["hash"] = json!(hash);
        next["number"] = json!("0x6");
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(30));
                server.respond("get_tip_header", json!([]), next);
            });
            wait_for_tip(&rpc, &hash).unwrap();
            assert_eq!(rpc.tip_header().unwrap().hash, hash);
        });
        server.respond("get_tip_header", json!([]), old);
        let bounded =
            CkbRpcClient::new_supervision(&server.url, Duration::from_millis(50)).unwrap();
        assert!(wait_for_tip(&bounded, &hash).is_err());
    }
}
