//! Real-node UDT conditions through the public operator, not a second builder.
//! Fulfillment and refund/mixed outcomes run on mutually exclusive controlled
//! forks. Exact signatures and participant journals are never rolled back.
use super::conditional_batch_operator::{self as operator, Command, Context};
use super::multi_asset::MultiAssetSmokeOptions;
use super::*;
use crate::conditional_packages::{StoredConditionalBatchPackage, StoredConditionalResolution};
use crate::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex};
use morph_core::{
    ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant, ConditionalTransferSpec,
    MultiAssetRecoveryPackage, MultiAssetSettlement, MultiAssetSettlementCapability,
};
use serde_json::{Value, json};

pub(super) fn arm(
    rpc: &CkbRpcClient,
    options: &MultiAssetSmokeOptions,
    package: &MultiAssetRecoveryPackage,
    settlement: &mut MultiAssetSettlement,
) -> Result<()> {
    ensure!(
        settlement.capability == MultiAssetSettlementCapability::Ordinary,
        "typed acceptance requires ordinary source allocation"
    );
    let expiry = rpc
        .tip_header()?
        .number_value()?
        .checked_add(64)
        .ok_or_else(|| anyhow!("refund block overflow"))?;
    let mut batches = Vec::new();
    for payout in &mut settlement.payouts {
        ensure!(
            matches!(payout.asset, VaultAsset::Xudt(_)),
            "UDT campaign expects exact typed Vaults"
        );
        for value in &mut payout.values {
            value.amount = value
                .amount
                .checked_sub(40)
                .ok_or_else(|| anyhow!("insufficient pending token backing"))?;
        }
        let capacities = [payout.values[0].capacity()?, payout.values[1].capacity()?];
        batches.push(ConditionalBatch {
            asset: payout.asset.clone(),
            batch_id: morph_core::derive_conditional_batch_id(
                &package.state.header.channel_id,
                &package.state.funding_context_id()?,
                package
                    .state
                    .header
                    .state_number
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("state number overflow"))?,
                &[91; 32],
                &payout.asset,
            ),
            application_context_commitment: [91; 32],
            participants: core::array::from_fn(|index| ConditionalParticipant {
                settlement_lock_hash: settlement.participant_lock_hashes[index],
                settled_capacity: capacities[index],
                settled_amount: payout.values[index].amount,
            }),
            transfers: (0..8)
                .map(|index| {
                    let algorithm = if index % 2 == 0 {
                        ConditionalHashAlgorithm::CkbBlake2b
                    } else {
                        ConditionalHashAlgorithm::Sha256
                    };
                    Ok(ConditionalTransferSpec {
                        transfer_id: [1 + index as u8; 32],
                        payer_lock_hash: settlement.participant_lock_hashes[index % 2],
                        hash_algorithm: algorithm,
                        payment_hash: morph_core::derive_conditional_payment_hash(
                            algorithm,
                            &[80 + index as u8; 32],
                        )?,
                        amount: 10,
                        refund_after_block: expiry,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        });
    }
    settlement.capability = MultiAssetSettlementCapability::Conditional {
        batch_code_hash: morph_core::blake2b256(&fs::read(
            options.contracts_dir.join("morph-batch-lock"),
        )?),
        batch_hash_type: 2,
        batches,
    };
    settlement.encode()?;
    Ok(())
}

fn wait_tip(rpc: &CkbRpcClient, hash: &str) -> Result<()> {
    loop {
        if rpc.tip_header()?.hash == hash {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub(super) fn resolve(
    rpc: &CkbRpcClient,
    options: &MultiAssetSmokeOptions,
    package: &MultiAssetRecoveryPackage,
    deps: &[CellDep],
    terminal: &Value,
    sessions: [&Path; 2],
) -> Result<Value> {
    let MultiAssetSettlementCapability::Conditional { batches, .. } =
        &package.settlement.capability
    else {
        return Err(anyhow!("missing typed signed conditions"));
    };
    ensure!(
        batches.len() == options.asset_count && batches.iter().all(|b| b.transfers.len() == 8),
        "incomplete typed condition dimensions"
    );
    let journals = [fs::read(sessions[0])?, fs::read(sessions[1])?];
    let store = options.store_dir.join("typed-condition-execution");
    let source = StoredMultiAssetPackage::from_recovery(package, deps)?;
    let terminal_hash = parse_h256(
        terminal["tx_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("missing Batch creation transaction"))?,
    )?;
    let key = parse_privkey(&options.private_key)?;
    let owner = secp256k1_lock(&key)?;
    let pubkey = hex::encode(compressed_pubkey(&key)?);
    // Independent pre-fork fee inputs make every exact fulfillment replayable
    // after rollback. Chaining wallet change would orphan later fee sources as
    // well, correctly requiring a new reviewed draft rather than exact replay.
    let fee_source = find_largest_live_cell(rpc, &owner, rpc.tip_header()?.number_value()?)?;
    let fee_capacity = 10_000_000_000u64
        .checked_add(options.fee)
        .ok_or_else(|| anyhow!("fee capacity overflow"))?;
    let fee_total = fee_capacity
        .checked_mul(batches.len() as u64)
        .ok_or_else(|| anyhow!("fee funding overflow"))?;
    let mut fee_tx = TransactionBuilder::default()
        .set_cell_deps(deps.to_vec())
        .input(CellInput::new(fee_source.out_point, 0));
    for _ in batches {
        fee_tx = fee_tx
            .output(
                CellOutput::new_builder()
                    .capacity(fee_capacity)
                    .lock(owner.clone())
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }
    let fee_tx = fee_tx
        .output(super::multi_asset::wallet_change(
            fee_source.capacity,
            fee_total,
            options.fee,
            &owner,
        )?)
        .output_data(Bytes::new().pack())
        .build();
    let fee_funding = send_and_mine(
        rpc,
        super::multi_asset::sign_group(fee_tx, &key, &[0])?,
        options.mine_blocks,
    )?;
    let fee_hash = parse_h256(&fee_funding.tx_hash)?;
    let checkpoint = rpc.tip_header()?;
    let execute = |branch: &str, index: usize, refund: bool| -> Result<Value> {
        let batch = &batches[index];
        let resolutions = batch
            .transfers
            .iter()
            .enumerate()
            .map(|(leaf, transfer)| {
                if !refund || (index % 2 == 1 && leaf % 3 == 0) {
                    StoredConditionalResolution::Fulfill {
                        transfer_id: canonical_hex(&transfer.transfer_id),
                        preimage: canonical_hex(&[80 + leaf as u8; 32]),
                    }
                } else {
                    StoredConditionalResolution::Refund {
                        transfer_id: canonical_hex(&transfer.transfer_id),
                    }
                }
            })
            .collect::<Vec<_>>();
        let since = if refund {
            morph_script_common::absolute_block_since(
                batch
                    .transfers
                    .iter()
                    .map(|t| t.refund_after_block)
                    .max()
                    .ok_or_else(|| anyhow!("empty Batch"))?,
            )
            .map_err(|e| anyhow!("invalid refund height: {e:?}"))?
        } else {
            0
        };
        let package = StoredConditionalBatchPackage::from_source(
            source.clone(),
            batch.batch_id,
            resolutions,
            since,
        )?;
        let directory = store.join(format!("{branch}-{index}"));
        let path = directory.join("resolution.json");
        crate::persistence::write_private_immutable(&path, &serde_json::to_vec_pretty(&package)?)?;
        let draft = directory.join("draft.json");
        let signed = directory.join("signed.bin");
        let operation_store = directory.join("operations.db");
        let context = || Context {
            package: path.clone(),
            contracts_dir: options.contracts_dir.clone(),
            max_fee: options.fee,
            min_confirmations: 4,
        };
        let fee = OutPoint::new(fee_hash.pack(), index as u32);
        operator::run(
            rpc,
            Command::Prepare {
                context: context(),
                batch_out_point: format_out_point(&OutPoint::new(
                    terminal_hash.pack(),
                    index as u32,
                )),
                fee_out_point: format_out_point(&fee),
                fee_pubkey: pubkey.clone(),
                fee: options.fee,
                output: draft.clone(),
            },
        )?;
        operator::run(
            rpc,
            Command::WalletSign {
                context: context(),
                draft: draft.clone(),
                private_key: options.private_key.clone(),
                output: signed.clone(),
            },
        )?;
        let submit = || Command::Submit {
            context: context(),
            draft: draft.clone(),
            transaction: signed.clone(),
            store_dir: directory.join("transactions"),
            operation_store: operation_store.clone(),
            mine_blocks: 8,
            dry_run: false,
        };
        let result = operator::run(rpc, submit())?;
        ensure!(
            result["operation"]["status"]["state"] == "finalised"
                && result["operation"]["canonical_confirmations"]
                    .as_u64()
                    .unwrap_or(0)
                    >= 4,
            "typed Batch did not reach required canonical depth"
        );
        let tx = ckb_types::packed::Transaction::from_slice(&fs::read(&signed)?)?.into_view();
        let expected = package.cells()?;
        for (output, (cell, data)) in expected.outputs.into_iter().enumerate() {
            let observed = load_canonical_live_cell(rpc, OutPoint::new(tx.hash(), output as u32))?;
            ensure!(
                observed.output == cell && observed.data == data,
                "typed Batch payout differs from exact enforced terms"
            );
        }
        let repeated = operator::run(rpc, submit())?;
        ensure!(
            repeated["operation"]["broadcasts"] == result["operation"]["broadcasts"],
            "canonical Batch replay rebroadcast unexpectedly"
        );
        ensure!(
            [fs::read(sessions[0])?, fs::read(sessions[1])?] == journals,
            "Batch withdrawal mutated participant authority"
        );
        Ok(
            json!({"operation":result["operation"],"summary":result["summary"],"canonical_payouts_verified":true,
            "exact_retry_did_not_rebroadcast":true,"participant_journals_unchanged":true,"operation_store":operation_store}),
        )
    };
    let mut fulfilled = Vec::new();
    for index in 0..batches.len() {
        fulfilled.push(execute("fulfill", index, false)?);
    }
    let fork = CkbRpcClient::new_supervision(rpc.endpoint(), std::time::Duration::from_secs(120))?;
    fork.truncate(parse_h256(&checkpoint.hash)?)?;
    wait_tip(&fork, &checkpoint.hash)?;
    let mut orphaned = Vec::new();
    for row in &fulfilled {
        let status = crate::operation_runtime::status(
            Path::new(
                row["operation_store"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing operation store"))?,
            ),
            row["operation"]["operation_id"]
                .as_str()
                .ok_or_else(|| anyhow!("missing operation identity"))?,
            4,
            0,
        )?;
        ensure!(
            status["operation"]["status"]["state"] == "reorged"
                && status["operation"]["canonical_confirmations"] == 0
                && status["depth_reached"] == false,
            "orphaned fulfillment did not lose canonical credit: {}",
            status["operation"]["status"]
        );
        orphaned.push(status);
    }
    let maximum = batches
        .iter()
        .flat_map(|b| &b.transfers)
        .map(|t| t.refund_after_block)
        .max()
        .ok_or_else(|| anyhow!("missing deadlines"))?;
    let remaining = maximum.saturating_sub(fork.tip_header()?.number_value()?);
    ensure!(
        remaining <= 128,
        "refund exceeds bounded node campaign horizon"
    );
    for _ in 0..remaining {
        let hash = fork.generate_block()?;
        wait_tip(&fork, &hash)?;
    }
    let mut refunded = Vec::new();
    for index in 0..batches.len() {
        refunded.push(execute("refund-mixed", index, true)?);
    }
    ensure!(
        [fs::read(sessions[0])?, fs::read(sessions[1])?] == journals,
        "controlled reorg reset signing authority"
    );
    Ok(
        json!({"schema":"morph.typed_condition_native.v1","batch_count":batches.len(),"conditions_per_batch":8,
        "fulfilled":fulfilled,"orphaned_fulfillments":orphaned,"refunded_or_mixed":refunded,
        "all_payouts_verified":true,"participant_journals_unchanged":true,"provider_rpc_used":false,
        "independent_fee_funding_tx_hash":fee_funding.tx_hash,
        "branches":"fulfillments_orphaned_then_canonical_refund_and_mixed_resolutions"}),
    )
}
