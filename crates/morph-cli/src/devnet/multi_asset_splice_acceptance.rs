//! Actual-node evidence for asset removal/admission and asymmetric delivery.
//! Uses the public builder, independent journals, submitter and canonical
//! handoff. Fixture exports are observations of committed transactions.
use super::*;
use crate::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex, write_package};
use crate::multi_asset_session::{SessionCommand, SigningTarget, run as session_run};
use crate::multi_asset_splice_transaction::{SpliceDraft, SpliceTerms};
use morph_core::{
    MultiAssetRecoveryPackage, MultiAssetSpliceFlow, MultiAssetValue,
    encode_multi_asset_splice_flows,
};
use serde_json::{Value, json};

pub struct Context<'a> {
    pub options: &'a super::multi_asset::MultiAssetSmokeOptions,
    pub alice_session: &'a Path,
    pub bob_session: &'a Path,
    pub owner_lock: &'a Script,
    pub recovery_deps: &'a [CellDep],
}

fn mine_depth(rpc: &CkbRpcClient, included: u64, minimum: u64) -> Result<()> {
    for _ in 0..64 {
        if block_confirmations(included, rpc.tip_header()?.number_value()?)? >= minimum {
            return Ok(());
        }
        rpc.generate_block()?;
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow!(
        "splice acceptance did not reach confirmation depth"
    ))
}

fn path_field(value: &Value, name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(
        value[name]
            .as_str()
            .ok_or_else(|| anyhow!("missing {name} path"))?,
    ))
}

pub fn run(
    rpc: &CkbRpcClient,
    context: Context<'_>,
    mut current: MultiAssetRecoveryPackage,
    mut state_point: OutPoint,
) -> Result<Value> {
    use super::multi_asset_operator as operator;
    use super::multi_asset_splice_operator as splice_operator;
    let options = context.options;
    let admission_config = options.store_dir.join("bilateral-admission-config.json");
    ensure!(
        current.manifest.vaults.len() == 2,
        "trace requires two initial Vaults"
    );
    let original = current.clone();
    let removed = original.manifest.vaults[1].clone();
    let mut released_input = None;
    let mut traces = Vec::new();
    let mut observations = Vec::new();
    for (name, removing) in [("remove", true), ("admit", false)] {
        let directory = options.store_dir.join(format!("splice-{name}"));
        crate::persistence::create_private_directories(&directory)?;
        let before = StoredMultiAssetPackage::from_recovery(&current, context.recovery_deps)?;
        let before_path = write_package(&directory, &before)?;
        let mut settlement = current.settlement.clone();
        if removing {
            settlement
                .payouts
                .retain(|payout| payout.asset != removed.asset);
        } else {
            settlement
                .payouts
                .push(original.settlement.payouts[1].clone());
            settlement
                .payouts
                .sort_by_key(|payout| payout.asset.clone());
        }
        let flows = original
            .manifest
            .vaults
            .iter()
            .map(|vault| MultiAssetSpliceFlow {
                asset: vault.asset.clone(),
                deposit: if !removing && vault.asset == removed.asset {
                    vault.value
                } else {
                    MultiAssetValue::default()
                },
                withdrawal: if removing && vault.asset == removed.asset {
                    vault.value
                } else {
                    MultiAssetValue::default()
                },
            })
            .collect::<Vec<_>>();
        let terms = SpliceTerms {
            schema: "morph.multi_asset_splice_terms.v1".to_string(),
            descriptor_hex: canonical_hex(&settlement.encode()?),
            flows_hex: canonical_hex(&encode_multi_asset_splice_flows(&flows)?),
            new_type_scripts_hex: original
                .scripts
                .type_scripts
                .iter()
                .filter(|entry| {
                    settlement
                        .payouts
                        .iter()
                        .any(|payout| payout.asset == morph_core::VaultAsset::Xudt(entry.type_hash))
                })
                .map(|entry| canonical_hex(&entry.script))
                .collect(),
            withdrawal_lock_hex: if removing {
                canonical_hex(context.owner_lock.as_slice())
            } else {
                "0x".to_string()
            },
            cell_deps: before.cell_deps.clone(),
        };
        let terms_path = directory.join("terms.json");
        crate::persistence::write_private_atomic(&terms_path, &serde_json::to_vec_pretty(&terms)?)?;
        let fee =
            find_largest_live_cell(rpc, context.owner_lock, rpc.tip_header()?.number_value()?)?;
        let mut external_inputs = vec![format_out_point(&fee.out_point)];
        if let Some(point) = &released_input {
            external_inputs.push(format_out_point(point));
        }
        let draft_path = directory.join("draft.json");
        splice_operator::prepare(
            rpc,
            splice_operator::PrepareOptions {
                admission_config: admission_config.clone(),
                old_package: before_path.clone(),
                state_out_point: format_out_point(&state_point),
                terms: terms_path,
                external_inputs,
                change_pubkey: hex::encode(k256_pubkey(&k256_signing_key(&options.private_key)?)),
                fee: options.fee,
                contracts_dir: options.contracts_dir.clone(),
                output: draft_path.clone(),
            },
        )?;
        for session in [context.alice_session, context.bob_session] {
            session_run(
                session,
                SessionCommand::PrepareSplice {
                    admission_config: admission_config.clone(),
                    contracts_dir: options.contracts_dir.clone(),
                    draft: draft_path.clone(),
                },
            )?;
        }
        let mut role_receipts = Vec::new();
        for target in [
            SigningTarget::SpliceCreation,
            SigningTarget::SpliceRecovery,
            SigningTarget::SpliceBridge,
        ] {
            let mut receipts = Vec::new();
            let mut paths = Vec::new();
            for (index, (session, secret)) in [
                (context.alice_session, &options.alice_private_key),
                (context.bob_session, &options.bob_private_key),
            ]
            .into_iter()
            .enumerate()
            {
                let receipt = session_run(
                    session,
                    SessionCommand::Sign {
                        target,
                        private_key: secret.clone(),
                    },
                )?;
                let path = directory.join(format!("{target:?}-{index}.json"));
                crate::persistence::write_private_atomic(
                    &path,
                    &serde_json::to_vec_pretty(&receipt)?,
                )?;
                receipts.push(receipt);
                paths.push(path);
            }
            session_run(
                context.bob_session,
                SessionCommand::AddSignature {
                    target,
                    signature: paths[0].clone(),
                },
            )?;
            // Bob can broadcast while withholding his final bridge receipt.
            if !matches!(target, SigningTarget::SpliceBridge) {
                session_run(
                    context.alice_session,
                    SessionCommand::AddSignature {
                        target,
                        signature: paths[1].clone(),
                    },
                )?;
            }
            role_receipts.push(receipts);
        }
        let journal_before = fs::read(context.alice_session)?;
        let offline = session_run(
            context.alice_session,
            SessionCommand::ExportSpliceRecovery {
                store_dir: directory.join("offline-exit"),
            },
        )?;
        ensure!(
            fs::read(context.alice_session)? == journal_before,
            "exit export changed signing authority"
        );
        let peer = session_run(
            context.bob_session,
            SessionCommand::ExportSplice {
                store_dir: directory.join("export"),
            },
        )?;
        let future_path = path_field(&peer, "recovery_package")?;
        let future = crate::multi_asset_packages::read_package(&future_path)?;
        ensure!(
            crate::multi_asset_packages::read_package(&path_field(&offline, "recovery_package")?)?
                == future,
            "withheld-receipt exit differs from broadcaster exit"
        );
        let submitted = splice_operator::submit(
            rpc,
            splice_operator::Options {
                admission_config: admission_config.clone(),
                transaction: path_field(&peer, "transaction")?,
                old_package: before_path,
                new_package: future_path.clone(),
                contracts_dir: options.contracts_dir.clone(),
                store_dir: directory.join("submission"),
                fee_authorization: splice_operator::FeeAuthorization::Wallet {
                    private_key: options.private_key.clone(),
                },
                max_fee: options.fee,
                mine_blocks: options.mine_blocks,
                dry_run: false,
            },
        )?;
        let transaction = ckb_types::packed::Transaction::from_slice(&fs::read(path_field(
            &submitted,
            "signed_transaction",
        )?)?)?;
        let hash: H256 = transaction.calc_tx_hash().unpack();
        let (canonical, _) = splice_operator::canonical_transaction(rpc, hash.clone(), 1)?;
        ensure!(
            canonical.as_slice() == transaction.as_slice(),
            "saved splice differs from actual committed transaction"
        );
        if removing {
            let output = 1 + settlement.payouts.len();
            let paid = transaction
                .raw()
                .outputs()
                .get(output)
                .ok_or_else(|| anyhow!("missing withdrawal"))?;
            let amount = transaction
                .raw()
                .outputs_data()
                .get(output)
                .ok_or_else(|| anyhow!("missing withdrawal data"))?
                .raw_data();
            let morph_core::VaultAsset::Xudt(type_hash) = removed.asset else {
                return Err(anyhow!("expected removed xUDT"));
            };
            ensure!(
                paid.lock() == *context.owner_lock
                    && paid
                        .type_()
                        .to_opt()
                        .is_some_and(|ty| ty.calc_script_hash().as_slice() == type_hash)
                    && amount.as_ref() == removed.value.amount.to_le_bytes(),
                "withdrawn asset did not reach the exact wallet output"
            );
            released_input = Some(OutPoint::new(hash.pack(), output as u32));
        }
        current = future.recovery()?;
        let fee =
            find_largest_live_cell(rpc, context.owner_lock, rpc.tip_header()?.number_value()?)?;
        let activation = operator::transact(
            rpc,
            operator::Options {
                operation: operator::Operation::Activate,
                package: future_path,
                state_out_point: format_out_point(&OutPoint::new(hash.pack(), 0)),
                fee_out_point: format_out_point(&fee.out_point),
                fee_authorization: operator::FeeAuthorization::Wallet {
                    private_key: options.private_key.clone(),
                },
                contracts_dir: options.contracts_dir.clone(),
                store_dir: directory.join("activation"),
                fee: options.fee,
                max_fee: options.fee,
                mine_blocks: options.mine_blocks,
                publication_profile: None,
                attempt_log: None,
                dry_run: false,
            },
        )?;
        state_point = OutPoint::new(
            parse_h256(
                activation["tx_hash"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing activation hash"))?,
            )?
            .pack(),
            0,
        );
        mine_depth(
            rpc,
            activation["block_number"]
                .as_u64()
                .ok_or_else(|| anyhow!("missing activation height"))?,
            4,
        )?;
        for session in [context.alice_session, context.bob_session] {
            session_run(
                session,
                SessionCommand::ConfirmSplice {
                    rpc_url: rpc.endpoint().to_string(),
                    state_out_point: format_out_point(&state_point),
                    min_confirmations: 4,
                    archive_dir: directory.join("retired"),
                    contracts_dir: options.contracts_dir.clone(),
                },
            )?;
        }
        let fresh = session_run(context.alice_session, SessionCommand::Inspect)?;
        ensure!(
            fresh["current"]["funding_context_id"] == future.validate()?.funding_context_id,
            "canonical handoff did not switch the same signing authority"
        );
        let (public_draft, _, _) =
            SpliceDraft::from_signed_transaction(&before.recovery()?, &current, &transaction)?;
        traces.push(json!({
            "name":name,"current":before,"draft":public_draft,
            "creation_receipts":role_receipts[0],"recovery_receipts":role_receipts[1],"bridge_receipts":role_receipts[2],
            "funding":{"schema":"morph.multi_asset_splice_funding.v1","transaction_hex":canonical_hex(transaction.as_slice()),"recovery_package":future},
        }));
        observations.push(json!({"operation":name,"submission":submitted,"activation":activation,"withheld_bridge_receipt_reconciled":true}));
    }
    let trace_path = options.store_dir.join("splice-transitions.json");
    crate::persistence::write_private_atomic(&trace_path, &serde_json::to_vec_pretty(&traces)?)?;
    let package = StoredMultiAssetPackage::from_recovery(&current, context.recovery_deps)?;
    let package_path = write_package(&options.store_dir, &package)?;
    let mut endings = Vec::new();
    for operation in [operator::Operation::Publish, operator::Operation::Finalise] {
        if matches!(operation, operator::Operation::Finalise) {
            mine_relative_since_maturity(rpc, options.finalise_since)?;
        }
        let fee =
            find_largest_live_cell(rpc, context.owner_lock, rpc.tip_header()?.number_value()?)?;
        let sent = operator::transact(
            rpc,
            operator::Options {
                operation,
                package: package_path.clone(),
                state_out_point: format_out_point(&state_point),
                fee_out_point: format_out_point(&fee.out_point),
                fee_authorization: operator::FeeAuthorization::Wallet {
                    private_key: options.private_key.clone(),
                },
                contracts_dir: options.contracts_dir.clone(),
                store_dir: options.store_dir.join("terminal"),
                fee: options.fee,
                max_fee: options.fee,
                mine_blocks: options.mine_blocks,
                publication_profile: None,
                attempt_log: None,
                dry_run: false,
            },
        )?;
        if matches!(operation, operator::Operation::Publish) {
            state_point = OutPoint::new(
                parse_h256(
                    sent["tx_hash"]
                        .as_str()
                        .ok_or_else(|| anyhow!("missing publication hash"))?,
                )?
                .pack(),
                0,
            );
        }
        endings.push(sent);
    }
    ensure!(
        rpc.live_cell(state_point.into(), false)?.status != "live",
        "splice channel failed to retire"
    );
    Ok(
        json!({"trace_file":trace_path,"operations":observations,"terminal":endings,"summary":package.validate()?}),
    )
}
