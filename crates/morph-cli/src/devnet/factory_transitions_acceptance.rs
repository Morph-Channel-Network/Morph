//! Current native Factory transitions through independent durable authorities.
use super::factory_operator as operator;
use super::*;
use crate::factory_context::FactoryPreparationContext;
use crate::factory_packets::read_request;
use crate::factory_root_transaction::FactoryReserveTerms;
use crate::factory_session::{FactorySessionCommand, run as session};
use crate::factory_transaction::{
    FactoryPayoutTerms, FactoryPreparationOperation, FactoryPreparationTerms,
};
use crate::funding_wallets::{FundingInput, FundingWallet};
use crate::multi_asset_packages::{StoredMultiAssetCellDep, canonical_hex, read_bounded_json};
use serde_json::{Value, json};

pub(crate) struct Context<'a> {
    pub options: &'a super::factory_acceptance::Options,
    pub sessions: &'a [PathBuf],
    pub cell_deps: &'a [StoredMultiAssetCellDep],
    pub policy: &'a Path,
}

pub(crate) fn save_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    crate::persistence::write_private_immutable(path, &serde_json::to_vec_pretty(value)?)
}
pub(crate) fn public_context(
    session_path: &Path,
    output: &Path,
) -> Result<FactoryPreparationContext> {
    session(
        session_path,
        FactorySessionCommand::ExportContext {
            output: output.to_path_buf(),
        },
    )?;
    read_bounded_json(output, 4 * 1024 * 1024)
}
pub(crate) fn fee_wallet(
    rpc: &CkbRpcClient,
    options: &super::factory_acceptance::Options,
    contribution: u64,
) -> Result<FundingWallet> {
    let key =
        parse_privkey(&options.private_key).map_err(|_| anyhow!("invalid acceptance fee key"))?;
    let funding = find_largest_live_cell(
        rpc,
        &secp256k1_lock(&key)?,
        rpc.tip_header()?.number_value()?,
    )?;
    Ok(FundingWallet {
        pubkey: canonical_hex(&compressed_pubkey(&key)?),
        inputs: vec![FundingInput {
            tx_hash: canonical_hex(funding.out_point.tx_hash().as_slice()),
            index: funding.out_point.index().unpack(),
        }],
        ckb_contribution: contribution.to_string(),
        fee_contribution: options.fee.to_string(),
        tokens: vec![],
    })
}
pub(crate) fn prepare(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    directory: &Path,
    terms: &FactoryPreparationTerms,
) -> Result<PathBuf> {
    let path = directory.join("terms.json");
    save_json(&path, terms)?;
    let packet = directory.join("request.json");
    crate::factory_transaction::prepare(
        rpc,
        crate::factory_transaction::PrepareOptions {
            terms: path,
            contracts_dir: context.options.contracts_dir.clone(),
            policy: context.policy.to_path_buf(),
            max_fee: context.options.fee,
            output: packet.clone(),
        },
    )?;
    Ok(packet)
}

pub(crate) fn run(rpc: &CkbRpcClient, context: Context<'_>) -> Result<Value> {
    let options = context.options;
    let directory = options.store_dir.join("transitions");
    let before_path = directory.join("before.json");
    let before = public_context(&context.sessions[0], &before_path)?;
    let funder = fee_wallet(rpc, options, 0)?;
    let metadata = FactoryPreparationTerms {
        schema: "morph.factory_preparation_terms.v1".to_string(),
        context: before.clone(),
        intent: FactoryPreparationOperation::Metadata {
            access_manifest_root: canonical_hex(&[81; 32]),
        },
        target_rights: before.rights.clone(),
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![funder.clone()],
    };
    let pending_path = prepare(
        rpc,
        &context,
        &directory.join("withheld-metadata"),
        &metadata,
    )?;
    let pending = read_request(&pending_path)?.decode()?;
    let pending_id = canonical_hex(&pending.request_id()?);
    session(
        &context.sessions[0],
        FactorySessionCommand::Prepare {
            request: pending_path.clone(),
        },
    )?;
    let old_receipt = session(
        &context.sessions[0],
        FactorySessionCommand::Sign {
            rpc_url: rpc.endpoint().to_string(),
            request_id: pending_id.clone(),
            private_key: options.alice_private_key.clone(),
        },
    )?;
    save_json(
        &directory.join("withheld-metadata/alice-receipt.json"),
        &old_receipt,
    )?;
    // Bob disappears before returning the final full-consent signature.
    // Alice explicitly authorizes a reduced alternative without revocation.
    let mut rights = before.rights.clone();
    rights[0].quantity = "3000000000".to_string();
    let alice = parse_privkey(&options.alice_private_key)
        .map_err(|_| anyhow!("invalid acceptance Alice key"))?;
    let escape = FactoryPreparationTerms {
        schema: metadata.schema.clone(),
        context: before.clone(),
        intent: FactoryPreparationOperation::ReducedRelease {
            participant: before.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "23900000000".to_string(),
                business_ckb: "6100000000".to_string(),
                amount: "0".to_string(),
            }],
            payouts: vec![FactoryPayoutTerms {
                type_hash: None,
                reserve: "6100000000".to_string(),
                business_ckb: "3900000000".to_string(),
                amount: "0".to_string(),
                lock_script_hex: canonical_hex(secp256k1_lock(&alice)?.as_slice()),
            }],
        },
        target_rights: rights,
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![funder],
    };
    let escape_directory = directory.join("reduced-escape");
    let escape_packet = prepare(rpc, &context, &escape_directory, &escape)?;
    let escaped = execute(
        rpc,
        &context,
        &escape_directory,
        &escape_packet,
        Some(&pending_id),
    )?;
    refresh_peer(rpc, &context, &escaped)?;
    let alice_context = public_context(
        &context.sessions[0],
        &directory.join("after-escape-alice.json"),
    )?;
    let bob_context = public_context(
        &context.sessions[1],
        &directory.join("after-escape-bob.json"),
    )?;
    ensure!(
        serde_json::to_value(&alice_context)? == serde_json::to_value(&bob_context)?,
        "uninvolved member could not refresh exact current rights without peer data"
    );
    let before_reject = fs::read(&context.sessions[1])?;
    ensure!(
        session(
            &context.sessions[1],
            FactorySessionCommand::Reconcile {
                rpc_url: rpc.endpoint().to_string(),
                context: before_path,
                min_confirmations: 1
            }
        )
        .is_err(),
        "spent Factory source accepted as canonical context"
    );
    ensure!(
        fs::read(&context.sessions[1])? == before_reject,
        "rejected stale context changed member authority"
    );
    let mut deposit_rights = alice_context.rights.clone();
    deposit_rights[0].quantity = "23000000000".to_string();
    let deposit = FactoryPreparationTerms {
        schema: metadata.schema,
        context: alice_context,
        intent: FactoryPreparationOperation::ReducedDeposit {
            participant: before.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "43900000000".to_string(),
                business_ckb: "6100000000".to_string(),
                amount: "0".to_string(),
            }],
            type_scripts_hex: vec![],
        },
        target_rights: deposit_rights,
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![fee_wallet(rpc, options, 20_000_000_000)?],
    };
    let deposit_directory = directory.join("reduced-deposit");
    let deposit_packet = prepare(rpc, &context, &deposit_directory, &deposit)?;
    let deposited = execute(rpc, &context, &deposit_directory, &deposit_packet, None)?;
    refresh_peer(rpc, &context, &deposited)?;
    let child = super::factory_child_acceptance::run(rpc, &context, &directory.join("child"))?;
    Ok(
        json!({"withheld_full_consent_escaped":true,"previous_approval_not_revoked":true,
        "peer_refreshed_from_public_changes":true,"stale_context_preserves_journal":true,"escape":escaped,"deposit":deposited,"child":child}),
    )
}

pub(crate) fn refresh_peer(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    operation: &Value,
) -> Result<()> {
    session(
        &context.sessions[1],
        FactorySessionCommand::Refresh {
            rpc_url: rpc.endpoint().to_string(),
            transaction_hash: operation["report"]["tx_hash"]
                .as_str()
                .ok_or_else(|| anyhow!("missing transition hash"))?
                .to_string(),
            state_out_point: operation["state_out_point"]
                .as_str()
                .ok_or_else(|| anyhow!("missing retained State"))?
                .to_string(),
            min_confirmations: 1,
            full_request: None,
        },
    )?;
    Ok(())
}

pub(crate) fn execute(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    directory: &Path,
    packet: &Path,
    replacement: Option<&str>,
) -> Result<Value> {
    let request = read_request(packet)?.decode()?;
    let id = canonical_hex(&request.request_id()?);
    let mut signed_members = Vec::new();
    let mut receipts = Vec::new();
    let member_keys = [
        &context.options.alice_private_key,
        &context.options.bob_private_key,
    ];
    for required in request.required_members()? {
        let index = request
            .members()?
            .iter()
            .position(|member| member.participant == required.participant)
            .ok_or_else(|| anyhow!("unknown required member"))?;
        if let Some(previous) = replacement {
            session(
                &context.sessions[index],
                FactorySessionCommand::Replace {
                    previous_request: previous.to_string(),
                    request: packet.to_path_buf(),
                },
            )?;
        } else {
            session(
                &context.sessions[index],
                FactorySessionCommand::Prepare {
                    request: packet.to_path_buf(),
                },
            )?;
        }
        let receipt = session(
            &context.sessions[index],
            FactorySessionCommand::Sign {
                rpc_url: rpc.endpoint().to_string(),
                request_id: id.clone(),
                private_key: member_keys[index].clone(),
            },
        )?;
        let path = directory.join(format!("member-{index}-receipt.json"));
        save_json(&path, &receipt)?;
        signed_members.push(index);
        receipts.push((index, path));
    }
    for index in &signed_members {
        for (peer, path) in &receipts {
            if peer != index {
                session(
                    &context.sessions[*index],
                    FactorySessionCommand::AddSignature {
                        request_id: id.clone(),
                        signature: path.clone(),
                    },
                )?;
            }
        }
    }
    let export = session(
        &context.sessions[signed_members[0]],
        FactorySessionCommand::Export {
            request_id: id.clone(),
            store_dir: directory.join("exports"),
        },
    )?;
    let signed = operator::sign_preparation_wallet(
        rpc,
        operator::WalletSignOptions {
            terms: directory.join("terms.json"),
            request: packet.to_path_buf(),
            transaction: PathBuf::from(
                export["transaction"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing protocol transaction"))?,
            ),
            contracts_dir: context.options.contracts_dir.clone(),
            policy: context.policy.to_path_buf(),
            max_fee: context.options.fee,
            store_dir: directory.join("wallets"),
            private_key: context.options.private_key.clone(),
        },
    )?;
    let tx = PathBuf::from(
        signed["transaction"]
            .as_str()
            .ok_or_else(|| anyhow!("missing wallet transaction"))?,
    );
    let submitted = operator::submit(
        rpc,
        operator::SubmitOptions {
            request: packet.to_path_buf(),
            transaction: tx.clone(),
            contracts_dir: context.options.contracts_dir.clone(),
            policy: context.policy.to_path_buf(),
            max_fee: context.options.fee,
            mine_blocks: context.options.mine_blocks,
            store_dir: directory.join("submitted"),
            dry_run: false,
        },
    )?;
    ensure!(
        submitted["report"]["status"] == "Committed",
        "Factory transition did not commit"
    );
    let state_point = if request.requires_activation()? {
        let key = parse_privkey(&context.options.private_key)
            .map_err(|_| anyhow!("invalid acceptance wallet key"))?;
        let funding = find_largest_live_cell(
            rpc,
            &secp256k1_lock(&key)?,
            rpc.tip_header()?.number_value()?,
        )?;
        let activated = operator::activate(
            rpc,
            operator::ActivateOptions {
                request: packet.to_path_buf(),
                fee_out_point: format_out_point(&funding.out_point),
                contracts_dir: context.options.contracts_dir.clone(),
                store_dir: directory.join("activated"),
                fee: context.options.fee,
                max_fee: context.options.fee,
                mine_blocks: context.options.mine_blocks,
                private_key: context.options.private_key.clone(),
            },
        )?;
        Some(
            activated["state_out_point"]
                .as_str()
                .ok_or_else(|| anyhow!("missing activated Factory"))?
                .to_string(),
        )
    } else {
        request.target.as_ref().map(|target| {
            format!(
                "{}:{}",
                canonical_hex(&target.state_out_point.tx_hash),
                target.state_out_point.index
            )
        })
    };
    for index in signed_members {
        session(
            &context.sessions[index],
            FactorySessionCommand::Confirm {
                rpc_url: rpc.endpoint().to_string(),
                request_id: id.clone(),
                state_out_point: state_point.clone(),
                min_confirmations: 1,
            },
        )?;
    }
    Ok(
        json!({"request":packet,"request_id":id,"transaction":tx,"state_out_point":state_point,"report":submitted["report"]}),
    )
}
