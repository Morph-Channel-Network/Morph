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
    pub admission_config: &'a Path,
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
            admission_config: context.admission_config.to_path_buf(),
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
    let rights_updates = qualify_state_updates(rpc, &context, &directory.join("rights-updates"))?;
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
    rights[0].quantity = "6100000000".to_string();
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
                business_ckb: "9200000000".to_string(),
                amount: "0".to_string(),
            }],
            payouts: vec![FactoryPayoutTerms {
                type_hash: None,
                reserve: "6100000000".to_string(),
                business_ckb: "800000000".to_string(),
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
    deposit_rights[0].quantity = "46100000000".to_string();
    let deposit = FactoryPreparationTerms {
        schema: metadata.schema,
        context: alice_context,
        intent: FactoryPreparationOperation::ReducedDeposit {
            participant: before.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "63900000000".to_string(),
                business_ckb: "9200000000".to_string(),
                amount: "0".to_string(),
            }],
            type_scripts_hex: vec![],
        },
        target_rights: deposit_rights,
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![fee_wallet(rpc, options, 40_000_000_000)?],
    };
    let deposit_directory = directory.join("reduced-deposit");
    let deposit_packet = prepare(rpc, &context, &deposit_directory, &deposit)?;
    let deposited = execute(rpc, &context, &deposit_directory, &deposit_packet, None)?;
    refresh_peer(rpc, &context, &deposited)?;
    let child = super::factory_child_acceptance::run(rpc, &context, &directory.join("child"))?;
    Ok(
        json!({"withheld_full_consent_escaped":true,"previous_approval_not_revoked":true,
        "peer_refreshed_from_public_changes":true,"stale_context_preserves_journal":true,"rights_updates":rights_updates,"escape":escaped,"deposit":deposited,"child":child}),
    )
}

fn qualify_state_updates(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    directory: &Path,
) -> Result<Value> {
    let before = public_context(
        &context.sessions[0],
        &directory.join("before-metadata.json"),
    )?;
    let metadata = FactoryPreparationTerms {
        schema: "morph.factory_preparation_terms.v1".to_string(),
        context: before.clone(),
        intent: FactoryPreparationOperation::Metadata {
            access_manifest_root: canonical_hex(&[82; 32]),
        },
        target_rights: before.rights.clone(),
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![fee_wallet(rpc, context.options, 0)?],
    };
    let metadata_directory = directory.join("full-consent-metadata");
    let packet = prepare(rpc, context, &metadata_directory, &metadata)?;
    let full_consent_metadata = execute(rpc, context, &metadata_directory, &packet, None)?;
    let mut operations = Vec::new();
    for count in [1usize, 4, 10] {
        let operation_directory = directory.join(format!("reduced-rights-{count}"));
        let before = public_context(
            &context.sessions[1],
            &operation_directory.join("before.json"),
        )?;
        let participant = before.members[1].participant.clone();
        let mut rights = before.rights.clone();
        let mut changed = 0usize;
        for right in &mut rights {
            if right.participant == participant
                && right.kind == morph_core::FactoryRightKind::SponsorBudgetClaim
                && changed < count
            {
                let quantity = right.quantity.parse::<u128>()?;
                right.quantity = quantity
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("native reduced right exhausted"))?
                    .to_string();
                changed += 1;
            }
        }
        ensure!(changed == count, "missing precommitted native rights");
        let terms = FactoryPreparationTerms {
            schema: metadata.schema.clone(),
            context: before,
            intent: FactoryPreparationOperation::ReducedRights { participant },
            target_rights: rights,
            cell_deps: context.cell_deps.to_vec(),
            funders: vec![fee_wallet(rpc, context.options, 0)?],
        };
        let packet = prepare(rpc, context, &operation_directory, &terms)?;
        let request = read_request(&packet)?.decode()?;
        let frame = morph_script_common::factory_multi_asset::FactoryReducedReleaseWitness::parse(
            &request.witness,
        )
        .map_err(|error| anyhow!("native reduced frame: {error:?}"))?;
        ensure!(
            frame.right_count() == count && request.required_members()?.len() == 1,
            "native reduced request has the wrong proof or authority shape"
        );
        let mut operation = execute_inner(
            rpc,
            context,
            &operation_directory,
            &packet,
            None,
            context.options.reorg && count == 1,
        )?;
        refresh_member(rpc, context, &operation, 0)?;
        let owner = public_context(
            &context.sessions[1],
            &operation_directory.join("after-owner.json"),
        )?;
        let peer = public_context(
            &context.sessions[0],
            &operation_directory.join("after-peer.json"),
        )?;
        ensure!(
            serde_json::to_value(owner)? == serde_json::to_value(peer)?,
            "native reduced update did not refresh untouched member proofs"
        );
        operation["changed_right_count"] = json!(count);
        operation["peer_refreshed_from_public_changes"] = json!(true);
        operations.push(operation);
    }
    Ok(json!({"full_consent_metadata":full_consent_metadata,"operations":operations}))
}

pub(crate) fn refresh_peer(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    operation: &Value,
) -> Result<()> {
    refresh_member(rpc, context, operation, 1)
}

fn refresh_member(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    operation: &Value,
    member_index: usize,
) -> Result<()> {
    session(
        &context.sessions[member_index],
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
    let terminal = read_request(packet)?.decode()?.target.is_none();
    execute_inner(
        rpc,
        context,
        directory,
        packet,
        replacement,
        terminal && context.options.reorg,
    )
}

fn execute_inner(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    directory: &Path,
    packet: &Path,
    replacement: Option<&str>,
    orphan_replay: bool,
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
            admission_config: context.admission_config.to_path_buf(),
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
    let replay_baseline = if orphan_replay {
        Some((
            rpc.tip_header()?,
            fs::read(&tx)?,
            context
                .sessions
                .iter()
                .map(fs::read)
                .collect::<std::io::Result<Vec<_>>>()?,
        ))
    } else {
        None
    };
    let mut submitted = operator::submit(
        rpc,
        operator::SubmitOptions {
            request: packet.to_path_buf(),
            transaction: tx.clone(),
            contracts_dir: context.options.contracts_dir.clone(),
            admission_config: context.admission_config.to_path_buf(),
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
    let canonical_reorg_replay = if let Some((tip, signed_bytes, journals)) = replay_baseline {
        let original = submitted.clone();
        rpc.truncate(parse_h256(&tip.hash)?)?;
        ensure!(
            rpc.tip_header()?.hash == tip.hash,
            "Factory orphan replay did not restore its canonical predecessor"
        );
        ensure!(
            rpc.transaction(request.transaction_hash()?.into())?
                .tx_status
                .status
                != Status::Committed,
            "Factory transition remained committed after controlled rollback"
        );
        let source = request
            .source
            .as_ref()
            .ok_or_else(|| anyhow!("Factory orphan replay requires an existing source"))?;
        operator::validate_live_custody(rpc, source, &context.options.contracts_dir)?;
        crate::admission::reconcile_native(
            rpc,
            context.admission_config,
            &context.options.contracts_dir,
        )?;
        let orphan_admission =
            crate::admission::facts(context.admission_config, &context.options.contracts_dir)?;
        ensure!(
            orphan_admission["active_factories"] == 1,
            "orphaned terminal closure did not restore the active Factory admission slot"
        );
        // Reuse the complete immutable wallet/protocol transaction. No sign,
        // add-signature or participant journal command occurs after rollback.
        submitted = operator::submit(
            rpc,
            operator::SubmitOptions {
                request: packet.to_path_buf(),
                transaction: tx.clone(),
                contracts_dir: context.options.contracts_dir.clone(),
                admission_config: context.admission_config.to_path_buf(),
                policy: context.policy.to_path_buf(),
                max_fee: context.options.fee,
                mine_blocks: context.options.mine_blocks,
                store_dir: directory.join("submitted"),
                dry_run: false,
            },
        )?;
        ensure!(
            submitted["report"]["status"] == "Committed"
                && submitted["report"]["tx_hash"] == original["report"]["tx_hash"]
                && fs::read(&tx)? == signed_bytes
                && context
                    .sessions
                    .iter()
                    .map(fs::read)
                    .collect::<std::io::Result<Vec<_>>>()?
                    == journals,
            "Factory orphan replay changed the signed transaction or participant authority"
        );
        let replay_admission =
            crate::admission::facts(context.admission_config, &context.options.contracts_dir)?;
        ensure!(
            orphan_admission["lifetime_child_reservations"]
                == replay_admission["lifetime_child_reservations"],
            "canonical reorg replay changed lifetime child reservations"
        );
        json!({"orphaned":true,"authentic_source_live":true,"exact_body_and_witnesses":true,
            "admission":{"orphaned":orphan_admission,"replayed":replay_admission,"lifetime_children_preserved":true},
            "unchanged_signer_journals":true,"no_new_participant_signatures":true,
            "original":original,"replayed":submitted})
    } else {
        Value::Null
    };
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
                admission_config: context.admission_config.to_path_buf(),
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
        json!({"request":packet,"request_id":id,"transaction":tx,"state_out_point":state_point,"report":submitted["report"],"canonical_reorg_replay":canonical_reorg_replay}),
    )
}
