//! Native Factory child creation, independent initial recovery ceremonies and
//! ordinary bilateral operation after canonical same-path handoff.
use super::factory_transitions_acceptance::{self as parent, Context};
use super::multi_asset_operator::{self as channel, FeeAuthorization, Operation};
use super::*;
use crate::channel_creation::ChannelCreationTerms;
use crate::factory_child_session::{FactoryChildSessionCommand, run as child_session};
use crate::factory_delivery::{DeliveryCommand, run as deliver};
use crate::factory_packets::{read_for_delivery_review, read_request};
use crate::factory_root_transaction::FactoryReserveTerms;
use crate::factory_session::{FactorySessionCommand, run as factory_session};
use crate::factory_transaction::{
    FactoryChildTerms, FactoryPreparationOperation, FactoryPreparationTerms,
};
use crate::multi_asset_packages::{canonical_hex, read_package};
use crate::multi_asset_session::{SessionCommand, SigningTarget, run as bilateral_session};
use morph_core::{
    MultiAssetPayout, MultiAssetSettlement, MultiAssetSettlementCapability, MultiAssetValue,
    VaultAsset, blake2b256,
};
use serde_json::{Value, json};

fn path(value: &Value, field: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(
        value[field]
            .as_str()
            .ok_or_else(|| anyhow!("missing {field} path"))?,
    ))
}
fn fee_point(rpc: &CkbRpcClient, context: &Context<'_>) -> Result<String> {
    let key = parse_privkey(&context.options.private_key)
        .map_err(|_| anyhow!("invalid child acceptance fee key"))?;
    let cell = find_largest_live_cell(
        rpc,
        &secp256k1_lock(&key)?,
        rpc.tip_header()?.number_value()?,
    )?;
    Ok(format_out_point(&cell.out_point))
}
fn transact(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    directory: &Path,
    operation: Operation,
    package: &Path,
    state: &str,
) -> Result<Value> {
    channel::transact(
        rpc,
        channel::Options {
            operation,
            package: package.to_path_buf(),
            state_out_point: state.to_string(),
            fee_out_point: fee_point(rpc, context)?,
            fee_authorization: FeeAuthorization::Wallet {
                private_key: context.options.private_key.clone(),
            },
            contracts_dir: context.options.contracts_dir.clone(),
            store_dir: directory.to_path_buf(),
            fee: context.options.fee,
            max_fee: context.options.fee,
            mine_blocks: context.options.mine_blocks,
            publication_profile: None,
            attempt_log: None,
            dry_run: false,
        },
    )
}

pub(crate) fn run(rpc: &CkbRpcClient, context: &Context<'_>, directory: &Path) -> Result<Value> {
    let before = parent::public_context(&context.sessions[0], &directory.join("context.json"))?;
    let (custody, members, _) = before.decode()?;
    ensure!(
        custody.manifest.vaults.len() == 1 && custody.manifest.vaults[0].asset == VaultAsset::Ckb,
        "child acceptance requires preceding plain Factory deposit"
    );
    ensure!(
        before.rights[0].quantity == "23000000000",
        "expected backed Alice claim after native deposit"
    );
    let keys = [
        &context.options.alice_private_key,
        &context.options.bob_private_key,
    ];
    let mut child_keys = members
        .iter()
        .map(|member| canonical_hex(&member.pubkey_sec1))
        .collect::<Vec<_>>();
    child_keys.sort();
    let mut locks = keys
        .iter()
        .map(|private| -> Result<_> {
            let key =
                parse_privkey(private).map_err(|_| anyhow!("invalid child participant key"))?;
            Ok(secp256k1_lock(&key)?.as_slice().to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    locks.sort_by_key(|lock| blake2b256(lock));
    let owner = parse_privkey(&context.options.private_key)
        .map_err(|_| anyhow!("invalid child carrier funder"))?;
    let settlement = MultiAssetSettlement {
        capability: MultiAssetSettlementCapability::Ordinary,
        participant_lock_hashes: [blake2b256(&locks[0]), blake2b256(&locks[1])],
        carrier_refund_lock_hash: secp256k1_lock(&owner)?.calc_script_hash().unpack(),
        payouts: vec![MultiAssetPayout {
            asset: VaultAsset::Ckb,
            values: [MultiAssetValue {
                reserve: 9_000_000_000,
                business_ckb: 1_000_000_000,
                amount: 0,
            }; 2],
        }],
    };
    let channel_terms = ChannelCreationTerms {
        participants: child_keys
            .try_into()
            .map_err(|_| anyhow!("child requires exactly two members"))?,
        participant_locks_hex: [canonical_hex(&locks[0]), canonical_hex(&locks[1])],
        carrier_refund_lock_hex: canonical_hex(secp256k1_lock(&owner)?.as_slice()),
        descriptor_hex: canonical_hex(&settlement.encode()?),
        challenge_blocks: "24".to_string(),
        type_scripts_hex: vec![],
    };
    let code = |name: &str| -> Result<[u8; 32]> {
        Ok(blake2b256(&fs::read(
            context.options.contracts_dir.join(name),
        )?))
    };
    let authority = crate::multi_asset_root_transaction::RootAuthorityHashes {
        state_type: code("morph-state-type")?,
        state_lock: code("morph-state-lock")?,
        vault_lock: code("morph-vault-lock")?,
    };
    // The creation slot is deterministic: retained State0/Vault1, then child2.
    let state_input = CellInput::new(
        OutPoint::new(
            custody.state_out_point.tx_hash.pack(),
            custody.state_out_point.index,
        ),
        0,
    );
    let mut anchor = state_input.as_slice().to_vec();
    anchor.extend_from_slice(&2u64.to_le_bytes());
    let creation = channel_terms.build(
        custody.state()?.fields().chain_id,
        authority,
        blake2b256(&anchor),
        Some(blake2b256(&custody.state_type)),
    )?;
    let mut rights = before.rights.clone();
    rights[0].quantity = "3000000000".to_string();
    let terms = FactoryPreparationTerms {
        schema: "morph.factory_preparation_terms.v1".to_string(),
        context: before.clone(),
        intent: FactoryPreparationOperation::ReducedChild {
            participant: before.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "25900000000".to_string(),
                business_ckb: "4100000000".to_string(),
                amount: "0".to_string(),
            }],
            children: vec![FactoryChildTerms {
                channel: channel_terms,
                state_type_code_hash: canonical_hex(&authority.state_type),
                state_lock_code_hash: canonical_hex(&authority.state_lock),
                vault_lock_code_hash: canonical_hex(&authority.vault_lock),
            }],
        },
        target_rights: rights,
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![parent::fee_wallet(
            rpc,
            context.options,
            creation.state_carrier_capacity,
        )?],
    };
    let reduced = run_case(rpc, context, &directory.join("reduced"), &terms, false)?;
    let terminal_context = parent::public_context(
        &context.sessions[0],
        &directory.join("terminal-context.json"),
    )?;
    let terminal_source = terminal_context.custody.decode()?;
    let FactoryPreparationOperation::ReducedChild { children, .. } = &terms.intent else {
        return Err(anyhow!("unexpected child intent"));
    };
    let mut terminal_child = children[0].clone();
    let mut terminal_settlement = settlement;
    terminal_settlement.payouts[0].values = [MultiAssetValue {
        reserve: 12_950_000_000,
        business_ckb: 2_050_000_000,
        amount: 0,
    }; 2];
    terminal_child.channel.descriptor_hex = canonical_hex(&terminal_settlement.encode()?);
    let input = CellInput::new(
        OutPoint::new(
            terminal_source.state_out_point.tx_hash.pack(),
            terminal_source.state_out_point.index,
        ),
        0,
    );
    let mut anchor = input.as_slice().to_vec();
    anchor.extend_from_slice(&1u64.to_le_bytes());
    let terminal_creation = terminal_child.channel.build(
        terminal_source.state()?.fields().chain_id,
        authority,
        blake2b256(&anchor),
        Some(blake2b256(&terminal_source.state_type)),
    )?;
    let terminal_terms = FactoryPreparationTerms {
        schema: terms.schema.clone(),
        context: terminal_context,
        intent: FactoryPreparationOperation::Materialise {
            retained: None,
            children: vec![terminal_child],
            carrier_refund_lock_hex: canonical_hex(secp256k1_lock(&owner)?.as_slice()),
            access_manifest_root: canonical_hex(&[91; 32]),
        },
        target_rights: vec![],
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![parent::fee_wallet(
            rpc,
            context.options,
            terminal_creation.state_carrier_capacity,
        )?],
    };
    let terminal = run_case(
        rpc,
        context,
        &directory.join("terminal"),
        &terminal_terms,
        true,
    )?;
    Ok(json!({"reduced":reduced,"terminal":terminal}))
}

fn run_case(
    rpc: &CkbRpcClient,
    context: &Context<'_>,
    directory: &Path,
    terms: &FactoryPreparationTerms,
    terminal: bool,
) -> Result<Value> {
    let keys = [
        &context.options.alice_private_key,
        &context.options.bob_private_key,
    ];
    let draft = parent::prepare(rpc, context, directory, terms)?;
    let unsigned = read_for_delivery_review(&draft)?.decode_for_delivery_review()?;
    let factory_before = fs::read(&context.sessions[0])?;
    ensure!(
        factory_session(
            &context.sessions[0],
            FactorySessionCommand::Prepare {
                request: draft.clone()
            }
        )
        .is_err(),
        "parent authority accepted missing private child delivery"
    );
    ensure!(
        fs::read(&context.sessions[0])? == factory_before,
        "missing child delivery modified parent signer authority"
    );
    let mut child_sessions = Vec::new();
    let mut signatures = Vec::new();
    for (index, private) in keys.iter().enumerate() {
        let key = parse_privkey(private).map_err(|_| anyhow!("invalid child signer key"))?;
        let local_pubkey = canonical_hex(&compressed_pubkey(&key)?);
        let session = directory.join(format!("child-party-{index}.json"));
        child_session(
            &session,
            FactoryChildSessionCommand::Init {
                request: draft.clone(),
                child_index: 0,
                local_pubkey,
                policy: context.policy.to_path_buf(),
                contracts_dir: context.options.contracts_dir.clone(),
            },
        )?;
        let initial = fs::read(&session)?;
        ensure!(
            child_session(
                &session,
                FactoryChildSessionCommand::Sign {
                    private_key: keys[1 - index].clone()
                }
            )
            .is_err(),
            "wrong child key was accepted"
        );
        ensure!(
            fs::read(&session)? == initial,
            "wrong child key reserved the initial exit"
        );
        let signature = child_session(
            &session,
            FactoryChildSessionCommand::Sign {
                private_key: (*private).clone(),
            },
        )?;
        let signature_path = directory.join(format!("child-signature-{index}.json"));
        parent::save_json(&signature_path, &signature)?;
        let partial = directory.join(format!("partial-child-{index}"));
        ensure!(
            child_session(
                &session,
                FactoryChildSessionCommand::Export {
                    store_dir: partial.clone()
                }
            )
            .is_err()
                && !partial.exists(),
            "partial child exit occupied its immutable private export"
        );
        child_sessions.push(session);
        signatures.push(signature_path);
    }
    let mut complete = draft;
    let mut private_packages = Vec::new();
    for (index, session) in child_sessions.iter().enumerate() {
        child_session(
            session,
            FactoryChildSessionCommand::AddSignature {
                signature: signatures[1 - index].clone(),
            },
        )?;
        let exported = child_session(
            session,
            FactoryChildSessionCommand::Export {
                store_dir: directory.join(format!("private-party-{index}")),
            },
        )?;
        let private_package = path(&exported, "private_recovery")?;
        unsigned.verify_child_recovery(0, &read_package(&private_package)?.recovery()?)?;
        let public_receipt = directory.join(format!("child-delivery-{index}.json"));
        let key = parse_privkey(keys[index]).map_err(|_| anyhow!("invalid delivery signer key"))?;
        deliver(DeliveryCommand::Receive {
            request: complete.clone(),
            child_index: 0,
            package: private_package.clone(),
            local_pubkey: canonical_hex(&compressed_pubkey(&key)?),
            store_dir: directory.join(format!("delivery-private-{index}")),
            receipt: public_receipt.clone(),
            private_key: keys[index].clone(),
        })?;
        let attached = directory.join(format!("complete-request-{index}.json"));
        deliver(DeliveryCommand::Attach {
            request: complete,
            receipt: public_receipt,
            output: attached.clone(),
        })?;
        complete = attached;
        private_packages.push(private_package);
    }
    let request = read_request(&complete)?.decode()?;
    let private = read_package(&private_packages[0])?.recovery()?;
    ensure!(
        private == read_package(&private_packages[1])?.recovery()?,
        "child parties did not retain the same complete exit"
    );
    let public = fs::read_to_string(&complete)?;
    for signature in &private.authorization.signatures {
        ensure!(
            !public.contains(&canonical_hex(&signature.signature)),
            "parent packet leaked a child's private exit signature"
        );
    }
    let executed = parent::execute(rpc, context, directory, &complete, None)?;
    if !terminal {
        parent::refresh_peer(rpc, context, &executed)?;
    }
    let raw_hash = request.transaction_hash()?;
    let child = request.public_child(0)?;
    let original_point = format!("{}:{}", canonical_hex(&raw_hash), child.state_output_index);
    let activated = transact(
        rpc,
        context,
        &directory.join("child-activation"),
        Operation::Activate,
        &private_packages[0],
        &original_point,
    )?;
    let active_hash = activated["tx_hash"]
        .as_str()
        .ok_or_else(|| anyhow!("missing child activation hash"))?;
    let active_point = format!("{active_hash}:0");
    let parent_transaction = path(&executed, "transaction")?;
    let mut handoffs = Vec::new();
    for session in &child_sessions {
        let before = fs::read(session)?;
        ensure!(
            child_session(
                session,
                FactoryChildSessionCommand::Confirm {
                    request: complete.clone(),
                    transaction: parent_transaction.clone(),
                    rpc_url: rpc.endpoint().to_string(),
                    state_out_point: active_point.clone(),
                    min_confirmations: u64::MAX,
                    archive_dir: directory.join("child-history"),
                    contracts_dir: context.options.contracts_dir.clone()
                }
            )
            .is_err(),
            "child handoff accepted impossible confirmation depth"
        );
        ensure!(
            fs::read(session)? == before,
            "failed child handoff changed initial authority"
        );
        let handoff = child_session(
            session,
            FactoryChildSessionCommand::Confirm {
                request: complete.clone(),
                transaction: parent_transaction.clone(),
                rpc_url: rpc.endpoint().to_string(),
                state_out_point: active_point.clone(),
                min_confirmations: 1,
                archive_dir: directory.join("child-history"),
                contracts_dir: context.options.contracts_dir.clone(),
            },
        )?;
        ensure!(
            handoff["session"]["reserved_state_number"] == "1",
            "child handoff did not retain its initial vote"
        );
        handoffs.push(handoff);
    }
    let packages = directory.join("watch-recovery");
    crate::multi_asset_packages::write_package(&packages, &read_package(&private_packages[0])?)?;
    let mut updated = private.settlement.clone();
    updated.payouts[0].values[0].business_ckb -= 100_000_000;
    updated.payouts[0].values[1].business_ckb += 100_000_000;
    let proposed = bilateral_session(
        &child_sessions[0],
        SessionCommand::Propose {
            descriptor_hex: canonical_hex(&updated.encode()?),
        },
    )?;
    let proposal_path = directory.join("child-update.json");
    parent::save_json(&proposal_path, &proposed)?;
    bilateral_session(
        &child_sessions[1],
        SessionCommand::Accept {
            proposal: proposal_path,
        },
    )?;
    let mut votes = Vec::new();
    for (index, session) in child_sessions.iter().enumerate() {
        let vote = bilateral_session(
            session,
            SessionCommand::Sign {
                target: SigningTarget::Update,
                private_key: keys[index].clone(),
            },
        )?;
        let vote_path = directory.join(format!("child-update-signature-{index}.json"));
        parent::save_json(&vote_path, &vote)?;
        votes.push(vote_path);
    }
    let mut committed = Vec::new();
    for (index, session) in child_sessions.iter().enumerate() {
        bilateral_session(
            session,
            SessionCommand::AddSignature {
                target: SigningTarget::Update,
                signature: votes[1 - index].clone(),
            },
        )?;
        committed.push(bilateral_session(
            session,
            SessionCommand::Commit {
                store_dir: packages.clone(),
            },
        )?);
    }
    let latest = path(&committed[0], "recovery_package")?;
    ensure!(
        read_package(&latest)?.recovery()?.state.header.state_number == 2,
        "independent child update did not commit state2"
    );
    // Publish an older valid exit, then require the current watcher to correct
    // it using the latest private package produced by the operational journals.
    let stale = transact(
        rpc,
        context,
        &directory.join("old-publication"),
        Operation::Publish,
        &private_packages[0],
        &active_point,
    )?;
    let profile = crate::publication::fixture_publication_profile();
    let publication_max_fee = profile.fee.max_fee;
    let profile_path = directory.join("publication-profile.json");
    parent::save_json(&profile_path, &profile)?;
    let from_block = rpc
        .transaction(raw_hash.into())?
        .tx_status
        .block_number
        .ok_or_else(|| anyhow!("child creation inclusion height unavailable"))?
        .value();
    let watched = super::multi_asset_watch::watch(
        rpc,
        super::multi_asset_watch::Options {
            contracts_dir: context.options.contracts_dir.clone(),
            fee_authorization: FeeAuthorization::Wallet {
                private_key: context.options.private_key.clone(),
            },
            fee_out_point: fee_point(rpc, context)?,
            store_dir: packages.clone(),
            channel_id: canonical_hex(&private.state.header.channel_id),
            from_block,
            cursor_file: directory.join("watch-cursor.json"),
            alert_file: directory.join("watch-alerts.jsonl"),
            publication_profile: profile_path,
            attempt_log: directory.join("publication-attempts.jsonl"),
            detection_depth: 1,
            timeout_secs: 2,
            poll_ms: 100,
            max_fee: publication_max_fee,
            mine_blocks: context.options.mine_blocks,
            watch_policy: None,
            alert_webhook_url: None,
            auto_fund_sponsor: None,
        },
    )?;
    ensure!(
        !watched["publication"].is_null() && watched["publication"]["canonical_confirmed"] == true,
        "current watcher failed to correct old child exit with latest evidence"
    );
    let corrected_hash = watched["publication"]["tx_hash"]
        .as_str()
        .ok_or_else(|| anyhow!("missing watcher correction hash"))?;
    let corrected = format!("{corrected_hash}:0");
    let since = morph_script_common::multi_asset::MultiAssetVaultArgs::parse(
        &private.scripts.vault_lock[53..],
    )
    .map_err(|error| anyhow!("invalid child finalise policy: {error:?}"))?
    .finalise_since();
    mine_relative_since_maturity(rpc, since & 0x00ff_ffff_ffff_ffff)?;
    let finalised = transact(
        rpc,
        context,
        &directory.join("finalised"),
        Operation::Finalise,
        &latest,
        &corrected,
    )?;
    ensure!(
        finalised["status"] == "Committed",
        "child finalisation failed"
    );
    for point in &private.outpoints {
        ensure!(
            rpc.canonical_live_cell(
                OutPoint::new(point.tx_hash.pack(), point.index).into(),
                false
            )?
            .status
                != "live",
            "closed child left a live custody Vault"
        );
    }
    let remaining = if terminal {
        for session in context.sessions {
            ensure!(
                factory_session(session, FactorySessionCommand::Inspect)?["current"].is_null(),
                "terminal materialisation left active parent authority"
            );
        }
        let source = request
            .source
            .as_ref()
            .ok_or_else(|| anyhow!("missing terminal Factory source"))?;
        for point in std::iter::once(&source.state_out_point).chain(&source.vault_outpoints) {
            ensure!(
                rpc.canonical_live_cell(
                    OutPoint::new(point.tx_hash.pack(), point.index).into(),
                    false
                )?
                .status
                    != "live",
                "terminal materialisation orphaned parent custody"
            );
        }
        let (actual, _) = super::multi_asset_splice_operator::canonical_transaction(
            rpc,
            request.transaction_hash()?.into(),
            1,
        )?;
        let refund = actual
            .raw()
            .outputs()
            .get(0)
            .ok_or_else(|| anyhow!("missing carrier refund output"))?;
        let owner = parse_privkey(&context.options.private_key)
            .map_err(|_| anyhow!("invalid refund owner key"))?;
        ensure!(
            u64::from(refund.capacity()) == source.state_carrier_capacity
                && refund.lock() == secp256k1_lock(&owner)?
                && refund.type_().to_opt().is_none()
                && actual
                    .raw()
                    .outputs_data()
                    .get(0)
                    .is_some_and(|data| data.raw_data().is_empty()),
            "terminal Factory did not refund its entire carrier to the signed owner lock"
        );
        json!({"retired":true,"carrier_refund":{"transaction_hash":canonical_hex(&request.transaction_hash()?),"index":0,"capacity":source.state_carrier_capacity.to_string(),"lock_hash":canonical_hex(refund.lock().calc_script_hash().as_slice())}})
    } else {
        let remaining = parent::public_context(
            &context.sessions[1],
            &directory.join("retained-parent.json"),
        )?;
        ensure!(
            remaining.rights[0].quantity == "3000000000"
                && remaining.rights[1].quantity == "13000000000",
            "child lifecycle changed unrelated Factory claims"
        );
        serde_json::to_value(remaining)?
    };
    Ok(
        json!({"terminal_factory":terminal,"parent":executed,"activation":activated,"independent_initial_exit_sessions":child_sessions,"private_exits":private_packages,"same_path_handoffs":handoffs,"initial_exit_required_before_parent_vote":true,"private_exit_signatures_absent_from_parent":true,"independent_update":committed,"old_publication":stale,"latest_package_watch":watched,"finalise":finalised,"retained_factory":remaining,"external_child_carrier":private.state_carrier_capacity.to_string()}),
    )
}
