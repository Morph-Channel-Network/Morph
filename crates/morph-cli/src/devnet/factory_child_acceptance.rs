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
        before.rights[0].quantity == "46100000000",
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
    rights[0].quantity = "26100000000".to_string();
    let terms = FactoryPreparationTerms {
        schema: "morph.factory_preparation_terms.v1".to_string(),
        context: before.clone(),
        intent: FactoryPreparationOperation::ReducedChild {
            participant: before.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "45900000000".to_string(),
                business_ckb: "7200000000".to_string(),
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
    // Full-consent materialisation with retained custody uses a distinct FM
    // authorization from the reduced child above. Both parties still obtain
    // their own private exit before either parent journal can approve it.
    let retained_context = parent::public_context(
        &context.sessions[0],
        &directory.join("retained-context.json"),
    )?;
    let retained_source = retained_context.custody.decode()?;
    let FactoryPreparationOperation::ReducedChild { children, .. } = &terms.intent else {
        return Err(anyhow!("unexpected child intent"));
    };
    let retained_child = children[0].clone();
    let retained_input = CellInput::new(
        OutPoint::new(
            retained_source.state_out_point.tx_hash.pack(),
            retained_source.state_out_point.index,
        ),
        0,
    );
    let mut retained_anchor = retained_input.as_slice().to_vec();
    retained_anchor.extend_from_slice(&2u64.to_le_bytes());
    let retained_creation = retained_child.channel.build(
        retained_source.state()?.fields().chain_id,
        authority,
        blake2b256(&retained_anchor),
        Some(blake2b256(&retained_source.state_type)),
    )?;
    let mut retained_rights = retained_context.rights.clone();
    // Keep both retained ReserveClaims independently payable after the
    // second child debit; the shared retained floor remains collective.
    retained_rights[0].quantity = "6100000000".to_string();
    retained_rights[1].quantity = "13000000000".to_string();
    let retained_terms = FactoryPreparationTerms {
        schema: terms.schema.clone(),
        context: retained_context,
        intent: FactoryPreparationOperation::Materialise {
            retained: Some(vec![FactoryReserveTerms {
                type_hash: None,
                reserve: "27900000000".to_string(),
                business_ckb: "5200000000".to_string(),
                amount: "0".to_string(),
            }]),
            children: vec![retained_child],
            carrier_refund_lock_hex: "0x".to_string(),
            access_manifest_root: canonical_hex(&[90; 32]),
        },
        target_rights: retained_rights,
        cell_deps: context.cell_deps.to_vec(),
        funders: vec![parent::fee_wallet(
            rpc,
            context.options,
            retained_creation.state_carrier_capacity,
        )?],
    };
    let retained = run_case(
        rpc,
        context,
        &directory.join("retained"),
        &retained_terms,
        false,
    )?;
    let terminal_context = parent::public_context(
        &context.sessions[0],
        &directory.join("terminal-context.json"),
    )?;
    let terminal_source = terminal_context.custody.decode()?;
    let mut terminal_child = children[0].clone();
    let mut terminal_settlement = settlement;
    let terminal_value = terminal_source.manifest.vaults[0].value;
    terminal_settlement.payouts[0].values = [
        MultiAssetValue {
            reserve: terminal_value.reserve / 2,
            business_ckb: terminal_value.business_ckb / 2,
            amount: 0,
        },
        MultiAssetValue {
            reserve: terminal_value.reserve - terminal_value.reserve / 2,
            business_ckb: terminal_value.business_ckb - terminal_value.business_ckb / 2,
            amount: 0,
        },
    ];
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
    Ok(json!({"reduced":reduced,"retained":retained,"terminal":terminal}))
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
    // Reserve a concrete existing right for the independently derived physical
    // child BEFORE consuming its parent. The right label is not its future ID.
    let (source, members, rights) = terms.context.decode()?;
    let right = rights
        .iter()
        .find(|right| right.quantity > 0 && right.id.asset_type.is_none())
        .ok_or_else(|| anyhow!("missing CKB reservation right"))?;
    let owner = members
        .iter()
        .find(|member| member.participant == right.id.participant)
        .ok_or_else(|| anyhow!("reservation member absent"))?;
    let participants = keys.map(|secret| -> Result<morph_core::ChannelParticipant> {
        let signer = k256_signing_key(secret)?;
        let lock = secp256k1_lock(&parse_privkey(secret)?)?;
        Ok(morph_core::ChannelParticipant {
            node_id: blake2b256(&k256_pubkey(&signer)),
            settlement_lock_hash: lock.calc_script_hash().unpack(),
        })
    });
    let [left, right_party] = participants;
    let participants = [left?, right_party?];
    let owner_lock = participants
        .iter()
        .find(|p| p.node_id == blake2b256(&owner.pubkey_sec1))
        .ok_or_else(|| anyhow!("provider owner is not a child party"))?
        .settlement_lock_hash;
    let side = private
        .settlement
        .participant_lock_hashes
        .iter()
        .position(|l| *l == owner_lock)
        .ok_or_else(|| anyhow!("owner payout missing"))?;
    let quantity =
        u128::from(private.settlement.payouts[0].values[side].business_ckb).min(right.quantity);
    let proof = morph_core::factory_right_sparse_proof(&rights, &right.id)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let fields = source.state()?.fields();
    let mut reservation = morph_core::FactoryRightReservation {
        reservation_id: [0; 32],
        factory_id: fields.factory_id,
        factory_update_number: fields.update_number,
        right: right.id.clone(),
        target_channel_id: private.state.header.channel_id,
        quantity,
        factory_state_root: fields.state_root,
        access_manifest_root: fields.access_manifest_root,
        proof_commitment: morph_core::factory_right_proof_commitment(&proof),
        right_proof: proof,
        idempotency_key: request.transaction_hash()?,
        reserved_at_unix: now,
        expires_at_unix: now + 3600,
    };
    reservation.reservation_id = reservation.derive_id()?;
    reservation.validate(now)?;
    parent::save_json(&directory.join("shadow-reservation.json"), &reservation)?;
    let executed = parent::execute(rpc, context, directory, &complete, None)?;
    if !terminal && request.required_members()?.len() == 1 {
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
    let candidate = super::shadow_observer::Candidate {
        schema: "morph.shadow_candidate.v1".into(),
        package: read_package(&private_packages[0])?,
        state_out_point: active_point.clone(),
        participants,
        asset: morph_core::GatewayAsset::Ckb {
            ckb_genesis_hash: private.state.header.chain_id,
        },
        reservation: Some(reservation),
        origin: super::shadow_observer::Origin::Factory {
            history: Box::new(crate::factory_child_origin::FactoryChildOrigin {
                schema: crate::factory_child_origin::SCHEMA.into(),
                request: read_request(&complete)?,
                transaction_hex: canonical_hex(&fs::read(&parent_transaction)?),
                child_index: 0,
                initial_recovery: read_package(&private_packages[0])?,
            }),
        },
    };
    let candidate_path = directory.join("shadow-candidate.json");
    parent::save_json(&candidate_path, &candidate)?;
    super::multi_asset_splice_acceptance::mine_depth(
        rpc,
        activated["block_number"]
            .as_u64()
            .ok_or_else(|| anyhow!("activation height missing"))?,
        4,
    )?;
    // A different, genuinely signed child history from this same Factory cannot
    // supply this child's provenance, even after that earlier child is closed.
    let prior_path = directory
        .parent()
        .ok_or_else(|| anyhow!("missing child parent"))?
        .join("reduced/shadow-candidate.json");
    let cross_child_history_rejected = if prior_path != candidate_path && prior_path.exists() {
        let prior: super::shadow_observer::Candidate =
            crate::multi_asset_packages::read_bounded_json(
                &prior_path,
                super::shadow_observer::MAX_REQUEST_BYTES,
            )?;
        let mut wrong: super::shadow_observer::Candidate =
            serde_json::from_slice(&serde_json::to_vec(&candidate)?)?;
        wrong.origin = prior.origin;
        let wrong_path = directory.join("shadow-wrong-child.json");
        parent::save_json(&wrong_path, &wrong)?;
        let error = super::shadow_observer::run(
            rpc.endpoint(),
            &wrong_path,
            &context.options.contracts_dir,
            4,
            10_000,
        )
        .err()
        .ok_or_else(|| anyhow!("another child's history accepted"))?;
        ensure!(
            error
                .to_string()
                .contains("Factory child history targets another channel"),
            "wrong child rejected by unrelated guard: {error}"
        );
        Some(true)
    } else {
        None
    };
    let shadow = super::shadow_observer::run(
        rpc.endpoint(),
        &candidate_path,
        &context.options.contracts_dir,
        4,
        10_000,
    )?;
    ensure!(
        shadow["forwarding"] == false && !shadow["edge"]["factory_id"].is_null(),
        "Factory observation lost provenance or enabled forwarding"
    );
    ensure!(
        rpc.canonical_live_cell(
            OutPoint::new(
                source.state_out_point.tx_hash.pack(),
                source.state_out_point.index
            )
            .into(),
            false
        )?
        .status
            != "live",
        "historical Factory source unexpectedly live"
    );
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
    let session_source = crate::multi_asset_session::shadow::capture(
        &child_sessions[0],
        candidate.participants.clone(),
        candidate.asset.clone(),
        candidate.reservation.clone(),
    )?;
    ensure!(
        !session_source.draining,
        "idle Factory child journal marked draining"
    );
    let session_observation = session_source
        .observe(std::time::Duration::from_secs(10))?
        .public()?;
    ensure!(
        session_observation["edge"] == shadow["edge"],
        "current Factory child journal differs from canonical observation"
    );
    crate::multi_asset_packages::write_package(&packages, &read_package(&private_packages[0])?)?;
    let mut updated = private.settlement.clone();
    updated.payouts[0].values[0].business_ckb -= 100_000_000;
    updated.payouts[0].values[1].business_ckb += 100_000_000;
    if terminal {
        // Preserve a real pending claim after the parent has retired. The child
        // independently authorizes this update and its later terminal close.
        updated.payouts[0].values[0].business_ckb = updated.payouts[0].values[0]
            .business_ckb
            .checked_sub(100_000_000)
            .ok_or_else(|| anyhow!("missing pending CKB"))?;
        let capacities = [
            updated.payouts[0].values[0].capacity()?,
            updated.payouts[0].values[1].capacity()?,
        ];
        let batch = morph_core::ConditionalBatch {
            batch_id: [31; 32],
            application_context_commitment: [32; 32],
            participants: core::array::from_fn(|index| morph_core::ConditionalParticipant {
                settlement_lock_hash: updated.participant_lock_hashes[index],
                settled_capacity: capacities[index],
            }),
            transfers: vec![morph_core::ConditionalTransferSpec {
                transfer_id: [33; 32],
                payer_lock_hash: updated.participant_lock_hashes[0],
                hash_algorithm: morph_core::ConditionalHashAlgorithm::CkbBlake2b,
                payment_hash: morph_core::derive_conditional_payment_hash(
                    morph_core::ConditionalHashAlgorithm::CkbBlake2b,
                    &[34; 32],
                )?,
                amount: 100_000_000,
                refund_after_block: rpc
                    .tip_header()?
                    .number_value()?
                    .checked_add(64)
                    .ok_or_else(|| anyhow!("refund height overflow"))?,
            }],
        };
        updated.capability = MultiAssetSettlementCapability::CkbConditional {
            batch_code_hash: blake2b256(&fs::read(
                context.options.contracts_dir.join("morph-batch-lock"),
            )?),
            batch_hash_type: 2,
            batch: Box::new(batch),
        };
    }
    let proposed = bilateral_session(
        &child_sessions[0],
        SessionCommand::Propose {
            descriptor_hex: canonical_hex(&updated.encode()?),
        },
    )?;
    ensure!(
        session_source.ensure_current().is_err(),
        "journal mutation failed to invalidate captured observation"
    );
    let draining_source = crate::multi_asset_session::shadow::capture(
        &child_sessions[0],
        candidate.participants.clone(),
        candidate.asset.clone(),
        candidate.reservation.clone(),
    )?;
    ensure!(
        draining_source.draining,
        "pending child update remained active"
    );
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
            SessionCommand::SignLocal {
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
    let cooperative_close = super::factory_child_close::run(
        rpc,
        context,
        &directory.join("cooperative-close"),
        &child_sessions,
        &latest,
        &active_point,
    )?;
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
            cursor_file: directory.join("watch-cursor.db"),
            alert_file: directory.join("watch-alerts.jsonl"),
            publication_profile: profile_path,
            attempt_log: directory.join("publication-attempts.jsonl"),
            detection_depth: 1,
            timeout_secs: 2,
            poll_ms: 100,
            max_fee: publication_max_fee,
            mine_blocks: context.options.mine_blocks,
            watch_policy: None,
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
            serde_json::to_value(&remaining.rights)? == serde_json::to_value(&terms.target_rights)?,
            "child lifecycle changed unrelated Factory claims"
        );
        serde_json::to_value(remaining)?
    };
    let admission =
        crate::admission::facts(context.admission_config, &context.options.contracts_dir)?;
    ensure!(
        super::shadow_observer::run(
            rpc.endpoint(),
            &candidate_path,
            &context.options.contracts_dir,
            4,
            10_000
        )
        .is_err(),
        "finalised child remained admissible"
    );
    Ok(
        json!({"cooperative_close":cooperative_close,"journal_source_verified":true,"changed_journal_rejected":true,"pending_update_drains":true,"cross_child_history_rejected":cross_child_history_rejected,"shadow_observer":shadow,"shadow_spent_child_rejected":true,"admission":admission,"terminal_factory":terminal,"parent":executed,"activation":activated,"independent_initial_exit_sessions":child_sessions,"private_exits":private_packages,"same_path_handoffs":handoffs,"initial_exit_required_before_parent_vote":true,"private_exit_signatures_absent_from_parent":true,"independent_update":committed,"old_publication":stale,"latest_package_watch":watched,"finalise":finalised,"retained_factory":remaining,"external_child_carrier":private.state_carrier_capacity.to_string()}),
    )
}
