//! Real-node close acceptance through the public builder, journals, independent
//! key service, wallet signer and keyless submitter. No direct participant vote.
use super::multi_asset_close_operator::{self as close, Command, Context};
use super::*;
use crate::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex, write_package};
use crate::multi_asset_session::{CloseCommand, SessionCommand};
use morph_core::MultiAssetRecoveryPackage;
use serde_json::{Value, json};

pub(super) fn run(
    rpc: &CkbRpcClient,
    options: &super::multi_asset::MultiAssetSmokeOptions,
    sessions: [&Path; 2],
    owner_lock: &Script,
    package: &MultiAssetRecoveryPackage,
    source: OutPoint,
    deps: &[CellDep],
) -> Result<Value> {
    use std::os::unix::fs::DirBuilderExt;
    let mut random = [0; 8];
    getrandom::fill(&mut random)
        .map_err(|_| anyhow!("cannot allocate private operation runtime"))?;
    let runtime_dir = std::env::temp_dir().canonicalize()?.join(format!(
        "morph-close-operations-{}-{}",
        std::process::id(),
        hex::encode(random)
    ));
    fs::DirBuilder::new().mode(0o700).create(&runtime_dir)?;
    let operation_store = runtime_dir.join("operations.db");
    let stored = StoredMultiAssetPackage::from_recovery(package, deps)?;
    let package_path = write_package(&options.store_dir, &stored)?;
    // Participant-to-payout ownership is explicit local configuration, not
    // inferred from arbitrary on-chain locks. This harness owns both keys.
    let participants = [&options.alice_private_key, &options.bob_private_key].map(
        |secret| -> Result<morph_core::ChannelParticipant> {
            let signer = k256_signing_key(secret)?;
            let lock = secp256k1_lock(&parse_privkey(secret)?)?;
            Ok(morph_core::ChannelParticipant {
                node_id: morph_core::blake2b256(&k256_pubkey(&signer)),
                settlement_lock_hash: lock.calc_script_hash().unpack(),
            })
        },
    );
    let [left, right] = participants;
    let asset = match package.manifest.vaults[0].asset {
        VaultAsset::Ckb => morph_core::GatewayAsset::Ckb {
            ckb_genesis_hash: package.state.header.chain_id,
        },
        VaultAsset::Xudt(type_script_hash) => morph_core::GatewayAsset::Xudt {
            ckb_genesis_hash: package.state.header.chain_id,
            type_script_hash,
        },
    };
    let candidate = super::shadow_observer::Candidate {
        schema: "morph.shadow_candidate.v1".into(),
        package: stored.clone(),
        state_out_point: format_out_point(&source),
        participants: [left?, right?],
        asset,
        reservation: None,
        origin: super::shadow_observer::Origin::Root {},
    };
    let candidate_path = options.store_dir.join("shadow-candidate.json");
    crate::persistence::write_private_immutable(&candidate_path, &serde_json::to_vec(&candidate)?)?;
    let observe = || {
        super::shadow_observer::run(
            rpc.endpoint(),
            &candidate_path,
            &options.contracts_dir,
            4,
            10_000,
        )
    };
    let shadow_before = observe()?;
    ensure!(
        shadow_before["forwarding"] == false,
        "shadow enabled forwarding"
    );
    let max_fee = options
        .fee
        .checked_mul(2)
        .ok_or_else(|| anyhow!("fee overflow"))?;
    let context = || Context {
        package: package_path.clone(),
        contracts_dir: options.contracts_dir.clone(),
        max_fee,
        min_confirmations: 4,
    };
    let fee_cell = find_largest_live_cell(rpc, owner_lock, rpc.tip_header()?.number_value()?)?;
    let key = k256_signing_key(&options.private_key)?;
    let pubkey = canonical_hex(&k256_pubkey(&key));
    let mut drafts = Vec::new();
    let mut hashes = Vec::new();
    let mut exports = Vec::new();
    for (version, fee) in [options.fee, max_fee].into_iter().enumerate() {
        let draft = options
            .store_dir
            .join(format!("close-draft-{version}.json"));
        let prepared = close::run(
            rpc,
            Command::Prepare {
                context: context(),
                state_out_point: format_out_point(&source),
                fee_out_point: format_out_point(&fee_cell.out_point),
                fee_pubkey: pubkey.clone(),
                fee,
                output: draft.clone(),
            },
        )?;
        let hash = crate::canonical_fields::hash(
            prepared["transaction_hash"]
                .as_str()
                .ok_or_else(|| anyhow!("missing close hash"))?,
        )?;
        for session in sessions {
            crate::multi_asset_session::run(
                session,
                SessionCommand::CooperativeClose {
                    operation: CloseCommand::Prepare {
                        draft: draft.clone(),
                    },
                },
            )?;
        }
        for (index, (session, secret)) in sessions
            .into_iter()
            .zip([&options.alice_private_key, &options.bob_private_key])
            .enumerate()
        {
            let receipt = crate::participant_signer::acceptance::sign_close(
                rpc,
                session,
                secret,
                package,
                options.signer_faults,
                &hash,
            )?;
            let path = options
                .store_dir
                .join(format!("close-receipt-{version}-{index}.json"));
            crate::persistence::write_private_immutable(&path, &serde_json::to_vec(&receipt)?)?;
            crate::multi_asset_session::run(
                sessions[1 - index],
                SessionCommand::CooperativeClose {
                    operation: CloseCommand::AddSignature {
                        transaction_hash: canonical_hex(&hash),
                        signature: path,
                    },
                },
            )?;
        }
        let export = options
            .store_dir
            .join(format!("close-authorized-{version}.tx"));
        crate::multi_asset_session::run(
            sessions[0],
            SessionCommand::CooperativeClose {
                operation: CloseCommand::Export {
                    transaction_hash: canonical_hex(&hash),
                    output: export.clone(),
                },
            },
        )?;
        ensure!(
            crate::multi_asset_session::run(
                sessions[0],
                SessionCommand::CooperativeClose {
                    operation: CloseCommand::Cancel
                }
            )
            .is_err(),
            "signed close was cancellable"
        );
        drafts.push(draft);
        hashes.push(hash);
        exports.push(export);
    }
    ensure!(
        hashes[0] != hashes[1],
        "fee replacement reused transaction identity"
    );
    // Re-export the older approval after replacement. It remains authority.
    let old = options.store_dir.join("close-older-approval.tx");
    crate::multi_asset_session::run(
        sessions[0],
        SessionCommand::CooperativeClose {
            operation: CloseCommand::Export {
                transaction_hash: canonical_hex(&hashes[0]),
                output: old.clone(),
            },
        },
    )?;
    ensure!(
        fs::read(old)? == fs::read(&exports[0])?,
        "replacement changed old authorization"
    );
    let submit_dir = options.store_dir.join("close-submitted");
    ensure!(
        close::run(
            rpc,
            Command::Submit {
                operation_store: operation_store.clone(),
                replaces_operation: None,
                context: context(),
                draft: drafts[1].clone(),
                transaction: exports[1].clone(),
                store_dir: submit_dir.clone(),
                mine_blocks: 0,
                dry_run: true
            }
        )
        .is_err(),
        "missing fee signature passed VM preflight"
    );
    ensure!(
        !submit_dir
            .join(format!("close-{}.tx", hex::encode(hashes[1])))
            .exists(),
        "failed preflight poisoned exact artifact path"
    );
    let signed = options.store_dir.join("close-wallet-signed.tx");
    ensure!(
        close::run(
            rpc,
            Command::WalletSign {
                context: context(),
                draft: drafts[1].clone(),
                transaction: exports[1].clone(),
                private_key: options.alice_private_key.clone(),
                output: signed.clone()
            }
        )
        .is_err(),
        "wrong fee owner signed"
    );
    ensure!(!signed.exists(), "wrong wallet persisted a transaction");
    let wallet = close::run(
        rpc,
        Command::WalletSign {
            context: context(),
            draft: drafts[1].clone(),
            transaction: exports[1].clone(),
            private_key: options.private_key.clone(),
            output: signed.clone(),
        },
    )?;
    let old_signed = options.store_dir.join("close-older-wallet-signed.tx");
    close::run(
        rpc,
        Command::WalletSign {
            context: context(),
            draft: drafts[0].clone(),
            transaction: exports[0].clone(),
            private_key: options.private_key.clone(),
            output: old_signed.clone(),
        },
    )?;
    let predecessor_preview = close::run(
        rpc,
        Command::Submit {
            context: context(),
            draft: drafts[0].clone(),
            transaction: old_signed.clone(),
            store_dir: submit_dir.clone(),
            operation_store: operation_store.clone(),
            replaces_operation: None,
            mine_blocks: 0,
            dry_run: true,
        },
    )?;
    let predecessor = predecessor_preview["operation"]["operation_id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing predecessor operation"))?
        .to_owned();
    let preview = close::run(
        rpc,
        Command::Submit {
            operation_store: operation_store.clone(),
            replaces_operation: Some(predecessor.clone()),
            context: context(),
            draft: drafts[1].clone(),
            transaction: signed.clone(),
            store_dir: submit_dir.clone(),
            mine_blocks: 0,
            dry_run: true,
        },
    )?;
    let before_close = rpc.tip_header()?;
    let journals_before = [fs::read(sessions[0])?, fs::read(sessions[1])?];
    let submitted = close::run(
        rpc,
        Command::Submit {
            operation_store: operation_store.clone(),
            replaces_operation: Some(predecessor.clone()),
            context: context(),
            draft: drafts[1].clone(),
            transaction: signed.clone(),
            store_dir: submit_dir.clone(),
            mine_blocks: options.mine_blocks + 4,
            dry_run: false,
        },
    )?;
    ensure!(
        submitted["canonical_confirmations"]
            .as_u64()
            .is_some_and(|depth| depth > 0),
        "close lacks canonical confirmation"
    );
    ensure!(
        submitted["status"]["state"] == "finalised"
            && submitted["canonical_confirmations"]
                .as_u64()
                .is_some_and(|depth| depth >= 4),
        "runtime finality requires configured depth"
    );
    ensure!(
        observe().is_err(),
        "closed source accepted by shadow observer"
    );
    let repeated = close::run(
        rpc,
        Command::Submit {
            operation_store: operation_store.clone(),
            replaces_operation: Some(predecessor.clone()),
            context: context(),
            draft: drafts[1].clone(),
            transaction: signed.clone(),
            store_dir: submit_dir.clone(),
            mine_blocks: 0,
            dry_run: false,
        },
    )?;
    ensure!(
        repeated["operation"]["operation_id"] == submitted["operation"]["operation_id"]
            && repeated["operation"]["broadcasts"] == submitted["operation"]["broadcasts"]
            && repeated["signed_transaction"] == submitted["signed_transaction"]
            && repeated["durable_package"] == submitted["durable_package"]
            && repeated["status"]["state"] == "finalised",
        "confirmed retry duplicated broadcast or lost operation identity"
    );
    let predecessor_lost = crate::operation_runtime::status(&operation_store, &predecessor, 4, 0)?;
    ensure!(
        predecessor_lost["operation"]["status"]["state"] == "replaced"
            && predecessor_lost["operation"]["status"]["by_operation_id"]
                == submitted["operation"]["operation_id"]
            && predecessor_lost["operation"]["canonical_confirmations"] == 0
            && predecessor_lost["operation"]["broadcasts"] == 0,
        "replacement registration was confused with canonical winner evidence"
    );
    for point in std::iter::once(source.clone()).chain(
        package
            .outpoints
            .iter()
            .map(|p| OutPoint::new(p.tx_hash.pack(), p.index)),
    ) {
        ensure!(
            rpc.live_cell(point.into(), false)?.status != "live",
            "closed custody remains live"
        );
    }
    let transaction = ckb_types::packed::Transaction::from_slice(&fs::read(&signed)?)?;
    for (index, expected) in transaction.raw().outputs().into_iter().enumerate() {
        let cell =
            load_canonical_live_cell(rpc, OutPoint::new(transaction.calc_tx_hash(), index as u32))?;
        ensure!(
            cell.output == expected
                && transaction
                    .raw()
                    .outputs_data()
                    .get(index)
                    .is_some_and(|d| d.raw_data() == cell.data),
            "canonical close payout differs from signed output"
        );
    }
    ensure!(
        crate::multi_asset_packages::read_package(&package_path)? == stored,
        "close changed saved unilateral recovery"
    );
    // An orphaned exact approval must remain usable without either participant.
    // Neither this controlled rollback nor replay may rewrite signer authority.
    rpc.truncate(parse_h256(&before_close.hash)?)?;
    ensure!(
        rpc.tip_header()?.hash == before_close.hash,
        "close rollback missed predecessor"
    );
    ensure!(
        rpc.transaction(transaction.calc_tx_hash().unpack())?
            .tx_status
            .status
            != Status::Committed,
        "close remained canonical after rollback"
    );
    ensure!(
        [fs::read(sessions[0])?, fs::read(sessions[1])?] == journals_before,
        "rollback changed close authority"
    );
    let shadow_after_rollback = observe()?;
    ensure!(
        shadow_after_rollback["edge"] == shadow_before["edge"],
        "rollback changed diagnostic edge"
    );
    // Controlled blocks can be mined faster than the real retry cadence. Honor
    // that cadence rather than disabling it for the acceptance path.
    std::thread::sleep(Duration::from_secs(1));
    let replay = close::run(
        rpc,
        Command::Submit {
            operation_store: operation_store.clone(),
            replaces_operation: Some(predecessor.clone()),
            context: context(),
            draft: drafts[1].clone(),
            transaction: signed.clone(),
            store_dir: submit_dir.clone(),
            mine_blocks: options.mine_blocks + 4,
            dry_run: false,
        },
    )?;
    ensure!(
        replay["transaction_hash"] == submitted["transaction_hash"]
            && replay["canonical_confirmations"]
                .as_u64()
                .is_some_and(|v| v > 0),
        "exact close replay changed or failed"
    );
    // A declared fee replacement cannot revoke the old approval. On this
    // branch the older exact body wins, and its descendant must recognize that.
    rpc.truncate(parse_h256(&before_close.hash)?)?;
    let predecessor_won = close::run(
        rpc,
        Command::Submit {
            context: context(),
            draft: drafts[0].clone(),
            transaction: old_signed.clone(),
            store_dir: submit_dir.clone(),
            operation_store: operation_store.clone(),
            replaces_operation: None,
            mine_blocks: options.mine_blocks + 4,
            dry_run: false,
        },
    )?;
    ensure!(
        predecessor_won["status"]["state"] == "finalised",
        "older approval was revoked"
    );
    let descendant_lost = crate::operation_runtime::status(
        &operation_store,
        submitted["operation"]["operation_id"]
            .as_str()
            .ok_or_else(|| anyhow!("missing operation"))?,
        4,
        0,
    )?;
    ensure!(
        descendant_lost["operation"]["status"]["state"] == "replaced"
            && descendant_lost["operation"]["status"]["by_operation_id"] == predecessor
            && descendant_lost["operation"]["canonical_confirmations"] == 0,
        "older canonical winner not reconciled"
    );
    // On a third rollback branch an ordinary publication wins source consumption.
    // Neither cached replacement winner may be reused as confirmation here.
    rpc.truncate(parse_h256(&before_close.hash)?)?;
    let fees = find_largest_live_cell(rpc, owner_lock, rpc.tip_header()?.number_value()?)?;
    let published = super::multi_asset_operator::transact(
        rpc,
        super::multi_asset_operator::Options {
            operation: super::multi_asset_operator::Operation::Publish,
            package: package_path.clone(),
            state_out_point: format_out_point(&source),
            fee_out_point: format_out_point(&fees.out_point),
            fee_authorization: super::multi_asset_operator::FeeAuthorization::Wallet {
                private_key: options.private_key.clone(),
            },
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            fee: options.fee,
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            publication_profile: None,
            attempt_log: None,
            dry_run: false,
        },
    )?;
    let lost_race = close::run(
        rpc,
        Command::Submit {
            operation_store: operation_store.clone(),
            replaces_operation: Some(predecessor.clone()),
            context: context(),
            draft: drafts[1].clone(),
            transaction: signed.clone(),
            store_dir: submit_dir.clone(),
            mine_blocks: 0,
            dry_run: true,
        },
    )?;
    ensure!(
        lost_race["status"]["state"] == "operator_action"
            && lost_race["canonical_confirmations"] == 0,
        "close ignored source consumption race"
    );
    let published_point = OutPoint::new(
        parse_h256(
            published["tx_hash"]
                .as_str()
                .ok_or_else(|| anyhow!("missing publication hash"))?,
        )?
        .pack(),
        0,
    );
    // Use the new, still-live Settling State: rejection must not rely only
    // on the old Active cell already being spent.
    let mut settling_candidate = candidate;
    settling_candidate.state_out_point = format_out_point(&published_point);
    let settling_path = options.store_dir.join("shadow-settling-candidate.json");
    crate::persistence::write_private_immutable(
        &settling_path,
        &serde_json::to_vec(&settling_candidate)?,
    )?;
    let settling_error = super::shadow_observer::run(
        rpc.endpoint(),
        &settling_path,
        &options.contracts_dir,
        1,
        10_000,
    )
    .err()
    .ok_or_else(|| anyhow!("settling channel accepted by shadow observer"))?;
    ensure!(
        settling_error.to_string().contains("settling or unbound"),
        "settling rejection did not reach phase guard: {settling_error}"
    );
    mine_relative_since_maturity(rpc, options.finalise_since)?;
    let fees = find_largest_live_cell(rpc, owner_lock, rpc.tip_header()?.number_value()?)?;
    let fallback = super::multi_asset_operator::transact(
        rpc,
        super::multi_asset_operator::Options {
            operation: super::multi_asset_operator::Operation::Finalise,
            package: package_path.clone(),
            state_out_point: format_out_point(&published_point),
            fee_out_point: format_out_point(&fees.out_point),
            fee_authorization: super::multi_asset_operator::FeeAuthorization::Wallet {
                private_key: options.private_key.clone(),
            },
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            fee: options.fee,
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            publication_profile: None,
            attempt_log: None,
            dry_run: false,
        },
    )?;
    for point in std::iter::once(published_point).chain(
        package
            .outpoints
            .iter()
            .map(|p| OutPoint::new(p.tx_hash.pack(), p.index)),
    ) {
        ensure!(
            rpc.live_cell(point.into(), false)?.status != "live",
            "fallback left custody live"
        );
    }
    ensure!(
        [fs::read(sessions[0])?, fs::read(sessions[1])?] == journals_before,
        "replay or fallback changed close authority"
    );
    Ok(
        json!({"wallet":wallet,"preview":preview,"submitted":submitted,"replacement_hashes":hashes.iter().map(|h|canonical_hex(h)).collect::<Vec<_>>(),"payout_count":transaction.raw().outputs().len(),"all_custody_consumed":true,"old_approval_exportable":true,"missing_fee_preflight_rejected":true,"wrong_fee_owner_rejected":true,"unilateral_package_retained":true,
        "reorg_replay":replay,"competing_publication":published,"fallback_finalise":fallback,"source_race_rejected":true,"journals_unchanged_after_reorg_and_fallback":true,"final_branch":"ordinary_unilateral_fallback_after_three_controlled_rollbacks","confirmed_retry_no_broadcast":true,"required_depth_enforced":true,"operation_store":operation_store,"lost_race_operation":lost_race,"predecessor_preview":predecessor_preview,"predecessor_lost":predecessor_lost,"predecessor_won":predecessor_won,"descendant_lost":descendant_lost,"replacement_winners_reconciled":true,"shadow_observer":{"before_close":shadow_before,"after_rollback":shadow_after_rollback,"spent_source_rejected":true,"live_settling_source_rejected":true}}),
    )
}
