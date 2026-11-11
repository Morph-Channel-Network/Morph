use super::*;
use morph_packages::{
    multi_asset_close::CloseDraft,
    signer_protocol::{Payload, Target},
};

#[derive(Debug, Subcommand)]
pub enum CloseCommand {
    Prepare {
        #[arg(long)]
        draft: PathBuf,
    },
    Sign {
        #[arg(long)]
        transaction_hash: String,
        #[arg(long)]
        signer_config: PathBuf,
    },
    AddSignature {
        #[arg(long)]
        transaction_hash: String,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Export complete participant authorization; wallet fee witnesses are still required.
    Export {
        #[arg(long)]
        transaction_hash: String,
        #[arg(long)]
        output: PathBuf,
    },
    Cancel,
}

pub(super) fn check_receipt_budget(session: &StoredSession) -> Result<()> {
    if session.backend.close_attempts().is_empty() {
        return Ok(());
    }
    // A representational upper bound, never signing authority: fill every slot
    // with maximum-width JSON bytes, including receipts not yet received.
    let mut value = serde_json::to_value(session)?;
    let placeholders = session
        .backend
        .current()
        .authorization
        .signatures
        .iter()
        .map(|sig| json!({"pubkey_sec1":sig.pubkey_sec1,"signature":vec![255u8;64]}))
        .collect::<Vec<_>>();
    for attempt in value["backend"]["close"]
        .as_array_mut()
        .ok_or_else(|| anyhow!("missing close history"))?
    {
        attempt["signatures"] = json!(placeholders);
        attempt["signature_reserved"] = false.into();
    }
    ensure!(
        serde_json::to_vec(&value)?.len() as u64 <= MAX_SESSION_BYTES,
        "session cannot retain close receipts within byte budget; existing approvals and recovery remain intact"
    );
    Ok(())
}
fn attempt(session: &StoredSession, hash: &Bytes32) -> Result<MultiAssetCloseProposal> {
    for attempt in session.backend.close_attempts() {
        if attempt.proposal.transaction_hash()? == *hash {
            return Ok(attempt.proposal.clone());
        }
    }
    Err(anyhow!("unknown exact close transaction"))
}
fn payload(session: &StoredSession, proposal: &MultiAssetCloseProposal) -> Result<Payload> {
    Ok(Payload::CooperativeClose {
        current: Box::new(session.package()?),
        draft: CloseDraft::from_proposal(proposal)?,
    })
}
fn verify_with_rpc(
    session: &StoredSession,
    proposal: &MultiAssetCloseProposal,
    rpc: &crate::rpc::CkbRpcClient,
) -> Result<()> {
    let lineage = session
        .lineage
        .as_ref()
        .ok_or_else(|| anyhow!("close requires canonical lineage"))?;
    ensure!(
        crate::multi_asset_session_chain::rpc_endpoint(&lineage.rpc_url)?
            == crate::multi_asset_session_chain::rpc_endpoint(rpc.endpoint())?,
        "close RPC differs from installed lineage"
    );
    #[cfg(feature = "devnet")]
    {
        crate::devnet::multi_asset_splice_operator::verify_context_guard(
            rpc,
            &lineage.evidence,
            lineage.min_confirmations,
            &session.package()?,
            &lineage.contracts_dir,
        )?;
        crate::devnet::multi_asset_operator::validate_close_proposal(
            rpc,
            session.backend.current(),
            proposal,
            &lineage.contracts_dir,
            lineage.min_confirmations,
        )
    }
    #[cfg(not(feature = "devnet"))]
    {
        let _ = proposal;
        anyhow::bail!("close signing requires RPC-enabled devnet feature")
    }
}
fn verify(session: &StoredSession, proposal: &MultiAssetCloseProposal) -> Result<()> {
    let lineage = session
        .lineage
        .as_ref()
        .ok_or_else(|| anyhow!("close requires canonical lineage"))?;
    let rpc =
        crate::rpc::CkbRpcClient::new_signer(&lineage.rpc_url, std::time::Duration::from_secs(5))?;
    verify_with_rpc(session, proposal, &rpc)
}
pub(crate) fn external_authority(
    bytes: &[u8],
    hash: &Bytes32,
    rpc: &crate::rpc::CkbRpcClient,
) -> Result<(Payload, String)> {
    let session: StoredSession = serde_json::from_slice(bytes)?;
    session.package()?;
    check_receipt_budget(&session)?;
    let proposal = attempt(&session, hash)?;
    ensure!(
        session.backend.close_signature_reserved(hash)?,
        "close requires durable exact-body reservation"
    );
    verify_with_rpc(&session, &proposal, rpc)?;
    Ok((
        payload(&session, &proposal)?,
        canonical_hex(session.backend.local_pubkey()),
    ))
}
pub(super) fn run(path: &Path, mut session: StoredSession, command: CloseCommand) -> Result<Value> {
    match command {
        CloseCommand::Prepare { draft } => {
            let draft: CloseDraft = serde_json::from_slice(&read_limited(&draft)?)?;
            let proposal = draft.proposal(session.backend.current())?;
            verify(&session, &proposal)?;
            let hash = proposal.transaction_hash()?;
            let signing_digest = session.backend.prepare_close(proposal)?;
            save(path, &session)?;
            Ok(
                json!({"transaction_hash":canonical_hex(&hash),"signing_digest":canonical_hex(&signing_digest)}),
            )
        }
        CloseCommand::Sign {
            transaction_hash,
            signer_config,
        } => {
            let hash = digest(&transaction_hash)?;
            let proposal = attempt(&session, &hash)?;
            let signer = crate::participant_signer::Prepared::external(
                &signer_config,
                path,
                session.backend.local_pubkey(),
            )?;
            let signing_digest = proposal.signing_digest(session.backend.current())?;
            if let Some(sig) = session
                .backend
                .close_attempts()
                .iter()
                .find(|a| a.proposal == proposal)
                .and_then(|a| {
                    a.signatures
                        .iter()
                        .find(|s| s.pubkey_sec1 == session.backend.local_pubkey())
                })
            {
                return Ok(serde_json::to_value(SignatureMessage::new(
                    &signing_digest,
                    sig,
                ))?);
            }
            verify(&session, &proposal)?;
            ensure!(
                session.backend.reserve_close_signature(&hash)? == signing_digest,
                "close reservation digest changed"
            );
            save(path, &session)?;
            #[cfg(all(test, target_os = "linux"))]
            crate::participant_signer::tests::checkpoint("reserved");
            verify(&session, &proposal)?;
            let receipt = signer.sign(Target::CooperativeClose, &signing_digest, || {
                payload(&session, &proposal)
            })?;
            #[cfg(all(test, target_os = "linux"))]
            crate::participant_signer::tests::checkpoint("received");
            session
                .backend
                .record_close_signature(&hash, receipt.clone())?;
            save(path, &session)?;
            #[cfg(all(test, target_os = "linux"))]
            crate::participant_signer::tests::checkpoint("recorded");
            Ok(serde_json::to_value(SignatureMessage::new(
                &signing_digest,
                &receipt,
            ))?)
        }
        CloseCommand::AddSignature {
            transaction_hash,
            signature,
        } => {
            let hash = digest(&transaction_hash)?;
            let proposal = attempt(&session, &hash)?;
            let receipt: SignatureMessage = serde_json::from_slice(&read_limited(&signature)?)?;
            ensure!(
                receipt.schema == SIGNATURE_SCHEMA
                    && digest(&receipt.signing_digest)?
                        == proposal.signing_digest(session.backend.current())?,
                "close receipt has another role or body"
            );
            session.backend.record_close_signature(
                &hash,
                ParticipantSignature {
                    pubkey_sec1: decode_hex(&receipt.pubkey, 33)?,
                    signature: decode_hex(&receipt.signature, 64)?,
                },
            )?;
            save(path, &session)?;
            session.summary()
        }
        CloseCommand::Export {
            transaction_hash,
            output,
        } => {
            let hash = digest(&transaction_hash)?;
            let proposal = attempt(&session, &hash)?;
            let witness = packed::WitnessArgs::new_builder()
                .output_type(
                    Some(ckb_types::bytes::Bytes::from(
                        session.backend.close_witness(&hash)?,
                    ))
                    .pack(),
                )
                .build();
            let transaction = packed::Transaction::new_builder()
                .raw(proposal.raw_transaction()?)
                .witnesses(vec![witness.as_bytes().pack()].pack())
                .build();
            crate::persistence::write_private_immutable(&output, transaction.as_slice())?;
            Ok(
                json!({"transaction_hash":canonical_hex(&hash),"participant_authorized_transaction":output,"fee_witnesses_attached":false}),
            )
        }
        CloseCommand::Cancel => {
            session.backend.cancel_close()?;
            save(path, &session)?;
            session.summary()
        }
    }
}
