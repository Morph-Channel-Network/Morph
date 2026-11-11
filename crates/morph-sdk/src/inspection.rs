//! Stateless public review: canonical codecs and Core own all validation.
use anyhow::{Result, ensure};
use morph_core::*;
use morph_packages::{
    conditional_packages, factory_packets, factory_transition_packages, multi_asset_funding,
    multi_asset_packages, multi_asset_signatures, multi_asset_splice_transaction, proposal,
};
use multi_asset_packages::{StoredMultiAssetPackage, canonical_hex};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T> {
    Ok(serde_json::from_value(value.clone())?)
}

pub fn inspect(document: &Value, base: Option<&Value>) -> Result<Value> {
    match document.get("schema").and_then(Value::as_str).unwrap_or("") {
        "morph.multi_asset_recovery_package.v1" => Ok(serde_json::to_value(
            decode::<StoredMultiAssetPackage>(document)?.validate()?,
        )?),
        "morph.conditional_batch_package.v2" => Ok(serde_json::to_value(
            decode::<conditional_packages::StoredConditionalBatchPackage>(document)?.validate()?,
        )?),
        "morph.multi_asset_root_draft.v1" => Ok(serde_json::to_value(
            decode::<multi_asset_funding::RootFundingDraft>(document)?.inspection()?,
        )?),
        "morph.multi_asset_root_collection.v1" => Ok(serde_json::to_value(
            decode::<multi_asset_funding::RootFundingCollection>(document)?.summary()?,
        )?),
        "morph.multi_asset_root_funding.v1" => Ok(serde_json::to_value(
            decode::<multi_asset_funding::RootFundingExport>(document)?.inspection()?,
        )?),
        "morph.multi_asset_proposal.v1" => {
            let base: StoredMultiAssetPackage = decode(base.ok_or_else(|| {
                anyhow::anyhow!("proposal review requires signed base recovery")
            })?)?;
            let current = base.recovery()?;
            let message: proposal::ProposalMessage = decode(document)?;
            let proposal = message.proposal(&current)?;
            // An ephemeral validator checks exact base and monotonic progress; no reservation/signing occurs.
            let mut validator = MultiAssetChannelBackend::new(
                current.clone(),
                current.authorization.signatures[0].pubkey_sec1.clone(),
            )?;
            validator.accept_proposal(proposal.clone())?;
            let mut next = current;
            next.state = proposal.state;
            next.settlement = proposal.settlement;
            Ok(morph_packages::review::contents_review(
                &next,
                base.cell_deps.len(),
                &base.validate()?.signer_pubkeys,
            )?)
        }
        "morph.multi_asset_splice_draft.v1" | "morph.multi_asset_splice_funding.v1" => {
            let base: StoredMultiAssetPackage =
                decode(base.ok_or_else(|| {
                    anyhow::anyhow!("splice review requires signed base recovery")
                })?)?;
            let current = base.recovery()?;
            let draft = if document["schema"] == "morph.multi_asset_splice_draft.v1" {
                decode::<multi_asset_splice_transaction::SpliceDraft>(document)?
            } else {
                let export: multi_asset_splice_transaction::SpliceFundingExport = decode(document)?;
                export.validated_draft(&current)?.0
            };
            let plan = draft.proposal(&current)?;
            plan.validate_contents(&current)?;
            let exit = plan.initial_recovery_contents(&current)?;
            let review = morph_packages::review::contents_review(
                &exit,
                base.cell_deps.len(),
                &base.validate()?.signer_pubkeys,
            )?;
            Ok(
                json!({"transaction_hash":canonical_hex(&plan.transaction_hash),"channel_id":canonical_hex(&current.state.header.channel_id),"old_funding_context_id":canonical_hex(&current.state.funding_context_id()?),"new_funding_context_id":canonical_hex(&exit.state.funding_context_id()?),"funding_epoch":plan.new_state.header.funding_epoch.to_string(),"old_state_outpoint":{"tx_hash":canonical_hex(&plan.old_state_outpoint.tx_hash),"index":plan.old_state_outpoint.index},"creation_digest":canonical_hex(&plan.new_state.signing_digest()?),"recovery_digest":canonical_hex(&exit.state.signing_digest()?),"bridge_digest":canonical_hex(&plan.intent_digest(&current)?),"withdrawal_lock_hex":canonical_hex(&plan.withdrawal_lock),"vault_outpoints":exit.outpoints.iter().map(|p|json!({"tx_hash":canonical_hex(&p.tx_hash),"index":p.index})).collect::<Vec<_>>(),"assets":review["summary"]["assets"],"capability":review["capability"],"payouts":review["payouts"],"flows":plan.flows.iter().map(|f|json!({"type_hash":morph_packages::summaries::asset_summary(&f.asset),"deposit":morph_packages::summaries::value_summary(f.deposit),"withdrawal":morph_packages::summaries::value_summary(f.withdrawal)})).collect::<Vec<_>>()}),
            )
        }
        "morph.factory_request.v1" => {
            let request: factory_packets::StoredFactoryRequest = decode(document)?;
            let mut review = request.inspect()?;
            let core = request.decode_for_delivery_review()?;
            let mut children = vec![];
            for index in 0..core.child_count()? {
                let exit = core.expected_child_recovery(index as u16)?;
                children.push(json!({"child_index":index,"state_output_index":core.public_child(index)?.state_output_index,"initial_exit":morph_packages::review::contents_summary(&exit,0,&[canonical_hex(&exit.authorization.signatures[0].pubkey_sec1),canonical_hex(&exit.authorization.signatures[1].pubkey_sec1)])?}));
            }
            review["children"] = json!(children);
            review["validation_scope"] = json!("canonical_core_public_review");
            Ok(review)
        }
        "morph.factory_transition_package.v1" => {
            let package: factory_transition_packages::StoredFactoryTransitionPackage =
                decode(document)?;
            let view = package.validate()?;
            let frame = view.witness()?;
            let members = (0..frame.member_count())
                .map(|i| {
                    let (p, k) = frame.member(i).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    Ok(json!({"participant":canonical_hex(p),"pubkey":canonical_hex(k)}))
                })
                .collect::<Result<Vec<_>>>()?;
            let required = (0..frame.signature_count())
                .map(|i| {
                    let (p, k) = frame
                        .authorized_member(i)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    Ok(json!({"participant":canonical_hex(p),"pubkey":canonical_hex(k)}))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(
                json!({"operation":format!("{:?}",frame.operation()),"transaction_hash":canonical_hex(frame.transaction_hash()),"signing_digest":canonical_hex(&frame.signing_digest()),"members":members,"required_members":required,"validation_scope":"signed_frame_and_exact_body"}),
            )
        }
        _ => anyhow::bail!("unsupported public document schema"),
    }
}
pub fn inspect_signature(document: &Value, base: Option<&Value>, receipt: &Value) -> Result<Value> {
    let review = inspect(document, base)?;
    if document["schema"] == "morph.factory_request.v1" {
        let request: factory_packets::StoredFactoryRequest = decode(document)?;
        let signature: factory_packets::FactorySignatureReceipt = decode(receipt)?;
        signature.verify(&request.decode()?)?;
        return Ok(
            json!({"participant":signature.participant,"pubkey":signature.pubkey,"request_id":signature.request_id,"signing_digest":signature.signing_digest}),
        );
    }
    ensure!(
        document["schema"] == "morph.multi_asset_proposal.v1",
        "a signature role must be explicit for this document"
    );
    let message: multi_asset_signatures::SignatureMessage = decode(receipt)?;
    let digest = multi_asset_packages::decode_hex(
        document["signing_digest"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing digest"))?,
        32,
    )?;
    let digest: Bytes32 = digest
        .try_into()
        .map_err(|_| anyhow::anyhow!("digest length"))?;
    let signers: [String; 2] = serde_json::from_value(review["summary"]["signer_pubkeys"].clone())?;
    message.verify(&digest, &signers)?;
    Ok(json!({"signer_pubkey":message.pubkey,"signing_digest":message.signing_digest}))
}
