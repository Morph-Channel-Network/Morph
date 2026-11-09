//! Stateless construction and receipt assembly. No signer reservation or private key is owned here.
use crate::{
    multi_asset_funding::{
        RootFundingCollection, RootFundingDraft, RootFundingExport, RootFundingTarget,
    },
    multi_asset_packages::{StoredMultiAssetPackage, canonical_hex, decode_hex},
    multi_asset_signatures::SignatureMessage,
    multi_asset_splice_transaction::{SpliceDraft, SpliceFundingExport},
    proposal::ProposalMessage,
};
use anyhow::{Result, ensure};
use morph_core::*;

pub fn create_proposal(
    base: &StoredMultiAssetPackage,
    number: &str,
    descriptor_hex: &str,
) -> Result<ProposalMessage> {
    let current = base.recovery()?;
    let number_value = number.parse::<u64>()?;
    ensure!(
        number_value.to_string() == number,
        "noncanonical state number"
    );
    let settlement = MultiAssetSettlement::decode(&decode_hex(descriptor_hex, 16 * 1024)?)?;
    let mut state = current.state.clone();
    state.header.state_number = number_value;
    state.header.settlement_descriptor_commitment = settlement.commitment()?;
    let proposal = MultiAssetProposal {
        base_state_digest: current.state.signing_digest()?,
        state,
        settlement,
    };
    let mut validator = MultiAssetChannelBackend::new(
        current.clone(),
        current.authorization.signatures[0].pubkey_sec1.clone(),
    )?;
    validator.accept_proposal(proposal.clone())?;
    ProposalMessage::from_proposal(&proposal)
}
pub fn inspect_funding_signature(
    draft: &RootFundingDraft,
    target: RootFundingTarget,
    receipt: &SignatureMessage,
) -> Result<serde_json::Value> {
    draft.inspection()?;
    receipt.verify(&target.digest(draft)?, &draft.participants)?;
    Ok(serde_json::json!({"signer_pubkey":receipt.pubkey,"signing_digest":receipt.signing_digest}))
}
pub fn assemble_root(
    draft: RootFundingDraft,
    exit: &[SignatureMessage],
    creation: &[SignatureMessage],
) -> Result<RootFundingExport> {
    ensure!(
        exit.len() == 2 && creation.len() == 2,
        "both participant receipts are required for each role"
    );
    let mut collection = RootFundingCollection::new(draft)?;
    for receipt in exit {
        ensure!(
            collection.add(RootFundingTarget::Exit, receipt.clone())?,
            "duplicate exit receipt"
        );
    }
    for receipt in creation {
        ensure!(
            collection.add(RootFundingTarget::Creation, receipt.clone())?,
            "duplicate creation receipt"
        );
    }
    collection.export()
}
fn pair(
    digest: &Bytes32,
    participants: &[String; 2],
    receipts: &[SignatureMessage],
) -> Result<StateAuthorization> {
    ensure!(
        receipts.len() == 2,
        "both participant receipts are required"
    );
    let mut signatures = receipts
        .iter()
        .map(|r| r.verify(digest, participants))
        .collect::<Result<Vec<_>>>()?;
    signatures.sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
    ensure!(
        signatures[0].pubkey_sec1 != signatures[1].pubkey_sec1,
        "duplicate participant receipt"
    );
    Ok(StateAuthorization {
        threshold: 2,
        signatures,
    })
}
#[derive(Debug, Clone, Copy)]
pub enum SpliceTarget {
    Creation,
    Recovery,
    Bridge,
}
pub fn splice_signature(
    base: &StoredMultiAssetPackage,
    draft: &SpliceDraft,
    target: SpliceTarget,
    receipt: &SignatureMessage,
) -> Result<serde_json::Value> {
    let current = base.recovery()?;
    let plan = draft.proposal(&current)?;
    let digest = match target {
        SpliceTarget::Creation => plan.new_state.signing_digest()?,
        SpliceTarget::Recovery => plan
            .initial_recovery_contents(&current)?
            .state
            .signing_digest()?,
        SpliceTarget::Bridge => plan.intent_digest(&current)?,
    };
    receipt.verify(&digest, &base.validate()?.signer_pubkeys)?;
    Ok(serde_json::json!({"signer_pubkey":receipt.pubkey,"signing_digest":receipt.signing_digest}))
}
pub fn assemble_splice(
    base: &StoredMultiAssetPackage,
    draft: &SpliceDraft,
    recovery: &[SignatureMessage],
    creation: &[SignatureMessage],
    bridge: &[SignatureMessage],
) -> Result<SpliceFundingExport> {
    let current = base.recovery()?;
    let mut plan = draft.proposal(&current)?;
    let keys = base.validate()?.signer_pubkeys;
    plan.initial_recovery_authorization = pair(
        &plan
            .initial_recovery_contents(&current)?
            .state
            .signing_digest()?,
        &keys,
        recovery,
    )?;
    plan.new_state_authorization = pair(&plan.new_state.signing_digest()?, &keys, creation)?;
    plan.validate(&current)?;
    let bridge = pair(&plan.signing_digest(&current)?, &keys, bridge)?;
    let transaction = draft.authorized_transaction(&current, &plan, &bridge)?;
    use ckb_types::prelude::*;
    let exit = plan.initial_recovery(&current)?;
    let export = SpliceFundingExport {
        schema: "morph.multi_asset_splice_funding.v1".into(),
        transaction_hex: canonical_hex(transaction.as_slice()),
        recovery_package: StoredMultiAssetPackage::from_recovery(
            &exit,
            &transaction
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>(),
        )?,
    };
    export.validated_draft(&current)?;
    Ok(export)
}

pub fn public_exit_terms(
    header: &str,
    witness: &str,
    carrier: &str,
    participants: &[String; 2],
) -> Result<crate::multi_asset_packages::MultiAssetPackageSummary> {
    let capacity = carrier.parse::<u64>()?;
    ensure!(
        capacity.to_string() == carrier,
        "noncanonical carrier capacity"
    );
    let recovery = MultiAssetRecoveryPackage::decode_contents(
        &decode_hex(header, 318)?,
        &decode_hex(witness, 128 * 1024)?,
        capacity,
    )?;
    let keys = participants
        .iter()
        .map(|p| crate::canonical_fields::public(p))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        keys[0] < keys[1],
        "participant public keys must be strictly sorted"
    );
    ensure!(
        participants_commitment(2, &[keys[0].as_slice(), keys[1].as_slice()])
            == recovery.state.header.participants_commitment,
        "participant identities do not match public exit"
    );
    crate::review::contents_summary(&recovery, 0, participants)
}
