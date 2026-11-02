//! Durable state negotiation. The stable sidecar lock survives atomic snapshot
//! replacement; OS locks release on process death. No private key is persisted.
use crate::packages::{lock_private_path, required_option};
#[cfg(test)]
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::multi_asset_session_chain::{SessionLineage, SessionOrigin};
use crate::multi_asset_splice_transaction::SpliceDraft;
use anyhow::{Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use clap::{Subcommand, ValueEnum};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::*;
use morph_script_common::multi_asset as wire;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::multi_asset_packages::{
    self as packages, StoredMultiAssetCellDep, StoredMultiAssetPackage, canonical_hex, decode_hex,
};

const SESSION_SCHEMA: &str = "morph.multi_asset_session.v1";
const PROPOSAL_SCHEMA: &str = "morph.multi_asset_proposal.v1";
pub(crate) const SIGNATURE_SCHEMA: &str = "morph.multi_asset_signature.v1";
const RETIRED_SCHEMA: &str = "morph.multi_asset_retired_session.v1";
const MAX_SESSION_BYTES: u64 = 512 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = wire::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
    + wire::MULTI_ASSET_MAX_VAULTS * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN;

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Review the current state, pending proposal, and signing reservation.
    Inspect,
    /// Propose a canonical settlement descriptor; no key is invoked.
    Propose {
        #[arg(long)]
        descriptor_hex: String,
    },
    /// Review and adopt a peer's proposal against the current signed state.
    Accept {
        #[arg(long)]
        proposal: PathBuf,
    },
    /// Persist the reservation before signing, and persist the signature before returning it.
    Sign {
        #[arg(long, value_enum)]
        target: SigningTarget,
        #[arg(long, env = "MORPH_CHANNEL_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
    },
    /// Import one peer signature; its signer and exact proposal digest are verified.
    AddSignature {
        #[arg(long, value_enum)]
        target: SigningTarget,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Commit both signatures and durably export a directly publishable package.
    Commit {
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Recover a completed peer update without resetting the local signing reservation.
    Recover {
        #[arg(long)]
        package: PathBuf,
    },
    /// Persist an exact raw transaction and unsigned new-context evidence.
    PrepareSplice {
        #[arg(long)]
        draft: PathBuf,
    },
    /// Cancel only before a local old-context bridge signature is reserved.
    CancelSplice,
    /// Save the complete future recovery package before exporting the signed splice.
    ExportSplice {
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Export the complete signed epoch-0 funding body and current unilateral exit.
    ExportRootFunding {
        #[arg(long)]
        store_dir: PathBuf,
    },
    /// Retire the frozen journal and switch only after canonical splice/State confirmation.
    #[cfg(feature = "devnet")]
    ConfirmSplice {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        min_confirmations: u64,
        #[arg(long)]
        archive_dir: PathBuf,
        #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
        contracts_dir: PathBuf,
    },
    /// Reconcile the same funding context after a reorg without resetting votes.
    #[cfg(feature = "devnet")]
    RefreshChain {
        #[arg(long)]
        state_out_point: String,
        #[arg(long)]
        package: PathBuf,
    },
    /// Discard the proposal while retaining the signing reservation.
    Cancel,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SigningTarget {
    Update,
    SpliceCreation,
    SpliceRecovery,
    SpliceBridge,
}
impl SigningTarget {
    fn funding_kind(self) -> Option<MultiAssetSpliceFundingKind> {
        match self {
            Self::SpliceCreation => Some(MultiAssetSpliceFundingKind::Creation),
            Self::SpliceRecovery => Some(MultiAssetSpliceFundingKind::InitialRecovery),
            _ => None,
        }
    }
    fn digest(self, backend: &MultiAssetChannelBackend) -> Result<Bytes32> {
        if let Some(kind) = self.funding_kind() {
            return Ok(backend.splice_funding_signing_digest(kind)?);
        }
        Ok(match self {
            Self::Update => backend
                .proposal()
                .ok_or_else(|| anyhow!("no pending update"))?
                .signing_digest()?,
            Self::SpliceBridge => backend
                .splice_proposal()
                .ok_or_else(|| anyhow!("no pending splice"))?
                .signing_digest(backend.current())?,
            _ => return Err(anyhow!("invalid signing target")),
        })
    }
    fn signatures(self, backend: &MultiAssetChannelBackend) -> &[ParticipantSignature] {
        match self {
            Self::Update => backend.signatures(),
            Self::SpliceBridge => backend.splice_signatures(),
            Self::SpliceCreation => backend.splice_proposal().map_or(&[], |plan| {
                plan.new_state_authorization.signatures.as_slice()
            }),
            Self::SpliceRecovery => backend.splice_proposal().map_or(&[], |plan| {
                plan.initial_recovery_authorization.signatures.as_slice()
            }),
        }
    }
    fn reserve(self, backend: &mut MultiAssetChannelBackend) -> Result<Bytes32> {
        if let Some(kind) = self.funding_kind() {
            return Ok(backend.reserve_splice_funding_signature(kind)?);
        }
        Ok(match self {
            Self::Update => backend.reserve_signature()?.signing_digest,
            Self::SpliceBridge => backend.reserve_splice_signature()?,
            _ => return Err(anyhow!("invalid signing target")),
        })
    }
    fn record(
        self,
        backend: &mut MultiAssetChannelBackend,
        signature: ParticipantSignature,
    ) -> Result<()> {
        if let Some(kind) = self.funding_kind() {
            backend.record_splice_funding_signature(kind, signature)?;
        } else {
            match self {
                Self::Update => backend.record_signature(signature)?,
                Self::SpliceBridge => backend.record_splice_signature(signature)?,
                _ => return Err(anyhow!("invalid signing target")),
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSession {
    schema: String,
    backend: MultiAssetChannelBackend,
    cell_deps: Vec<StoredMultiAssetCellDep>,
    #[serde(deserialize_with = "required_option")]
    splice_draft: Option<SpliceDraft>,
    #[serde(deserialize_with = "required_option")]
    lineage: Option<SessionLineage>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiredSession {
    schema: String,
    session: StoredSession,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalMessage {
    schema: String,
    base_state_digest: String,
    state_number: String,
    descriptor_hex: String,
    signing_digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignatureMessage {
    pub(crate) schema: String,
    pub(crate) signing_digest: String,
    pub(crate) pubkey: String,
    pub(crate) signature: String,
}

pub(crate) fn channel_signing_key(private_key: &str, expected: &[u8]) -> Result<SigningKey> {
    let raw = hex::decode(private_key.strip_prefix("0x").unwrap_or(private_key))
        .map_err(|_| anyhow!("invalid channel signing key"))?;
    let key = SigningKey::from_slice(&raw).map_err(|_| anyhow!("invalid channel signing key"))?;
    ensure!(
        key.verifying_key().to_encoded_point(true).as_bytes() == expected,
        "key does not match session's local signer"
    );
    Ok(key)
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_SESSION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_SESSION_BYTES,
        "session/message exceeds byte limit"
    );
    Ok(bytes)
}

fn digest(value: &str) -> Result<Bytes32> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("digest must be 32 bytes"))
}

impl ProposalMessage {
    fn from_proposal(proposal: &MultiAssetProposal) -> Result<Self> {
        Ok(Self {
            schema: PROPOSAL_SCHEMA.to_string(),
            base_state_digest: canonical_hex(&proposal.base_state_digest),
            state_number: proposal.state.header.state_number.to_string(),
            descriptor_hex: canonical_hex(&proposal.settlement.encode()?),
            signing_digest: canonical_hex(&proposal.signing_digest()?),
        })
    }
    fn proposal(&self, backend: &MultiAssetChannelBackend) -> Result<MultiAssetProposal> {
        ensure!(
            self.schema == PROPOSAL_SCHEMA,
            "unsupported proposal schema"
        );
        let number = self.state_number.parse::<u64>()?;
        ensure!(
            number.to_string() == self.state_number,
            "state number must be canonical decimal"
        );
        let descriptor = decode_hex(&self.descriptor_hex, MAX_DESCRIPTOR_BYTES)?;
        let settlement = MultiAssetSettlement::decode(&descriptor)?;
        let mut state = backend.current().state.clone();
        state.header.state_number = number;
        state.header.settlement_descriptor_commitment = settlement.commitment()?;
        let proposal = MultiAssetProposal {
            base_state_digest: digest(&self.base_state_digest)?,
            state,
            settlement,
        };
        ensure!(
            proposal.signing_digest()? == digest(&self.signing_digest)?,
            "proposal digest does not match contents"
        );
        Ok(proposal)
    }
}

fn asset_summary(asset: &VaultAsset) -> Option<String> {
    match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(hash) => Some(canonical_hex(hash)),
    }
}
fn value_summary(value: MultiAssetValue) -> Value {
    json!({"reserve":value.reserve.to_string(), "business_ckb":value.business_ckb.to_string(), "amount":value.amount.to_string()})
}
pub(crate) fn payout_summary(settlement: &MultiAssetSettlement) -> Vec<Value> {
    settlement.payouts.iter().map(|payout| json!({"type_hash":asset_summary(&payout.asset), "allocations":payout.values.map(value_summary)})).collect()
}

impl StoredSession {
    fn package(&self) -> Result<StoredMultiAssetPackage> {
        ensure!(
            self.schema == SESSION_SCHEMA,
            "unsupported signing session schema"
        );
        self.backend.validate()?;
        self.validate_lineage_binding()?;
        match (&self.splice_draft, self.backend.splice_proposal()) {
            (Some(draft), Some(plan)) => draft.validate_plan(self.backend.current(), plan)?,
            (None, None) => {}
            _ => {
                return Err(anyhow!(
                    "splice snapshot must retain its exact transaction draft"
                ));
            }
        }
        StoredMultiAssetPackage::with_dependency_records(
            self.backend.current(),
            self.cell_deps.clone(),
        )
    }
    fn validate_guard_shape(&self) -> Result<()> {
        let Some(lineage) = &self.lineage else {
            ensure!(
                self.backend.current().state.header.funding_epoch == 0,
                "post-splice signer requires explicit lineage evidence"
            );
            return Ok(());
        };
        ensure!(
            lineage.min_confirmations > 0 && lineage.contracts_dir.is_absolute(),
            "invalid signer chain guard"
        );
        crate::multi_asset_session_chain::rpc_endpoint(&lineage.rpc_url)?;
        for included in [&lineage.evidence.funding, &lineage.evidence.state] {
            digest(&included.transaction_hash)?;
            digest(&included.block_hash)?;
        }
        let (state_hash, index) = lineage
            .evidence
            .state_out_point
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid lineage State OutPoint"))?;
        ensure!(
            state_hash == lineage.evidence.state.transaction_hash
                && index.parse::<u32>()?.to_string() == index,
            "lineage State OutPoint differs from canonical evidence"
        );
        Ok(())
    }
    fn retired(&self) -> Result<Option<StoredSession>> {
        let Some(lineage) = &self.lineage else {
            return Ok(None);
        };
        let SessionOrigin::Splice {
            retired_journal,
            retired_journal_hash,
        } = &lineage.origin
        else {
            return Ok(None);
        };
        ensure!(
            retired_journal.is_absolute(),
            "retired journal path must be absolute"
        );
        let bytes = read_limited(retired_journal)?;
        ensure!(
            canonical_hex(&blake2b256(&bytes)) == *retired_journal_hash,
            "retired journal content hash mismatch"
        );
        let archive: RetiredSession = serde_json::from_slice(&bytes)?;
        ensure!(
            archive.schema == RETIRED_SCHEMA,
            "unsupported retired evidence schema"
        );
        let retired = archive.session;
        ensure!(
            retired.schema == SESSION_SCHEMA,
            "unsupported retired journal schema"
        );
        retired.backend.validate()?;
        ensure!(
            retired.backend.splice_signature_reserved(),
            "retired journal is not sealed"
        );
        retired.backend.splice_authorization()?;
        let plan = retired
            .backend
            .splice_proposal()
            .ok_or_else(|| anyhow!("retired splice intent missing"))?;
        retired
            .splice_draft
            .as_ref()
            .ok_or_else(|| anyhow!("retired exact body missing"))?
            .validate_plan(retired.backend.current(), plan)?;
        Ok(Some(retired))
    }
    fn validate_lineage_binding(&self) -> Result<()> {
        self.validate_guard_shape()?;
        if let Some(lineage) = &self.lineage
            && let SessionOrigin::Root {
                funding_transaction_hex,
            } = &lineage.origin
        {
            let transaction = packed::Transaction::from_slice(&decode_hex(
                funding_transaction_hex,
                crate::multi_asset_funding::MAX_FUNDING_BYTES,
            )?)?;
            crate::multi_asset_funding::validate_root_funding(
                self.backend.current(),
                &transaction,
            )?;
            ensure!(
                lineage.evidence.funding.transaction_hash
                    == canonical_hex(transaction.calc_tx_hash().as_slice()),
                "root checkpoint differs from exact funding body"
            );
            self.validate_funding_dependencies(&transaction)?;
        }
        if let Some(retired) = self.retired()? {
            let lineage = self
                .lineage
                .as_ref()
                .ok_or_else(|| anyhow!("lineage missing"))?;
            let plan = retired
                .backend
                .splice_proposal()
                .ok_or_else(|| anyhow!("retired splice intent missing"))?;
            let recovery = plan.initial_recovery(retired.backend.current())?;
            ensure!(
                recovery.state.funding_context_id()?
                    == self.backend.current().state.funding_context_id()?
                    && retired.backend.local_pubkey() == self.backend.local_pubkey()
                    && lineage.evidence.funding.transaction_hash
                        == canonical_hex(&plan.transaction_hash),
                "signer does not extend the retired funding context"
            );
            let transaction = retired
                .splice_draft
                .as_ref()
                .ok_or_else(|| anyhow!("retired exact body missing"))?
                .transaction()?;
            self.validate_funding_dependencies(&transaction)?;
        }
        Ok(())
    }
    fn validate_funding_dependencies(&self, transaction: &packed::Transaction) -> Result<()> {
        let expected = StoredMultiAssetPackage::from_recovery(
            self.backend.current(),
            &transaction
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>(),
        )?;
        ensure!(
            expected.cell_deps == self.cell_deps,
            "signer dependencies differ from exact funding body"
        );
        Ok(())
    }
    fn verify_chain(&self) -> Result<()> {
        let lineage = self.lineage.as_ref().ok_or_else(|| {
            anyhow!("operational signer requires confirmed initial funding lineage")
        })?;
        #[cfg(feature = "devnet")]
        {
            let rpc = crate::rpc::CkbRpcClient::new(&lineage.rpc_url)?;
            crate::devnet::multi_asset_splice_operator::verify_context_guard(
                &rpc,
                &lineage.evidence,
                lineage.min_confirmations,
                &self.package()?,
                &lineage.contracts_dir,
            )
        }
        #[cfg(not(feature = "devnet"))]
        {
            let _ = lineage;
            Err(anyhow!(
                "this signer requires the RPC-enabled devnet feature for canonical verification"
            ))
        }
    }
    fn signed_splice(&self) -> Result<packed::Transaction> {
        let authorization = self.backend.splice_authorization()?;
        let plan = self
            .backend
            .splice_proposal()
            .ok_or_else(|| anyhow!("no pending splice"))?;
        let draft = self
            .splice_draft
            .as_ref()
            .ok_or_else(|| anyhow!("missing splice body"))?;
        draft.validate_plan(self.backend.current(), plan)?;
        let transaction = draft.transaction()?;
        let witness = packed::WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&plan.new_state_authorization)?.to_vec(),
                ))
                .pack(),
            )
            .output_type(
                Some(Bytes::from(
                    plan.encode_witness(self.backend.current(), &authorization)?,
                ))
                .pack(),
            )
            .build();
        let mut witnesses = transaction.witnesses().into_iter().collect::<Vec<_>>();
        if witnesses.is_empty() {
            witnesses.push(Bytes::new().pack());
        }
        witnesses[0] = witness.as_bytes().pack();
        Ok(transaction.as_builder().witnesses(witnesses.pack()).build())
    }
    fn summary(&self) -> Result<Value> {
        let payouts = self
            .backend
            .proposal()
            .map(|proposal| payout_summary(&proposal.settlement));
        let splice = self.backend.splice_proposal().map(|plan| -> Result<Value> {
            Ok(json!({"signing_digest": canonical_hex(&self.backend.splice_intent_digest()?),
                "transaction_hash":canonical_hex(&plan.transaction_hash),
                "old_state_outpoint":{"tx_hash":canonical_hex(&plan.old_state_outpoint.tx_hash),"index":plan.old_state_outpoint.index},
                "new_funding_anchor":canonical_hex(&plan.new_state.header.funding_anchor),
                "new_funding_epoch":plan.new_state.header.funding_epoch.to_string(),
                "new_payouts":payout_summary(&plan.new_settlement),
                "funding_flows":plan.flows.iter().map(|flow| json!({"type_hash":asset_summary(&flow.asset), "deposit":value_summary(flow.deposit), "withdrawal":value_summary(flow.withdrawal)})).collect::<Vec<_>>(),
                "initial_recovery_digest":canonical_hex(&self.backend.splice_funding_signing_digest(MultiAssetSpliceFundingKind::InitialRecovery)?),
                "creation_signature_count":plan.new_state_authorization.signatures.len(),
                "initial_recovery_signature_count":plan.initial_recovery_authorization.signatures.len(),
                "signature_reserved":self.backend.splice_signature_reserved(),
                "signature_count":self.backend.splice_signatures().len()}))
        }).transpose()?;
        Ok(
            json!({"current": self.package()?.validate()?, "local_pubkey":canonical_hex(self.backend.local_pubkey()),
            "reserved_state_number":self.backend.reservation().state_number.to_string(),
            "reserved_signing_digest":canonical_hex(&self.backend.reservation().signing_digest),
            "proposal":self.backend.proposal().map(ProposalMessage::from_proposal).transpose()?,
            "proposal_payouts":payouts,"splice":splice,"lineage":self.lineage,
            "participant_lock_hashes":self.backend.current().settlement.participant_lock_hashes.map(|hash| canonical_hex(&hash)),
            "signature_count":self.backend.signatures().len()}),
        )
    }
}

fn save(path: &Path, session: &StoredSession) -> Result<()> {
    session.package()?;
    let bytes = serde_json::to_vec(session)?;
    ensure!(
        bytes.len() as u64 <= MAX_SESSION_BYTES,
        "session exceeds byte limit"
    );
    crate::packages::write_private_atomic(path, &bytes)
}

#[cfg(test)]
pub(crate) fn test_session(path: &Path, package: &Path, local_pubkey: &str) -> Result<()> {
    let package = packages::read_package(package)?;
    let session = StoredSession {
        schema: SESSION_SCHEMA.to_string(),
        backend: MultiAssetChannelBackend::new(package.recovery()?, decode_hex(local_pubkey, 33)?)?,
        cell_deps: package.cell_deps,
        splice_draft: None,
        lineage: None,
    };
    save(path, &session)
}

pub fn run(path: &Path, command: SessionCommand) -> Result<Value> {
    let _lock = lock_private_path(path)?;
    let session: StoredSession = serde_json::from_slice(&read_limited(path)?)?;
    ensure!(
        session.lineage.is_some(),
        "operational signer requires confirmed initial funding lineage"
    );
    run_loaded(path, command, session, StoredSession::verify_chain)
}

fn run_loaded(
    path: &Path,
    command: SessionCommand,
    mut session: StoredSession,
    verify: fn(&StoredSession) -> Result<()>,
) -> Result<Value> {
    session.package()?;
    let requires_chain = match &command {
        SessionCommand::Inspect
        | SessionCommand::ExportSplice { .. }
        | SessionCommand::ExportRootFunding { .. }
        | SessionCommand::Cancel
        | SessionCommand::CancelSplice => false,
        #[cfg(feature = "devnet")]
        SessionCommand::ConfirmSplice { .. } | SessionCommand::RefreshChain { .. } => false,
        _ => true,
    };
    if requires_chain {
        verify(&session)?;
    }
    match command {
        SessionCommand::Inspect => session.summary(),
        SessionCommand::Propose { descriptor_hex } => {
            let descriptor = decode_hex(&descriptor_hex, MAX_DESCRIPTOR_BYTES)?;
            let proposal = session
                .backend
                .propose(MultiAssetSettlement::decode(&descriptor)?)?;
            save(path, &session)?;
            Ok(serde_json::to_value(ProposalMessage::from_proposal(
                &proposal,
            )?)?)
        }
        SessionCommand::Accept { proposal } => {
            let message: ProposalMessage = serde_json::from_slice(&read_limited(&proposal)?)?;
            session
                .backend
                .accept_proposal(message.proposal(&session.backend)?)?;
            save(path, &session)?;
            session.summary()
        }
        SessionCommand::Sign {
            target,
            private_key,
        } => {
            let key = channel_signing_key(&private_key, session.backend.local_pubkey())?;
            let pubkey = session.backend.local_pubkey().to_vec();
            let signing_digest = target.digest(&session.backend)?;
            if let Some(signature) = target
                .signatures(&session.backend)
                .iter()
                .find(|signature| signature.pubkey_sec1 == pubkey)
            {
                return Ok(serde_json::to_value(SignatureMessage {
                    schema: SIGNATURE_SCHEMA.to_string(),
                    signing_digest: canonical_hex(&signing_digest),
                    pubkey: canonical_hex(&signature.pubkey_sec1),
                    signature: canonical_hex(&signature.signature),
                })?);
            }
            let reserved_digest = target.reserve(&mut session.backend)?;
            ensure!(
                reserved_digest == signing_digest,
                "signing digest changed during reservation"
            );
            // Crash after this write can only retry the same digest or move to
            // a greater state number, even if no signature was returned yet.
            save(path, &session)?;
            verify(&session)?;
            let signature: Signature = key
                .sign_prehash(&reserved_digest)
                .map_err(|_| anyhow!("channel signature generation failed"))?;
            let signature = ParticipantSignature {
                pubkey_sec1: pubkey,
                signature: signature.to_bytes().to_vec(),
            };
            target.record(&mut session.backend, signature.clone())?;
            save(path, &session)?;
            verify(&session)?;
            Ok(serde_json::to_value(SignatureMessage {
                schema: SIGNATURE_SCHEMA.to_string(),
                signing_digest: canonical_hex(&reserved_digest),
                pubkey: canonical_hex(&signature.pubkey_sec1),
                signature: canonical_hex(&signature.signature),
            })?)
        }
        SessionCommand::AddSignature { target, signature } => {
            let message: SignatureMessage = serde_json::from_slice(&read_limited(&signature)?)?;
            ensure!(
                message.schema == SIGNATURE_SCHEMA,
                "unsupported signature schema"
            );
            ensure!(
                digest(&message.signing_digest)? == target.digest(&session.backend)?,
                "signature is for another signing target"
            );
            target.record(
                &mut session.backend,
                ParticipantSignature {
                    pubkey_sec1: decode_hex(&message.pubkey, 33)?,
                    signature: decode_hex(&message.signature, 64)?,
                },
            )?;
            save(path, &session)?;
            session.summary()
        }
        SessionCommand::Commit { store_dir } => {
            session.backend.commit()?;
            let package = session.package()?;
            let recovery_path = packages::write_package(&store_dir, &package)?;
            save(path, &session)?;
            Ok(json!({"recovery_package":recovery_path,"summary":package.validate()?}))
        }
        SessionCommand::Recover { package } => {
            let package = packages::read_package(&package)?;
            session.backend.recover_committed(package.recovery()?)?;
            session.cell_deps = package.cell_deps;
            save(path, &session)?;
            session.summary()
        }
        SessionCommand::PrepareSplice { draft } => {
            let draft: SpliceDraft = serde_json::from_slice(&read_limited(&draft)?)?;
            let proposal = draft.proposal(session.backend.current())?;
            session.backend.prepare_splice(proposal)?;
            if let Some(existing) = &session.splice_draft {
                ensure!(
                    *existing == draft,
                    "another exact splice draft is already persisted"
                );
            }
            session.splice_draft = Some(draft);
            save(path, &session)?;
            session.summary()
        }
        SessionCommand::CancelSplice => {
            session.backend.cancel_splice()?;
            session.splice_draft = None;
            save(path, &session)?;
            session.summary()
        }
        SessionCommand::ExportSplice { store_dir } => {
            let signed = session.signed_splice()?;
            let plan = session
                .backend
                .splice_proposal()
                .ok_or_else(|| anyhow!("no pending splice"))?;
            let recovery = plan.initial_recovery(session.backend.current())?;
            let package = StoredMultiAssetPackage::from_recovery(
                &recovery,
                &signed.raw().cell_deps().into_iter().collect::<Vec<_>>(),
            )?;
            let recovery_path = packages::write_package(&store_dir, &package)?;
            let transaction_path = crate::multi_asset_splice_transaction::write_transaction(
                &store_dir,
                &signed,
                crate::multi_asset_splice_transaction::TransactionKind::Splice,
            )?;
            Ok(
                json!({"recovery_package":recovery_path,"transaction":transaction_path,"transaction_hash":canonical_hex(&plan.transaction_hash)}),
            )
        }
        SessionCommand::ExportRootFunding { store_dir } => {
            let lineage = session
                .lineage
                .as_ref()
                .ok_or_else(|| anyhow!("root funding has not been bound"))?;
            let SessionOrigin::Root {
                funding_transaction_hex,
            } = &lineage.origin
            else {
                return Err(anyhow!("active context is not root funding"));
            };
            let transaction = packed::Transaction::from_slice(&decode_hex(
                funding_transaction_hex,
                crate::multi_asset_funding::MAX_FUNDING_BYTES,
            )?)?;
            crate::multi_asset_funding::validate_root_funding(
                session.backend.current(),
                &transaction,
            )?;
            let recovery_path = packages::write_package(&store_dir, &session.package()?)?;
            let transaction_path = crate::multi_asset_splice_transaction::write_transaction(
                &store_dir,
                &transaction,
                crate::multi_asset_splice_transaction::TransactionKind::Root,
            )?;
            Ok(
                json!({"funding_transaction":transaction_path,"recovery_package":recovery_path,"tx_hash":canonical_hex(transaction.calc_tx_hash().as_slice())}),
            )
        }
        #[cfg(feature = "devnet")]
        SessionCommand::ConfirmSplice {
            rpc_url,
            state_out_point,
            min_confirmations,
            archive_dir,
            contracts_dir,
        } => confirm_splice(
            path,
            session,
            Confirmation {
                rpc_url: &rpc_url,
                state_out_point: &state_out_point,
                min_confirmations,
                archive_dir: &archive_dir,
                contracts_dir: &contracts_dir,
            },
        ),
        #[cfg(feature = "devnet")]
        SessionCommand::RefreshChain {
            state_out_point,
            package,
        } => refresh_chain(path, session, &state_out_point, &package),
        SessionCommand::Cancel => {
            session.backend.cancel_proposal();
            save(path, &session)?;
            session.summary()
        }
    }
}

#[cfg(feature = "devnet")]
pub(super) fn observe_for_supervision(
    path: &Path,
    budget: std::time::Duration,
) -> crate::multi_asset_supervision::Observation {
    use crate::multi_asset_supervision::{Identity, Observation, Status};
    let _lock = match crate::packages::try_lock_private_path(path) {
        Ok(Some(lock)) => lock,
        Ok(None) => return Observation::failure(Status::Busy, "signer journal is busy"),
        Err(error) => return Observation::failure(Status::Unreadable, error),
    };
    let session =
        read_limited(path).and_then(|bytes| Ok(serde_json::from_slice::<StoredSession>(&bytes)?));
    let session = match session {
        Ok(session) => session,
        Err(error) => return Observation::failure(Status::Unreadable, error),
    };
    let current = session.backend.current();
    let identity = match current.state.funding_context_id() {
        Ok(context) => Identity {
            pubkey: canonical_hex(session.backend.local_pubkey()),
            channel_id: canonical_hex(&current.state.header.channel_id),
            funding_context_id: canonical_hex(&context),
            state_number: current.state.header.state_number.to_string(),
        },
        Err(error) => return Observation::failure(Status::Unreadable, error),
    };
    let mut observation = Observation {
        identity: Some(identity),
        status: Status::Verified,
        error: None,
    };
    let checked = (|| -> Result<()> {
        let package = session.package()?;
        let Some(lineage) = &session.lineage else {
            observation.status = Status::Unmanaged;
            return Err(anyhow!(
                "session has no canonical lineage guard; use bind-root for confirmed epoch-0 custody"
            ));
        };
        let rpc = crate::rpc::CkbRpcClient::new_supervision(&lineage.rpc_url, budget)?;
        crate::devnet::multi_asset_splice_operator::verify_context_guard(
            &rpc,
            &lineage.evidence,
            lineage.min_confirmations,
            &package,
            &lineage.contracts_dir,
        )?;
        rpc.ensure_deadline()
    })();
    if let Err(error) = checked {
        if observation.status == Status::Verified {
            observation.status = Status::Blocked;
        }
        observation.error = Some(error.to_string());
    }
    observation
}

#[cfg(feature = "devnet")]
fn bind_root(
    path: &Path,
    mut session: StoredSession,
    rpc_url: &str,
    state_out_point: &str,
    min_confirmations: u64,
    contracts_dir: &Path,
) -> Result<Value> {
    ensure!(
        session.lineage.is_none() && session.backend.current().state.header.funding_epoch == 0,
        "only an unbound epoch-0 journal can bind root evidence; use refresh-chain for an existing guard"
    );
    let endpoint = crate::multi_asset_session_chain::rpc_endpoint(rpc_url)?;
    let contracts_dir = contracts_dir.canonicalize()?;
    let rpc = crate::rpc::CkbRpcClient::new(endpoint.as_str())?;
    let (evidence, transaction) = crate::devnet::multi_asset_splice_operator::confirm_root_context(
        &rpc,
        session.backend.current(),
        state_out_point,
        min_confirmations,
        &contracts_dir,
    )?;
    session.validate_funding_dependencies(&transaction)?;
    session.lineage = Some(SessionLineage {
        rpc_url: endpoint.to_string(),
        contracts_dir,
        min_confirmations,
        evidence,
        origin: SessionOrigin::Root {
            funding_transaction_hex: canonical_hex(transaction.as_slice()),
        },
    });
    session.package()?;
    session.verify_chain()?;
    save(path, &session)?;
    session.summary()
}

/// Called only while the root funding session holds this path's stable lock.
#[cfg(feature = "devnet")]
pub(crate) fn confirm_initial_funding(
    path: &Path,
    package: StoredMultiAssetPackage,
    local_pubkey: Vec<u8>,
    rpc_url: &str,
    state_out_point: &str,
    min_confirmations: u64,
    contracts_dir: &Path,
) -> Result<Value> {
    let session = StoredSession {
        schema: SESSION_SCHEMA.to_string(),
        backend: MultiAssetChannelBackend::new(package.recovery()?, local_pubkey)?,
        cell_deps: package.cell_deps,
        splice_draft: None,
        lineage: None,
    };
    bind_root(
        path,
        session,
        rpc_url,
        state_out_point,
        min_confirmations,
        contracts_dir,
    )
}

#[cfg(feature = "devnet")]
struct Confirmation<'a> {
    rpc_url: &'a str,
    state_out_point: &'a str,
    min_confirmations: u64,
    archive_dir: &'a Path,
    contracts_dir: &'a Path,
}

#[cfg(feature = "devnet")]
fn confirm_splice(path: &Path, session: StoredSession, options: Confirmation<'_>) -> Result<Value> {
    use crate::devnet::multi_asset_splice_operator::{ConfirmationOptions, confirm_context};
    let endpoint = crate::multi_asset_session_chain::rpc_endpoint(options.rpc_url)?;
    ensure!(
        session.backend.splice_signature_reserved(),
        "cannot retire an unsealed signer journal"
    );
    let transaction = session.signed_splice()?;
    let plan = session
        .backend
        .splice_proposal()
        .ok_or_else(|| anyhow!("no pending splice"))?;
    let recovery = plan.initial_recovery(session.backend.current())?;
    let contracts_dir = options.contracts_dir.canonicalize()?;
    let rpc = crate::rpc::CkbRpcClient::new(endpoint.as_str())?;
    let evidence = confirm_context(
        &rpc,
        ConfirmationOptions {
            old: session.backend.current(),
            initial_recovery: &recovery,
            current: &recovery,
            transaction: &transaction,
            state_out_point: options.state_out_point,
            min_confirmations: options.min_confirmations,
            contracts_dir: &contracts_dir,
        },
    )?;
    let local_pubkey = session.backend.local_pubkey().to_vec();
    let bytes = serde_json::to_vec(&RetiredSession {
        schema: RETIRED_SCHEMA.to_string(),
        session,
    })?;
    ensure!(
        bytes.len() as u64 <= MAX_SESSION_BYTES,
        "retired journal exceeds byte limit"
    );
    let hash = canonical_hex(&blake2b256(&bytes));
    let retired = std::path::absolute(options.archive_dir)?
        .join(format!("retired-{}.json", hash.trim_start_matches("0x")));
    let _retired_lock = lock_private_path(&retired)?;
    if retired.exists() {
        ensure!(
            read_limited(&retired)? == bytes,
            "retired journal path contains different evidence"
        );
        File::open(&retired)?.sync_all()?;
    } else {
        crate::packages::write_private_atomic(&retired, &bytes)?;
    }
    let retired = retired.canonicalize()?;
    ensure!(
        retired != path.canonicalize()?,
        "active and retired journals must use distinct paths"
    );
    let package = StoredMultiAssetPackage::from_recovery(
        &recovery,
        &transaction
            .raw()
            .cell_deps()
            .into_iter()
            .collect::<Vec<_>>(),
    )?;
    let recovery_path = packages::write_package(&options.archive_dir.join("recovery"), &package)?;
    let next = StoredSession {
        schema: SESSION_SCHEMA.to_string(),
        backend: MultiAssetChannelBackend::new(recovery, local_pubkey)?,
        cell_deps: package.cell_deps,
        splice_draft: None,
        lineage: Some(SessionLineage {
            rpc_url: endpoint.to_string(),
            contracts_dir,
            min_confirmations: options.min_confirmations,
            evidence,
            origin: SessionOrigin::Splice {
                retired_journal: retired,
                retired_journal_hash: hash,
            },
        }),
    };
    next.package()?;
    next.verify_chain()?;
    save(path, &next)?;
    Ok(json!({"initial_recovery_package":recovery_path,"session":next.summary()?}))
}

#[cfg(feature = "devnet")]
fn refresh_chain(
    path: &Path,
    mut session: StoredSession,
    state_out_point: &str,
    package_path: &Path,
) -> Result<Value> {
    let package = packages::read_package(package_path)?;
    let recovery = package.recovery()?;
    if recovery != *session.backend.current() {
        session.backend.recover_committed(recovery)?;
    }
    session.cell_deps = package.cell_deps;
    session.package()?;
    use crate::devnet::multi_asset_splice_operator::{
        ConfirmationOptions, confirm_context, confirm_root_context,
    };
    let lineage = session
        .lineage
        .as_ref()
        .ok_or_else(|| anyhow!("session has no canonical lineage"))?;
    let rpc = crate::rpc::CkbRpcClient::new(&lineage.rpc_url)?;
    let evidence = match &lineage.origin {
        SessionOrigin::Root { .. } => {
            confirm_root_context(
                &rpc,
                session.backend.current(),
                state_out_point,
                lineage.min_confirmations,
                &lineage.contracts_dir,
            )?
            .0
        }
        SessionOrigin::Splice { .. } => {
            let retired = session
                .retired()?
                .ok_or_else(|| anyhow!("retired splice journal missing"))?;
            let transaction = retired.signed_splice()?;
            let initial = retired
                .backend
                .splice_proposal()
                .ok_or_else(|| anyhow!("retired splice intent missing"))?
                .initial_recovery(retired.backend.current())?;
            confirm_context(
                &rpc,
                ConfirmationOptions {
                    old: retired.backend.current(),
                    initial_recovery: &initial,
                    current: session.backend.current(),
                    transaction: &transaction,
                    state_out_point,
                    min_confirmations: lineage.min_confirmations,
                    contracts_dir: &lineage.contracts_dir,
                },
            )?
        }
    };
    session
        .lineage
        .as_mut()
        .ok_or_else(|| anyhow!("session has no canonical lineage"))?
        .evidence = evidence;
    session.verify_chain()?;
    save(path, &session)?;
    session.summary()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    // These unit tests exercise persistence/crypto without a chain. Guarded
    // command verification is covered by the isolated-node acceptance flow.
    fn run(path: &Path, command: SessionCommand) -> Result<Value> {
        let _lock = lock_private_path(path)?;
        let session = serde_json::from_slice(&read_limited(path)?)?;
        run_loaded(path, command, session, |_| Ok(()))
    }
    #[test]
    fn operational_commands_reject_unconfirmed_recovery_bootstrap() {
        let (dir, path, package, _) = fixture();
        test_session(&path, &package, &public(1)).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(
            super::run(&path, SessionCommand::Inspect)
                .unwrap_err()
                .to_string()
                .contains("confirmed initial funding")
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(dir).unwrap();
    }
    fn fixture() -> (PathBuf, PathBuf, PathBuf, StoredMultiAssetPackage) {
        let dir = std::env::temp_dir().join(format!(
            "morph-session-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let package = packages::fixture_package().unwrap();
        let package_path = dir.join("recovery.json");
        fs::write(&package_path, serde_json::to_vec(&package).unwrap()).unwrap();
        (dir.clone(), dir.join("alice.json"), package_path, package)
    }
    fn public(key: u8) -> String {
        canonical_hex(
            SigningKey::from_slice(&[key; 32])
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
    }
    fn init(path: &Path, package: &Path, key: u8) {
        test_session(path, package, &public(key)).unwrap();
    }
    fn propose(path: &Path, package: &StoredMultiAssetPackage) -> Value {
        let mut settlement = package.recovery().unwrap().settlement;
        // Keep the full u128 quantity; Rust's private snapshot must not round it.
        let first = &mut settlement.payouts[0];
        first.values[0].amount -= 1;
        first.values[1].amount += 1;
        run(
            path,
            SessionCommand::Propose {
                descriptor_hex: canonical_hex(&settlement.encode().unwrap()),
            },
        )
        .unwrap()
    }

    #[test]
    fn durable_session_negotiates_both_signers_and_exports_lossless_recovery() {
        let (dir, alice, original_path, package) = fixture();
        let bob = dir.join("bob.json");
        init(&alice, &original_path, 1);
        init(&bob, &original_path, 2);
        let proposal = propose(&alice, &package);
        let proposal_path = dir.join("proposal.json");
        fs::write(&proposal_path, serde_json::to_vec(&proposal).unwrap()).unwrap();
        run(
            &bob,
            SessionCommand::Accept {
                proposal: proposal_path,
            },
        )
        .unwrap();
        let mut receipts = Vec::new();
        for (path, key) in [(&alice, 1u8), (&bob, 2)] {
            let signed = run(
                path,
                SessionCommand::Sign {
                    target: SigningTarget::Update,
                    private_key: hex::encode([key; 32]),
                },
            )
            .unwrap();
            assert_eq!(
                run(
                    path,
                    SessionCommand::Sign {
                        target: SigningTarget::Update,
                        private_key: hex::encode([key; 32])
                    }
                )
                .unwrap(),
                signed
            );
            let receipt = dir.join(format!("signature-{key}.json"));
            fs::write(&receipt, serde_json::to_vec(&signed).unwrap()).unwrap();
            receipts.push(receipt);
            assert!(
                run(
                    path,
                    SessionCommand::Commit {
                        store_dir: dir.join("packages")
                    }
                )
                .is_err()
            );
        }
        run(
            &alice,
            SessionCommand::AddSignature {
                target: SigningTarget::Update,
                signature: receipts[1].clone(),
            },
        )
        .unwrap();
        run(
            &bob,
            SessionCommand::AddSignature {
                target: SigningTarget::Update,
                signature: receipts[0].clone(),
            },
        )
        .unwrap();
        let a = run(
            &alice,
            SessionCommand::Commit {
                store_dir: dir.join("packages"),
            },
        )
        .unwrap();
        let b = run(
            &bob,
            SessionCommand::Commit {
                store_dir: dir.join("packages"),
            },
        )
        .unwrap();
        assert_eq!(a, b);
        let exported =
            packages::read_package(Path::new(a["recovery_package"].as_str().unwrap())).unwrap();
        assert_eq!(exported.cell_deps, package.cell_deps);
        assert_eq!(
            exported.validate().unwrap().state_number,
            proposal["state_number"].as_str().unwrap()
        );
        exported.recovery().unwrap().validate().unwrap();
        let restored = run(&alice, SessionCommand::Inspect).unwrap();
        assert_eq!(restored["proposal"], Value::Null);
        assert_eq!(
            restored["current"]["package_id"],
            proposal["signing_digest"]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&alice).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn splice_session_collects_three_signature_roles_and_exports_exact_body_and_exit() {
        let (dir, alice, original, package) = fixture();
        let bob = dir.join("bob.json");
        init(&alice, &original, 1);
        init(&bob, &original, 2);
        let draft =
            crate::multi_asset_splice_transaction::fixture_draft(&package.recovery().unwrap());
        let draft_path = dir.join("splice-draft.json");
        fs::write(&draft_path, serde_json::to_vec(&draft).unwrap()).unwrap();
        for path in [&alice, &bob] {
            run(
                path,
                SessionCommand::PrepareSplice {
                    draft: draft_path.clone(),
                },
            )
            .unwrap();
            assert!(
                run(
                    path,
                    SessionCommand::Sign {
                        target: SigningTarget::SpliceBridge,
                        private_key: hex::encode([1u8; 32])
                    }
                )
                .is_err()
            );
        }
        for target in [
            SigningTarget::SpliceCreation,
            SigningTarget::SpliceRecovery,
            SigningTarget::SpliceBridge,
        ] {
            let mut receipts = Vec::new();
            for (path, key) in [(&alice, 1u8), (&bob, 2u8)] {
                let signed = run(
                    path,
                    SessionCommand::Sign {
                        target,
                        private_key: hex::encode([key; 32]),
                    },
                )
                .unwrap();
                assert_eq!(
                    signed,
                    run(
                        path,
                        SessionCommand::Sign {
                            target,
                            private_key: hex::encode([key; 32])
                        }
                    )
                    .unwrap()
                );
                let receipt = dir.join(format!("{:?}-{key}.json", target));
                fs::write(&receipt, serde_json::to_vec(&signed).unwrap()).unwrap();
                receipts.push(receipt);
                assert!(
                    run(
                        path,
                        SessionCommand::ExportSplice {
                            store_dir: dir.join("exports")
                        }
                    )
                    .is_err()
                );
            }
            for (path, receipt) in [(&alice, &receipts[1]), (&bob, &receipts[0])] {
                run(
                    path,
                    SessionCommand::AddSignature {
                        target,
                        signature: receipt.clone(),
                    },
                )
                .unwrap();
            }
        }
        let result = run(
            &alice,
            SessionCommand::ExportSplice {
                store_dir: dir.join("exports"),
            },
        )
        .unwrap();
        assert_eq!(
            result,
            run(
                &bob,
                SessionCommand::ExportSplice {
                    store_dir: dir.join("exports")
                }
            )
            .unwrap()
        );
        let exit = packages::read_package(Path::new(result["recovery_package"].as_str().unwrap()))
            .unwrap();
        let recovery = exit.recovery().unwrap();
        assert_eq!(recovery.state.header.state_number, 1);
        let bytes = fs::read(result["transaction"].as_str().unwrap()).unwrap();
        let tx = packed::Transaction::from_slice(&bytes).unwrap();
        let (_, verified) =
            SpliceDraft::from_signed_transaction(&package.recovery().unwrap(), &recovery, &tx)
                .unwrap();
        assert_eq!(
            verified.transaction_hash.as_slice(),
            tx.calc_tx_hash().as_slice()
        );
        let mut wrong = recovery.clone();
        wrong.authorization = package.recovery().unwrap().authorization;
        assert!(
            SpliceDraft::from_signed_transaction(&package.recovery().unwrap(), &wrong, &tx)
                .is_err()
        );
        assert_eq!(
            tx.raw().as_slice(),
            draft.transaction().unwrap().raw().as_slice()
        );
        assert!(
            recovery
                .outpoints
                .iter()
                .all(|point| point.tx_hash.as_slice() == tx.calc_tx_hash().as_slice())
        );
        let witness =
            packed::WitnessArgs::from_slice(&tx.witnesses().get(0).unwrap().raw_data()).unwrap();
        let envelope = witness.output_type().to_opt().unwrap().raw_data();
        morph_script_common::multi_asset_splice::MultiAssetSpliceWitness::parse(&envelope).unwrap();
        assert!(run(&alice, SessionCommand::CancelSplice).is_err());
        assert!(
            run(
                &alice,
                SessionCommand::Propose {
                    descriptor_hex: canonical_hex(
                        &package.recovery().unwrap().settlement.encode().unwrap()
                    )
                }
            )
            .is_err()
        );
        let mut stored: StoredSession = serde_json::from_slice(&fs::read(&alice).unwrap()).unwrap();
        stored.splice_draft = None;
        let encoded = serde_json::to_string(&stored).unwrap();
        // Keep u128 values in the typed serializer; Value would round them
        // and could produce an unrelated decoding failure before this check.
        assert!(serde_json::from_str::<StoredSession>(&encoded).is_ok());
        for field in ["splice_draft", "lineage"] {
            let missing = encoded.replace(&format!(",\"{field}\":null"), "");
            assert_ne!(missing, encoded);
            let error = serde_json::from_str::<StoredSession>(&missing).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{field}`"))
            );
        }
        // A switched journal must bind the exact sealed predecessor. This
        // structural check remains available without an online RPC client.
        use crate::multi_asset_session_chain::{CanonicalInclusion, ContextChainEvidence};
        let archived_session: StoredSession =
            serde_json::from_slice(&fs::read(&alice).unwrap()).unwrap();
        let archived_bytes = serde_json::to_vec(&RetiredSession {
            schema: RETIRED_SCHEMA.to_string(),
            session: archived_session,
        })
        .unwrap();
        let archive = dir.join("retired.json");
        fs::write(&archive, &archived_bytes).unwrap();
        assert!(run(&archive, SessionCommand::Inspect).is_err());
        let funding = CanonicalInclusion {
            transaction_hash: canonical_hex(tx.calc_tx_hash().as_slice()),
            block_number: 1,
            block_hash: canonical_hex(&[9; 32]),
        };
        let mut switched = StoredSession {
            schema: SESSION_SCHEMA.to_string(),
            backend: MultiAssetChannelBackend::new(
                recovery.clone(),
                decode_hex(&public(1), 33).unwrap(),
            )
            .unwrap(),
            cell_deps: exit.cell_deps.clone(),
            splice_draft: None,
            lineage: Some(SessionLineage {
                rpc_url: "http://127.0.0.1:1/".to_string(),
                contracts_dir: dir.canonicalize().unwrap(),
                min_confirmations: 1,
                evidence: ContextChainEvidence {
                    funding: funding.clone(),
                    state: funding.clone(),
                    state_out_point: format!("{}:0", funding.transaction_hash),
                },
                origin: SessionOrigin::Splice {
                    retired_journal: archive.clone(),
                    retired_journal_hash: canonical_hex(&blake2b256(&archived_bytes)),
                },
            }),
        };
        switched.package().unwrap();
        let mut missing_origin = serde_json::to_value(switched.lineage.as_ref().unwrap()).unwrap();
        missing_origin.as_object_mut().unwrap().remove("origin");
        assert!(
            serde_json::from_value::<SessionLineage>(missing_origin)
                .unwrap_err()
                .to_string()
                .contains("missing field `origin`")
        );
        switched
            .lineage
            .as_mut()
            .unwrap()
            .evidence
            .funding
            .transaction_hash = canonical_hex(&[0; 32]);
        assert!(switched.package().is_err());
        switched.lineage.as_mut().unwrap().evidence.funding = funding;
        fs::write(&archive, b"changed journal").unwrap();
        assert!(switched.package().is_err());
        fs::write(&archive, archived_bytes).unwrap();
        switched.package().unwrap();
        let transaction_path = result["transaction"].as_str().unwrap();
        fs::write(transaction_path, b"different witnesses").unwrap();
        assert!(
            run(
                &alice,
                SessionCommand::ExportSplice {
                    store_dir: dir.join("exports")
                }
            )
            .is_err()
        );
        assert_eq!(fs::read(transaction_path).unwrap(), b"different witnesses");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cancelled_signature_survives_restart_and_wrong_key_does_not_reserve() {
        let (dir, session, original_path, package) = fixture();
        init(&session, &original_path, 1);
        let proposal = propose(&session, &package);
        let before = fs::read(&session).unwrap();
        assert!(
            run(
                &session,
                SessionCommand::Sign {
                    target: SigningTarget::Update,
                    private_key: hex::encode([2u8; 32])
                }
            )
            .is_err()
        );
        assert_eq!(fs::read(&session).unwrap(), before);
        run(
            &session,
            SessionCommand::Sign {
                target: SigningTarget::Update,
                private_key: hex::encode([1u8; 32]),
            },
        )
        .unwrap();
        run(&session, SessionCommand::Cancel).unwrap();
        let next = propose(&session, &package);
        assert_eq!(
            next["state_number"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            proposal["state_number"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                + 1
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn session_lock_covers_read_reserve_and_atomic_snapshot_replacement() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (dir, path, original_path, package) = fixture();
        init(&path, &original_path, 1);
        propose(&path, &package);
        let lock = lock_private_path(&path).unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            sender
                .send(run(
                    &worker_path,
                    SessionCommand::Sign {
                        target: SigningTarget::Update,
                        private_key: hex::encode([1u8; 32]),
                    },
                ))
                .unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        // A holder can cancel/replace the snapshot while the signer waits.
        let mut session: StoredSession =
            serde_json::from_slice(&read_limited(&path).unwrap()).unwrap();
        session.backend.cancel_proposal();
        save(&path, &session).unwrap();
        drop(lock);
        assert!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_err()
        );
        worker.join().unwrap();
        assert_eq!(
            run(&path, SessionCommand::Inspect).unwrap()["signature_count"],
            0
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod cross_language_tests {
    use super::*;

    #[test]
    fn accepts_sdk_proposal_and_peer_signature_with_full_u128_values() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/multi-asset-update.json"
        ))
        .unwrap();
        let package = packages::fixture_package().unwrap();
        let recovery = package.recovery().unwrap();
        let key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut backend = MultiAssetChannelBackend::new(
            recovery,
            key.verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
        let proposal: ProposalMessage =
            serde_json::from_value(fixture["proposal"].clone()).unwrap();
        let proposal = proposal.proposal(&backend).unwrap();
        backend.accept_proposal(proposal).unwrap();
        let peer: SignatureMessage = serde_json::from_value(fixture["signature"].clone()).unwrap();
        backend
            .record_signature(ParticipantSignature {
                pubkey_sec1: decode_hex(&peer.pubkey, 33).unwrap(),
                signature: decode_hex(&peer.signature, 64).unwrap(),
            })
            .unwrap();
        let reservation = backend.reserve_signature().unwrap();
        let signature: Signature = key.sign_prehash(&reservation.signing_digest).unwrap();
        backend
            .record_signature(ParticipantSignature {
                pubkey_sec1: backend.local_pubkey().to_vec(),
                signature: signature.to_bytes().to_vec(),
            })
            .unwrap();
        let current = backend.commit().unwrap();
        assert_eq!(
            canonical_hex(&current.state.signing_digest().unwrap()),
            fixture["proposal"]["signing_digest"]
        );
        current.validate().unwrap();
    }
}
