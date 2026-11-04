//! Current channel capability services. Signing authority belongs exclusively
//! to `MultiAssetChannelBackend`; payment and conditional bookkeeping never
//! contain a second signer, StateCell lifecycle or descriptor fallback.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Bytes32, ConditionalBatch, ConditionalError, ConditionalResolution, MultiAssetBackendError,
    MultiAssetChannelBackend, MultiAssetError, MultiAssetProposal, MultiAssetSettlementCapability,
    StateAuthorization, VaultAsset, blake2b256, derive_conditional_batch_id,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelParticipant {
    pub node_id: Bytes32,
    pub settlement_lock_hash: Bytes32,
}

pub(crate) fn validate_participant_identities(
    authorization: &StateAuthorization,
    participants: &[ChannelParticipant; 2],
) -> Result<(), ParticipantIdentityError> {
    if authorization.threshold != 2 || authorization.signatures.len() != 2 {
        return Err(ParticipantIdentityError);
    }
    let signed = authorization
        .signatures
        .iter()
        .map(|signature| blake2b256(&signature.pubkey_sec1))
        .collect::<BTreeSet<_>>();
    let configured = participants
        .iter()
        .map(|member| member.node_id)
        .collect::<BTreeSet<_>>();
    if configured.len() != 2 || signed != configured {
        return Err(ParticipantIdentityError);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("configured channel nodes do not match its two authenticated signers")]
pub struct ParticipantIdentityError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionalBatchLifecycle {
    Armed,
    ForceClosing,
    CooperativeSettled { state_number: u64 },
    ForceSettled { settlement_tx: Bytes32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalPreimage {
    pub transfer_id: Bytes32,
    pub preimage: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalBatchRecord {
    pub batch: ConditionalBatch,
    pub armed_state_number: u64,
    pub armed_at_block: u64,
    pub preimages: Vec<ConditionalPreimage>,
    pub lifecycle: ConditionalBatchLifecycle,
}

impl ConditionalBatchRecord {
    fn preimage_map(&self) -> BTreeMap<Bytes32, Bytes32> {
        self.preimages
            .iter()
            .map(|entry| (entry.transfer_id, entry.preimage))
            .collect()
    }
    fn is_active(&self) -> bool {
        matches!(
            self.lifecycle,
            ConditionalBatchLifecycle::Armed | ConditionalBatchLifecycle::ForceClosing
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalForceClosePackage {
    pub batch_id: Bytes32,
    pub armed_state_number: u64,
    pub descriptor: Vec<u8>,
    pub resolution_witness: Vec<u8>,
    pub input_since: u64,
    pub payout_capacities: [u64; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ConditionalChange {
    Arm {
        batch: ConditionalBatch,
        armed_at_block: u64,
        proposal: MultiAssetProposal,
    },
    Consolidate {
        batch_id: Bytes32,
        proposal: MultiAssetProposal,
    },
}
impl ConditionalChange {
    fn proposal(&self) -> &MultiAssetProposal {
        match self {
            Self::Arm { proposal, .. } | Self::Consolidate { proposal, .. } => proposal,
        }
    }
}

/// Metadata for explicit CKB Batch transitions on the current custody model.
/// Persist with the agreement engine under its existing stable journal lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConditionalBatches {
    channel_id: Bytes32,
    funding_context_id: Bytes32,
    records: Vec<ConditionalBatchRecord>,
    #[serde(deserialize_with = "required_option")]
    pending: Option<ConditionalChange>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

impl ChannelConditionalBatches {
    pub fn new(backend: &MultiAssetChannelBackend) -> ConditionalBackendResult<Self> {
        backend.validate()?;
        Ok(Self {
            channel_id: backend.current().state.header.channel_id,
            funding_context_id: backend.current().state.funding_context_id()?,
            records: vec![],
            pending: None,
        })
    }

    pub fn validate(&self, backend: &MultiAssetChannelBackend) -> ConditionalBackendResult<()> {
        backend.validate()?;
        if self.channel_id != backend.current().state.header.channel_id
            || self.funding_context_id != backend.current().state.funding_context_id()?
        {
            return Err(ConditionalBackendError::WrongContext);
        }
        let mut ids = BTreeSet::new();
        let mut active = 0;
        for record in &self.records {
            record.batch.validate()?;
            if !ids.insert(record.batch.batch_id) || record.armed_state_number == 0 {
                return Err(ConditionalBackendError::InvalidRecord);
            }
            let mut transfers = BTreeSet::new();
            for entry in &record.preimages {
                let transfer = record
                    .batch
                    .transfers
                    .iter()
                    .find(|transfer| transfer.transfer_id == entry.transfer_id)
                    .ok_or(ConditionalBackendError::UnknownTransfer)?;
                if !transfers.insert(entry.transfer_id)
                    || crate::derive_conditional_payment_hash(
                        transfer.hash_algorithm,
                        &entry.preimage,
                    )? != transfer.payment_hash
                {
                    return Err(ConditionalBackendError::WrongPreimage);
                }
            }
            if record.is_active() {
                active += 1;
            }
            if matches!(&record.lifecycle, ConditionalBatchLifecycle::ForceSettled { settlement_tx } if *settlement_tx == [0; 32])
            {
                return Err(ConditionalBackendError::InvalidRecord);
            }
        }
        if active > 1 {
            return Err(ConditionalBackendError::BatchActive);
        }
        if let Some(change) = &self.pending {
            let proposal = change.proposal();
            if proposal.state.header.channel_id != self.channel_id
                || proposal.state.funding_context_id()? != self.funding_context_id
                || proposal.state.header.settlement_descriptor_commitment
                    != proposal.settlement.commitment()?
            {
                return Err(ConditionalBackendError::InvalidRecord);
            }
            match change {
                ConditionalChange::Arm { batch, .. } => {
                    batch.validate()?;
                    if active != 0
                        || ids.contains(&batch.batch_id)
                        || !matches!(&proposal.settlement.capability,
                            MultiAssetSettlementCapability::CkbConditional { batch: signed, .. } if signed.as_ref() == batch)
                    {
                        return Err(ConditionalBackendError::InvalidRecord);
                    }
                }
                ConditionalChange::Consolidate { batch_id, .. } => {
                    let record = self
                        .conditional_batch(batch_id)
                        .ok_or(ConditionalBackendError::UnknownBatch)?;
                    if record.lifecycle != ConditionalBatchLifecycle::Armed
                        || proposal.settlement.capability
                            != MultiAssetSettlementCapability::Ordinary
                    {
                        return Err(ConditionalBackendError::InvalidRecord);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn conditional_batch(&self, batch_id: &Bytes32) -> Option<&ConditionalBatchRecord> {
        self.records
            .iter()
            .find(|record| &record.batch.batch_id == batch_id)
    }

    fn settled_engine(&self, backend: &MultiAssetChannelBackend) -> ConditionalBackendResult<()> {
        self.validate(backend)?;
        if self.pending.is_some()
            || backend.proposal().is_some()
            || backend.reservation().state_number != backend.current().state.header.state_number
            || backend.reservation().signing_digest != backend.current().state.signing_digest()?
        {
            return Err(ConditionalBackendError::UnresolvedAuthority);
        }
        Ok(())
    }

    pub fn prepare_conditional_batch(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
        batch: ConditionalBatch,
        batch_code_hash: Bytes32,
        batch_hash_type: u8,
        armed_at_block: u64,
    ) -> ConditionalBackendResult<MultiAssetProposal> {
        self.settled_engine(backend)?;
        if self
            .records
            .iter()
            .any(|record| record.is_active() || record.batch.batch_id == batch.batch_id)
            || backend.current().settlement.capability != MultiAssetSettlementCapability::Ordinary
        {
            return Err(ConditionalBackendError::BatchActive);
        }
        batch.validate()?;
        let number = backend
            .current()
            .state
            .header
            .state_number
            .checked_add(1)
            .ok_or(ConditionalBackendError::InvalidRecord)?;
        if batch.transfers.is_empty()
            || batch.batch_id
                != derive_conditional_batch_id(
                    &self.channel_id,
                    &self.funding_context_id,
                    number,
                    &batch.application_context_commitment,
                )
        {
            return Err(ConditionalBackendError::BatchMismatch);
        }
        let mut settlement = backend.current().settlement.clone();
        let ckb = settlement
            .payouts
            .iter_mut()
            .find(|payout| payout.asset == VaultAsset::Ckb)
            .ok_or(ConditionalBackendError::CkbVaultRequired)?;
        for transfer in &batch.transfers {
            let payer = settlement
                .participant_lock_hashes
                .iter()
                .position(|lock| *lock == transfer.payer_lock_hash)
                .ok_or(ConditionalBackendError::BatchMismatch)?;
            ckb.values[payer].business_ckb = ckb.values[payer]
                .business_ckb
                .checked_sub(transfer.amount)
                .ok_or(ConditionalBackendError::InsufficientBusinessBalance)?;
        }
        for index in 0..2 {
            if batch.participants[index].settlement_lock_hash
                != settlement.participant_lock_hashes[index]
                || batch.participants[index].settled_capacity != ckb.values[index].capacity()?
            {
                return Err(ConditionalBackendError::BatchMismatch);
            }
        }
        settlement.capability = MultiAssetSettlementCapability::CkbConditional {
            batch_code_hash,
            batch_hash_type,
            batch: Box::new(batch.clone()),
        };
        let proposal = backend.propose(settlement)?;
        self.pending = Some(ConditionalChange::Arm {
            batch,
            armed_at_block,
            proposal: proposal.clone(),
        });
        Ok(proposal)
    }

    /// Commit only the exact pending capability change through the shared
    /// engine. Its two signatures and reserve-before-sign rules are mandatory.
    pub fn commit_change(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
    ) -> ConditionalBackendResult<()> {
        self.validate(backend)?;
        let change = self
            .pending
            .clone()
            .ok_or(ConditionalBackendError::NoPendingChange)?;
        let proposal = change.proposal();
        if backend.current().state != proposal.state
            || backend.current().settlement != proposal.settlement
        {
            if backend.current().state.signing_digest()? != proposal.base_state_digest
                || backend.proposal() != Some(proposal)
            {
                return Err(ConditionalBackendError::UnresolvedAuthority);
            }
            backend.commit()?;
        }
        match change {
            ConditionalChange::Arm {
                batch,
                armed_at_block,
                proposal,
            } => self.records.push(ConditionalBatchRecord {
                batch,
                armed_at_block,
                armed_state_number: proposal.state.header.state_number,
                preimages: vec![],
                lifecycle: ConditionalBatchLifecycle::Armed,
            }),
            ConditionalChange::Consolidate { batch_id, proposal } => {
                self.records
                    .iter_mut()
                    .find(|record| record.batch.batch_id == batch_id)
                    .ok_or(ConditionalBackendError::UnknownBatch)?
                    .lifecycle = ConditionalBatchLifecycle::CooperativeSettled {
                    state_number: proposal.state.header.state_number,
                };
            }
        }
        self.pending = None;
        Ok(())
    }

    pub fn cancel_pending_change(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
    ) -> ConditionalBackendResult<()> {
        self.validate(backend)?;
        let proposal = self
            .pending
            .as_ref()
            .ok_or(ConditionalBackendError::NoPendingChange)?
            .proposal();
        if backend.proposal() != Some(proposal)
            || backend.current().state.signing_digest()? != proposal.base_state_digest
        {
            return Err(ConditionalBackendError::UnresolvedAuthority);
        }
        if backend.reservation().state_number >= proposal.state.header.state_number
            || !backend.signatures().is_empty()
        {
            return Err(ConditionalBackendError::UnresolvedAuthority);
        }
        backend.cancel_proposal();
        self.pending = None;
        Ok(())
    }

    pub fn learn_conditional_preimage(
        &mut self,
        batch_id: &Bytes32,
        transfer_id: &Bytes32,
        preimage: Bytes32,
    ) -> ConditionalBackendResult<()> {
        let record = self
            .records
            .iter_mut()
            .find(|record| &record.batch.batch_id == batch_id)
            .ok_or(ConditionalBackendError::UnknownBatch)?;
        if !record.is_active() {
            return Err(ConditionalBackendError::BatchInactive);
        }
        let transfer = record
            .batch
            .transfers
            .iter()
            .find(|transfer| &transfer.transfer_id == transfer_id)
            .ok_or(ConditionalBackendError::UnknownTransfer)?;
        if crate::derive_conditional_payment_hash(transfer.hash_algorithm, &preimage)?
            != transfer.payment_hash
        {
            return Err(ConditionalBackendError::WrongPreimage);
        }
        if let Some(existing) = record
            .preimages
            .iter()
            .find(|entry| &entry.transfer_id == transfer_id)
        {
            return if existing.preimage == preimage {
                Ok(())
            } else {
                Err(ConditionalBackendError::WrongPreimage)
            };
        }
        record.preimages.push(ConditionalPreimage {
            transfer_id: *transfer_id,
            preimage,
        });
        record.preimages.sort_by_key(|entry| entry.transfer_id);
        Ok(())
    }

    pub fn prepare_cooperative_consolidation(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
        batch_id: &Bytes32,
    ) -> ConditionalBackendResult<MultiAssetProposal> {
        self.settled_engine(backend)?;
        let record = self
            .conditional_batch(batch_id)
            .ok_or(ConditionalBackendError::UnknownBatch)?;
        self.require_armed_current(backend, record)?;
        if record.lifecycle != ConditionalBatchLifecycle::Armed {
            return Err(ConditionalBackendError::BatchInactive);
        }
        let capacities = record
            .batch
            .cooperative_capacities(&record.preimage_map())?;
        let mut settlement = backend.current().settlement.clone();
        let ckb = settlement
            .payouts
            .iter_mut()
            .find(|payout| payout.asset == VaultAsset::Ckb)
            .ok_or(ConditionalBackendError::CkbVaultRequired)?;
        for (value, capacity) in ckb.values.iter_mut().zip(capacities) {
            value.business_ckb = capacity
                .checked_sub(value.reserve)
                .ok_or(ConditionalBackendError::InsufficientBusinessBalance)?;
        }
        settlement.capability = MultiAssetSettlementCapability::Ordinary;
        let proposal = backend.propose(settlement)?;
        self.pending = Some(ConditionalChange::Consolidate {
            batch_id: *batch_id,
            proposal: proposal.clone(),
        });
        Ok(proposal)
    }

    fn require_armed_current(
        &self,
        backend: &MultiAssetChannelBackend,
        record: &ConditionalBatchRecord,
    ) -> ConditionalBackendResult<()> {
        match &backend.current().settlement.capability {
            MultiAssetSettlementCapability::CkbConditional { batch, .. }
                if batch.as_ref() == &record.batch
                    && backend.current().state.header.state_number == record.armed_state_number =>
            {
                Ok(())
            }
            _ => Err(ConditionalBackendError::BatchInactive),
        }
    }

    pub fn begin_conditional_force_resolution(
        &mut self,
        backend: &MultiAssetChannelBackend,
        batch_id: &Bytes32,
        current_block: u64,
    ) -> ConditionalBackendResult<ConditionalForceClosePackage> {
        self.validate(backend)?;
        if self.pending.is_some() || backend.proposal().is_some() {
            return Err(ConditionalBackendError::UnresolvedAuthority);
        }
        let record = self
            .conditional_batch(batch_id)
            .ok_or(ConditionalBackendError::UnknownBatch)?;
        self.require_armed_current(backend, record)?;
        if !record.is_active() {
            return Err(ConditionalBackendError::BatchInactive);
        }
        let known = record.preimage_map();
        let mut resolutions = BTreeMap::new();
        let mut required_refund_block = 0;
        for transfer in &record.batch.transfers {
            let resolution = match known.get(&transfer.transfer_id) {
                Some(preimage) => ConditionalResolution::Fulfill {
                    preimage: *preimage,
                },
                None if current_block >= transfer.refund_after_block => {
                    required_refund_block = required_refund_block.max(transfer.refund_after_block);
                    ConditionalResolution::Refund
                }
                None => return Err(ConditionalBackendError::TransferPending),
            };
            resolutions.insert(transfer.transfer_id, resolution);
        }
        let input_since = morph_script_common::absolute_block_since(required_refund_block)
            .map_err(|_| ConditionalBackendError::TransferPending)?;
        let result = ConditionalForceClosePackage {
            batch_id: *batch_id,
            armed_state_number: record.armed_state_number,
            descriptor: record.batch.encode_descriptor()?.to_vec(),
            resolution_witness: record
                .batch
                .encode_resolution_witness(&resolutions)?
                .to_vec(),
            input_since,
            payout_capacities: record.batch.resolve(&resolutions, input_since)?,
        };
        self.records
            .iter_mut()
            .find(|record| &record.batch.batch_id == batch_id)
            .ok_or(ConditionalBackendError::UnknownBatch)?
            .lifecycle = ConditionalBatchLifecycle::ForceClosing;
        Ok(result)
    }

    /// The caller supplies the canonically confirmed Batch spend, not mere
    /// submission success. Chain reconciliation remains outside this metadata.
    pub fn confirm_conditional_force_settlement(
        &mut self,
        batch_id: &Bytes32,
        settlement_tx: Bytes32,
    ) -> ConditionalBackendResult<()> {
        if settlement_tx == [0; 32] {
            return Err(ConditionalBackendError::InvalidRecord);
        }
        let record = self
            .records
            .iter_mut()
            .find(|record| &record.batch.batch_id == batch_id)
            .ok_or(ConditionalBackendError::UnknownBatch)?;
        if record.lifecycle != ConditionalBatchLifecycle::ForceClosing {
            return Err(ConditionalBackendError::BatchInactive);
        }
        record.lifecycle = ConditionalBatchLifecycle::ForceSettled { settlement_tx };
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConditionalBackendError {
    #[error("conditional metadata belongs to another funding context")]
    WrongContext,
    #[error("conditional metadata is inconsistent")]
    InvalidRecord,
    #[error("an active or reused batch prevents arming another batch")]
    BatchActive,
    #[error("batch terms do not match the exact current allocation")]
    BatchMismatch,
    #[error("conditional capability requires a funded plain CKB Vault")]
    CkbVaultRequired,
    #[error("pending transfers exceed spendable business CKB")]
    InsufficientBusinessBalance,
    #[error("unknown conditional batch")]
    UnknownBatch,
    #[error("unknown conditional transfer")]
    UnknownTransfer,
    #[error("preimage does not satisfy the transfer")]
    WrongPreimage,
    #[error("batch is not active at the exact current signed state")]
    BatchInactive,
    #[error("transfer is neither fulfilled nor mature for refund")]
    TransferPending,
    #[error("pending or issued signing authority must be reconciled first")]
    UnresolvedAuthority,
    #[error("no conditional change is pending")]
    NoPendingChange,
    #[error(transparent)]
    Conditional(#[from] ConditionalError),
    #[error(transparent)]
    Agreement(#[from] MultiAssetBackendError),
    #[error(transparent)]
    Evidence(#[from] MultiAssetError),
}

pub type ConditionalBackendResult<T> = Result<T, ConditionalBackendError>;
