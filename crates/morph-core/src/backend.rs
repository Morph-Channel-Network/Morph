//! Native bilateral ChannelBackend built on the existing Morph State/Vault
//! model. It does not introduce a second channel state machine.

use std::collections::{BTreeMap, BTreeSet};

use morph_script_common::{
    BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN, BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_LEN,
    BilateralCkbConditionalDescriptor, BilateralCkbSettlementDescriptor,
    BilateralCkbXudtSettlementDescriptor, absolute_block_since, settlement_descriptor_commitment,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent::{
    AgentAsset, BackendSettlementEvidence, MorphStateSettlementEvidence, PaymentIntent,
};
use crate::validation::{MorphError, validate_state_authorization, validate_state_transition};
use crate::{
    AssetRegistry, Bytes32, ConditionalBatch, ConditionalError, ConditionalResolution, Phase,
    StateAuthorization, StateCell, StateTransitionContext, asset_registry_commitment, blake2b256,
    derive_conditional_batch_id,
};

const PREPARED_PAYMENT_DOMAIN: &[u8] = b"CKB_MORPH_PREPARED_PAYMENT_V1";
const SETTLEMENT_ID_DOMAIN: &[u8] = b"CKB_MORPH_BACKEND_SETTLEMENT_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelParticipant {
    pub node_id: Bytes32,
    pub settlement_lock_hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPayment {
    pub prepared_id: Bytes32,
    pub intent: PaymentIntent,
    pub base_state_number: u64,
    pub prepared_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendPaymentState {
    Prepared(PreparedPayment),
    Settled(BackendSettlementEvidence),
    Cancelled(BackendSettlementEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConditionalBatchLifecycle {
    Armed,
    ForceClosing,
    CooperativeSettled { state_number: u64 },
    ForceSettled { settlement_tx: Bytes32 },
}

impl ConditionalBatchLifecycle {
    const fn is_active(&self) -> bool {
        matches!(self, Self::Armed | Self::ForceClosing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalBatchRecord {
    pub batch: ConditionalBatch,
    pub armed_state_number: u64,
    pub armed_at_block: u64,
    pub preimages: BTreeMap<Bytes32, Bytes32>,
    pub lifecycle: ConditionalBatchLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalForceClosePackage {
    pub batch_id: Bytes32,
    pub armed_state_number: u64,
    pub descriptor: Vec<u8>,
    pub resolution_witness: Vec<u8>,
    pub input_since: u64,
    pub payout_capacities: [u64; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphSignedStateUpdate {
    pub next_state: StateCell,
    pub context: StateTransitionContext,
    /// Exact descriptor whose commitment is carried by `next_state`.
    pub settlement_descriptor: Vec<u8>,
}

/// Interface consumed by Morph Agent and routing adapters. Implementations are
/// required to return canonical backend evidence rather than an RPC success
/// boolean.
pub trait ChannelBackend {
    fn backend_id(&self) -> &'static str;
    fn channel_id(&self) -> Bytes32;
    fn funding_context_id(&self) -> Bytes32;
    fn current_state(&self) -> &StateCell;
    fn payment_state(&self, intent_id: &Bytes32) -> Option<&BackendPaymentState>;
    fn prepare_payment(
        &mut self,
        intent: PaymentIntent,
        now_unix: u64,
    ) -> BackendResult<PreparedPayment>;
    fn commit_payment(
        &mut self,
        prepared_id: &Bytes32,
        update: MorphSignedStateUpdate,
        committed_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence>;
    fn cancel_payment(
        &mut self,
        prepared_id: &Bytes32,
        cancelled_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MorphBilateralChannelBackend {
    current_state: StateCell,
    current_authorization: StateAuthorization,
    current_settlement_descriptor: Vec<u8>,
    participants: [ChannelParticipant; 2],
    asset_registry: AssetRegistry,
    verified_rgbpp_bindings: BTreeSet<Bytes32>,
    payments: BTreeMap<Bytes32, BackendPaymentState>,
    idempotency_index: BTreeMap<Bytes32, Bytes32>,
    conditional_batches: BTreeMap<Bytes32, ConditionalBatchRecord>,
}

impl MorphBilateralChannelBackend {
    pub fn new(
        current_state: StateCell,
        current_authorization: StateAuthorization,
        current_settlement_descriptor: Vec<u8>,
        participants: [ChannelParticipant; 2],
        asset_registry: AssetRegistry,
        verified_rgbpp_bindings: BTreeSet<Bytes32>,
    ) -> BackendResult<Self> {
        if !matches!(current_state.header.phase, Phase::Active | Phase::Settling)
            || participants[0].node_id == participants[1].node_id
            || participants[0].settlement_lock_hash == participants[1].settlement_lock_hash
            || participants.iter().any(|participant| {
                is_zero(&participant.node_id) || is_zero(&participant.settlement_lock_hash)
            })
        {
            return Err(BackendError::InvalidChannel);
        }
        validate_state_authorization(&current_state.header, &current_authorization)?;
        if current_state.header.asset_registry_commitment
            != asset_registry_commitment(&asset_registry)
        {
            return Err(BackendError::AssetRegistryMismatch);
        }
        validate_participant_identities(&current_authorization, &participants)?;
        validate_descriptor_commitment(&current_state, &current_settlement_descriptor)?;
        validate_descriptor_locks(&current_settlement_descriptor, &participants)?;
        if verified_rgbpp_bindings.iter().any(is_zero) {
            return Err(BackendError::InvalidRgbppEvidence);
        }
        Ok(Self {
            current_state,
            current_authorization,
            current_settlement_descriptor,
            participants,
            asset_registry,
            verified_rgbpp_bindings,
            payments: BTreeMap::new(),
            idempotency_index: BTreeMap::new(),
            conditional_batches: BTreeMap::new(),
        })
    }

    pub fn current_authorization(&self) -> &StateAuthorization {
        &self.current_authorization
    }

    pub fn current_settlement_descriptor(&self) -> &[u8] {
        &self.current_settlement_descriptor
    }

    pub fn register_verified_rgbpp_binding(&mut self, commitment: Bytes32) -> BackendResult<()> {
        if is_zero(&commitment) {
            return Err(BackendError::InvalidRgbppEvidence);
        }
        self.verified_rgbpp_bindings.insert(commitment);
        Ok(())
    }

    pub fn conditional_batch(&self, batch_id: &Bytes32) -> Option<&ConditionalBatchRecord> {
        self.conditional_batches.get(batch_id)
    }

    pub fn arm_conditional_batch(
        &mut self,
        batch: ConditionalBatch,
        update: MorphSignedStateUpdate,
        armed_at_block: u64,
    ) -> BackendResult<&ConditionalBatchRecord> {
        if self.conditional_batches.contains_key(&batch.batch_id) {
            return Err(BackendError::ConditionalBatchAlreadyActive);
        }
        if self
            .payments
            .values()
            .any(|state| matches!(state, BackendPaymentState::Prepared(_)))
        {
            return Err(BackendError::ConcurrentPreparationUnsupported);
        }
        if self
            .conditional_batches
            .values()
            .any(|record| record.lifecycle.is_active())
        {
            return Err(BackendError::ConditionalBatchAlreadyActive);
        }
        let current_descriptor = match parse_descriptor(&self.current_settlement_descriptor)? {
            ParsedDescriptor::Conditional(descriptor) if descriptor.transfer_count() == 0 => {
                descriptor
            }
            _ => return Err(BackendError::ConditionalProfileRequired),
        };
        let descriptor = batch.encode_descriptor()?;
        let expected_batch_id = derive_conditional_batch_id(
            &self.current_state.header.channel_id,
            &self.funding_context_id(),
            update.next_state.header.state_number,
            &batch.application_context_commitment,
        );
        if batch.batch_id != expected_batch_id {
            return Err(BackendError::ConditionalBatchMismatch);
        }
        let parsed = BilateralCkbConditionalDescriptor::parse(&descriptor)
            .map_err(|_| BackendError::InvalidSettlementDescriptor)?;
        if update.settlement_descriptor != descriptor
            || update.next_state.header.descriptor_version
                != BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION
            || update.next_state.header.settlement_descriptor_commitment
                != settlement_descriptor_commitment(&descriptor)
            || parsed
                .checked_total_capacity()
                .map_err(|_| BackendError::ConditionalBatchMismatch)?
                != current_descriptor
                    .checked_total_capacity()
                    .map_err(|_| BackendError::ConditionalBatchMismatch)?
        {
            return Err(BackendError::ConditionalBatchMismatch);
        }
        validate_conditional_participant_locks(&parsed, &self.participants)?;
        if update.context.asset_registry != self.asset_registry {
            return Err(BackendError::AssetRegistryMismatch);
        }
        validate_participant_identities(&update.context.authorization, &self.participants)?;
        validate_state_transition(&self.current_state, &update.next_state, &update.context)?;

        let batch_id = batch.batch_id;
        let record = ConditionalBatchRecord {
            batch,
            armed_state_number: update.next_state.header.state_number,
            armed_at_block,
            preimages: BTreeMap::new(),
            lifecycle: ConditionalBatchLifecycle::Armed,
        };
        self.current_authorization = update.context.authorization;
        self.current_settlement_descriptor = update.settlement_descriptor;
        self.current_state = update.next_state;
        self.conditional_batches.insert(batch_id, record);
        self.conditional_batches
            .get(&batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)
    }

    pub fn record_conditional_preimage(
        &mut self,
        batch_id: &Bytes32,
        transfer_id: &Bytes32,
        preimage: Bytes32,
    ) -> BackendResult<()> {
        let record = self
            .conditional_batches
            .get_mut(batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)?;
        if !record.lifecycle.is_active() {
            return Err(BackendError::ConditionalBatchNotActive);
        }
        let transfer = record
            .batch
            .transfers
            .iter()
            .find(|transfer| &transfer.transfer_id == transfer_id)
            .ok_or(BackendError::ConditionalTransferNotFound)?;
        let actual = crate::derive_conditional_payment_hash(transfer.hash_algorithm, &preimage)?;
        if actual != transfer.payment_hash {
            return Err(BackendError::ConditionalPreimageMismatch);
        }
        if let Some(existing) = record.preimages.get(transfer_id) {
            if existing != &preimage {
                return Err(BackendError::ConditionalPreimageMismatch);
            }
            return Ok(());
        }
        record.preimages.insert(*transfer_id, preimage);
        Ok(())
    }

    pub fn begin_conditional_force_resolution(
        &mut self,
        batch_id: &Bytes32,
        current_block: u64,
    ) -> BackendResult<ConditionalForceClosePackage> {
        let record = self
            .conditional_batches
            .get(batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)?
            .clone();
        if !record.lifecycle.is_active()
            || self.current_state.header.state_number != record.armed_state_number
        {
            return Err(BackendError::ConditionalBatchNotActive);
        }
        let mut resolutions = BTreeMap::new();
        let mut required_refund_block = 0u64;
        for transfer in &record.batch.transfers {
            let resolution = if let Some(preimage) = record.preimages.get(&transfer.transfer_id) {
                ConditionalResolution::Fulfill {
                    preimage: *preimage,
                }
            } else {
                if current_block < transfer.refund_after_block {
                    return Err(BackendError::ConditionalTransferPending);
                }
                required_refund_block = required_refund_block.max(transfer.refund_after_block);
                ConditionalResolution::Refund
            };
            resolutions.insert(transfer.transfer_id, resolution);
        }
        let input_since = absolute_block_since(required_refund_block)
            .map_err(|_| BackendError::ConditionalTransferPending)?;
        let descriptor = record.batch.encode_descriptor()?.to_vec();
        let resolution_witness = record
            .batch
            .encode_resolution_witness(&resolutions)?
            .to_vec();
        let payout_capacities = record.batch.resolve(&resolutions, input_since)?;
        let stored = self
            .conditional_batches
            .get_mut(batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)?;
        stored.lifecycle = ConditionalBatchLifecycle::ForceClosing;
        Ok(ConditionalForceClosePackage {
            batch_id: *batch_id,
            armed_state_number: record.armed_state_number,
            descriptor,
            resolution_witness,
            input_since,
            payout_capacities,
        })
    }

    pub fn confirm_conditional_force_settlement(
        &mut self,
        batch_id: &Bytes32,
        settlement_tx: Bytes32,
    ) -> BackendResult<()> {
        if is_zero(&settlement_tx) {
            return Err(BackendError::ConditionalSettlementIdInvalid);
        }
        let record = self
            .conditional_batches
            .get_mut(batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)?;
        if !matches!(record.lifecycle, ConditionalBatchLifecycle::ForceClosing) {
            return Err(BackendError::ConditionalBatchNotActive);
        }
        record.lifecycle = ConditionalBatchLifecycle::ForceSettled { settlement_tx };
        Ok(())
    }

    pub fn cooperatively_settle_conditional_batch(
        &mut self,
        batch_id: &Bytes32,
        final_batch: ConditionalBatch,
        update: MorphSignedStateUpdate,
    ) -> BackendResult<()> {
        let record = self
            .conditional_batches
            .get(batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)?
            .clone();
        if !matches!(record.lifecycle, ConditionalBatchLifecycle::Armed)
            || self.current_state.header.state_number != record.armed_state_number
            || final_batch.batch_id != record.batch.batch_id
            || final_batch.application_context_commitment
                != record.batch.application_context_commitment
            || !final_batch.transfers.is_empty()
        {
            return Err(BackendError::ConditionalBatchMismatch);
        }
        let expected = record.batch.cooperative_capacities(&record.preimages)?;
        let descriptor = final_batch.encode_descriptor()?;
        let parsed = BilateralCkbConditionalDescriptor::parse(&descriptor)
            .map_err(|_| BackendError::InvalidSettlementDescriptor)?;
        validate_conditional_participant_locks(&parsed, &self.participants)?;
        if [parsed.settled_capacity(0), parsed.settled_capacity(1)] != expected
            || update.settlement_descriptor != descriptor
            || update.next_state.header.descriptor_version
                != BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION
            || update.next_state.header.settlement_descriptor_commitment
                != settlement_descriptor_commitment(&descriptor)
        {
            return Err(BackendError::ConditionalBatchMismatch);
        }
        if update.context.asset_registry != self.asset_registry {
            return Err(BackendError::AssetRegistryMismatch);
        }
        validate_participant_identities(&update.context.authorization, &self.participants)?;
        validate_state_transition(&self.current_state, &update.next_state, &update.context)?;
        let settled_state_number = update.next_state.header.state_number;
        self.current_authorization = update.context.authorization;
        self.current_settlement_descriptor = update.settlement_descriptor;
        self.current_state = update.next_state;
        self.conditional_batches
            .get_mut(batch_id)
            .ok_or(BackendError::ConditionalBatchNotFound)?
            .lifecycle = ConditionalBatchLifecycle::CooperativeSettled {
            state_number: settled_state_number,
        };
        Ok(())
    }

    fn prepared_by_id(&self, prepared_id: &Bytes32) -> BackendResult<&PreparedPayment> {
        self.payments
            .values()
            .find_map(|state| match state {
                BackendPaymentState::Prepared(prepared) if &prepared.prepared_id == prepared_id => {
                    Some(prepared)
                }
                _ => None,
            })
            .ok_or(BackendError::PreparedPaymentNotFound)
    }

    fn validate_intent_asset(&self, intent: &PaymentIntent) -> BackendResult<()> {
        let ckb_genesis_hash = match &intent.asset {
            AgentAsset::Ckb { ckb_genesis_hash }
            | AgentAsset::Xudt {
                ckb_genesis_hash, ..
            } => ckb_genesis_hash,
            AgentAsset::Rgbpp(asset) => &asset.ckb_genesis_hash,
        };
        if ckb_genesis_hash != &self.current_state.header.chain_id {
            return Err(BackendError::WrongNetwork);
        }
        match &intent.asset {
            AgentAsset::Ckb { .. } => {}
            AgentAsset::Xudt {
                type_script_hash, ..
            } => {
                if !self.asset_registry.contains(type_script_hash) {
                    return Err(BackendError::AssetNotRegistered);
                }
            }
            AgentAsset::Rgbpp(asset) => {
                if !self.asset_registry.contains(&asset.xudt_type_script_hash) {
                    return Err(BackendError::AssetNotRegistered);
                }
                let commitment = intent
                    .required_rgbpp_proof_commitment
                    .ok_or(BackendError::InvalidRgbppEvidence)?;
                if !self.verified_rgbpp_bindings.contains(&commitment) {
                    return Err(BackendError::InvalidRgbppEvidence);
                }
            }
        }
        Ok(())
    }
}

impl ChannelBackend for MorphBilateralChannelBackend {
    fn backend_id(&self) -> &'static str {
        "morph-bilateral-v1"
    }

    fn channel_id(&self) -> Bytes32 {
        self.current_state.header.channel_id
    }

    fn funding_context_id(&self) -> Bytes32 {
        self.current_state.header.funding_context_id()
    }

    fn current_state(&self) -> &StateCell {
        &self.current_state
    }

    fn payment_state(&self, intent_id: &Bytes32) -> Option<&BackendPaymentState> {
        self.payments.get(intent_id)
    }

    fn prepare_payment(
        &mut self,
        intent: PaymentIntent,
        now_unix: u64,
    ) -> BackendResult<PreparedPayment> {
        intent.validate(now_unix)?;
        if !matches!(
            self.current_state.header.phase,
            Phase::Active | Phase::Settling
        ) {
            return Err(BackendError::InvalidChannel);
        }
        if matches!(
            parse_descriptor(&self.current_settlement_descriptor)?,
            ParsedDescriptor::Conditional(_)
        ) {
            return Err(BackendError::ConditionalBatchRequired);
        }
        let binding = intent
            .channel_binding
            .as_ref()
            .ok_or(BackendError::MissingChannelBinding)?;
        if binding.channel_id != self.channel_id()
            || binding.funding_context_id != self.funding_context_id()
        {
            return Err(BackendError::WrongChannelBinding);
        }
        self.validate_intent_asset(&intent)?;

        if let Some(existing_intent_id) = self.idempotency_index.get(&intent.idempotency_key) {
            if existing_intent_id != &intent.intent_id {
                return Err(BackendError::IdempotencyConflict);
            }
            return match self.payments.get(existing_intent_id) {
                Some(BackendPaymentState::Prepared(prepared)) => Ok(prepared.clone()),
                _ => Err(BackendError::AlreadyTerminal),
            };
        }
        // The current bilateral wire profile signs one complete successor
        // descriptor at a time. Multiple simultaneous reservations would make
        // their expected descriptors mutually incompatible.
        if self
            .payments
            .values()
            .any(|state| matches!(state, BackendPaymentState::Prepared(_)))
        {
            return Err(BackendError::ConcurrentPreparationUnsupported);
        }
        let mut raw = Vec::with_capacity(PREPARED_PAYMENT_DOMAIN.len() + 72);
        raw.extend_from_slice(PREPARED_PAYMENT_DOMAIN);
        raw.extend_from_slice(&intent.intent_id);
        raw.extend_from_slice(&self.current_state.header.state_number.to_le_bytes());
        raw.extend_from_slice(&self.current_state.header.signing_digest());
        let prepared = PreparedPayment {
            prepared_id: blake2b256(&raw),
            intent: intent.clone(),
            base_state_number: self.current_state.header.state_number,
            prepared_at_unix: now_unix,
        };
        self.idempotency_index
            .insert(intent.idempotency_key, intent.intent_id);
        self.payments.insert(
            intent.intent_id,
            BackendPaymentState::Prepared(prepared.clone()),
        );
        Ok(prepared)
    }

    fn commit_payment(
        &mut self,
        prepared_id: &Bytes32,
        update: MorphSignedStateUpdate,
        committed_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence> {
        let prepared = self.prepared_by_id(prepared_id)?.clone();
        if committed_at_unix < prepared.prepared_at_unix
            || committed_at_unix >= prepared.intent.expires_at_unix
        {
            return Err(BackendError::InvalidCommitTime);
        }
        if prepared.base_state_number != self.current_state.header.state_number {
            return Err(BackendError::StalePreparation);
        }
        let binding = prepared
            .intent
            .channel_binding
            .as_ref()
            .ok_or(BackendError::MissingChannelBinding)?;
        if update.next_state.header.settlement_descriptor_commitment
            != binding.expected_settlement_descriptor_commitment
        {
            return Err(BackendError::WrongSettlementDescriptor);
        }
        validate_descriptor_commitment(&update.next_state, &update.settlement_descriptor)?;
        validate_descriptor_locks(&update.settlement_descriptor, &self.participants)?;
        validate_payment_delta(
            &self.current_settlement_descriptor,
            &update.settlement_descriptor,
            &self.participants,
            &prepared.intent,
        )?;
        if update.context.asset_registry != self.asset_registry {
            return Err(BackendError::AssetRegistryMismatch);
        }
        validate_participant_identities(&update.context.authorization, &self.participants)?;
        validate_state_transition(&self.current_state, &update.next_state, &update.context)?;

        let state_commitment = update.next_state.header.signing_digest();
        let mut settlement_raw = Vec::with_capacity(SETTLEMENT_ID_DOMAIN.len() + 96);
        settlement_raw.extend_from_slice(SETTLEMENT_ID_DOMAIN);
        settlement_raw.extend_from_slice(&prepared.intent.intent_id);
        settlement_raw.extend_from_slice(&state_commitment);
        settlement_raw.extend_from_slice(prepared_id);
        let evidence = BackendSettlementEvidence {
            provider_id: self.backend_id().to_string(),
            settlement_id: blake2b256(&settlement_raw),
            opaque_commitment: state_commitment,
            morph_state: Some(MorphStateSettlementEvidence {
                channel_id: update.next_state.header.channel_id,
                funding_context_id: update.next_state.header.funding_context_id(),
                state_number: update.next_state.header.state_number,
                state_header_commitment: state_commitment,
                settlement_descriptor_commitment: update
                    .next_state
                    .header
                    .settlement_descriptor_commitment,
            }),
            ckb_anchor: None,
            rgbpp_proof_commitment: prepared.intent.required_rgbpp_proof_commitment,
            failure_code: None,
        };
        self.current_authorization = update.context.authorization;
        self.current_settlement_descriptor = update.settlement_descriptor;
        self.current_state = update.next_state;
        self.payments.insert(
            prepared.intent.intent_id,
            BackendPaymentState::Settled(evidence.clone()),
        );
        Ok(evidence)
    }

    fn cancel_payment(
        &mut self,
        prepared_id: &Bytes32,
        cancelled_at_unix: u64,
    ) -> BackendResult<BackendSettlementEvidence> {
        let prepared = self.prepared_by_id(prepared_id)?.clone();
        if cancelled_at_unix < prepared.prepared_at_unix {
            return Err(BackendError::InvalidCancellationTime);
        }
        let mut raw = Vec::with_capacity(SETTLEMENT_ID_DOMAIN.len() + 81);
        raw.extend_from_slice(SETTLEMENT_ID_DOMAIN);
        raw.extend_from_slice(&prepared.intent.intent_id);
        raw.extend_from_slice(prepared_id);
        raw.extend_from_slice(&cancelled_at_unix.to_le_bytes());
        raw.extend_from_slice(b"cancelled");
        let commitment = blake2b256(&raw);
        let evidence = BackendSettlementEvidence {
            provider_id: self.backend_id().to_string(),
            settlement_id: commitment,
            opaque_commitment: commitment,
            morph_state: None,
            ckb_anchor: None,
            rgbpp_proof_commitment: None,
            failure_code: None,
        };
        self.payments.insert(
            prepared.intent.intent_id,
            BackendPaymentState::Cancelled(evidence.clone()),
        );
        Ok(evidence)
    }
}

fn validate_descriptor_commitment(state: &StateCell, descriptor: &[u8]) -> BackendResult<()> {
    parse_descriptor(descriptor)?;
    if settlement_descriptor_commitment(descriptor) != state.header.settlement_descriptor_commitment
    {
        return Err(BackendError::WrongSettlementDescriptor);
    }
    Ok(())
}

fn validate_descriptor_locks(
    descriptor: &[u8],
    participants: &[ChannelParticipant; 2],
) -> BackendResult<()> {
    let expected = [
        participants[0].settlement_lock_hash,
        participants[1].settlement_lock_hash,
    ];
    let actual = descriptor_locks(descriptor)?;
    if !expected.iter().all(|lock| actual.contains(lock)) {
        return Err(BackendError::WrongSettlementParticipants);
    }
    Ok(())
}

fn validate_payment_delta(
    old_descriptor: &[u8],
    new_descriptor: &[u8],
    participants: &[ChannelParticipant; 2],
    intent: &PaymentIntent,
) -> BackendResult<()> {
    let payer = participants
        .iter()
        .find(|participant| participant.node_id == intent.payer)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    let payee = participants
        .iter()
        .find(|participant| participant.node_id == intent.payee)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    let old = descriptor_amounts(old_descriptor, &intent.asset)?;
    let new = descriptor_amounts(new_descriptor, &intent.asset)?;
    let locks = descriptor_locks(old_descriptor)?;
    let payer_index = locks
        .iter()
        .position(|lock| lock == &payer.settlement_lock_hash)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    let payee_index = locks
        .iter()
        .position(|lock| lock == &payee.settlement_lock_hash)
        .ok_or(BackendError::WrongSettlementParticipants)?;
    if matches!(
        &intent.asset,
        AgentAsset::Xudt { .. } | AgentAsset::Rgbpp(_)
    ) && descriptor_capacities(old_descriptor)? != descriptor_capacities(new_descriptor)?
    {
        return Err(BackendError::UnrelatedAssetDelta);
    }
    let old_total = old[0]
        .checked_add(old[1])
        .ok_or(BackendError::PaymentDeltaMismatch)?;
    let new_total = new[0]
        .checked_add(new[1])
        .ok_or(BackendError::PaymentDeltaMismatch)?;
    if old[payer_index].checked_sub(intent.amount) != Some(new[payer_index])
        || old[payee_index].checked_add(intent.amount) != Some(new[payee_index])
        || old_total != new_total
    {
        return Err(BackendError::PaymentDeltaMismatch);
    }
    Ok(())
}

pub(crate) fn validate_participant_identities(
    authorization: &StateAuthorization,
    participants: &[ChannelParticipant; 2],
) -> BackendResult<()> {
    if authorization.threshold != 2 || authorization.signatures.len() != 2 {
        return Err(BackendError::WrongSettlementParticipants);
    }
    let mut signed_node_ids = authorization
        .signatures
        .iter()
        .map(|signature| blake2b256(&signature.pubkey_sec1))
        .collect::<Vec<_>>();
    signed_node_ids.sort();
    let mut configured_node_ids = participants
        .iter()
        .map(|participant| participant.node_id)
        .collect::<Vec<_>>();
    configured_node_ids.sort();
    if signed_node_ids != configured_node_ids {
        return Err(BackendError::WrongSettlementParticipants);
    }
    Ok(())
}

enum ParsedDescriptor<'a> {
    Ckb(BilateralCkbSettlementDescriptor<'a>),
    Xudt(BilateralCkbXudtSettlementDescriptor<'a>),
    Conditional(BilateralCkbConditionalDescriptor<'a>),
}

fn parse_descriptor(raw: &[u8]) -> BackendResult<ParsedDescriptor<'_>> {
    match raw.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => BilateralCkbSettlementDescriptor::parse(raw)
            .map(ParsedDescriptor::Ckb)
            .map_err(|_| BackendError::InvalidSettlementDescriptor),
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => BilateralCkbXudtSettlementDescriptor::parse(raw)
            .map(ParsedDescriptor::Xudt)
            .map_err(|_| BackendError::InvalidSettlementDescriptor),
        BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN => BilateralCkbConditionalDescriptor::parse(raw)
            .map(ParsedDescriptor::Conditional)
            .map_err(|_| BackendError::InvalidSettlementDescriptor),
        _ => Err(BackendError::InvalidSettlementDescriptor),
    }
}

fn descriptor_locks(raw: &[u8]) -> BackendResult<[Bytes32; 2]> {
    let parsed = parse_descriptor(raw)?;
    let lock = |index| -> BackendResult<Bytes32> {
        let bytes = match &parsed {
            ParsedDescriptor::Ckb(descriptor) => descriptor.lock_hash(index),
            ParsedDescriptor::Xudt(descriptor) => descriptor.lock_hash(index),
            ParsedDescriptor::Conditional(descriptor) => descriptor.lock_hash(index),
        };
        bytes
            .try_into()
            .map_err(|_| BackendError::InvalidSettlementDescriptor)
    };
    Ok([lock(0)?, lock(1)?])
}

fn descriptor_amounts(raw: &[u8], asset: &AgentAsset) -> BackendResult<[u128; 2]> {
    match (parse_descriptor(raw)?, asset) {
        (ParsedDescriptor::Ckb(descriptor), AgentAsset::Ckb { .. }) => Ok([
            u128::from(descriptor.capacity(0)),
            u128::from(descriptor.capacity(1)),
        ]),
        (
            ParsedDescriptor::Xudt(descriptor),
            AgentAsset::Xudt {
                type_script_hash, ..
            },
        ) => {
            if descriptor.xudt_type_hash() != type_script_hash {
                return Err(BackendError::AssetMismatch);
            }
            Ok([descriptor.xudt_amount(0), descriptor.xudt_amount(1)])
        }
        (ParsedDescriptor::Xudt(descriptor), AgentAsset::Rgbpp(asset)) => {
            if descriptor.xudt_type_hash() != asset.xudt_type_script_hash {
                return Err(BackendError::AssetMismatch);
            }
            Ok([descriptor.xudt_amount(0), descriptor.xudt_amount(1)])
        }
        (ParsedDescriptor::Conditional(_), _) => Err(BackendError::ConditionalBatchRequired),
        _ => Err(BackendError::AssetMismatch),
    }
}

fn descriptor_capacities(raw: &[u8]) -> BackendResult<[u64; 2]> {
    match parse_descriptor(raw)? {
        ParsedDescriptor::Ckb(descriptor) => Ok([descriptor.capacity(0), descriptor.capacity(1)]),
        ParsedDescriptor::Xudt(descriptor) => Ok([descriptor.capacity(0), descriptor.capacity(1)]),
        ParsedDescriptor::Conditional(_) => Err(BackendError::ConditionalBatchRequired),
    }
}

fn validate_conditional_participant_locks(
    descriptor: &BilateralCkbConditionalDescriptor<'_>,
    participants: &[ChannelParticipant; 2],
) -> BackendResult<()> {
    let mut expected = [
        participants[0].settlement_lock_hash,
        participants[1].settlement_lock_hash,
    ];
    expected.sort();
    if descriptor.lock_hash(0) != expected[0].as_slice()
        || descriptor.lock_hash(1) != expected[1].as_slice()
    {
        return Err(BackendError::WrongSettlementParticipants);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("Morph bilateral channel is invalid or not active")]
    InvalidChannel,
    #[error("payment intent does not bind a Morph channel")]
    MissingChannelBinding,
    #[error("payment intent binds another channel or funding context")]
    WrongChannelBinding,
    #[error("payment asset is not registered in the channel")]
    AssetNotRegistered,
    #[error("payment asset belongs to another CKB network")]
    WrongNetwork,
    #[error("RGB++ proof commitment is missing or not verified")]
    InvalidRgbppEvidence,
    #[error("another intent already uses this idempotency key")]
    IdempotencyConflict,
    #[error("payment intent is already terminal")]
    AlreadyTerminal,
    #[error("current bilateral profile permits one prepared successor at a time")]
    ConcurrentPreparationUnsupported,
    #[error("this channel uses the conditional-batch profile")]
    ConditionalBatchRequired,
    #[error("a descriptor-version-3 channel with no pending batch is required")]
    ConditionalProfileRequired,
    #[error("another conditional batch is already active or the batch id was reused")]
    ConditionalBatchAlreadyActive,
    #[error("conditional batch was not found")]
    ConditionalBatchNotFound,
    #[error("conditional batch is not active at the current signed state")]
    ConditionalBatchNotActive,
    #[error("conditional batch does not match the signed state or expected consolidation")]
    ConditionalBatchMismatch,
    #[error("conditional transfer was not found")]
    ConditionalTransferNotFound,
    #[error("conditional transfer preimage does not match")]
    ConditionalPreimageMismatch,
    #[error("at least one conditional transfer is neither fulfilled nor refundable")]
    ConditionalTransferPending,
    #[error("conditional force-settlement transaction id is invalid")]
    ConditionalSettlementIdInvalid,
    #[error("prepared payment was not found")]
    PreparedPaymentNotFound,
    #[error("prepared payment is stale relative to the current signed state")]
    StalePreparation,
    #[error("settlement descriptor is malformed")]
    InvalidSettlementDescriptor,
    #[error("settlement descriptor commitment does not match the payment or State header")]
    WrongSettlementDescriptor,
    #[error("settlement descriptor does not pay the channel participants")]
    WrongSettlementParticipants,
    #[error("settlement descriptor asset does not match the payment asset")]
    AssetMismatch,
    #[error("settlement descriptor delta does not match the payment amount and direction")]
    PaymentDeltaMismatch,
    #[error("settlement descriptor changes an asset outside the payment intent")]
    UnrelatedAssetDelta,
    #[error("state update uses a different asset registry")]
    AssetRegistryMismatch,
    #[error("cancellation time predates preparation")]
    InvalidCancellationTime,
    #[error("commit time predates preparation or is at/after intent expiry")]
    InvalidCommitTime,
    #[error(transparent)]
    Agent(#[from] crate::agent::AgentError),
    #[error(transparent)]
    Conditional(#[from] ConditionalError),
    #[error(transparent)]
    Morph(#[from] MorphError),
}

pub type BackendResult<T> = Result<T, BackendError>;

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use morph_script_common::{
        BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT, BILATERAL_CKB_DESCRIPTOR_VERSION,
        BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
    };

    use super::*;
    use crate::agent::{HttpOperation, MorphChannelPaymentBinding, PaymentHashAlgorithm};
    use crate::{ClassifiedCell, Mode, ParticipantSignature, PartitionedTransaction};

    fn descriptor(first_lock: Bytes32, first: u64, second_lock: Bytes32, second: u64) -> Vec<u8> {
        let mut entries = [(first_lock, first), (second_lock, second)];
        entries.sort_by_key(|entry| entry.0);
        let mut raw = vec![0; BILATERAL_CKB_DESCRIPTOR_LEN];
        raw[0..2].copy_from_slice(&BILATERAL_CKB_DESCRIPTOR_VERSION.to_le_bytes());
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        for (index, (lock, capacity)) in entries.iter().enumerate() {
            let offset = 4 + index * 40;
            raw[offset..offset + 32].copy_from_slice(lock);
            raw[offset + 32..offset + 40].copy_from_slice(&capacity.to_le_bytes());
        }
        raw
    }

    fn xudt_descriptor(
        type_hash: Bytes32,
        first_lock: Bytes32,
        first: u128,
        second_lock: Bytes32,
        second: u128,
    ) -> Vec<u8> {
        let mut entries = [(first_lock, first), (second_lock, second)];
        entries.sort_by_key(|entry| entry.0);
        let mut raw = vec![0; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN];
        raw[0..2].copy_from_slice(&BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION.to_le_bytes());
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT;
        raw[4..36].copy_from_slice(&type_hash);
        for (index, (lock, amount)) in entries.iter().enumerate() {
            let offset = 36 + index * 56;
            raw[offset..offset + 32].copy_from_slice(lock);
            raw[offset + 32..offset + 40].copy_from_slice(&1_000u64.to_le_bytes());
            raw[offset + 40..offset + 56].copy_from_slice(&amount.to_le_bytes());
        }
        raw
    }

    fn authorization(header: &crate::StateHeader, keys: &[SigningKey; 2]) -> StateAuthorization {
        let mut signatures = keys
            .iter()
            .map(|key| {
                let signature: Signature = key.sign_prehash(&header.signing_digest()).unwrap();
                ParticipantSignature {
                    pubkey_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .collect::<Vec<_>>();
        signatures.sort_by(|left, right| left.pubkey_sec1.cmp(&right.pubkey_sec1));
        StateAuthorization {
            threshold: 2,
            signatures,
        }
    }

    fn fixture() -> (
        MorphBilateralChannelBackend,
        [SigningKey; 2],
        [ChannelParticipant; 2],
    ) {
        let keys = [
            SigningKey::from_slice(&[1; 32]).unwrap(),
            SigningKey::from_slice(&[2; 32]).unwrap(),
        ];
        let mut pubkeys = keys
            .iter()
            .map(|key| {
                key.verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        pubkeys.sort();
        let participants_commitment =
            crate::participants_commitment(2, &[pubkeys[0].as_slice(), pubkeys[1].as_slice()]);
        let participants = [
            ChannelParticipant {
                node_id: blake2b256(keys[0].verifying_key().to_encoded_point(true).as_bytes()),
                settlement_lock_hash: [21; 32],
            },
            ChannelParticipant {
                node_id: blake2b256(keys[1].verifying_key().to_encoded_point(true).as_bytes()),
                settlement_lock_hash: [22; 32],
            },
        ];
        let descriptor = descriptor([21; 32], 6_000, [22; 32], 4_000);
        let state = StateCell {
            header: crate::StateHeader {
                protocol_version: 1,
                chain_id: [3; 32],
                signature_scheme_id: 1,
                channel_id: [4; 32],
                funding_epoch: 0,
                funding_anchor: [5; 32],
                vault_set_commitment: [6; 32],
                state_number: 0,
                mode: Mode::BilateralPlain,
                phase: Phase::Active,
                participants_commitment,
                asset_registry_commitment: asset_registry_commitment(&AssetRegistry {
                    xudt_types: BTreeSet::new(),
                }),
                settlement_descriptor_commitment: settlement_descriptor_commitment(&descriptor),
                descriptor_version: BILATERAL_CKB_DESCRIPTOR_VERSION,
                vault_materialisation_root: [8; 32],
                vault_outpoint_commitment: [10; 32],
                challenge_policy_commitment: [9; 32],
                state_layout_version: 1,
            },
            capacity: 1_000,
            occupied_capacity: 1_000,
        };
        let auth = authorization(&state.header, &keys);
        (
            MorphBilateralChannelBackend::new(
                state,
                auth,
                descriptor,
                participants.clone(),
                AssetRegistry {
                    xudt_types: BTreeSet::new(),
                },
                BTreeSet::new(),
            )
            .unwrap(),
            keys,
            participants,
        )
    }

    fn conditional_fixture() -> (
        MorphBilateralChannelBackend,
        [SigningKey; 2],
        [ChannelParticipant; 2],
    ) {
        let (base, keys, participants) = fixture();
        let empty = ConditionalBatch {
            batch_id: [40; 32],
            application_context_commitment: [41; 32],
            participants: [
                crate::ConditionalParticipant {
                    settlement_lock_hash: [21; 32],
                    settled_capacity: 6_000,
                },
                crate::ConditionalParticipant {
                    settlement_lock_hash: [22; 32],
                    settled_capacity: 4_000,
                },
            ],
            transfers: Vec::new(),
        };
        let descriptor = empty.encode_descriptor().unwrap().to_vec();
        let mut state = base.current_state.clone();
        state.header.descriptor_version = BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION;
        state.header.settlement_descriptor_commitment =
            settlement_descriptor_commitment(&descriptor);
        let auth = authorization(&state.header, &keys);
        (
            MorphBilateralChannelBackend::new(
                state,
                auth,
                descriptor,
                participants.clone(),
                AssetRegistry {
                    xudt_types: BTreeSet::new(),
                },
                BTreeSet::new(),
            )
            .unwrap(),
            keys,
            participants,
        )
    }

    fn pending_batch(backend: &MorphBilateralChannelBackend) -> (ConditionalBatch, [Bytes32; 2]) {
        let preimages = [[7; 32], [8; 32]];
        let application_context_commitment = [43; 32];
        (
            ConditionalBatch {
                batch_id: derive_conditional_batch_id(
                    &backend.channel_id(),
                    &backend.funding_context_id(),
                    backend.current_state.header.state_number + 1,
                    &application_context_commitment,
                ),
                application_context_commitment,
                participants: [
                    crate::ConditionalParticipant {
                        settlement_lock_hash: [21; 32],
                        settled_capacity: 5_500,
                    },
                    crate::ConditionalParticipant {
                        settlement_lock_hash: [22; 32],
                        settled_capacity: 3_700,
                    },
                ],
                transfers: vec![
                    crate::ConditionalTransferSpec {
                        transfer_id: [44; 32],
                        payer_lock_hash: [21; 32],
                        hash_algorithm: crate::ConditionalHashAlgorithm::Sha256,
                        payment_hash: crate::derive_conditional_payment_hash(
                            crate::ConditionalHashAlgorithm::Sha256,
                            &preimages[0],
                        )
                        .unwrap(),
                        amount: 500,
                        refund_after_block: 500,
                    },
                    crate::ConditionalTransferSpec {
                        transfer_id: [45; 32],
                        payer_lock_hash: [22; 32],
                        hash_algorithm: crate::ConditionalHashAlgorithm::CkbBlake2b,
                        payment_hash: crate::derive_conditional_payment_hash(
                            crate::ConditionalHashAlgorithm::CkbBlake2b,
                            &preimages[1],
                        )
                        .unwrap(),
                        amount: 300,
                        refund_after_block: 600,
                    },
                ],
            },
            preimages,
        )
    }

    fn conditional_update(
        backend: &MorphBilateralChannelBackend,
        keys: &[SigningKey; 2],
        batch: &ConditionalBatch,
    ) -> MorphSignedStateUpdate {
        let descriptor = batch.encode_descriptor().unwrap().to_vec();
        let mut signed = update(backend, keys, descriptor);
        signed.next_state.header.descriptor_version = BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION;
        signed.next_state.header.settlement_descriptor_commitment =
            settlement_descriptor_commitment(&signed.settlement_descriptor);
        signed.context.authorization = authorization(&signed.next_state.header, keys);
        signed
    }

    fn intent(backend: &MorphBilateralChannelBackend) -> PaymentIntent {
        let next_descriptor = descriptor([21; 32], 5_500, [22; 32], 4_500);
        let mut intent = PaymentIntent {
            intent_id: [0; 32],
            payer: backend.participants[0].node_id,
            payee: backend.participants[1].node_id,
            asset: AgentAsset::Ckb {
                ckb_genesis_hash: [3; 32],
            },
            amount: 500,
            payment_hash: [31; 32],
            hash_algorithm: PaymentHashAlgorithm::Sha256,
            resource: "/compute/result".to_string(),
            operation: HttpOperation::Get,
            nonce: [32; 32],
            idempotency_key: [33; 32],
            created_at_unix: 100,
            expires_at_unix: 200,
            required_rgbpp_proof_commitment: None,
            channel_binding: Some(MorphChannelPaymentBinding {
                channel_id: backend.channel_id(),
                funding_context_id: backend.funding_context_id(),
                expected_settlement_descriptor_commitment: settlement_descriptor_commitment(
                    &next_descriptor,
                ),
            }),
        };
        intent.intent_id = intent.derive_id().unwrap();
        intent
    }

    fn update(
        backend: &MorphBilateralChannelBackend,
        keys: &[SigningKey; 2],
        descriptor: Vec<u8>,
    ) -> MorphSignedStateUpdate {
        let mut next = backend.current_state.clone();
        next.header.state_number += 1;
        next.header.phase = Phase::Settling;
        next.header.settlement_descriptor_commitment =
            settlement_descriptor_commitment(&descriptor);
        let authorization = authorization(&next.header, keys);
        MorphSignedStateUpdate {
            next_state: next,
            context: StateTransitionContext {
                referenced_funding_anchor: backend.current_state.header.funding_anchor,
                authorization,
                asset_registry: AssetRegistry {
                    xudt_types: BTreeSet::new(),
                },
                partition: PartitionedTransaction {
                    inputs: vec![
                        ClassifiedCell::business_ckb(10_000, 1_000, 9_000),
                        ClassifiedCell::state_carrier(
                            backend.current_state.capacity,
                            backend.current_state.occupied_capacity,
                        ),
                    ],
                    outputs: vec![
                        ClassifiedCell::business_ckb(10_000, 1_000, 9_000),
                        ClassifiedCell::state_carrier(
                            backend.current_state.capacity,
                            backend.current_state.occupied_capacity,
                        ),
                    ],
                    tx_fee: 0,
                    authorised_reserve_refund: 0,
                },
            },
            settlement_descriptor: descriptor,
        }
    }

    #[test]
    fn signed_descriptor_delta_settles_exact_intent() {
        let (mut backend, keys, _) = fixture();
        let prepared = backend.prepare_payment(intent(&backend), 110).unwrap();
        let evidence = backend
            .commit_payment(
                &prepared.prepared_id,
                update(
                    &backend,
                    &keys,
                    descriptor([21; 32], 5_500, [22; 32], 4_500),
                ),
                120,
            )
            .unwrap();
        assert_eq!(evidence.provider_id, "morph-bilateral-v1");
        assert_eq!(evidence.morph_state.unwrap().state_number, 1);
    }

    #[test]
    fn signed_but_wrong_amount_descriptor_is_rejected() {
        let (mut backend, keys, _) = fixture();
        let mut intent = intent(&backend);
        let wrong_descriptor = descriptor([21; 32], 5_600, [22; 32], 4_400);
        intent
            .channel_binding
            .as_mut()
            .unwrap()
            .expected_settlement_descriptor_commitment =
            settlement_descriptor_commitment(&wrong_descriptor);
        intent.intent_id = intent.derive_id().unwrap();
        let prepared = backend.prepare_payment(intent, 110).unwrap();
        assert_eq!(
            backend.commit_payment(
                &prepared.prepared_id,
                update(&backend, &keys, wrong_descriptor),
                120,
            ),
            Err(BackendError::PaymentDeltaMismatch)
        );
    }

    #[test]
    fn commit_rejects_times_outside_the_prepared_intent_window() {
        let (mut backend, keys, _) = fixture();
        let prepared = backend.prepare_payment(intent(&backend), 110).unwrap();
        let signed_update = update(
            &backend,
            &keys,
            descriptor([21; 32], 5_500, [22; 32], 4_500),
        );

        assert_eq!(
            backend.commit_payment(&prepared.prepared_id, signed_update.clone(), 109),
            Err(BackendError::InvalidCommitTime)
        );
        assert_eq!(
            backend.commit_payment(&prepared.prepared_id, signed_update, 200),
            Err(BackendError::InvalidCommitTime)
        );
        assert!(matches!(
            backend.payment_state(&prepared.intent.intent_id),
            Some(BackendPaymentState::Prepared(_))
        ));
    }

    #[test]
    fn overflowing_xudt_totals_are_rejected_without_panicking() {
        let participants = [
            ChannelParticipant {
                node_id: [1; 32],
                settlement_lock_hash: [21; 32],
            },
            ChannelParticipant {
                node_id: [2; 32],
                settlement_lock_hash: [22; 32],
            },
        ];
        let intent = PaymentIntent {
            intent_id: [3; 32],
            payer: [1; 32],
            payee: [2; 32],
            asset: AgentAsset::Xudt {
                ckb_genesis_hash: [4; 32],
                type_script_hash: [5; 32],
            },
            amount: 1,
            payment_hash: [6; 32],
            hash_algorithm: PaymentHashAlgorithm::Sha256,
            resource: "/overflow".to_string(),
            operation: HttpOperation::Get,
            nonce: [7; 32],
            idempotency_key: [8; 32],
            created_at_unix: 1,
            expires_at_unix: 2,
            required_rgbpp_proof_commitment: None,
            channel_binding: None,
        };
        let old = xudt_descriptor([5; 32], [21; 32], u128::MAX, [22; 32], 1);
        let new = xudt_descriptor([5; 32], [21; 32], u128::MAX - 1, [22; 32], 2);
        assert!(matches!(
            validate_payment_delta(&old, &new, &participants, &intent),
            Err(BackendError::InvalidSettlementDescriptor | BackendError::PaymentDeltaMismatch)
        ));
    }

    #[test]
    fn idempotency_key_cannot_be_reused_for_another_intent() {
        let (mut backend, _, _) = fixture();
        let original = intent(&backend);
        backend.prepare_payment(original.clone(), 110).unwrap();
        let mut conflict = original;
        conflict.nonce = [34; 32];
        conflict.intent_id = conflict.derive_id().unwrap();
        assert_eq!(
            backend.prepare_payment(conflict, 111),
            Err(BackendError::IdempotencyConflict)
        );
    }

    #[test]
    fn payment_asset_must_match_the_channel_ckb_network() {
        let (mut backend, _, _) = fixture();
        let mut wrong_network = intent(&backend);
        wrong_network.asset = AgentAsset::Ckb {
            ckb_genesis_hash: [99; 32],
        };
        wrong_network.intent_id = wrong_network.derive_id().unwrap();
        assert_eq!(
            backend.prepare_payment(wrong_network, 110),
            Err(BackendError::WrongNetwork)
        );
    }

    #[test]
    fn channel_node_ids_must_derive_from_the_state_signers() {
        let (backend, _, mut participants) = fixture();
        participants[0].node_id = [99; 32];
        assert_eq!(
            MorphBilateralChannelBackend::new(
                backend.current_state.clone(),
                backend.current_authorization.clone(),
                backend.current_settlement_descriptor.clone(),
                participants,
                backend.asset_registry.clone(),
                BTreeSet::new(),
            ),
            Err(BackendError::WrongSettlementParticipants)
        );
    }

    #[test]
    fn channel_asset_registry_must_match_the_signed_header() {
        let (backend, _, participants) = fixture();
        let registry = AssetRegistry {
            xudt_types: BTreeSet::from([[42; 32]]),
        };

        assert_eq!(
            MorphBilateralChannelBackend::new(
                backend.current_state.clone(),
                backend.current_authorization.clone(),
                backend.current_settlement_descriptor.clone(),
                participants,
                registry,
                BTreeSet::new(),
            ),
            Err(BackendError::AssetRegistryMismatch)
        );
    }

    #[test]
    fn conditional_batch_arms_multiple_transfers_and_builds_force_resolution() {
        let (mut backend, keys, _) = conditional_fixture();
        let (batch, preimages) = pending_batch(&backend);
        let armed = backend
            .arm_conditional_batch(
                batch.clone(),
                conditional_update(&backend, &keys, &batch),
                100,
            )
            .unwrap();
        assert_eq!(armed.batch.transfers.len(), 2);
        backend
            .record_conditional_preimage(&batch.batch_id, &[44; 32], preimages[0])
            .unwrap();
        assert_eq!(
            backend.begin_conditional_force_resolution(&batch.batch_id, 599),
            Err(BackendError::ConditionalTransferPending)
        );
        let package = backend
            .begin_conditional_force_resolution(&batch.batch_id, 600)
            .unwrap();
        assert_eq!(package.armed_state_number, 1);
        assert_eq!(package.payout_capacities, [5_500, 4_500]);
        assert_eq!(package.input_since, absolute_block_since(600).unwrap());
        assert!(matches!(
            backend
                .conditional_batch(&batch.batch_id)
                .unwrap()
                .lifecycle,
            ConditionalBatchLifecycle::ForceClosing
        ));
        backend
            .confirm_conditional_force_settlement(&batch.batch_id, [99; 32])
            .unwrap();
        assert!(matches!(
            backend
                .conditional_batch(&batch.batch_id)
                .unwrap()
                .lifecycle,
            ConditionalBatchLifecycle::ForceSettled { .. }
        ));
    }

    #[test]
    fn conditional_batch_rejects_wrong_preimage() {
        let (mut backend, keys, _) = conditional_fixture();
        let (batch, _) = pending_batch(&backend);
        backend
            .arm_conditional_batch(
                batch.clone(),
                conditional_update(&backend, &keys, &batch),
                100,
            )
            .unwrap();
        assert_eq!(
            backend.record_conditional_preimage(&batch.batch_id, &[44; 32], [9; 32]),
            Err(BackendError::ConditionalPreimageMismatch)
        );
    }

    #[test]
    fn conditional_batch_cooperatively_consolidates_known_and_cancelled_transfers() {
        let (mut backend, keys, _) = conditional_fixture();
        let (batch, preimages) = pending_batch(&backend);
        backend
            .arm_conditional_batch(
                batch.clone(),
                conditional_update(&backend, &keys, &batch),
                100,
            )
            .unwrap();
        backend
            .record_conditional_preimage(&batch.batch_id, &[44; 32], preimages[0])
            .unwrap();
        let final_batch = ConditionalBatch {
            batch_id: batch.batch_id,
            application_context_commitment: batch.application_context_commitment,
            participants: [
                crate::ConditionalParticipant {
                    settlement_lock_hash: [21; 32],
                    settled_capacity: 5_500,
                },
                crate::ConditionalParticipant {
                    settlement_lock_hash: [22; 32],
                    settled_capacity: 4_500,
                },
            ],
            transfers: Vec::new(),
        };
        backend
            .cooperatively_settle_conditional_batch(
                &batch.batch_id,
                final_batch.clone(),
                conditional_update(&backend, &keys, &final_batch),
            )
            .unwrap();
        assert!(matches!(
            backend
                .conditional_batch(&batch.batch_id)
                .unwrap()
                .lifecycle,
            ConditionalBatchLifecycle::CooperativeSettled { state_number: 2 }
        ));
    }

    #[test]
    fn conditional_profile_rejects_single_intent_prepare() {
        let (mut backend, _, _) = conditional_fixture();
        let request = intent(&backend);
        assert_eq!(
            backend.prepare_payment(request, 110),
            Err(BackendError::ConditionalBatchRequired)
        );
    }
}
