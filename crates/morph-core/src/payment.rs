//! Payment intent bookkeeping over the one current channel agreement engine.
//!
//! This object owns no signer, vote counter, channel State or recovery package.
//! Callers persist it together with the supplied `MultiAssetChannelBackend`.
//! Reserve and record operations retain that engine's durable-before-release
//! contract. Intent expiry gates preparation and signing, not an already issued
//! channel signature: expired authorisations still require recovery, not a
//! fictional cancellation receipt.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BackendSettlementEvidence, Bytes32, ChannelParticipant, GatewayAsset, GatewayError,
    MorphStateSettlementEvidence, MultiAssetBackendError, MultiAssetChannelBackend,
    MultiAssetError, MultiAssetProposal, MultiAssetSettlement, MultiAssetSettlementCapability,
    MultiAssetSigningReservation, ParticipantSignature, PaymentIntent, VaultAsset, blake2b256,
};

const PREPARED_DOMAIN: &[u8] = b"CKB_MORPH_CURRENT_PREPARED_PAYMENT_V1";
const SETTLEMENT_DOMAIN: &[u8] = b"CKB_MORPH_CURRENT_PAYMENT_SETTLEMENT_V1";
const CANCEL_DOMAIN: &[u8] = b"CKB_MORPH_CURRENT_PAYMENT_CANCEL_V1";
const BACKEND_ID: &str = "morph-current";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedChannelPayment {
    pub prepared_id: Bytes32,
    pub intent: PaymentIntent,
    pub prepared_at_unix: u64,
    /// The exact proposal reviewed for this intent, without signer authority.
    pub proposal: MultiAssetProposal,
}

impl PreparedChannelPayment {
    fn derive_id(&self) -> PaymentResult<Bytes32> {
        let mut bytes = PREPARED_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.intent.intent_id);
        bytes.extend_from_slice(&self.proposal.base_state_digest);
        bytes.extend_from_slice(&self.proposal.signing_digest()?);
        Ok(blake2b256(&bytes))
    }

    fn validate(&self) -> PaymentResult<()> {
        if self.proposal.settlement.capability != MultiAssetSettlementCapability::Ordinary {
            return Err(PaymentError::ConditionalLifecycleRequired);
        }
        self.intent.validate(self.prepared_at_unix)?;
        let binding = self
            .intent
            .channel_binding
            .as_ref()
            .ok_or(PaymentError::WrongBinding)?;
        if binding.channel_id != self.proposal.state.header.channel_id
            || binding.funding_context_id != self.proposal.state.funding_context_id()?
            || binding.expected_settlement_descriptor_commitment
                != self.proposal.settlement.commitment()?
            || self.proposal.state.header.settlement_descriptor_commitment
                != binding.expected_settlement_descriptor_commitment
            || self.prepared_id != self.derive_id()?
        {
            return Err(PaymentError::WrongBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelPaymentState {
    Prepared {
        payment: PreparedChannelPayment,
    },
    Settled {
        payment: PreparedChannelPayment,
        evidence: BackendSettlementEvidence,
    },
    Cancelled {
        payment: PreparedChannelPayment,
        evidence: BackendSettlementEvidence,
    },
}

impl ChannelPaymentState {
    pub fn payment(&self) -> &PreparedChannelPayment {
        match self {
            Self::Prepared { payment }
            | Self::Settled { payment, .. }
            | Self::Cancelled { payment, .. } => payment,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentBook {
    channel_id: Bytes32,
    funding_context_id: Bytes32,
    /// Indexed in settlement descriptor order, not pubkey order.
    participants: [ChannelParticipant; 2],
    verified_rgbpp_bindings: BTreeSet<Bytes32>,
    payments: Vec<ChannelPaymentState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PaymentBook", into = "PaymentBook")]
pub struct ChannelPayments {
    book: PaymentBook,
}

impl From<ChannelPayments> for PaymentBook {
    fn from(payments: ChannelPayments) -> Self {
        payments.book
    }
}

impl TryFrom<PaymentBook> for ChannelPayments {
    type Error = PaymentError;

    fn try_from(book: PaymentBook) -> PaymentResult<Self> {
        if book.channel_id == [0; 32]
            || book.funding_context_id == [0; 32]
            || book.participants[0].node_id == book.participants[1].node_id
            || book
                .participants
                .iter()
                .any(|member| member.node_id == [0; 32] || member.settlement_lock_hash == [0; 32])
            || book.participants[0].settlement_lock_hash
                >= book.participants[1].settlement_lock_hash
            || book.verified_rgbpp_bindings.contains(&[0; 32])
        {
            return Err(PaymentError::WrongParticipants);
        }
        let mut idempotency_keys = BTreeSet::new();
        let mut intent_ids = BTreeSet::new();
        let mut active = 0;
        for state in &book.payments {
            let payment = state.payment();
            payment.validate()?;
            if !intent_ids.insert(payment.intent.intent_id)
                || payment.proposal.state.header.channel_id != book.channel_id
                || payment.proposal.state.funding_context_id()? != book.funding_context_id
                || !idempotency_keys.insert(payment.intent.idempotency_key)
            {
                return Err(PaymentError::InvalidBook);
            }
            if matches!(state, ChannelPaymentState::Prepared { .. }) {
                active += 1;
            }
            match state {
                ChannelPaymentState::Settled { evidence, .. }
                    if *evidence != settlement_evidence(payment)? =>
                {
                    return Err(PaymentError::InvalidBook);
                }
                ChannelPaymentState::Cancelled { evidence, .. }
                    if *evidence != cancellation_evidence(payment) =>
                {
                    return Err(PaymentError::InvalidBook);
                }
                _ => {}
            }
        }
        if active > 1 {
            return Err(PaymentError::ConcurrentPreparation);
        }
        Ok(Self { book })
    }
}

impl ChannelPayments {
    pub fn new(
        backend: &MultiAssetChannelBackend,
        participants: [ChannelParticipant; 2],
        verified_rgbpp_bindings: BTreeSet<Bytes32>,
    ) -> PaymentResult<Self> {
        let payments = Self::try_from(PaymentBook {
            channel_id: backend.current().state.header.channel_id,
            funding_context_id: backend.current().state.funding_context_id()?,
            participants,
            verified_rgbpp_bindings,
            payments: Vec::new(),
        })?;
        payments.validate(backend)?;
        Ok(payments)
    }

    pub fn validate(&self, backend: &MultiAssetChannelBackend) -> PaymentResult<()> {
        backend.validate()?;
        let current = backend.current();
        if current.state.header.channel_id != self.book.channel_id
            || current.state.funding_context_id()? != self.book.funding_context_id
        {
            return Err(PaymentError::WrongBinding);
        }
        crate::backend::validate_participant_identities(
            &current.authorization,
            &self.book.participants,
        )
        .map_err(|_| PaymentError::WrongParticipants)?;
        for (index, member) in self.book.participants.iter().enumerate() {
            if current.settlement.participant_lock_hashes[index] != member.settlement_lock_hash {
                return Err(PaymentError::WrongParticipants);
            }
        }
        Ok(())
    }

    pub fn payment_state(&self, intent_id: &Bytes32) -> Option<&ChannelPaymentState> {
        self.book
            .payments
            .iter()
            .find(|entry| &entry.payment().intent.intent_id == intent_id)
    }

    /// Called only after the application's RGB++ verifier accepts the proof.
    pub fn register_verified_rgbpp_binding(&mut self, commitment: Bytes32) -> PaymentResult<()> {
        if commitment == [0; 32] {
            return Err(PaymentError::UnverifiedRgbpp);
        }
        self.book.verified_rgbpp_bindings.insert(commitment);
        Ok(())
    }

    /// Derive the sole allowed successor allocation. CKB business value may be
    /// held in typed Vaults too; transfer it in canonical Vault order without
    /// changing any reserve, token quantity, carrier or unrelated asset.
    pub fn payment_settlement(
        &self,
        backend: &MultiAssetChannelBackend,
        intent: &PaymentIntent,
    ) -> PaymentResult<MultiAssetSettlement> {
        self.validate(backend)?;
        if backend.current().settlement.capability != MultiAssetSettlementCapability::Ordinary {
            return Err(PaymentError::ConditionalLifecycleRequired);
        }
        let binding = intent
            .channel_binding
            .as_ref()
            .ok_or(PaymentError::WrongBinding)?;
        if binding.channel_id != self.book.channel_id
            || binding.funding_context_id != self.book.funding_context_id
        {
            return Err(PaymentError::WrongBinding);
        }
        let payer = self
            .book
            .participants
            .iter()
            .position(|member| member.node_id == intent.payer)
            .ok_or(PaymentError::WrongParticipants)?;
        let payee = self
            .book
            .participants
            .iter()
            .position(|member| member.node_id == intent.payee)
            .ok_or(PaymentError::WrongParticipants)?;
        if payer == payee || intent.amount == 0 {
            return Err(PaymentError::WrongParticipants);
        }
        let chain_id = backend.current().state.header.chain_id;
        let asset = match &intent.asset {
            GatewayAsset::Ckb { ckb_genesis_hash } if *ckb_genesis_hash == chain_id => None,
            GatewayAsset::Xudt {
                ckb_genesis_hash,
                type_script_hash,
            } if *ckb_genesis_hash == chain_id => Some(*type_script_hash),
            GatewayAsset::Rgbpp(asset) if asset.ckb_genesis_hash == chain_id => {
                if !intent
                    .required_rgbpp_proof_commitment
                    .is_some_and(|commitment| {
                        self.book.verified_rgbpp_bindings.contains(&commitment)
                    })
                {
                    return Err(PaymentError::UnverifiedRgbpp);
                }
                Some(asset.xudt_type_script_hash)
            }
            _ => return Err(PaymentError::WrongNetwork),
        };
        let mut settlement = backend.current().settlement.clone();
        if let Some(type_hash) = asset {
            let payout = settlement
                .payouts
                .iter_mut()
                .find(|payout| payout.asset == VaultAsset::Xudt(type_hash))
                .ok_or(PaymentError::AssetNotFunded)?;
            payout.values[payer].amount = payout.values[payer]
                .amount
                .checked_sub(intent.amount)
                .ok_or(PaymentError::InsufficientBalance)?;
            payout.values[payee].amount = payout.values[payee]
                .amount
                .checked_add(intent.amount)
                .ok_or(PaymentError::InsufficientBalance)?;
        } else {
            let mut remaining = intent.amount;
            for payout in &mut settlement.payouts {
                let transfer = remaining.min(u128::from(payout.values[payer].business_ckb)) as u64;
                payout.values[payer].business_ckb -= transfer;
                payout.values[payee].business_ckb = payout.values[payee]
                    .business_ckb
                    .checked_add(transfer)
                    .ok_or(PaymentError::InsufficientBalance)?;
                remaining -= u128::from(transfer);
            }
            if remaining != 0 {
                return Err(PaymentError::InsufficientBalance);
            }
        }
        settlement.encode()?;
        Ok(settlement)
    }

    pub fn prepare_payment(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
        intent: PaymentIntent,
        now_unix: u64,
    ) -> PaymentResult<PreparedChannelPayment> {
        self.validate(backend)?;
        intent.validate(now_unix)?;
        if let Some(existing) = self
            .book
            .payments
            .iter()
            .find(|entry| entry.payment().intent.idempotency_key == intent.idempotency_key)
        {
            if existing.payment().intent != intent {
                return Err(PaymentError::IdempotencyConflict);
            }
            return match existing {
                ChannelPaymentState::Prepared { payment } => Ok(payment.clone()),
                _ => Err(PaymentError::AlreadyTerminal),
            };
        }
        if self
            .book
            .payments
            .iter()
            .any(|entry| matches!(entry, ChannelPaymentState::Prepared { .. }))
        {
            return Err(PaymentError::ConcurrentPreparation);
        }
        if backend.proposal().is_some()
            || backend.reservation().state_number != backend.current().state.header.state_number
            || backend.reservation().signing_digest != backend.current().state.signing_digest()?
        {
            return Err(PaymentError::UnresolvedAuthority);
        }
        let settlement = self.payment_settlement(backend, &intent)?;
        if settlement.commitment()?
            != intent
                .channel_binding
                .as_ref()
                .ok_or(PaymentError::WrongBinding)?
                .expected_settlement_descriptor_commitment
        {
            return Err(PaymentError::WrongBinding);
        }
        let proposal = backend.propose(settlement)?;
        let mut payment = PreparedChannelPayment {
            prepared_id: [0; 32],
            intent,
            prepared_at_unix: now_unix,
            proposal,
        };
        payment.prepared_id = payment.derive_id()?;
        self.set_state(ChannelPaymentState::Prepared {
            payment: payment.clone(),
        });
        Ok(payment)
    }

    fn set_state(&mut self, state: ChannelPaymentState) {
        if let Some(existing) = self
            .book
            .payments
            .iter_mut()
            .find(|entry| entry.payment().intent.intent_id == state.payment().intent.intent_id)
        {
            *existing = state;
        } else {
            self.book.payments.push(state);
        }
    }

    fn by_prepared_id(&self, prepared_id: &Bytes32) -> PaymentResult<&ChannelPaymentState> {
        self.book
            .payments
            .iter()
            .find(|entry| &entry.payment().prepared_id == prepared_id)
            .ok_or(PaymentError::NotPrepared)
    }

    fn require_proposal(
        backend: &MultiAssetChannelBackend,
        payment: &PreparedChannelPayment,
    ) -> PaymentResult<()> {
        if backend.current().state.signing_digest()? != payment.proposal.base_state_digest
            || backend.proposal() != Some(&payment.proposal)
        {
            return Err(PaymentError::StalePreparation);
        }
        Ok(())
    }

    /// Persist both the supplied engine and payment book before signing.
    pub fn reserve_payment_signature(
        &self,
        backend: &mut MultiAssetChannelBackend,
        prepared_id: &Bytes32,
        now_unix: u64,
    ) -> PaymentResult<MultiAssetSigningReservation> {
        self.validate(backend)?;
        let payment = match self.by_prepared_id(prepared_id)? {
            ChannelPaymentState::Prepared { payment } => payment,
            _ => return Err(PaymentError::AlreadyTerminal),
        };
        payment.intent.validate(now_unix)?;
        if now_unix < payment.prepared_at_unix {
            return Err(PaymentError::InvalidTime);
        }
        Self::require_proposal(backend, payment)?;
        Ok(backend.reserve_signature()?)
    }

    /// Late signatures remain evidence. Persist before disclosing a local
    /// signature; expiry cannot invalidate an authority already issued.
    pub fn record_payment_signature(
        &self,
        backend: &mut MultiAssetChannelBackend,
        prepared_id: &Bytes32,
        signature: ParticipantSignature,
    ) -> PaymentResult<()> {
        self.validate(backend)?;
        let payment = match self.by_prepared_id(prepared_id)? {
            ChannelPaymentState::Prepared { payment } => payment,
            _ => return Err(PaymentError::AlreadyTerminal),
        };
        Self::require_proposal(backend, payment)?;
        Ok(backend.record_signature(signature)?)
    }

    /// Commit exactly the reviewed proposal, or recover its already committed
    /// result after an interrupted metadata write. A different signed successor
    /// is never evidence that this payment settled.
    pub fn commit_payment(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
        prepared_id: &Bytes32,
        now_unix: u64,
    ) -> PaymentResult<BackendSettlementEvidence> {
        self.validate(backend)?;
        let payment = match self.by_prepared_id(prepared_id)? {
            ChannelPaymentState::Settled { evidence, .. } => return Ok(evidence.clone()),
            ChannelPaymentState::Cancelled { .. } => return Err(PaymentError::AlreadyTerminal),
            ChannelPaymentState::Prepared { payment } => payment.clone(),
        };
        if now_unix < payment.prepared_at_unix {
            return Err(PaymentError::InvalidTime);
        }
        if backend.current().state != payment.proposal.state
            || backend.current().settlement != payment.proposal.settlement
        {
            Self::require_proposal(backend, &payment)?;
            backend.commit()?;
        }
        let evidence = settlement_evidence(&payment)?;
        self.set_state(ChannelPaymentState::Settled {
            payment,
            evidence: evidence.clone(),
        });
        Ok(evidence)
    }

    /// Only an unsigned, unreserved proposal can yield a cancellation receipt.
    /// A reserved vote might already have escaped to the peer even when its
    /// local signature receipt was lost; it must be reconciled, never reset.
    pub fn cancel_payment(
        &mut self,
        backend: &mut MultiAssetChannelBackend,
        prepared_id: &Bytes32,
        now_unix: u64,
    ) -> PaymentResult<BackendSettlementEvidence> {
        self.validate(backend)?;
        let payment = match self.by_prepared_id(prepared_id)? {
            ChannelPaymentState::Cancelled { evidence, .. } => return Ok(evidence.clone()),
            ChannelPaymentState::Settled { .. } => return Err(PaymentError::AlreadyTerminal),
            ChannelPaymentState::Prepared { payment } => payment.clone(),
        };
        if now_unix < payment.prepared_at_unix {
            return Err(PaymentError::InvalidTime);
        }
        Self::require_proposal(backend, &payment)?;
        if backend.reservation().state_number >= payment.proposal.state.header.state_number
            || !backend.signatures().is_empty()
        {
            return Err(PaymentError::AuthorizationMayExist);
        }
        backend.cancel_proposal();
        let evidence = cancellation_evidence(&payment);
        self.set_state(ChannelPaymentState::Cancelled {
            payment,
            evidence: evidence.clone(),
        });
        Ok(evidence)
    }
}

fn settlement_evidence(
    payment: &PreparedChannelPayment,
) -> PaymentResult<BackendSettlementEvidence> {
    let digest = payment.proposal.signing_digest()?;
    let mut bytes = SETTLEMENT_DOMAIN.to_vec();
    bytes.extend_from_slice(&payment.prepared_id);
    bytes.extend_from_slice(&digest);
    Ok(BackendSettlementEvidence {
        provider_id: BACKEND_ID.into(),
        settlement_id: blake2b256(&bytes),
        opaque_commitment: digest,
        morph_state: Some(MorphStateSettlementEvidence {
            channel_id: payment.proposal.state.header.channel_id,
            funding_context_id: payment.proposal.state.funding_context_id()?,
            state_number: payment.proposal.state.header.state_number,
            state_header_commitment: digest,
            settlement_descriptor_commitment: payment.proposal.settlement.commitment()?,
        }),
        ckb_anchor: None,
        rgbpp_proof_commitment: payment.intent.required_rgbpp_proof_commitment,
        failure_code: None,
    })
}

fn cancellation_evidence(payment: &PreparedChannelPayment) -> BackendSettlementEvidence {
    let mut bytes = CANCEL_DOMAIN.to_vec();
    bytes.extend_from_slice(&payment.prepared_id);
    let commitment = blake2b256(&bytes);
    BackendSettlementEvidence {
        provider_id: BACKEND_ID.into(),
        settlement_id: commitment,
        opaque_commitment: commitment,
        morph_state: None,
        ckb_anchor: None,
        rgbpp_proof_commitment: None,
        failure_code: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaymentError {
    #[error("payment participant identities or settlement locks do not match the channel")]
    WrongParticipants,
    #[error("payment binds another channel, funding context or successor allocation")]
    WrongBinding,
    #[error("payment belongs to another network")]
    WrongNetwork,
    #[error("RGB++ proof was not verified")]
    UnverifiedRgbpp,
    #[error("payment asset is not funded")]
    AssetNotFunded,
    #[error("business balance is insufficient or would overflow")]
    InsufficientBalance,
    #[error("idempotency key already belongs to a different complete intent")]
    IdempotencyConflict,
    #[error("payment is already terminal")]
    AlreadyTerminal,
    #[error("a different payment is already prepared")]
    ConcurrentPreparation,
    #[error("payment preparation was not found")]
    NotPrepared,
    #[error("payment no longer matches the engine's exact pending proposal")]
    StalePreparation,
    #[error("operation predates preparation")]
    InvalidTime,
    #[error("a signing reservation or signature prevents claiming cancellation")]
    AuthorizationMayExist,
    #[error("existing proposal or unresolved signing authority must be reconciled first")]
    UnresolvedAuthority,
    #[error("payment bookkeeping is inconsistent")]
    InvalidBook,
    #[error("conditional settlement requires its explicit batch lifecycle")]
    ConditionalLifecycleRequired,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
    #[error(transparent)]
    Agreement(#[from] MultiAssetBackendError),
    #[error(transparent)]
    Evidence(#[from] MultiAssetError),
}

pub type PaymentResult<T> = Result<T, PaymentError>;
