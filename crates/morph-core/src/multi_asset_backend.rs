//! Bilateral multi-asset state negotiation. Signers must durably persist a
//! reservation before invoking their private-key signer, then durably persist
//! the resulting signature before exposing it. Cancelling never resets votes.
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use morph_script_common::multi_asset::MultiAssetStateHeader;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Bytes32, MultiAssetError, MultiAssetRecoveryPackage, MultiAssetSettlement,
    MultiAssetSpliceProposal, MultiAssetState, ParticipantSignature, Phase, StateAuthorization,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MultiAssetBackendError {
    #[error(transparent)]
    Evidence(#[from] MultiAssetError),
    #[error("backend requires bound bilateral settling recovery evidence")]
    UnboundRecovery,
    #[error("local signing key is not a channel participant")]
    UnknownParticipant,
    #[error("a different proposal is already pending")]
    PendingProposal,
    #[error("there is no pending proposal")]
    NoProposal,
    #[error("proposal does not extend the exact current funding context and state")]
    StaleProposal,
    #[error("state number exhausted")]
    StateNumberExhausted,
    #[error("signing would reuse or decrease a reserved state number")]
    ConflictingVote,
    #[error("local signature requires a matching durable signing reservation")]
    UnreservedSignature,
    #[error("invalid participant signature")]
    InvalidSignature,
    #[error("proposal requires both participant signatures")]
    IncompleteSignatures,
    #[error("old funding context is frozen by a prepared or reserved splice")]
    SpliceFrozen,
    #[error("splice preparation requires complete recovery of every reserved old-context vote")]
    UnsettledVotes,
}

type Result<T> = std::result::Result<T, MultiAssetBackendError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetProposal {
    pub base_state_digest: Bytes32,
    pub state: MultiAssetState,
    pub settlement: MultiAssetSettlement,
}

impl MultiAssetProposal {
    pub fn signing_digest(&self) -> Result<Bytes32> {
        Ok(self.state.signing_digest()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetSigningReservation {
    pub state_number: u64,
    pub signing_digest: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingUpdate {
    proposal: MultiAssetProposal,
    signatures: Vec<ParticipantSignature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiAssetSpliceFundingKind {
    Creation,
    InitialRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSplice {
    proposal: MultiAssetSpliceProposal,
    signature_reserved: bool,
    creation_reserved: bool,
    initial_recovery_reserved: bool,
    signatures: Vec<ParticipantSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendSnapshot {
    current: MultiAssetRecoveryPackage,
    local_pubkey: Vec<u8>,
    reservation: MultiAssetSigningReservation,
    #[serde(deserialize_with = "required_option")]
    pending: Option<PendingUpdate>,
    #[serde(deserialize_with = "required_option")]
    splice: Option<PendingSplice>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

/// Only validated snapshots can be deserialized. The private signer and code
/// dependencies remain outside the host protocol state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BackendSnapshot", into = "BackendSnapshot")]
pub struct MultiAssetChannelBackend {
    snapshot: BackendSnapshot,
}

impl TryFrom<BackendSnapshot> for MultiAssetChannelBackend {
    type Error = MultiAssetBackendError;
    fn try_from(snapshot: BackendSnapshot) -> Result<Self> {
        let backend = Self { snapshot };
        backend.validate()?;
        Ok(backend)
    }
}

impl From<MultiAssetChannelBackend> for BackendSnapshot {
    fn from(backend: MultiAssetChannelBackend) -> Self {
        backend.snapshot
    }
}

impl MultiAssetChannelBackend {
    pub fn new(current: MultiAssetRecoveryPackage, local_pubkey: Vec<u8>) -> Result<Self> {
        let reservation = MultiAssetSigningReservation {
            state_number: current.state.header.state_number,
            signing_digest: current.state.signing_digest()?,
        };
        Self::try_from(BackendSnapshot {
            current,
            local_pubkey,
            reservation,
            pending: None,
            splice: None,
        })
    }

    pub fn current(&self) -> &MultiAssetRecoveryPackage {
        &self.snapshot.current
    }
    pub fn local_pubkey(&self) -> &[u8] {
        &self.snapshot.local_pubkey
    }
    pub fn proposal(&self) -> Option<&MultiAssetProposal> {
        self.snapshot
            .pending
            .as_ref()
            .map(|pending| &pending.proposal)
    }
    pub fn signatures(&self) -> &[ParticipantSignature] {
        self.snapshot
            .pending
            .as_ref()
            .map_or(&[], |pending| &pending.signatures)
    }
    pub fn reservation(&self) -> &MultiAssetSigningReservation {
        &self.snapshot.reservation
    }

    fn candidate(&self, proposal: &MultiAssetProposal) -> Result<MultiAssetRecoveryPackage> {
        let current = self.current();
        let before = current.state.encode()?;
        let after = proposal.state.encode()?;
        if proposal.base_state_digest != current.state.signing_digest()?
            || proposal.state.header.state_number <= current.state.header.state_number
            || proposal.state.header.phase != Phase::Settling
            || !MultiAssetStateHeader::parse(&before)
                .map_err(MultiAssetError::from)?
                .same_context_except_progress(
                    &MultiAssetStateHeader::parse(&after).map_err(MultiAssetError::from)?,
                )
        {
            return Err(MultiAssetBackendError::StaleProposal);
        }
        let mut candidate = current.clone();
        candidate.state = proposal.state.clone();
        candidate.settlement = proposal.settlement.clone();
        candidate.authorization = StateAuthorization {
            threshold: 2,
            signatures: vec![],
        };
        candidate.validate_contents()?;
        Ok(candidate)
    }

    fn eligible(&self, proposal: &MultiAssetProposal) -> Result<()> {
        let reservation = self.reservation();
        let number = proposal.state.header.state_number;
        if number < reservation.state_number
            || (number == reservation.state_number
                && proposal.signing_digest()? != reservation.signing_digest)
        {
            return Err(MultiAssetBackendError::ConflictingVote);
        }
        Ok(())
    }

    fn verify_signature(&self, digest: &Bytes32, signature: &ParticipantSignature) -> Result<()> {
        if !self
            .current()
            .authorization
            .signatures
            .iter()
            .any(|member| member.pubkey_sec1 == signature.pubkey_sec1)
        {
            return Err(MultiAssetBackendError::UnknownParticipant);
        }
        let key = VerifyingKey::from_sec1_bytes(&signature.pubkey_sec1)
            .map_err(|_| MultiAssetBackendError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature.signature)
            .map_err(|_| MultiAssetBackendError::InvalidSignature)?;
        key.verify_prehash(digest, &signature)
            .map_err(|_| MultiAssetBackendError::InvalidSignature)
    }

    pub fn validate(&self) -> Result<()> {
        self.current().validate()?;
        if self.current().state.header.phase != Phase::Settling
            || self.current().outpoints.len() != self.current().manifest.vaults.len()
        {
            return Err(MultiAssetBackendError::UnboundRecovery);
        }
        if !self
            .current()
            .authorization
            .signatures
            .iter()
            .any(|member| member.pubkey_sec1 == self.snapshot.local_pubkey)
        {
            return Err(MultiAssetBackendError::UnknownParticipant);
        }
        if self.reservation().state_number < self.current().state.header.state_number
            || (self.reservation().state_number == self.current().state.header.state_number
                && self.reservation().signing_digest != self.current().state.signing_digest()?)
        {
            return Err(MultiAssetBackendError::ConflictingVote);
        }
        if let Some(splice) = &self.snapshot.splice {
            splice.proposal.validate_contents(self.current())?;
            self.validate_splice_funding(splice)?;
            if self.snapshot.pending.is_some() {
                return Err(MultiAssetBackendError::PendingProposal);
            }
            self.require_settled_votes()?;
            self.validate_splice_signatures(splice)?;
        }
        if let Some(pending) = &self.snapshot.pending {
            self.candidate(&pending.proposal)?;
            self.eligible(&pending.proposal)?;
            if pending.signatures.len() > 2
                || pending
                    .signatures
                    .windows(2)
                    .any(|pair| pair[0].pubkey_sec1 >= pair[1].pubkey_sec1)
            {
                return Err(MultiAssetBackendError::InvalidSignature);
            }
            for signature in &pending.signatures {
                self.verify_signature(&pending.proposal.signing_digest()?, signature)?;
                self.require_local_reservation(&pending.proposal, signature)?;
            }
        }
        Ok(())
    }

    /// Generate the next proposal without invoking any signer. Invalid asset
    /// totals or insufficient occupied reserve are rejected here.
    pub fn propose(&mut self, settlement: MultiAssetSettlement) -> Result<MultiAssetProposal> {
        self.require_no_splice()?;
        if let Some(proposal) = self.proposal() {
            return if proposal.settlement == settlement {
                Ok(proposal.clone())
            } else {
                Err(MultiAssetBackendError::PendingProposal)
            };
        }
        let number = self
            .reservation()
            .state_number
            .checked_add(1)
            .ok_or(MultiAssetBackendError::StateNumberExhausted)?;
        let mut state = self.current().state.clone();
        state.header.state_number = number;
        state.header.settlement_descriptor_commitment = settlement.commitment()?;
        let proposal = MultiAssetProposal {
            base_state_digest: self.current().state.signing_digest()?,
            state,
            settlement,
        };
        self.accept_proposal(proposal.clone())?;
        Ok(proposal)
    }

    /// Explicitly review and adopt a peer proposal; it cannot replace a pending
    /// different proposal or cross a funding context.
    pub fn accept_proposal(&mut self, proposal: MultiAssetProposal) -> Result<()> {
        self.require_no_splice()?;
        self.candidate(&proposal)?;
        self.eligible(&proposal)?;
        if let Some(pending) = &self.snapshot.pending {
            return if pending.proposal == proposal {
                Ok(())
            } else {
                Err(MultiAssetBackendError::PendingProposal)
            };
        }
        self.snapshot.pending = Some(PendingUpdate {
            proposal,
            signatures: vec![],
        });
        Ok(())
    }

    /// Persist the resulting backend snapshot and fsync it BEFORE invoking
    /// the local private-key signer. Repeating the same reservation is safe.
    pub fn reserve_signature(&mut self) -> Result<MultiAssetSigningReservation> {
        self.require_no_splice()?;
        let proposal = self.proposal().ok_or(MultiAssetBackendError::NoProposal)?;
        self.eligible(proposal)?;
        let reservation = MultiAssetSigningReservation {
            state_number: proposal.state.header.state_number,
            signing_digest: proposal.signing_digest()?,
        };
        self.snapshot.reservation = reservation.clone();
        Ok(reservation)
    }

    fn require_local_reservation(
        &self,
        proposal: &MultiAssetProposal,
        signature: &ParticipantSignature,
    ) -> Result<()> {
        if signature.pubkey_sec1 == self.snapshot.local_pubkey
            && (self.reservation().state_number != proposal.state.header.state_number
                || self.reservation().signing_digest != proposal.signing_digest()?)
        {
            return Err(MultiAssetBackendError::UnreservedSignature);
        }
        Ok(())
    }

    /// Persist this snapshot before returning a local signature to a peer.
    /// Duplicate delivery is idempotent, but a second differing signature for
    /// the same participant is rejected rather than silently overwriting it.
    pub fn record_signature(&mut self, signature: ParticipantSignature) -> Result<()> {
        self.require_no_splice()?;
        let proposal = self.proposal().ok_or(MultiAssetBackendError::NoProposal)?;
        self.verify_signature(&proposal.signing_digest()?, &signature)?;
        self.require_local_reservation(proposal, &signature)?;
        let pending = self
            .snapshot
            .pending
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        if let Some(existing) = pending
            .signatures
            .iter()
            .find(|entry| entry.pubkey_sec1 == signature.pubkey_sec1)
        {
            return if existing == &signature {
                Ok(())
            } else {
                Err(MultiAssetBackendError::InvalidSignature)
            };
        }
        pending.signatures.push(signature);
        pending
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        Ok(())
    }

    /// Return the complete, directly publishable recovery package. Persist it
    /// and this backend snapshot before acknowledging the update to the peer.
    pub fn commit(&mut self) -> Result<MultiAssetRecoveryPackage> {
        self.require_no_splice()?;
        let pending = self
            .snapshot
            .pending
            .as_ref()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        if pending.signatures.len() != 2 {
            return Err(MultiAssetBackendError::IncompleteSignatures);
        }
        let mut candidate = self.candidate(&pending.proposal)?;
        candidate.authorization.signatures = pending.signatures.clone();
        candidate.validate()?;
        self.snapshot.current = candidate.clone();
        self.snapshot.pending = None;
        Ok(candidate)
    }

    /// Recover a peer's completed update after a lost response or cancellation.
    /// A newer reserved vote remains burned. Unknown future local signatures
    /// indicate another signer/rolled-back journal and must not reset history.
    pub fn recover_committed(&mut self, package: MultiAssetRecoveryPackage) -> Result<()> {
        self.require_no_splice()?;
        package.validate()?;
        let number = package.state.header.state_number;
        let digest = package.state.signing_digest()?;
        let current_number = self.current().state.header.state_number;
        if number == current_number && package == *self.current() {
            return Ok(());
        }
        let before = self.current().state.encode()?;
        let after = package.state.encode()?;
        if number <= current_number
            || package.state.header.phase != Phase::Settling
            || package.manifest != self.current().manifest
            || package.outpoints != self.current().outpoints
            || package.scripts != self.current().scripts
            || package.state_carrier_capacity != self.current().state_carrier_capacity
            || !MultiAssetStateHeader::parse(&before)
                .map_err(MultiAssetError::from)?
                .same_context_except_progress(
                    &MultiAssetStateHeader::parse(&after).map_err(MultiAssetError::from)?,
                )
        {
            return Err(MultiAssetBackendError::StaleProposal);
        }
        if number > self.reservation().state_number
            || (number == self.reservation().state_number
                && digest != self.reservation().signing_digest)
        {
            return Err(MultiAssetBackendError::ConflictingVote);
        }
        self.snapshot.current = package;
        self.snapshot.pending = None;
        Ok(())
    }

    fn require_no_splice(&self) -> Result<()> {
        if self.snapshot.splice.is_some() {
            return Err(MultiAssetBackendError::SpliceFrozen);
        }
        Ok(())
    }
    fn require_settled_votes(&self) -> Result<()> {
        if self.reservation().state_number != self.current().state.header.state_number
            || self.reservation().signing_digest != self.current().state.signing_digest()?
        {
            return Err(MultiAssetBackendError::UnsettledVotes);
        }
        Ok(())
    }
    fn validate_splice_signatures(&self, splice: &PendingSplice) -> Result<()> {
        if splice.signatures.len() > 2
            || splice
                .signatures
                .windows(2)
                .any(|pair| pair[0].pubkey_sec1 >= pair[1].pubkey_sec1)
        {
            return Err(MultiAssetBackendError::InvalidSignature);
        }
        if splice.signature_reserved || !splice.signatures.is_empty() {
            splice.proposal.validate(self.current())?;
        }
        let digest = splice.proposal.intent_digest(self.current())?;
        for signature in &splice.signatures {
            self.verify_signature(&digest, signature)?;
            if signature.pubkey_sec1 == self.snapshot.local_pubkey && !splice.signature_reserved {
                return Err(MultiAssetBackendError::UnreservedSignature);
            }
        }
        Ok(())
    }
    fn splice_funding_digest(
        &self,
        splice: &PendingSplice,
        kind: MultiAssetSpliceFundingKind,
    ) -> Result<Bytes32> {
        Ok(match kind {
            MultiAssetSpliceFundingKind::Creation => splice.proposal.new_state.signing_digest()?,
            MultiAssetSpliceFundingKind::InitialRecovery => splice
                .proposal
                .initial_recovery_contents(self.current())?
                .state
                .signing_digest()?,
        })
    }
    fn validate_splice_funding(&self, splice: &PendingSplice) -> Result<()> {
        for kind in [
            MultiAssetSpliceFundingKind::Creation,
            MultiAssetSpliceFundingKind::InitialRecovery,
        ] {
            let auth = match kind {
                MultiAssetSpliceFundingKind::Creation => &splice.proposal.new_state_authorization,
                MultiAssetSpliceFundingKind::InitialRecovery => {
                    &splice.proposal.initial_recovery_authorization
                }
            };
            if auth.threshold != 2
                || auth.signatures.len() > 2
                || auth
                    .signatures
                    .windows(2)
                    .any(|pair| pair[0].pubkey_sec1 >= pair[1].pubkey_sec1)
            {
                return Err(MultiAssetBackendError::InvalidSignature);
            }
            let digest = self.splice_funding_digest(splice, kind)?;
            for signature in &auth.signatures {
                self.verify_signature(&digest, signature)?;
            }
        }
        Ok(())
    }
    /// Persist the returned snapshot before invoking a funding signer.
    pub fn reserve_splice_funding_signature(
        &mut self,
        kind: MultiAssetSpliceFundingKind,
    ) -> Result<Bytes32> {
        let splice = self
            .snapshot
            .splice
            .as_ref()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        let digest = self.splice_funding_digest(splice, kind)?;
        let splice = self
            .snapshot
            .splice
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        match kind {
            MultiAssetSpliceFundingKind::Creation => splice.creation_reserved = true,
            MultiAssetSpliceFundingKind::InitialRecovery => splice.initial_recovery_reserved = true,
        }
        Ok(digest)
    }
    pub fn record_splice_funding_signature(
        &mut self,
        kind: MultiAssetSpliceFundingKind,
        signature: ParticipantSignature,
    ) -> Result<()> {
        let splice = self
            .snapshot
            .splice
            .as_ref()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        let digest = self.splice_funding_digest(splice, kind)?;
        self.verify_signature(&digest, &signature)?;
        let reserved = match kind {
            MultiAssetSpliceFundingKind::Creation => splice.creation_reserved,
            MultiAssetSpliceFundingKind::InitialRecovery => splice.initial_recovery_reserved,
        };
        if signature.pubkey_sec1 == self.snapshot.local_pubkey && !reserved {
            return Err(MultiAssetBackendError::UnreservedSignature);
        }
        let splice = self
            .snapshot
            .splice
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        let auth = match kind {
            MultiAssetSpliceFundingKind::Creation => &mut splice.proposal.new_state_authorization,
            MultiAssetSpliceFundingKind::InitialRecovery => {
                &mut splice.proposal.initial_recovery_authorization
            }
        };
        if let Some(previous) = auth
            .signatures
            .iter()
            .find(|entry| entry.pubkey_sec1 == signature.pubkey_sec1)
        {
            return if previous == &signature {
                Ok(())
            } else {
                Err(MultiAssetBackendError::InvalidSignature)
            };
        }
        auth.signatures.push(signature);
        auth.signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        Ok(())
    }
    /// Review the fixed bridge intent before all new-context signatures exist.
    /// This does not authorise signing; reserve_splice_signature remains gated.
    pub fn splice_intent_digest(&self) -> Result<Bytes32> {
        Ok(self
            .splice_proposal()
            .ok_or(MultiAssetBackendError::NoProposal)?
            .intent_digest(self.current())?)
    }
    pub fn splice_funding_signing_digest(
        &self,
        kind: MultiAssetSpliceFundingKind,
    ) -> Result<Bytes32> {
        self.splice_funding_digest(
            self.snapshot
                .splice
                .as_ref()
                .ok_or(MultiAssetBackendError::NoProposal)?,
            kind,
        )
    }
    pub fn splice_proposal(&self) -> Option<&MultiAssetSpliceProposal> {
        self.snapshot.splice.as_ref().map(|splice| &splice.proposal)
    }
    pub fn splice_signature_reserved(&self) -> bool {
        self.snapshot
            .splice
            .as_ref()
            .is_some_and(|splice| splice.signature_reserved)
    }
    pub fn splice_signatures(&self) -> &[ParticipantSignature] {
        self.snapshot
            .splice
            .as_ref()
            .map_or(&[], |splice| splice.signatures.as_slice())
    }
    pub fn prepare_splice(&mut self, proposal: MultiAssetSpliceProposal) -> Result<Bytes32> {
        proposal.validate_contents(self.current())?;
        self.require_settled_votes()?;
        if self.snapshot.pending.is_some() {
            return Err(MultiAssetBackendError::PendingProposal);
        }
        let digest = proposal.intent_digest(self.current())?;
        if let Some(existing) = &self.snapshot.splice {
            return if existing.proposal == proposal {
                Ok(digest)
            } else {
                Err(MultiAssetBackendError::SpliceFrozen)
            };
        }
        let splice = PendingSplice {
            proposal,
            signature_reserved: false,
            creation_reserved: false,
            initial_recovery_reserved: false,
            signatures: vec![],
        };
        self.validate_splice_funding(&splice)?;
        self.snapshot.splice = Some(splice);
        Ok(digest)
    }
    /// Fsync this snapshot before invoking the signer. Once reserved, neither
    /// cancellation nor restart can permit another old-context update.
    pub fn reserve_splice_signature(&mut self) -> Result<Bytes32> {
        let digest = self
            .splice_proposal()
            .ok_or(MultiAssetBackendError::NoProposal)?
            .signing_digest(self.current())?;
        let splice = self
            .snapshot
            .splice
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        splice.signature_reserved = true;
        Ok(digest)
    }
    pub fn record_splice_signature(&mut self, signature: ParticipantSignature) -> Result<()> {
        let splice = self
            .snapshot
            .splice
            .as_ref()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        let digest = splice.proposal.signing_digest(self.current())?;
        self.verify_signature(&digest, &signature)?;
        if signature.pubkey_sec1 == self.snapshot.local_pubkey && !splice.signature_reserved {
            return Err(MultiAssetBackendError::UnreservedSignature);
        }
        let splice = self
            .snapshot
            .splice
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        if let Some(previous) = splice
            .signatures
            .iter()
            .find(|entry| entry.pubkey_sec1 == signature.pubkey_sec1)
        {
            return if previous == &signature {
                Ok(())
            } else {
                Err(MultiAssetBackendError::InvalidSignature)
            };
        }
        splice.signatures.push(signature);
        splice
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        Ok(())
    }
    pub fn splice_authorization(&self) -> Result<StateAuthorization> {
        let splice = self
            .snapshot
            .splice
            .as_ref()
            .ok_or(MultiAssetBackendError::NoProposal)?;
        if splice.signatures.len() != 2 {
            return Err(MultiAssetBackendError::IncompleteSignatures);
        }
        let authorization = StateAuthorization {
            threshold: 2,
            signatures: splice.signatures.clone(),
        };
        splice
            .proposal
            .verify_authorization(self.current(), &authorization)?;
        Ok(authorization)
    }
    pub fn cancel_splice(&mut self) -> Result<()> {
        if self.splice_signature_reserved() {
            return Err(MultiAssetBackendError::SpliceFrozen);
        }
        self.snapshot.splice = None;
        Ok(())
    }

    pub fn cancel_proposal(&mut self) {
        self.snapshot.pending = None;
    }
}
