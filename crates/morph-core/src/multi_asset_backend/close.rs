use super::*;
use crate::MultiAssetCloseProposal;

/// Bounded durable approval history. Exhaustion never deletes/revokes approvals;
/// the already saved unilateral package remains the escape route.
pub const MULTI_ASSET_CLOSE_MAX_APPROVALS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetCloseAttempt {
    pub proposal: MultiAssetCloseProposal,
    pub signature_reserved: bool,
    pub signatures: Vec<ParticipantSignature>,
}

impl MultiAssetChannelBackend {
    pub fn close_attempts(&self) -> &[MultiAssetCloseAttempt] {
        self.snapshot.close.as_deref().unwrap_or(&[])
    }
    pub fn close_signature_reserved(&self, transaction_hash: &Bytes32) -> Result<bool> {
        Ok(self.close_attempt(transaction_hash)?.signature_reserved)
    }
    fn close_attempt(&self, hash: &Bytes32) -> Result<&MultiAssetCloseAttempt> {
        for attempt in self.close_attempts() {
            if attempt.proposal.transaction_hash()? == *hash {
                return Ok(attempt);
            }
        }
        Err(MultiAssetBackendError::NoProposal)
    }
    fn close_attempt_index(&self, hash: &Bytes32) -> Result<usize> {
        for (index, attempt) in self.close_attempts().iter().enumerate() {
            if attempt.proposal.transaction_hash()? == *hash {
                return Ok(index);
            }
        }
        Err(MultiAssetBackendError::NoProposal)
    }
    pub(super) fn require_no_close(&self) -> Result<()> {
        if self.snapshot.close.is_some() {
            return Err(MultiAssetBackendError::CloseFrozen);
        }
        Ok(())
    }
    pub(super) fn validate_close(&self) -> Result<()> {
        let Some(attempts) = &self.snapshot.close else {
            return Ok(());
        };
        if attempts.is_empty()
            || attempts.len() > MULTI_ASSET_CLOSE_MAX_APPROVALS
            || self.snapshot.pending.is_some()
            || self.snapshot.splice.is_some()
        {
            return Err(MultiAssetBackendError::CloseFrozen);
        }
        self.require_settled_votes()?;
        let first = &attempts[0].proposal;
        let mut hashes = std::collections::BTreeSet::new();
        for attempt in attempts {
            let digest = attempt.proposal.signing_digest(self.current())?;
            if attempt.proposal.source_outpoint != first.source_outpoint
                || attempt.proposal.source_state != first.source_state
                || !hashes.insert(attempt.proposal.transaction_hash()?)
            {
                return Err(MultiAssetBackendError::StaleProposal);
            }
            if attempt.signatures.len() > 2
                || attempt
                    .signatures
                    .windows(2)
                    .any(|p| p[0].pubkey_sec1 >= p[1].pubkey_sec1)
            {
                return Err(MultiAssetBackendError::InvalidSignature);
            }
            for signature in &attempt.signatures {
                self.verify_signature(&digest, signature)?;
                if signature.pubkey_sec1 == self.snapshot.local_pubkey
                    && !attempt.signature_reserved
                {
                    return Err(MultiAssetBackendError::UnreservedSignature);
                }
            }
        }
        Ok(())
    }

    /// Select the latest saved allocation and exact source, never a free-form
    /// target. Fee replacements append history; old approvals stay executable.
    pub fn prepare_close(&mut self, proposal: MultiAssetCloseProposal) -> Result<Bytes32> {
        if self.snapshot.splice.is_some() {
            return Err(MultiAssetBackendError::SpliceFrozen);
        }
        if self.snapshot.pending.is_some() {
            return Err(MultiAssetBackendError::PendingProposal);
        }
        self.require_settled_votes()?;
        let digest = proposal.signing_digest(self.current())?;
        if let Some(first) = self.close_attempts().first() {
            if first.proposal.source_outpoint != proposal.source_outpoint
                || first.proposal.source_state != proposal.source_state
            {
                return Err(MultiAssetBackendError::StaleProposal);
            }
            if self
                .close_attempts()
                .iter()
                .any(|attempt| attempt.proposal == proposal)
            {
                return Ok(digest);
            }
        }
        if self.close_attempts().len() >= MULTI_ASSET_CLOSE_MAX_APPROVALS {
            return Err(MultiAssetBackendError::CloseHistoryFull);
        }
        self.snapshot
            .close
            .get_or_insert_with(Vec::new)
            .push(MultiAssetCloseAttempt {
                proposal,
                signature_reserved: false,
                signatures: vec![],
            });
        Ok(digest)
    }
    /// Persist/fsync the returned state BEFORE key use. Cancellation is forever
    /// forbidden after this point, even if no receipt was delivered or recorded.
    pub fn reserve_close_signature(&mut self, transaction_hash: &Bytes32) -> Result<Bytes32> {
        let index = self.close_attempt_index(transaction_hash)?;
        let digest = self
            .close_attempt(transaction_hash)?
            .proposal
            .signing_digest(self.current())?;
        self.snapshot
            .close
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?[index]
            .signature_reserved = true;
        Ok(digest)
    }
    pub fn record_close_signature(
        &mut self,
        transaction_hash: &Bytes32,
        signature: ParticipantSignature,
    ) -> Result<()> {
        let index = self.close_attempt_index(transaction_hash)?;
        let attempt = self.close_attempt(transaction_hash)?;
        let digest = attempt.proposal.signing_digest(self.current())?;
        self.verify_signature(&digest, &signature)?;
        if signature.pubkey_sec1 == self.snapshot.local_pubkey && !attempt.signature_reserved {
            return Err(MultiAssetBackendError::UnreservedSignature);
        }
        if let Some(previous) = attempt
            .signatures
            .iter()
            .find(|p| p.pubkey_sec1 == signature.pubkey_sec1)
        {
            return if previous == &signature {
                Ok(())
            } else {
                Err(MultiAssetBackendError::InvalidSignature)
            };
        }
        let attempt = &mut self
            .snapshot
            .close
            .as_mut()
            .ok_or(MultiAssetBackendError::NoProposal)?[index];
        attempt.signatures.push(signature);
        attempt
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        Ok(())
    }
    pub fn close_authorization(&self, transaction_hash: &Bytes32) -> Result<StateAuthorization> {
        self.validate_close()?;
        let attempt = self.close_attempt(transaction_hash)?;
        if attempt.signatures.len() != 2 {
            return Err(MultiAssetBackendError::IncompleteSignatures);
        }
        Ok(StateAuthorization {
            threshold: 2,
            signatures: attempt.signatures.clone(),
        })
    }
    pub fn close_witness(&self, transaction_hash: &Bytes32) -> Result<Vec<u8>> {
        use morph_script_common::multi_asset_close as wire;
        let signatures =
            crate::encode_multi_asset_signatures(&self.close_authorization(transaction_hash)?)?;
        let current = self.current();
        let inner = crate::encode_multi_asset_witness(
            &current.manifest,
            &current.settlement,
            &current.outpoints,
            &current.scripts,
        )?;
        let mut raw = vec![0; wire::MULTI_ASSET_CLOSE_FIXED_LEN + inner.len()];
        wire::encode_multi_asset_close(
            &mut raw,
            transaction_hash,
            &current.state.encode()?,
            &signatures,
            &inner,
        )
        .map_err(MultiAssetError::from)?;
        Ok(raw)
    }
    pub fn cancel_close(&mut self) -> Result<()> {
        if self
            .close_attempts()
            .iter()
            .any(|attempt| attempt.signature_reserved || !attempt.signatures.is_empty())
        {
            return Err(MultiAssetBackendError::CloseFrozen);
        }
        self.snapshot.close = None;
        Ok(())
    }
}
