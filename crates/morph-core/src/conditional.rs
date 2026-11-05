//! Bounded, CKB-enforceable conditional batches for bilateral channels.
//!
//! A batch is signed once as part of a current Morph state. Fulfilled
//! transfers are then authorised by preimages; refunds are authorised only by
//! canonical absolute-block `since` values. The fixed-size wire profile keeps
//! host and CKB-script parsing identical and bounded.

use std::collections::{BTreeMap, BTreeSet};

use morph_script_common::{
    BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN, BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
    BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT, BilateralCkbConditionalDescriptor,
    CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN, CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION,
    CONDITIONAL_HASH_CKB_BLAKE2B, CONDITIONAL_HASH_SHA256, CONDITIONAL_RESOLUTION_FULFILL,
    CONDITIONAL_RESOLUTION_LEN, CONDITIONAL_RESOLUTION_REFUND, CONDITIONAL_TRANSFER_LEN,
    CONDITIONAL_TRANSFER_MAX_COUNT, ConditionalBatchResolutionWitness, absolute_block_since,
    conditional_payment_hash, write_u16, write_u64,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Bytes32, blake2b256};

pub const CONDITIONAL_BATCH_ID_DOMAIN: &[u8] = b"CKB_MORPH_CONDITIONAL_BATCH_ID_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionalHashAlgorithm {
    CkbBlake2b,
    Sha256,
}

impl ConditionalHashAlgorithm {
    const fn as_u8(self) -> u8 {
        match self {
            Self::CkbBlake2b => CONDITIONAL_HASH_CKB_BLAKE2B,
            Self::Sha256 => CONDITIONAL_HASH_SHA256,
        }
    }

    fn from_u8(value: u8) -> ConditionalResult<Self> {
        match value {
            CONDITIONAL_HASH_CKB_BLAKE2B => Ok(Self::CkbBlake2b),
            CONDITIONAL_HASH_SHA256 => Ok(Self::Sha256),
            _ => Err(ConditionalError::Encoding),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalParticipant {
    pub settlement_lock_hash: Bytes32,
    /// Capacity not reserved by any pending transfer.
    pub settled_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalTransferSpec {
    pub transfer_id: Bytes32,
    pub payer_lock_hash: Bytes32,
    pub hash_algorithm: ConditionalHashAlgorithm,
    pub payment_hash: Bytes32,
    pub amount: u64,
    /// Absolute CKB block number. The wire stores its canonical `since` form.
    pub refund_after_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalBatch {
    pub batch_id: Bytes32,
    pub application_context_commitment: Bytes32,
    pub participants: [ConditionalParticipant; 2],
    pub transfers: Vec<ConditionalTransferSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConditionalResolution {
    Fulfill { preimage: Bytes32 },
    Refund,
}

impl ConditionalBatch {
    pub fn validate(&self) -> ConditionalResult<()> {
        self.encode_descriptor().map(|_| ())
    }

    pub fn encode_descriptor(
        &self,
    ) -> ConditionalResult<[u8; BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN]> {
        if is_zero(&self.batch_id)
            || is_zero(&self.application_context_commitment)
            || self.transfers.len() > CONDITIONAL_TRANSFER_MAX_COUNT as usize
        {
            return Err(ConditionalError::InvalidBatch);
        }

        let participants = &self.participants;
        if is_zero(&participants[0].settlement_lock_hash)
            || participants[0].settlement_lock_hash >= participants[1].settlement_lock_hash
        {
            return Err(ConditionalError::InvalidParticipants);
        }

        let transfers = &self.transfers;
        let mut payment_hashes = BTreeSet::new();
        let participant_locks = [
            participants[0].settlement_lock_hash,
            participants[1].settlement_lock_hash,
        ];
        for (index, transfer) in transfers.iter().enumerate() {
            if is_zero(&transfer.transfer_id)
                || is_zero(&transfer.payment_hash)
                || transfer.amount == 0
                || !participant_locks.contains(&transfer.payer_lock_hash)
                || (index > 0 && transfers[index - 1].transfer_id >= transfer.transfer_id)
                || !payment_hashes.insert(transfer.payment_hash)
            {
                return Err(ConditionalError::InvalidTransfer);
            }
            absolute_block_since(transfer.refund_after_block)
                .map_err(|_| ConditionalError::InvalidRefundBlock)?;
            if transfer.refund_after_block == 0 {
                return Err(ConditionalError::InvalidRefundBlock);
            }
        }

        let mut raw = [0u8; BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN];
        write_u16(&mut raw, 0, BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION);
        raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
        raw[3] = CONDITIONAL_TRANSFER_MAX_COUNT;
        raw[4..36].copy_from_slice(&self.batch_id);
        raw[36..68].copy_from_slice(&self.application_context_commitment);
        raw[68] = transfers.len() as u8;
        for (index, participant) in participants.iter().enumerate() {
            let offset = conditional_participant_offset(index);
            raw[offset..offset + 32].copy_from_slice(&participant.settlement_lock_hash);
            write_u64(&mut raw, offset + 32, participant.settled_capacity);
        }
        for (index, transfer) in transfers.iter().enumerate() {
            let offset = conditional_transfer_offset(index);
            raw[offset..offset + 32].copy_from_slice(&transfer.transfer_id);
            raw[offset + 32] = participant_locks
                .iter()
                .position(|lock| lock == &transfer.payer_lock_hash)
                .ok_or(ConditionalError::InvalidTransfer)? as u8;
            raw[offset + 33] = transfer.hash_algorithm.as_u8();
            raw[offset + 36..offset + 68].copy_from_slice(&transfer.payment_hash);
            write_u64(&mut raw, offset + 68, transfer.amount);
            write_u64(
                &mut raw,
                offset + 76,
                absolute_block_since(transfer.refund_after_block)
                    .map_err(|_| ConditionalError::InvalidRefundBlock)?,
            );
        }
        BilateralCkbConditionalDescriptor::parse(&raw).map_err(|_| ConditionalError::Encoding)?;
        Ok(raw)
    }

    pub fn decode_descriptor(raw: &[u8]) -> ConditionalResult<Self> {
        let descriptor = BilateralCkbConditionalDescriptor::parse(raw)
            .map_err(|_| ConditionalError::Encoding)?;
        let participants = [
            ConditionalParticipant {
                settlement_lock_hash: copy32(descriptor.lock_hash(0))?,
                settled_capacity: descriptor.settled_capacity(0),
            },
            ConditionalParticipant {
                settlement_lock_hash: copy32(descriptor.lock_hash(1))?,
                settled_capacity: descriptor.settled_capacity(1),
            },
        ];
        let mut transfers = Vec::with_capacity(descriptor.transfer_count() as usize);
        for index in 0..descriptor.transfer_count() as usize {
            let transfer = descriptor
                .transfer(index)
                .map_err(|_| ConditionalError::Encoding)?;
            let refund_since = transfer.refund_after_since();
            transfers.push(ConditionalTransferSpec {
                transfer_id: copy32(transfer.transfer_id())?,
                payer_lock_hash: participants[transfer.payer_index() as usize].settlement_lock_hash,
                hash_algorithm: ConditionalHashAlgorithm::from_u8(transfer.hash_algorithm())?,
                payment_hash: copy32(transfer.payment_hash())?,
                amount: transfer.amount(),
                refund_after_block: refund_since & 0x00ff_ffff_ffff_ffff,
            });
        }
        Ok(Self {
            batch_id: copy32(descriptor.batch_id())?,
            application_context_commitment: copy32(descriptor.application_context_commitment())?,
            participants,
            transfers,
        })
    }

    pub fn total_capacity(&self) -> ConditionalResult<u64> {
        let raw = self.encode_descriptor()?;
        BilateralCkbConditionalDescriptor::parse(&raw)
            .map_err(|_| ConditionalError::Encoding)?
            .checked_total_capacity()
            .map_err(|_| ConditionalError::CapacityOverflow)
    }

    pub fn encode_resolution_witness(
        &self,
        resolutions: &BTreeMap<Bytes32, ConditionalResolution>,
    ) -> ConditionalResult<[u8; CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN]> {
        let descriptor = self.encode_descriptor()?;
        if resolutions.len() != self.transfers.len() {
            return Err(ConditionalError::MissingResolution);
        }
        let mut transfer_ids = self
            .transfers
            .iter()
            .map(|transfer| transfer.transfer_id)
            .collect::<Vec<_>>();
        transfer_ids.sort();

        let mut raw = [0u8; CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN];
        write_u16(&mut raw, 0, CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION);
        raw[2] = transfer_ids.len() as u8;
        raw[4..4 + BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN].copy_from_slice(&descriptor);
        for (index, transfer_id) in transfer_ids.iter().enumerate() {
            let resolution = resolutions
                .get(transfer_id)
                .ok_or(ConditionalError::MissingResolution)?;
            let offset = conditional_resolution_offset(index);
            match resolution {
                ConditionalResolution::Fulfill { preimage } => {
                    if is_zero(preimage) {
                        return Err(ConditionalError::InvalidPreimage);
                    }
                    raw[offset] = CONDITIONAL_RESOLUTION_FULFILL;
                    raw[offset + 1..offset + 33].copy_from_slice(preimage);
                }
                ConditionalResolution::Refund => {
                    raw[offset] = CONDITIONAL_RESOLUTION_REFUND;
                }
            }
        }
        ConditionalBatchResolutionWitness::parse(&raw).map_err(|_| ConditionalError::Encoding)?;
        Ok(raw)
    }

    pub fn resolve(
        &self,
        resolutions: &BTreeMap<Bytes32, ConditionalResolution>,
        input_since: u64,
    ) -> ConditionalResult<[u64; 2]> {
        let raw = self.encode_resolution_witness(resolutions)?;
        ConditionalBatchResolutionWitness::parse(&raw)
            .map_err(|_| ConditionalError::Encoding)?
            .resolved_capacities(input_since)
            .map_err(ConditionalError::from_script_error)
    }

    /// Computes a mutually signed consolidation: known preimages pay the
    /// receiver, while every still-unrevealed condition is cooperatively
    /// cancelled back to its payer without waiting for the on-chain timeout.
    pub fn cooperative_capacities(
        &self,
        preimages: &BTreeMap<Bytes32, Bytes32>,
    ) -> ConditionalResult<[u64; 2]> {
        let raw = self.encode_descriptor()?;
        let descriptor = BilateralCkbConditionalDescriptor::parse(&raw)
            .map_err(|_| ConditionalError::Encoding)?;
        if preimages.keys().any(|transfer_id| {
            !self
                .transfers
                .iter()
                .any(|transfer| &transfer.transfer_id == transfer_id)
        }) {
            return Err(ConditionalError::InvalidTransfer);
        }
        let mut capacities = [
            descriptor.settled_capacity(0),
            descriptor.settled_capacity(1),
        ];
        for index in 0..descriptor.transfer_count() as usize {
            let transfer = descriptor
                .transfer(index)
                .map_err(|_| ConditionalError::Encoding)?;
            let transfer_id = copy32(transfer.transfer_id())?;
            let recipient = if let Some(preimage) = preimages.get(&transfer_id) {
                let actual = conditional_payment_hash(transfer.hash_algorithm(), preimage)
                    .map_err(|_| ConditionalError::InvalidPreimage)?;
                if actual.as_slice() != transfer.payment_hash() {
                    return Err(ConditionalError::InvalidPreimage);
                }
                1usize.saturating_sub(transfer.payer_index() as usize)
            } else {
                transfer.payer_index() as usize
            };
            capacities[recipient] = capacities[recipient]
                .checked_add(transfer.amount())
                .ok_or(ConditionalError::CapacityOverflow)?;
        }
        Ok(capacities)
    }
}

pub fn derive_conditional_batch_id(
    channel_id: &Bytes32,
    funding_context_id: &Bytes32,
    state_number: u64,
    application_context_commitment: &Bytes32,
) -> Bytes32 {
    let mut raw = Vec::with_capacity(CONDITIONAL_BATCH_ID_DOMAIN.len() + 104);
    raw.extend_from_slice(CONDITIONAL_BATCH_ID_DOMAIN);
    raw.extend_from_slice(channel_id);
    raw.extend_from_slice(funding_context_id);
    raw.extend_from_slice(&state_number.to_le_bytes());
    raw.extend_from_slice(application_context_commitment);
    blake2b256(&raw)
}

pub fn derive_conditional_payment_hash(
    algorithm: ConditionalHashAlgorithm,
    preimage: &Bytes32,
) -> ConditionalResult<Bytes32> {
    conditional_payment_hash(algorithm.as_u8(), preimage)
        .map_err(|_| ConditionalError::InvalidPreimage)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConditionalError {
    #[error("conditional batch is invalid")]
    InvalidBatch,
    #[error("conditional batch participants are invalid")]
    InvalidParticipants,
    #[error("conditional transfer is invalid")]
    InvalidTransfer,
    #[error("conditional refund block is invalid")]
    InvalidRefundBlock,
    #[error("conditional descriptor or witness encoding is invalid")]
    Encoding,
    #[error("conditional capacity arithmetic overflowed")]
    CapacityOverflow,
    #[error("a conditional transfer resolution is missing")]
    MissingResolution,
    #[error("conditional preimage does not match")]
    InvalidPreimage,
    #[error("conditional refund has not matured")]
    RefundNotMature,
}

pub type ConditionalResult<T> = Result<T, ConditionalError>;

impl ConditionalError {
    fn from_script_error(error: morph_script_common::ScriptError) -> Self {
        match error {
            morph_script_common::ScriptError::ConditionalPreimageMismatch => Self::InvalidPreimage,
            morph_script_common::ScriptError::ConditionalRefundNotMature => Self::RefundNotMature,
            morph_script_common::ScriptError::ConditionalValueMismatch => Self::CapacityOverflow,
            _ => Self::Encoding,
        }
    }
}

fn conditional_participant_offset(index: usize) -> usize {
    4 + 2 * 32 + 1 + 7 + index * (32 + 8)
}

fn conditional_transfer_offset(index: usize) -> usize {
    4 + 2 * 32 + 1 + 7 + 2 * (32 + 8) + index * CONDITIONAL_TRANSFER_LEN
}

fn conditional_resolution_offset(index: usize) -> usize {
    4 + BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN + index * CONDITIONAL_RESOLUTION_LEN
}

fn copy32(raw: &[u8]) -> ConditionalResult<Bytes32> {
    raw.try_into().map_err(|_| ConditionalError::Encoding)
}

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ConditionalBatch {
        let participants = [
            ConditionalParticipant {
                settlement_lock_hash: [1; 32],
                settled_capacity: 100,
            },
            ConditionalParticipant {
                settlement_lock_hash: [2; 32],
                settled_capacity: 200,
            },
        ];
        let preimage_0 = [7; 32];
        let preimage_1 = [8; 32];
        ConditionalBatch {
            batch_id: [3; 32],
            application_context_commitment: [4; 32],
            participants,
            transfers: vec![
                ConditionalTransferSpec {
                    transfer_id: [5; 32],
                    payer_lock_hash: [1; 32],
                    hash_algorithm: ConditionalHashAlgorithm::Sha256,
                    payment_hash: derive_conditional_payment_hash(
                        ConditionalHashAlgorithm::Sha256,
                        &preimage_0,
                    )
                    .unwrap(),
                    amount: 25,
                    refund_after_block: 500,
                },
                ConditionalTransferSpec {
                    transfer_id: [6; 32],
                    payer_lock_hash: [2; 32],
                    hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                    payment_hash: derive_conditional_payment_hash(
                        ConditionalHashAlgorithm::CkbBlake2b,
                        &preimage_1,
                    )
                    .unwrap(),
                    amount: 40,
                    refund_after_block: 600,
                },
            ],
        }
    }

    #[test]
    fn descriptor_round_trip_is_canonical() {
        let batch = fixture();
        let raw = batch.encode_descriptor().unwrap();
        assert_eq!(raw.len(), BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN);
        assert_eq!(ConditionalBatch::decode_descriptor(&raw).unwrap(), batch);
        assert_eq!(batch.total_capacity().unwrap(), 365);
    }

    #[test]
    fn mixed_fulfill_and_refund_resolves_exact_value() {
        let batch = fixture();
        let resolutions = BTreeMap::from([
            (
                [5; 32],
                ConditionalResolution::Fulfill { preimage: [7; 32] },
            ),
            ([6; 32], ConditionalResolution::Refund),
        ]);
        assert_eq!(batch.resolve(&resolutions, 600).unwrap(), [100, 265]);
        assert_eq!(
            batch.resolve(&resolutions, 599),
            Err(ConditionalError::RefundNotMature)
        );
    }

    #[test]
    fn wrong_preimage_fails_closed() {
        let batch = fixture();
        let resolutions = BTreeMap::from([
            (
                [5; 32],
                ConditionalResolution::Fulfill { preimage: [9; 32] },
            ),
            ([6; 32], ConditionalResolution::Refund),
        ]);
        assert_eq!(
            batch.resolve(&resolutions, 600),
            Err(ConditionalError::InvalidPreimage)
        );
    }

    #[test]
    fn duplicate_payment_hash_is_rejected() {
        let mut batch = fixture();
        batch.transfers[1].payment_hash = batch.transfers[0].payment_hash;
        assert_eq!(batch.validate(), Err(ConditionalError::InvalidTransfer));
    }

    #[test]
    fn noncanonical_participant_or_transfer_order_is_rejected() {
        let mut batch = fixture();
        batch.participants.swap(0, 1);
        assert_eq!(batch.validate(), Err(ConditionalError::InvalidParticipants));

        let mut batch = fixture();
        batch.transfers.swap(0, 1);
        assert_eq!(batch.validate(), Err(ConditionalError::InvalidTransfer));
    }

    #[test]
    fn zero_unconditional_capacity_is_rejected() {
        let mut batch = fixture();
        batch.participants[0].settled_capacity = 0;
        assert_eq!(batch.validate(), Err(ConditionalError::Encoding));
    }
}
