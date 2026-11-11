#![no_std]
#![forbid(unsafe_code)]

use ckb_hash::new_blake2b;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod crypto_vectors;

mod factory_empty_hashes;
pub mod factory_multi_asset;
pub mod multi_asset;
pub mod multi_asset_close;
pub mod multi_asset_conditional;
pub mod multi_asset_splice;
pub mod script_table;
extern crate alloc;
#[cfg(target_arch = "riscv64")]
pub mod factory_multi_asset_runtime;
#[cfg(target_arch = "riscv64")]
pub mod multi_asset_close_runtime;
#[cfg(target_arch = "riscv64")]
pub mod multi_asset_runtime;
#[cfg(target_arch = "riscv64")]
pub mod multi_asset_splice_runtime;

const CKB_SINCE_LOCK_TYPE_FLAG: u64 = 1 << 63;
const CKB_SINCE_METRIC_TYPE_FLAG_MASK: u64 = 0x6000_0000_0000_0000;
const CKB_SINCE_REMAIN_FLAGS_BITS: u64 = 0x1f00_0000_0000_0000;
const CKB_SINCE_VALUE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const CKB_SINCE_LOCK_BY_BLOCK_NUMBER: u64 = 0;

pub const BYTE32_LEN: usize = 32;

pub const SPONSOR_POLICY_LEN: usize = 136;

pub const CONDITIONAL_TRANSFER_LEN: usize = BYTE32_LEN + 1 + 1 + 2 + BYTE32_LEN + 16 + 8;

pub const CONDITIONAL_TRANSFER_MAX_COUNT: u8 = 8;

pub const CONDITIONAL_BATCH_DESCRIPTOR_PREFIX_LEN: usize = 2
    + 1
    + 1
    + BYTE32_LEN
    + BYTE32_LEN
    + 1
    + 7
    + multi_asset::MULTI_ASSET_ID_LEN
    + 2 * (BYTE32_LEN + 8 + 16);
pub const CONDITIONAL_BATCH_DESCRIPTOR_MAX_LEN: usize = CONDITIONAL_BATCH_DESCRIPTOR_PREFIX_LEN
    + CONDITIONAL_TRANSFER_MAX_COUNT as usize * CONDITIONAL_TRANSFER_LEN;
pub const CONDITIONAL_RESOLUTION_MAX_LEN: usize = 1 + BYTE32_LEN;
pub const CONDITIONAL_BATCH_RESOLUTION_WITNESS_MAX_LEN: usize = 4
    + CONDITIONAL_BATCH_DESCRIPTOR_MAX_LEN
    + CONDITIONAL_TRANSFER_MAX_COUNT as usize * CONDITIONAL_RESOLUTION_MAX_LEN;

pub const COMPRESSED_SECP256K1_PUBKEY_LEN: usize = 33;

pub const ECDSA_SIGNATURE_LEN: usize = 64;

pub const BILATERAL_SIGNATURE_WITNESS_LEN: usize =
    2 + 1 + 1 + (2 * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN));

pub const FACTORY_MIN_PARTICIPANTS: u8 = 2;

pub const FACTORY_MAX_PARTICIPANTS: u8 = 16;

pub const FACTORY_SIGNATURE_ENTRY_LEN: usize =
    BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN;

pub const FACTORY_SIGNATURE_HEADER_LEN: usize = 2 + 1 + 1;

pub const FACTORY_RIGHT_LEN: usize = BYTE32_LEN + BYTE32_LEN + 1 + 1 + BYTE32_LEN + 16;

pub const FACTORY_SPARSE_MERKLE_DEPTH: usize = 256;

pub const FACTORY_COMPACT_PROOF_MAX_SIBLINGS: usize = 64;

pub const FACTORY_COMPACT_PROOF_PAIR_LEN: usize = 2 + BYTE32_LEN;

pub const PHASE_ACTIVE: u8 = 1;

pub const PHASE_SETTLING: u8 = 2;

pub const MORPH_PROTOCOL_VERSION: u16 = 1;

pub const SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B: u16 = 1;

pub const BILATERAL_SIGNATURE_WITNESS_VERSION: u16 = 1;

pub const BILATERAL_SIGNATURE_THRESHOLD: u8 = 2;

pub const BILATERAL_SIGNATURE_COUNT: u8 = 2;

pub const FACTORY_RIGHT_KIND_BALANCE: u8 = 0;

pub const FACTORY_RIGHT_KIND_RESERVE_CLAIM: u8 = 1;

pub const FACTORY_RIGHT_KIND_SPONSOR_BUDGET_CLAIM: u8 = 4;

pub const FACTORY_SIGNATURE_WITNESS_VERSION: u16 = 1;

pub const FACTORY_RIGHT_EMPTY_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_EMPTY";

pub const ASSET_REGISTRY_DOMAIN: &[u8] = b"CKB_MORPH_ASSET_REGISTRY_V1";

pub const PARTICIPANTS_DOMAIN: &[u8] = b"CKB_MORPH_PARTICIPANTS";

pub const FACTORY_PARTICIPANTS_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_PARTICIPANTS";

pub const FACTORY_RIGHT_KEY_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_KEY";

pub const FACTORY_RIGHT_LEAF_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_LEAF";

pub const FACTORY_RIGHT_NODE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_NODE";

pub const SETTLEMENT_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_SETTLEMENT_DESCRIPTOR";

pub const CONDITIONAL_BATCH_DESCRIPTOR_VERSION: u16 = 5;

pub const CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION: u16 = 3;

pub const CONDITIONAL_HASH_CKB_BLAKE2B: u8 = 0;

pub const CONDITIONAL_HASH_SHA256: u8 = 1;

pub const CONDITIONAL_RESOLUTION_UNUSED: u8 = 0;

pub const CONDITIONAL_RESOLUTION_FULFILL: u8 = 1;

pub const CONDITIONAL_RESOLUTION_REFUND: u8 = 2;

pub const STATE_MODE_BILATERAL_PLAINTEXT: u8 = 1;

pub const CONDITIONAL_PARTICIPANT_COUNT: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptError {
    IndexOutOfBounds = 5,
    Encoding = 6,
    WrongArgsLength = 7,
    WrongGroupShape = 8,
    FundingAnchorMismatch = 9,
    NonMonotonicStateNumber = 10,
    NewStateNotSettling = 11,
    HeaderContextChanged = 12,
    OutputBelowOccupiedCapacity = 13,
    StateCellMissing = 14,
    StateCellAmbiguous = 15,
    StateSinceNotMature = 16,
    SponsorFeeTooHigh = 17,
    SponsorBudgetExceeded = 18,
    // 19 is reserved; retired error code.
    CapacityUnderflow = 20,
    ParticipantWitnessMissing = 21,
    ParticipantWitnessEncoding = 22,
    ParticipantCommitmentMismatch = 23,
    InvalidParticipantSignature = 24,
    SettlementWitnessMissing = 25,
    // 26 is reserved; retired error code.
    // 27 is reserved; retired error code.
    // 28 is reserved; retired error code.
    SponsorStateOutOfRange = 29,
    XudtAmountEncoding = 30,
    XudtMintUnauthorised = 31,
    XudtConservationMismatch = 32,
    // 33 is reserved; retired error code.
    FactoryIdMismatch = 34,
    // 35 is reserved; retired error code.
    // 36 is reserved; retired error code.
    StateTypeMismatch = 37,
    FactoryReducedProofEncoding = 38,
    FactoryReducedProofMismatch = 39,
    // 44 is reserved; retired error code.
    // 46 is reserved; retired error code.
    // 47 is reserved; retired error code.
    // 48 is reserved; retired error code.
    VaultOutPointMismatch = 50,
    VaultActivationInvalid = 51,
    StateCarrierMismatch = 52,
    SponsorFeeMismatch = 53,
    UnsupportedProtocolProfile = 54,
    ConditionalDescriptorEncoding = 55,
    ConditionalBatchOutputMismatch = 56,
    ConditionalResolutionEncoding = 57,
    ConditionalPreimageMismatch = 58,
    ConditionalRefundNotMature = 59,
    ConditionalBatchLockMismatch = 60,
    ConditionalValueMismatch = 61,
    MultiAssetEncoding = 62,
    MultiAssetCommitmentMismatch = 63,
    MultiAssetConservationMismatch = 64,
    MultiAssetCapacityMismatch = 65,
    MultiAssetVaultSetIncomplete = 66,
    MultiAssetSpliceEncoding = 67,
    MultiAssetSpliceMismatch = 68,
    FactoryMultiAssetPartitionMismatch = 69,
    MultiAssetCloseEncoding = 70,
    MultiAssetCloseMismatch = 71,
}

pub type Result<T> = core::result::Result<T, ScriptError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilateralSignatureWitness<'a> {
    raw: &'a [u8],
}

impl<'a> BilateralSignatureWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != BILATERAL_SIGNATURE_WITNESS_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        if witness.version() != BILATERAL_SIGNATURE_WITNESS_VERSION
            || witness.threshold() != BILATERAL_SIGNATURE_THRESHOLD
            || witness.count() != BILATERAL_SIGNATURE_COUNT
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        if witness.pubkey(0) >= witness.pubkey(1) {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn count(&self) -> u8 {
        self.raw[3]
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        let offset = participant_offset(index);
        field(self.raw, offset, COMPRESSED_SECP256K1_PUBKEY_LEN)
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        let offset = participant_offset(index) + COMPRESSED_SECP256K1_PUBKEY_LEN;
        field(self.raw, offset, ECDSA_SIGNATURE_LEN)
    }

    pub fn participants_commitment(&self) -> [u8; 32] {
        participants_commitment(self.threshold(), &[self.pubkey(0), self.pubkey(1)])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorySignatureWitness<'a> {
    raw: &'a [u8],
}

impl<'a> FactorySignatureWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < FACTORY_SIGNATURE_HEADER_LEN {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        let witness = Self { raw };
        let count = witness.count();
        if witness.version() != FACTORY_SIGNATURE_WITNESS_VERSION
            || !(FACTORY_MIN_PARTICIPANTS..=FACTORY_MAX_PARTICIPANTS).contains(&count)
            || witness.threshold() != count
            || raw.len() != factory_signature_witness_len(count)
        {
            return Err(ScriptError::ParticipantWitnessEncoding);
        }
        witness.validate_participant_set()?;
        Ok(witness)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn threshold(&self) -> u8 {
        self.raw[2]
    }

    pub fn count(&self) -> u8 {
        self.raw[3]
    }

    pub fn participant(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_signature_participant_offset(index),
            BYTE32_LEN,
        )
    }

    pub fn pubkey(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_signature_participant_offset(index) + BYTE32_LEN,
            COMPRESSED_SECP256K1_PUBKEY_LEN,
        )
    }

    pub fn signature(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            factory_signature_participant_offset(index)
                + BYTE32_LEN
                + COMPRESSED_SECP256K1_PUBKEY_LEN,
            ECDSA_SIGNATURE_LEN,
        )
    }

    pub fn participants_commitment(&self) -> [u8; BYTE32_LEN] {
        let threshold = [self.threshold()];
        let count = [self.count()];
        let mut hasher = new_blake2b();
        hasher.update(FACTORY_PARTICIPANTS_DOMAIN);
        hasher.update(&threshold);
        hasher.update(&count);
        for index in 0..self.count() as usize {
            hasher.update(self.participant(index));
            hasher.update(self.pubkey(index));
        }
        let mut out = [0u8; BYTE32_LEN];
        hasher.finalize(&mut out);
        out
    }

    pub fn pubkey_participants_commitment(&self) -> [u8; BYTE32_LEN] {
        let threshold = [self.threshold()];
        let count = [self.count()];
        let mut hasher = new_blake2b();
        hasher.update(PARTICIPANTS_DOMAIN);
        hasher.update(&threshold);
        hasher.update(&count);
        for index in 0..self.count() as usize {
            hasher.update(self.pubkey(index));
        }
        let mut out = [0u8; BYTE32_LEN];
        hasher.finalize(&mut out);
        out
    }

    fn validate_participant_set(&self) -> Result<()> {
        for index in 0..self.count() as usize {
            if index > 0 && self.participant(index - 1) >= self.participant(index) {
                return Err(ScriptError::ParticipantWitnessEncoding);
            }
            for previous in 0..index {
                if self.pubkey(previous) == self.pubkey(index) {
                    return Err(ScriptError::ParticipantWitnessEncoding);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryRight<'a> {
    identity: &'a [u8],
    quantity: &'a [u8],
}

impl<'a> FactoryRight<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != FACTORY_RIGHT_LEN {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let right = Self {
            identity: &raw[..FACTORY_RIGHT_LEN - 16],
            quantity: &raw[FACTORY_RIGHT_LEN - 16..],
        };
        if right.kind() > 4 {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        match right.asset_present() {
            0 => {
                if !right.asset_type().iter().all(|value| *value == 0) {
                    return Err(ScriptError::FactoryReducedProofEncoding);
                }
            }
            1 => {}
            _ => return Err(ScriptError::FactoryReducedProofEncoding),
        }
        Ok(right)
    }

    pub fn participant(&self) -> &'a [u8] {
        field(self.identity, 0, BYTE32_LEN)
    }

    pub fn subchannel(&self) -> &'a [u8] {
        field(self.identity, BYTE32_LEN, BYTE32_LEN)
    }

    pub fn kind(&self) -> u8 {
        self.identity[2 * BYTE32_LEN]
    }

    pub fn asset_present(&self) -> u8 {
        self.identity[2 * BYTE32_LEN + 1]
    }

    pub fn asset_type(&self) -> &'a [u8] {
        field(self.identity, 2 * BYTE32_LEN + 2, BYTE32_LEN)
    }

    pub fn quantity(&self) -> u128 {
        read_u128(self.quantity, 0)
    }

    pub(crate) fn with_quantity(&self, quantity: &'a [u8]) -> Result<Self> {
        if quantity.len() != 16 {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        Ok(Self {
            identity: self.identity,
            quantity,
        })
    }

    fn id_key(&self) -> (&'a [u8], &'a [u8], u8, u8, &'a [u8]) {
        (
            self.participant(),
            self.subchannel(),
            self.kind(),
            self.asset_present(),
            self.asset_type(),
        )
    }

    fn same_id(&self, other: &Self) -> bool {
        self.id_key() == other.id_key()
    }

    fn same_asset(&self, other: &Self) -> bool {
        self.asset_present() == other.asset_present() && self.asset_type() == other.asset_type()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalTransfer<'a> {
    raw: &'a [u8],
}

impl<'a> ConditionalTransfer<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != CONDITIONAL_TRANSFER_LEN {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        let transfer = Self { raw };
        if transfer.transfer_id().iter().all(|byte| *byte == 0)
            || transfer.payer_index() > 1
            || !matches!(
                transfer.hash_algorithm(),
                CONDITIONAL_HASH_CKB_BLAKE2B | CONDITIONAL_HASH_SHA256
            )
            || transfer.reserved() != 0
            || transfer.payment_hash().iter().all(|byte| *byte == 0)
            || transfer.amount() == 0
            || transfer.refund_after_since() == 0
            || !since_is_valid_absolute_block(transfer.refund_after_since())
        {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        Ok(transfer)
    }

    pub fn transfer_id(&self) -> &'a [u8] {
        field(self.raw, 0, BYTE32_LEN)
    }

    pub fn payer_index(&self) -> u8 {
        self.raw[BYTE32_LEN]
    }

    pub fn hash_algorithm(&self) -> u8 {
        self.raw[BYTE32_LEN + 1]
    }

    pub fn reserved(&self) -> u16 {
        read_u16(self.raw, BYTE32_LEN + 2)
    }

    pub fn payment_hash(&self) -> &'a [u8] {
        field(self.raw, BYTE32_LEN + 4, BYTE32_LEN)
    }

    pub fn amount(&self) -> u128 {
        read_u128(self.raw, BYTE32_LEN + 4 + BYTE32_LEN)
    }

    pub fn refund_after_since(&self) -> u64 {
        read_u64(self.raw, BYTE32_LEN + 4 + BYTE32_LEN + 16)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalBatchDescriptor<'a> {
    raw: &'a [u8],
}

impl<'a> ConditionalBatchDescriptor<'a> {
    /// Determine one bounded term's length within a containing frame. Full
    /// validation and exact slice consumption remain the responsibility of parse.
    pub fn encoded_len(raw: &[u8]) -> Result<usize> {
        if raw.len() < CONDITIONAL_BATCH_DESCRIPTOR_PREFIX_LEN
            || read_u16(raw, 0) != CONDITIONAL_BATCH_DESCRIPTOR_VERSION
            || !(1..=CONDITIONAL_TRANSFER_MAX_COUNT).contains(&raw[68])
        {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        let len =
            CONDITIONAL_BATCH_DESCRIPTOR_PREFIX_LEN + raw[68] as usize * CONDITIONAL_TRANSFER_LEN;
        if raw.len() < len {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        Ok(len)
    }
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != Self::encoded_len(raw)? {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        let descriptor = Self { raw };
        let asset = descriptor.asset()?;
        if asset == multi_asset::MultiAssetId::CKB
            && (descriptor.settled_amount(0) != 0 || descriptor.settled_amount(1) != 0)
        {
            return Err(ScriptError::ConditionalValueMismatch);
        }
        if descriptor.version() != CONDITIONAL_BATCH_DESCRIPTOR_VERSION
            || descriptor.output_count() != CONDITIONAL_PARTICIPANT_COUNT
            || descriptor.transfer_capacity() != CONDITIONAL_TRANSFER_MAX_COUNT
            || descriptor.transfer_count() == 0
            || descriptor.transfer_count() > CONDITIONAL_TRANSFER_MAX_COUNT
            || descriptor.reserved().iter().any(|byte| *byte != 0)
            || descriptor.batch_id().iter().all(|byte| *byte == 0)
            || descriptor
                .application_context_commitment()
                .iter()
                .all(|byte| *byte == 0)
            || descriptor.lock_hash(0).iter().all(|byte| *byte == 0)
            || descriptor.lock_hash(0) >= descriptor.lock_hash(1)
            || descriptor.settled_capacity(0) == 0
            || descriptor.settled_capacity(1) == 0
        {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }

        let mut previous_id: Option<&[u8]> = None;
        for index in 0..descriptor.transfer_count() as usize {
            let raw_transfer = field(
                descriptor.raw,
                conditional_descriptor_transfer_offset(index),
                CONDITIONAL_TRANSFER_LEN,
            );
            if index < descriptor.transfer_count() as usize {
                let transfer = ConditionalTransfer::parse(raw_transfer)?;
                if previous_id.is_some_and(|previous| previous >= transfer.transfer_id()) {
                    return Err(ScriptError::ConditionalDescriptorEncoding);
                }
                for earlier in 0..index {
                    if descriptor.transfer(earlier)?.payment_hash() == transfer.payment_hash() {
                        return Err(ScriptError::ConditionalDescriptorEncoding);
                    }
                }
                previous_id = Some(transfer.transfer_id());
            }
        }
        descriptor.checked_total_capacity()?;
        descriptor.checked_total_amount()?;
        Ok(descriptor)
    }

    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }

    pub fn output_count(&self) -> u8 {
        self.raw[2]
    }

    pub fn transfer_capacity(&self) -> u8 {
        self.raw[3]
    }

    pub fn batch_id(&self) -> &'a [u8] {
        field(self.raw, 4, BYTE32_LEN)
    }

    pub fn application_context_commitment(&self) -> &'a [u8] {
        field(self.raw, 4 + BYTE32_LEN, BYTE32_LEN)
    }

    pub fn transfer_count(&self) -> u8 {
        self.raw[4 + 2 * BYTE32_LEN]
    }

    pub fn reserved(&self) -> &'a [u8] {
        field(self.raw, 4 + 2 * BYTE32_LEN + 1, 7)
    }

    pub fn lock_hash(&self, index: usize) -> &'a [u8] {
        field(
            self.raw,
            conditional_descriptor_participant_offset(index),
            BYTE32_LEN,
        )
    }

    pub fn settled_capacity(&self, index: usize) -> u64 {
        read_u64(
            self.raw,
            conditional_descriptor_participant_offset(index) + BYTE32_LEN,
        )
    }

    pub fn asset(&self) -> Result<multi_asset::MultiAssetId> {
        multi_asset::MultiAssetId::parse(field(self.raw, 76, multi_asset::MULTI_ASSET_ID_LEN))
    }

    pub fn settled_amount(&self, index: usize) -> u128 {
        read_u128(
            self.raw,
            conditional_descriptor_participant_offset(index) + BYTE32_LEN + 8,
        )
    }

    pub fn checked_pending_amount(&self) -> Result<u128> {
        let mut total = 0u128;
        for index in 0..self.transfer_count() as usize {
            total = total
                .checked_add(self.transfer(index)?.amount())
                .ok_or(ScriptError::ConditionalValueMismatch)?;
        }
        Ok(total)
    }

    pub fn transfer(&self, index: usize) -> Result<ConditionalTransfer<'a>> {
        if index >= self.transfer_count() as usize {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        ConditionalTransfer::parse(field(
            self.raw,
            conditional_descriptor_transfer_offset(index),
            CONDITIONAL_TRANSFER_LEN,
        ))
    }

    pub fn checked_total_capacity(&self) -> Result<u64> {
        let total = self
            .settled_capacity(0)
            .checked_add(self.settled_capacity(1))
            .ok_or(ScriptError::ConditionalValueMismatch)?;
        if self.asset()? == multi_asset::MultiAssetId::CKB {
            total
                .checked_add(
                    u64::try_from(self.checked_pending_amount()?)
                        .map_err(|_| ScriptError::ConditionalValueMismatch)?,
                )
                .ok_or(ScriptError::ConditionalValueMismatch)
        } else {
            Ok(total)
        }
    }

    pub fn checked_total_amount(&self) -> Result<u128> {
        let total = self
            .settled_amount(0)
            .checked_add(self.settled_amount(1))
            .ok_or(ScriptError::ConditionalValueMismatch)?;
        if self.asset()?.kind == 1 {
            total
                .checked_add(self.checked_pending_amount()?)
                .ok_or(ScriptError::ConditionalValueMismatch)
        } else {
            Ok(total)
        }
    }

    pub fn commitment(&self) -> [u8; BYTE32_LEN] {
        settlement_descriptor_commitment(self.raw)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

/// Separate CKB capacity and token quantity. A pending amount enters exactly
/// one lane according to its committed asset; they are never interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalValue {
    pub capacity: u64,
    pub amount: u128,
}

impl ConditionalValue {
    pub fn add_pending(&mut self, is_ckb: bool, amount: u128) -> Result<()> {
        if is_ckb {
            self.capacity = self
                .capacity
                .checked_add(
                    u64::try_from(amount).map_err(|_| ScriptError::ConditionalValueMismatch)?,
                )
                .ok_or(ScriptError::ConditionalValueMismatch)?;
        } else {
            self.amount = self
                .amount
                .checked_add(amount)
                .ok_or(ScriptError::ConditionalValueMismatch)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalResolution<'a> {
    raw: &'a [u8],
}

impl<'a> ConditionalResolution<'a> {
    pub fn kind(&self) -> u8 {
        self.raw[0]
    }

    pub fn preimage(&self) -> &'a [u8] {
        if self.kind() == CONDITIONAL_RESOLUTION_REFUND {
            &[0; BYTE32_LEN]
        } else {
            field(self.raw, 1, BYTE32_LEN)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalBatchResolutionWitness<'a> {
    raw: &'a [u8],
    descriptor: ConditionalBatchDescriptor<'a>,
    resolutions: [Option<ConditionalResolution<'a>>; CONDITIONAL_TRANSFER_MAX_COUNT as usize],
}

impl<'a> ConditionalBatchResolutionWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 4 + CONDITIONAL_BATCH_DESCRIPTOR_PREFIX_LEN
            || raw.len() > CONDITIONAL_BATCH_RESOLUTION_WITNESS_MAX_LEN
            || read_u16(raw, 0) != CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION
            || raw[3] != 0
        {
            return Err(ScriptError::ConditionalResolutionEncoding);
        }
        let descriptor_len = ConditionalBatchDescriptor::encoded_len(&raw[4..])?;
        let descriptor = ConditionalBatchDescriptor::parse(&raw[4..4 + descriptor_len])?;
        if raw[2] != descriptor.transfer_count() {
            return Err(ScriptError::ConditionalResolutionEncoding);
        }
        let mut resolutions = [None; CONDITIONAL_TRANSFER_MAX_COUNT as usize];
        let mut offset = 4 + descriptor_len;
        for slot in resolutions.iter_mut().take(raw[2] as usize) {
            let kind = *raw
                .get(offset)
                .ok_or(ScriptError::ConditionalResolutionEncoding)?;
            let len = match kind {
                CONDITIONAL_RESOLUTION_FULFILL => CONDITIONAL_RESOLUTION_MAX_LEN,
                CONDITIONAL_RESOLUTION_REFUND => 1,
                _ => return Err(ScriptError::ConditionalResolutionEncoding),
            };
            let bytes = raw
                .get(offset..offset + len)
                .ok_or(ScriptError::ConditionalResolutionEncoding)?;
            let resolution = ConditionalResolution { raw: bytes };
            if kind == CONDITIONAL_RESOLUTION_FULFILL
                && resolution.preimage().iter().all(|byte| *byte == 0)
            {
                return Err(ScriptError::ConditionalResolutionEncoding);
            }
            *slot = Some(resolution);
            offset += len;
        }
        if offset != raw.len() {
            return Err(ScriptError::ConditionalResolutionEncoding);
        }
        Ok(Self {
            raw,
            descriptor,
            resolutions,
        })
    }
    pub fn version(&self) -> u16 {
        read_u16(self.raw, 0)
    }
    pub fn resolution_count(&self) -> u8 {
        self.raw[2]
    }
    pub fn reserved(&self) -> u8 {
        self.raw[3]
    }
    pub fn descriptor(&self) -> Result<ConditionalBatchDescriptor<'a>> {
        Ok(self.descriptor)
    }
    pub fn resolution(&self, index: usize) -> Result<ConditionalResolution<'a>> {
        if index >= self.resolution_count() as usize {
            return Err(ScriptError::ConditionalResolutionEncoding);
        }
        self.resolutions[index].ok_or(ScriptError::ConditionalResolutionEncoding)
    }

    pub fn resolved_values(&self, input_since: u64) -> Result<[ConditionalValue; 2]> {
        let descriptor = self.descriptor()?;
        let mut values = core::array::from_fn(|index| ConditionalValue {
            capacity: descriptor.settled_capacity(index),
            amount: descriptor.settled_amount(index),
        });
        let is_ckb = descriptor.asset()? == multi_asset::MultiAssetId::CKB;
        for index in 0..descriptor.transfer_count() as usize {
            let transfer = descriptor.transfer(index)?;
            let resolution = self.resolution(index)?;
            let recipient = match resolution.kind() {
                CONDITIONAL_RESOLUTION_FULFILL => {
                    let actual =
                        conditional_payment_hash(transfer.hash_algorithm(), resolution.preimage())?;
                    if actual.as_slice() != transfer.payment_hash() {
                        return Err(ScriptError::ConditionalPreimageMismatch);
                    }
                    1usize.saturating_sub(transfer.payer_index() as usize)
                }
                CONDITIONAL_RESOLUTION_REFUND => {
                    validate_absolute_block_since(input_since, transfer.refund_after_since())
                        .map_err(|_| ScriptError::ConditionalRefundNotMature)?;
                    transfer.payer_index() as usize
                }
                _ => return Err(ScriptError::ConditionalResolutionEncoding),
            };
            values[recipient].add_pending(is_ckb, transfer.amount())?;
        }
        if values[0]
            .capacity
            .checked_add(values[1].capacity)
            .ok_or(ScriptError::ConditionalValueMismatch)?
            != descriptor.checked_total_capacity()?
            || values[0].amount.checked_add(values[1].amount)
                != Some(descriptor.checked_total_amount()?)
        {
            return Err(ScriptError::ConditionalValueMismatch);
        }
        Ok(values)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorPolicy<'a> {
    raw: &'a [u8],
}

impl<'a> SponsorPolicy<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != SPONSOR_POLICY_LEN {
            return Err(ScriptError::Encoding);
        }
        Ok(Self { raw })
    }

    pub fn channel_id(&self) -> &'a [u8] {
        field(self.raw, 0, 32)
    }

    pub fn min_state_number(&self) -> u64 {
        read_u64(self.raw, 32)
    }

    pub fn max_state_number(&self) -> u64 {
        read_u64(self.raw, 40)
    }

    pub fn max_fee_per_tx(&self) -> u64 {
        read_u64(self.raw, 48)
    }

    pub fn max_total_fee(&self) -> u64 {
        read_u64(self.raw, 56)
    }

    pub fn already_spent(&self) -> u64 {
        read_u64(self.raw, 64)
    }

    pub fn publication_state_type_hash(&self) -> &'a [u8] {
        field(self.raw, 72, 32)
    }

    pub fn change_lock(&self) -> &'a [u8] {
        field(self.raw, 104, 32)
    }
}

pub const fn factory_signature_witness_len(participant_count: u8) -> usize {
    FACTORY_SIGNATURE_HEADER_LEN + participant_count as usize * FACTORY_SIGNATURE_ENTRY_LEN
}

fn verify_factory_signatures_for_digest(
    digest: &[u8; BYTE32_LEN],
    witness: &FactorySignatureWitness,
) -> Result<()> {
    for index in 0..witness.count() as usize {
        let verifying_key = VerifyingKey::from_sec1_bytes(witness.pubkey(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        let signature = Signature::try_from(witness.signature(index))
            .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
        verifying_key
            .verify_prehash(digest, &signature)
            .map_err(|_| ScriptError::InvalidParticipantSignature)?;
    }
    Ok(())
}

fn factory_sparse_empty_hashes() -> &'static [[u8; BYTE32_LEN]; FACTORY_SPARSE_MERKLE_DEPTH + 1] {
    &factory_empty_hashes::HASHES
}

fn factory_compact_proof_pair_roots_cached(
    raw: &[u8],
    offset_before: usize,
    offset_after: usize,
    right_before: &FactoryRight,
    right_after: &FactoryRight,
    other_keys: &[[u8; BYTE32_LEN]],
    empty_hashes: &[[u8; BYTE32_LEN]; FACTORY_SPARSE_MERKLE_DEPTH + 1],
) -> Result<([u8; BYTE32_LEN], [u8; BYTE32_LEN])> {
    let key = factory_right_key(right_before);
    let mut current_before = factory_right_leaf_hash(right_before);
    let mut current_after = factory_right_leaf_hash(right_after);
    let count_before = read_u16(raw, offset_before) as usize;
    let count_after = read_u16(raw, offset_after) as usize;
    let mut pair_before = 0usize;
    let mut pair_after = 0usize;
    for depth in (0..FACTORY_SPARSE_MERKLE_DEPTH).rev() {
        let empty = empty_hashes[FACTORY_SPARSE_MERKLE_DEPTH - depth - 1];
        let mut sibling_before = empty;
        let pair_offset_before = offset_before + 2 + pair_before * FACTORY_COMPACT_PROOF_PAIR_LEN;
        if pair_before < count_before && read_u16(raw, pair_offset_before) as usize == depth {
            sibling_before.copy_from_slice(field(raw, pair_offset_before + 2, BYTE32_LEN));
            pair_before += 1;
        }
        let mut sibling_after = empty;
        let pair_offset_after = offset_after + 2 + pair_after * FACTORY_COMPACT_PROOF_PAIR_LEN;
        if pair_after < count_after && read_u16(raw, pair_offset_after) as usize == depth {
            sibling_after.copy_from_slice(field(raw, pair_offset_after + 2, BYTE32_LEN));
            pair_after += 1;
        }
        if sibling_before != sibling_after {
            let sibling_bit = !factory_key_bit(&key, depth);
            let mut excused = false;
            for other in other_keys {
                if factory_key_in_sibling_subtree(&key, other, depth, sibling_bit) {
                    excused = true;
                    break;
                }
            }
            if !excused {
                return Err(ScriptError::FactoryReducedProofMismatch);
            }
        }
        current_before = if factory_key_bit(&key, depth) {
            factory_right_node_hash(depth, &sibling_before, &current_before)
        } else {
            factory_right_node_hash(depth, &current_before, &sibling_before)
        };
        current_after = if factory_key_bit(&key, depth) {
            factory_right_node_hash(depth, &sibling_after, &current_after)
        } else {
            factory_right_node_hash(depth, &current_after, &sibling_after)
        };
    }
    if pair_before != count_before || pair_after != count_after {
        return Err(ScriptError::FactoryReducedProofEncoding);
    }
    Ok((current_before, current_after))
}

pub fn conditional_payment_hash(algorithm: u8, preimage: &[u8]) -> Result<[u8; BYTE32_LEN]> {
    if preimage.len() != BYTE32_LEN {
        return Err(ScriptError::ConditionalResolutionEncoding);
    }
    match algorithm {
        CONDITIONAL_HASH_CKB_BLAKE2B => Ok(blake2b256(&[preimage])),
        CONDITIONAL_HASH_SHA256 => {
            let digest = Sha256::digest(preimage);
            let mut hash = [0u8; BYTE32_LEN];
            hash.copy_from_slice(&digest);
            Ok(hash)
        }
        _ => Err(ScriptError::ConditionalDescriptorEncoding),
    }
}

pub fn settlement_descriptor_commitment(raw: &[u8]) -> [u8; 32] {
    blake2b256(&[SETTLEMENT_DESCRIPTOR_DOMAIN, raw])
}

pub fn read_u16(raw: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&raw[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

pub fn write_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn read_u64(raw: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&raw[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub fn write_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn read_u32(raw: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&raw[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

pub fn write_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn read_u128(raw: &[u8], offset: usize) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&raw[offset..offset + 16]);
    u128::from_le_bytes(bytes)
}

pub fn write_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

pub fn field(raw: &[u8], offset: usize, len: usize) -> &[u8] {
    &raw[offset..offset + len]
}

pub fn relative_block_since(value: u64) -> Result<u64> {
    if value & !CKB_SINCE_VALUE_MASK != 0 {
        return Err(ScriptError::StateSinceNotMature);
    }
    Ok(CKB_SINCE_LOCK_TYPE_FLAG | CKB_SINCE_LOCK_BY_BLOCK_NUMBER | value)
}

pub fn validate_relative_block_since(input_since: u64, required_since: u64) -> Result<()> {
    if !since_is_valid_relative_block(input_since) || !since_is_valid_relative_block(required_since)
    {
        return Err(ScriptError::StateSinceNotMature);
    }
    if (input_since & CKB_SINCE_VALUE_MASK) < (required_since & CKB_SINCE_VALUE_MASK) {
        return Err(ScriptError::StateSinceNotMature);
    }
    Ok(())
}

fn since_is_valid_relative_block(value: u64) -> bool {
    (value & CKB_SINCE_LOCK_TYPE_FLAG != 0)
        && (value & CKB_SINCE_REMAIN_FLAGS_BITS == 0)
        && (value & CKB_SINCE_METRIC_TYPE_FLAG_MASK == CKB_SINCE_LOCK_BY_BLOCK_NUMBER)
}

pub fn absolute_block_since(value: u64) -> Result<u64> {
    if value & !CKB_SINCE_VALUE_MASK != 0 {
        return Err(ScriptError::ConditionalRefundNotMature);
    }
    Ok(CKB_SINCE_LOCK_BY_BLOCK_NUMBER | value)
}

pub fn validate_absolute_block_since(input_since: u64, required_since: u64) -> Result<()> {
    if !since_is_valid_absolute_block(input_since)
        || !since_is_valid_absolute_block(required_since)
        || (input_since & CKB_SINCE_VALUE_MASK) < (required_since & CKB_SINCE_VALUE_MASK)
    {
        return Err(ScriptError::ConditionalRefundNotMature);
    }
    Ok(())
}

fn since_is_valid_absolute_block(value: u64) -> bool {
    (value & CKB_SINCE_LOCK_TYPE_FLAG == 0)
        && (value & CKB_SINCE_REMAIN_FLAGS_BITS == 0)
        && (value & CKB_SINCE_METRIC_TYPE_FLAG_MASK == CKB_SINCE_LOCK_BY_BLOCK_NUMBER)
}

pub fn blake2b256(chunks: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = new_blake2b();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize(&mut out);
    out
}

pub fn participants_commitment(threshold: u8, pubkeys: &[&[u8]]) -> [u8; 32] {
    let count = [pubkeys.len() as u8];
    let threshold = [threshold];
    let mut hasher = new_blake2b();
    hasher.update(PARTICIPANTS_DOMAIN);
    hasher.update(&threshold);
    hasher.update(&count);
    for pubkey in pubkeys {
        hasher.update(pubkey);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn asset_registry_commitment(type_hashes: &[&[u8]]) -> Result<[u8; 32]> {
    if type_hashes
        .iter()
        .any(|type_hash| type_hash.len() != BYTE32_LEN)
        || !type_hashes.windows(2).all(|window| window[0] < window[1])
    {
        return Err(ScriptError::Encoding);
    }
    let count = (type_hashes.len() as u64).to_le_bytes();
    let mut hasher = new_blake2b();
    hasher.update(ASSET_REGISTRY_DOMAIN);
    hasher.update(&count);
    for type_hash in type_hashes {
        hasher.update(type_hash);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    Ok(out)
}

pub fn factory_participants_commitment(threshold: u8, entries: &[(&[u8], &[u8])]) -> [u8; 32] {
    let count = [entries.len() as u8];
    let threshold = [threshold];
    let mut hasher = new_blake2b();
    hasher.update(FACTORY_PARTICIPANTS_DOMAIN);
    hasher.update(&threshold);
    hasher.update(&count);
    for (participant, pubkey) in entries {
        hasher.update(participant);
        hasher.update(pubkey);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn participant_offset(index: usize) -> usize {
    4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN)
}

fn factory_signature_participant_offset(index: usize) -> usize {
    FACTORY_SIGNATURE_HEADER_LEN + index * FACTORY_SIGNATURE_ENTRY_LEN
}

fn conditional_descriptor_participant_offset(index: usize) -> usize {
    4 + 2 * BYTE32_LEN + 1 + 7 + multi_asset::MULTI_ASSET_ID_LEN + index * (BYTE32_LEN + 8 + 16)
}

fn conditional_descriptor_transfer_offset(index: usize) -> usize {
    4 + 2 * BYTE32_LEN
        + 1
        + 7
        + multi_asset::MULTI_ASSET_ID_LEN
        + 2 * (BYTE32_LEN + 8 + 16)
        + index * CONDITIONAL_TRANSFER_LEN
}

#[cfg(test)]
fn conditional_resolution_offset(descriptor_len: usize, index: usize) -> usize {
    4 + descriptor_len + index * CONDITIONAL_RESOLUTION_MAX_LEN
}

fn factory_right_key(right: &FactoryRight) -> [u8; 32] {
    blake2b256(&[
        FACTORY_RIGHT_KEY_DOMAIN,
        right.participant(),
        right.subchannel(),
        &[right.kind()],
        &[right.asset_present()],
        right.asset_type(),
    ])
}

fn factory_right_leaf_hash(right: &FactoryRight) -> [u8; 32] {
    let key = factory_right_key(right);
    blake2b256(&[
        FACTORY_RIGHT_LEAF_DOMAIN,
        &key,
        right.identity,
        right.quantity,
    ])
}

fn factory_right_node_hash(depth: usize, left: &[u8], right: &[u8]) -> [u8; 32] {
    blake2b256(&[
        FACTORY_RIGHT_NODE_DOMAIN,
        &(depth as u16).to_le_bytes(),
        left,
        right,
    ])
}

fn factory_key_bit(key: &[u8; 32], depth: usize) -> bool {
    let byte = key[depth / 8];
    let mask = 0x80u8 >> (depth % 8);
    byte & mask != 0
}

fn factory_key_in_sibling_subtree(
    key: &[u8; BYTE32_LEN],
    candidate: &[u8; BYTE32_LEN],
    depth: usize,
    sibling_bit: bool,
) -> bool {
    let full_bytes = depth / 8;
    if candidate[..full_bytes] != key[..full_bytes] {
        return false;
    }
    let remainder = depth % 8;
    if remainder != 0 {
        let mask = 0xffu8 << (8 - remainder);
        if candidate[full_bytes] & mask != key[full_bytes] & mask {
            return false;
        }
    }
    factory_key_bit(candidate, depth) == sibling_bit
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
        raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
        raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn conditional_descriptor_bytes() -> alloc::vec::Vec<u8> {
        let mut raw = alloc::vec![0u8; CONDITIONAL_BATCH_DESCRIPTOR_PREFIX_LEN + 2 * CONDITIONAL_TRANSFER_LEN];
        put_u16(&mut raw, 0, CONDITIONAL_BATCH_DESCRIPTOR_VERSION);
        raw[2] = CONDITIONAL_PARTICIPANT_COUNT;
        raw[3] = CONDITIONAL_TRANSFER_MAX_COUNT;
        raw[4..36].fill(3);
        raw[36..68].fill(4);
        raw[68] = 2;
        let participant_0 = conditional_descriptor_participant_offset(0);
        raw[participant_0..participant_0 + BYTE32_LEN].fill(1);
        put_u64(&mut raw, participant_0 + BYTE32_LEN, 100);
        let participant_1 = conditional_descriptor_participant_offset(1);
        raw[participant_1..participant_1 + BYTE32_LEN].fill(2);
        put_u64(&mut raw, participant_1 + BYTE32_LEN, 200);

        let preimages = [[7u8; BYTE32_LEN], [8u8; BYTE32_LEN]];
        let algorithms = [CONDITIONAL_HASH_SHA256, CONDITIONAL_HASH_CKB_BLAKE2B];
        let amounts = [25, 40];
        let refund_blocks = [500, 600];
        for index in 0..2 {
            let offset = conditional_descriptor_transfer_offset(index);
            raw[offset..offset + BYTE32_LEN].fill(5 + index as u8);
            raw[offset + BYTE32_LEN] = index as u8;
            raw[offset + BYTE32_LEN + 1] = algorithms[index];
            let payment_hash =
                conditional_payment_hash(algorithms[index], &preimages[index]).unwrap();
            raw[offset + BYTE32_LEN + 4..offset + 2 * BYTE32_LEN + 4]
                .copy_from_slice(&payment_hash);
            put_u64(&mut raw, offset + 2 * BYTE32_LEN + 4, amounts[index]);
            put_u64(
                &mut raw,
                offset + 2 * BYTE32_LEN + 20,
                absolute_block_since(refund_blocks[index]).unwrap(),
            );
        }
        raw
    }
    #[test]
    fn precomputed_factory_empty_subtrees_match_all_current_hash_levels() {
        let mut current = blake2b256(&[FACTORY_RIGHT_EMPTY_DOMAIN]);
        assert_eq!(factory_empty_hashes::HASHES[0], current);
        for height in 1..=FACTORY_SPARSE_MERKLE_DEPTH {
            current =
                factory_right_node_hash(FACTORY_SPARSE_MERKLE_DEPTH - height, &current, &current);
            assert_eq!(factory_empty_hashes::HASHES[height], current);
        }
    }

    #[test]
    fn sponsor_policy_fields_are_fixed_width() {
        let mut raw = [0u8; SPONSOR_POLICY_LEN];
        raw[0..32].fill(1);
        put_u64(&mut raw, 32, 10);
        put_u64(&mut raw, 40, 20);
        put_u64(&mut raw, 48, 30);
        put_u64(&mut raw, 56, 40);
        put_u64(&mut raw, 64, 50);
        raw[72..104].fill(2);
        raw[104..136].fill(3);

        let policy = SponsorPolicy::parse(&raw).unwrap();
        assert_eq!(policy.channel_id(), &[1u8; 32]);
        assert_eq!(policy.min_state_number(), 10);
        assert_eq!(policy.max_state_number(), 20);
        assert_eq!(policy.max_fee_per_tx(), 30);
        assert_eq!(policy.max_total_fee(), 40);
        assert_eq!(policy.already_spent(), 50);
        assert_eq!(policy.publication_state_type_hash(), &[2u8; 32]);
        assert_eq!(policy.change_lock(), &[3u8; 32]);
    }
    #[test]
    fn sibling_subtree_membership_matches_naive_prefix_check() {
        let keys = [
            blake2b256(&[&[0u8]]),
            blake2b256(&[&[1u8]]),
            blake2b256(&[&[2u8]]),
            [0u8; BYTE32_LEN],
            [0xff; BYTE32_LEN],
        ];
        for key in keys {
            for candidate in keys {
                for depth in 0..FACTORY_SPARSE_MERKLE_DEPTH {
                    for sibling_bit in [false, true] {
                        let naive = (0..depth).all(|probe| {
                            factory_key_bit(&candidate, probe) == factory_key_bit(&key, probe)
                        }) && factory_key_bit(&candidate, depth) == sibling_bit;
                        assert_eq!(
                            factory_key_in_sibling_subtree(&key, &candidate, depth, sibling_bit),
                            naive,
                            "key {key:?} candidate {candidate:?} depth {depth} bit {sibling_bit}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn parses_and_resolves_conditional_batch() {
        let descriptor_raw = conditional_descriptor_bytes();
        let descriptor = ConditionalBatchDescriptor::parse(&descriptor_raw).unwrap();
        assert_eq!(descriptor.transfer_count(), 2);
        assert_eq!(descriptor.checked_total_capacity().unwrap(), 365);

        let mut witness_raw = alloc::vec![0u8; 4 + descriptor_raw.len() + 34];
        put_u16(
            &mut witness_raw,
            0,
            CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION,
        );
        witness_raw[2] = 2;
        witness_raw[4..4 + descriptor_raw.len()].copy_from_slice(&descriptor_raw);
        let first = conditional_resolution_offset(descriptor_raw.len(), 0);
        witness_raw[first] = CONDITIONAL_RESOLUTION_FULFILL;
        witness_raw[first + 1..first + 1 + BYTE32_LEN].fill(7);
        let second = conditional_resolution_offset(descriptor_raw.len(), 1);
        witness_raw[second] = CONDITIONAL_RESOLUTION_REFUND;

        let witness = ConditionalBatchResolutionWitness::parse(&witness_raw).unwrap();
        assert_eq!(
            witness
                .resolved_values(absolute_block_since(600).unwrap())
                .unwrap()
                .map(|value| value.capacity),
            [100, 265]
        );
        assert_eq!(
            witness
                .resolved_values(absolute_block_since(599).unwrap())
                .unwrap_err(),
            ScriptError::ConditionalRefundNotMature
        );
    }
    #[test]
    fn conditional_batch_rejects_wrong_preimage_and_duplicate_hash() {
        let descriptor_raw = conditional_descriptor_bytes();
        let mut witness_raw = alloc::vec![0u8; 4 + descriptor_raw.len() + 34];
        put_u16(
            &mut witness_raw,
            0,
            CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION,
        );
        witness_raw[2] = 2;
        witness_raw[4..4 + descriptor_raw.len()].copy_from_slice(&descriptor_raw);
        let first = conditional_resolution_offset(descriptor_raw.len(), 0);
        witness_raw[first] = CONDITIONAL_RESOLUTION_FULFILL;
        witness_raw[first + 1..first + 1 + BYTE32_LEN].fill(9);
        let second = conditional_resolution_offset(descriptor_raw.len(), 1);
        witness_raw[second] = CONDITIONAL_RESOLUTION_REFUND;
        let witness = ConditionalBatchResolutionWitness::parse(&witness_raw).unwrap();
        assert_eq!(
            witness
                .resolved_values(absolute_block_since(600).unwrap())
                .unwrap_err(),
            ScriptError::ConditionalPreimageMismatch
        );

        let mut duplicate = descriptor_raw;
        let first_hash = conditional_descriptor_transfer_offset(0) + BYTE32_LEN + 4;
        let second_hash = conditional_descriptor_transfer_offset(1) + BYTE32_LEN + 4;
        let hash = duplicate[first_hash..first_hash + BYTE32_LEN].to_vec();
        duplicate[second_hash..second_hash + BYTE32_LEN].copy_from_slice(&hash);
        assert_eq!(
            ConditionalBatchDescriptor::parse(&duplicate).unwrap_err(),
            ScriptError::ConditionalDescriptorEncoding
        );
    }

    #[test]
    fn typed_batch_preserves_capacity_and_resolves_full_width_tokens() {
        let mut raw = conditional_descriptor_bytes();
        raw[76] = 1;
        raw[77..109].fill(42);
        let large = u64::MAX as u128 + 123;
        write_u128(
            &mut raw,
            conditional_descriptor_participant_offset(0) + 40,
            large,
        );
        write_u128(
            &mut raw,
            conditional_descriptor_participant_offset(1) + 40,
            9,
        );
        write_u128(
            &mut raw,
            conditional_descriptor_transfer_offset(0) + 68,
            large,
        );
        let parsed = ConditionalBatchDescriptor::parse(&raw).unwrap();
        assert_eq!(parsed.checked_total_capacity().unwrap(), 300);
        assert_eq!(parsed.checked_total_amount().unwrap(), 2 * large + 49);
        let mut witness = alloc::vec![0u8; 4 + raw.len() + 34];
        write_u16(
            &mut witness,
            0,
            CONDITIONAL_BATCH_RESOLUTION_WITNESS_VERSION,
        );
        witness[2] = 2;
        witness[4..4 + raw.len()].copy_from_slice(&raw);
        let first = conditional_resolution_offset(raw.len(), 0);
        witness[first] = CONDITIONAL_RESOLUTION_FULFILL;
        witness[first + 1..first + 33].fill(7);
        witness[conditional_resolution_offset(raw.len(), 1)] = CONDITIONAL_RESOLUTION_REFUND;
        let parsed = ConditionalBatchResolutionWitness::parse(&witness).unwrap();
        assert_eq!(
            parsed
                .resolved_values(absolute_block_since(600).unwrap())
                .unwrap(),
            [
                ConditionalValue {
                    capacity: 100,
                    amount: large
                },
                ConditionalValue {
                    capacity: 200,
                    amount: large + 49
                },
            ]
        );
        assert_eq!(
            parsed.resolved_values(absolute_block_since(599).unwrap()),
            Err(ScriptError::ConditionalRefundNotMature)
        );
    }

    #[test]
    fn typed_batch_rejects_wrong_asset_and_both_arithmetic_overflows() {
        let raw = conditional_descriptor_bytes();
        let mut changed = raw.clone();
        changed[77] = 1; // Plain CKB cannot carry a token Type.
        assert!(ConditionalBatchDescriptor::parse(&changed).is_err());
        changed = raw.clone();
        write_u128(
            &mut changed,
            conditional_descriptor_transfer_offset(0) + 68,
            u64::MAX as u128,
        );
        assert!(ConditionalBatchDescriptor::parse(&changed).is_err());
        changed = raw.clone();
        changed[76] = 1;
        changed[77..109].fill(42);
        write_u128(
            &mut changed,
            conditional_descriptor_participant_offset(0) + 40,
            u128::MAX,
        );
        assert!(ConditionalBatchDescriptor::parse(&changed).is_err());
        changed = raw.clone();
        changed[0..2].copy_from_slice(&3u16.to_le_bytes());
        assert!(ConditionalBatchDescriptor::parse(&changed).is_err());
        let mut retired = raw.clone();
        retired.resize(828, 0);
        assert!(ConditionalBatchDescriptor::parse(&retired).is_err());
    }
}
