//! One-member, proof-localised release from complete current Factory custody.
//! This verifier authenticates an explicit transition, not CKB cells. Runtime
//! callers must compare both headers, every input/output and the raw tx hash.
//! A retained successor is required; its carrier cannot be taken by a member.
use super::{
    FACTORY_MATERIALISATION_MAX_INTENT_LEN, FactoryMaterialisationIntent,
    FactoryMultiAssetStateHeader, Result, ScriptError,
};
use crate::multi_asset::{
    self as asset, MultiAssetAllocation, MultiAssetId, MultiAssetVaultManifest,
};
use crate::{FactoryRight, blake2b256, read_u16, read_u32, read_u64};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub const FACTORY_REDUCED_RELEASE_MAGIC: &[u8; 8] = b"MORPHFR!";
pub const FACTORY_REDUCED_RELEASE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_REDUCED_RELEASE_V1";
pub const FACTORY_REDUCED_RELEASE_LOCALITY_DOMAIN: &[u8] =
    b"CKB_MORPH_FACTORY_REDUCED_RELEASE_LOCALITY_V1";
pub const FACTORY_REDUCED_RELEASE_PREFIX_LEN: usize = 788;
pub const FACTORY_REDUCED_RELEASE_MAX_RIGHTS: usize = 9;
pub const FACTORY_TRANSITION_MAX_RIGHTS: usize = 10;
pub const FACTORY_REDUCED_RELEASE_MAX_LEN: usize = FACTORY_REDUCED_RELEASE_PREFIX_LEN
    + 4
    + FACTORY_MATERIALISATION_MAX_INTENT_LEN
    + 4 * 66
    + 15 * 64
    + 16 * 65
    + 2 * 780
    + 8 * 36
    + 4
    + (2 + 117)
    + 16 * (2 + 512)
    + 16
    + 8 * (2 + 512 + 69)
    + FACTORY_TRANSITION_MAX_RIGHTS * (crate::FACTORY_RIGHT_LEN + 16 + 2 * (2 + 64 * 34));

/// Explicit current operations; every variant signs its tag and exact body.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryTransitionOperation {
    ReducedRelease = 0,
    ReducedRights = 1,
    ReducedDeposit = 2,
    FullCustody = 4,
    ReducedChild = 5,
}
impl FactoryTransitionOperation {
    pub fn parse(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::ReducedRelease),
            1 => Ok(Self::ReducedRights),
            2 => Ok(Self::ReducedDeposit),
            4 => Ok(Self::FullCustody),
            5 => Ok(Self::ReducedChild),
            _ => bad(),
        }
    }
    pub fn is_full(self) -> bool {
        matches!(self, Self::FullCustody)
    }
    pub fn moves_custody(self) -> bool {
        !matches!(self, Self::ReducedRights)
    }
}
fn bad<T>() -> Result<T> {
    Err(ScriptError::FactoryReducedProofMismatch)
}
fn take<'a>(raw: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(ScriptError::FactoryReducedProofEncoding)?;
    let value = raw
        .get(*offset..end)
        .ok_or(ScriptError::FactoryReducedProofEncoding)?;
    *offset = end;
    Ok(value)
}
fn proof_end(raw: &[u8], offset: &mut usize) -> Result<usize> {
    let start = *offset;
    let count = read_u16(take(raw, offset, 2)?, 0) as usize;
    if count > crate::FACTORY_COMPACT_PROOF_MAX_SIBLINGS {
        return bad();
    }
    let pairs = take(raw, offset, count * 34)?;
    let mut previous = 256;
    for pair in pairs.chunks_exact(34) {
        let depth = read_u16(pair, 0) as usize;
        if depth >= previous {
            return bad();
        }
        previous = depth;
    }
    Ok(start)
}
#[derive(Debug, Clone, Copy)]
pub struct FactoryReducedReleaseRight<'a> {
    pub before: FactoryRight<'a>,
    pub after: FactoryRight<'a>,
    raw: &'a [u8],
    before_proof_offset: usize,
    after_proof_offset: usize,
}
impl<'a> FactoryReducedReleaseRight<'a> {
    /// Read one bounded before/after right and its two compact proofs.
    pub fn parse_at(raw: &'a [u8], offset: &mut usize) -> Result<Self> {
        let before = FactoryRight::parse(take(raw, offset, crate::FACTORY_RIGHT_LEN)?)?;
        let after = before.with_quantity(take(raw, offset, 16)?)?;
        let before_proof_offset = proof_end(raw, offset)?;
        let after_proof_offset = proof_end(raw, offset)?;
        Ok(Self {
            before,
            after,
            raw,
            before_proof_offset,
            after_proof_offset,
        })
    }
    pub fn key(&self) -> [u8; 32] {
        crate::factory_right_key(&self.before)
    }
    /// Number of explicitly carried siblings across the two compact proofs.
    pub fn proof_sibling_count(&self) -> usize {
        read_u16(self.raw, self.before_proof_offset) as usize
            + read_u16(self.raw, self.after_proof_offset) as usize
    }
}
#[derive(Debug, Clone, Copy)]
pub struct FactoryReducedReleasePayout<'a> {
    pub asset: MultiAssetId,
    pub allocation: MultiAssetAllocation,
    pub output_index: usize,
    pub lock_script: &'a [u8],
    raw: &'a [u8],
}
impl<'a> FactoryReducedReleasePayout<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
}
#[derive(Debug, Clone, Copy)]
pub struct FactoryReducedReleaseWitness<'a> {
    raw: &'a [u8],
    before: FactoryMultiAssetStateHeader<'a>,
    after: FactoryMultiAssetStateHeader<'a>,
    members: &'a [u8],
    source: MultiAssetVaultManifest<'a>,
    points: &'a [u8],
    retained: MultiAssetVaultManifest<'a>,
    factory_lock: &'a [u8],
    types: [Option<&'a [u8]>; 16],
    payouts: [Option<FactoryReducedReleasePayout<'a>>; 8],
    rights: [Option<FactoryReducedReleaseRight<'a>>; FACTORY_TRANSITION_MAX_RIGHTS],
    child_intent: Option<FactoryMaterialisationIntent<'a>>,
    child_keys: &'a [u8],
    locality_end: usize,
}
impl<'a> FactoryReducedReleaseWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < FACTORY_REDUCED_RELEASE_PREFIX_LEN
            || raw.len() > FACTORY_REDUCED_RELEASE_MAX_LEN
            || raw.get(..8) != Some(FACTORY_REDUCED_RELEASE_MAGIC.as_slice())
            || read_u16(raw, 8) != 2
            || read_u16(raw, 10) > 5
            || !(2..=16).contains(&read_u16(raw, 12))
            || read_u16(raw, 14) >= read_u16(raw, 12)
            || read_u16(raw, 16) > FACTORY_TRANSITION_MAX_RIGHTS as u16
            || read_u16(raw, 18) > 8
            || read_u16(raw, 32) > 16
            || read_u32(raw, 20) > 780
            || read_u32(raw, 24) > 780
            || read_u32(raw, 28) as usize > crate::script_table::MAX_TABLE_LEN
        {
            return Err(ScriptError::FactoryReducedProofEncoding);
        }
        let before = FactoryMultiAssetStateHeader::parse(&raw[112..418])?;
        let after = FactoryMultiAssetStateHeader::parse(&raw[418..724])?;
        let operation = FactoryTransitionOperation::parse(read_u16(raw, 10))?;
        if operation == FactoryTransitionOperation::ReducedChild && read_u16(raw, 32) != 0 {
            return bad();
        }
        let mut offset = FACTORY_REDUCED_RELEASE_PREFIX_LEN;
        if operation.is_full() {
            take(raw, &mut offset, (read_u16(raw, 12) as usize - 1) * 64)?;
        }
        let members = take(raw, &mut offset, read_u16(raw, 12) as usize * 65)?;
        let source =
            MultiAssetVaultManifest::parse(take(raw, &mut offset, read_u32(raw, 20) as usize)?)?;
        let points = take(raw, &mut offset, source.count() * 36)?;
        let retained =
            MultiAssetVaultManifest::parse(take(raw, &mut offset, read_u32(raw, 24) as usize)?)?;
        let table = crate::script_table::ScriptTable::parse(take(
            raw,
            &mut offset,
            read_u32(raw, 28) as usize,
        )?)?;
        let factory_index = read_u16(raw, 34) as usize;
        let factory_lock = table.script(factory_index)?;
        if factory_lock.len() != 117 {
            return bad();
        }
        let mut used = 1u64 << factory_index;
        let mut types = [None; 16];
        let mut previous = None;
        for slot in types.iter_mut().take(read_u16(raw, 32) as usize) {
            let index = take(raw, &mut offset, 1)?[0] as usize;
            let script = table.script(index)?;
            used |= 1u64 << index;
            let hash = blake2b256(&[script]);
            if previous.is_some_and(|p| p >= hash) {
                return bad();
            }
            previous = Some(hash);
            *slot = Some(script);
        }
        let mut payouts = [None; 8];
        let mut previous_asset = None;
        for slot in payouts.iter_mut().take(read_u16(raw, 18) as usize) {
            let prefix = take(raw, &mut offset, 69)?;
            let asset = MultiAssetId::parse(&prefix[..33])?;
            let allocation = MultiAssetAllocation::parse(&prefix[33..65])?;
            allocation.validate_for(asset, false)?;
            let index = read_u16(prefix, 65) as usize;
            if previous_asset.is_some_and(|p| p >= asset) || allocation.capacity()? == 0 {
                return bad();
            }
            previous_asset = Some(asset);
            let lock_script = table.script(index)?;
            used |= 1u64 << index;
            *slot = Some(FactoryReducedReleasePayout {
                asset,
                allocation,
                output_index: read_u16(prefix, 67) as usize,
                lock_script,
                raw: prefix,
            });
        }
        let mut rights = [None; FACTORY_TRANSITION_MAX_RIGHTS];
        for slot in rights.iter_mut().take(read_u16(raw, 16) as usize) {
            *slot = Some(FactoryReducedReleaseRight::parse_at(raw, &mut offset)?);
        }
        let locality_end = offset;
        let (child_intent, child_keys) = if operation == FactoryTransitionOperation::ReducedChild {
            let len = read_u32(take(raw, &mut offset, 4)?, 0) as usize;
            if len > FACTORY_MATERIALISATION_MAX_INTENT_LEN {
                return bad();
            }
            let intent = FactoryMaterialisationIntent::parse(take(raw, &mut offset, len)?)?;
            let keys = take(raw, &mut offset, intent.child_count() * 66)?;
            (Some(intent), keys)
        } else {
            (None, &raw[0..0])
        };
        if offset != raw.len() || used != table.complete_usage() {
            return bad();
        }
        if let Some(intent) = child_intent.as_ref() {
            let mut assets = [MultiAssetId::CKB; 16];
            let mut n = 0;
            for manifest in [&source, &retained] {
                for i in 0..manifest.count() {
                    let asset = manifest.entry(i)?.asset;
                    if asset.kind == 1 && !assets[..n].contains(&asset) {
                        assets[n] = asset;
                        n += 1;
                    }
                }
            }
            assets[..n].sort_unstable();
            for (i, asset) in assets.iter().take(n).enumerate() {
                types[i] = intent.type_script(*asset)?;
            }
        }
        Ok(Self {
            raw,
            before,
            after,
            members,
            source,
            points,
            retained,
            factory_lock,
            types,
            payouts,
            rights,
            child_intent,
            child_keys,
            locality_end,
        })
    }
    pub fn operation(&self) -> FactoryTransitionOperation {
        // parse() checks this tag before constructing the view.
        match read_u16(self.raw, 10) {
            0 => FactoryTransitionOperation::ReducedRelease,
            1 => FactoryTransitionOperation::ReducedRights,
            2 => FactoryTransitionOperation::ReducedDeposit,
            4 => FactoryTransitionOperation::FullCustody,
            _ => FactoryTransitionOperation::ReducedChild,
        }
    }
    pub fn signature_count(&self) -> usize {
        if self.operation().is_full() {
            self.member_count()
        } else {
            1
        }
    }
    pub fn signature(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.signature_count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let offset = if index == 0 {
            724
        } else {
            788 + (index - 1) * 64
        };
        Ok(&self.raw[offset..offset + 64])
    }
    pub fn member(&self, index: usize) -> Result<(&'a [u8], &'a [u8])> {
        if index >= self.member_count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        Ok((
            &self.members[index * 65..index * 65 + 32],
            &self.members[index * 65 + 32..(index + 1) * 65],
        ))
    }
    pub fn authorized_member(&self, index: usize) -> Result<(&'a [u8], &'a [u8])> {
        if index >= self.signature_count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        self.member(if self.operation().is_full() {
            index
        } else {
            read_u16(self.raw, 14) as usize
        })
    }
    /// Fill only the current frame's authorization slots and verify before
    /// returning. The caller owns allocation; this codec requires no heap.
    pub fn write_signatures(&self, signatures: &[[u8; 64]], output: &mut [u8]) -> Result<()> {
        if signatures.len() != self.signature_count() || output.len() != self.raw.len() {
            return bad();
        }
        output.copy_from_slice(self.raw);
        for (i, signature) in signatures.iter().enumerate() {
            let offset = if i == 0 { 724 } else { 788 + (i - 1) * 64 };
            output[offset..offset + 64].copy_from_slice(signature);
        }
        FactoryReducedReleaseWitness::parse(output)?.verify()
    }
    /// Produce a proposal through the sole current codec. Only Factory
    /// authorization bytes are zeroed; public child terms remain intact.
    pub fn write_unsigned(&self, output: &mut [u8]) -> Result<()> {
        if output.len() != self.raw.len() {
            return bad();
        }
        output.copy_from_slice(self.raw);
        for i in 0..self.signature_count() {
            let offset = if i == 0 { 724 } else { 788 + (i - 1) * 64 };
            output[offset..offset + 64].fill(0);
        }
        FactoryReducedReleaseWitness::parse(output)?.validate_transition()
    }
    fn signatures_end(&self) -> usize {
        788 + if self.operation().is_full() {
            (self.member_count() - 1) * 64
        } else {
            0
        }
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn before(&self) -> &FactoryMultiAssetStateHeader<'a> {
        &self.before
    }
    pub fn after(&self) -> &FactoryMultiAssetStateHeader<'a> {
        &self.after
    }
    pub fn source(&self) -> &MultiAssetVaultManifest<'a> {
        &self.source
    }
    pub fn retained(&self) -> &MultiAssetVaultManifest<'a> {
        &self.retained
    }
    pub fn source_points(&self) -> &'a [u8] {
        self.points
    }
    pub fn old_state_outpoint(&self) -> &'a [u8] {
        &self.raw[36..72]
    }
    pub fn transaction_hash(&self) -> &'a [u8] {
        &self.raw[72..104]
    }
    pub fn carrier_capacity(&self) -> u64 {
        read_u64(self.raw, 104)
    }
    pub fn factory_lock_script(&self) -> &'a [u8] {
        self.factory_lock
    }
    pub fn payout_count(&self) -> usize {
        read_u16(self.raw, 18) as usize
    }
    pub fn right_count(&self) -> usize {
        read_u16(self.raw, 16) as usize
    }
    pub fn member_count(&self) -> usize {
        read_u16(self.raw, 12) as usize
    }
    pub fn payout(&self, index: usize) -> Result<FactoryReducedReleasePayout<'a>> {
        self.payouts
            .get(index)
            .copied()
            .flatten()
            .ok_or(ScriptError::IndexOutOfBounds)
    }
    pub fn right(&self, index: usize) -> Result<FactoryReducedReleaseRight<'a>> {
        self.rights
            .get(index)
            .copied()
            .flatten()
            .ok_or(ScriptError::IndexOutOfBounds)
    }
    pub fn touched_participant(&self) -> &'a [u8] {
        let i = read_u16(self.raw, 14) as usize;
        &self.members[i * 65..i * 65 + 32]
    }
    pub fn type_script(&self, asset: MultiAssetId) -> Result<Option<&'a [u8]>> {
        if asset.kind == 0 {
            return Ok(None);
        }
        self.types
            .iter()
            .flatten()
            .copied()
            .find(|script| blake2b256(&[script]) == asset.type_hash)
            .map(Some)
            .ok_or(ScriptError::FactoryReducedProofMismatch)
    }
    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[
            FACTORY_REDUCED_RELEASE_DOMAIN,
            &self.raw[..724],
            &self.raw[self.signatures_end()..],
        ])
    }
    pub fn child_intent(&self) -> Option<&FactoryMaterialisationIntent<'a>> {
        self.child_intent.as_ref()
    }
    pub fn child_pubkey(&self, child: usize, participant: usize) -> Result<&'a [u8]> {
        let intent = self
            .child_intent()
            .ok_or(ScriptError::FactoryReducedProofMismatch)?;
        if child >= intent.child_count() || participant >= 2 {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let offset = child * 66 + participant * 33;
        Ok(&self.child_keys[offset..offset + 33])
    }
    pub fn locality_digest(&self) -> [u8; 32] {
        // parse() has bounded these offsets. The child trailer is excluded:
        // its initial exit commits the final tx hash, avoiding a fixed point.
        blake2b256(&[
            FACTORY_REDUCED_RELEASE_LOCALITY_DOMAIN,
            &self.raw[..72],
            &self.raw[104..590],
            &self.raw[622..724],
            &self.raw[self.signatures_end()..self.locality_end],
        ])
    }
    pub fn participants_commitment(&self) -> [u8; 32] {
        let mut h = crate::new_blake2b();
        h.update(crate::FACTORY_PARTICIPANTS_DOMAIN);
        h.update(&[self.member_count() as u8, self.member_count() as u8]);
        h.update(self.members);
        let mut result = [0; 32];
        h.finalize(&mut result);
        result
    }
    /// Verify the explicit authority operation and independent custody lanes.
    /// Cryptographic signatures and actual CKB cells are checked separately.
    pub fn validate_transition(&self) -> Result<()> {
        let operation = self.operation();
        if !self.before.same_identity(&self.after)
            || !self.before.vaults_are_bound()
            || self.after.update_number()
                != self
                    .before
                    .update_number()
                    .checked_add(1)
                    .ok_or(ScriptError::NonMonotonicStateNumber)?
            || self.before.content_root() != self.source.commitment()
            || self.before.outpoint_root()
                != asset::multi_asset_outpoint_set_commitment(
                    &self.source.commitment(),
                    self.source.count(),
                    self.points,
                )?
            || self.before.vault_count() != self.source.count()
            || self.after.content_root() != self.retained.commitment()
            || self.after.vault_count() != self.retained.count()
            || (!operation.is_full()
                && self.before.as_bytes()[140..172] != self.after.as_bytes()[140..172])
            || self.after.as_bytes()[172..204] != self.locality_digest()
            || self.before.participants_commitment() != self.participants_commitment()
            || self.raw[36..68] == [0; 32]
            || self.raw[72..104] == [0; 32]
            || self.raw[36..68] == self.raw[72..104]
            || self.carrier_capacity() == 0
            || self.factory_lock[53..85] != *self.before.factory_id()
            || self.factory_lock[85..117] == [0; 32]
            || blake2b256(&[self.factory_lock]) != self.source.entry(0)?.lock_hash
            || self.source.entry(0)?.lock_hash != self.retained.entry(0)?.lock_hash
            || (operation.is_full() && (self.right_count() != 0 || read_u16(self.raw, 14) != 0))
            || (!operation.is_full() && self.right_count() == 0)
            || (matches!(operation, FactoryTransitionOperation::ReducedRelease)
                && self.payout_count() == 0)
            || (matches!(
                operation,
                FactoryTransitionOperation::ReducedDeposit
                    | FactoryTransitionOperation::ReducedRights
            ) && self.payout_count() != 0)
        {
            return bad();
        }
        if operation != FactoryTransitionOperation::ReducedRights
            && self.right_count() > FACTORY_REDUCED_RELEASE_MAX_RIGHTS
        {
            return bad();
        }
        if operation == FactoryTransitionOperation::ReducedChild && self.payout_count() != 0 {
            return bad();
        }
        if operation.moves_custody() {
            if self.after.vaults_are_bound() {
                return bad();
            }
        } else if !self.after.same_custody(&self.before)
            || self.source.as_bytes() != self.retained.as_bytes()
        {
            return bad();
        }
        for point in self.points.chunks_exact(36) {
            if point == self.old_state_outpoint() || point[..32] == self.transaction_hash()[..] {
                return bad();
            }
        }
        for (i, member) in self.members.chunks_exact(65).enumerate() {
            if member[..32] == [0; 32]
                || (i > 0 && self.members[(i - 1) * 65..(i - 1) * 65 + 32] >= member[..32])
            {
                return bad();
            }
            VerifyingKey::from_sec1_bytes(&member[32..])
                .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
            if self
                .members
                .chunks_exact(65)
                .take(i)
                .any(|p| p[32..] == member[32..])
            {
                return bad();
            }
        }
        self.validate_children()?;
        let (assets, count) = self.assets()?;
        let mut type_count = 0;
        for current_asset in assets.iter().take(count) {
            let ty = self.type_script(*current_asset)?;
            if ty.is_some() {
                type_count += 1;
            }
            for manifest in [&self.source, &self.retained] {
                let value = value_for(manifest, *current_asset)?;
                if value != MultiAssetAllocation::default()
                    && value.reserve
                        < asset::multi_asset_occupied_capacity(
                            self.factory_lock,
                            ty,
                            if ty.is_some() { 16 } else { 0 },
                        )?
                {
                    return bad();
                }
            }
            if matches!(
                operation,
                FactoryTransitionOperation::ReducedRelease
                    | FactoryTransitionOperation::ReducedChild
            ) {
                self.withdrawn_value(*current_asset)?;
            }
            let deposit = self.deposited_value(*current_asset)?;
            if !matches!(
                operation,
                FactoryTransitionOperation::ReducedDeposit
                    | FactoryTransitionOperation::FullCustody
                    | FactoryTransitionOperation::ReducedRelease
            ) && deposit != MultiAssetAllocation::default()
            {
                return bad();
            }
        }
        if matches!(
            operation,
            FactoryTransitionOperation::ReducedRelease | FactoryTransitionOperation::ReducedChild
        ) {
            self.withdrawn_value(MultiAssetId::CKB)?;
        }
        let ckb_deposit = self.deposited_value(MultiAssetId::CKB)?;
        if !matches!(
            operation,
            FactoryTransitionOperation::ReducedDeposit
                | FactoryTransitionOperation::FullCustody
                | FactoryTransitionOperation::ReducedRelease
        ) && ckb_deposit.capacity()? != 0
        {
            return bad();
        }
        if self.types.iter().flatten().count() != type_count {
            return bad();
        }
        for (i, payout) in self.payouts.iter().flatten().enumerate() {
            if (payout.asset.kind == 1 && !assets[..count].contains(&payout.asset))
                || payout.output_index != 1 + self.retained.count() + i
                || payout.output_index >= 64
                || blake2b256(&[payout.lock_script]) == self.source.entry(0)?.lock_hash
                || payout.allocation.reserve
                    < asset::multi_asset_occupied_capacity(
                        payout.lock_script,
                        self.type_script(payout.asset)?,
                        if payout.asset.kind == 1 { 16 } else { 0 },
                    )?
            {
                return bad();
            }
        }
        if operation.is_full() {
            // Canonical N-of-N metadata uses MORPHFS UPDATE; this authority
            // is reserved for actual funded custody or withdrawal changes.
            if self.payout_count() == 0 && self.source.as_bytes() == self.retained.as_bytes() {
                return bad();
            }
            return Ok(());
        }
        let mut keys = [[0; 32]; FACTORY_TRANSITION_MAX_RIGHTS];
        for (i, key) in keys.iter_mut().enumerate().take(self.right_count()) {
            *key = self.right(i)?.key();
        }
        let empty_hashes = crate::factory_sparse_empty_hashes();
        let mut previous = None;
        for i in 0..self.right_count() {
            let right = self.right(i)?;
            if previous.is_some_and(|p| p >= right.before.id_key()) {
                return bad();
            }
            previous = Some(right.before.id_key());
            let mut others = [[0; 32]; FACTORY_TRANSITION_MAX_RIGHTS];
            let mut n = 0;
            for (j, key) in keys.iter().enumerate().take(self.right_count()) {
                if i != j {
                    others[n] = *key;
                    n += 1;
                }
            }
            verify_factory_localized_right_change_cached(
                &right,
                self.touched_participant(),
                self.before.state_root(),
                self.after.state_root(),
                &others[..n],
                empty_hashes,
            )?;
            if matches!(operation, FactoryTransitionOperation::ReducedRights) {
                if !matches!(
                    right.before.kind(),
                    crate::FACTORY_RIGHT_KIND_BALANCE
                        | crate::FACTORY_RIGHT_KIND_RESERVE_CLAIM
                        | crate::FACTORY_RIGHT_KIND_SPONSOR_BUDGET_CLAIM
                ) {
                    return bad();
                }
            } else if right.before.kind() != crate::FACTORY_RIGHT_KIND_RESERVE_CLAIM
                || (operation == FactoryTransitionOperation::ReducedDeposit
                    && right.after.quantity() <= right.before.quantity())
                || (matches!(
                    operation,
                    FactoryTransitionOperation::ReducedRelease
                        | FactoryTransitionOperation::ReducedChild
                ) && right.before.quantity() <= right.after.quantity())
            {
                return bad();
            }
        }
        if operation == FactoryTransitionOperation::ReducedRights {
            let mut changed = false;
            for i in 0..self.right_count() {
                let group = self.right(i)?.before;
                let mut before = 0u128;
                let mut after = 0u128;
                for j in 0..self.right_count() {
                    let right = self.right(j)?;
                    if group.same_asset(&right.before) {
                        before = before
                            .checked_add(right.before.quantity())
                            .ok_or(ScriptError::FactoryReducedProofMismatch)?;
                        after = after
                            .checked_add(right.after.quantity())
                            .ok_or(ScriptError::FactoryReducedProofMismatch)?;
                        changed |= right.before.quantity() != right.after.quantity();
                    }
                }
                if after > before {
                    return bad();
                }
            }
            return if changed { Ok(()) } else { bad() };
        }
        let ckb_expected = if operation == FactoryTransitionOperation::ReducedDeposit {
            self.deposited_value(MultiAssetId::CKB)?.capacity()?
        } else {
            self.withdrawn_value(MultiAssetId::CKB)?.capacity()?
        } as u128;
        for current_asset in assets.iter().take(count) {
            if current_asset.kind == 1 {
                let amount = if operation == FactoryTransitionOperation::ReducedDeposit {
                    self.deposited_value(*current_asset)?.amount
                } else {
                    self.withdrawn_value(*current_asset)?.amount
                };
                if self.claim_delta(Some(&current_asset.type_hash))? != amount {
                    return bad();
                }
            }
        }
        if self.claim_delta(None)? != ckb_expected {
            return bad();
        }
        // Every listed token claim must correspond to an actual custody asset.
        for i in 0..self.right_count() {
            let right = self.right(i)?.before;
            if right.asset_present() == 1
                && !assets[..count]
                    .iter()
                    .any(|asset| asset.kind == 1 && asset.type_hash == right.asset_type())
            {
                return bad();
            }
        }
        Ok(())
    }
    fn validate_children(&self) -> Result<()> {
        let Some(intent) = self.child_intent() else {
            return Ok(());
        };
        if intent.chain_id() != self.before.chain_id()
            || intent.factory_id() != self.before.factory_id()
            || intent.participants_commitment() != self.before.participants_commitment()
            || intent.old_state_outpoint() != self.old_state_outpoint()
            || intent.transaction_hash() != self.transaction_hash()
            || intent.source().as_bytes() != self.source.as_bytes()
            || intent.source_points() != self.points
            || intent.retained().map(|m| m.as_bytes()) != Some(self.retained.as_bytes())
            || intent.factory_carrier_capacity() != self.carrier_capacity()
            || intent.factory_lock_script() != self.factory_lock
        {
            return bad();
        }
        for i in 0..intent.child_count() {
            let a = &self.child_keys[i * 66..i * 66 + 33];
            let b = &self.child_keys[i * 66 + 33..i * 66 + 66];
            if a >= b
                || crate::participants_commitment(2, &[a, b])
                    != intent.child(i)?.header.participants_commitment()
            {
                return bad();
            }
        }
        Ok(())
    }
    fn claim_delta(&self, asset: Option<&[u8]>) -> Result<u128> {
        let mut total = 0u128;
        for i in 0..self.right_count() {
            let right = self.right(i)?;
            let matches = match asset {
                Some(hash) => {
                    right.before.asset_present() == 1 && right.before.asset_type() == hash
                }
                None => right.before.asset_present() == 0,
            };
            if matches {
                let delta = if self.operation() == FactoryTransitionOperation::ReducedDeposit {
                    right.after.quantity().checked_sub(right.before.quantity())
                } else {
                    right.before.quantity().checked_sub(right.after.quantity())
                }
                .ok_or(ScriptError::FactoryReducedProofMismatch)?;
                total = total
                    .checked_add(delta)
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?;
            }
        }
        Ok(total)
    }
    pub fn assets(&self) -> Result<([MultiAssetId; 16], usize)> {
        let mut result = [MultiAssetId::CKB; 16];
        let mut count = 0;
        for manifest in [&self.source, &self.retained] {
            for i in 0..manifest.count() {
                let asset = manifest.entry(i)?.asset;
                if !result[..count].contains(&asset) {
                    result[count] = asset;
                    count += 1;
                }
            }
        }
        Ok((result, count))
    }
    pub fn payout_value(&self, asset: MultiAssetId) -> Result<MultiAssetAllocation> {
        if let Some(intent) = self.child_intent() {
            let mut sum = MultiAssetAllocation::default();
            for i in 0..intent.child_count() {
                let value = value_for(intent.child(i)?.evidence.manifest(), asset)?;
                sum.reserve = sum
                    .reserve
                    .checked_add(value.reserve)
                    .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
                sum.business_ckb = sum
                    .business_ckb
                    .checked_add(value.business_ckb)
                    .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
                sum.amount = sum
                    .amount
                    .checked_add(value.amount)
                    .ok_or(ScriptError::MultiAssetConservationMismatch)?;
            }
            return Ok(sum);
        }
        Ok(self
            .payouts
            .iter()
            .flatten()
            .find(|p| p.asset == asset)
            .map(|p| p.allocation)
            .unwrap_or_default())
    }
    /// Value actually leaving Factory custody. Wallet outputs can be larger
    /// when independent external inputs fund their occupied capacity/change;
    /// that extra value never consumes a member's Factory entitlement.
    pub fn withdrawn_value(&self, asset: MultiAssetId) -> Result<MultiAssetAllocation> {
        if asset.kind == 0 {
            let before = super::factory_manifest_ckb(&self.source)?;
            let after = super::factory_manifest_ckb(&self.retained)?;
            Ok(MultiAssetAllocation {
                reserve: before
                    .reserve
                    .checked_sub(after.reserve)
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?,
                business_ckb: before
                    .business_ckb
                    .checked_sub(after.business_ckb)
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?,
                amount: 0,
            })
        } else {
            Ok(MultiAssetAllocation {
                reserve: 0,
                business_ckb: 0,
                amount: value_for(&self.source, asset)?
                    .amount
                    .checked_sub(value_for(&self.retained, asset)?.amount)
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?,
            })
        }
    }
    /// Total CKBinrecipient/childoutputs, including external topups.
    pub fn released_ckb(&self) -> Result<MultiAssetAllocation> {
        let mut sum = MultiAssetAllocation::default();
        if let Some(intent) = self.child_intent() {
            for i in 0..intent.child_count() {
                sum = super::factory_add_ckb(
                    sum,
                    super::factory_manifest_ckb(intent.child(i)?.evidence.manifest())?,
                )?;
            }
        } else {
            for payout in self.payouts.iter().flatten() {
                sum = super::factory_add_ckb(sum, payout.allocation)?;
            }
        }
        Ok(sum)
    }
    /// CKB is one global reserve/business domain, even when no plain Vault
    /// exists. Typed queries return only that Type's token contribution.
    pub fn deposited_value(&self, asset: MultiAssetId) -> Result<MultiAssetAllocation> {
        if asset.kind == 0 {
            let before = super::factory_manifest_ckb(&self.source)?;
            let after = super::factory_manifest_ckb(&self.retained)?;
            let payout = self.released_ckb()?;
            Ok(MultiAssetAllocation {
                reserve: after
                    .reserve
                    .checked_add(payout.reserve)
                    .and_then(|v| v.checked_sub(before.reserve))
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?,
                business_ckb: after
                    .business_ckb
                    .checked_add(payout.business_ckb)
                    .and_then(|v| v.checked_sub(before.business_ckb))
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?,
                amount: 0,
            })
        } else {
            let before = value_for(&self.source, asset)?.amount;
            let after = value_for(&self.retained, asset)?.amount;
            let payout = self.payout_value(asset)?.amount;
            Ok(MultiAssetAllocation {
                reserve: 0,
                business_ckb: 0,
                amount: after
                    .checked_add(payout)
                    .and_then(|v| v.checked_sub(before))
                    .ok_or(ScriptError::FactoryReducedProofMismatch)?,
            })
        }
    }
    pub fn verify(&self) -> Result<()> {
        self.validate_transition()?;
        let digest = self.signing_digest();
        let count = if self.operation().is_full() {
            self.member_count()
        } else {
            1
        };
        for i in 0..count {
            let member = if self.operation().is_full() {
                i
            } else {
                read_u16(self.raw, 14) as usize
            };
            let offset = if i == 0 { 724 } else { 788 + (i - 1) * 64 };
            let key =
                VerifyingKey::from_sec1_bytes(&self.members[member * 65 + 32..(member + 1) * 65])
                    .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
            let signature = Signature::try_from(&self.raw[offset..offset + 64])
                .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
            key.verify_prehash(&digest, &signature)
                .map_err(|_| ScriptError::InvalidParticipantSignature)?;
        }
        Ok(())
    }
}
fn value_for(
    manifest: &MultiAssetVaultManifest,
    asset: MultiAssetId,
) -> Result<MultiAssetAllocation> {
    for i in 0..manifest.count() {
        let entry = manifest.entry(i)?;
        if entry.asset == asset {
            return Ok(entry.allocation);
        }
    }
    Ok(MultiAssetAllocation::default())
}

/// Reusable Merkle locality primitive for current Factory capabilities.
/// It checks the right identity, touched owner and both roots, and rejects any
/// changed sibling subtree without another listed key. It does not authorize
/// an operation or impose a value predicate: each capability must separately
/// validate its full changed-right list, membership, quantities and custody.
pub fn verify_factory_localized_right_change(
    right: &FactoryReducedReleaseRight<'_>,
    touched: &[u8],
    before_root: &[u8],
    after_root: &[u8],
    other_keys: &[[u8; 32]],
) -> Result<()> {
    let empty_hashes = crate::factory_sparse_empty_hashes();
    verify_factory_localized_right_change_cached(
        right,
        touched,
        before_root,
        after_root,
        other_keys,
        empty_hashes,
    )
}

fn verify_factory_localized_right_change_cached(
    right: &FactoryReducedReleaseRight<'_>,
    touched: &[u8],
    before_root: &[u8],
    after_root: &[u8],
    other_keys: &[[u8; 32]],
    empty_hashes: &[[u8; 32]; 257],
) -> Result<()> {
    if !right.before.same_id(&right.after)
        || right.before.participant() != touched
        || other_keys.len() >= FACTORY_TRANSITION_MAX_RIGHTS
    {
        return bad();
    }
    let (before, after) = crate::factory_compact_proof_pair_roots_cached(
        right.raw,
        right.before_proof_offset,
        right.after_proof_offset,
        &right.before,
        &right.after,
        other_keys,
        empty_hashes,
    )?;
    if before != before_root || after != after_root {
        return bad();
    }
    Ok(())
}

/// Derives the parent-locality commitment before an exact transaction and
/// child recovery signatures exist. `body` ends after the compact rights;
/// the eventual exact-tx signature additionally binds the child trailer.
/// This is a hashing primitive, not an authorization or transition verifier.
pub fn factory_transition_locality_digest(body: &[u8], signatures_end: usize) -> Result<[u8; 32]> {
    if body.len() < 788 || signatures_end < 788 || signatures_end > body.len() {
        return bad();
    }
    Ok(blake2b256(&[
        FACTORY_REDUCED_RELEASE_LOCALITY_DOMAIN,
        &body[..72],
        &body[104..590],
        &body[622..724],
        &body[signatures_end..],
    ]))
}

/// Bounded read-only view for child State and reserve-lock gates. The authentic
/// Factory Type separately performs the complete transition/rights/signature
/// verifier. This avoids re-running every child's full intent validation in
/// every dependent script; it grants no standalone spending authority.
pub fn factory_reduced_child_view(raw: &[u8]) -> Result<super::FactoryMaterialisationView<'_>> {
    if raw.len() < 788
        || raw.len() > FACTORY_REDUCED_RELEASE_MAX_LEN
        || raw.get(..8) != Some(FACTORY_REDUCED_RELEASE_MAGIC.as_slice())
        || read_u16(raw, 8) != 2
        || read_u16(raw, 10) != FactoryTransitionOperation::ReducedChild as u16
        || !(2..=16).contains(&read_u16(raw, 12))
        || read_u16(raw, 14) >= read_u16(raw, 12)
        || !(1..=9).contains(&read_u16(raw, 16))
        || read_u16(raw, 18) != 0
        || read_u32(raw, 20) > 780
        || read_u32(raw, 24) > 780
        || read_u32(raw, 28) as usize > crate::script_table::MAX_TABLE_LEN
        || read_u16(raw, 32) != 0
    {
        return bad();
    }
    let mut offset = 788;
    take(raw, &mut offset, read_u16(raw, 12) as usize * 65)?;
    let source =
        MultiAssetVaultManifest::parse(take(raw, &mut offset, read_u32(raw, 20) as usize)?)?;
    take(raw, &mut offset, source.count() * 36)?;
    take(raw, &mut offset, read_u32(raw, 24) as usize)?;
    let table = crate::script_table::ScriptTable::parse(take(
        raw,
        &mut offset,
        read_u32(raw, 28) as usize,
    )?)?;
    if table.count() != 1 || table.script(read_u16(raw, 34) as usize)?.len() != 117 {
        return bad();
    }
    for _ in 0..read_u16(raw, 16) {
        take(raw, &mut offset, crate::FACTORY_RIGHT_LEN + 16)?;
        proof_end(raw, &mut offset)?;
        proof_end(raw, &mut offset)?;
    }
    let len = read_u32(take(raw, &mut offset, 4)?, 0) as usize;
    if len > FACTORY_MATERIALISATION_MAX_INTENT_LEN {
        return bad();
    }
    let intent = take(raw, &mut offset, len)?;
    let view = super::FactoryMaterialisationView::from_intent_bytes(intent)?;
    take(raw, &mut offset, read_u16(intent, 2) as usize * 66)?;
    if offset != raw.len() {
        return bad();
    }
    Ok(view)
}
