use super::{
    FACTORY_MULTI_ASSET_MAX_CHILDREN, MultiAssetVaultManifest, Result, ScriptError,
    materialisation_commitment, mismatch, validate_materialisation_partition,
};
use crate::multi_asset::{self as asset, MultiAssetStateHeader, MultiAssetWitness};
use crate::{
    BilateralSignatureWitness, FactorySignatureWitness, blake2b256, read_u16, read_u32, read_u64,
};

pub const FACTORY_MATERIALISATION_PREFIX_LEN: usize = 208;
pub const FACTORY_CHILD_PREFIX_LEN: usize = 334;
pub const FACTORY_MATERIALISATION_MAX_INTENT_LEN: usize = FACTORY_MATERIALISATION_PREFIX_LEN
    + 2 * (4 + 8 * 97)
    + 8 * 36
    + 2 * asset::MULTI_ASSET_MAX_SCRIPT_LEN
    + 8 * (4 + asset::MULTI_ASSET_MAX_SCRIPT_LEN)
    + FACTORY_MULTI_ASSET_MAX_CHILDREN
        * (FACTORY_CHILD_PREFIX_LEN + asset::MULTI_ASSET_MAX_WITNESS_LEN);
pub const FACTORY_MATERIALISATION_MAGIC: &[u8; 8] = b"MORPHFM!";
pub const FACTORY_MATERIALISATION_WITNESS_PREFIX_LEN: usize = 24;
pub const FACTORY_MATERIALISATION_MAX_WITNESS_LEN: usize =
    24 + FACTORY_MATERIALISATION_MAX_INTENT_LEN + 4 + 16 * 129 + 4 * 66;

fn take<'a>(raw: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?;
    let value = raw
        .get(*offset..end)
        .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?;
    *offset = end;
    Ok(value)
}
fn nonzero(raw: &[u8]) -> bool {
    raw.iter().any(|byte| *byte != 0)
}
fn hash32(raw: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(raw);
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMaterialisationChild<'a> {
    pub state_output_index: usize,
    pub carrier_capacity: u64,
    pub header: MultiAssetStateHeader<'a>,
    pub evidence: MultiAssetWitness<'a>,
    script_hashes: [[u8; 32]; 3],
}
impl FactoryMaterialisationChild<'_> {
    pub fn state_type_hash(&self) -> [u8; 32] {
        self.script_hashes[0]
    }
    pub fn state_lock_hash(&self) -> [u8; 32] {
        self.script_hashes[1]
    }
    pub fn vault_lock_hash(&self) -> [u8; 32] {
        self.script_hashes[2]
    }

    pub fn creation_header(&self) -> Result<[u8; 318]> {
        let mut raw = [0; 318];
        raw.copy_from_slice(self.header.as_bytes());
        raw[108..116].fill(0);
        raw[117] = crate::PHASE_ACTIVE;
        raw[282..314].fill(0);
        MultiAssetStateHeader::parse(&raw)?;
        Ok(raw)
    }
    pub fn verify_recovery_authorisation(
        &self,
        recovery: &BilateralSignatureWitness,
    ) -> Result<()> {
        self.header.verify_signatures(recovery)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMaterialisationIntent<'a> {
    raw: &'a [u8],
    source: MultiAssetVaultManifest<'a>,
    source_points: &'a [u8],
    retained: Option<MultiAssetVaultManifest<'a>>,
    refund: &'a [u8],
    factory_lock: &'a [u8],
    types: [Option<&'a [u8]>; 8],
    children: [Option<FactoryMaterialisationChild<'a>>; 4],
}
impl<'a> FactoryMaterialisationIntent<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < FACTORY_MATERIALISATION_PREFIX_LEN
            || raw.len() > FACTORY_MATERIALISATION_MAX_INTENT_LEN
            || read_u16(raw, 0) != 2
            || !(1..=4).contains(&read_u16(raw, 2))
            || read_u16(raw, 202) != 0
        {
            return mismatch();
        }
        let count = read_u16(raw, 2) as usize;
        let source_len = read_u32(raw, 168) as usize;
        let retained_len = read_u32(raw, 172) as usize;
        let refund_index = read_u32(raw, 192);
        let factory_index = read_u32(raw, 196) as usize;
        let type_count = read_u16(raw, 200) as usize;
        if source_len > 780 || retained_len > 780 || type_count > 8 {
            return mismatch();
        }
        let mut offset = FACTORY_MATERIALISATION_PREFIX_LEN;
        let source = MultiAssetVaultManifest::parse(take(raw, &mut offset, source_len)?)?;
        let source_points = take(raw, &mut offset, source.count() * 36)?;
        asset::multi_asset_outpoint_set_commitment(
            &source.commitment(),
            source.count(),
            source_points,
        )?;
        let retained = if retained_len == 0 {
            None
        } else {
            Some(MultiAssetVaultManifest::parse(take(
                raw,
                &mut offset,
                retained_len,
            )?)?)
        };
        let table = crate::script_table::ScriptTable::parse(take(
            raw,
            &mut offset,
            read_u32(raw, 204) as usize,
        )?)?;
        let factory_lock = table.script(factory_index)?;
        if factory_lock.len() != 117 {
            return mismatch();
        }
        let mut used = 1u64 << factory_index;
        let refund = if refund_index == u32::MAX {
            &raw[..0]
        } else {
            let value = table.script(refund_index as usize)?;
            used |= 1u64 << refund_index;
            value
        };
        let mut types = [None; 8];
        let mut previous = None;
        for slot in types.iter_mut().take(type_count) {
            let index = take(raw, &mut offset, 1)?[0] as usize;
            let script = table.script(index)?;
            used |= 1u64 << index;
            let hash = blake2b256(&[script]);
            if previous.is_some_and(|value| value >= hash) {
                return mismatch();
            }
            previous = Some(hash);
            *slot = Some(script);
        }
        let mut children = [None; 4];
        for slot in children.iter_mut().take(count) {
            let prefix = take(raw, &mut offset, FACTORY_CHILD_PREFIX_LEN)?;
            let len = read_u32(prefix, 330) as usize;
            if len > asset::MULTI_ASSET_MAX_WITNESS_LEN {
                return mismatch();
            }
            let header = MultiAssetStateHeader::parse(&prefix[12..330])?;
            let evidence =
                MultiAssetWitness::parse_with_table(take(raw, &mut offset, len)?, Some(&table))?;
            evidence.validate_header(&header)?;
            used |= evidence.scripts().dictionary_usage();
            *slot = Some(FactoryMaterialisationChild {
                state_output_index: read_u32(prefix, 0) as usize,
                carrier_capacity: read_u64(prefix, 4),
                header,
                evidence,
                script_hashes: [
                    blake2b256(&[evidence.scripts().script(4)?]),
                    blake2b256(&[evidence.scripts().script(5)?]),
                    blake2b256(&[evidence.scripts().script(3)?]),
                ],
            });
        }
        if offset != raw.len() || used != table.complete_usage() {
            return mismatch();
        }
        let intent = Self {
            raw,
            source,
            source_points,
            retained,
            refund,
            factory_lock,
            types,
            children,
        };
        intent.validate_contents()?;
        Ok(intent)
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn chain_id(&self) -> &'a [u8] {
        &self.raw[4..36]
    }
    pub fn factory_id(&self) -> &'a [u8] {
        &self.raw[36..68]
    }
    pub fn participants_commitment(&self) -> &'a [u8] {
        &self.raw[68..100]
    }
    pub fn old_state_outpoint(&self) -> &'a [u8] {
        &self.raw[100..136]
    }
    pub fn transaction_hash(&self) -> [u8; 32] {
        hash32(&self.raw[136..168])
    }
    pub fn factory_carrier_capacity(&self) -> u64 {
        read_u64(self.raw, 176)
    }
    pub fn external_carrier_contribution(&self) -> u64 {
        read_u64(self.raw, 184)
    }
    pub fn source(&self) -> &MultiAssetVaultManifest<'a> {
        &self.source
    }
    pub fn source_points(&self) -> &'a [u8] {
        self.source_points
    }
    pub fn retained(&self) -> Option<&MultiAssetVaultManifest<'a>> {
        self.retained.as_ref()
    }
    pub fn refund_script(&self) -> &'a [u8] {
        self.refund
    }
    pub fn type_script(&self, asset: asset::MultiAssetId) -> Result<Option<&'a [u8]>> {
        if asset.kind == 0 {
            return Ok(None);
        }
        self.types
            .iter()
            .flatten()
            .copied()
            .find(|script| blake2b256(&[script]) == asset.type_hash)
            .map(Some)
            .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)
    }
    pub fn factory_lock_script(&self) -> &'a [u8] {
        self.factory_lock
    }
    pub fn child_count(&self) -> usize {
        read_u16(self.raw, 2) as usize
    }
    pub fn child(&self, index: usize) -> Result<&FactoryMaterialisationChild<'a>> {
        self.children
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(ScriptError::IndexOutOfBounds)
    }
    pub fn source_outpoint_root(&self) -> Result<[u8; 32]> {
        asset::multi_asset_outpoint_set_commitment(
            &self.source.commitment(),
            self.source.count(),
            self.source_points,
        )
    }
    pub fn signing_digest(&self) -> [u8; 32] {
        materialisation_commitment(self.raw)
    }
    fn validate_contents(&self) -> Result<()> {
        if !nonzero(self.chain_id())
            || !nonzero(self.factory_id())
            || !nonzero(self.participants_commitment())
            || !nonzero(&self.old_state_outpoint()[..32])
            || !nonzero(&self.transaction_hash())
            || self.old_state_outpoint()[..32] == self.transaction_hash()
            || self.factory_carrier_capacity() == 0
            || &self.factory_lock[53..85] != self.factory_id()
            || !nonzero(&self.factory_lock[85..])
            || blake2b256(&[self.factory_lock]) != self.source.entry(0)?.lock_hash
        {
            return mismatch();
        }
        for point in self.source_points.chunks_exact(36) {
            if point == self.old_state_outpoint() || point[..32] == self.transaction_hash() {
                return mismatch();
            }
        }
        let mut type_index = 0;
        for i in 0..self.source.count() {
            let entry = self.source.entry(i)?;
            if entry.asset.kind == 1 {
                let script = self
                    .types
                    .get(type_index)
                    .copied()
                    .flatten()
                    .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?;
                if blake2b256(&[script]) != entry.asset.type_hash {
                    return mismatch();
                }
                type_index += 1;
            }
        }
        if self.types.iter().flatten().count() != type_index {
            return mismatch();
        }
        for manifest in core::iter::once(&self.source).chain(self.retained.iter()) {
            for i in 0..manifest.count() {
                let entry = manifest.entry(i)?;
                let ty = if entry.asset.kind == 0 {
                    None
                } else {
                    self.types
                        .iter()
                        .flatten()
                        .find(|script| blake2b256(&[script]) == entry.asset.type_hash)
                        .copied()
                };
                if entry.asset.kind == 1 && ty.is_none() {
                    return mismatch();
                }
                if entry.allocation.reserve
                    < asset::multi_asset_occupied_capacity(
                        self.factory_lock,
                        ty,
                        if ty.is_some() { 16 } else { 0 },
                    )?
                {
                    return mismatch();
                }
            }
        }
        let mut manifests = [self.source; 4];
        for (i, slot) in manifests.iter_mut().enumerate().take(self.child_count()) {
            *slot = *self.child(i)?.evidence.manifest();
        }
        validate_materialisation_partition(
            &self.source,
            self.retained.as_ref(),
            &manifests[..self.child_count()],
        )?;
        if self.retained.is_some() {
            if !self.refund.is_empty() {
                return mismatch();
            }
        } else if self.refund.is_empty()
            || asset::multi_asset_occupied_capacity(self.refund, None, 0)?
                > self.factory_carrier_capacity()
        {
            return mismatch();
        }
        let mut occupied = [false; 64];
        occupied[0] = true;
        if let Some(retained) = self.retained {
            for slot in occupied.iter_mut().take(retained.count() + 1).skip(1) {
                *slot = true;
            }
        }
        let mut carriers = 0u64;
        for i in 0..self.child_count() {
            let child = self.child(i)?;
            let header = child.header;
            if header.chain_id() != self.chain_id()
                || header.funding_epoch() != 0
                || header.phase() != crate::PHASE_SETTLING
                || header.state_number() != 1
                || child.state_output_index >= 64
                || occupied[child.state_output_index]
            {
                return mismatch();
            }
            occupied[child.state_output_index] = true;
            let mut anchor_index = [0; 8];
            crate::write_u64(&mut anchor_index, 0, child.state_output_index as u64);
            if blake2b256(&[&[0; 8], self.old_state_outpoint(), &anchor_index])
                != header.funding_anchor()
            {
                return mismatch();
            }
            let scripts = child.evidence.scripts();
            if scripts.script(4)?.len() != 125
                || scripts.script(4)?[85..117] != self.factory_lock[85..117]
            {
                return mismatch();
            }
            if child.carrier_capacity
                < asset::multi_asset_occupied_capacity(
                    scripts.script(5)?,
                    Some(scripts.script(4)?),
                    318,
                )?
                || child.carrier_capacity
                    < asset::multi_asset_occupied_capacity(scripts.script(2)?, None, 0)?
            {
                return mismatch();
            }
            for previous in 0..i {
                let other = self.child(previous)?;
                if other.header.channel_id() == header.channel_id()
                    || other.evidence.scripts().script(4)? == scripts.script(4)?
                    || other.evidence.scripts().script(5)? == scripts.script(5)?
                {
                    return mismatch();
                }
            }
            for point in child.evidence.outpoints().chunks_exact(36) {
                let index = read_u32(point, 32) as usize;
                if point[..32] != self.transaction_hash() || index >= 64 || occupied[index] {
                    return mismatch();
                }
                occupied[index] = true;
            }
            carriers = carriers
                .checked_add(child.carrier_capacity)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
        }
        for i in 0..self.child_count() {
            let child = self.child(i)?;
            for role in 0..3 {
                if self.is_custody_lock(&blake2b256(&[child.evidence.scripts().script(role)?]))? {
                    return mismatch();
                }
            }
        }
        if !self.refund.is_empty() && self.is_custody_lock(&blake2b256(&[self.refund]))? {
            return mismatch();
        }
        if carriers != self.external_carrier_contribution() {
            return mismatch();
        }
        let source_capacity = (0..self.source.count()).try_fold(0u64, |sum, i| {
            sum.checked_add(self.source.entry(i)?.allocation.capacity()?)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)
        })?;
        source_capacity
            .checked_add(self.factory_carrier_capacity())
            .and_then(|value| value.checked_add(carriers))
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
        Ok(())
    }
    pub fn is_custody_lock(&self, hash: &[u8; 32]) -> Result<bool> {
        if *hash == self.source.entry(0)?.lock_hash {
            return Ok(true);
        }
        for i in 0..self.child_count() {
            let child = self.child(i)?;
            if child.vault_lock_hash() == *hash || child.state_lock_hash() == *hash {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMaterialisationWitness<'a> {
    raw: &'a [u8],
    intent: FactoryMaterialisationIntent<'a>,
    factory: FactorySignatureWitness<'a>,
    child_keys: &'a [u8],
}
impl<'a> FactoryMaterialisationWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 24
            || raw.len() > FACTORY_MATERIALISATION_MAX_WITNESS_LEN
            || &raw[..8] != FACTORY_MATERIALISATION_MAGIC
            || read_u16(raw, 8) != 2
            || read_u16(raw, 10) != 0
            || read_u16(raw, 22) != 0
        {
            return mismatch();
        }
        let intent_len = read_u32(raw, 12) as usize;
        let signature_len = read_u32(raw, 16) as usize;
        let count = read_u16(raw, 20) as usize;
        if intent_len > FACTORY_MATERIALISATION_MAX_INTENT_LEN
            || signature_len > 4 + 16 * 129
            || !(1..=4).contains(&count)
        {
            return mismatch();
        }
        let mut offset = 24;
        let intent = FactoryMaterialisationIntent::parse(take(raw, &mut offset, intent_len)?)?;
        let factory = FactorySignatureWitness::parse(take(raw, &mut offset, signature_len)?)?;
        let child_keys = take(raw, &mut offset, count * 66)?;
        if offset != raw.len() || intent.child_count() != count {
            return mismatch();
        }
        Ok(Self {
            raw,
            intent,
            factory,
            child_keys,
        })
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn intent(&self) -> &FactoryMaterialisationIntent<'a> {
        &self.intent
    }
    pub fn factory_signatures(&self) -> &FactorySignatureWitness<'a> {
        &self.factory
    }
    pub fn child_pubkey(&self, index: usize, participant: usize) -> Result<&'a [u8]> {
        if index >= self.intent.child_count() || participant >= 2 {
            return mismatch();
        }
        Ok(&self.child_keys[index * 66 + participant * 33..index * 66 + (participant + 1) * 33])
    }
    /// Validates parent membership and the exact independent child key pairs.
    /// This does not validate Factory ECDSA authorization.
    pub fn validate_public_contents(&self) -> Result<()> {
        if self.factory.participants_commitment().as_slice()
            != self.intent.participants_commitment()
        {
            return Err(ScriptError::ParticipantCommitmentMismatch);
        }
        for i in 0..self.intent.child_count() {
            let first = self.child_pubkey(i, 0)?;
            let second = self.child_pubkey(i, 1)?;
            if first >= second
                || crate::participants_commitment(2, &[first, second]).as_slice()
                    != self.intent.child(i)?.header.participants_commitment()
            {
                return Err(ScriptError::ParticipantCommitmentMismatch);
            }
        }
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        self.validate_public_contents()?;
        crate::verify_factory_signatures_for_digest(&self.intent.signing_digest(), &self.factory)
    }
}

/// Bounded access for scripts which delegate complete transition verification
/// to the authentic Factory Type. This is not an authorisation verifier.
#[derive(Debug, Clone, Copy)]
pub struct FactoryMaterialisationView<'a> {
    intent: &'a [u8],
    count: usize,
}
impl<'a> FactoryMaterialisationView<'a> {
    /// Read-only bounded view; authorization remains the authentic Factory
    /// Type's responsibility, exactly as for the outer materialisation frame.
    pub fn from_intent_bytes(intent: &'a [u8]) -> Result<Self> {
        if !(FACTORY_MATERIALISATION_PREFIX_LEN..=FACTORY_MATERIALISATION_MAX_INTENT_LEN)
            .contains(&intent.len())
            || read_u16(intent, 0) != 2
            || !(1..=4).contains(&read_u16(intent, 2))
            || read_u16(intent, 202) != 0
        {
            return mismatch();
        }
        let view = Self {
            intent,
            count: read_u16(intent, 2) as usize,
        };
        view.source_context()?;
        Ok(view)
    }

    pub fn from_intent(intent: &FactoryMaterialisationIntent<'a>) -> Self {
        Self {
            intent: intent.as_bytes(),
            count: intent.child_count(),
        }
    }

    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 24
            || raw.len() > FACTORY_MATERIALISATION_MAX_WITNESS_LEN
            || &raw[..8] != FACTORY_MATERIALISATION_MAGIC
            || read_u16(raw, 8) != 2
            || read_u16(raw, 10) != 0
            || read_u16(raw, 22) != 0
        {
            return mismatch();
        }
        let len = read_u32(raw, 12) as usize;
        let siglen = read_u32(raw, 16) as usize;
        let count = read_u16(raw, 20) as usize;
        if !(1..=4).contains(&count)
            || !(FACTORY_MATERIALISATION_PREFIX_LEN..=FACTORY_MATERIALISATION_MAX_INTENT_LEN)
                .contains(&len)
            || siglen > 2068
            || 24 + len + siglen + count * 66 != raw.len()
        {
            return mismatch();
        }
        let intent = &raw[24..24 + len];
        if read_u16(intent, 0) != 2
            || read_u16(intent, 2) as usize != count
            || read_u16(intent, 202) != 0
        {
            return mismatch();
        }
        FactorySignatureWitness::parse(&raw[24 + len..24 + len + siglen])?;
        Ok(Self { intent, count })
    }
    pub fn source_context(&self) -> Result<FactoryMaterialisationSource<'a>> {
        FactoryMaterialisationSource::parse(self.intent)
    }
    pub fn child_by_anchor(&self, wanted: &[u8]) -> Result<FactoryMaterialisationChild<'a>> {
        let source = self.source_context()?;
        let retained = read_u32(self.intent, 172) as usize;
        let type_count = read_u16(self.intent, 200) as usize;
        if retained > 780 || type_count > 8 {
            return mismatch();
        }
        let mut offset = FACTORY_MATERIALISATION_PREFIX_LEN
            + source.source.as_bytes().len()
            + source.points.len();
        take(self.intent, &mut offset, retained)?;
        let table = crate::script_table::ScriptTable::parse(take(
            self.intent,
            &mut offset,
            read_u32(self.intent, 204) as usize,
        )?)?;
        take(self.intent, &mut offset, type_count)?;
        let mut result = None;
        for _ in 0..self.count {
            let prefix = take(self.intent, &mut offset, 334)?;
            let len = read_u32(prefix, 330) as usize;
            if len > asset::MULTI_ASSET_MAX_WITNESS_LEN {
                return mismatch();
            }
            let evidence = take(self.intent, &mut offset, len)?;
            if &prefix[88..120] == wanted {
                if result.is_some() {
                    return mismatch();
                }
                let header = MultiAssetStateHeader::parse(&prefix[12..330])?;
                let evidence = MultiAssetWitness::parse_with_table(evidence, Some(&table))?;
                evidence.validate_header(&header)?;
                result = Some(FactoryMaterialisationChild {
                    state_output_index: read_u32(prefix, 0) as usize,
                    carrier_capacity: read_u64(prefix, 4),
                    header,
                    evidence,
                    script_hashes: [
                        blake2b256(&[evidence.scripts().script(4)?]),
                        blake2b256(&[evidence.scripts().script(5)?]),
                        blake2b256(&[evidence.scripts().script(3)?]),
                    ],
                });
            }
        }
        if offset != self.intent.len() {
            return mismatch();
        }
        result.ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)
    }
    pub fn transaction_hash(&self) -> [u8; 32] {
        hash32(&self.intent[136..168])
    }
}
#[derive(Debug, Clone, Copy)]
pub struct FactoryMaterialisationSource<'a> {
    raw: &'a [u8],
    source: MultiAssetVaultManifest<'a>,
    points: &'a [u8],
}
impl<'a> FactoryMaterialisationSource<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < FACTORY_MATERIALISATION_PREFIX_LEN
            || raw.len() > FACTORY_MATERIALISATION_MAX_INTENT_LEN
            || read_u16(raw, 0) != 2
            || read_u16(raw, 202) != 0
        {
            return mismatch();
        }
        let len = read_u32(raw, 168) as usize;
        if len > 780 {
            return mismatch();
        }
        let mut offset = FACTORY_MATERIALISATION_PREFIX_LEN;
        let source = MultiAssetVaultManifest::parse(take(raw, &mut offset, len)?)?;
        let points = take(raw, &mut offset, source.count() * 36)?;
        Ok(Self {
            raw,
            source,
            points,
        })
    }
    pub fn chain_id(&self) -> &'a [u8] {
        &self.raw[4..36]
    }
    pub fn factory_id(&self) -> &'a [u8] {
        &self.raw[36..68]
    }
    pub fn participants_commitment(&self) -> &'a [u8] {
        &self.raw[68..100]
    }
    pub fn old_state_outpoint(&self) -> &'a [u8] {
        &self.raw[100..136]
    }
    pub fn factory_carrier_capacity(&self) -> u64 {
        read_u64(self.raw, 176)
    }
    pub fn source(&self) -> &MultiAssetVaultManifest<'a> {
        &self.source
    }
    pub fn source_outpoint_root(&self) -> Result<[u8; 32]> {
        asset::multi_asset_outpoint_set_commitment(
            &self.source.commitment(),
            self.source.count(),
            self.points,
        )
    }
}
impl<'a> FactoryMaterialisationIntent<'a> {
    pub fn source_context(&self) -> FactoryMaterialisationSource<'a> {
        FactoryMaterialisationSource {
            raw: self.raw,
            source: self.source,
            points: self.source_points,
        }
    }
}
