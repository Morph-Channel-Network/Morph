//! Multi-Vault Factory State profile. It has its own exact layout and signing
//! domains; a single-Vault Factory header or authorisation is never accepted.
use super::mismatch;
use crate::multi_asset::{MultiAssetVaultManifest, multi_asset_outpoint_set_commitment};
use crate::{
    FactorySignatureWitness, Result, ScriptError, blake2b256, read_u16, read_u32, read_u64,
    write_u16, write_u64,
};
pub const FACTORY_MULTI_ASSET_STATE_HEADER_LEN: usize = 306;
pub const FACTORY_MULTI_ASSET_STATE_LAYOUT_VERSION: u16 = 2;
pub const FACTORY_MULTI_ASSET_STATE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_MULTI_ASSET_STATE_V1";
pub const FACTORY_MULTI_ASSET_UPDATE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_MULTI_ASSET_UPDATE_V1";
pub const FACTORY_MULTI_ASSET_STATE_WITNESS_FORMAT: u16 = 2;
pub const FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN: &[u8] =
    b"CKB_MORPH_FACTORY_MULTI_ASSET_ROOT_FUNDING_V1";
pub const FACTORY_MULTI_ASSET_TYPE_ARGS_MAGIC: &[u8; 8] = b"MORPHFT!";
pub const FACTORY_MULTI_ASSET_TYPE_ARGS_LEN: usize = 44;
pub const FACTORY_MULTI_ASSET_STATE_WITNESS_MAGIC: &[u8; 8] = b"MORPHFS!";
pub const FACTORY_STATE_WITNESS_ROOT: u16 = 1;
pub const FACTORY_STATE_WITNESS_ACTIVATE: u16 = 2;
pub const FACTORY_STATE_WITNESS_UPDATE: u16 = 3;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMultiAssetHeaderFields {
    pub chain_id: [u8; 32],
    pub factory_id: [u8; 32],
    pub update_number: u64,
    pub state_root: [u8; 32],
    pub participants_commitment: [u8; 32],
    pub access_manifest_root: [u8; 32],
    pub non_interference_digest: [u8; 32],
    pub challenge_policy_commitment: [u8; 32],
    pub content_root: [u8; 32],
    pub outpoint_root: [u8; 32],
    pub vault_count: u16,
}
impl FactoryMultiAssetHeaderFields {
    pub fn encode(&self) -> Result<[u8; 306]> {
        let mut raw = [0; 306];
        write_u16(&mut raw, 0, 1);
        raw[2..34].copy_from_slice(&self.chain_id);
        write_u16(&mut raw, 34, 1);
        raw[36..68].copy_from_slice(&self.factory_id);
        write_u64(&mut raw, 68, self.update_number);
        raw[76..108].copy_from_slice(&self.state_root);
        raw[108..140].copy_from_slice(&self.participants_commitment);
        raw[140..172].copy_from_slice(&self.access_manifest_root);
        raw[172..204].copy_from_slice(&self.non_interference_digest);
        raw[204..236].copy_from_slice(&self.challenge_policy_commitment);
        write_u16(&mut raw, 236, 2);
        raw[238..270].copy_from_slice(&self.content_root);
        raw[270..302].copy_from_slice(&self.outpoint_root);
        write_u16(&mut raw, 302, self.vault_count);
        FactoryMultiAssetStateHeader::parse(&raw)?;
        Ok(raw)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMultiAssetStateHeader<'a> {
    raw: &'a [u8],
}
impl<'a> FactoryMultiAssetStateHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != 306
            || read_u16(raw, 0) != 1
            || read_u16(raw, 34) != 1
            || read_u16(raw, 236) != 2
            || read_u16(raw, 304) != 0
            || !(1..=8).contains(&read_u16(raw, 302))
        {
            return mismatch();
        }
        let header = Self { raw };
        for field in [
            header.chain_id(),
            header.factory_id(),
            header.state_root(),
            header.participants_commitment(),
            header.challenge_policy_commitment(),
            header.content_root(),
        ] {
            if field == [0; 32] {
                return mismatch();
            }
        }
        Ok(header)
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn chain_id(&self) -> &'a [u8] {
        &self.raw[2..34]
    }
    pub fn factory_id(&self) -> &'a [u8] {
        &self.raw[36..68]
    }
    pub fn update_number(&self) -> u64 {
        read_u64(self.raw, 68)
    }
    pub fn state_root(&self) -> &'a [u8] {
        &self.raw[76..108]
    }
    pub fn participants_commitment(&self) -> &'a [u8] {
        &self.raw[108..140]
    }
    pub fn challenge_policy_commitment(&self) -> &'a [u8] {
        &self.raw[204..236]
    }
    pub fn content_root(&self) -> &'a [u8] {
        &self.raw[238..270]
    }
    pub fn outpoint_root(&self) -> &'a [u8] {
        &self.raw[270..302]
    }
    pub fn access_manifest_root(&self) -> &'a [u8] {
        &self.raw[140..172]
    }
    pub fn non_interference_digest(&self) -> &'a [u8] {
        &self.raw[172..204]
    }
    /// Decodes the sole current header layout for host/native builders.
    pub fn fields(&self) -> FactoryMultiAssetHeaderFields {
        let hash = |bytes: &[u8]| {
            let mut value = [0; 32];
            value.copy_from_slice(bytes);
            value
        };
        FactoryMultiAssetHeaderFields {
            chain_id: hash(self.chain_id()),
            factory_id: hash(self.factory_id()),
            update_number: self.update_number(),
            state_root: hash(self.state_root()),
            participants_commitment: hash(self.participants_commitment()),
            access_manifest_root: hash(self.access_manifest_root()),
            non_interference_digest: hash(self.non_interference_digest()),
            challenge_policy_commitment: hash(self.challenge_policy_commitment()),
            content_root: hash(self.content_root()),
            outpoint_root: hash(self.outpoint_root()),
            vault_count: self.vault_count() as u16,
        }
    }
    pub fn vault_count(&self) -> usize {
        read_u16(self.raw, 302) as usize
    }
    pub fn vaults_are_bound(&self) -> bool {
        self.outpoint_root() != [0; 32]
    }
    pub fn same_identity(&self, next: &Self) -> bool {
        self.raw[..68] == next.raw[..68]
            && self.raw[108..140] == next.raw[108..140]
            && self.raw[204..238] == next.raw[204..238]
    }
    pub fn is_activation_to(&self, next: &Self) -> bool {
        !self.vaults_are_bound()
            && next.vaults_are_bound()
            && self.raw[..270] == next.raw[..270]
            && self.raw[302..] == next.raw[302..]
    }
    pub fn same_custody(&self, next: &Self) -> bool {
        self.raw[238..] == next.raw[238..]
    }
    /// Header commitment used inside role-specific exact-transaction domains;
    /// this digest alone is not accepted as a Factory update authorization.
    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[FACTORY_MULTI_ASSET_STATE_DOMAIN, self.raw])
    }
    pub fn root_funding_signing_digest(&self, transaction: &[u8; 32]) -> Result<[u8; 32]> {
        if self.update_number() != 0 || self.vaults_are_bound() || *transaction == [0; 32] {
            return mismatch();
        }
        Ok(blake2b256(&[
            FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN,
            &self.signing_digest(),
            transaction,
        ]))
    }
    pub fn update_signing_digest(&self, transaction: &[u8; 32]) -> Result<[u8; 32]> {
        if self.update_number() == 0 || !self.vaults_are_bound() || *transaction == [0; 32] {
            return mismatch();
        }
        Ok(blake2b256(&[
            FACTORY_MULTI_ASSET_UPDATE_DOMAIN,
            &self.signing_digest(),
            transaction,
        ]))
    }
    pub fn verify_update_signatures(
        &self,
        transaction: &[u8; 32],
        signatures: &FactorySignatureWitness,
    ) -> Result<()> {
        self.verify_digest(&self.update_signing_digest(transaction)?, signatures)
    }
    pub fn verify_root_signatures(
        &self,
        transaction: &[u8; 32],
        signatures: &FactorySignatureWitness,
    ) -> Result<()> {
        self.verify_digest(&self.root_funding_signing_digest(transaction)?, signatures)
    }
    fn verify_digest(&self, digest: &[u8; 32], signatures: &FactorySignatureWitness) -> Result<()> {
        if signatures.participants_commitment().as_slice() != self.participants_commitment() {
            return Err(ScriptError::ParticipantCommitmentMismatch);
        }
        crate::verify_factory_signatures_for_digest(digest, signatures)
    }
}
pub fn parse_factory_multi_asset_type_args(raw: &[u8]) -> Result<&[u8]> {
    if raw.len() != 44
        || &raw[..8] != FACTORY_MULTI_ASSET_TYPE_ARGS_MAGIC
        || read_u16(raw, 8) != 1
        || read_u16(raw, 10) != 0
        || raw[12..] == [0; 32]
    {
        return mismatch();
    }
    Ok(&raw[12..])
}
pub fn encode_factory_multi_asset_type_args(factory: &[u8; 32]) -> Result<[u8; 44]> {
    let mut raw = [0; 44];
    raw[..8].copy_from_slice(FACTORY_MULTI_ASSET_TYPE_ARGS_MAGIC);
    write_u16(&mut raw, 8, 1);
    raw[12..].copy_from_slice(factory);
    parse_factory_multi_asset_type_args(&raw)?;
    Ok(raw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryMultiAssetStateWitness<'a> {
    raw: &'a [u8],
    manifest: MultiAssetVaultManifest<'a>,
    points: &'a [u8],
    signatures: Option<FactorySignatureWitness<'a>>,
}
impl<'a> FactoryMultiAssetStateWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 24
            || raw.len() > 24 + 780 + 288 + 2068
            || &raw[..8] != FACTORY_MULTI_ASSET_STATE_WITNESS_MAGIC
            || read_u16(raw, 8) != FACTORY_MULTI_ASSET_STATE_WITNESS_FORMAT
            || read_u16(raw, 10) != 0
        {
            return mismatch();
        }
        let kind = read_u16(raw, 12);
        let count = read_u16(raw, 14) as usize;
        let len = read_u32(raw, 16) as usize;
        let siglen = read_u32(raw, 20) as usize;
        if !(1..=3).contains(&kind) || count > 8 || len > 780 || siglen > 2068 {
            return mismatch();
        }
        let end = 24 + len;
        let sigstart = end + 36 * count;
        if sigstart + siglen != raw.len() {
            return mismatch();
        }
        let manifest = MultiAssetVaultManifest::parse(&raw[24..end])?;
        let points = &raw[end..sigstart];
        let signatures = if siglen == 0 {
            None
        } else {
            Some(FactorySignatureWitness::parse(&raw[sigstart..])?)
        };
        if (kind == FACTORY_STATE_WITNESS_ROOT && (count != 0 || signatures.is_none()))
            || (kind == FACTORY_STATE_WITNESS_ACTIVATE
                && (count != manifest.count() || signatures.is_some()))
            || (kind == FACTORY_STATE_WITNESS_UPDATE
                && (count != manifest.count() || signatures.is_none()))
        {
            return mismatch();
        }
        Ok(Self {
            raw,
            manifest,
            points,
            signatures,
        })
    }
    pub fn kind(&self) -> u16 {
        read_u16(self.raw, 12)
    }
    pub fn manifest(&self) -> &MultiAssetVaultManifest<'a> {
        &self.manifest
    }
    pub fn points(&self) -> &'a [u8] {
        self.points
    }
    pub fn signatures(&self) -> Result<&FactorySignatureWitness<'a>> {
        self.signatures
            .as_ref()
            .ok_or(ScriptError::ParticipantWitnessMissing)
    }
    pub fn validate_header(&self, header: &FactoryMultiAssetStateHeader) -> Result<()> {
        if self.manifest.count() != header.vault_count()
            || self.manifest.commitment() != header.content_root()
        {
            return mismatch();
        }
        if header.vaults_are_bound() {
            if multi_asset_outpoint_set_commitment(
                header.content_root(),
                header.vault_count(),
                self.points,
            )?
            .as_slice()
                != header.outpoint_root()
            {
                return mismatch();
            }
        } else if !self.points.is_empty() {
            return mismatch();
        }
        Ok(())
    }
}
