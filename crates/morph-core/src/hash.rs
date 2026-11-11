use crate::types::{AssetRegistry, Bytes32, Mode, Phase};
use blake2b_rs::Blake2bBuilder;
pub use morph_script_common::multi_asset_close::MULTI_ASSET_CLOSE_DOMAIN;
pub const PARTICIPANTS_DOMAIN: &[u8] = b"CKB_MORPH_PARTICIPANTS";
pub const FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN: &[u8] =
    b"CKB_MORPH_FACTORY_MULTI_ASSET_MATERIALISATION_V1";
pub const FACTORY_MULTI_ASSET_UPDATE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_MULTI_ASSET_UPDATE_V1";
pub const FACTORY_SIGNING_REQUEST_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_SIGNING_REQUEST_V1";
pub const FACTORY_CHILD_DELIVERY_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_CHILD_DELIVERY_V1";
pub const FACTORY_REDUCED_RELEASE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_REDUCED_RELEASE_V1";
pub const FACTORY_REDUCED_RELEASE_LOCALITY_DOMAIN: &[u8] =
    b"CKB_MORPH_FACTORY_REDUCED_RELEASE_LOCALITY_V1";
pub const MULTI_ASSET_SPLICE_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_SPLICE_V1";
pub const MULTI_ASSET_SPLICE_FLOW_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_SPLICE_FLOW_V1";
pub const MULTI_ASSET_ROOT_FUNDING_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_ROOT_FUNDING_V1";
pub const MULTI_ASSET_STATE_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_STATE_V1";
pub const MULTI_ASSET_VAULT_SET_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_VAULT_SET_V1";
pub const MULTI_ASSET_OUTPOINT_SET_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1";
pub const MULTI_ASSET_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1";
pub const MULTI_ASSET_FUNDING_CONTEXT_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1";
pub const FACTORY_MULTI_ASSET_STATE_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_MULTI_ASSET_STATE_V1";
pub const FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN: &[u8] =
    b"CKB_MORPH_FACTORY_MULTI_ASSET_ROOT_FUNDING_V1";
pub trait SigningBytes {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>);
}
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}
pub fn participants_commitment(threshold: u8, pubkeys: &[&[u8]]) -> Bytes32 {
    let mut out = [0u8; 32];
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(PARTICIPANTS_DOMAIN);
    hasher.update(&[threshold]);
    hasher.update(&[pubkeys.len() as u8]);
    for pubkey in pubkeys {
        hasher.update(pubkey);
    }
    hasher.finalize(&mut out);
    out
}
pub fn asset_registry_commitment(registry: &AssetRegistry) -> Bytes32 {
    let mut bytes = Vec::with_capacity(
        morph_script_common::ASSET_REGISTRY_DOMAIN.len() + 8 + registry.xudt_types.len() * 32,
    );
    bytes.extend_from_slice(morph_script_common::ASSET_REGISTRY_DOMAIN);
    bytes.extend_from_slice(&(registry.xudt_types.len() as u64).to_le_bytes());
    for type_hash in &registry.xudt_types {
        bytes.extend_from_slice(type_hash);
    }
    blake2b256(&bytes)
}
impl Mode {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::BilateralPlain => 1,
        }
    }
}
impl Phase {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Funding => 0,
            Self::Active => 1,
            Self::Settling => 2,
            Self::Closed => 3,
        }
    }
}
