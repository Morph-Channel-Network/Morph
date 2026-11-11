//! Installed expectations, never supplied by an edge or provider response.
use super::*;

pub const CAPABILITIES_METHOD: &str = "morph_external_edge_capabilities";
pub const DRAIN_EXTERNAL_EDGE_METHOD: &str = "morph_drain_external_edge";
pub const SHADOW_PROFILE: &str = "morph.external_edges.shadow.v1";
pub const MAX_SHADOW_EDGES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookPolicy {
    pub fiber_commit: String,
    pub patch_hash: String,
    pub ckb_genesis_hash: String,
}
impl HookPolicy {
    pub fn validate(&self) -> AdapterResult<()> {
        if self.fiber_commit.len() != 40
            || !self
                .fiber_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.fiber_commit.bytes().all(|b| b == b'0')
            || decode_byte32(&self.patch_hash)? == [0; 32]
            || decode_byte32(&self.ckb_genesis_hash)? == [0; 32]
        {
            return Err(AdapterError::InvalidRequest);
        }
        Ok(())
    }
    fn matches(&self, capabilities: &HookCapabilities) -> bool {
        capabilities.profile == SHADOW_PROFILE
            && capabilities.fiber_commit == self.fiber_commit
            && capabilities.patch_hash == self.patch_hash
            && capabilities.ckb_genesis_hash == self.ckb_genesis_hash
            && !capabilities.forwarding
            && capabilities.max_edges > 0
            && capabilities.max_edges <= MAX_SHADOW_EDGES as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookCapabilities {
    pub profile: String,
    pub fiber_commit: String,
    pub patch_hash: String,
    pub ckb_genesis_hash: String,
    pub forwarding: bool,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    pub max_edges: u64,
}
impl HookCapabilities {
    pub fn check(&self, policy: &HookPolicy) -> AdapterResult<()> {
        policy.validate()?;
        if !policy.matches(self) {
            return Err(AdapterError::HookMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorState {
    Active,
    Draining,
    Disabled,
}
