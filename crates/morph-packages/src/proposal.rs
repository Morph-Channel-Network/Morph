use crate::multi_asset_packages::{canonical_hex, decode_hex};
use anyhow::{Result, anyhow, ensure};
use morph_core::*;
use serde::{Deserialize, Serialize};
const PROPOSAL_SCHEMA: &str = "morph.multi_asset_proposal.v1";
const MAX_DESCRIPTOR_BYTES: usize =
    morph_script_common::multi_asset::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
        + morph_script_common::multi_asset::MULTI_ASSET_MAX_VAULTS
            * morph_script_common::multi_asset::MULTI_ASSET_PAYOUT_ENTRY_LEN
        + morph_script_common::multi_asset_conditional::MULTI_ASSET_CONDITIONAL_LEN;
fn digest(value: &str) -> Result<Bytes32> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("digest must be 32 bytes"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalMessage {
    pub schema: String,
    pub base_state_digest: String,
    pub state_number: String,
    pub descriptor_hex: String,
    pub signing_digest: String,
}

impl ProposalMessage {
    pub fn from_proposal(proposal: &MultiAssetProposal) -> Result<Self> {
        Ok(Self {
            schema: PROPOSAL_SCHEMA.to_string(),
            base_state_digest: canonical_hex(&proposal.base_state_digest),
            state_number: proposal.state.header.state_number.to_string(),
            descriptor_hex: canonical_hex(&proposal.settlement.encode()?),
            signing_digest: canonical_hex(&proposal.signing_digest()?),
        })
    }
    pub fn proposal(&self, current: &MultiAssetRecoveryPackage) -> Result<MultiAssetProposal> {
        ensure!(
            self.schema == PROPOSAL_SCHEMA,
            "unsupported proposal schema"
        );
        let number = self.state_number.parse::<u64>()?;
        ensure!(
            number.to_string() == self.state_number,
            "state number must be canonical decimal"
        );
        let descriptor = decode_hex(&self.descriptor_hex, MAX_DESCRIPTOR_BYTES)?;
        let settlement = MultiAssetSettlement::decode(&descriptor)?;
        let mut state = current.state.clone();
        state.header.state_number = number;
        state.header.settlement_descriptor_commitment = settlement.commitment()?;
        let proposal = MultiAssetProposal {
            base_state_digest: digest(&self.base_state_digest)?,
            state,
            settlement,
        };
        ensure!(
            proposal.signing_digest()? == digest(&self.signing_digest)?,
            "proposal digest does not match contents"
        );
        Ok(proposal)
    }
}
