//! Current public close draft; scalar wire fields stay in their canonical bytes.
use crate::multi_asset_packages::{canonical_hex, decode_hex};
use anyhow::{Result, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::{MultiAssetCloseProposal, MultiAssetOutPoint, MultiAssetRecoveryPackage, Phase};
use morph_script_common::multi_asset as wire;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseDraft {
    pub source_header_hex: String,
    pub raw_transaction_hex: String,
}
impl CloseDraft {
    pub fn from_proposal(proposal: &MultiAssetCloseProposal) -> Result<Self> {
        proposal.raw_transaction()?;
        Ok(Self {
            source_header_hex: canonical_hex(&proposal.source_state.encode()?),
            raw_transaction_hex: canonical_hex(&proposal.transaction),
        })
    }
    pub fn proposal(&self, current: &MultiAssetRecoveryPackage) -> Result<MultiAssetCloseProposal> {
        let source = decode_hex(&self.source_header_hex, wire::MULTI_ASSET_STATE_HEADER_LEN)?;
        let bytes = decode_hex(
            &self.raw_transaction_hex,
            morph_core::MULTI_ASSET_CLOSE_MAX_TRANSACTION_BYTES,
        )?;
        ensure!(
            canonical_hex(&source) == self.source_header_hex
                && canonical_hex(&bytes) == self.raw_transaction_hex,
            "close draft requires canonical hex"
        );
        let header =
            wire::MultiAssetStateHeader::parse(&source).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut state = current.state.clone();
        state.header.state_number = header.state_number();
        state.header.phase = if header.phase() == morph_script_common::PHASE_ACTIVE {
            Phase::Active
        } else {
            Phase::Settling
        };
        state
            .header
            .settlement_descriptor_commitment
            .copy_from_slice(header.settlement_descriptor_commitment());
        ensure!(
            state.encode()?.as_slice() == source,
            "close source changes immutable context"
        );
        let raw = packed::RawTransaction::from_slice(&bytes)?;
        let point = raw
            .inputs()
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("missing close source"))?
            .previous_output();
        let proposal = MultiAssetCloseProposal {
            source_outpoint: MultiAssetOutPoint {
                tx_hash: point.tx_hash().unpack(),
                index: point.index().unpack(),
            },
            source_state: state,
            transaction: bytes,
        };
        proposal.validate(current)?;
        Ok(proposal)
    }
}
