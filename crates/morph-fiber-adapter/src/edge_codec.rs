//! Inverse of the public projection. Identity validation is not chain evidence.
use super::*;

impl TryFrom<&FiberExternalEdge> for ProviderEdgeDescriptor {
    type Error = AdapterError;

    fn try_from(edge: &FiberExternalEdge) -> AdapterResult<Self> {
        let asset = match &edge.asset {
            FiberEdgeAsset::Ckb { ckb_genesis_hash } => GatewayAsset::Ckb {
                ckb_genesis_hash: decode_byte32(ckb_genesis_hash)?,
            },
            FiberEdgeAsset::Xudt {
                ckb_genesis_hash,
                type_script_hash,
            } => GatewayAsset::Xudt {
                ckb_genesis_hash: decode_byte32(ckb_genesis_hash)?,
                type_script_hash: decode_byte32(type_script_hash)?,
            },
            FiberEdgeAsset::Rgbpp {
                ckb_genesis_hash,
                type_script_hash,
                bitcoin_network,
                binding_code_hash,
            } => GatewayAsset::Rgbpp(morph_core::RgbppAssetId {
                ckb_genesis_hash: decode_byte32(ckb_genesis_hash)?,
                xudt_type_script_hash: decode_byte32(type_script_hash)?,
                bitcoin_network: match bitcoin_network.as_str() {
                    "mainnet" => morph_core::BitcoinNetwork::Mainnet,
                    "testnet" => morph_core::BitcoinNetwork::Testnet,
                    "signet" => morph_core::BitcoinNetwork::Signet,
                    "regtest" => morph_core::BitcoinNetwork::Regtest,
                    _ => return Err(AdapterError::InvalidMorphEdge),
                },
                binding_code_hash: decode_byte32(binding_code_hash)?,
            }),
        };
        let parse_key = |raw: &str| -> AdapterResult<Vec<u8>> {
            if raw.len() != 68 {
                return Err(AdapterError::InvalidMorphEdge);
            }
            let bytes = hex::decode(
                raw.strip_prefix("0x")
                    .ok_or(AdapterError::InvalidMorphEdge)?,
            )
            .map_err(|_| AdapterError::InvalidMorphEdge)?;
            if hex_bytes(&bytes) != raw {
                return Err(AdapterError::InvalidMorphEdge);
            }
            Ok(bytes)
        };
        let amount = |raw: &str| -> AdapterResult<u128> {
            let value = raw
                .parse::<u128>()
                .map_err(|_| AdapterError::InvalidMorphEdge)?;
            if value.to_string() != raw {
                return Err(AdapterError::InvalidMorphEdge);
            }
            Ok(value)
        };
        let result = Self {
            edge_id: decode_byte32(&edge.morph_edge_id)?,
            channel_id: decode_byte32(&edge.channel_id)?,
            funding_context_id: decode_byte32(&edge.funding_context_id)?,
            funding_epoch: edge.funding_epoch,
            state_number: edge.state_number,
            participants: [
                decode_byte32(&edge.morph_participant_ids[0])?,
                decode_byte32(&edge.morph_participant_ids[1])?,
            ],
            participant_pubkeys_sec1: [
                parse_key(&edge.node_ids[0])?,
                parse_key(&edge.node_ids[1])?,
            ],
            asset,
            directional_liquidity: [
                amount(&edge.directional_liquidity[0])?,
                amount(&edge.directional_liquidity[1])?,
            ],
            deployment_id: decode_byte32(&edge.deployment_id)?,
            factory_id: edge.factory_id.as_deref().map(decode_byte32).transpose()?,
            factory_update_number: edge.factory_update_number,
            factory_reservation_id: edge
                .factory_reservation_id
                .as_deref()
                .map(decode_byte32)
                .transpose()?,
            evidence_block_hash: decode_byte32(&edge.evidence_block_hash)?,
            evidence_block_number: edge.evidence_block_number,
            opaque_morph_commitment: decode_byte32(&edge.opaque_morph_commitment)?,
        };
        if result
            .derive_id()
            .map_err(|_| AdapterError::InvalidMorphEdge)?
            != result.edge_id
        {
            return Err(AdapterError::InvalidMorphEdge);
        }
        Ok(result)
    }
}

impl FiberEdgeAsset {
    pub(crate) fn genesis(&self) -> &str {
        match self {
            Self::Ckb { ckb_genesis_hash }
            | Self::Xudt {
                ckb_genesis_hash, ..
            }
            | Self::Rgbpp {
                ckb_genesis_hash, ..
            } => ckb_genesis_hash,
        }
    }

    /// XUDT and RGB++ presentations of one Type never become two capacities.
    pub(crate) fn physical_type(&self) -> Option<&str> {
        match self {
            Self::Ckb { .. } => None,
            Self::Xudt {
                type_script_hash, ..
            }
            | Self::Rgbpp {
                type_script_hash, ..
            } => Some(type_script_hash),
        }
    }
}
