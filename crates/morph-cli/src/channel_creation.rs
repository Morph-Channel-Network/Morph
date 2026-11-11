//! Shared current bilateral creation terms. Root and Factory child creation
//! choose different anchors/provenance, then use one script/custody constructor.
use crate::canonical_fields::{decimal_u64, public};
use crate::multi_asset_packages::decode_hex;
use crate::multi_asset_root_transaction::RootAuthorityHashes;
use anyhow::{Result, anyhow, ensure};
use ckb_types::{core::Capacity, packed, prelude::*};
use morph_core::*;
use morph_script_common::multi_asset as wire;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelCreationTerms {
    pub participants: [String; 2],
    pub participant_locks_hex: [String; 2],
    pub carrier_refund_lock_hex: String,
    pub descriptor_hex: String,
    pub challenge_blocks: String,
    pub type_scripts_hex: Vec<String>,
}
fn script(raw: &str) -> Result<Vec<u8>> {
    let raw = decode_hex(raw, wire::MULTI_ASSET_MAX_SCRIPT_LEN)?;
    packed::Script::from_slice(&raw)?;
    Ok(raw)
}
fn data1(code: &Bytes32, args: &[u8]) -> packed::Script {
    packed::Script::new_builder()
        .code_hash(code.pack())
        .hash_type(2u8)
        .args(args.pack())
        .build()
}
impl ChannelCreationTerms {
    pub(crate) fn build(
        &self,
        chain_id: Bytes32,
        authority: RootAuthorityHashes,
        anchor: Bytes32,
        factory_origin: Option<Bytes32>,
    ) -> Result<MultiAssetRecoveryPackage> {
        let keys = self.participants.each_ref().map(|key| public(key));
        let [first, second] = keys;
        let keys = [first?, second?];
        ensure!(
            keys[0] < keys[1],
            "participants must be distinct and ordered"
        );
        let blocks = decimal_u64(&self.challenge_blocks)?;
        ensure!(blocks > 0, "challenge blocks must be positive");
        let since = morph_script_common::relative_block_since(blocks)
            .map_err(|error| anyhow!("invalid challenge blocks: {error:?}"))?;
        let mut args = anchor.to_vec();
        if let Some(origin) = factory_origin {
            args.extend_from_slice(&origin);
        }
        args.extend_from_slice(&since.to_le_bytes());
        wire::MultiAssetStateTypeArgs::parse(&args)
            .map_err(|error| anyhow!("invalid current State authority: {error:?}"))?;
        let state_type = data1(&authority.state_type, &args);
        let state_lock = data1(
            &authority.state_lock,
            state_type.calc_script_hash().as_slice(),
        );
        let vault_args = wire::encode_multi_asset_vault_args(
            &anchor,
            since,
            &state_type.calc_script_hash().unpack(),
            &state_lock.calc_script_hash().unpack(),
        )
        .map_err(|error| anyhow!("invalid Vault authority: {error:?}"))?;
        let vault_lock = data1(&authority.vault_lock, &vault_args);
        let settlement = MultiAssetSettlement::decode(&decode_hex(
            &self.descriptor_hex,
            wire::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
                + wire::MULTI_ASSET_MAX_VAULTS * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN
                + morph_script_common::multi_asset_conditional::MULTI_ASSET_CONDITIONAL_MAX_LEN,
        )?)?;
        let manifest = settlement.custody_manifest(vault_lock.calc_script_hash().unpack())?;
        ensure!(
            self.type_scripts_hex.len() <= wire::MULTI_ASSET_MAX_VAULTS,
            "too many Type Scripts"
        );
        let type_scripts = self
            .type_scripts_hex
            .iter()
            .map(|raw| -> Result<_> {
                let raw = script(raw)?;
                Ok(MultiAssetTypeScript {
                    type_hash: blake2b256(&raw),
                    script: raw,
                })
            })
            .collect::<Result<_>>()?;
        let state_output = packed::CellOutput::new_builder()
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build();
        let carrier = state_output
            .occupied_capacity(Capacity::bytes(wire::MULTI_ASSET_STATE_HEADER_LEN)?)?
            .as_u64();
        let mut channel = b"CKB_MORPH_CHANNEL_ID".to_vec();
        channel.extend_from_slice(&anchor);
        let mut challenge = b"CKB_MORPH_CHALLENGE_POLICY".to_vec();
        challenge.extend_from_slice(&since.to_le_bytes());
        let creation = MultiAssetRecoveryPackage {
            state: MultiAssetState {
                header: MultiAssetHeader {
                    protocol_version: 1,
                    chain_id,
                    signature_scheme_id: 1,
                    channel_id: blake2b256(&channel),
                    funding_epoch: 0,
                    funding_anchor: anchor,
                    state_number: 0,
                    mode: Mode::BilateralPlain,
                    phase: Phase::Active,
                    participants_commitment: participants_commitment(2, &[&keys[0], &keys[1]]),
                    asset_registry_commitment: asset_registry_commitment(&manifest.registry()?),
                    settlement_descriptor_commitment: settlement.commitment()?,
                    descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
                    challenge_policy_commitment: blake2b256(&challenge),
                    state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
                },
                vault_content_set_root: manifest.commitment()?,
                vault_outpoint_set_root: [0; 32],
                vault_count: manifest.vaults.len() as u16,
            },
            authorization: StateAuthorization {
                threshold: 2,
                signatures: vec![],
            },
            manifest,
            settlement,
            outpoints: vec![],
            state_carrier_capacity: carrier,
            scripts: MultiAssetRecoveryScripts {
                vault_lock: vault_lock.as_slice().to_vec(),
                state_type: state_type.as_slice().to_vec(),
                state_lock: state_lock.as_slice().to_vec(),
                participant_locks: [
                    script(&self.participant_locks_hex[0])?,
                    script(&self.participant_locks_hex[1])?,
                ],
                carrier_refund_lock: script(&self.carrier_refund_lock_hex)?,
                type_scripts,
            },
        };
        creation.validate_contents()?;
        Ok(creation)
    }
}
