//! Canonical public current Factory messages. These codecs reserve no signer
//! authority, perform no RPC and never carry a child's private exit signature.
//! Core owns all protocol validation and participant/delivery verification.
use std::path::Path;

use anyhow::{Result, ensure};
use morph_core::*;
use morph_script_common::factory_multi_asset::FACTORY_MULTI_ASSET_STATE_HEADER_LEN;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::canonical_fields::{decimal_u64, decimal_u128, hash, public};
use crate::multi_asset_packages::{canonical_hex, decode_hex, read_bounded_json};
use crate::persistence::required_option;

pub const CUSTODY_SCHEMA: &str = "morph.factory_custody.v1";
pub const REQUEST_SCHEMA: &str = "morph.factory_request.v1";
pub const SIGNATURE_SCHEMA: &str = "morph.factory_signature.v1";
// Raw body and witness each admit FACTORY_MAX_TRANSACTION_BYTES, rendered as
// hex, plus two bounded custody snapshots and the complete rights snapshot.
pub const MAX_PACKET_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryMemberTerms {
    pub participant: String,
    pub pubkey: String,
}
impl FactoryMemberTerms {
    pub fn decode(&self) -> Result<FactoryParticipantKey> {
        let participant = hash(&self.participant)?;
        ensure!(participant != [0; 32], "zero Factory participant identity");
        Ok(FactoryParticipantKey {
            participant,
            pubkey_sec1: public(&self.pubkey)?,
        })
    }
    pub fn from_core(value: &FactoryParticipantKey) -> Self {
        Self {
            participant: canonical_hex(&value.participant),
            pubkey: canonical_hex(&value.pubkey_sec1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryRightTerms {
    pub participant: String,
    pub subchannel: String,
    pub kind: FactoryRightKind,
    #[serde(deserialize_with = "required_option")]
    pub asset_type: Option<String>,
    pub quantity: String,
}
impl FactoryRightTerms {
    pub fn decode(&self) -> Result<FactoryRight> {
        Ok(FactoryRight {
            id: FactoryRightId {
                participant: hash(&self.participant)?,
                subchannel: hash(&self.subchannel)?,
                kind: self.kind,
                asset_type: self.asset_type.as_deref().map(hash).transpose()?,
            },
            quantity: decimal_u128(&self.quantity)?,
        })
    }
    pub fn from_core(value: &FactoryRight) -> Self {
        Self {
            participant: canonical_hex(&value.id.participant),
            subchannel: canonical_hex(&value.id.subchannel),
            kind: value.id.kind,
            asset_type: value.id.asset_type.as_ref().map(|hash| canonical_hex(hash)),
            quantity: value.quantity.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFactoryPoint {
    pub tx_hash: String,
    pub index: u32,
}
impl StoredFactoryPoint {
    pub fn decode(&self) -> Result<MultiAssetOutPoint> {
        Ok(MultiAssetOutPoint {
            tx_hash: hash(&self.tx_hash)?,
            index: self.index,
        })
    }
    pub fn from_core(value: &MultiAssetOutPoint) -> Self {
        Self {
            tx_hash: canonical_hex(&value.tx_hash),
            index: value.index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFactoryTypeScript {
    pub type_hash: String,
    pub script_hex: String,
}
impl StoredFactoryTypeScript {
    fn decode(&self) -> Result<MultiAssetTypeScript> {
        Ok(MultiAssetTypeScript {
            type_hash: hash(&self.type_hash)?,
            script: decode_hex(&self.script_hex, 512)?,
        })
    }
    fn from_core(value: &MultiAssetTypeScript) -> Self {
        Self {
            type_hash: canonical_hex(&value.type_hash),
            script_hex: canonical_hex(&value.script),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFactoryCustody {
    pub schema: String,
    pub header_hex: String,
    pub state_out_point: StoredFactoryPoint,
    pub manifest_hex: String,
    pub vault_outpoints: Vec<StoredFactoryPoint>,
    pub state_type_hex: String,
    pub state_lock_hex: String,
    pub vault_lock_hex: String,
    pub type_scripts: Vec<StoredFactoryTypeScript>,
    pub state_carrier_capacity: String,
}
impl StoredFactoryCustody {
    pub fn from_core(value: &FactoryCustody) -> Result<Self> {
        value.validate()?;
        Ok(Self {
            schema: CUSTODY_SCHEMA.to_string(),
            header_hex: canonical_hex(&value.header),
            state_out_point: StoredFactoryPoint::from_core(&value.state_out_point),
            manifest_hex: canonical_hex(&value.manifest.encode()?),
            vault_outpoints: value
                .vault_outpoints
                .iter()
                .map(StoredFactoryPoint::from_core)
                .collect(),
            state_type_hex: canonical_hex(&value.state_type),
            state_lock_hex: canonical_hex(&value.state_lock),
            vault_lock_hex: canonical_hex(&value.vault_lock),
            type_scripts: value
                .type_scripts
                .iter()
                .map(StoredFactoryTypeScript::from_core)
                .collect(),
            state_carrier_capacity: value.state_carrier_capacity.to_string(),
        })
    }
    pub fn decode(&self) -> Result<FactoryCustody> {
        ensure!(
            self.schema == CUSTODY_SCHEMA,
            "unsupported current Factory custody schema"
        );
        ensure!(
            (1..=8).contains(&self.vault_outpoints.len()) && self.type_scripts.len() <= 8,
            "Factory custody exceeds count bounds"
        );
        let value = FactoryCustody {
            header: decode_hex(&self.header_hex, FACTORY_MULTI_ASSET_STATE_HEADER_LEN)?,
            state_out_point: self.state_out_point.decode()?,
            manifest: MultiAssetManifest::decode(&decode_hex(&self.manifest_hex, 4 + 8 * 97)?)?,
            vault_outpoints: self
                .vault_outpoints
                .iter()
                .map(StoredFactoryPoint::decode)
                .collect::<Result<_>>()?,
            state_type: decode_hex(&self.state_type_hex, 512)?,
            state_lock: decode_hex(&self.state_lock_hex, 512)?,
            vault_lock: decode_hex(&self.vault_lock_hex, 512)?,
            type_scripts: self
                .type_scripts
                .iter()
                .map(StoredFactoryTypeScript::decode)
                .collect::<Result<_>>()?,
            state_carrier_capacity: decimal_u64(&self.state_carrier_capacity)?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn inspect(&self) -> Result<Value> {
        custody_review(&self.decode()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFactoryDelivery {
    pub child_index: u16,
    pub pubkey: String,
    pub signature: String,
}
impl StoredFactoryDelivery {
    pub fn decode(&self) -> Result<FactoryChildDeliveryReceipt> {
        Ok(FactoryChildDeliveryReceipt {
            child_index: self.child_index,
            pubkey_sec1: public(&self.pubkey)?,
            signature: exact_hex(&self.signature, 64)?,
        })
    }
    pub fn from_core(value: &FactoryChildDeliveryReceipt) -> Self {
        Self {
            child_index: value.child_index,
            pubkey: canonical_hex(&value.pubkey_sec1),
            signature: canonical_hex(&value.signature),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFactoryRequest {
    pub schema: String,
    pub role: FactorySigningRole,
    #[serde(deserialize_with = "required_option")]
    pub source: Option<StoredFactoryCustody>,
    #[serde(deserialize_with = "required_option")]
    pub target: Option<StoredFactoryCustody>,
    pub raw_transaction_hex: String,
    pub witness_hex: String,
    pub target_rights: Vec<FactoryRightTerms>,
    pub deliveries: Vec<StoredFactoryDelivery>,
}
impl StoredFactoryRequest {
    fn encode(value: &FactorySigningRequest) -> Result<Self> {
        Ok(Self {
            schema: REQUEST_SCHEMA.to_string(),
            role: value.role,
            source: value
                .source
                .as_ref()
                .map(StoredFactoryCustody::from_core)
                .transpose()?,
            target: value
                .target
                .as_ref()
                .map(StoredFactoryCustody::from_core)
                .transpose()?,
            raw_transaction_hex: canonical_hex(&value.transaction),
            witness_hex: canonical_hex(&value.witness),
            target_rights: value
                .target_rights
                .iter()
                .map(FactoryRightTerms::from_core)
                .collect(),
            deliveries: value
                .deliveries
                .iter()
                .map(StoredFactoryDelivery::from_core)
                .collect(),
        })
    }
    pub fn from_core(value: &FactorySigningRequest) -> Result<Self> {
        value.validate(&value.members()?)?;
        Self::encode(value)
    }
    pub fn from_delivery_review(value: &FactorySigningRequest) -> Result<Self> {
        value.validate_for_review(&value.members()?)?;
        Self::encode(value)
    }
    fn contents(&self) -> Result<FactorySigningRequest> {
        ensure!(
            self.schema == REQUEST_SCHEMA,
            "unsupported current Factory request schema"
        );
        ensure!(
            self.target_rights.len() <= FACTORY_MAX_RIGHTS_SNAPSHOT && self.deliveries.len() <= 8,
            "Factory request exceeds count bounds"
        );
        Ok(FactorySigningRequest {
            role: self.role,
            source: self
                .source
                .as_ref()
                .map(StoredFactoryCustody::decode)
                .transpose()?,
            target: self
                .target
                .as_ref()
                .map(StoredFactoryCustody::decode)
                .transpose()?,
            transaction: decode_hex(&self.raw_transaction_hex, FACTORY_MAX_TRANSACTION_BYTES)?,
            witness: decode_hex(&self.witness_hex, FACTORY_MAX_TRANSACTION_BYTES)?,
            target_rights: self
                .target_rights
                .iter()
                .map(FactoryRightTerms::decode)
                .collect::<Result<_>>()?,
            deliveries: self
                .deliveries
                .iter()
                .map(StoredFactoryDelivery::decode)
                .collect::<Result<_>>()?,
        })
    }
    pub fn decode(&self) -> Result<FactorySigningRequest> {
        let value = self.contents()?;
        value.validate(&value.members()?)?;
        Ok(value)
    }
    /// Explicit read/delivery preparation only. A signing caller must use
    /// `decode`, whose Core check requires every child delivery attestation.
    pub fn decode_for_delivery_review(&self) -> Result<FactorySigningRequest> {
        let value = self.contents()?;
        value.validate_for_review(&value.members()?)?;
        Ok(value)
    }
    pub fn inspect(&self) -> Result<Value> {
        let value = self.decode_for_delivery_review()?;
        let missing = value
            .missing_delivery_receipts()?
            .into_iter()
            .map(|(child_index, pubkey)| json!({"child_index":child_index,"pubkey":canonical_hex(&pubkey)}))
            .collect::<Vec<_>>();
        Ok(json!({
            "schema":"morph.factory_request_summary.v1",
            "stage":"offline_review",
            "request_id":canonical_hex(&value.request_id()?),
            "signing_digest":canonical_hex(&value.signing_digest()?),
            "role":value.role,
            "transaction_hash":canonical_hex(&value.transaction_hash()?),
            "raw_transaction_bytes":value.transaction.len(),
            "witness_bytes":value.witness.len(),
            "source":value.source.as_ref().map(custody_review).transpose()?,
            "target":value.target.as_ref().map(custody_review).transpose()?,
            "members":value.members()?.iter().map(FactoryMemberTerms::from_core).collect::<Vec<_>>(),
            "required_members":value.required_members()?.iter().map(FactoryMemberTerms::from_core).collect::<Vec<_>>(),
            "requires_activation":value.requires_activation()?,
            "target_rights":self.target_rights,
            "delivery_count":value.deliveries.len(),
            "missing_deliveries":missing,
            "constraints":{
                "canonical_source":"native_check_required",
                "approved_dependencies":"native_check_required",
                "vm_preflight":"native_check_required",
                "monotonic_signer_reservation":"required_before_key_use"
            }
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorySignatureReceipt {
    pub schema: String,
    pub request_id: String,
    pub signing_digest: String,
    pub participant: String,
    pub pubkey: String,
    pub signature: String,
}
impl FactorySignatureReceipt {
    #[cfg(any(feature = "devnet", test))]
    pub fn new(
        request: &FactorySigningRequest,
        signature: &FactoryParticipantSignature,
    ) -> Result<Self> {
        request.validate(&request.members()?)?;
        request.verify_participant_signature(signature)?;
        Ok(Self {
            schema: SIGNATURE_SCHEMA.to_string(),
            request_id: canonical_hex(&request.request_id()?),
            signing_digest: canonical_hex(&request.signing_digest()?),
            participant: canonical_hex(&signature.participant),
            pubkey: canonical_hex(&signature.pubkey_sec1),
            signature: canonical_hex(&signature.signature),
        })
    }
    pub fn verify(&self, request: &FactorySigningRequest) -> Result<FactoryParticipantSignature> {
        request.validate(&request.members()?)?;
        ensure!(
            self.schema == SIGNATURE_SCHEMA
                && self.request_id == canonical_hex(&request.request_id()?)
                && self.signing_digest == canonical_hex(&request.signing_digest()?),
            "Factory receipt is for another exact request or signing role"
        );
        let signature = FactoryParticipantSignature {
            participant: hash(&self.participant)?,
            pubkey_sec1: public(&self.pubkey)?,
            signature: exact_hex(&self.signature, 64)?,
        };
        request.verify_participant_signature(&signature)?;
        Ok(signature)
    }
}

pub fn exact_hex(raw: &str, length: usize) -> Result<Vec<u8>> {
    let bytes = decode_hex(raw, length)?;
    ensure!(
        bytes.len() == length,
        "Factory field must contain exactly {length} bytes"
    );
    Ok(bytes)
}
pub fn custody_review(value: &FactoryCustody) -> Result<Value> {
    value.validate()?;
    let header = value.state()?;
    let assets = value.manifest.vaults.iter().map(|vault| json!({
        "type_hash":match vault.asset { VaultAsset::Ckb=>None, VaultAsset::Xudt(hash)=>Some(canonical_hex(&hash)) },
        "reserve":vault.value.reserve.to_string(),
        "business_ckb":vault.value.business_ckb.to_string(),
        "amount":vault.value.amount.to_string()
    })).collect::<Vec<_>>();
    Ok(json!({
        "factory_id":canonical_hex(header.factory_id()),
        "chain_id":canonical_hex(header.chain_id()),
        "update_number":header.update_number().to_string(),
        "state_out_point":StoredFactoryPoint::from_core(&value.state_out_point),
        "content_root":canonical_hex(header.content_root()),
        "outpoint_root":canonical_hex(header.outpoint_root()),
        "state_carrier_capacity":value.state_carrier_capacity.to_string(),
        "vault_count":value.manifest.vaults.len(),
        "assets":assets
    }))
}

pub fn read_request(path: &Path) -> Result<StoredFactoryRequest> {
    let value: StoredFactoryRequest = read_bounded_json(path, MAX_PACKET_BYTES)?;
    value.decode()?;
    Ok(value)
}
pub fn read_for_delivery_review(path: &Path) -> Result<StoredFactoryRequest> {
    let value: StoredFactoryRequest = read_bounded_json(path, MAX_PACKET_BYTES)?;
    value.decode_for_delivery_review()?;
    Ok(value)
}
pub fn read_custody(path: &Path) -> Result<StoredFactoryCustody> {
    let value: StoredFactoryCustody = read_bounded_json(path, 256 * 1024)?;
    value.decode()?;
    Ok(value)
}
