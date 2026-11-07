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

pub(crate) const CUSTODY_SCHEMA: &str = "morph.factory_custody.v1";
pub(crate) const REQUEST_SCHEMA: &str = "morph.factory_request.v1";
pub(crate) const SIGNATURE_SCHEMA: &str = "morph.factory_signature.v1";
// Raw body and witness each admit FACTORY_MAX_TRANSACTION_BYTES, rendered as
// hex, plus two bounded custody snapshots and the complete rights snapshot.
pub(crate) const MAX_PACKET_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryMemberTerms {
    pub participant: String,
    pub pubkey: String,
}
impl FactoryMemberTerms {
    pub(crate) fn decode(&self) -> Result<FactoryParticipantKey> {
        let participant = hash(&self.participant)?;
        ensure!(participant != [0; 32], "zero Factory participant identity");
        Ok(FactoryParticipantKey {
            participant,
            pubkey_sec1: public(&self.pubkey)?,
        })
    }
    pub(crate) fn from_core(value: &FactoryParticipantKey) -> Self {
        Self {
            participant: canonical_hex(&value.participant),
            pubkey: canonical_hex(&value.pubkey_sec1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryRightTerms {
    pub participant: String,
    pub subchannel: String,
    pub kind: FactoryRightKind,
    #[serde(deserialize_with = "required_option")]
    pub asset_type: Option<String>,
    pub quantity: String,
}
impl FactoryRightTerms {
    pub(crate) fn decode(&self) -> Result<FactoryRight> {
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
    pub(crate) fn from_core(value: &FactoryRight) -> Self {
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
pub(crate) struct StoredFactoryPoint {
    pub tx_hash: String,
    pub index: u32,
}
impl StoredFactoryPoint {
    pub(crate) fn decode(&self) -> Result<MultiAssetOutPoint> {
        Ok(MultiAssetOutPoint {
            tx_hash: hash(&self.tx_hash)?,
            index: self.index,
        })
    }
    pub(crate) fn from_core(value: &MultiAssetOutPoint) -> Self {
        Self {
            tx_hash: canonical_hex(&value.tx_hash),
            index: value.index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredFactoryTypeScript {
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
pub(crate) struct StoredFactoryCustody {
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
    pub(crate) fn from_core(value: &FactoryCustody) -> Result<Self> {
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
    pub(crate) fn decode(&self) -> Result<FactoryCustody> {
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
    pub(crate) fn inspect(&self) -> Result<Value> {
        custody_review(&self.decode()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredFactoryDelivery {
    pub child_index: u16,
    pub pubkey: String,
    pub signature: String,
}
impl StoredFactoryDelivery {
    pub(crate) fn decode(&self) -> Result<FactoryChildDeliveryReceipt> {
        Ok(FactoryChildDeliveryReceipt {
            child_index: self.child_index,
            pubkey_sec1: public(&self.pubkey)?,
            signature: exact_hex(&self.signature, 64)?,
        })
    }
    pub(crate) fn from_core(value: &FactoryChildDeliveryReceipt) -> Self {
        Self {
            child_index: value.child_index,
            pubkey: canonical_hex(&value.pubkey_sec1),
            signature: canonical_hex(&value.signature),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredFactoryRequest {
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
    pub(crate) fn from_core(value: &FactorySigningRequest) -> Result<Self> {
        value.validate(&value.members()?)?;
        Self::encode(value)
    }
    pub(crate) fn from_delivery_review(value: &FactorySigningRequest) -> Result<Self> {
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
    pub(crate) fn decode(&self) -> Result<FactorySigningRequest> {
        let value = self.contents()?;
        value.validate(&value.members()?)?;
        Ok(value)
    }
    /// Explicit read/delivery preparation only. A signing caller must use
    /// `decode`, whose Core check requires every child delivery attestation.
    pub(crate) fn decode_for_delivery_review(&self) -> Result<FactorySigningRequest> {
        let value = self.contents()?;
        value.validate_for_review(&value.members()?)?;
        Ok(value)
    }
    pub(crate) fn inspect(&self) -> Result<Value> {
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
pub(crate) struct FactorySignatureReceipt {
    pub schema: String,
    pub request_id: String,
    pub signing_digest: String,
    pub participant: String,
    pub pubkey: String,
    pub signature: String,
}
impl FactorySignatureReceipt {
    #[cfg(any(feature = "devnet", test))]
    pub(crate) fn new(
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
    pub(crate) fn verify(
        &self,
        request: &FactorySigningRequest,
    ) -> Result<FactoryParticipantSignature> {
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

fn exact_hex(raw: &str, length: usize) -> Result<Vec<u8>> {
    let bytes = decode_hex(raw, length)?;
    ensure!(
        bytes.len() == length,
        "Factory field must contain exactly {length} bytes"
    );
    Ok(bytes)
}
fn custody_review(value: &FactoryCustody) -> Result<Value> {
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

pub(crate) fn read_request(path: &Path) -> Result<StoredFactoryRequest> {
    let value: StoredFactoryRequest = read_bounded_json(path, MAX_PACKET_BYTES)?;
    value.decode()?;
    Ok(value)
}
pub(crate) fn read_for_delivery_review(path: &Path) -> Result<StoredFactoryRequest> {
    let value: StoredFactoryRequest = read_bounded_json(path, MAX_PACKET_BYTES)?;
    value.decode_for_delivery_review()?;
    Ok(value)
}
pub(crate) fn read_custody(path: &Path) -> Result<StoredFactoryCustody> {
    let value: StoredFactoryCustody = read_bounded_json(path, 256 * 1024)?;
    value.decode()?;
    Ok(value)
}

#[cfg(test)]
pub(crate) fn sdk_packet_fixture() -> Value {
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    fn case(name: &str, request: &FactorySigningRequest) -> Value {
        let packet = StoredFactoryRequest::from_delivery_review(request).unwrap();
        let signatures = if request.missing_delivery_receipts().unwrap().is_empty() {
            request
                .required_members()
                .unwrap()
                .iter()
                .map(|member| {
                    let key = (1u8..=2)
                        .map(|seed| SigningKey::from_slice(&[seed; 32]).unwrap())
                        .find(|key| {
                            key.verifying_key().to_sec1_point(true).as_bytes() == member.pubkey_sec1
                        })
                        .unwrap();
                    let signature: Signature = key
                        .sign_prehash(&request.signing_digest().unwrap())
                        .unwrap();
                    FactorySignatureReceipt::new(
                        request,
                        &FactoryParticipantSignature {
                            participant: member.participant,
                            pubkey_sec1: member.pubkey_sec1.clone(),
                            signature: signature.to_bytes().to_vec(),
                        },
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        json!({"name":name,"request":packet,"summary":packet.inspect().unwrap(),"signatures":signatures})
    }
    let root: FactorySigningRequest = serde_json::from_value(
        crate::factory_root_transaction::tests::signer_fixture()["request"].clone(),
    )
    .unwrap();
    let (mut child, _, _, private) = crate::factory_journal_fixture::reduced_child_request();
    let missing = case("reduced_child_missing_delivery", &child);
    child.deliveries.push(
        FactoryChildDeliveryReceipt::new_signed(
            &child,
            0,
            &private[0],
            &SigningKey::from_slice(&[1; 32]).unwrap(),
        )
        .unwrap(),
    );
    let partial = case("reduced_child_partial_delivery", &child);
    child.deliveries.push(
        FactoryChildDeliveryReceipt::new_signed(
            &child,
            0,
            &private[0],
            &SigningKey::from_slice(&[2; 32]).unwrap(),
        )
        .unwrap(),
    );
    json!({"schema":"morph.factory_packet_test_cases.v1","provenance":"Synthetic current native Root and CKB-VM-qualified ReducedChild terms; no chain deployment or private child recovery signatures.",
        "cases":[case("root_funding",&root),missing,partial,case("reduced_child_delivered",&child)]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

    fn request() -> FactorySigningRequest {
        serde_json::from_value(
            crate::factory_root_transaction::tests::signer_fixture()["request"].clone(),
        )
        .unwrap()
    }

    #[test]
    fn factory_public_request_and_custody_roundtrip_exact_current_root() {
        let request = request();
        let packet = StoredFactoryRequest::from_core(&request).unwrap();
        let json = serde_json::to_value(&packet).unwrap();
        assert_eq!(json["source"], Value::Null);
        assert_eq!(json["target"]["state_carrier_capacity"], "50000000000");
        assert_eq!(json["target_rights"][0]["quantity"], "13000000000");
        let decoded: StoredFactoryRequest = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.decode().unwrap(), request);
        assert_eq!(decoded.decode_for_delivery_review().unwrap(), request);
        let summary = decoded.inspect().unwrap();
        assert_eq!(summary["stage"], "offline_review");
        assert_eq!(summary["missing_deliveries"], json!([]));
        assert_eq!(summary["required_members"].as_array().unwrap().len(), 2);
        assert_eq!(
            summary["target"]["assets"][0]["business_ckb"],
            "10000000000"
        );
        assert_eq!(
            summary["constraints"]["canonical_source"],
            "native_check_required"
        );
        let target = request.target.as_ref().unwrap();
        assert_eq!(
            StoredFactoryCustody::from_core(target)
                .unwrap()
                .decode()
                .unwrap(),
            *target
        );
        let subject = ValueSubject::from_factory_request(&request).unwrap();
        assert_eq!(subject.ckb_capacity, 90_000_000_000);
        assert!(subject.xudt_amounts.is_empty());
        let path = std::env::temp_dir().join(format!(
            "morph-public-factory-packet-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, serde_json::to_vec(&packet).unwrap()).unwrap();
        assert_eq!(read_request(&path).unwrap(), packet);
        assert_eq!(read_for_delivery_review(&path).unwrap(), packet);
        let (schema, policy_subject) =
            crate::value_limit::extract_value_subject(&path, None).unwrap();
        assert_eq!(schema, REQUEST_SCHEMA);
        assert_eq!(policy_subject, subject);
        std::fs::write(
            &path,
            serde_json::to_vec(packet.target.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_custody(&path).unwrap().inspect().unwrap(),
            summary["target"]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn factory_public_review_requires_verified_delivery_before_strict_signing_decode() {
        let fixture = sdk_packet_fixture();
        for case in fixture["cases"].as_array().unwrap() {
            let packet: StoredFactoryRequest =
                serde_json::from_value(case["request"].clone()).unwrap();
            let request = packet.decode_for_delivery_review().unwrap();
            let missing = request.missing_delivery_receipts().unwrap();
            assert_eq!(packet.decode().is_ok(), missing.is_empty());
            assert_eq!(packet.inspect().unwrap(), case["summary"]);
            if packet.role == FactorySigningRole::Transition {
                assert_eq!(
                    ValueSubject::from_factory_request(&request)
                        .unwrap()
                        .ckb_capacity,
                    400_000_000_000
                );
            }
            let public = serde_json::to_string(&packet).unwrap();
            assert!(!public.contains("signature_witness_hex"));
            assert!(!public.contains("recovery_package"));
            if !packet.deliveries.is_empty() {
                let mut wrong = packet.clone();
                wrong.deliveries[0].signature = canonical_hex(&[0; 64]);
                assert!(wrong.decode_for_delivery_review().is_err());
                let mut duplicate = packet.clone();
                duplicate.deliveries.push(duplicate.deliveries[0].clone());
                assert!(duplicate.decode_for_delivery_review().is_err());
            }
        }
    }

    #[test]
    fn factory_public_schema_rejects_missing_nulls_unknown_fields_and_noncanonical_values() {
        let packet = StoredFactoryRequest::from_core(&request()).unwrap();
        for field in ["source", "target", "deliveries", "target_rights"] {
            let mut value = serde_json::to_value(&packet).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<StoredFactoryRequest>(value).is_err(),
                "{field}"
            );
        }
        let mut unknown = serde_json::to_value(&packet).unwrap();
        unknown["old_factory"] = json!({});
        assert!(serde_json::from_value::<StoredFactoryRequest>(unknown).is_err());
        let mut numeric = serde_json::to_value(&packet).unwrap();
        numeric["target_rights"][0]["quantity"] = json!(13_000_000_000u64);
        assert!(serde_json::from_value::<StoredFactoryRequest>(numeric).is_err());
        let mut missing_asset = serde_json::to_value(&packet).unwrap();
        missing_asset["target_rights"][0]
            .as_object_mut()
            .unwrap()
            .remove("asset_type");
        assert!(serde_json::from_value::<StoredFactoryRequest>(missing_asset).is_err());
        let mut wrong = packet.clone();
        wrong.schema = "morph.factory_request.v0".to_string();
        assert!(wrong.decode().is_err());
        let mut wrong = packet.clone();
        wrong
            .target
            .as_mut()
            .unwrap()
            .state_carrier_capacity
            .insert(0, '0');
        assert!(wrong.decode().is_err());
        let mut wrong = packet.clone();
        wrong.raw_transaction_hex = wrong.raw_transaction_hex.to_uppercase();
        assert!(wrong.decode().is_err());
        let mut wrong = packet.clone();
        wrong.role = FactorySigningRole::MetadataUpdate;
        assert!(wrong.decode().is_err());
        let mut wrong = packet.clone();
        wrong.target.as_mut().unwrap().state_carrier_capacity = "50000000001".to_string();
        assert!(wrong.decode().is_err());
    }

    #[test]
    fn factory_public_right_quantity_preserves_full_u128_without_json_numbers() {
        let right = FactoryRight {
            id: FactoryRightId {
                participant: [1; 32],
                subchannel: [2; 32],
                kind: FactoryRightKind::Balance,
                asset_type: Some([3; 32]),
            },
            quantity: u128::MAX,
        };
        let dto = FactoryRightTerms::from_core(&right);
        assert_eq!(
            serde_json::to_value(&dto).unwrap()["quantity"],
            u128::MAX.to_string()
        );
        assert_eq!(dto.decode().unwrap(), right);
        for quantity in ["00", "+1", "-1", "340282366920938463463374607431768211456"] {
            let mut invalid = dto.clone();
            invalid.quantity = quantity.to_string();
            assert!(invalid.decode().is_err());
        }
    }

    #[test]
    fn factory_request_policy_rejects_unlisted_future_type_even_with_zero_claims() {
        let (mut terms, authority, cells) = crate::factory_root_transaction::tests::fixture();
        let mut future = terms.rights[0].clone();
        future.asset_type = Some(canonical_hex(&[77; 32]));
        future.quantity = "0".to_string();
        terms.rights.push(future);
        terms
            .rights
            .sort_by(|left, right| left.decode().unwrap().id.cmp(&right.decode().unwrap().id));
        let prepared = terms
            .build([41; 32], authority, &cells, 100_000_000)
            .unwrap();
        let request = prepared.signing_request().unwrap();
        let packet = StoredFactoryRequest::from_core(&request).unwrap();
        assert_eq!(packet.decode().unwrap(), request);
        let subject = ValueSubject::from_factory_request(&request).unwrap();
        assert_eq!(subject.ckb_capacity, 90_000_000_000);
        let asset = canonical_hex(&[77; 32]);
        assert_eq!(subject.xudt_amounts.get(&asset), Some(&0));
        let mut policy = ValueLimitPolicy {
            schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
            created_unix_ms: 1,
            max_channel_ckb_capacity: 90_000_000_000,
            max_xudt_amounts: Default::default(),
        };
        assert!(matches!(
            policy.enforce(&subject),
            Err(ValueLimitError::UnlistedXudt { .. })
        ));
        policy.max_xudt_amounts.insert(asset, 1);
        policy.enforce(&subject).unwrap();
        let mut invalid = request;
        invalid.target_rights[0].quantity += 1;
        assert!(ValueSubject::from_factory_request(&invalid).is_err());
    }

    #[test]
    fn factory_public_signature_receipt_is_bound_to_exact_request_role_and_member() {
        let request = request();
        let key = SigningKey::from_slice(&[1; 32]).unwrap();
        let signature: Signature = key
            .sign_prehash(&request.signing_digest().unwrap())
            .unwrap();
        let authorization = FactoryParticipantSignature {
            participant: [1; 32],
            pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        };
        let receipt = FactorySignatureReceipt::new(&request, &authorization).unwrap();
        assert_eq!(receipt.verify(&request).unwrap(), authorization);
        for field in [
            "request_id",
            "signing_digest",
            "participant",
            "pubkey",
            "signature",
            "schema",
        ] {
            let mut value = serde_json::to_value(&receipt).unwrap();
            value[field] = json!("0x00");
            let damaged: FactorySignatureReceipt = serde_json::from_value(value).unwrap();
            assert!(damaged.verify(&request).is_err(), "{field}");
        }
        let mut changed = request.clone();
        changed.role = FactorySigningRole::MetadataUpdate;
        assert!(receipt.verify(&changed).is_err());
        let mut hidden = StoredFactoryRequest::from_core(&request).unwrap();
        // Parent authority must be detached. Filling any slot inside a request
        // would bypass the journal's explicit reserve-before-sign boundary.
        let mut witness = decode_hex(&hidden.witness_hex, FACTORY_MAX_TRANSACTION_BYTES).unwrap();
        *witness.last_mut().unwrap() = 1;
        hidden.witness_hex = canonical_hex(&witness);
        assert!(hidden.decode().is_err());
        let mut fake_delivery = StoredFactoryRequest::from_core(&request).unwrap();
        fake_delivery.deliveries.push(StoredFactoryDelivery {
            child_index: 0,
            pubkey: receipt.pubkey,
            signature: receipt.signature,
        });
        assert!(fake_delivery.decode_for_delivery_review().is_err());
        assert!(fake_delivery.decode().is_err());
    }
}
