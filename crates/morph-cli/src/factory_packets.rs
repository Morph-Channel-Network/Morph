//! CLI entry points and baseline regression tests reuse the sole public Rust package implementation.
#[allow(unused_imports)]
pub use morph_packages::factory_packets::*;

#[cfg(test)]
#[allow(unused_imports)]
use std::path::Path;

#[cfg(test)]
#[allow(unused_imports)]
use anyhow::{Result, ensure};

#[cfg(test)]
#[allow(unused_imports)]
use morph_core::*;

#[cfg(test)]
#[allow(unused_imports)]
use morph_script_common::factory_multi_asset::FACTORY_MULTI_ASSET_STATE_HEADER_LEN;

#[cfg(test)]
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[allow(unused_imports)]
use serde_json::{Value, json};

#[cfg(test)]
#[allow(unused_imports)]
use crate::canonical_fields::{decimal_u64, decimal_u128, hash, public};

#[cfg(test)]
#[allow(unused_imports)]
use crate::multi_asset_packages::{canonical_hex, decode_hex, read_bounded_json};

#[cfg(test)]
#[allow(unused_imports)]
use crate::persistence::required_option;

#[cfg(test)]
pub(crate) fn packet_fixture() -> Value {
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
        let fixture = packet_fixture();
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
