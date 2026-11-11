//! Public JSON adapters for Core intent/receipt objects. They change transport
//! representation only. Core's binary IDs, signing digests and validators are
//! authoritative and are not derived from these JSON representations.
use morph_core::{
    BackendSettlementEvidence, BitcoinNetwork, Bytes32, CkbOutPoint, CkbSettlementAnchor,
    GatewayAsset, HttpOperation, MorphChannelPaymentBinding, MorphStateSettlementEvidence,
    PaymentHashAlgorithm, PaymentIntent, RgbppAssetId, TerminalPaymentStatus,
    TerminalSettlementReceipt,
};
use morph_packages::public_encoding::{amount, decimal};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "BitcoinNetwork", rename_all = "snake_case")]
pub enum BitcoinNetworkWire {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "PaymentHashAlgorithm", rename_all = "snake_case")]
pub enum PaymentHashAlgorithmWire {
    CkbBlake2b,
    Sha256,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "HttpOperation", rename_all = "snake_case")]
pub enum HttpOperationWire {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "TerminalPaymentStatus", rename_all = "snake_case")]
pub enum TerminalPaymentStatusWire {
    Settled,
    Cancelled,
    Expired,
    Failed,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "RgbppAssetId", deny_unknown_fields)]
pub struct RgbppAssetIdWire {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub ckb_genesis_hash: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub xudt_type_script_hash: Bytes32,
    #[serde(with = "BitcoinNetworkWire")]
    #[schemars(with = "BitcoinNetworkWire")]
    pub bitcoin_network: BitcoinNetwork,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub binding_code_hash: Bytes32,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "MorphChannelPaymentBinding", deny_unknown_fields)]
pub struct MorphChannelPaymentBindingWire {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub channel_id: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub funding_context_id: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub expected_settlement_descriptor_commitment: Bytes32,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "PaymentIntent", deny_unknown_fields)]
pub struct PaymentIntentWire {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub intent_id: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub payer: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub payee: Bytes32,
    #[serde(with = "GatewayAssetWire")]
    #[schemars(with = "GatewayAssetWire")]
    pub asset: GatewayAsset,
    #[serde(with = "amount")]
    #[schemars(schema_with = "amount::schema")]
    pub amount: u128,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub payment_hash: Bytes32,
    #[serde(with = "PaymentHashAlgorithmWire")]
    #[schemars(with = "PaymentHashAlgorithmWire")]
    pub hash_algorithm: PaymentHashAlgorithm,
    pub resource: String,
    #[serde(with = "HttpOperationWire")]
    #[schemars(with = "HttpOperationWire")]
    pub operation: HttpOperation,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub nonce: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub idempotency_key: Bytes32,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub created_at_unix: u64,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub expires_at_unix: u64,
    #[serde(with = "optional_hex32")]
    #[schemars(schema_with = "optional_hex32::schema")]
    pub required_rgbpp_proof_commitment: Option<Bytes32>,
    #[serde(with = "optional_binding")]
    #[schemars(with = "Option<MorphChannelPaymentBindingWire>", required)]
    pub channel_binding: Option<MorphChannelPaymentBinding>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "MorphStateSettlementEvidence", deny_unknown_fields)]
pub struct MorphStateSettlementEvidenceWire {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub channel_id: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub funding_context_id: Bytes32,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub state_number: u64,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub state_header_commitment: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub settlement_descriptor_commitment: Bytes32,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "CkbOutPoint", deny_unknown_fields)]
pub struct CkbOutPointWire {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub tx_hash: Bytes32,
    pub index: u32,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "CkbSettlementAnchor", deny_unknown_fields)]
pub struct CkbSettlementAnchorWire {
    #[serde(with = "CkbOutPointWire")]
    #[schemars(with = "CkbOutPointWire")]
    pub transaction: CkbOutPoint,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub block_hash: Bytes32,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub block_number: u64,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub confirmations: u64,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "BackendSettlementEvidence", deny_unknown_fields)]
pub struct BackendSettlementEvidenceWire {
    pub provider_id: String,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub settlement_id: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub opaque_commitment: Bytes32,
    #[serde(with = "optional_state")]
    #[schemars(with = "Option<MorphStateSettlementEvidenceWire>", required)]
    pub morph_state: Option<MorphStateSettlementEvidence>,
    #[serde(with = "optional_anchor")]
    #[schemars(with = "Option<CkbSettlementAnchorWire>", required)]
    pub ckb_anchor: Option<CkbSettlementAnchor>,
    #[serde(with = "optional_hex32")]
    #[schemars(schema_with = "optional_hex32::schema")]
    pub rgbpp_proof_commitment: Option<Bytes32>,
    pub failure_code: Option<String>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(remote = "TerminalSettlementReceipt", deny_unknown_fields)]
pub struct TerminalSettlementReceiptWire {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub receipt_id: Bytes32,
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub intent_id: Bytes32,
    #[serde(with = "TerminalPaymentStatusWire")]
    #[schemars(with = "TerminalPaymentStatusWire")]
    pub status: TerminalPaymentStatus,
    #[serde(with = "BackendSettlementEvidenceWire")]
    #[schemars(with = "BackendSettlementEvidenceWire")]
    pub evidence: BackendSettlementEvidence,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub finalised_at_unix: u64,
    #[serde(with = "pubkey")]
    #[schemars(schema_with = "pubkey::schema")]
    pub signer_pubkey_sec1: Vec<u8>,
    pub signature_scheme_id: u16,
    #[serde(with = "signature")]
    #[schemars(schema_with = "signature::schema")]
    pub signature: Vec<u8>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    remote = "GatewayAsset",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GatewayAssetWire {
    Ckb {
        #[serde(with = "hex32")]
        #[schemars(schema_with = "hex32::schema")]
        ckb_genesis_hash: Bytes32,
    },
    Xudt {
        #[serde(with = "hex32")]
        #[schemars(schema_with = "hex32::schema")]
        ckb_genesis_hash: Bytes32,
        #[serde(with = "hex32")]
        #[schemars(schema_with = "hex32::schema")]
        type_script_hash: Bytes32,
    },
    Rgbpp(
        #[serde(with = "RgbppAssetIdWire")]
        #[schemars(with = "RgbppAssetIdWire")]
        RgbppAssetId,
    ),
}
macro_rules! optional_remote {
    ($module:ident,$core:ident,$wire:literal) => {
        pub mod $module {
            use super::*;
            #[derive(Serialize, Deserialize)]
            struct Wrapped(#[serde(with=$wire)] $core);
            pub fn serialize<S: serde::Serializer>(
                value: &Option<$core>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                value.clone().map(Wrapped).serialize(s)
            }
            pub fn deserialize<'de, D: serde::Deserializer<'de>>(
                d: D,
            ) -> Result<Option<$core>, D::Error> {
                Option::<Wrapped>::deserialize(d).map(|value| value.map(|v| v.0))
            }
        }
    };
}
optional_remote!(
    optional_bitcoin_network,
    BitcoinNetwork,
    "BitcoinNetworkWire"
);
optional_remote!(
    optional_binding,
    MorphChannelPaymentBinding,
    "MorphChannelPaymentBindingWire"
);
optional_remote!(
    optional_state,
    MorphStateSettlementEvidence,
    "MorphStateSettlementEvidenceWire"
);
optional_remote!(
    optional_anchor,
    CkbSettlementAnchor,
    "CkbSettlementAnchorWire"
);

fn decode_hex<const N: usize, E: serde::de::Error>(raw: String) -> Result<[u8; N], E> {
    if raw.len() != 2 + N * 2
        || !raw.starts_with("0x")
        || !raw.as_bytes()[2..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(E::custom(
            "expected canonical fixed-length lowercase hexadecimal",
        ));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(&raw[2..], &mut bytes).map_err(|_| E::custom("invalid hexadecimal"))?;
    Ok(bytes)
}
fn hex_schema(bytes: usize) -> schemars::Schema {
    schemars::json_schema!({"type":"string","minLength":2+bytes*2,"maxLength":2+bytes*2,
        "pattern":format!("^0x[0-9a-f]{{{}}}$",bytes*2)})
}
pub mod hex32 {
    use super::*;
    pub fn serialize<S: serde::Serializer>(v: &Bytes32, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(v)))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Bytes32, D::Error> {
        decode_hex(String::deserialize(d)?)
    }
    pub fn schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        hex_schema(32)
    }
}
pub mod optional_hex32 {
    use super::*;
    pub fn serialize<S: serde::Serializer>(v: &Option<Bytes32>, s: S) -> Result<S::Ok, S::Error> {
        v.map(|b| format!("0x{}", hex::encode(b))).serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Bytes32>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(decode_hex)
            .transpose()
    }
    pub fn schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"anyOf":[hex_schema(32),{"type":"null"}]})
    }
}
macro_rules! fixed_vector {
    ($module:ident,$length:literal) => {
        pub mod $module {
            use super::*;
            pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
                if v.len() != $length {
                    return Err(serde::ser::Error::custom(
                        "invalid public signature material length",
                    ));
                }
                s.serialize_str(&format!("0x{}", hex::encode(v)))
            }
            pub fn deserialize<'de, D: serde::Deserializer<'de>>(
                d: D,
            ) -> Result<Vec<u8>, D::Error> {
                decode_hex::<$length, D::Error>(String::deserialize(d)?).map(Vec::from)
            }
            pub fn schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                hex_schema($length)
            }
        }
    };
}
fixed_vector!(pubkey, 33);
fixed_vector!(signature, 64);

/// Exact CKB Script transport; display metadata and unknown keys are rejected.
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicScript {
    #[serde(with = "hex32")]
    #[schemars(schema_with = "hex32::schema")]
    pub code_hash: Bytes32,
    #[schemars(schema_with = "script_hash_type_schema")]
    pub hash_type: ckb_jsonrpc_types::ScriptHashType,
    pub args: String,
}
fn script_hash_type_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    // The pinned CKB RPC type has data/type and VM data1..data127 encodings.
    let names = std::iter::once("data".to_owned())
        .chain(std::iter::once("type".to_owned()))
        .chain((1..=127).map(|n| format!("data{n}")))
        .collect::<Vec<_>>();
    schemars::json_schema!({"type":"string","enum":names})
}
impl PublicScript {
    pub fn validate(&self) -> bool {
        self.args.starts_with("0x")
            && self.args.len().is_multiple_of(2)
            && self.args.as_bytes()[2..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    }
}
pub mod optional_script {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        v: &Option<serde_json::Value>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let script = v
            .clone()
            .map(serde_json::from_value::<PublicScript>)
            .transpose()
            .map_err(serde::ser::Error::custom)?;
        if script.as_ref().is_some_and(|v| !v.validate()) {
            return Err(serde::ser::Error::custom("invalid canonical Script args"));
        }
        script.serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<serde_json::Value>, D::Error> {
        let script = Option::<PublicScript>::deserialize(d)?;
        if script.as_ref().is_some_and(|v| !v.validate()) {
            return Err(serde::de::Error::custom("invalid canonical Script args"));
        }
        script
            .map(|v| {
                let mut value = serde_json::to_value(v).map_err(serde::de::Error::custom)?;
                value.sort_all_objects();
                Ok(value)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use serde_json::json;
    #[derive(Serialize, Deserialize)]
    struct SignedTransport {
        #[serde(with = "PaymentIntentWire")]
        intent: PaymentIntent,
        #[serde(with = "TerminalSettlementReceiptWire")]
        receipt: TerminalSettlementReceipt,
    }
    #[test]
    fn public_receipts_preserve_core_commitments_and_cover_every_asset_and_anchor() {
        let signer = SigningKey::from_slice(&[7; 32]).unwrap();
        let pubkey = signer.verifying_key().to_sec1_point(true);
        for asset in [
            GatewayAsset::Ckb {
                ckb_genesis_hash: [1; 32],
            },
            GatewayAsset::Xudt {
                ckb_genesis_hash: [1; 32],
                type_script_hash: [2; 32],
            },
            GatewayAsset::Rgbpp(RgbppAssetId {
                ckb_genesis_hash: [1; 32],
                xudt_type_script_hash: [2; 32],
                bitcoin_network: BitcoinNetwork::Regtest,
                binding_code_hash: [3; 32],
            }),
        ] {
            let proof = matches!(asset, GatewayAsset::Rgbpp(_)).then_some([4; 32]);
            let amount = if matches!(asset, GatewayAsset::Ckb { .. }) {
                u128::from(u64::MAX)
            } else {
                u128::MAX
            };
            let mut intent = PaymentIntent {
                intent_id: [0; 32],
                payer: [5; 32],
                payee: [6; 32],
                asset,
                amount,
                payment_hash: [8; 32],
                hash_algorithm: PaymentHashAlgorithm::Sha256,
                resource: "/paid".into(),
                operation: HttpOperation::Get,
                nonce: [9; 32],
                idempotency_key: [10; 32],
                created_at_unix: 1,
                expires_at_unix: u64::MAX,
                required_rgbpp_proof_commitment: proof,
                channel_binding: Some(MorphChannelPaymentBinding {
                    channel_id: [11; 32],
                    funding_context_id: [12; 32],
                    expected_settlement_descriptor_commitment: [13; 32],
                }),
            };
            intent.intent_id = intent.derive_id().unwrap();
            let evidence = BackendSettlementEvidence {
                provider_id: "test-provider".into(),
                settlement_id: [14; 32],
                opaque_commitment: [15; 32],
                morph_state: Some(MorphStateSettlementEvidence {
                    channel_id: [11; 32],
                    funding_context_id: [12; 32],
                    state_number: u64::MAX,
                    state_header_commitment: [16; 32],
                    settlement_descriptor_commitment: [13; 32],
                }),
                ckb_anchor: Some(CkbSettlementAnchor {
                    transaction: CkbOutPoint {
                        tx_hash: [17; 32],
                        index: u32::MAX,
                    },
                    block_hash: [18; 32],
                    block_number: u64::MAX,
                    confirmations: 1,
                }),
                rgbpp_proof_commitment: proof,
                failure_code: None,
            };
            let receipt = TerminalSettlementReceipt::new_signed(
                &intent,
                TerminalPaymentStatus::Settled,
                evidence,
                2,
                &signer,
            )
            .unwrap();
            let transport = SignedTransport {
                intent: intent.clone(),
                receipt: receipt.clone(),
            };
            let value = serde_json::to_value(&transport).unwrap();
            assert_eq!(value["intent"]["amount"], amount.to_string());
            assert_eq!(value["intent"]["expires_at_unix"], u64::MAX.to_string());
            assert!(
                value["receipt"]["signature"]
                    .as_str()
                    .unwrap()
                    .starts_with("0x")
            );
            assert_eq!(
                value["receipt"]["evidence"]["morph_state"]["state_number"],
                u64::MAX.to_string()
            );
            let restored: SignedTransport = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(restored.intent, intent);
            assert_eq!(restored.receipt, receipt);
            assert_eq!(restored.intent.derive_id().unwrap(), intent.intent_id);
            assert_eq!(restored.receipt.signing_digest(), receipt.signing_digest());
            restored
                .receipt
                .validate_for_signer(pubkey.as_bytes())
                .unwrap();
            restored
                .receipt
                .validate_against_intent(&restored.intent)
                .unwrap();
            // Core private serialization has not been repurposed as the API.
            assert!(serde_json::to_value(&intent).unwrap()["amount"].is_number());
            for (pointer, invalid) in [
                ("/intent/amount", json!(1)),
                ("/intent/amount", json!("01")),
                (
                    "/intent/amount",
                    json!("340282366920938463463374607431768211456"),
                ),
                ("/intent/payer", json!(vec![5; 32])),
                ("/intent/payer", json!(format!("0x{}", "AB".repeat(32)))),
                ("/receipt/evidence/morph_state/state_number", json!(1)),
                ("/receipt/signature", json!("0x00")),
            ] {
                let mut bad = value.clone();
                *bad.pointer_mut(pointer).unwrap() = invalid;
                assert!(
                    serde_json::from_value::<SignedTransport>(bad).is_err(),
                    "{pointer}"
                );
            }
            let mut missing = value.clone();
            missing["receipt"]["evidence"]
                .as_object_mut()
                .unwrap()
                .remove("morph_state");
            assert!(serde_json::from_value::<SignedTransport>(missing).is_err());
            let mut bad = value.clone();
            bad["receipt"]["evidence"]["extra"] = json!(true);
            assert!(serde_json::from_value::<SignedTransport>(bad).is_err());
            let mut bad = value;
            bad["intent"]["amount"] = json!("1");
            let tampered: SignedTransport = serde_json::from_value(bad).unwrap();
            assert!(
                tampered
                    .receipt
                    .validate_against_intent(&tampered.intent)
                    .is_err()
            );
        }
    }
    #[test]
    fn script_schema_and_pinned_rpc_decoder_accept_the_same_hash_types() {
        let schema = script_hash_type_schema(&mut schemars::SchemaGenerator::default());
        for name in schema.as_value()["enum"].as_array().unwrap() {
            assert!(
                serde_json::from_value::<ckb_jsonrpc_types::ScriptHashType>(name.clone()).is_ok(),
                "{name}"
            );
        }
        for name in ["data0", "data128", "TYPE", "unknown"] {
            assert!(
                serde_json::from_str::<ckb_jsonrpc_types::ScriptHashType>(&format!("\"{name}\""))
                    .is_err()
            );
        }
    }
}
