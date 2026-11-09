use morph_sdk::gateway::*;
use serde_json::{Value, json};

#[test]
fn canonical_authorization_matches_independent_signature_vector() {
    let vector: Value =
        serde_json::from_str(include_str!("../../../fixtures/gateway/authorization.json")).unwrap();
    let requirements: PaymentRequirements =
        serde_json::from_value(vector["requirements"].clone()).unwrap();
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let payload = PaymentPayload::new_signed(&requirements, None, &key).unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), vector["payload"]);
    payload.validate(&requirements).unwrap();
    let mut wrong = requirements;
    wrong.payment_hash = format!("0x{}", "23".repeat(32));
    assert!(payload.validate(&wrong).is_err());
}

#[test]
fn shared_x402_codec_preserves_exact_values_and_enforces_header_bounds() {
    let original = json!({"amount":"340282366920938463463374607431768211455","unicode":"中文"});
    let header = encode_x402_header(&original).unwrap();
    assert!(!header.contains('='));
    assert_eq!(decode_x402_header::<Value>(&header).unwrap(), original);
    assert!(decode_x402_header::<Value>(&"a".repeat(MAX_X402_HEADER_BYTES + 1)).is_err());
    assert!(decode_x402_header::<Value>("%%%not-base64").is_err());
}

#[test]
fn changed_identifier_never_bypasses_current_requirement_binding() {
    let vector: Value =
        serde_json::from_str(include_str!("../../../fixtures/gateway/authorization.json")).unwrap();
    let mut requirement: PaymentRequirements =
        serde_json::from_value(vector["requirements"].clone()).unwrap();
    requirement.requirement_id = format!("0x{}", "00".repeat(32));
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    assert!(PaymentPayload::new_signed(&requirement, None, &key).is_err());
}
