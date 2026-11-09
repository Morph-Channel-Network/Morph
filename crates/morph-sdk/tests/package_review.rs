use morph_sdk::inspection;
use serde_json::{Value, json};

#[test]
fn current_public_documents_and_detached_receipts_are_reviewed() {
    let package: Value =
        serde_json::from_str(include_str!("../../../fixtures/protocol/multi-asset.json")).unwrap();
    let expected: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/multi-asset-summary.json"
    ))
    .unwrap();
    assert_eq!(inspection::inspect(&package, None).unwrap(), expected);

    let update: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/multi-asset-update.json"
    ))
    .unwrap();
    let reviewed =
        inspection::inspect_signature(&update["proposal"], Some(&package), &update["signature"])
            .unwrap();
    assert_eq!(reviewed["signer_pubkey"], update["signature"]["pubkey"]);
    assert_eq!(
        reviewed["signing_digest"],
        update["proposal"]["signing_digest"]
    );

    let root: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/multi-asset-root.json"
    ))
    .unwrap();
    for field in ["draft", "collection", "funding"] {
        inspection::inspect(&root[field], None).unwrap();
    }

    let splice: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/multi-asset-splice.json"
    ))
    .unwrap();
    for field in ["draft", "funding"] {
        let reviewed = inspection::inspect(&splice[field], Some(&splice["current"])).unwrap();
        assert_eq!(reviewed["bridge_digest"], splice["bridge_digest"]);
        assert_eq!(reviewed["recovery_digest"], splice["recovery_digest"]);
    }

    let factory: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/factory-packets.json"
    ))
    .unwrap();
    for case in factory["cases"].as_array().unwrap() {
        inspection::inspect(&case["request"], None).unwrap();
        for receipt in case["signatures"].as_array().unwrap() {
            let reviewed = inspection::inspect_signature(&case["request"], None, receipt).unwrap();
            assert_eq!(reviewed["participant"], receipt["participant"]);
            assert_eq!(reviewed["signing_digest"], receipt["signing_digest"]);
        }
    }

    let transitions: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/factory-transitions.json"
    ))
    .unwrap();
    for case in transitions["cases"].as_array().unwrap() {
        let reviewed = inspection::inspect(&case["package"], None).unwrap();
        assert_eq!(reviewed["validation_scope"], "signed_frame_and_exact_body");
    }
}

#[test]
fn public_review_rejects_missing_context_corrupt_evidence_and_wrong_signature() {
    let package: Value =
        serde_json::from_str(include_str!("../../../fixtures/protocol/multi-asset.json")).unwrap();
    let update: Value = serde_json::from_str(include_str!(
        "../../../fixtures/protocol/multi-asset-update.json"
    ))
    .unwrap();
    assert!(inspection::inspect(&update["proposal"], None).is_err());
    assert!(inspection::inspect(&json!({"schema":"unknown"}), None).is_err());

    let mut corrupt = package.clone();
    corrupt["witness_hex"] = json!("0x00");
    assert!(inspection::inspect(&corrupt, None).is_err());
    let mut receipt = update["signature"].clone();
    receipt["signature"] = json!(format!("0x{}", "00".repeat(64)));
    assert!(inspection::inspect_signature(&update["proposal"], Some(&package), &receipt).is_err());
}
