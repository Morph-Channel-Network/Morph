use morph_hub_api::{PublishStateRequest, RpcView, mutation::decimal};
use serde_json::json;

#[test]
fn full_width_public_numbers_round_trip_without_json_number_coercion() {
    for number in [0, 1, (1u64 << 53) + 1, u64::MAX - 1, u64::MAX] {
        let request = PublishStateRequest {
            funding_context_id: format!("0x{}", "12".repeat(32)),
            state_number: number,
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["state_number"], number.to_string());
        assert_eq!(
            serde_json::from_value::<PublishStateRequest>(value)
                .unwrap()
                .state_number,
            number
        );
    }
    for value in [
        json!(1),
        json!(1.0),
        json!("01"),
        json!("+1"),
        json!(" 1"),
        json!("1\n"),
        json!("18446744073709551616"),
        json!(null),
    ] {
        assert!(
            serde_json::from_value::<PublishStateRequest>(
                json!({"funding_context_id":"public","state_number":value})
            )
            .is_err()
        );
    }
    for value in [json!(null), json!("18446744073709551615")] {
        let view: RpcView =
            serde_json::from_value(json!({"status":"test", "tip_height":value})).unwrap();
        assert_eq!(serde_json::to_value(view).unwrap()["tip_height"], value);
    }
    assert!(serde_json::from_value::<RpcView>(json!({"status":"test", "tip_height":1})).is_err());
    assert!(serde_json::from_value::<RpcView>(json!({"status":"test"})).is_err());
}

#[test]
fn generated_decimal_schema_matches_runtime_range_at_precision_boundaries() {
    let schema =
        serde_json::to_value(decimal::schema(&mut schemars::SchemaGenerator::default())).unwrap();
    let pattern = regex::Regex::new(schema["pattern"].as_str().unwrap()).unwrap();
    let nondigit = regex::Regex::new(schema["not"]["pattern"].as_str().unwrap()).unwrap();
    let matches = |s: &str| pattern.is_match(s) && !nondigit.is_match(s);
    for number in [
        0u128,
        1,
        9,
        10,
        (1u128 << 53) + 1,
        u64::MAX as u128 - 1,
        u64::MAX as u128,
        u64::MAX as u128 + 1,
        u128::MAX,
    ] {
        let s = number.to_string();
        assert_eq!(matches(&s), decimal::parse(&s).is_some(), "{s}");
    }
    // Exercise all prefixes and lengths around the maximum, not just MAX+1.
    let maximum = u64::MAX.to_string();
    for pos in 0..maximum.len() {
        for digit in b'0'..=b'9' {
            let mut bytes = maximum.as_bytes().to_vec();
            bytes[pos] = digit;
            let s = String::from_utf8(bytes).unwrap();
            assert_eq!(matches(&s), decimal::parse(&s).is_some(), "{s}");
        }
    }
    for s in [
        "", "00", "01", "+1", "-1", "1.0", "1\n", "1\r\n", " 1", "１２",
    ] {
        assert!(!matches(s), "{s:?}");
        assert!(decimal::parse(s).is_none());
    }
}

#[test]
fn capability_review_has_closed_variants_and_preserves_conditional_value() {
    use morph_packages::capability_summary::CapabilitySummary;
    let ordinary: CapabilitySummary = serde_json::from_value(json!({"kind":"ordinary"})).unwrap();
    assert_eq!(
        serde_json::to_value(ordinary).unwrap(),
        json!({"kind":"ordinary"})
    );
    assert!(
        serde_json::from_value::<CapabilitySummary>(json!({"kind":"ordinary","pending_ckb":"1"}))
            .is_err()
    );
    assert!(serde_json::from_value::<CapabilitySummary>(json!({"kind":"future"})).is_err());
    let value = json!({"kind":"conditional","batch_code_hash":"public-code", "batch_hash_type":1,
        "batches":[{"asset":{"kind":"xudt","type_hash":"public-type"},"batch_id":"public-batch",
            "application_context_commitment":"public-context","pending_amount":"18446744073709551738",
            "batch_lock_hash":"public-lock","settled_capacities":["1","2"],"settled_amounts":["0","340282366920938463463374607431768211455"],
            "transfers":[{"transfer_id":"public-transfer","payer_lock_hash":"public-payer","payee_lock_hash":"public-payee",
                "hash_algorithm":"ckb_blake2b","payment_hash":"public-payment","amount":"18446744073709551738","refund_after_block":"100"}]}]});
    let typed: CapabilitySummary = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        typed.conditional().unwrap().batches[0].pending_amount,
        "18446744073709551738"
    );
    assert_eq!(serde_json::to_value(typed).unwrap(), value);
    let mut invalid = value.clone();
    invalid["batches"][0]["transfers"][0]["hash_algorithm"] = json!("sha1");
    assert!(serde_json::from_value::<CapabilitySummary>(invalid).is_err());
    let mut missing = value;
    missing["batches"][0]
        .as_object_mut()
        .unwrap()
        .remove("batch_lock_hash");
    assert!(serde_json::from_value::<CapabilitySummary>(missing).is_err());
}

#[test]
fn empty_asset_variant_does_not_ignore_extra_fields() {
    use morph_hub_api::AssetRequest;
    assert!(serde_json::from_value::<AssetRequest>(json!({"kind":"ckb"})).is_ok());
    assert!(
        serde_json::from_value::<AssetRequest>(json!({"kind":"ckb","type_hash":"ignored"}))
            .is_err()
    );
    assert!(serde_json::from_value::<AssetRequest>(json!({"kind":"xudt"})).is_err());
}
