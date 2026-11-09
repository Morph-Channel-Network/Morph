use morph_sdk::inspection;
use serde_json::Value;

#[test]
fn retiring_sdk_public_vectors_remain_validated_by_canonical_rust() {
    let suite: Value = serde_json::from_str(include_str!(
        "../../../fixtures/interop/typescript-baseline.json"
    ))
    .unwrap();
    let vectors = suite["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 29);
    for (index, vector) in vectors.iter().enumerate() {
        let op = vector["operation"].as_str().unwrap();
        let input = &vector["input"];
        let actual = match op {
            "inspectMultiAssetProposal" => {
                inspection::inspect(&input["proposal"], Some(&input["base"]))
            }
            "inspectMultiAssetProposalSignature" => inspection::inspect_signature(
                &input["proposal"],
                Some(&input["base"]),
                &input["signature"],
            ),
            "inspectMultiAssetSpliceDraft" => {
                inspection::inspect(&input["draft"], Some(&input["base"]))
            }
            "inspectMultiAssetSpliceFunding" => {
                inspection::inspect(&input["funding"], Some(&input["base"]))
            }
            "inspectFactorySignature" => {
                inspection::inspect_signature(&input["request"], None, &input["signature"])
            }
            _ => inspection::inspect(input, None),
        };
        if vector["accepted"] == false {
            assert!(actual.is_err(), "negative vector {index} accepted");
            continue;
        }
        let actual = actual.unwrap_or_else(|e| panic!("vector {index} {op}: {e:#}"));
        let mut expected = vector["result"].clone();
        // Native Core validates complete physical bodies. The retired browser
        // checker honestly described its weaker public-terms scope.
        if matches!(
            op,
            "inspectFactoryRequest" | "inspectFactoryTransitionPackage"
        ) {
            expected.as_object_mut().unwrap().remove("validation_scope");
            expected.as_object_mut().unwrap().remove("constraints");
        }
        assert_projection(&expected, &actual, &format!("vector {index} {op}"));
    }
}
fn assert_projection(expected: &Value, actual: &Value, path: &str) {
    match expected {
        Value::Object(fields) => {
            for (key, value) in fields {
                assert_projection(value, &actual[key], &format!("{path}.{key}"));
            }
        }
        Value::Array(values) => {
            let items = actual
                .as_array()
                .unwrap_or_else(|| panic!("{path}: expected array, got {actual}"));
            assert_eq!(values.len(), items.len(), "{path}");
            for (i, value) in values.iter().enumerate() {
                assert_projection(value, &items[i], &format!("{path}[{i}]"));
            }
        }
        _ => assert_eq!(expected, actual, "{path}"),
    }
}

#[test]
fn complete_retiring_protocol_smoke_calls_preserve_positive_and_negative_behavior() {
    let suite: Value = serde_json::from_str(include_str!(
        "../../../fixtures/interop/retiring-sdk-protocol-regressions.json"
    ))
    .unwrap();
    let vectors = suite["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 202);
    let mut failures = vec![];
    for (index, vector) in vectors.iter().enumerate() {
        let operation = vector["operation"].as_str().unwrap();
        let args = vector["arguments"].as_array().unwrap();
        let result = inspection::public_operation(operation, args);
        if vector["accepted"] == false {
            if result.is_ok() {
                failures.push(format!("{index}: {operation}: accepted retired negative"))
            }
            continue;
        }
        match result {
            Err(error) => failures.push(format!("{index}: {operation}: {error:#}")),
            Ok(actual) => {
                let mut expected = vector["result"].clone();
                if matches!(
                    operation,
                    "inspectFactoryRequest" | "inspectFactoryTransitionPackage"
                ) {
                    expected.as_object_mut().unwrap().remove("validation_scope");
                    expected.as_object_mut().unwrap().remove("constraints");
                }
                // Exact projection comparison, with additional Core-native review fields permitted.
                assert_projection(&expected, &actual, &format!("{index}: {operation}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
