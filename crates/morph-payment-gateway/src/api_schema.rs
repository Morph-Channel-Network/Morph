//! Development-only generated contracts, never run for individual requests.
use crate::{
    api::*,
    endpoints::{Authority, Body, Endpoint},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn documents() -> Result<BTreeMap<String, String>, serde_json::Error> {
    let mut out = BTreeMap::new();
    out.insert(
        "GatewayErrorBody.json".into(),
        morph_packages::schema::text::<GatewayErrorBody>()?,
    );
    for endpoint in Endpoint::ALL {
        let spec = endpoint.spec();
        for body in [spec.request, spec.response] {
            if let Body::Json(contract) | Body::Query(contract) = body {
                out.insert(format!("{}.json", contract.name), (contract.schema)()?);
            }
        }
    }
    Ok(out)
}
fn description(body: &Body) -> String {
    match body {
        Body::Text => "Prometheus text".into(),
        Body::Empty => "None".into(),
        Body::Json(c) => format!("[{}](gateway-types/{}.json)", c.name, c.name),
        Body::Query(c) => format!("Query: [{}](gateway-types/{}.json)", c.name, c.name),
        Body::Bytes => "Bounded opaque upstream body".into(),
        Body::Upstream => "Upstream status/body/selected headers".into(),
    }
}
pub fn markdown() -> String {
    let mut out = String::from(
        "# Current Payment Gateway endpoints\n\nGenerated from `morph_payment_gateway::endpoints`; do not edit the table by hand.\nRegenerate with `cargo run -p morph-payment-gateway --example export_api`.\n\nReadiness HTTP 503 returns the same Readiness body as HTTP 200. Other API failures use [GatewayErrorBody](gateway-types/GatewayErrorBody.json).\nThe normal x402 challenge uses HTTP 402 with PaymentRequirements, not the error\nenvelope. A proxied upstream error remains the upstream response. Diagnostic\nrequest IDs and API version headers do not grant idempotency or prove payment\nnon-submission. See [transport and retry rules](gateway-errors.md).\n\nOperator bearer may be omitted only in explicitly allowed local development.\nPayer-signature endpoints still validate exact terms and configured outgoing\npolicy; stored-credential endpoints require the stored receipt and resource.\nThe operator-only `/v1/events` endpoint pages immutable, redacted local records\nwith source-bound cursors; it is not a chain-finality or signing interface.\nSee [event delivery](../runbooks/event-delivery.md). Public liveness is not full readiness. Raw Fiber evidence in PayResponse is an\nexplicit provider-specific diagnostic object; it is not a signed Morph receipt.\n\n| Method | Path | Authority | Request | Success | Body | Retry semantics |\n| --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for endpoint in Endpoint::ALL {
        let spec = endpoint.spec();
        out.push_str(&format!(
            "| {} | `{}` | {} | {} | {} | {} | {} |\n",
            spec.method.verbs().join(", ").to_uppercase(),
            spec.path,
            spec.authority.label(),
            description(&spec.request),
            if matches!(spec.response, Body::Upstream) {
                "upstream".into()
            } else {
                spec.success.to_string()
            },
            description(&spec.response),
            spec.retry
        ));
    }
    out
}
pub fn openapi() -> Result<String, serde_json::Error> {
    let mut paths = serde_json::Map::new();
    for endpoint in Endpoint::ALL {
        let spec = endpoint.spec();
        let path = spec.path.replace("{*path}", "{path}");
        for verb in spec.method.verbs() {
            let security = match spec.authority {
                Authority::OperatorBearer => json!([{"operatorBearer":[]}]),
                Authority::PaidResource => json!([{"paidCredential":[]},{"paymentSignature":[]}]),
                _ => json!([]),
            };
            let mut parameters = Vec::new();
            if path.contains("{path}") {
                parameters.push(json!({"name":"path","in":"path","required":true,"schema":{"type":"string"},"description":"Nonempty captured path, may contain slashes. Reject dot segments, backslashes, authorities and leading slash. Exact method and raw query form the authorized resource."}));
            }
            if let Body::Query(c) = &spec.request {
                parameters.push(json!({"name":"limit","in":"query","required":false,"schema":{"$ref":format!("gateway-types/{}.json#/properties/limit",c.name)},"description":"Canonical decimal 1..1000, default 100. Duplicate and unknown parameters are rejected."}));
            }
            let error = json!({"description":"Typed Gateway failure, not an upstream response.","content":{"application/json":{"schema":{"$ref":"gateway-types/GatewayErrorBody.json"}}}});
            let mut responses = serde_json::Map::new();
            responses.insert("default".into(), error);
            match &spec.response {
                Body::Text => {
                    responses.insert(spec.success.to_string(), json!({"description":"Fixed Prometheus exposition", "content":{"text/plain":{"schema":{"type":"string"}}}}));
                }
                Body::Json(c) => {
                    let mut response = json!({"description":"Successful result", "content":{"application/json":{"schema":{"$ref":format!("gateway-types/{}.json",c.name)}}}});
                    if *endpoint == Endpoint::X402Challenge {
                        response["description"] = json!(
                            "Normal payment-required challenge, not a Gateway error. A rejected request can also return GatewayErrorBody with its documented failure status."
                        );
                        response["headers"] = json!({"PAYMENT-REQUIRED":{"description":"Base64url without padding of the same PaymentRequirements JSON.","schema":{"type":"string"}}});
                    }
                    if *endpoint == Endpoint::Readiness {
                        responses.insert("503".into(), response.clone());
                    }
                    responses.insert(spec.success.to_string(), response);
                }
                Body::Upstream => {
                    responses.insert("default".into(),json!({"description":"Upstream status/body and selected headers, or a typed GatewayErrorBody before forwarding. Upstream status is not recast as a Gateway error.","content":{"*/*":{"schema":{"type":"string","format":"binary"}}},"x-gateway-error-schema":{"$ref":"gateway-types/GatewayErrorBody.json"}}));
                }
                _ => {}
            }
            let mut operation = json!({"operationId":format!("{endpoint:?}_{verb}"),"security":security,"x-morph-authority":spec.authority.label(),"description":spec.retry,"parameters":parameters,"responses":responses});
            match &spec.request {
                Body::Json(c) => {
                    operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("gateway-types/{}.json",c.name)}}}})
                }
                Body::Bytes => {
                    operation["requestBody"] = json!({"required":false,"content":{"*/*":{"schema":{"type":"string","format":"binary"}}}})
                }
                _ => {}
            }
            paths.entry(path.clone()).or_insert_with(|| json!({}))[verb.to_string()] = operation;
        }
    }
    let mut value = json!({"openapi":"3.1.0","jsonSchemaDialect":"https://json-schema.org/draft/2020-12/schema", "info":{"title":"Morph Payment Gateway API","version":API_VERSION,"description":"Current public Gateway HTTP contracts; core signing encodings remain separate. No generic durable idempotency or expected-revision header is implemented here yet. Payer signatures are in bodies, not an operator bearer token."},"paths":Value::Object(paths),"components":{"securitySchemes":{"operatorBearer":{"type":"http","scheme":"bearer"},"paidCredential":{"type":"http","scheme":"bearer","description":"Stored resource/method-bound Biscuit credential, not an operator token."},"paymentSignature":{"type":"apiKey","in":"header","name":"PAYMENT-SIGNATURE","description":"Base64url SettleRequest JSON with signed payer authorization. Must not accompany a paid credential."}}}});
    value.sort_all_objects();
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_gateway_contracts_match_types_routes_and_no_stale_files() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api");
        let documents = documents().unwrap();
        let names = std::fs::read_dir(root.join("gateway-types"))
            .unwrap()
            .map(|p| p.unwrap().file_name().into_string().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names, documents.keys().cloned().collect());
        for (name, text) in documents {
            assert_eq!(
                std::fs::read_to_string(root.join("gateway-types").join(&name)).unwrap(),
                text,
                "{name}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(root.join("gateway-endpoints.md")).unwrap(),
            markdown()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("gateway-openapi.json")).unwrap(),
            openapi().unwrap()
        );
        let mut paths = std::collections::BTreeSet::new();
        for e in Endpoint::ALL {
            let spec = e.spec();
            for verb in spec.method.verbs() {
                assert!(paths.insert((verb, spec.path)));
            }
        }
    }
}
