//! Generated HTTP binding for the current Hub. Schemas come from the route
//! registry's Rust types; this module only describes HTTP framing.
use crate::{
    AuthScope,
    endpoints::{BodyContract, Endpoint},
    mutation,
};
use serde_json::{Value, json};

pub fn document() -> Result<String, serde_json::Error> {
    let mut paths = serde_json::Map::new();
    for endpoint in Endpoint::ALL {
        let spec = endpoint.spec();
        let scope = match spec.scope {
            AuthScope::Read => "read",
            AuthScope::Write => "write",
            AuthScope::Restore => "restore",
            AuthScope::Sign => "sign",
        };
        let mut parameters = Vec::new();
        if spec.path.contains("{id}") {
            parameters.push(json!({"name":"id", "in":"path", "required":true,
                "description":"Exact resource identifier. Canonical lowercase 0x-prefixed 32 bytes.",
                "schema":{"type":"string","minLength":66,"maxLength":66,"pattern":"^0x[0-9a-f]{64}$"}}));
        }
        if spec.mutates {
            parameters.extend([
                json!({"name":mutation::API_VERSION_HEADER,"in":"header","required":true,"schema":{"type":"string","const":mutation::API_VERSION}}),
                json!({"name":mutation::IDEMPOTENCY_HEADER,"in":"header","required":true,"schema":{"type":"string","minLength":32,"maxLength":32,"pattern":"^[0-9a-f]{32}$"},"description":"Public request identity. Exact retries keep this key, method, path, body and revision. Never a secret."}),
                json!({"name":mutation::REVISION_HEADER,"in":"header","required":true,"schema":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":19},"description":"Reviewed durable projection revision, canonical decimal 0..9223372036854775806. A stale fresh request fails; an exact replay returns the historical response."}),
            ]);
        }
        if *endpoint == Endpoint::Events {
            parameters.push(json!({"name":"Last-Event-ID","in":"header","required":false,
                "schema":{"type":"string"},"description":"Last observed event ID. Current bounded in-memory history; not durable event delivery."}));
        }
        let success = match spec.response {
            BodyContract::Json(contract) => {
                json!({"description":"Successful current representation", "content":{"application/json":{"schema":{"$ref":format!("hub-types/{}.json",contract.name)}}}})
            }
            BodyContract::EventStream(contract) => {
                json!({"description":"Server-sent morph-hub-event records; each data value is EventView JSON. Keepalive comments have no data.",
                "content":{"text/event-stream":{"schema":{"type":"string"},"x-event-data-schema":{"$ref":format!("hub-types/{}.json",contract.name)}}}})
            }
            BodyContract::Text => {
                json!({"description":"Bounded Prometheus text exposition", "content":{"text/plain":{"schema":{"type":"string", "maxLength":65536}}}})
            }
            BodyContract::Empty => json!({"description":"Success without a body"}),
        };
        let mut operation = json!({
            "operationId": format!("{endpoint:?}"), "security":[{"bearerAuth":[]}],
            "x-morph-required-scope":scope,"x-morph-durable-mutation":spec.mutates,
            "parameters":parameters,
            "responses":{"200":success,"default":{"description":"Typed API failure; malformed transport can close the connection before API dispatch.",
                "content":{"application/json":{"schema":{"$ref":"hub-types/ApiErrorBody.json"}}}}}
        });
        if *endpoint == Endpoint::Readiness {
            operation["responses"]["503"] = json!({"description":"At least one configured scope is not ready", "content":{"application/json":{"schema":{"$ref":"hub-types/Readiness.json"}}}});
        }
        if let BodyContract::Json(contract) = spec.request {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("hub-types/{}.json",contract.name)}}}});
        }
        paths
            .entry(spec.path.to_owned())
            .or_insert_with(|| json!({}))[spec.method.to_ascii_lowercase()] = operation;
    }
    let mut value = json!({
        "openapi":"3.1.0", "jsonSchemaDialect":"https://json-schema.org/draft/2020-12/schema",
        "info":{"title":"Morph Hub API","version":mutation::API_VERSION,
            "description":"One current unpublished API. Scopes are exact grants. Explicit server-enabled unauthenticated loopback is a development override; administrative import also requires allow-state-restore and remains empty-bootstrap-only. This document covers Hub HTTP, not Payment Gateway or chain readiness. Structural schemas do not replace domain validation. No signer state is restored through these endpoints."},
        "paths":Value::Object(paths),
        "components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","description":"Scoped Hub bearer token; never put it in the URL."}}}
    });
    value.sort_all_objects();
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}
#[cfg(test)]
mod tests {
    #[test]
    fn checked_openapi_matches_routes_and_types() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/api/hub-openapi.json");
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            super::document().unwrap(),
            "regenerate with cargo run -p morph-hub-api --example export_schemas"
        );
    }
}
