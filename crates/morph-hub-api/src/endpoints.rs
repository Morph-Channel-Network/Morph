//! Sole current Hub route registry. Server dispatch and SDK permissions consume it.
use crate::*;
use morph_packages::{
    conditional_packages::StoredConditionalBatchPackage,
    multi_asset_funding::{RootFundingCollection, RootFundingDraft, RootFundingExport},
    multi_asset_packages::StoredMultiAssetPackage,
};

pub struct JsonContract {
    pub name: &'static str,
    pub schema: fn() -> Result<String, serde_json::Error>,
}
pub enum BodyContract {
    Empty,
    Text,
    Json(JsonContract),
    EventStream(JsonContract),
}
macro_rules! json {
    ($ty:ty) => {
        BodyContract::Json(JsonContract {
            name: stringify!($ty),
            schema: crate::schema::text::<$ty>,
        })
    };
}
pub struct EndpointSpec {
    pub endpoint: Endpoint,
    pub method: &'static str,
    pub path: &'static str,
    pub scope: AuthScope,
    pub mutates: bool,
    pub request: BodyContract,
    pub response: BodyContract,
}
macro_rules! routes {
    ($( $variant:ident, $method:literal, $path:literal, $scope:ident, $mutates:literal, $request:expr, $response:expr; )+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Endpoint { $($variant,)+ }
        impl Endpoint {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];
            pub const fn route(self) -> (&'static str, &'static str) {
                match self { $(Self::$variant => ($method, $path),)+ }
            }
            pub const fn scope(self) -> AuthScope {
                match self { $(Self::$variant => AuthScope::$scope,)+ }
            }
            pub const fn mutates(self) -> bool {
                match self { $(Self::$variant => $mutates,)+ }
            }
            pub fn spec(self) -> EndpointSpec {
                let (method, path) = self.route();
                let (request, response) = match self { $(Self::$variant => ($request, $response),)+ };
                EndpointSpec { endpoint:self, method, path, scope:self.scope(), mutates:self.mutates(), request, response }
            }
        }
    }
}
routes! {
    Meta, "GET", "/api/meta", Read, false, BodyContract::Empty, json!(ApiInfo);
    Health, "GET", "/api/health", Read, false, BodyContract::Empty, json!(Liveness);
    Readiness, "GET", "/api/readiness", Read, false, BodyContract::Empty, json!(Readiness);
    Metrics, "GET", "/api/metrics", Read, false, BodyContract::Empty, BodyContract::Text;
    State, "GET", "/api/state", Read, false, BodyContract::Empty, json!(HubView);
    EventLog, "POST", "/api/event-log", Read, false, json!(EventPageRequest), json!(EventPage);
    Events, "GET", "/api/events", Read, false, BodyContract::Empty, BodyContract::EventStream(JsonContract { name:"EventView", schema:crate::schema::text::<EventView> });
    ExportState, "GET", "/api/state-file", Restore, false, BodyContract::Empty, json!(StateArchive);
    PreviewRestore, "POST", "/api/state-file/preview", Restore, false, json!(StateArchive), json!(RestorePreview);
    RestoreState, "PUT", "/api/state-file", Restore, true, json!(RestoreArchiveRequest), json!(HubView);
    ConnectPeer, "POST", "/api/peers", Write, true, json!(ConnectPeerRequest), json!(HubView);
    CreateInvoice, "POST", "/api/invoices", Sign, true, json!(CreateInvoiceRequest), json!(HubView);
    DecodeInvoice, "POST", "/api/invoices/decode", Write, true, json!(DecodeInvoiceRequest), json!(HubView);
    ReceiveInvoice, "POST", "/api/invoices/{id}/receive", Write, true, json!(EmptyRequest), json!(HubView);
    SettleInvoice, "POST", "/api/invoices/{id}/settle", Write, true, json!(SettleInvoiceRequest), json!(HubView);
    OpenChannel, "POST", "/api/channels", Write, true, json!(OpenChannelRequest), json!(HubView);
    SpliceChannel, "POST", "/api/channels/{id}/splice", Write, true, json!(SpliceChannelRequest), json!(HubView);
    PublishChannel, "POST", "/api/channels/{id}/publish", Write, true, json!(PublishStateRequest), json!(HubView);
    FinaliseChannel, "POST", "/api/channels/{id}/finalise", Write, true, BodyContract::Empty, json!(HubView);
    OpenFactory, "POST", "/api/factories", Write, true, json!(OpenFactoryRequest), json!(HubView);
    AdvanceFactory, "POST", "/api/factories/{id}/advance", Write, true, json!(AdvanceFactoryRequest), json!(HubView);
    MaterialiseChild, "POST", "/api/factories/{id}/materialise-child", Write, true, json!(MaterialiseChildRequest), json!(HubView);
    ImportBatch, "POST", "/api/conditional-batches", Write, true, json!(StoredConditionalBatchPackage), json!(HubView);
    ImportRecovery, "POST", "/api/multi-asset-packages", Write, true, json!(StoredMultiAssetPackage), json!(HubView);
    RecoveryPackage, "GET", "/api/multi-asset-packages/{id}", Read, false, BodyContract::Empty, json!(StoredMultiAssetPackage);
    ImportRoot, "POST", "/api/root-fundings", Write, true, json!(RootFundingDraft), json!(HubView);
    RootCollection, "GET", "/api/root-fundings/{id}", Read, false, BodyContract::Empty, json!(RootFundingCollection);
    RootExport, "GET", "/api/root-fundings/{id}/export", Read, false, BodyContract::Empty, json!(RootFundingExport);
    RootSignature, "POST", "/api/root-fundings/{id}/signatures", Write, true, json!(RootReceiptRequest), json!(HubView);
}
impl Endpoint {
    /// Recognize exactly one route shape. Resource IDs are subsequently checked
    /// by the domain decoder, so malformed IDs never select another operation.
    pub fn resolve(method: &str, path: &str) -> Option<Self> {
        if path.contains(['?', '#', '%']) {
            return None;
        }
        Self::ALL.iter().copied().find(|endpoint| {
            let (verb, template) = endpoint.route();
            if method != verb {
                return false;
            }
            if let Some((prefix, suffix)) = template.split_once("{id}") {
                path.strip_prefix(prefix)
                    .and_then(|rest| rest.strip_suffix(suffix))
                    .is_some_and(|id| !id.is_empty() && !id.contains('/'))
            } else {
                path == template
            }
        })
    }
}

/// Deterministic route documentation. No request payloads or private state are
/// embedded. Administrative types are separate from private persistence.
pub fn markdown() -> String {
    fn body_label(body: BodyContract) -> String {
        match body {
            BodyContract::Empty => "No body".into(),
            BodyContract::Text => "Prometheus text (bounded)".into(),
            BodyContract::Json(contract) => {
                format!("[{}](hub-types/{}.json)", contract.name, contract.name)
            }
            BodyContract::EventStream(contract) => format!(
                "SSE data: [{}](hub-types/{}.json)",
                contract.name, contract.name
            ),
        }
    }
    let mut out = String::from(
        "# Current Hub endpoints\n\nGenerated by `cargo run -p morph-hub-api --example export_schemas`.\nSource: `morph_hub_api::endpoints`; do not edit the table by hand.\n\nThe server dispatches this closed registry; the Rust SDK consumes its scopes and\nmutation classification. Request/result types generate the linked structural\nschemas. Domain validation still checks signatures, exact identifiers and value\nconservation. Administrative archives are explicit public DTOs, separate from private\nruntime snapshots. Import remains limited to empty bootstrap state.\n\nEvery API error uses [ApiErrorBody](hub-types/ApiErrorBody.json). Successful JSON\nresponses use HTTP 200. `/api/events` returns `text/event-stream` with EventView\ndata; connection/authentication errors before the stream use the same error body.\nThis stream is a bounded UI activity feed. `POST /api/event-log` provides durable,\nsource-bound typed event pagination under read permission; its body is a query,\nnot a mutation. See [delivery and retention rules](../runbooks/event-delivery.md).\n`/api/metrics` returns Prometheus `text/plain`; the remaining bodies use JSON. Authentication is required unless\nthe server explicitly enables unauthenticated loopback. Scopes are exact grants,\nnot a hierarchy; restore also requires the server's explicit restore option.\n\nDurable mutations require API version, idempotency key and reviewed revision\nheaders. Preview is read-only even though it uses POST. Health reports process liveness without store/RPC access. Readiness reports\nexplicit configured capability scopes (200 or 503); metrics are bounded authenticated text.\nReadiness is observation, never signing or chain admission authority.\nSee [mutation/retry rules](../hub-api-mutations.md).\n\n| Method | Path | Scope | Durable mutation | Request | Success body |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    for endpoint in Endpoint::ALL {
        let spec = endpoint.spec();
        let scope = match spec.scope {
            AuthScope::Read => "read",
            AuthScope::Write => "write",
            AuthScope::Sign => "sign",
            AuthScope::Restore => "restore",
        };
        out.push_str(&format!(
            "| {} | `{}` | {} | {} | {} | {} |\n",
            spec.method,
            spec.path,
            scope,
            if spec.mutates { "Yes" } else { "No" },
            body_label(spec.request),
            body_label(spec.response)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_endpoint_inventory_matches_registry() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/api/hub-endpoints.md");
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            markdown(),
            "regenerate with cargo run -p morph-hub-api --example export_schemas"
        );
    }
    #[test]
    fn routes_are_unique_closed_and_round_trip() {
        let mut registered = std::collections::BTreeSet::new();
        for endpoint in Endpoint::ALL {
            let (method, template) = endpoint.route();
            assert!(registered.insert((method, template)));
            let path = template.replace("{id}", &format!("0x{}", "12".repeat(32)));
            assert_eq!(Endpoint::resolve(method, &path), Some(*endpoint));
            assert_eq!(Endpoint::resolve("DELETE", &path), None);
            for bad in [
                format!("{path}/"),
                format!("{path}?ignored=1"),
                format!("{path}#fragment"),
            ] {
                assert_eq!(Endpoint::resolve(method, &bad), None);
            }
        }
        for path in [
            "/api/invoices//receive",
            "/api/channels/id/unknown",
            "/api/root-fundings/id/unknown",
            "/api/multi-asset-packages/a/b",
            "/api/channels/%2f/publish",
        ] {
            assert_eq!(Endpoint::resolve("POST", path), None);
        }
        assert_eq!(Endpoint::CreateInvoice.scope(), AuthScope::Sign);
        assert!(!Endpoint::PreviewRestore.mutates());
        assert_eq!(Endpoint::PreviewRestore.scope(), AuthScope::Restore);
    }
}
