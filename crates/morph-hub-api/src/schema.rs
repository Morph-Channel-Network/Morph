//! Deterministic structural schemas from the current public Rust DTOs.
//! Each entry is an independent JSON Schema document with local definitions.
use crate::*;
use schemars::JsonSchema;
use std::collections::BTreeMap;

pub use morph_packages::schema::text;

pub fn documents() -> Result<BTreeMap<String, String>, serde_json::Error> {
    fn add<T: JsonSchema>(
        out: &mut BTreeMap<String, String>,
        name: &str,
    ) -> Result<(), serde_json::Error> {
        out.insert(format!("{name}.json"), text::<T>()?);
        Ok(())
    }
    let mut out = BTreeMap::new();
    macro_rules! roots { ($($ty:ty),+ $(,)?) => { $(add::<$ty>(&mut out, stringify!($ty))?;)+ }; }
    // Standalone documents not owned by one HTTP endpoint. Endpoint bodies are
    // collected below directly from the same registry used by server dispatch.
    roots!(
        MutationContext,
        ApiErrorBody,
        HubModelView,
        WatchtowerView,
        EventEnvelope
    );
    for endpoint in endpoints::Endpoint::ALL {
        let spec = endpoint.spec();
        for body in [spec.request, spec.response] {
            if let endpoints::BodyContract::Json(contract)
            | endpoints::BodyContract::EventStream(contract) = body
            {
                out.insert(format!("{}.json", contract.name), (contract.schema)()?);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn checked_schemas_match_authoritative_types_without_stale_files() {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/hub-types");
        let actual = super::documents().unwrap();
        let names: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            names,
            actual.keys().cloned().collect(),
            "stale/missing generated schema"
        );
        for (name, expected) in actual {
            assert_eq!(
                std::fs::read_to_string(directory.join(&name)).unwrap(),
                expected,
                "{name}: regenerate with cargo run -p morph-hub-api --example export_schemas"
            );
        }
    }
}
