//! Deterministic developer-facing structural schema generation.
use schemars::{JsonSchema, generate::SchemaSettings};
pub fn text<T: JsonSchema>() -> Result<String, serde_json::Error> {
    let schema = SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>();
    let mut schema = serde_json::to_value(schema)?;
    schema.sort_all_objects();
    let mut text = serde_json::to_string_pretty(&schema)?;
    text.push('\n');
    Ok(text)
}
