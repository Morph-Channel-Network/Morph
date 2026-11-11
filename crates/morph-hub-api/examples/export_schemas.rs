//! Development-only code generation. Never used in the server request path.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/hub-types");
    std::fs::create_dir_all(&directory)?;
    for (name, text) in morph_hub_api::schema::documents()? {
        std::fs::write(directory.join(name), text)?;
    }
    std::fs::write(
        directory.join("../hub-endpoints.md"),
        morph_hub_api::endpoints::markdown(),
    )?;
    std::fs::write(
        directory.join("../hub-openapi.json"),
        morph_hub_api::openapi::document()?,
    )?;
    Ok(())
}
