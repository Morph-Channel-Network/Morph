fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api");
    std::fs::create_dir_all(root.join("gateway-types"))?;
    for (name, text) in morph_payment_gateway::api_schema::documents()? {
        std::fs::write(root.join("gateway-types").join(name), text)?;
    }
    std::fs::write(
        root.join("gateway-endpoints.md"),
        morph_payment_gateway::api_schema::markdown(),
    )?;
    std::fs::write(
        root.join("gateway-openapi.json"),
        morph_payment_gateway::api_schema::openapi()?,
    )?;
    Ok(())
}
