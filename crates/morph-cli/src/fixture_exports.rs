//! Deterministic test-only fixture regeneration. This recreates synthetic
//! current-protocol evidence from Rust constructors; it never upgrades live
//! state or rewrites recorded node transactions.
use super::*;
use std::path::Path;

#[test]
fn factory_signer_fixture_matches_native_current_root_constructor() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../morph-core/tests/fixtures/factory-root.json");
    let value = crate::factory_root_transaction::tests::signer_fixture();
    if std::env::var("MORPH_UPDATE_FIXTURES").as_deref() == Ok("1") {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        )
        .unwrap();
    }
    let recorded: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        recorded, value,
        "regenerate native Factory test vector with MORPH_UPDATE_FIXTURES=1 cargo test -p morph-cli factory_signer_fixture_matches_native_current_root_constructor"
    );
}

pub(crate) fn conditional_package() -> multi_asset_packages::StoredMultiAssetPackage {
    crate::conditional_packages::fixture_source_package().unwrap()
}

#[test]
fn protocol_fixture_corpus_matches_current_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol");
    let ordinary = multi_asset_packages::fixture_package().unwrap();
    let fixtures = [
        ("multi-asset.json", serde_json::to_value(&ordinary).unwrap()),
        (
            "multi-asset-summary.json",
            serde_json::to_value(ordinary.validate().unwrap()).unwrap(),
        ),
        (
            "multi-asset-update.json",
            multi_asset_session::proposal_fixture(),
        ),
        (
            "multi-asset-root.json",
            multi_asset_funding::root_collection_tests::fixture(),
        ),
        (
            "multi-asset-splice.json",
            multi_asset_splice_transaction::tests::splice_fixture(),
        ),
        (
            "factory-packets.json",
            crate::factory_packets::packet_fixture(),
        ),
    ];
    for (name, value) in fixtures {
        let path = root.join(name);
        if std::env::var("MORPH_UPDATE_FIXTURES").as_deref() == Ok("1") {
            let mut encoded = serde_json::to_string_pretty(&value).unwrap();
            encoded.push('\n');
            fs::write(&path, encoded).unwrap();
        }
        let recorded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            recorded, value,
            "regenerate current synthetic fixtures with MORPH_UPDATE_FIXTURES=1 cargo test -p morph-cli fixture_exports::protocol_fixture_corpus_matches_current_protocol"
        );
    }
}
