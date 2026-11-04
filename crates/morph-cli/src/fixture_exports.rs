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

fn conditional_root_fixture() -> serde_json::Value {
    let (mut terms, authority, cells, chain) =
        crate::multi_asset_root_transaction::tests::fixture(0, true);
    let mut settlement = morph_core::MultiAssetSettlement::decode(
        &multi_asset_packages::decode_hex(&terms.descriptor_hex, 4096).unwrap(),
    )
    .unwrap();
    settlement.payouts[0].values[0].business_ckb -= 2_000_000_000;
    let conditional = conditional_package()
        .recovery()
        .unwrap()
        .settlement
        .capability;
    let morph_core::MultiAssetSettlementCapability::CkbConditional {
        batch_code_hash,
        batch_hash_type,
        mut batch,
    } = conditional
    else {
        panic!("conditional fixture");
    };
    for party in 0..2 {
        batch.participants[party].settlement_lock_hash = settlement.participant_lock_hashes[party];
        batch.participants[party].settled_capacity =
            settlement.payouts[0].values[party].capacity().unwrap();
    }
    batch.transfers[0].payer_lock_hash = settlement.participant_lock_hashes[0];
    settlement.capability = morph_core::MultiAssetSettlementCapability::CkbConditional {
        batch_code_hash,
        batch_hash_type,
        batch,
    };
    terms.descriptor_hex = multi_asset_packages::canonical_hex(&settlement.encode().unwrap());
    let prepared = terms.build(chain, authority, &cells, 100_000_000).unwrap();
    let document =
        crate::multi_asset_funding::root_collection_tests::fixture_from_draft(prepared.draft);
    let source: multi_asset_packages::StoredMultiAssetPackage =
        serde_json::from_value(document["funding"]["recovery_package"].clone()).unwrap();
    assert_eq!(
        document["inspection"]["capability"],
        source.validate().unwrap().capability
    );
    document
}

#[test]
fn sdk_fixture_corpus_matches_current_protocol() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/typescript/test/fixtures");
    let ordinary = multi_asset_packages::fixture_package().unwrap();
    let conditional = conditional_package();
    let resolution = crate::conditional_packages::fixture_package().unwrap();
    let fixtures = [
        ("multi-asset.json", serde_json::to_value(&ordinary).unwrap()),
        (
            "multi-asset-summary.json",
            serde_json::to_value(ordinary.validate().unwrap()).unwrap(),
        ),
        (
            "multi-asset-update.json",
            multi_asset_session::sdk_update_fixture(),
        ),
        (
            "multi-asset-root.json",
            multi_asset_funding::root_collection_tests::fixture(),
        ),
        (
            "multi-asset-splice.json",
            multi_asset_splice_transaction::tests::sdk_splice_fixture(),
        ),
        (
            "multi-asset-conditional.json",
            serde_json::json!({"package":conditional,"summary":conditional.validate().unwrap()}),
        ),
        (
            "conditional-batch.json",
            serde_json::json!({"package":resolution,"summary":resolution.validate().unwrap()}),
        ),
        (
            "multi-asset-conditional-root.json",
            conditional_root_fixture(),
        ),
        (
            "factory-packets.json",
            crate::factory_packets::sdk_packet_fixture(),
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
            "regenerate current synthetic fixtures with MORPH_UPDATE_FIXTURES=1 cargo test -p morph-cli fixture_exports::sdk_fixture_corpus_matches_current_protocol"
        );
    }
}
