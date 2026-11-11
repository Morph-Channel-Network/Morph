use super::*;
use crate::admission_channel::tests::MockRpc;
use ckb_types::{
    bytes::Bytes,
    core::{BlockBuilder, TransactionBuilder},
};
use serde_json::json;

fn fixture() -> (MockRpc, OutPoint, CellOutput, serde_json::Value) {
    let rpc = MockRpc::start([7; 32], 13);
    let output = CellOutput::new_builder()
        .capacity(100_000_000_000u64)
        .build();
    let tx = TransactionBuilder::default()
        .output(output.clone())
        .output_data(Bytes::from_static(b"custody").pack())
        .build();
    let point = OutPoint::new(tx.hash(), 0);
    let block = BlockBuilder::default()
        .number(10u64)
        .epoch(ckb_types::core::EpochNumberWithFraction::new(1, 0, 100).full_value())
        .transaction(tx.clone())
        .build();
    let view: ckb_jsonrpc_types::BlockView = block.clone().into();
    let block_json = serde_json::to_value(view).unwrap();
    rpc.respond(
        "get_block_by_number",
        json!(["0xa", "0x2", false]),
        block_json.clone(),
    );
    rpc.respond("get_transaction", json!([format!("{:#x}",H256::from(tx.hash())),"0x2",null]),
        json!({"transaction":null,"tx_status":{"status":"committed","block_hash":format!("{:#x}",H256::from(block.hash())),"block_number":"0xa","tx_index":"0x0","reason":null}}));
    (rpc, point, output, block_json)
}
fn live(mock: &MockRpc, point: &OutPoint, output: &CellOutput, data: &[u8]) {
    mock.respond("get_live_cell", json!([ckb_jsonrpc_types::OutPoint::from(point.clone()),true,false]),
        json!({"status":"live","cell":{"output":ckb_jsonrpc_types::CellOutput::from(output.clone()),"data":{"content":format!("0x{}",hex::encode(data)),"hash":format!("0x{}",hex::encode(blake2b_256(data)))}}}));
}
#[test]
fn spent_parent_is_history_but_never_live_custody() {
    let (mock, point, _, _) = fixture();
    mock.respond(
        "get_live_cell",
        json!([
            ckb_jsonrpc_types::OutPoint::from(point.clone()),
            true,
            false
        ]),
        json!({"status":"dead","cell":null}),
    );
    let rpc = CkbRpcClient::new(&mock.url).unwrap();
    assert_eq!(cell(&rpc, &point, 4, false).unwrap().data, b"custody");
    assert!(cell(&rpc, &point, 4, true).is_err());
    assert!(cell(&rpc, &point, 5, false).is_err());
}
#[test]
fn live_bytes_must_equal_canonical_bytes() {
    let (mock, point, output, _) = fixture();
    let rpc = CkbRpcClient::new(&mock.url).unwrap();
    live(&mock, &point, &output, b"custody");
    assert!(cell(&rpc, &point, 4, true).is_ok());
    live(&mock, &point, &output, b"forged");
    assert!(cell(&rpc, &point, 4, true).is_err());
    let forged = output.as_builder().capacity(1u64).build();
    live(&mock, &point, &forged, b"custody");
    assert!(cell(&rpc, &point, 4, true).is_err());
}
#[test]
fn orphaned_inclusion_and_forged_body_are_rejected() {
    let (mock, point, _, block) = fixture();
    let rpc = CkbRpcClient::new(&mock.url).unwrap();
    let mut changed = block.clone();
    changed["header"]["hash"] = json!(format!("0x{}", hex::encode([8; 32])));
    mock.respond("get_block_by_number", json!(["0xa", "0x2", false]), changed);
    assert!(cell(&rpc, &point, 4, false).is_err());
    let mut changed = block;
    changed["transactions"][0]["outputs_data"][0] = json!("0x666f72676564");
    mock.respond("get_block_by_number", json!(["0xa", "0x2", false]), changed);
    assert!(cell(&rpc, &point, 4, false).is_err());
}
#[test]
fn installed_artifact_pins_script_identity_and_hash_type() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("script"), b"approved executable").unwrap();
    let expected = identity(directory.path(), "script").unwrap();
    let script = Script::new_builder()
        .code_hash(expected.code_hash.pack())
        .hash_type(2u8)
        .build();
    assert!(trusted(script.as_slice(), &expected).is_ok());
    assert!(
        trusted(
            script
                .clone()
                .as_builder()
                .hash_type(1u8)
                .build()
                .as_slice(),
            &expected
        )
        .is_err()
    );
    assert!(
        trusted(
            script
                .as_builder()
                .code_hash([3; 32].pack())
                .build()
                .as_slice(),
            &expected
        )
        .is_err()
    );
    fs::write(directory.path().join("script"), []).unwrap();
    assert!(identity(directory.path(), "script").is_err());
}
#[test]
fn origin_is_strict_and_does_not_accept_legacy_aliases() {
    assert!(serde_json::from_value::<Origin>(json!({"kind":"root"})).is_ok());
    assert!(serde_json::from_value::<Origin>(json!({"kind":"root","trusted":true})).is_err());
    assert!(serde_json::from_value::<Origin>(json!({"kind":"legacy"})).is_err());
}
