//! Pin the CKB dependency boundary independently of Morph's witness formats.
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, ScriptHashType},
    packed::{CellInput, CellOutput, Script},
    prelude::*,
};
use morph_script_common::{
    blake2b256, multi_asset::multi_asset_occupied_capacity, relative_block_since,
    validate_relative_block_since,
};

fn script(args_len: usize, hash_type: ScriptHashType) -> Script {
    Script::new_builder()
        .code_hash([0x11; 32].pack())
        .hash_type(hash_type)
        .args(Bytes::from(vec![0xaa; args_len]).pack())
        .build()
}

#[test]
fn canonical_molecule_script_and_ckb_personalized_hash_match_fixed_vectors() {
    // Independently encoded Molecule table: total 55, offsets 16/48/49,
    // code_hash, hash_type=Type, Bytes length=2, args=aabb.
    let raw = hex::decode(concat!(
        "37000000100000003000000031000000",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0102000000aabb"
    ))
    .unwrap();
    let expected_hash =
        hex::decode("0a3450f0035d8176e5fc241eee3207eda429c3434f9073271c48c6be0482b80a").unwrap();
    let packed = Script::new_builder()
        .code_hash([0x11; 32].pack())
        .hash_type(ScriptHashType::Type)
        .args(Bytes::from_static(&[0xaa, 0xbb]).pack())
        .build();
    assert_eq!(packed.as_slice(), raw);
    assert_eq!(Script::from_slice(&raw).unwrap(), packed);
    assert_eq!(packed.calc_script_hash().as_slice(), expected_hash);
    assert_eq!(blake2b256(&[&raw]).as_slice(), expected_hash);

    let mut malformed = raw;
    malformed[4] = 15;
    assert!(Script::from_slice(&malformed).is_err());
    assert!(multi_asset_occupied_capacity(&malformed, None, 0).is_err());
}

#[test]
fn ckb_occupied_capacity_matches_the_script_boundary_for_all_hash_types() {
    for hash_type in [
        ScriptHashType::Data,
        ScriptHashType::Type,
        ScriptHashType::Data1,
        ScriptHashType::Data2,
    ] {
        for args_len in [0, 20, 116] {
            let lock = script(args_len, hash_type);
            for type_script in [None, Some(script(32, ScriptHashType::Type))] {
                // Eight capacity bytes, 33 bytes plus args for each Script,
                // and sixteen data bytes; Molecule framing occupies no CKB.
                let expected = (8
                    + 33
                    + args_len as u64
                    + 16
                    + if type_script.is_some() { 33 + 32 } else { 0 })
                    * 100_000_000;
                let output = CellOutput::new_builder()
                    .capacity(expected - 1)
                    .lock(lock.clone())
                    .type_(type_script.clone().pack())
                    .build();
                let data = Capacity::bytes(16).unwrap();
                assert_eq!(output.occupied_capacity(data).unwrap().as_u64(), expected);
                assert!(output.is_lack_of_capacity(data).unwrap());
                assert_eq!(
                    multi_asset_occupied_capacity(
                        lock.as_slice(),
                        type_script.as_ref().map(Entity::as_slice),
                        16,
                    )
                    .unwrap(),
                    expected,
                );
            }
        }
    }
}

#[test]
fn canonical_relative_block_since_survives_packed_input_serialization() {
    let since = relative_block_since(42).unwrap();
    assert_eq!(since, 0x8000_0000_0000_002a);
    let input = CellInput::new_builder().since(since).build();
    assert_eq!(&input.as_slice()[..8], &[42, 0, 0, 0, 0, 0, 0, 128]);
    let decoded: u64 = CellInput::from_slice(input.as_slice())
        .unwrap()
        .since()
        .unpack();
    validate_relative_block_since(decoded, since).unwrap();
    for invalid in [
        42,                            // absolute block
        since | 0x2000_0000_0000_0000, // epoch metric
        since | 0x4000_0000_0000_0000, // timestamp metric
        since | 0x0100_0000_0000_0000, // reserved flag
        since - 1,                     // immature relative block
    ] {
        assert!(validate_relative_block_since(invalid, since).is_err());
    }
}
