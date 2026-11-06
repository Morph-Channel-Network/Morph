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

#[test]
fn unchecked_hex_decoder_bounds_short_sources_and_preserves_the_unused_destination() {
    // The safe unchecked API formerly let AVX2 load 64 source bytes using only
    // the destination length as its loop bound (RUSTSEC-2026-0306). Exercise
    // both sides of each SIMD boundary, including odd and empty source slices.
    // Decoding only complete source pairs must leave all other output intact.
    for source_len in 0..=129 {
        for destination_len in [0, 1, 31, 32, 33, 63, 64, 65] {
            let source = vec![b'a'; source_len];
            let mut destination = vec![0x5a; destination_len];
            faster_hex::hex_decode_unchecked(&source, &mut destination);
            let written = (source_len / 2).min(destination_len);
            assert!(destination[..written].iter().all(|&value| value == 0xaa));
            assert!(destination[written..].iter().all(|&value| value == 0x5a));
        }
    }
}

#[test]
fn ckb_rpc_hex_boundary_preserves_valid_bytes_and_rejects_malformed_input() {
    use ckb_jsonrpc_types::{Byte32, JsonBytes, ProposalShortId};

    for length in [0, 1, 20, 31, 32, 33, 63, 64, 65] {
        let bytes: Vec<u8> = (0..length).map(|index| index as u8).collect();
        let encoded = format!("0x{}", hex::encode(&bytes));
        let parsed: JsonBytes = serde_json::from_value(encoded.clone().into()).unwrap();
        assert_eq!(parsed.as_bytes(), bytes);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), encoded);
        let mixed_case = format!("0x{}", hex::encode_upper(&bytes));
        let parsed: JsonBytes = serde_json::from_value(mixed_case.into()).unwrap();
        assert_eq!(parsed.as_bytes(), bytes);
    }

    for invalid in ["", "00", "0X00", "0x0", "0xgg", "0x00 0", "0xé"] {
        assert!(serde_json::from_value::<JsonBytes>(invalid.into()).is_err());
    }
    for length in [31, 32, 33, 63, 64, 65] {
        let invalid = format!("0x{}gg", "00".repeat(length));
        assert!(serde_json::from_value::<JsonBytes>(invalid.into()).is_err());
    }
    for length in [0, 1, 31, 33, 64] {
        let encoded = format!("0x{}", "00".repeat(length));
        assert!(serde_json::from_value::<Byte32>(encoded.into()).is_err());
    }
    let fixed: Byte32 = serde_json::from_value(format!("0x{}", "aB".repeat(32)).into()).unwrap();
    assert_eq!(fixed.0, [0xab; 32]);
    assert_eq!(
        serde_json::to_value(fixed).unwrap(),
        format!("0x{}", "ab".repeat(32)),
    );
    let proposal: ProposalShortId =
        serde_json::from_value(format!("0x{}", "aB".repeat(10)).into()).unwrap();
    assert_eq!(proposal.into_inner(), [0xab; 10]);
    for length in [0, 9, 11, 32] {
        let invalid = format!("0x{}", "00".repeat(length));
        assert!(serde_json::from_value::<ProposalShortId>(invalid.into()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn memory_map_range_operations_reject_overflow_and_out_of_bounds_ranges() {
    use memmap2::{Advice, MmapMut};

    let mut mapping = MmapMut::map_anon(4096).unwrap();
    mapping[0] = 0xab;
    mapping.flush_range(0, 1).unwrap();
    mapping.flush_async_range(0, 1).unwrap();
    mapping.advise_range(Advice::Normal, 0, 1).unwrap();
    for (offset, length) in [(usize::MAX, 1), (1, usize::MAX), (4096, 1), (0, 4097)] {
        assert!(mapping.flush_range(offset, length).is_err());
        assert!(mapping.flush_async_range(offset, length).is_err());
    }
    // Advice is page-oriented; the upstream pointer-safety check independently
    // bounds the starting offset and length rather than their combined extent.
    for (offset, length) in [(usize::MAX, 1), (1, usize::MAX), (4097, 1), (0, 4097)] {
        assert!(
            mapping
                .advise_range(Advice::Normal, offset, length)
                .is_err()
        );
    }
    assert_eq!(mapping[0], 0xab);
}

#[test]
fn verification_lru_dependency_survives_a_panicking_removed_key_destructor() {
    use std::{
        hash::{Hash, Hasher},
        num::NonZeroUsize,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    struct Key(u8, bool);

    impl PartialEq for Key {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for Key {}
    impl Hash for Key {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }
    impl Drop for Key {
        fn drop(&mut self) {
            assert!(!self.1, "deliberate stored-key destructor panic");
        }
    }

    let mut cache = lru::LruCache::new(NonZeroUsize::new(1).unwrap());
    cache.put(Key(1, true), 11);
    assert!(catch_unwind(AssertUnwindSafe(|| cache.pop(&Key(1, false)))).is_err());
    assert!(cache.is_empty());
    // Pop must detach the removed node before dropping its key. Subsequent
    // insertion and eviction previously followed the dangling list node.
    cache.put(Key(2, false), 22);
    cache.put(Key(3, false), 33);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.get(&Key(2, false)), None);
    assert_eq!(cache.pop(&Key(3, false)), Some(33));
}
