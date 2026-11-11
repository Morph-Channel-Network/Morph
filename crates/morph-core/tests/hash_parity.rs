use morph_core::hash as host_hash;
use morph_core::{AssetRegistry, asset_registry_commitment, participants_commitment};
use morph_script_common as wire;
use std::collections::BTreeSet;
fn bytes32(value: u8) -> [u8; 32] {
    [value; 32]
}

#[test]
fn duplicated_current_host_and_script_domains_match() {
    assert_eq!(
        host_hash::MULTI_ASSET_CLOSE_DOMAIN,
        wire::multi_asset_close::MULTI_ASSET_CLOSE_DOMAIN
    );
    assert_eq!(host_hash::PARTICIPANTS_DOMAIN, wire::PARTICIPANTS_DOMAIN);
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_STATE_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_STATE_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_UPDATE_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_UPDATE_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_REDUCED_RELEASE_DOMAIN,
        wire::factory_multi_asset::FACTORY_REDUCED_RELEASE_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_REDUCED_RELEASE_LOCALITY_DOMAIN,
        wire::factory_multi_asset::FACTORY_REDUCED_RELEASE_LOCALITY_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_ROOT_FUNDING_DOMAIN,
        wire::multi_asset::MULTI_ASSET_ROOT_FUNDING_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_STATE_DOMAIN,
        wire::multi_asset::MULTI_ASSET_STATE_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_VAULT_SET_DOMAIN,
        wire::multi_asset::MULTI_ASSET_VAULT_SET_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_OUTPOINT_SET_DOMAIN,
        wire::multi_asset::MULTI_ASSET_OUTPOINT_SET_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_DESCRIPTOR_DOMAIN,
        wire::multi_asset::MULTI_ASSET_DESCRIPTOR_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_FUNDING_CONTEXT_DOMAIN,
        wire::multi_asset::MULTI_ASSET_FUNDING_CONTEXT_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_SPLICE_DOMAIN,
        wire::multi_asset_splice::MULTI_ASSET_SPLICE_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_SPLICE_FLOW_DOMAIN,
        wire::multi_asset_splice::MULTI_ASSET_SPLICE_FLOW_DOMAIN
    );
    assert_eq!(
        morph_core::FACTORY_RIGHT_EMPTY_SUBTREE_DOMAIN,
        wire::FACTORY_RIGHT_EMPTY_DOMAIN
    );
}

#[test]
fn participants_commitment_matches_script_common() {
    let pubkey_0 = [2u8; wire::COMPRESSED_SECP256K1_PUBKEY_LEN];
    let pubkey_1 = [3u8; wire::COMPRESSED_SECP256K1_PUBKEY_LEN];
    let pubkeys = [pubkey_0.as_slice(), pubkey_1.as_slice()];

    assert_eq!(
        participants_commitment(2, &pubkeys),
        wire::participants_commitment(2, &pubkeys)
    );
}

#[test]
fn asset_registry_commitment_matches_script_common() {
    let registry = AssetRegistry {
        xudt_types: BTreeSet::from([bytes32(7), bytes32(42)]),
    };
    let hashes = [bytes32(7), bytes32(42)];
    let hash_refs = [hashes[0].as_slice(), hashes[1].as_slice()];

    assert_eq!(
        asset_registry_commitment(&registry),
        wire::asset_registry_commitment(&hash_refs).unwrap()
    );
}

#[test]
fn compact_right_proofs_match_the_current_script_locality_primitive() {
    use morph_core::{
        FactoryRight, FactoryRightId, FactoryRightKind, factory_right_key,
        factory_right_sparse_proof_compact, factory_right_sparse_root,
    };
    use wire::factory_multi_asset::{
        FactoryReducedReleaseRight, verify_factory_localized_right_change,
    };
    fn encoded(right: &FactoryRight) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&right.id.participant);
        raw.extend_from_slice(&right.id.subchannel);
        raw.push(match right.id.kind {
            FactoryRightKind::Balance => 0,
            FactoryRightKind::ReserveClaim => 1,
            FactoryRightKind::Membership => 2,
            FactoryRightKind::ExitPath => 3,
            FactoryRightKind::SponsorBudgetClaim => 4,
        });
        raw.push(u8::from(right.id.asset_type.is_some()));
        raw.extend_from_slice(&right.id.asset_type.unwrap_or([0; 32]));
        raw.extend_from_slice(&right.quantity.to_le_bytes());
        raw
    }
    let before = (0..12)
        .map(|i| FactoryRight {
            id: FactoryRightId {
                participant: bytes32(if i < 4 { 1 } else { 2 }),
                subchannel: bytes32(i),
                kind: FactoryRightKind::Balance,
                asset_type: None,
            },
            quantity: 100,
        })
        .collect::<Vec<_>>();
    let mut after = before.clone();
    after[0].quantity = 40;
    after[1].quantity = 160;
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();
    let keys = [
        factory_right_key(&before[0].id),
        factory_right_key(&before[1].id),
    ];
    for index in 0..2 {
        let b = factory_right_sparse_proof_compact(&before, &before[index].id).unwrap();
        let a = factory_right_sparse_proof_compact(&after, &after[index].id).unwrap();
        let mut raw = encoded(&b.right);
        raw.extend_from_slice(&encoded(&a.right));
        for proof in [&b, &a] {
            raw.extend_from_slice(&(proof.siblings.len() as u16).to_le_bytes());
            for sibling in &proof.siblings {
                raw.extend_from_slice(&sibling.depth.to_le_bytes());
                raw.extend_from_slice(&sibling.hash);
            }
        }
        let mut offset = 0;
        let parsed = FactoryReducedReleaseRight::parse_at(&raw, &mut offset).unwrap();
        assert_eq!(offset, raw.len());
        verify_factory_localized_right_change(
            &parsed,
            &bytes32(1),
            &before_root,
            &after_root,
            &[keys[1 - index]],
        )
        .unwrap();
        assert!(
            verify_factory_localized_right_change(
                &parsed,
                &bytes32(1),
                &before_root,
                &after_root,
                &[]
            )
            .is_err()
        );
    }
}
