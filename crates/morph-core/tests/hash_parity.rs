use std::collections::BTreeSet;

use morph_core::hash as host_hash;
use morph_core::{
    AssetRegistry, FactorySpliceHeader, FactorySpliceKind, FactoryVaultDelta,
    FactoryVaultDescriptor, Mode, Phase, SpliceAssetDelta, SpliceHeader, SpliceKind, StateHeader,
    VaultAsset, VaultAssetAmount, asset_registry_commitment, factory_vault_delta_commitment,
    factory_vault_descriptor_commitment, participants_commitment, splice_asset_delta_commitment,
    vault_descriptor_commitment,
};
use morph_script_common as wire;

fn bytes32(value: u8) -> [u8; 32] {
    [value; 32]
}

#[test]
fn duplicated_host_and_script_domains_match() {
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN
    );
    assert_eq!(host_hash::STATE_DOMAIN, wire::STATE_DOMAIN);
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_STATE_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_STATE_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN,
        wire::factory_multi_asset::FACTORY_MULTI_ASSET_ROOT_FUNDING_DOMAIN
    );
    assert_eq!(
        host_hash::MULTI_ASSET_ROOT_FUNDING_DOMAIN,
        wire::multi_asset::MULTI_ASSET_ROOT_FUNDING_DOMAIN
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
        host_hash::FUNDING_CONTEXT_DOMAIN,
        wire::FUNDING_CONTEXT_DOMAIN
    );
    assert_eq!(host_hash::PARTICIPANTS_DOMAIN, wire::PARTICIPANTS_DOMAIN);
    assert_eq!(host_hash::SPLICE_HEADER_DOMAIN, wire::SPLICE_HEADER_DOMAIN);
    assert_eq!(host_hash::SPLICE_DELTA_DOMAIN, wire::SPLICE_DELTA_DOMAIN);
    assert_eq!(
        host_hash::VAULT_DESCRIPTOR_DOMAIN,
        wire::VAULT_DESCRIPTOR_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_SPLICE_HEADER_DOMAIN,
        wire::FACTORY_SPLICE_HEADER_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_VAULT_DESCRIPTOR_DOMAIN,
        wire::FACTORY_VAULT_DESCRIPTOR_DOMAIN
    );
    assert_eq!(
        host_hash::FACTORY_VAULT_DELTA_DOMAIN,
        wire::FACTORY_VAULT_DELTA_DOMAIN
    );
    assert_eq!(
        host_hash::VAULT_OUTPOINT_COMMITMENT_DOMAIN,
        wire::VAULT_OUTPOINT_COMMITMENT_DOMAIN
    );
}

fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

fn wire_asset(kind: u8, asset_type: [u8; 32], amount: u128, len: usize) -> Vec<u8> {
    let mut raw = vec![0u8; len];
    raw[0] = kind;
    raw[1..33].copy_from_slice(&asset_type);
    put_u128(&mut raw, 33, amount);
    raw
}

struct WireDeltaInput {
    kind: u8,
    asset_type: [u8; 32],
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    signed_fee: Option<u128>,
    len: usize,
}

fn wire_delta(input: WireDeltaInput) -> Vec<u8> {
    let mut raw = vec![0u8; input.len];
    raw[0] = input.kind;
    raw[1..33].copy_from_slice(&input.asset_type);
    put_u128(&mut raw, 33, input.old_amount);
    put_u128(&mut raw, 49, input.new_amount);
    put_u128(&mut raw, 65, input.external_input);
    put_u128(&mut raw, 81, input.withdrawal);
    if let Some(signed_fee) = input.signed_fee {
        put_u128(&mut raw, 97, signed_fee);
    }
    raw
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
fn state_header_signing_digest_matches_script_common() {
    let header = StateHeader {
        protocol_version: 1,
        chain_id: bytes32(1),
        signature_scheme_id: 1,
        channel_id: bytes32(2),
        funding_epoch: 3,
        funding_anchor: bytes32(4),
        vault_set_commitment: bytes32(5),
        state_number: 6,
        mode: Mode::BilateralPlain,
        phase: Phase::Settling,
        participants_commitment: bytes32(7),
        asset_registry_commitment: bytes32(8),
        settlement_descriptor_commitment: bytes32(9),
        descriptor_version: 10,
        vault_materialisation_root: bytes32(11),
        vault_outpoint_commitment: bytes32(14),
        challenge_policy_commitment: bytes32(12),
        state_layout_version: 13,
    };
    let raw = wire::encode_state_header(&wire::StateHeaderInput {
        protocol_version: header.protocol_version,
        chain_id: header.chain_id,
        signature_scheme_id: header.signature_scheme_id,
        channel_id: header.channel_id,
        funding_epoch: header.funding_epoch,
        funding_anchor: header.funding_anchor,
        vault_set_commitment: header.vault_set_commitment,
        state_number: header.state_number,
        mode: header.mode.as_u8(),
        phase: header.phase.as_u8(),
        participants_commitment: header.participants_commitment,
        asset_registry_commitment: header.asset_registry_commitment,
        settlement_descriptor_commitment: header.settlement_descriptor_commitment,
        descriptor_version: header.descriptor_version,
        vault_materialisation_root: header.vault_materialisation_root,
        vault_outpoint_commitment: header.vault_outpoint_commitment,
        challenge_policy_commitment: header.challenge_policy_commitment,
        state_layout_version: header.state_layout_version,
    });
    let wire_header = wire::StateHeader::parse(&raw).unwrap();

    assert_eq!(header.signing_digest(), wire_header.signing_digest());
}

#[test]
fn splice_header_signing_digest_matches_script_common() {
    let header = SpliceHeader {
        protocol_version: 1,
        chain_id: bytes32(1),
        signature_scheme_id: 1,
        channel_id: bytes32(2),
        old_funding_anchor: bytes32(3),
        new_funding_anchor: bytes32(4),
        old_funding_epoch: 5,
        new_funding_epoch: 6,
        base_state_number: 7,
        splice_number: 8,
        kind: SpliceKind::In,
        old_vault_commitment: bytes32(9),
        new_vault_commitment: bytes32(10),
        asset_delta_commitment: bytes32(11),
        participants_commitment: bytes32(12),
        vault_materialisation_root: bytes32(14),
        new_vault_materialisation_root: bytes32(15),
        old_vault_outpoint_commitment: bytes32(16),
        new_vault_outpoint_commitment: bytes32(17),
        withdrawal_lock_hash: [0; 32],
        challenge_policy_commitment: bytes32(13),
    };
    let mut raw = [0u8; wire::SPLICE_HEADER_LEN];
    put_u16(&mut raw, 0, header.protocol_version);
    raw[2..34].copy_from_slice(&header.chain_id);
    put_u16(&mut raw, 34, header.signature_scheme_id);
    raw[36..68].copy_from_slice(&header.channel_id);
    raw[68..100].copy_from_slice(&header.old_funding_anchor);
    raw[100..132].copy_from_slice(&header.new_funding_anchor);
    put_u64(&mut raw, 132, header.old_funding_epoch);
    put_u64(&mut raw, 140, header.new_funding_epoch);
    put_u64(&mut raw, 148, header.base_state_number);
    put_u64(&mut raw, 156, header.splice_number);
    raw[164] = header.kind.as_u8();
    raw[165..197].copy_from_slice(&header.old_vault_commitment);
    raw[197..229].copy_from_slice(&header.new_vault_commitment);
    raw[229..261].copy_from_slice(&header.asset_delta_commitment);
    raw[261..293].copy_from_slice(&header.participants_commitment);
    raw[293..325].copy_from_slice(&header.vault_materialisation_root);
    raw[325..357].copy_from_slice(&header.new_vault_materialisation_root);
    raw[357..389].copy_from_slice(&header.challenge_policy_commitment);
    raw[389..421].copy_from_slice(&header.old_vault_outpoint_commitment);
    raw[421..453].copy_from_slice(&header.new_vault_outpoint_commitment);
    raw[453..485].copy_from_slice(&header.withdrawal_lock_hash);
    let wire_header = wire::SpliceHeader::parse(&raw).unwrap();

    assert_eq!(header.signing_digest(), wire_header.signing_digest());
}

#[test]
fn factory_splice_header_signing_digest_matches_script_common() {
    let header = FactorySpliceHeader {
        protocol_version: 1,
        chain_id: bytes32(1),
        signature_scheme_id: 1,
        factory_id: bytes32(2),
        old_update_number: 3,
        new_update_number: 4,
        old_state_root: bytes32(5),
        new_state_root: bytes32(6),
        old_access_manifest_root: bytes32(7),
        new_access_manifest_root: bytes32(8),
        kind: FactorySpliceKind::Out,
        vault_delta_commitment: bytes32(9),
        non_interference_digest: bytes32(10),
        participants_commitment: bytes32(11),
        old_vault_materialisation_root: bytes32(12),
        new_vault_materialisation_root: bytes32(13),
        old_vault_outpoint_commitment: bytes32(14),
        new_vault_outpoint_commitment: bytes32(15),
        withdrawal_lock_hash: bytes32(16),
    };
    let mut raw = [0u8; wire::FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut raw, 0, header.protocol_version);
    raw[2..34].copy_from_slice(&header.chain_id);
    put_u16(&mut raw, 34, header.signature_scheme_id);
    raw[36..68].copy_from_slice(&header.factory_id);
    put_u64(&mut raw, 68, header.old_update_number);
    put_u64(&mut raw, 76, header.new_update_number);
    raw[84..116].copy_from_slice(&header.old_state_root);
    raw[116..148].copy_from_slice(&header.new_state_root);
    raw[148..180].copy_from_slice(&header.old_access_manifest_root);
    raw[180..212].copy_from_slice(&header.new_access_manifest_root);
    raw[212] = header.kind.as_u8();
    raw[213..245].copy_from_slice(&header.vault_delta_commitment);
    raw[245..277].copy_from_slice(&header.non_interference_digest);
    raw[277..309].copy_from_slice(&header.participants_commitment);
    raw[309..341].copy_from_slice(&header.old_vault_materialisation_root);
    raw[341..373].copy_from_slice(&header.new_vault_materialisation_root);
    raw[373..405].copy_from_slice(&header.old_vault_outpoint_commitment);
    raw[405..437].copy_from_slice(&header.new_vault_outpoint_commitment);
    raw[437..469].copy_from_slice(&header.withdrawal_lock_hash);
    let wire_header = wire::FactorySpliceHeader::parse(&raw).unwrap();

    assert_eq!(header.signing_digest(), wire_header.signing_digest());
}

#[test]
fn vault_descriptor_commitments_match_script_common() {
    let descriptor = morph_core::VaultDescriptor {
        funding_anchor: bytes32(1),
        assets: vec![
            VaultAssetAmount {
                asset: VaultAsset::Ckb,
                amount: 100,
            },
            VaultAssetAmount {
                asset: VaultAsset::Xudt(bytes32(2)),
                amount: 200,
            },
        ],
    };
    let mut raw = [0u8; wire::SPLICE_VAULT_DESCRIPTOR_LEN];
    raw[0..32].copy_from_slice(&descriptor.funding_anchor);
    put_u16(&mut raw, 32, 2);
    raw[34..34 + wire::SPLICE_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(&wire_asset(
        wire::VAULT_ASSET_KIND_CKB,
        [0u8; 32],
        100,
        wire::SPLICE_VAULT_ASSET_AMOUNT_LEN,
    ));
    raw[34 + wire::SPLICE_VAULT_ASSET_AMOUNT_LEN..34 + 2 * wire::SPLICE_VAULT_ASSET_AMOUNT_LEN]
        .copy_from_slice(&wire_asset(
            wire::VAULT_ASSET_KIND_XUDT,
            bytes32(2),
            200,
            wire::SPLICE_VAULT_ASSET_AMOUNT_LEN,
        ));
    let wire_descriptor = wire::SpliceVaultDescriptor::parse(&raw).unwrap();

    assert_eq!(
        vault_descriptor_commitment(&descriptor),
        wire_descriptor.commitment().unwrap()
    );
}

#[test]
fn factory_vault_descriptor_commitments_match_script_common() {
    let descriptor = FactoryVaultDescriptor {
        factory_id: bytes32(1),
        assets: vec![
            VaultAssetAmount {
                asset: VaultAsset::Ckb,
                amount: 100,
            },
            VaultAssetAmount {
                asset: VaultAsset::Xudt(bytes32(2)),
                amount: 200,
            },
        ],
    };
    let mut raw = [0u8; wire::FACTORY_VAULT_DESCRIPTOR_LEN];
    raw[0..32].copy_from_slice(&descriptor.factory_id);
    put_u16(&mut raw, 32, 2);
    raw[34..34 + wire::FACTORY_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(&wire_asset(
        wire::VAULT_ASSET_KIND_CKB,
        [0u8; 32],
        100,
        wire::FACTORY_VAULT_ASSET_AMOUNT_LEN,
    ));
    raw[34 + wire::FACTORY_VAULT_ASSET_AMOUNT_LEN..34 + 2 * wire::FACTORY_VAULT_ASSET_AMOUNT_LEN]
        .copy_from_slice(&wire_asset(
            wire::VAULT_ASSET_KIND_XUDT,
            bytes32(2),
            200,
            wire::FACTORY_VAULT_ASSET_AMOUNT_LEN,
        ));
    let wire_descriptor = wire::FactoryVaultDescriptor::parse(&raw).unwrap();

    assert_eq!(
        factory_vault_descriptor_commitment(&descriptor),
        wire_descriptor.commitment().unwrap()
    );
}

#[test]
fn splice_delta_commitments_match_script_common() {
    let deltas = vec![
        SpliceAssetDelta {
            asset: VaultAsset::Ckb,
            old_amount: 100,
            new_amount: 120,
            external_input: 20,
            withdrawal: 0,
            signed_fee: 1,
        },
        SpliceAssetDelta {
            asset: VaultAsset::Xudt(bytes32(2)),
            old_amount: 200,
            new_amount: 240,
            external_input: 40,
            withdrawal: 0,
            signed_fee: 2,
        },
    ];
    let mut raw = [0u8; wire::SPLICE_ASSET_DELTAS_LEN];
    put_u16(&mut raw, 0, 2);
    raw[2..2 + wire::SPLICE_ASSET_DELTA_LEN].copy_from_slice(&wire_delta(WireDeltaInput {
        kind: wire::VAULT_ASSET_KIND_CKB,
        asset_type: [0u8; 32],
        old_amount: 100,
        new_amount: 120,
        external_input: 20,
        withdrawal: 0,
        signed_fee: Some(1),
        len: wire::SPLICE_ASSET_DELTA_LEN,
    }));
    raw[2 + wire::SPLICE_ASSET_DELTA_LEN..2 + 2 * wire::SPLICE_ASSET_DELTA_LEN].copy_from_slice(
        &wire_delta(WireDeltaInput {
            kind: wire::VAULT_ASSET_KIND_XUDT,
            asset_type: bytes32(2),
            old_amount: 200,
            new_amount: 240,
            external_input: 40,
            withdrawal: 0,
            signed_fee: Some(2),
            len: wire::SPLICE_ASSET_DELTA_LEN,
        }),
    );
    let wire_deltas = wire::SpliceAssetDeltas::parse(&raw).unwrap();

    assert_eq!(
        splice_asset_delta_commitment(&deltas),
        wire_deltas.commitment().unwrap()
    );
}

#[test]
fn factory_vault_delta_commitments_match_script_common() {
    let deltas = vec![
        FactoryVaultDelta {
            asset: VaultAsset::Ckb,
            old_amount: 100,
            new_amount: 120,
            external_input: 20,
            withdrawal: 0,
        },
        FactoryVaultDelta {
            asset: VaultAsset::Xudt(bytes32(2)),
            old_amount: 200,
            new_amount: 240,
            external_input: 40,
            withdrawal: 0,
        },
    ];
    let mut raw = [0u8; wire::FACTORY_VAULT_DELTAS_LEN];
    put_u16(&mut raw, 0, 2);
    raw[2..2 + wire::FACTORY_VAULT_DELTA_LEN].copy_from_slice(&wire_delta(WireDeltaInput {
        kind: wire::VAULT_ASSET_KIND_CKB,
        asset_type: [0u8; 32],
        old_amount: 100,
        new_amount: 120,
        external_input: 20,
        withdrawal: 0,
        signed_fee: None,
        len: wire::FACTORY_VAULT_DELTA_LEN,
    }));
    raw[2 + wire::FACTORY_VAULT_DELTA_LEN..2 + 2 * wire::FACTORY_VAULT_DELTA_LEN].copy_from_slice(
        &wire_delta(WireDeltaInput {
            kind: wire::VAULT_ASSET_KIND_XUDT,
            asset_type: bytes32(2),
            old_amount: 200,
            new_amount: 240,
            external_input: 40,
            withdrawal: 0,
            signed_fee: None,
            len: wire::FACTORY_VAULT_DELTA_LEN,
        }),
    );
    let wire_deltas = wire::FactoryVaultDeltas::parse(&raw).unwrap();

    assert_eq!(
        factory_vault_delta_commitment(&deltas),
        wire_deltas.commitment().unwrap()
    );
}

#[test]
fn multi_right_update_domains_match_script_common() {
    assert_eq!(
        morph_core::validation::FACTORY_MULTI_RIGHT_DOMAIN,
        wire::FACTORY_MULTI_RIGHT_UPDATE_DOMAIN
    );
    assert_eq!(
        morph_core::validation::FACTORY_RIGHT_EMPTY_SUBTREE_DOMAIN,
        wire::FACTORY_RIGHT_EMPTY_DOMAIN
    );
}

#[test]
fn multi_right_compact_proof_roots_match_script_common() {
    use morph_core::{
        FactoryRight, FactoryRightId, FactoryRightKind, factory_right_sparse_proof_compact,
        factory_right_sparse_root,
    };

    fn wire_right(right: &FactoryRight) -> [u8; wire::FACTORY_RIGHT_LEN] {
        let mut raw = [0u8; wire::FACTORY_RIGHT_LEN];
        raw[..32].copy_from_slice(&right.id.participant);
        raw[32..64].copy_from_slice(&right.id.subchannel);
        raw[64] = match right.id.kind {
            FactoryRightKind::Balance => 0,
            FactoryRightKind::ReserveClaim => 1,
            FactoryRightKind::Membership => 2,
            FactoryRightKind::ExitPath => 3,
            FactoryRightKind::SponsorBudgetClaim => 4,
        };
        if let Some(asset_type) = right.id.asset_type {
            raw[65] = 1;
            raw[66..98].copy_from_slice(&asset_type);
        }
        raw[98..114].copy_from_slice(&right.quantity.to_le_bytes());
        raw
    }

    let right =
        |participant: u8, subchannel: u8, kind: FactoryRightKind, quantity: u128| FactoryRight {
            id: FactoryRightId {
                participant: bytes32(participant),
                subchannel: bytes32(subchannel),
                kind,
                asset_type: None,
            },
            quantity,
        };
    let before = vec![
        right(1, 10, FactoryRightKind::Balance, 100),
        right(1, 10, FactoryRightKind::ReserveClaim, 50),
        right(1, 10, FactoryRightKind::SponsorBudgetClaim, 20),
        right(2, 10, FactoryRightKind::Balance, 100),
        right(2, 10, FactoryRightKind::ReserveClaim, 50),
    ];
    let mut after = before.clone();
    after[0].quantity = 60;
    after[1].quantity = 80;
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();

    let mut ids = [before[0].id.clone(), before[1].id.clone()];
    ids.sort();

    let participant_count = 2u8;
    let right_count = 2u8;
    let mut body =
        vec![0u8; wire::factory_multi_right_update_witness_len(participant_count, right_count)];
    put_u16(
        &mut body,
        0,
        wire::FACTORY_MULTI_RIGHT_UPDATE_WITNESS_VERSION,
    );
    body[2] = participant_count;
    body[3] = participant_count;
    body[4] = wire::FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    body[5] = right_count;
    for index in 0..participant_count as usize {
        let offset = 8 + index * wire::FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
        body[offset..offset + 32].fill((index + 1) as u8);
        body[offset + 32..offset + 32 + wire::COMPRESSED_SECP256K1_PUBKEY_LEN]
            .fill((index + 2) as u8);
        body[offset + 32 + wire::COMPRESSED_SECP256K1_PUBKEY_LEN] = u8::from(index == 0);
    }
    let touched_offset =
        8 + participant_count as usize * wire::FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    body[touched_offset..touched_offset + 32].fill(1);
    put_u16(
        &mut body,
        touched_offset + 32,
        wire::FACTORY_COMPACT_PROOF_MAX_SIBLINGS as u16,
    );
    let rights_before_offset = touched_offset + 32 + 2 + 2;
    let rights_after_offset = rights_before_offset + right_count as usize * wire::FACTORY_RIGHT_LEN;
    let proofs_offset = rights_after_offset + right_count as usize * wire::FACTORY_RIGHT_LEN;
    for (index, id) in ids.iter().enumerate() {
        let before_proof = factory_right_sparse_proof_compact(&before, id).unwrap();
        let after_proof = factory_right_sparse_proof_compact(&after, id).unwrap();
        let before_offset = rights_before_offset + index * wire::FACTORY_RIGHT_LEN;
        body[before_offset..before_offset + wire::FACTORY_RIGHT_LEN]
            .copy_from_slice(&wire_right(&before_proof.right));
        let after_offset = rights_after_offset + index * wire::FACTORY_RIGHT_LEN;
        body[after_offset..after_offset + wire::FACTORY_RIGHT_LEN]
            .copy_from_slice(&wire_right(&after_proof.right));
        for (after_side, proof) in [(false, &before_proof), (true, &after_proof)] {
            let proof_offset = proofs_offset
                + (right_count as usize * usize::from(after_side) + index)
                    * wire::FACTORY_COMPACT_PROOF_LEN;
            put_u16(&mut body, proof_offset, proof.siblings.len() as u16);
            for (pair, sibling) in proof.siblings.iter().enumerate() {
                let pair_offset = proof_offset + 2 + pair * wire::FACTORY_COMPACT_PROOF_PAIR_LEN;
                put_u16(&mut body, pair_offset, sibling.depth);
                body[pair_offset + 2..pair_offset + 2 + 32].copy_from_slice(&sibling.hash);
            }
        }
    }

    let witness = wire::FactoryMultiRightUpdateWitness::parse(&body).unwrap();
    for index in 0..right_count as usize {
        assert_eq!(witness.proof_root(false, index).unwrap(), before_root);
        assert_eq!(witness.proof_root(true, index).unwrap(), after_root);
    }
}
