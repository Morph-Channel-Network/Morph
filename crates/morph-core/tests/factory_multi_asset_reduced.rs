use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::*;
use morph_script_common::factory_multi_asset::FactoryReducedReleaseWitness;
#[path = "support/factory_reduced.rs"]
mod support;
use support::*;

#[test]
fn current_factory_release_accepts_one_member_and_separate_asset_lanes() {
    let (plan, key) = fixture_with_unlisted_change(false);
    let raw = plan.encode_witness(&sign(&plan, &key)).unwrap();
    let proof = FactoryReducedReleaseWitness::parse(&raw).unwrap();
    proof.verify().unwrap();
    assert_eq!(proof.member_count(), 2);
    assert_eq!(proof.payout_count(), 2);
    assert_eq!(proof.touched_participant(), [1; 32]);
}

#[test]
fn reduced_dictionary_references_and_shared_right_identity_are_canonical() {
    use morph_script_common::script_table::{self, ScriptTable};
    let (plan, key) = fixture_with_unlisted_change(false);
    let raw = plan.encode_witness(&sign(&plan, &key)).unwrap();
    let proof = FactoryReducedReleaseWitness::parse(&raw).unwrap();
    let start = proof.retained().as_bytes().as_ptr() as usize - raw.as_ptr() as usize
        + proof.retained().as_bytes().len();
    let len = u32::from_le_bytes(raw[28..32].try_into().unwrap()) as usize;
    let table = ScriptTable::parse(&raw[start..start + len]).unwrap();
    let payout_offsets: Vec<_> = (0..proof.payout_count())
        .map(|i| proof.payout(i).unwrap().as_bytes().as_ptr() as usize - raw.as_ptr() as usize)
        .collect();
    for mutation in 0..4 {
        let mut bad = raw.clone();
        match mutation {
            0 => bad[34..36].copy_from_slice(&(table.count() as u16).to_le_bytes()),
            1 => bad[payout_offsets[0] + 65..payout_offsets[0] + 67]
                .copy_from_slice(&(table.count() as u16).to_le_bytes()),
            2 => bad[start + len] = table.count() as u8,
            _ => bad[8..10].copy_from_slice(&1u16.to_le_bytes()),
        }
        assert!(FactoryReducedReleaseWitness::parse(&bad).is_err());
    }
    let extra = script(&[255; 40], 250);
    let mut entries: Vec<_> = (0..table.count())
        .map(|i| table.script(i).unwrap())
        .collect();
    entries.push(&extra);
    let expanded = script_table::encode(&entries).unwrap();
    let expanded_view = ScriptTable::parse(&expanded).unwrap();
    let remap = |i: usize| expanded_view.index_of(table.script(i).unwrap()).unwrap();
    let mut bad = raw.clone();
    let factory = u16::from_le_bytes(raw[34..36].try_into().unwrap()) as usize;
    bad[34..36].copy_from_slice(&(remap(factory) as u16).to_le_bytes());
    let count = u16::from_le_bytes(raw[32..34].try_into().unwrap()) as usize;
    for i in 0..count {
        bad[start + len + i] = remap(raw[start + len + i] as usize) as u8;
    }
    for offset in payout_offsets {
        let i = u16::from_le_bytes(raw[offset + 65..offset + 67].try_into().unwrap()) as usize;
        bad[offset + 65..offset + 67].copy_from_slice(&(remap(i) as u16).to_le_bytes());
    }
    bad[28..32].copy_from_slice(&(expanded.len() as u32).to_le_bytes());
    bad.splice(start..start + len, expanded);
    assert!(
        FactoryReducedReleaseWitness::parse(&bad).is_err(),
        "no unused dictionary entries"
    );
    let mut changed = plan;
    changed.rights[0].after.right.id.participant = [9; 32];
    assert!(
        changed.encode_unsigned().is_err(),
        "never discard a different after identity"
    );
}
#[test]
fn current_factory_release_rejects_unlisted_right_mutation_even_with_recomputed_roots() {
    let (plan, _) = fixture_with_unlisted_change(true);
    assert!(plan.encode_unsigned().is_err());
}
#[test]
fn current_factory_release_exact_tx_signature_survives_no_hash_fixed_point() {
    let (mut plan, key) = fixture_with_unlisted_change(false);
    let locality = plan.after.non_interference_digest;
    let signed = plan.encode_witness(&sign(&plan, &key)).unwrap();
    let mut changed = signed.clone();
    changed[72] = 99;
    assert!(
        FactoryReducedReleaseWitness::parse(&changed)
            .unwrap()
            .verify()
            .is_err()
    );
    plan.transaction_hash = [99; 32];
    plan.set_locality_digest().unwrap();
    assert_eq!(plan.after.non_interference_digest, locality);
    assert!(plan.encode_witness(&sign(&plan, &key)).is_ok());
}
#[test]
fn current_factory_release_rejects_other_signer_and_old_witness_magic() {
    let (plan, _) = fixture_with_unlisted_change(false);
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    assert!(plan.encode_witness(&sign(&plan, &key)).is_err());
    let mut raw = plan.encode_unsigned().unwrap();
    raw[..8].copy_from_slice(b"MORPHW!!");
    assert!(FactoryReducedReleaseWitness::parse(&raw).is_err());
}
#[test]
fn current_factory_release_rejects_reserve_borrow_and_capacity_claim_omission() {
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.retained.vaults[0].value.reserve -= CKB;
    plan.retained.vaults[0].value.business_ckb += CKB;
    plan.after.content_root = plan.retained.commitment().unwrap();
    plan.set_locality_digest().unwrap();
    assert!(plan.encode_unsigned().is_err());
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.rights.remove(0);
    plan.set_locality_digest().unwrap();
    assert!(plan.encode_unsigned().is_err());
}
#[test]
fn current_factory_release_rejects_output_alias_and_type_confusion() {
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.payouts[1].output_index = 3;
    plan.set_locality_digest().unwrap();
    assert!(plan.encode_unsigned().is_err());
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.payouts[1].asset = VaultAsset::Xudt([99; 32]);
    plan.set_locality_digest().unwrap();
    assert!(plan.encode_unsigned().is_err());
}
#[test]
fn current_factory_release_rejects_peer_claim_and_noncanonical_membership() {
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.signer_index = 1;
    plan.set_locality_digest().unwrap();
    assert!(plan.encode_unsigned().is_err());
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.members.swap(0, 1);
    plan.set_locality_digest().unwrap();
    assert!(plan.encode_unsigned().is_err());
}
#[test]
fn current_factory_release_handles_eight_types_sixteen_members_with_one_signature() {
    let (mut plan, key) = fixture_with_unlisted_change(false);
    plan.members = (1u8..=16)
        .map(|i| {
            let key = SigningKey::from_bytes((&[i; 32]).into()).unwrap();
            FactoryParticipantKey {
                participant: [i; 32],
                pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
            }
        })
        .collect();
    let entries: Vec<_> = plan
        .members
        .iter()
        .map(|m| (m.participant.as_slice(), m.pubkey_sec1.as_slice()))
        .collect();
    let membership = morph_script_common::factory_participants_commitment(16, &entries);
    plan.before.participants_commitment = membership;
    plan.after.participants_commitment = membership;
    plan.type_scripts = (50u8..58)
        .map(|i| {
            let script = script(&[], i);
            MultiAssetTypeScript {
                type_hash: blake2b256(&script),
                script,
            }
        })
        .collect();
    plan.type_scripts.sort_by_key(|s| s.type_hash);
    let lock_hash = blake2b256(&plan.factory_lock_script);
    plan.source.vaults = plan
        .type_scripts
        .iter()
        .map(|s| MultiAssetVault {
            asset: VaultAsset::Xudt(s.type_hash),
            lock_hash,
            value: MultiAssetValue {
                reserve: 600 * CKB,
                business_ckb: 0,
                amount: 100,
            },
        })
        .collect();
    plan.retained.vaults = plan
        .type_scripts
        .iter()
        .map(|s| MultiAssetVault {
            asset: VaultAsset::Xudt(s.type_hash),
            lock_hash,
            value: MultiAssetValue {
                reserve: 450 * CKB,
                business_ckb: 0,
                amount: 70,
            },
        })
        .collect();
    plan.payouts = plan
        .type_scripts
        .iter()
        .enumerate()
        .map(|(i, s)| FactoryReducedReleasePayout {
            asset: VaultAsset::Xudt(s.type_hash),
            value: MultiAssetValue {
                reserve: 150 * CKB,
                business_ckb: 0,
                amount: 30,
            },
            lock_script: script(&[], 44),
            output_index: 9 + i as u16,
        })
        .collect();
    let mut before_rights = vec![claim(1, None, 3000 * CKB as u128)];
    before_rights.extend(
        plan.type_scripts
            .iter()
            .map(|s| claim(1, Some(s.type_hash), 60)),
    );
    before_rights.push(claim(2, None, 1800 * CKB as u128));
    before_rights.extend(
        plan.type_scripts
            .iter()
            .map(|s| claim(2, Some(s.type_hash), 40)),
    );
    let mut after_rights = before_rights.clone();
    after_rights[0].quantity -= 1200 * CKB as u128;
    for right in after_rights.iter_mut().take(9).skip(1) {
        right.quantity -= 30;
    }
    plan.rights = before_rights
        .iter()
        .take(9)
        .map(|r| FactoryReducedReleaseRight {
            before: factory_right_sparse_proof_compact(&before_rights, &r.id).unwrap(),
            after: factory_right_sparse_proof_compact(&after_rights, &r.id).unwrap(),
        })
        .collect();
    plan.source_outpoints = (1..=8)
        .map(|index| MultiAssetOutPoint {
            tx_hash: [9; 32],
            index,
        })
        .collect();
    plan.before.vault_count = 8;
    plan.after.vault_count = 8;
    plan.before.content_root = plan.source.commitment().unwrap();
    plan.after.content_root = plan.retained.commitment().unwrap();
    plan.before.outpoint_root =
        multi_asset_outpoint_commitment(&plan.source, &plan.source_outpoints).unwrap();
    plan.before.state_root = factory_right_sparse_root(&before_rights).unwrap();
    plan.after.state_root = factory_right_sparse_root(&after_rights).unwrap();
    plan.set_locality_digest().unwrap();
    let encoded = plan.encode_witness(&sign(&plan, &key)).unwrap();
    let view = FactoryReducedReleaseWitness::parse(&encoded).unwrap();
    view.verify().unwrap();
    assert_eq!(view.right_count(), 9);
    assert_eq!(view.payout_count(), 8);
    assert_eq!(view.member_count(), 16);
    assert!(
        encoded.len() <= morph_script_common::factory_multi_asset::FACTORY_REDUCED_RELEASE_MAX_LEN
    );
}

fn initial_snapshot(plan: &FactoryMultiAssetReducedRelease) -> FactoryRightsSnapshot {
    let token = match plan.source.vaults[1].asset {
        VaultAsset::Xudt(hash) => hash,
        _ => unreachable!(),
    };
    FactoryRightsSnapshot {
        chain_id: plan.before.chain_id,
        factory_id: plan.before.factory_id,
        update_number: plan.before.update_number,
        state_root: plan.before.state_root,
        rights: vec![
            claim(1, None, 900 * CKB as u128),
            claim(1, Some(token), 60),
            claim(2, None, 820 * CKB as u128),
            claim(2, Some(token), 40),
        ],
    }
}
#[test]
fn uninvolved_factory_member_refreshes_current_proof_from_public_frame_without_peer_data() {
    let (plan, key) = fixture_with_unlisted_change(false);
    let frame = plan.encode_witness(&sign(&plan, &key)).unwrap();
    let initial = initial_snapshot(&plan);
    initial.validate().unwrap();
    let own = initial.rights[3].id.clone();
    let old_proof = initial.proof(&own).unwrap();
    assert!(
        verify_factory_right_compact_proof(plan.after.state_root, &old_proof).is_err(),
        "old proof is stale when sibling changes"
    );
    let refreshed = initial.apply_transition(&frame).unwrap();
    let current = refreshed.proof(&own).unwrap();
    verify_factory_right_compact_proof(plan.after.state_root, &current).unwrap();
    assert_eq!(current.right, old_proof.right);
    assert_eq!(refreshed.update_number, plan.after.update_number);
    assert!(
        refreshed.apply_transition(&frame).is_err(),
        "replayed prior transition cannot advance local evidence"
    );
}
#[test]
fn factory_proof_refresh_rejects_incomplete_snapshot_and_requires_delivered_full_root_data() {
    let (mut plan, _) = fixture_with_unlisted_change(false);
    let initial = initial_snapshot(&plan);
    let mut incomplete = initial.clone();
    incomplete.rights.pop();
    assert!(incomplete.validate().is_err());
    let mut delivered = initial.rights.clone();
    for change in &plan.rights {
        let i = delivered
            .iter()
            .position(|r| r.id == change.after.right.id)
            .unwrap();
        delivered[i] = change.after.right.clone();
    }
    plan.operation = FactoryTransitionOperation::FullCustody;
    plan.rights.clear();
    plan.set_locality_digest().unwrap();
    let digest = plan.signing_digest().unwrap();
    let signatures: Vec<[u8; 64]> = (1u8..=2)
        .map(|i| {
            let key = SigningKey::from_bytes((&[i; 32]).into()).unwrap();
            let signature: Signature = key.sign_prehash(&digest).unwrap();
            signature.to_bytes().into()
        })
        .collect();
    let frame = plan.encode_authorized(&signatures).unwrap();
    assert_eq!(
        initial.apply_transition(&frame),
        Err(FactoryRightsRefreshError::FullSnapshotRequired)
    );
    let next = initial
        .accept_full_snapshot(&plan.after, delivered)
        .unwrap();
    assert_eq!(next.state_root, plan.after.state_root);
    assert!(next.proof(&initial.rights[3].id).is_ok());
}

fn metadata_with_rights(
    before: Vec<FactoryRight>,
    after: Vec<FactoryRight>,
    ids: Vec<FactoryRightId>,
) -> FactoryMultiAssetReducedRelease {
    let (mut plan, _) = fixture_with_unlisted_change(false);
    plan.operation = FactoryTransitionOperation::ReducedRights;
    plan.retained = plan.source.clone();
    plan.payouts.clear();
    plan.before.state_root = factory_right_sparse_root(&before).unwrap();
    plan.after.state_root = factory_right_sparse_root(&after).unwrap();
    plan.after.content_root = plan.before.content_root;
    plan.after.outpoint_root = plan.before.outpoint_root;
    plan.rights = ids
        .iter()
        .map(|id| FactoryReducedReleaseRight {
            before: factory_right_sparse_proof_compact(&before, id).unwrap(),
            after: factory_right_sparse_proof_compact(&after, id).unwrap(),
        })
        .collect();
    plan.set_locality_digest().unwrap();
    plan
}
#[test]
fn reduced_metadata_preserves_value_kind_rebalancing_but_rejects_cross_asset_mint() {
    let (original, key) = fixture_with_unlisted_change(false);
    let snapshot = initial_snapshot(&original);
    let token = snapshot.rights[1].id.asset_type;
    let mut before = snapshot.rights.clone();
    before[0].quantity = 800 * CKB as u128;
    let mut balance = claim(1, None, 100 * CKB as u128);
    balance.id.kind = FactoryRightKind::Balance;
    before.push(balance.clone());
    before.sort_by(|a, b| a.id.cmp(&b.id));
    let mut after = before.clone();
    let i = after.iter().position(|r| r.id == balance.id).unwrap();
    after[i].quantity -= 10 * CKB as u128;
    let reserve = claim(1, None, 0).id;
    let j = after.iter().position(|r| r.id == reserve).unwrap();
    after[j].quantity += 10 * CKB as u128;
    let plan = metadata_with_rights(before, after, vec![balance.id, reserve]);
    assert!(plan.encode_witness(&sign(&plan, &key)).is_ok());
    let before = snapshot.rights;
    let mut after = before.clone();
    after[0].quantity -= 1;
    after[1].quantity += 1;
    assert_eq!(after[1].id.asset_type, token);
    let plan = metadata_with_rights(
        before.clone(),
        after,
        vec![before[0].id.clone(), before[1].id.clone()],
    );
    assert!(plan.signing_digest().is_err());
}
