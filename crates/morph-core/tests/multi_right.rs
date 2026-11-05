use morph_core::{
    Bytes32, FactoryCompactMerkleSibling, FactoryCompactRightProof, FactoryRight, FactoryRightId,
    FactoryRightKind, factory_empty_subtree_hash, factory_right_sparse_proof,
    factory_right_sparse_proof_compact, factory_right_sparse_root,
    verify_factory_right_compact_proof,
};
use morph_script_common::FACTORY_COMPACT_PROOF_MAX_SIBLINGS;
use proptest::prelude::*;

#[path = "support/factory_reduced.rs"]
mod support;

// A test case records only the changed proofs. Authorization and all wire
// semantics are exercised through the production current Factory frame.
struct CurrentRightsUpdate {
    before_root: Bytes32,
    after_root: Bytes32,
    before: Vec<FactoryCompactRightProof>,
    after: Vec<FactoryCompactRightProof>,
}
fn validate_current_rights_update(
    update: &CurrentRightsUpdate,
) -> morph_core::MultiAssetResult<Vec<u8>> {
    let (mut plan, _) = support::fixture_with_unlisted_change(false);
    plan.operation = morph_core::FactoryTransitionOperation::ReducedRights;
    plan.before.state_root = update.before_root;
    plan.after.state_root = update.after_root;
    plan.after.content_root = plan.before.content_root;
    plan.after.outpoint_root = plan.before.outpoint_root;
    plan.retained = plan.source.clone();
    plan.payouts.clear();
    plan.rights = update
        .before
        .iter()
        .zip(&update.after)
        .map(|(before, after)| morph_core::FactoryReducedReleaseRight {
            before: before.clone(),
            after: after.clone(),
        })
        .collect();
    plan.set_locality_digest()?;
    plan.encode_unsigned()
}

fn bytes32(value: u8) -> Bytes32 {
    [value; 32]
}

fn right(
    participant: u8,
    subchannel: u8,
    kind: FactoryRightKind,
    asset_type: Option<u8>,
    quantity: u128,
) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: bytes32(participant),
            subchannel: bytes32(subchannel),
            kind,
            asset_type: asset_type.map(bytes32),
        },
        quantity,
    }
}

fn tree() -> Vec<FactoryRight> {
    vec![
        right(1, 10, FactoryRightKind::Balance, None, 100),
        right(1, 10, FactoryRightKind::ReserveClaim, None, 50),
        right(1, 10, FactoryRightKind::SponsorBudgetClaim, None, 20),
        right(1, 11, FactoryRightKind::Balance, None, 7),
        right(2, 10, FactoryRightKind::Balance, None, 100),
        right(2, 10, FactoryRightKind::ReserveClaim, None, 50),
        right(2, 10, FactoryRightKind::Membership, None, 1),
        right(2, 10, FactoryRightKind::ExitPath, None, 1),
    ]
}

fn compact_update(
    before_tree: &[FactoryRight],
    after_tree: &[FactoryRight],
    changed: &[usize],
) -> CurrentRightsUpdate {
    let before_root = factory_right_sparse_root(before_tree).unwrap();
    let after_root = factory_right_sparse_root(after_tree).unwrap();
    let mut proof_pairs = Vec::new();
    for index in changed {
        let id = before_tree[*index].id.clone();
        proof_pairs.push((
            factory_right_sparse_proof_compact(before_tree, &id).unwrap(),
            factory_right_sparse_proof_compact(after_tree, &id).unwrap(),
        ));
    }
    proof_pairs.sort_by(|(left, _), (right, _)| left.right.id.cmp(&right.right.id));
    let (before_proofs, after_proofs) = proof_pairs.into_iter().unzip();
    CurrentRightsUpdate {
        before_root,
        after_root,
        before: before_proofs,
        after: after_proofs,
    }
}

#[test]
fn compact_proofs_verify_against_sparse_root() {
    let tree = tree();
    let root = factory_right_sparse_root(&tree).unwrap();
    for right in &tree {
        let proof = factory_right_sparse_proof_compact(&tree, &right.id).unwrap();
        assert!(proof.siblings.len() < 256);
        verify_factory_right_compact_proof(root, &proof).unwrap();
    }
}

#[test]
fn compact_proofs_omit_exactly_the_empty_siblings() {
    let tree = tree();
    for target in &tree {
        let full = factory_right_sparse_proof(&tree, &target.id).unwrap();
        let compact = factory_right_sparse_proof_compact(&tree, &target.id).unwrap();
        assert_eq!(full.siblings.len(), 256);
        let compact_depths = compact
            .siblings
            .iter()
            .map(|sibling| usize::from(sibling.depth))
            .collect::<Vec<_>>();
        assert_eq!(compact_depths.len(), compact.siblings.len());
        for (depth, sibling) in full.siblings.iter().enumerate() {
            if let Some(position) = compact_depths.iter().position(|value| *value == depth) {
                assert_eq!(
                    sibling.hash, compact.siblings[position].hash,
                    "carried sibling at depth {depth} must match the full proof"
                );
            }
        }
        let omitted = (0..256)
            .filter(|depth| !compact_depths.contains(depth))
            .collect::<Vec<_>>();
        let stride = (omitted.len() / 16).max(1);
        for depth in omitted.iter().step_by(stride) {
            assert_eq!(
                full.siblings[*depth].hash,
                factory_empty_subtree_hash(255 - depth),
                "omitted sibling at depth {depth} must be the canonical empty subtree hash"
            );
        }
    }
}

#[test]
fn compact_proof_rejects_wrong_root() {
    let tree = tree();
    let proof = factory_right_sparse_proof_compact(&tree, &tree[0].id).unwrap();

    assert!(verify_factory_right_compact_proof(bytes32(9), &proof).is_err());
}

#[test]
fn compact_proof_rejects_extra_or_ascending_pairs() {
    let tree = tree();
    let mut proof = factory_right_sparse_proof_compact(&tree, &tree[0].id).unwrap();
    let root = factory_right_sparse_root(&tree).unwrap();

    let mut ascending = proof.clone();
    ascending.siblings.reverse();
    assert!(verify_factory_right_compact_proof(root, &ascending).is_err());

    proof.siblings.insert(
        0,
        FactoryCompactMerkleSibling {
            depth: proof.siblings.first().map(|s| s.depth).unwrap_or(0),
            hash: bytes32(77),
        },
    );
    assert!(proof.siblings.len() <= FACTORY_COMPACT_PROOF_MAX_SIBLINGS);
    assert!(verify_factory_right_compact_proof(root, &proof).is_err());
}

#[test]
fn compact_proof_rejects_duplicated_depth() {
    let tree = tree();
    let root = factory_right_sparse_root(&tree).unwrap();
    let mut proof = factory_right_sparse_proof_compact(&tree, &tree[0].id).unwrap();
    let Some(first) = proof.siblings.first().cloned() else {
        return;
    };
    proof.siblings.insert(1, first);
    if proof.siblings.len() <= FACTORY_COMPACT_PROOF_MAX_SIBLINGS {
        assert!(verify_factory_right_compact_proof(root, &proof).is_err());
    }
}

#[test]
fn multi_right_update_validates_decrease_and_rebalance() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity = 60;
    after_tree[1].quantity = 80;

    let update = compact_update(&before_tree, &after_tree, &[0, 1]);
    validate_current_rights_update(&update).unwrap();
}

#[test]
fn multi_right_update_rejects_total_increase() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity = 150;

    let update = compact_update(&before_tree, &after_tree, &[0]);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn multi_right_update_rejects_cross_asset_rebalance() {
    let mut before_tree = tree();
    before_tree.push(right(1, 12, FactoryRightKind::Balance, Some(41), 100));
    before_tree.push(right(1, 12, FactoryRightKind::ReserveClaim, Some(42), 1));
    let mut after_tree = before_tree.clone();
    let first = before_tree.len() - 2;
    let second = before_tree.len() - 1;
    after_tree[first].quantity = 0;
    after_tree[second].quantity = 101;

    let update = compact_update(&before_tree, &after_tree, &[first, second]);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn multi_right_update_rejects_unchanged_rights() {
    let before_tree = tree();
    let after_tree = before_tree.clone();

    let update = compact_update(&before_tree, &after_tree, &[0]);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn multi_right_update_rejects_foreign_right() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[4].quantity = 40;

    let update = compact_update(&before_tree, &after_tree, &[0, 4]);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn multi_right_update_rejects_non_value_kind() {
    let mut before_tree = tree();
    before_tree.push(right(1, 10, FactoryRightKind::Membership, None, 1));
    let mut after_tree = before_tree.clone();
    let index = before_tree.len() - 1;
    after_tree[index].quantity = 0;
    let update = compact_update(&before_tree, &after_tree, &[index]);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn multi_right_update_rejects_tampered_proof() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity = 60;

    let mut update = compact_update(&before_tree, &after_tree, &[0]);
    update.before[0].siblings[0].hash = bytes32(123);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn current_rights_update_rejects_more_than_ten_rights() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity = 90;

    let mut update = compact_update(&before_tree, &after_tree, &[0]);
    while update.before.len() <= 10 {
        update.before.push(update.before[0].clone());
        update.after.push(update.after[0].clone());
    }
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn multi_right_update_rejects_unlisted_foreign_change() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity = 60;
    after_tree[1].quantity = 80;
    after_tree[4].quantity = 500;

    let update = compact_update(&before_tree, &after_tree, &[0, 1]);
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn current_rights_update_rejects_unsorted_ids_and_proof_pairs() {
    let before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity -= 1;
    after_tree[1].quantity -= 1;
    let mut update = compact_update(&before_tree, &after_tree, &[0, 1]);
    update.before.swap(0, 1);
    update.after.swap(0, 1);
    assert!(validate_current_rights_update(&update).is_err());
    let mut update = compact_update(&before_tree, &after_tree, &[0]);
    update.before[0].siblings.reverse();
    assert!(validate_current_rights_update(&update).is_err());
}

#[test]
fn current_rights_update_rejects_identity_swap_and_per_asset_sum_overflow() {
    let mut before_tree = tree();
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity -= 1;
    let mut update = compact_update(&before_tree, &after_tree, &[0]);
    update.after[0].right.id.subchannel = bytes32(99);
    assert!(validate_current_rights_update(&update).is_err());
    before_tree[0].quantity = u128::MAX;
    before_tree[1].quantity = 1;
    let mut after_tree = before_tree.clone();
    after_tree[0].quantity -= 1;
    let update = compact_update(&before_tree, &after_tree, &[0, 1]);
    assert!(validate_current_rights_update(&update).is_err());
}

proptest! {
    #[test]
    fn compact_proofs_verify_on_random_trees(
        seed in 0u64..16,
        size in 2usize..24,
        quantity in 0u128..10_000,
    ) {
        let mut tree: Vec<FactoryRight> = Vec::with_capacity(size);
        let mut step = 0usize;
        while tree.len() < size && step < size * 8 {
            let participant = 1 + (step % 3) as u8;
            let subchannel = 10 + (step % 5) as u8;
            let kind = match (step / 15) % 5 {
                0 | 3 => FactoryRightKind::Balance,
                1 => FactoryRightKind::ReserveClaim,
                2 => FactoryRightKind::SponsorBudgetClaim,
                _ => FactoryRightKind::Membership,
            };
            let asset = step.is_multiple_of(7).then_some((seed % 251) as u8);
            let candidate = right(
                participant,
                subchannel,
                kind,
                asset,
                quantity + step as u128,
            );
            if !tree.iter().any(|existing| existing.id == candidate.id) {
                tree.push(candidate);
            }
            step += 1;
        }
        let root = factory_right_sparse_root(&tree).unwrap();
        for target in &tree {
            let proof = factory_right_sparse_proof_compact(&tree, &target.id).unwrap();
            prop_assert!(proof.siblings.len() <= FACTORY_COMPACT_PROOF_MAX_SIBLINGS);
            prop_assert!(proof.siblings.len() < 256);
            verify_factory_right_compact_proof(root, &proof).unwrap();
        }
    }
}
