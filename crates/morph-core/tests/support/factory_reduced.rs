#![allow(dead_code)]
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::*;
use morph_script_common::factory_multi_asset::FactoryMultiAssetHeaderFields;

pub const CKB: u64 = 100_000_000;
pub fn script(args: &[u8], code: u8) -> Vec<u8> {
    let len = 53 + args.len();
    let mut raw = Vec::new();
    for n in [len, 16, 48, 49] {
        raw.extend_from_slice(&(n as u32).to_le_bytes());
    }
    raw.extend_from_slice(&[code; 32]);
    raw.push(2);
    raw.extend_from_slice(&(args.len() as u32).to_le_bytes());
    raw.extend_from_slice(args);
    raw
}
pub fn claim(participant: u8, asset: Option<Bytes32>, quantity: u128) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: [participant; 32],
            subchannel: [0; 32],
            kind: FactoryRightKind::ReserveClaim,
            asset_type: asset,
        },
        quantity,
    }
}
pub fn fixture_with_unlisted_change(
    unlisted: bool,
) -> (FactoryMultiAssetReducedRelease, SigningKey) {
    let keys = [
        SigningKey::from_bytes((&[1; 32]).into()).unwrap(),
        SigningKey::from_bytes((&[2; 32]).into()).unwrap(),
    ];
    let members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| FactoryParticipantKey {
            participant: [i as u8 + 1; 32],
            pubkey_sec1: k.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
        })
        .collect();
    let type_script = script(&[], 33);
    let token = blake2b256(&type_script);
    let before_rights = vec![
        claim(1, None, 900 * CKB as u128),
        claim(1, Some(token), 60),
        claim(2, None, 820 * CKB as u128),
        claim(2, Some(token), 40),
    ];
    let mut after_rights = before_rights.clone();
    after_rights[0].quantity -= 365 * CKB as u128;
    after_rights[1].quantity -= 30;
    if unlisted {
        after_rights[3].quantity += 1;
    }
    let rights = before_rights[..2]
        .iter()
        .map(|r| FactoryReducedReleaseRight {
            before: factory_right_sparse_proof_compact(&before_rights, &r.id).unwrap(),
            after: factory_right_sparse_proof_compact(&after_rights, &r.id).unwrap(),
        })
        .collect();
    let mut factory_args = [5; 64];
    factory_args[32..].fill(12);
    let lock = script(&factory_args, 22);
    let lock_hash = blake2b256(&lock);
    let source = MultiAssetManifest {
        vaults: vec![
            MultiAssetVault {
                asset: VaultAsset::Ckb,
                lock_hash,
                value: MultiAssetValue {
                    reserve: 1000 * CKB,
                    business_ckb: 100 * CKB,
                    amount: 0,
                },
            },
            MultiAssetVault {
                asset: VaultAsset::Xudt(token),
                lock_hash,
                value: MultiAssetValue {
                    reserve: 600 * CKB,
                    business_ckb: 20 * CKB,
                    amount: 100,
                },
            },
        ],
    };
    let retained = MultiAssetManifest {
        vaults: vec![
            MultiAssetVault {
                asset: VaultAsset::Ckb,
                lock_hash,
                value: MultiAssetValue {
                    reserve: 800 * CKB,
                    business_ckb: 90 * CKB,
                    amount: 0,
                },
            },
            MultiAssetVault {
                asset: VaultAsset::Xudt(token),
                lock_hash,
                value: MultiAssetValue {
                    reserve: 450 * CKB,
                    business_ckb: 15 * CKB,
                    amount: 70,
                },
            },
        ],
    };
    let points = vec![
        MultiAssetOutPoint {
            tx_hash: [9; 32],
            index: 1,
        },
        MultiAssetOutPoint {
            tx_hash: [9; 32],
            index: 2,
        },
    ];
    let entries: Vec<_> = members
        .iter()
        .map(|m| (m.participant.as_slice(), m.pubkey_sec1.as_slice()))
        .collect();
    let membership = morph_script_common::factory_participants_commitment(2, &entries);
    let before = FactoryMultiAssetHeaderFields {
        chain_id: [1; 32],
        factory_id: [5; 32],
        update_number: 2,
        state_root: factory_right_sparse_root(&before_rights).unwrap(),
        participants_commitment: membership,
        access_manifest_root: [6; 32],
        non_interference_digest: [7; 32],
        challenge_policy_commitment: [8; 32],
        content_root: source.commitment().unwrap(),
        outpoint_root: multi_asset_outpoint_commitment(&source, &points).unwrap(),
        vault_count: 2,
    };
    let after = FactoryMultiAssetHeaderFields {
        update_number: 3,
        state_root: factory_right_sparse_root(&after_rights).unwrap(),
        content_root: retained.commitment().unwrap(),
        outpoint_root: [0; 32],
        ..before
    };
    let mut plan = FactoryMultiAssetReducedRelease {
        operation: morph_core::FactoryTransitionOperation::ReducedRelease,
        before,
        after,
        members,
        signer_index: 0,
        old_state: MultiAssetOutPoint {
            tx_hash: [10; 32],
            index: 0,
        },
        transaction_hash: [11; 32],
        carrier_capacity: 500 * CKB,
        source,
        source_outpoints: points,
        retained,
        factory_lock_script: lock,
        type_scripts: vec![MultiAssetTypeScript {
            type_hash: token,
            script: type_script,
        }],
        payouts: vec![
            FactoryReducedReleasePayout {
                asset: VaultAsset::Ckb,
                value: MultiAssetValue {
                    reserve: 200 * CKB,
                    business_ckb: 10 * CKB,
                    amount: 0,
                },
                lock_script: script(&[], 44),
                output_index: 3,
            },
            FactoryReducedReleasePayout {
                asset: VaultAsset::Xudt(token),
                value: MultiAssetValue {
                    reserve: 150 * CKB,
                    business_ckb: 5 * CKB,
                    amount: 30,
                },
                lock_script: script(&[], 44),
                output_index: 4,
            },
        ],
        rights,
        materialisation: None,
    };
    plan.set_locality_digest().unwrap();
    (plan, keys[0].clone())
}
pub fn sign(plan: &FactoryMultiAssetReducedRelease, key: &SigningKey) -> [u8; 64] {
    let sig: Signature = key.sign_prehash(&plan.signing_digest().unwrap()).unwrap();
    sig.to_bytes().into()
}
