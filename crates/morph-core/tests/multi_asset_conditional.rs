//! The conditional capability shares the canonical current State/Vault model;
//! only the CKB lane is deferred to the bounded Batch executor.
use ckb_testtool::ckb_types::{core::ScriptHashType, packed::Script, prelude::*};
use morph_core::{
    ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant, ConditionalTransferSpec,
    derive_conditional_payment_hash,
};
use morph_script_common::multi_asset::*;
use morph_script_common::multi_asset_conditional::*;
use morph_script_common::{ScriptError, blake2b256, write_u16};

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let locks = [[1; 32], [2; 32]];
    let batch = ConditionalBatch {
        batch_id: [3; 32],
        application_context_commitment: [4; 32],
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: locks[0],
                settled_capacity: 120,
            },
            ConditionalParticipant {
                settlement_lock_hash: locks[1],
                settled_capacity: 110,
            },
        ],
        transfers: vec![ConditionalTransferSpec {
            transfer_id: [5; 32],
            payer_lock_hash: locks[0],
            hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
            payment_hash: derive_conditional_payment_hash(
                ConditionalHashAlgorithm::CkbBlake2b,
                &[6; 32],
            )
            .unwrap(),
            amount: 50,
            refund_after_block: 100,
        }],
    };
    let extension =
        encode_multi_asset_conditional(&[7; 32], 2, &batch.encode_descriptor().unwrap()).unwrap();
    let mut descriptor =
        vec![0; MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + 2 * MULTI_ASSET_PAYOUT_ENTRY_LEN];
    write_u16(&mut descriptor, 0, MULTI_ASSET_DESCRIPTOR_VERSION);
    descriptor[2] = 2;
    descriptor[3] = MULTI_ASSET_SETTLEMENT_CKB_CONDITIONAL;
    descriptor[4..36].copy_from_slice(&locks[0]);
    descriptor[36..68].copy_from_slice(&locks[1]);
    descriptor[68..100].copy_from_slice(&[8; 32]);
    let payouts = [
        MultiAssetPayoutEntry {
            asset: MultiAssetId::CKB,
            allocations: [
                MultiAssetAllocation {
                    reserve: 100,
                    business_ckb: 20,
                    amount: 0,
                },
                MultiAssetAllocation {
                    reserve: 100,
                    business_ckb: 10,
                    amount: 0,
                },
            ],
        },
        MultiAssetPayoutEntry {
            asset: MultiAssetId::xudt([9; 32]),
            allocations: [
                MultiAssetAllocation {
                    reserve: 100,
                    business_ckb: 10,
                    amount: 60,
                },
                MultiAssetAllocation {
                    reserve: 100,
                    business_ckb: 10,
                    amount: 40,
                },
            ],
        },
    ];
    for (index, payout) in payouts.iter().enumerate() {
        let offset = MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + index * MULTI_ASSET_PAYOUT_ENTRY_LEN;
        payout
            .encode(&mut descriptor[offset..offset + MULTI_ASSET_PAYOUT_ENTRY_LEN])
            .unwrap();
    }
    descriptor.extend_from_slice(&extension);
    let mut manifest = vec![0; 4 + 2 * MULTI_ASSET_VAULT_ENTRY_LEN];
    write_u16(&mut manifest, 0, MULTI_ASSET_ENCODING_VERSION);
    manifest[2] = 2;
    for (index, allocation) in [
        MultiAssetAllocation {
            reserve: 200,
            business_ckb: 80,
            amount: 0,
        },
        MultiAssetAllocation {
            reserve: 200,
            business_ckb: 20,
            amount: 100,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let offset = 4 + index * MULTI_ASSET_VAULT_ENTRY_LEN;
        MultiAssetVaultEntry {
            asset: payouts[index].asset,
            lock_hash: [10; 32],
            allocation,
        }
        .encode(&mut manifest[offset..offset + MULTI_ASSET_VAULT_ENTRY_LEN])
        .unwrap();
    }
    (manifest, descriptor)
}

#[test]
fn current_conditional_descriptor_conserves_pending_ckb_and_untouched_tokens() {
    let (manifest, descriptor) = fixture();
    let parsed = MultiAssetSettlementDescriptor::parse(&descriptor).unwrap();
    let conditional = parsed.conditional().unwrap().unwrap();
    assert_eq!(conditional.pending_capacity().unwrap(), 50);
    assert_eq!(conditional.batch().checked_total_capacity().unwrap(), 280);
    validate_multi_asset_conservation(&MultiAssetVaultManifest::parse(&manifest).unwrap(), &parsed)
        .unwrap();
    // The exact same pending CKB cannot be counted in settled business too.
    let mut inflated = descriptor.clone();
    inflated[MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + 41] += 1;
    assert!(MultiAssetSettlementDescriptor::parse(&inflated).is_err());
}

#[test]
fn host_conditional_encoding_is_lossless_and_requires_explicit_capability() {
    let (manifest, descriptor) = fixture();
    let host = morph_core::MultiAssetSettlement::decode(&descriptor).unwrap();
    assert_eq!(host.encode().unwrap(), descriptor);
    assert_eq!(
        host.custody_manifest([10; 32]).unwrap().encode().unwrap(),
        manifest
    );
    let conditional = MultiAssetSettlementDescriptor::parse(&descriptor)
        .unwrap()
        .conditional()
        .unwrap()
        .unwrap();
    match &host.capability {
        morph_core::MultiAssetSettlementCapability::CkbConditional {
            batch_code_hash,
            batch_hash_type,
            batch,
        } => {
            assert_eq!(batch_code_hash.as_slice(), conditional.code_hash());
            assert_eq!(*batch_hash_type, conditional.hash_type());
            assert_eq!(
                batch.encode_descriptor().unwrap().as_slice(),
                conditional.batch().raw()
            );
        }
        _ => panic!("conditional capability was erased"),
    }
    let mut json = serde_json::to_value(&host).unwrap();
    let roundtrip: morph_core::MultiAssetSettlement = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(roundtrip, host);
    json.as_object_mut().unwrap().remove("capability");
    assert!(serde_json::from_value::<morph_core::MultiAssetSettlement>(json).is_err());
    let mut unknown = serde_json::to_value(&host).unwrap();
    unknown["capability"]["kind"] = serde_json::Value::String("fallback".into());
    assert!(serde_json::from_value::<morph_core::MultiAssetSettlement>(unknown).is_err());
}

#[test]
fn current_conditional_descriptor_rejects_other_asset_or_reserve_funding_pending() {
    let (mut manifest, descriptor) = fixture();
    let parsed = MultiAssetSettlementDescriptor::parse(&descriptor).unwrap();
    // Move 1 shannon from reserve into business. Total CKB remains the same,
    // but the independently committed reserve lane must not be consumed.
    let mut entry = MultiAssetVaultManifest::parse(&manifest)
        .unwrap()
        .entry(0)
        .unwrap();
    entry.allocation.reserve -= 1;
    entry.allocation.business_ckb += 1;
    entry
        .encode(&mut manifest[4..4 + MULTI_ASSET_VAULT_ENTRY_LEN])
        .unwrap();
    assert_eq!(
        validate_multi_asset_conservation(
            &MultiAssetVaultManifest::parse(&manifest).unwrap(),
            &parsed
        ),
        Err(ScriptError::MultiAssetConservationMismatch)
    );
    // Token or other-lane CKB reductions cannot finance pending CKB either.
    let (mut manifest, _) = fixture();
    let offset = 4 + MULTI_ASSET_VAULT_ENTRY_LEN;
    let mut entry = MultiAssetVaultManifest::parse(&manifest)
        .unwrap()
        .entry(1)
        .unwrap();
    entry.allocation.amount -= 1;
    entry
        .encode(&mut manifest[offset..offset + MULTI_ASSET_VAULT_ENTRY_LEN])
        .unwrap();
    assert!(
        validate_multi_asset_conservation(
            &MultiAssetVaultManifest::parse(&manifest).unwrap(),
            &parsed
        )
        .is_err()
    );
}

#[test]
fn current_descriptor_rejects_old_version_unknown_capability_and_trailing_bytes() {
    let (_, raw) = fixture();
    let mut old = raw.clone();
    write_u16(&mut old, 0, 4);
    assert_eq!(
        MultiAssetSettlementDescriptor::parse(&old),
        Err(ScriptError::MultiAssetEncoding)
    );
    let mut unknown = raw.clone();
    unknown[3] = 2;
    assert!(MultiAssetSettlementDescriptor::parse(&unknown).is_err());
    let mut extra = raw.clone();
    extra.push(0);
    assert!(MultiAssetSettlementDescriptor::parse(&extra).is_err());
    let mut truncated = raw;
    truncated.pop();
    assert!(MultiAssetSettlementDescriptor::parse(&truncated).is_err());
}

#[test]
fn conditional_terms_must_match_current_recipient_and_settled_allocation() {
    let (_, raw) = fixture();
    let offset = MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + 2 * MULTI_ASSET_PAYOUT_ENTRY_LEN;
    let mut wrong_recipient = raw.clone();
    wrong_recipient[offset + 36 + 76] = 0;
    assert!(MultiAssetSettlementDescriptor::parse(&wrong_recipient).is_err());
    let mut wrong_value = raw.clone();
    wrong_value[offset + 36 + 76 + 32] += 1;
    assert_eq!(
        MultiAssetSettlementDescriptor::parse(&wrong_value),
        Err(ScriptError::ConditionalValueMismatch)
    );
    let mut reserved = raw;
    reserved[offset + 2] = 1;
    assert!(MultiAssetSettlementDescriptor::parse(&reserved).is_err());
}

#[test]
fn current_state_commitment_covers_batch_identity_and_conditions() {
    let (_, mut raw) = fixture();
    let before = MultiAssetSettlementDescriptor::parse(&raw)
        .unwrap()
        .commitment();
    let offset = MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + 2 * MULTI_ASSET_PAYOUT_ENTRY_LEN;
    raw[offset + 4] ^= 1;
    let after = MultiAssetSettlementDescriptor::parse(&raw)
        .unwrap()
        .commitment();
    assert_ne!(before, after);
}

#[test]
fn batch_script_matches_ckb_molecule_and_binds_channel_state_and_terms() {
    let (_, raw) = fixture();
    let descriptor = MultiAssetSettlementDescriptor::parse(&raw).unwrap();
    let conditional = descriptor.conditional().unwrap().unwrap();
    let mut args = [11; 32].to_vec();
    args.extend_from_slice(&[13; 32]);
    args.extend_from_slice(&12u64.to_le_bytes());
    args.extend_from_slice(&conditional.batch().commitment());
    let script = Script::new_builder()
        .code_hash([7; 32].pack())
        .hash_type(ScriptHashType::Data1)
        .args(args.pack())
        .build();
    assert_eq!(
        conditional
            .batch_script(&[11; 32], &[13; 32], 12)
            .unwrap()
            .as_slice(),
        script.as_slice()
    );
    assert_eq!(
        conditional
            .batch_lock_hash(&[11; 32], &[13; 32], 12)
            .unwrap(),
        blake2b256(&[script.as_slice()])
    );
    let expected_hash: [u8; 32] = script.calc_script_hash().unpack();
    assert_ne!(
        conditional
            .batch_lock_hash(&[11; 32], &[13; 32], 13)
            .unwrap(),
        expected_hash
    );
    assert_ne!(
        conditional
            .batch_lock_hash(&[12; 32], &[13; 32], 12)
            .unwrap(),
        expected_hash
    );
    assert_ne!(
        conditional
            .batch_lock_hash(&[11; 32], &[14; 32], 12)
            .unwrap(),
        expected_hash
    );
    assert!(conditional.batch_script(&[11; 32], &[0; 32], 12).is_err());
}
