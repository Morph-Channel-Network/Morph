use ckb_testtool::ckb_types::{core::ScriptHashType, packed::Script, prelude::*};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::*;
use morph_script_common::multi_asset as wire;
use proptest::prelude::*;

fn script(code: u8, args: &[u8]) -> Vec<u8> {
    Script::new_builder()
        .code_hash([code; 32].pack())
        .hash_type(ScriptHashType::Data1)
        .args(args.pack())
        .build()
        .as_slice()
        .to_vec()
}

fn sign(package: &mut MultiAssetRecoveryPackage) {
    let mut keys = [1u8, 2].map(|value| SigningKey::from_slice(&[value; 32]).unwrap());
    keys.sort_by_key(|key| {
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    });
    let pubkeys = keys
        .each_ref()
        .map(|key| key.verifying_key().to_encoded_point(true));
    package.state.header.participants_commitment =
        participants_commitment(2, &[pubkeys[0].as_bytes(), pubkeys[1].as_bytes()]);
    let digest = package.state.signing_digest().unwrap();
    package.authorization = StateAuthorization {
        threshold: 2,
        signatures: keys
            .iter()
            .map(|key| {
                let signature: Signature = key.sign_prehash(&digest).unwrap();
                ParticipantSignature {
                    pubkey_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .collect(),
    };
}

fn fixture(count: usize) -> MultiAssetRecoveryPackage {
    let anchor = [4; 32];
    let since = morph_script_common::relative_block_since(6).unwrap();
    let mut state_args = anchor.to_vec();
    state_args.extend_from_slice(&since.to_le_bytes());
    let state_type = script(3, &state_args);
    let state_lock = script(2, &blake2b256(&state_type));
    let vault_args = wire::encode_multi_asset_vault_args(
        &anchor,
        since,
        &blake2b256(&state_type),
        &blake2b256(&state_lock),
    )
    .unwrap();
    let vault_lock = script(1, &vault_args);
    let mut participant_locks = [script(4, &[1; 20]), script(4, &[2; 20])];
    participant_locks.sort_by_key(|raw| blake2b256(raw));
    let carrier_refund_lock = participant_locks[0].clone();
    let mut types: Vec<_> = (0..count)
        .map(|i| {
            let script = script(5, &[i as u8]);
            MultiAssetTypeScript {
                type_hash: blake2b256(&script),
                script,
            }
        })
        .collect();
    types.sort_by_key(|entry| entry.type_hash);
    let manifest = MultiAssetManifest {
        vaults: types
            .iter()
            .map(|entry| MultiAssetVault {
                asset: VaultAsset::Xudt(entry.type_hash),
                lock_hash: blake2b256(&vault_lock),
                value: MultiAssetValue {
                    reserve: 40_000_000_000,
                    business_ckb: 10_000_000_000,
                    amount: 1000,
                },
            })
            .collect(),
    };
    let settlement = MultiAssetSettlement {
        participant_lock_hashes: participant_locks.each_ref().map(|raw| blake2b256(raw)),
        carrier_refund_lock_hash: blake2b256(&carrier_refund_lock),
        payouts: manifest
            .vaults
            .iter()
            .map(|vault| MultiAssetPayout {
                asset: vault.asset.clone(),
                values: [
                    MultiAssetValue {
                        reserve: 20_000_000_000,
                        business_ckb: 6_000_000_000,
                        amount: 700,
                    },
                    MultiAssetValue {
                        reserve: 20_000_000_000,
                        business_ckb: 4_000_000_000,
                        amount: 300,
                    },
                ],
            })
            .collect(),
    };
    let outpoints = (0..count)
        .map(|i| MultiAssetOutPoint {
            tx_hash: [44; 32],
            index: i as u32 + 1,
        })
        .collect::<Vec<_>>();
    let content = manifest.commitment().unwrap();
    let mut package = MultiAssetRecoveryPackage {
        state: MultiAssetState {
            header: StateHeader {
                protocol_version: 1,
                chain_id: [1; 32],
                signature_scheme_id: 1,
                channel_id: [2; 32],
                funding_epoch: 0,
                funding_anchor: anchor,
                vault_set_commitment: content,
                state_number: 9,
                mode: Mode::BilateralPlain,
                phase: Phase::Settling,
                participants_commitment: [0; 32],
                asset_registry_commitment: asset_registry_commitment(&manifest.registry().unwrap()),
                settlement_descriptor_commitment: settlement.commitment().unwrap(),
                descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
                vault_materialisation_root: [0; 32],
                challenge_policy_commitment: [3; 32],
                state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
                vault_outpoint_commitment: [0; 32],
            },
            vault_content_set_root: content,
            vault_outpoint_set_root: multi_asset_outpoint_commitment(&manifest, &outpoints)
                .unwrap(),
            vault_count: count as u16,
        },
        authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        manifest,
        settlement,
        outpoints,
        scripts: MultiAssetRecoveryScripts {
            vault_lock,
            participant_locks,
            carrier_refund_lock,
            state_type,
            state_lock,
            type_scripts: types,
        },
        state_carrier_capacity: 100_000_000_000,
    };
    sign(&mut package);
    package
}

#[test]
fn multi_asset_two_types_recovery_round_trips_json_and_wire() {
    let package = fixture(2);
    package.validate().unwrap();
    let json = serde_json::to_vec(&package).unwrap();
    let restored: MultiAssetRecoveryPackage = serde_json::from_slice(&json).unwrap();
    assert_eq!(package, restored);
    restored.validate().unwrap();
    let raw = encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )
    .unwrap();
    let header = package.state.encode().unwrap();
    let parsed = wire::MultiAssetWitness::parse(&raw).unwrap();
    parsed
        .validate_header(&wire::MultiAssetStateHeader::parse(&header).unwrap())
        .unwrap();
    assert_eq!(
        parsed.manifest().commitment(),
        package.manifest.commitment().unwrap()
    );
    assert_eq!(
        parsed.descriptor().commitment(),
        package.settlement.commitment().unwrap()
    );
    assert_eq!(
        parsed.manifest().asset_registry_commitment().unwrap(),
        asset_registry_commitment(&package.manifest.registry().unwrap())
    );
}

#[test]
fn multi_asset_maximum_candidate_shape_has_bounded_evidence() {
    let package = fixture(wire::MULTI_ASSET_MAX_VAULTS);
    package.validate().unwrap();
    let raw = encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )
    .unwrap();
    assert!(raw.len() <= wire::MULTI_ASSET_MAX_WITNESS_LEN);
    assert!(fixture(1).validate().is_ok());
    let mut invalid = package.manifest.clone();
    invalid.vaults.push(invalid.vaults[0].clone());
    assert!(invalid.encode().is_err());
}

#[test]
fn multi_asset_domains_and_state_digests_match_host() {
    use morph_core::hash;
    assert_eq!(
        hash::MULTI_ASSET_STATE_DOMAIN,
        wire::MULTI_ASSET_STATE_DOMAIN
    );
    assert_eq!(
        hash::MULTI_ASSET_VAULT_SET_DOMAIN,
        wire::MULTI_ASSET_VAULT_SET_DOMAIN
    );
    assert_eq!(
        hash::MULTI_ASSET_OUTPOINT_SET_DOMAIN,
        wire::MULTI_ASSET_OUTPOINT_SET_DOMAIN
    );
    assert_eq!(
        hash::MULTI_ASSET_DESCRIPTOR_DOMAIN,
        wire::MULTI_ASSET_DESCRIPTOR_DOMAIN
    );
    assert_eq!(
        hash::MULTI_ASSET_FUNDING_CONTEXT_DOMAIN,
        wire::MULTI_ASSET_FUNDING_CONTEXT_DOMAIN
    );
    let package = fixture(2);
    let raw = package.state.encode().unwrap();
    let header = wire::MultiAssetStateHeader::parse(&raw).unwrap();
    assert_eq!(
        header.signing_digest(),
        package.state.signing_digest().unwrap()
    );
    assert_eq!(
        header.funding_context_id().unwrap(),
        package.state.funding_context_id().unwrap()
    );
    let points = encode_multi_asset_outpoints(&package.outpoints).unwrap();
    assert_eq!(
        wire::multi_asset_outpoint_set_commitment(
            header.content_root(),
            header.vault_count(),
            &points
        )
        .unwrap(),
        package.state.vault_outpoint_set_root
    );
    assert!(morph_script_common::StateHeader::parse(&raw).is_err());
}

#[test]
fn multi_asset_rejects_cross_asset_mint_even_when_aggregate_quantity_is_preserved() {
    let mut package = fixture(2);
    package.settlement.payouts[0].values[0].amount += 1;
    package.settlement.payouts[1].values[0].amount -= 1;
    assert!(
        package
            .settlement
            .validate_against(&package.manifest)
            .is_err()
    );
}

#[test]
fn multi_asset_rejects_reserve_business_capacity_reclassification() {
    let mut package = fixture(2);
    package.settlement.payouts[0].values[0].reserve -= 1;
    package.settlement.payouts[0].values[0].business_ckb += 1;
    assert!(
        package
            .settlement
            .validate_against(&package.manifest)
            .is_err()
    );
}

#[test]
fn multi_asset_rejects_incomplete_duplicate_reordered_or_substituted_outpoints() {
    let original = fixture(2);
    for mutation in 0..4 {
        let mut package = original.clone();
        match mutation {
            0 => {
                package.outpoints.pop();
            }
            1 => {
                package.outpoints[1] = package.outpoints[0].clone();
            }
            2 => package.outpoints.swap(0, 1),
            _ => package.outpoints[0].tx_hash = [55; 32],
        }
        assert!(package.validate().is_err(), "mutation {mutation}");
    }
}

#[test]
fn multi_asset_rejects_noncanonical_asset_shape_and_overflow() {
    let original = fixture(2);
    let mut manifest = original.manifest.clone();
    manifest.vaults.swap(0, 1);
    assert!(manifest.encode().is_err());
    manifest = original.manifest.clone();
    manifest.vaults[1] = manifest.vaults[0].clone();
    assert!(manifest.encode().is_err());
    manifest = original.manifest.clone();
    manifest.vaults[0].value.reserve = u64::MAX;
    assert!(manifest.encode().is_err());
    let mut settlement = original.settlement.clone();
    settlement.payouts[0].values[0].amount = u128::MAX;
    assert!(settlement.validate_against(&original.manifest).is_err());
}

#[test]
fn multi_asset_rejects_missing_scripts_wrong_identity_and_insufficient_reserve() {
    let original = fixture(2);
    for mutation in 0..5 {
        let mut package = original.clone();
        match mutation {
            0 => {
                package.scripts.type_scripts.pop();
            }
            1 => package.scripts.type_scripts[0].script.push(0),
            2 => package.scripts.participant_locks[0][20] ^= 1,
            3 => package.state_carrier_capacity = 1,
            _ => {
                package.manifest.vaults[0].value.reserve = 2;
                package.settlement.payouts[0].values[0].reserve = 1;
                package.settlement.payouts[0].values[1].reserve = 1;
            }
        }
        assert!(package.validate().is_err(), "mutation {mutation}");
    }
}

#[test]
fn multi_asset_rejects_foreign_funding_context_and_signature_replay() {
    let mut package = fixture(2);
    package.state.header.chain_id[0] ^= 1;
    assert!(package.validate().is_err());
    package = fixture(2);
    package.state.header.funding_anchor[0] ^= 1;
    sign(&mut package);
    assert!(package.validate().is_err());
    package = fixture(2);
    package.state.vault_content_set_root[0] ^= 1;
    assert!(package.state.encode().is_err());
    package = fixture(2);
    package.state.header.vault_materialisation_root = [1; 32];
    assert!(package.state.encode().is_err());
}

#[test]
fn multi_asset_activation_changes_only_exact_provenance() {
    let mut package = fixture(2);
    package.state.header.phase = Phase::Active;
    package.state.header.state_number = 0;
    let bound = package.state.encode().unwrap();
    package.state.vault_outpoint_set_root = [0; 32];
    package.outpoints.clear();
    sign(&mut package);
    package.validate().unwrap();
    let unbound = package.state.encode().unwrap();
    let old = wire::MultiAssetStateHeader::parse(&unbound).unwrap();
    let new = wire::MultiAssetStateHeader::parse(&bound).unwrap();
    assert!(old.is_activation_to(&new));
    assert!(!old.same_context_except_progress(&new).unwrap());
    let mut tampered = bound;
    tampered[140] = 1;
    assert!(!old.is_activation_to(&wire::MultiAssetStateHeader::parse(&tampered).unwrap()));
}

#[test]
fn multi_asset_one_sided_payout_omits_only_empty_allocations() {
    let mut package = fixture(2);
    for (payout, vault) in package
        .settlement
        .payouts
        .iter_mut()
        .zip(&package.manifest.vaults)
    {
        payout.values = [vault.value, MultiAssetValue::default()];
    }
    package.state.header.settlement_descriptor_commitment =
        package.settlement.commitment().unwrap();
    sign(&mut package);
    package.validate().unwrap();
    package.settlement.payouts[0].values[1].amount = 1;
    assert!(package.settlement.encode().is_err());
}

proptest! {
    #[test]
    fn multi_asset_parsers_fail_closed_on_arbitrary_bytes(raw in prop::collection::vec(any::<u8>(), 0..2500)) {
        let _ = wire::MultiAssetWitness::parse(&raw);
        let _ = wire::MultiAssetStateHeader::parse(&raw);
        let _ = wire::MultiAssetVaultManifest::parse(&raw);
        let _ = wire::MultiAssetSettlementDescriptor::parse(&raw);
        let _ = wire::MultiAssetVaultArgs::parse(&raw);
        let _ = wire::multi_asset_script_occupied_bytes(&raw);
    }

    #[test]
    fn multi_asset_rebalances_each_type_independently(a in 0u128..=1000, b in 0u128..=1000) {
        let mut package = fixture(2);
        for (index, amount) in [a,b].into_iter().enumerate() {
            package.settlement.payouts[index].values[0].amount = amount;
            package.settlement.payouts[index].values[1].amount = 1000 - amount;
        }
        prop_assert!(package.settlement.validate_against(&package.manifest).is_ok());
    }
}
