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
    keys.sort_by_key(|key| key.verifying_key().to_sec1_point(true).as_bytes().to_vec());
    let pubkeys = keys
        .each_ref()
        .map(|key| key.verifying_key().to_sec1_point(true));
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
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
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
        capability: morph_core::MultiAssetSettlementCapability::Ordinary,
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
            header: MultiAssetHeader {
                protocol_version: 1,
                chain_id: [1; 32],
                signature_scheme_id: 1,
                channel_id: [2; 32],
                funding_epoch: 0,
                funding_anchor: anchor,
                state_number: 9,
                mode: Mode::BilateralPlain,
                phase: Phase::Settling,
                participants_commitment: [0; 32],
                asset_registry_commitment: asset_registry_commitment(&manifest.registry().unwrap()),
                settlement_descriptor_commitment: settlement.commitment().unwrap(),
                descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
                challenge_policy_commitment: [3; 32],
                state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
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
    assert!(package.validate().is_err());
}

#[test]
fn zero_number_settling_is_not_a_unilateral_recovery_exit() {
    let mut package = fixture(2);
    package.state.header.phase = Phase::Settling;
    package.state.header.state_number = 0;
    sign(&mut package);
    assert_eq!(
        package.validate(),
        Err(MultiAssetError::InvalidSettlingStateNumber)
    );
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
    package.validate_contents().unwrap();
    assert_eq!(
        package.validate(),
        Err(MultiAssetError::RootFundingContextRequired)
    );
    let unbound = package.state.encode().unwrap();
    let old = wire::MultiAssetStateHeader::parse(&unbound).unwrap();
    let root_vote = package
        .state
        .root_funding_signing_digest(&[71; 32])
        .unwrap();
    assert_eq!(
        root_vote,
        old.root_funding_signing_digest(&[71; 32]).unwrap()
    );
    assert_ne!(root_vote, package.state.signing_digest().unwrap());
    assert_ne!(
        root_vote,
        package
            .state
            .root_funding_signing_digest(&[72; 32])
            .unwrap()
    );
    assert!(package.state.root_funding_signing_digest(&[0; 32]).is_err());

    let new = wire::MultiAssetStateHeader::parse(&bound).unwrap();
    assert!(old.is_activation_to(&new));
    assert!(!old.same_context_except_progress(&new));
    let mut tampered = bound;
    tampered[108] = 1;
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
        let _ = morph_script_common::multi_asset_splice::MultiAssetSpliceHeader::parse(&raw);
        let _ = morph_script_common::multi_asset_splice::MultiAssetSpliceFlows::parse(&raw);
        let _ = morph_script_common::multi_asset_splice::MultiAssetSpliceWitness::parse(&raw);
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

fn participant_key(value: u8) -> SigningKey {
    SigningKey::from_slice(&[value; 32]).unwrap()
}
fn participant_pubkey(value: u8) -> Vec<u8> {
    participant_key(value)
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec()
}
fn proposal_signature(proposal: &MultiAssetProposal, value: u8) -> ParticipantSignature {
    let signature: Signature = participant_key(value)
        .sign_prehash(&proposal.signing_digest().unwrap())
        .unwrap();
    ParticipantSignature {
        pubkey_sec1: participant_pubkey(value),
        signature: signature.to_bytes().to_vec(),
    }
}

#[test]
fn multi_asset_backend_two_signers_commit_direct_recovery_and_restart() {
    let original = fixture(8);
    let mut alice = MultiAssetChannelBackend::new(original.clone(), participant_pubkey(1)).unwrap();
    let mut bob = MultiAssetChannelBackend::new(original.clone(), participant_pubkey(2)).unwrap();
    let mut settlement = original.settlement.clone();
    for (index, payout) in settlement.payouts.iter_mut().enumerate() {
        payout.values[0].amount = index as u128 * 100;
        payout.values[1].amount = 1000 - payout.values[0].amount;
    }
    let proposal = alice.propose(settlement.clone()).unwrap();
    assert_eq!(alice.propose(settlement).unwrap(), proposal);
    bob.accept_proposal(proposal.clone()).unwrap();
    for (backend, key) in [(&mut alice, 1), (&mut bob, 2)] {
        backend.reserve_signature().unwrap();
        *backend = serde_json::from_slice(&serde_json::to_vec(backend).unwrap()).unwrap();
        backend
            .record_signature(proposal_signature(&proposal, key))
            .unwrap();
        assert_eq!(
            backend.commit().unwrap_err(),
            MultiAssetBackendError::IncompleteSignatures
        );
    }
    alice
        .record_signature(proposal_signature(&proposal, 2))
        .unwrap();
    bob.record_signature(proposal_signature(&proposal, 1))
        .unwrap();
    let next = alice.commit().unwrap();
    assert_eq!(bob.commit().unwrap(), next);
    assert_eq!(
        next.state.header.state_number,
        original.state.header.state_number + 1
    );
    let encoded = encode_multi_asset_witness(
        &next.manifest,
        &next.settlement,
        &next.outpoints,
        &next.scripts,
    )
    .unwrap();
    let decoded = MultiAssetRecoveryPackage::decode(
        &next.state.encode().unwrap(),
        &encoded,
        &encode_multi_asset_signatures(&next.authorization).unwrap(),
        next.state_carrier_capacity,
    )
    .unwrap();
    assert_eq!(decoded, next);
    let restarted: MultiAssetChannelBackend =
        serde_json::from_slice(&serde_json::to_vec(&alice).unwrap()).unwrap();
    assert_eq!(restarted.current(), &next);
}

#[test]
fn multi_asset_backend_cancel_and_restart_cannot_reuse_signed_state_number() {
    let original = fixture(2);
    let mut backend =
        MultiAssetChannelBackend::new(original.clone(), participant_pubkey(1)).unwrap();
    let proposal = backend.propose(original.settlement.clone()).unwrap();
    assert_eq!(
        backend
            .record_signature(proposal_signature(&proposal, 1))
            .unwrap_err(),
        MultiAssetBackendError::UnreservedSignature
    );
    backend.reserve_signature().unwrap();
    backend
        .record_signature(proposal_signature(&proposal, 1))
        .unwrap();
    backend.cancel_proposal();
    let mut backend: MultiAssetChannelBackend =
        serde_json::from_slice(&serde_json::to_vec(&backend).unwrap()).unwrap();
    let mut conflicting = proposal.clone();
    conflicting.settlement.payouts[0].values[0].amount -= 1;
    conflicting.settlement.payouts[0].values[1].amount += 1;
    conflicting.state.header.settlement_descriptor_commitment =
        conflicting.settlement.commitment().unwrap();
    assert_eq!(
        backend.accept_proposal(conflicting).unwrap_err(),
        MultiAssetBackendError::ConflictingVote
    );
    // Delivery retry for the same signed digest remains recoverable.
    backend.accept_proposal(proposal.clone()).unwrap();
    assert_eq!(
        backend.reserve_signature().unwrap().signing_digest,
        proposal.signing_digest().unwrap()
    );
    backend.cancel_proposal();
    let next = backend.propose(original.settlement).unwrap();
    assert_eq!(
        next.state.header.state_number,
        proposal.state.header.state_number + 1
    );
}

#[test]
fn multi_asset_backend_rejects_mint_context_changes_and_foreign_signatures_without_mutation() {
    let original = fixture(2);
    let mut backend =
        MultiAssetChannelBackend::new(original.clone(), participant_pubkey(1)).unwrap();
    let before = backend.clone();
    let mut mint = original.settlement.clone();
    mint.payouts[0].values[0].amount += 1;
    mint.payouts[1].values[0].amount -= 1;
    assert!(backend.propose(mint).is_err());
    assert_eq!(backend, before);
    let proposal = backend.propose(original.settlement).unwrap();
    let before = backend.clone();
    assert_eq!(
        backend
            .record_signature(proposal_signature(&proposal, 3))
            .unwrap_err(),
        MultiAssetBackendError::UnknownParticipant
    );
    assert_eq!(backend, before);
    backend.reserve_signature().unwrap();
    let mut invalid = proposal_signature(&proposal, 1);
    invalid.signature[0] ^= 1;
    assert_eq!(
        backend.record_signature(invalid).unwrap_err(),
        MultiAssetBackendError::InvalidSignature
    );
    let mut foreign_context = proposal.clone();
    foreign_context.state.header.funding_epoch += 1;
    assert_eq!(
        backend.accept_proposal(foreign_context).unwrap_err(),
        MultiAssetBackendError::StaleProposal
    );
}

#[test]
fn multi_asset_backend_restoration_rejects_tampered_pending_and_vote_snapshots() {
    let original = fixture(2);
    let mut backend =
        MultiAssetChannelBackend::new(original.clone(), participant_pubkey(1)).unwrap();
    backend.propose(original.settlement).unwrap();
    backend.reserve_signature().unwrap();
    let encoded = serde_json::to_value(&backend).unwrap();
    let mut corrupt = encoded.clone();
    corrupt["pending"]["proposal"]["state"]["header"]["funding_epoch"] = 2.into();
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(corrupt).is_err());
    let mut corrupt = encoded.clone();
    corrupt["reservation"]["state_number"] = 0.into();
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(corrupt).is_err());
    let mut obsolete_alias = encoded.clone();
    obsolete_alias["current"]["state"]["header"]["vault_commitment"] =
        serde_json::json!(vec![0; 32]);
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(obsolete_alias).is_err());
    let mut incomplete = encoded.clone();
    incomplete.as_object_mut().unwrap().remove("pending");
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(incomplete).is_err());
    let mut corrupt = encoded;
    corrupt["reservation"]["signing_digest"][0] = 99.into();
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(corrupt).is_err());
}

#[test]
fn multi_asset_backend_recovers_delayed_complete_update_without_resetting_newer_vote() {
    let original = fixture(2);
    let mut alice = MultiAssetChannelBackend::new(original.clone(), participant_pubkey(1)).unwrap();
    let mut bob = MultiAssetChannelBackend::new(original.clone(), participant_pubkey(2)).unwrap();
    let first = alice.propose(original.settlement.clone()).unwrap();
    bob.accept_proposal(first.clone()).unwrap();
    for backend in [&mut alice, &mut bob] {
        backend.reserve_signature().unwrap();
    }
    alice
        .record_signature(proposal_signature(&first, 1))
        .unwrap();
    bob.record_signature(proposal_signature(&first, 1)).unwrap();
    bob.record_signature(proposal_signature(&first, 2)).unwrap();
    let completed = bob.commit().unwrap();
    // Alice lost Bob's final signature and moved on to another reserved vote.
    alice.cancel_proposal();
    let later = alice.propose(original.settlement).unwrap();
    let later_vote = alice.reserve_signature().unwrap();
    alice.recover_committed(completed.clone()).unwrap();
    assert_eq!(alice.current(), &completed);
    assert_eq!(alice.reservation(), &later_vote);
    assert!(alice.proposal().is_none());
    assert_eq!(
        alice
            .propose(completed.settlement.clone())
            .unwrap()
            .state
            .header
            .state_number,
        later.state.header.state_number + 1
    );
    // Another signer cannot use this recovery path to erase a newer vote or
    // inject a state this canonical local journal never authorised.
    let before = alice.clone();
    let mut future = completed;
    future.state.header.state_number = later_vote.state_number + 10;
    sign(&mut future);
    assert_eq!(
        alice.recover_committed(future).unwrap_err(),
        MultiAssetBackendError::ConflictingVote
    );
    assert_eq!(alice, before);
}

#[test]
fn multi_asset_header_has_no_single_vault_fields_or_alternate_lengths() {
    let package = fixture(2);
    let raw = package.state.encode().unwrap();
    assert_eq!(raw.len(), 318);
    for length in [317, 319, 346, 414] {
        let mut unsupported = raw.to_vec();
        unsupported.resize(length, 0);
        assert!(wire::MultiAssetStateHeader::parse(&unsupported).is_err());
    }
    for field in [
        "vault_set_commitment",
        "vault_materialisation_root",
        "vault_outpoint_commitment",
    ] {
        let mut header = serde_json::to_value(&package.state.header).unwrap();
        header[field] = serde_json::json!(vec![0u8; 32]);
        assert!(serde_json::from_value::<MultiAssetHeader>(header).is_err());
    }
}

fn splice_settlement(
    manifest: &MultiAssetManifest,
    template: &MultiAssetSettlement,
) -> MultiAssetSettlement {
    let mut result = template.clone();
    result.payouts = manifest
        .vaults
        .iter()
        .map(|vault| {
            let left = MultiAssetValue {
                reserve: vault.value.reserve / 2,
                business_ckb: vault.value.business_ckb / 2,
                amount: vault.value.amount / 2,
            };
            MultiAssetPayout {
                asset: vault.asset.clone(),
                values: [
                    left,
                    MultiAssetValue {
                        reserve: vault.value.reserve - left.reserve,
                        business_ckb: vault.value.business_ckb - left.business_ckb,
                        amount: vault.value.amount - left.amount,
                    },
                ],
            }
        })
        .collect();
    result
}

fn splice_proposal(current: &MultiAssetRecoveryPackage) -> MultiAssetSpliceProposal {
    let point = MultiAssetOutPoint {
        tx_hash: [88; 32],
        index: 0,
    };
    let anchor = multi_asset_splice_funding_anchor(&point);
    let since = wire::MultiAssetVaultArgs::parse(&current.scripts.vault_lock[53..])
        .unwrap()
        .finalise_since();
    let mut state_args = anchor.to_vec();
    state_args.extend_from_slice(&since.to_le_bytes());
    let mut scripts = current.scripts.clone();
    scripts.state_type = script(3, &state_args);
    scripts.state_lock = script(2, &blake2b256(&scripts.state_type));
    scripts.vault_lock = script(
        1,
        &wire::encode_multi_asset_vault_args(
            &anchor,
            since,
            &blake2b256(&scripts.state_type),
            &blake2b256(&scripts.state_lock),
        )
        .unwrap(),
    );
    let mut manifest = current.manifest.clone();
    for vault in &mut manifest.vaults {
        vault.lock_hash = blake2b256(&scripts.vault_lock);
    }
    // Admit one asset, fully withdraw another, and top up the retained token
    // without charging additional CKB reserve to the token-only deposit.
    let removed = manifest.vaults.pop().unwrap();
    scripts
        .type_scripts
        .retain(|entry| VaultAsset::Xudt(entry.type_hash) != removed.asset);
    let admitted_script = script(5, &[99]);
    let admitted_hash = blake2b256(&admitted_script);
    let admitted = MultiAssetVault {
        asset: VaultAsset::Xudt(admitted_hash),
        lock_hash: blake2b256(&scripts.vault_lock),
        value: removed.value,
    };
    scripts.type_scripts.push(MultiAssetTypeScript {
        type_hash: admitted_hash,
        script: admitted_script,
    });
    scripts.type_scripts.sort_by_key(|entry| entry.type_hash);
    for vault in &mut manifest.vaults {
        vault.value.amount += 100;
    }
    let mut flows = manifest
        .vaults
        .iter()
        .map(|vault| MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: MultiAssetValue {
                amount: 100,
                ..MultiAssetValue::default()
            },
            withdrawal: MultiAssetValue::default(),
        })
        .collect::<Vec<_>>();
    flows.push(MultiAssetSpliceFlow {
        asset: removed.asset,
        deposit: MultiAssetValue::default(),
        withdrawal: removed.value,
    });
    flows.push(MultiAssetSpliceFlow {
        asset: admitted.asset.clone(),
        deposit: admitted.value,
        withdrawal: MultiAssetValue::default(),
    });
    flows.sort_by_key(|flow| flow.asset.clone());
    manifest.vaults.push(admitted);
    manifest.vaults.sort_by_key(|entry| entry.asset.clone());
    let settlement = splice_settlement(&manifest, &current.settlement);
    let mut state = current.state.clone();
    state.header.funding_epoch += 1;
    state.header.funding_anchor = anchor;
    state.header.state_number = 0;
    state.header.phase = Phase::Active;
    state.header.asset_registry_commitment =
        asset_registry_commitment(&manifest.registry().unwrap());
    state.header.settlement_descriptor_commitment = settlement.commitment().unwrap();
    state.vault_content_set_root = manifest.commitment().unwrap();
    state.vault_outpoint_set_root = [0; 32];
    state.vault_count = manifest.vaults.len() as u16;
    let mut plan = MultiAssetSpliceProposal {
        base_state_digest: current.state.signing_digest().unwrap(),
        old_state_outpoint: point,
        transaction_hash: [99; 32],
        new_state_authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        initial_recovery_authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        new_state: state,
        new_manifest: manifest,
        new_settlement: settlement,
        new_scripts: scripts,
        flows,
        withdrawal_lock: current.scripts.participant_locks[0].clone(),
    };
    sign_splice_funding(&mut plan, current);
    plan
}

fn sign_splice_funding(plan: &mut MultiAssetSpliceProposal, current: &MultiAssetRecoveryPackage) {
    let mut funding = MultiAssetRecoveryPackage {
        state: plan.new_state.clone(),
        authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        manifest: plan.new_manifest.clone(),
        settlement: plan.new_settlement.clone(),
        scripts: plan.new_scripts.clone(),
        outpoints: vec![],
        state_carrier_capacity: current.state_carrier_capacity,
    };
    sign(&mut funding);
    plan.new_state_authorization = funding.authorization.clone();
    funding.state.header.phase = Phase::Settling;
    funding.state.header.state_number = 1;
    funding.outpoints = (0..funding.manifest.vaults.len())
        .map(|index| MultiAssetOutPoint {
            tx_hash: plan.transaction_hash,
            index: index as u32 + 1,
        })
        .collect();
    funding.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&funding.manifest, &funding.outpoints).unwrap();
    sign(&mut funding);
    plan.initial_recovery_authorization = funding.authorization;
}

fn splice_signature(
    plan: &MultiAssetSpliceProposal,
    current: &MultiAssetRecoveryPackage,
    seed: u8,
) -> ParticipantSignature {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let signature: Signature = key
        .sign_prehash(&plan.signing_digest(current).unwrap())
        .unwrap();
    ParticipantSignature {
        pubkey_sec1: participant_pubkey(seed),
        signature: signature.to_bytes().to_vec(),
    }
}

#[test]
fn multi_asset_splice_admits_removes_assets_and_matches_wire_signing_domains() {
    use morph_script_common::multi_asset_splice as splice;
    let current = fixture(2);
    let plan = splice_proposal(&current);
    plan.validate(&current).unwrap();
    let raw = encode_multi_asset_splice_flows(&plan.flows).unwrap();
    let flows = splice::MultiAssetSpliceFlows::parse(&raw).unwrap();
    assert_eq!(
        flows.commitment(),
        multi_asset_splice_flow_commitment(&plan.flows).unwrap()
    );
    let header = plan.encode_header(&current).unwrap();
    let header = splice::MultiAssetSpliceHeader::parse(&header).unwrap();
    assert_eq!(
        header.signing_digest(),
        plan.signing_digest(&current).unwrap()
    );
    assert_eq!(
        header.new_funding_anchor(),
        multi_asset_splice_funding_anchor(&plan.old_state_outpoint)
    );
    let mut auth = StateAuthorization {
        threshold: 2,
        signatures: vec![
            splice_signature(&plan, &current, 1),
            splice_signature(&plan, &current, 2),
        ],
    };
    auth.signatures
        .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
    plan.verify_authorization(&current, &auth).unwrap();
    assert!(
        plan.verify_authorization(&current, &current.authorization)
            .is_err()
    );
    let mut wrong = plan;
    wrong.withdrawal_lock = current.scripts.participant_locks[1].clone();
    assert!(wrong.verify_authorization(&current, &auth).is_err());
}

#[test]
fn multi_asset_splice_rejects_cross_asset_lane_minting_missing_flows_and_context_changes() {
    let current = fixture(2);
    let good = splice_proposal(&current);
    for mutation in 0..10 {
        let mut plan = good.clone();
        match mutation {
            0 => {
                let indices = plan
                    .flows
                    .iter()
                    .enumerate()
                    .filter(|(_, flow)| flow.deposit.amount > 0)
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                plan.flows[indices[0]].deposit.amount += 1;
                plan.flows[indices[1]].deposit.amount -= 1;
            }
            1 => {
                plan.flows.swap(0, 1);
            }
            2 => {
                plan.flows.pop();
            }
            3 => {
                plan.new_state.header.funding_epoch = 0;
                sign_splice_funding(&mut plan, &current);
            }
            4 => {
                plan.old_state_outpoint.tx_hash = [0; 32];
            }
            5 => {
                plan.withdrawal_lock.clear();
            }
            6 => {
                plan.flows[0].deposit.reserve = u64::MAX;
            }
            7 => {
                plan.flows[0].deposit.amount = u128::MAX;
            }
            8 => {
                plan.new_scripts.state_type[16] ^= 1;
            }
            _ => {
                let flow = plan
                    .flows
                    .iter_mut()
                    .find(|flow| flow.withdrawal.reserve > 1000)
                    .unwrap();
                flow.withdrawal.reserve -= 1000;
                flow.withdrawal.business_ckb += 1000;
            }
        }
        assert!(plan.validate(&current).is_err(), "mutation {mutation}");
    }
    let mut raw = encode_multi_asset_splice_flows(&good.flows).unwrap();
    raw[2] = 1;
    assert!(morph_script_common::multi_asset_splice::MultiAssetSpliceFlows::parse(&raw).is_err());
}

#[test]
fn multi_asset_splice_freezes_old_votes_across_restart_and_cannot_be_cancelled_after_reserving() {
    let current = fixture(2);
    let plan = splice_proposal(&current);
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_splice(plan.clone()).unwrap();
    backend.cancel_splice().unwrap();
    backend.prepare_splice(plan.clone()).unwrap();
    let local = splice_signature(&plan, &current, 1);
    assert_eq!(
        backend.record_splice_signature(local.clone()).unwrap_err(),
        MultiAssetBackendError::UnreservedSignature
    );
    backend.reserve_splice_signature().unwrap();
    backend = serde_json::from_slice(&serde_json::to_vec(&backend).unwrap()).unwrap();
    backend.record_splice_signature(local).unwrap();
    backend
        .record_splice_signature(splice_signature(&plan, &current, 2))
        .unwrap();
    plan.verify_authorization(&current, &backend.splice_authorization().unwrap())
        .unwrap();
    assert_eq!(
        backend.cancel_splice().unwrap_err(),
        MultiAssetBackendError::SpliceFrozen
    );
    assert_eq!(
        backend.propose(current.settlement.clone()).unwrap_err(),
        MultiAssetBackendError::SpliceFrozen
    );
    assert_eq!(
        backend.recover_committed(current.clone()).unwrap_err(),
        MultiAssetBackendError::SpliceFrozen
    );
    let mut corrupt = serde_json::to_value(&backend).unwrap();
    corrupt["splice"]["signature_reserved"] = false.into();
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(corrupt).is_err());
    let mut missing = serde_json::to_value(&backend).unwrap();
    missing.as_object_mut().unwrap().remove("splice");
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(missing).is_err());
    let mut unresolved =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    unresolved.propose(current.settlement.clone()).unwrap();
    unresolved.reserve_signature().unwrap();
    unresolved.cancel_proposal();
    assert_eq!(
        unresolved.prepare_splice(plan).unwrap_err(),
        MultiAssetBackendError::UnsettledVotes
    );
}

#[test]
fn multi_asset_splice_transaction_replacement_requires_new_exit_and_bridge_signatures() {
    let current = fixture(2);
    let plan = splice_proposal(&current);
    let mut auth = StateAuthorization {
        threshold: 2,
        signatures: vec![
            splice_signature(&plan, &current, 1),
            splice_signature(&plan, &current, 2),
        ],
    };
    auth.signatures
        .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
    let mut replacement = plan.clone();
    replacement.transaction_hash[0] ^= 1;
    assert!(replacement.validate(&current).is_err());
    sign_splice_funding(&mut replacement, &current);
    replacement.validate(&current).unwrap();
    assert_ne!(
        plan.signing_digest(&current).unwrap(),
        replacement.signing_digest(&current).unwrap()
    );
    assert!(replacement.verify_authorization(&current, &auth).is_err());
    let mut incomplete = plan.clone();
    incomplete.initial_recovery_authorization.signatures.pop();
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_splice(incomplete).unwrap();
    assert!(backend.reserve_splice_signature().is_err());
    backend.validate().unwrap();
    backend.cancel_splice().unwrap();
    let mut incomplete = plan;
    incomplete.new_state_authorization.signatures.pop();
    backend.prepare_splice(incomplete).unwrap();
    assert!(backend.reserve_splice_signature().is_err());
    backend.validate().unwrap();
}

#[test]
fn multi_asset_splice_full_asset_replacement_uses_bounded_complete_union() {
    use morph_script_common::multi_asset_splice as splice;
    let current = fixture(8);
    let mut plan = splice_proposal(&current);
    let template = plan.new_manifest.vaults[0].clone();
    plan.new_manifest.vaults.clear();
    plan.new_scripts.type_scripts.clear();
    plan.flows = current
        .manifest
        .vaults
        .iter()
        .map(|vault| MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: MultiAssetValue::default(),
            withdrawal: vault.value,
        })
        .collect();
    for index in 0..8 {
        let raw = script(5, &[100 + index]);
        let hash = blake2b256(&raw);
        let mut vault = template.clone();
        vault.asset = VaultAsset::Xudt(hash);
        plan.flows.push(MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: vault.value,
            withdrawal: MultiAssetValue::default(),
        });
        plan.new_manifest.vaults.push(vault);
        plan.new_scripts.type_scripts.push(MultiAssetTypeScript {
            type_hash: hash,
            script: raw,
        });
    }
    plan.flows.sort_by_key(|flow| flow.asset.clone());
    plan.new_manifest
        .vaults
        .sort_by_key(|vault| vault.asset.clone());
    plan.new_scripts
        .type_scripts
        .sort_by_key(|entry| entry.type_hash);
    plan.new_settlement = splice_settlement(&plan.new_manifest, &current.settlement);
    plan.new_state.vault_content_set_root = plan.new_manifest.commitment().unwrap();
    plan.new_state.header.asset_registry_commitment =
        asset_registry_commitment(&plan.new_manifest.registry().unwrap());
    plan.new_state.header.settlement_descriptor_commitment =
        plan.new_settlement.commitment().unwrap();
    sign_splice_funding(&mut plan, &current);
    plan.validate(&current).unwrap();
    let raw = encode_multi_asset_splice_flows(&plan.flows).unwrap();
    assert_eq!(
        splice::MultiAssetSpliceFlows::parse(&raw).unwrap().count(),
        16
    );
    assert_eq!(raw.len(), 4 + 16 * 97);
    plan.flows.push(plan.flows[0].clone());
    assert!(plan.validate(&current).is_err());
}

#[test]
fn multi_asset_splice_funding_votes_survive_restart_and_gate_bridge_signing() {
    let current = fixture(2);
    let signed = splice_proposal(&current);
    let mut unsigned = signed.clone();
    unsigned.new_state_authorization.signatures.clear();
    unsigned.initial_recovery_authorization.signatures.clear();
    let mut backend =
        MultiAssetChannelBackend::new(current.clone(), participant_pubkey(1)).unwrap();
    backend.prepare_splice(unsigned).unwrap();
    assert!(backend.reserve_splice_signature().is_err());
    for (kind, auth, digest) in [
        (
            MultiAssetSpliceFundingKind::Creation,
            &signed.new_state_authorization,
            signed.new_state.signing_digest().unwrap(),
        ),
        (
            MultiAssetSpliceFundingKind::InitialRecovery,
            &signed.initial_recovery_authorization,
            signed
                .initial_recovery(&current)
                .unwrap()
                .state
                .signing_digest()
                .unwrap(),
        ),
    ] {
        let local = auth
            .signatures
            .iter()
            .find(|sig| sig.pubkey_sec1 == participant_pubkey(1))
            .unwrap();
        assert_eq!(
            backend
                .record_splice_funding_signature(kind, local.clone())
                .unwrap_err(),
            MultiAssetBackendError::UnreservedSignature
        );
        assert_eq!(
            backend.reserve_splice_funding_signature(kind).unwrap(),
            digest
        );
        backend = serde_json::from_slice(&serde_json::to_vec(&backend).unwrap()).unwrap();
        for signature in &auth.signatures {
            backend
                .record_splice_funding_signature(kind, signature.clone())
                .unwrap();
            backend
                .record_splice_funding_signature(kind, signature.clone())
                .unwrap();
        }
        backend.validate().unwrap();
    }
    assert_eq!(
        backend.reserve_splice_signature().unwrap(),
        signed.signing_digest(&current).unwrap()
    );
    backend = serde_json::from_slice(&serde_json::to_vec(&backend).unwrap()).unwrap();
    assert_eq!(
        backend.cancel_splice().unwrap_err(),
        MultiAssetBackendError::SpliceFrozen
    );
    assert!(backend.propose(current.settlement.clone()).is_err());
    let snapshot = serde_json::to_value(&backend).unwrap();
    for field in ["creation_reserved", "initial_recovery_reserved"] {
        let mut missing = snapshot.clone();
        missing["splice"].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<MultiAssetChannelBackend>(missing).is_err());
    }
    let mut corrupt = snapshot;
    let byte = &mut corrupt["splice"]["proposal"]["initial_recovery_authorization"]["signatures"]
        [0]["signature"][0];
    *byte = serde_json::json!(byte.as_u64().unwrap() ^ 1);
    assert!(serde_json::from_value::<MultiAssetChannelBackend>(corrupt).is_err());
}

#[path = "multi_asset_cases/factory.rs"]
mod factory_materialisation;

#[path = "multi_asset_cases/payments.rs"]
mod payments;

#[path = "multi_asset_cases/conditional_backend.rs"]
mod conditional_backend;

#[path = "multi_asset_cases/bridge.rs"]
mod bridge;

#[test]
fn current_state_type_args_have_one_shared_direct_and_factory_origin_layout() {
    use wire::MultiAssetStateTypeArgs;
    let anchor = [4; 32];
    let origin = [7; 32];
    let since = morph_script_common::relative_block_since(6).unwrap();
    let mut direct = anchor.to_vec();
    direct.extend_from_slice(&since.to_le_bytes());
    let parsed = MultiAssetStateTypeArgs::parse(&direct).unwrap();
    assert_eq!(parsed.funding_anchor(), anchor);
    assert_eq!(parsed.factory_origin(), None);
    assert_eq!(parsed.finalise_since(), since);
    let mut child = anchor.to_vec();
    child.extend_from_slice(&origin);
    child.extend_from_slice(&since.to_le_bytes());
    let parsed = MultiAssetStateTypeArgs::parse(&child).unwrap();
    assert_eq!(parsed.funding_anchor(), anchor);
    assert_eq!(parsed.factory_origin(), Some(origin.as_slice()));
    assert_eq!(parsed.finalise_since(), since);
    for len in [0, 32, 39, 41, 64, 71, 73, 139] {
        assert!(MultiAssetStateTypeArgs::parse(&vec![1; len]).is_err());
    }
    let mut zero_origin = child.clone();
    zero_origin[32..64].fill(0);
    assert!(MultiAssetStateTypeArgs::parse(&zero_origin).is_err());
    let mut wrong_order = direct.clone();
    wrong_order.extend_from_slice(&origin);
    assert!(MultiAssetStateTypeArgs::parse(&wrong_order).is_err());
    for invalid in [
        6,
        (1u64 << 63) | (1 << 61) | 6,
        (1u64 << 63) | (1 << 56) | 6,
    ] {
        let mut invalid_since = child.clone();
        invalid_since[64..72].copy_from_slice(&invalid.to_le_bytes());
        assert!(MultiAssetStateTypeArgs::parse(&invalid_since).is_err());
    }
}

proptest! {
    #[test]
    fn current_state_digest_binds_every_encoded_byte(index in 0usize..318, bit in 0u8..8) {
        let package = fixture(1);
        let encoded = package.state.encode().unwrap();
        let mut changed = encoded;
        changed[index] ^= 1 << bit;
        if let Ok(parsed) = wire::MultiAssetStateHeader::parse(&changed) {
            prop_assert_ne!(parsed.signing_digest(), package.state.signing_digest().unwrap());
        }
    }

    #[test]
    fn current_state_context_freezes_all_non_progress_fields(field in 0usize..13, marker in 64u8..=240) {
        let package = fixture(1);
        let before = package.state.encode().unwrap();
        let mut changed = package.state.clone();
        match field {
            0 => changed.header.chain_id = [marker;32],
            1 => changed.header.channel_id = [marker;32],
            2 => changed.header.funding_epoch += 1,
            3 => changed.header.funding_anchor = [marker;32],
            4 => changed.header.participants_commitment = [marker;32],
            5 => changed.header.asset_registry_commitment = [marker;32],
            6 => changed.header.challenge_policy_commitment = [marker;32],
            7 => changed.vault_content_set_root = [marker;32],
            8 => changed.vault_outpoint_set_root = [marker;32],
            9 => changed.vault_count += 1,
            10 => changed.header.protocol_version += 1,
            11 => changed.header.signature_scheme_id += 1,
            _ => changed.header.descriptor_version += 1,
        }
        if let Ok(after) = changed.encode() {
            let old = wire::MultiAssetStateHeader::parse(&before).unwrap();
            let new = wire::MultiAssetStateHeader::parse(&after).unwrap();
            prop_assert!(!old.same_context_except_progress(&new), "field {}", field);
        }
    }
}
