use super::*;
use morph_script_common::{FactorySignatureWitness, factory_multi_asset as factory};

fn child(count: usize, state_index: u32) -> FactoryMultiAssetChild {
    let mut recovery = fixture(count);
    let old = MultiAssetOutPoint {
        tx_hash: [41; 32],
        index: 0,
    };
    let mut anchor = vec![0u8; 8];
    anchor.extend_from_slice(&old.tx_hash);
    anchor.extend_from_slice(&old.index.to_le_bytes());
    anchor.extend_from_slice(&(state_index as u64).to_le_bytes());
    let anchor = blake2b256(&anchor);
    let since = morph_script_common::relative_block_since(6).unwrap();
    let mut args = anchor.to_vec();
    args.extend_from_slice(&[99; 32]);
    args.extend_from_slice(&since.to_le_bytes());
    recovery.scripts.state_type = script(3, &args);
    recovery.scripts.state_lock = script(2, &blake2b256(&recovery.scripts.state_type));
    let args = wire::encode_multi_asset_vault_args(
        &anchor,
        since,
        &blake2b256(&recovery.scripts.state_type),
        &blake2b256(&recovery.scripts.state_lock),
    )
    .unwrap();
    recovery.scripts.vault_lock = script(1, &args);
    for vault in &mut recovery.manifest.vaults {
        vault.lock_hash = blake2b256(&recovery.scripts.vault_lock);
    }
    recovery.state.header.funding_anchor = anchor;
    recovery.state.header.channel_id = blake2b256(&anchor);
    recovery.state.header.state_number = 1;
    recovery.state.vault_content_set_root = recovery.manifest.commitment().unwrap();
    for (i, point) in recovery.outpoints.iter_mut().enumerate() {
        point.index = state_index + 1 + i as u32;
    }
    recovery.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
    let mut child = FactoryMultiAssetChild {
        state_output_index: state_index,
        recovery,
    };
    resign_child(&mut child);
    child
}
fn resign_child(child: &mut FactoryMultiAssetChild) {
    let recovery = &mut child.recovery;
    recovery.state.header.asset_registry_commitment =
        asset_registry_commitment(&recovery.manifest.registry().unwrap());
    recovery.state.header.settlement_descriptor_commitment =
        recovery.settlement.commitment().unwrap();
    recovery.state.vault_content_set_root = recovery.manifest.commitment().unwrap();
    recovery.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
    sign(recovery);
}
fn plan(count: usize, child_count: usize, retained: bool) -> FactoryMultiAssetMaterialisation {
    let first_state = if retained { count as u32 + 1 } else { 1 };
    let children = (0..child_count)
        .map(|i| child(count, first_state + i as u32 * (count as u32 + 1)))
        .collect::<Vec<_>>();
    let mut source = children[0].recovery.manifest.clone();
    let mut args = vec![51; 32];
    args.extend_from_slice(&[99; 32]);
    let factory_vault_lock = script(6, &args);
    for vault in &mut source.vaults {
        vault.lock_hash = blake2b256(&factory_vault_lock);
    }
    let retained_manifest = retained.then(|| source.clone());
    for vault in &mut source.vaults {
        let scale = child_count as u64 + u64::from(retained);
        vault.value.reserve *= scale;
        vault.value.business_ckb *= scale;
        vault.value.amount *= scale as u128;
    }
    FactoryMultiAssetMaterialisation {
        chain_id: [1; 32],
        factory_id: [51; 32],
        participants_commitment: factory_members(2),
        old_state: MultiAssetOutPoint {
            tx_hash: [41; 32],
            index: 0,
        },
        transaction_hash: [44; 32],
        type_scripts: children[0].recovery.scripts.type_scripts.clone(),
        factory_vault_lock,
        source,
        source_outpoints: (0..count)
            .map(|i| MultiAssetOutPoint {
                tx_hash: [40; 32],
                index: i as u32 + 1,
            })
            .collect(),
        retained: retained_manifest,
        factory_carrier_capacity: 100_000_000_000,
        external_carrier_contribution: children
            .iter()
            .map(|child| child.recovery.state_carrier_capacity)
            .sum(),
        carrier_refund_lock: if retained {
            vec![]
        } else {
            script(4, &[1; 20])
        },
        children,
    }
}
fn factory_members(n: u8) -> Bytes32 {
    let mut raw = vec![1, 0, n, n];
    for seed in 1..=n {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        raw.extend_from_slice(&[seed; 32]);
        raw.extend_from_slice(key.verifying_key().to_sec1_point(true).as_bytes());
        raw.extend_from_slice(&[0; 64]);
    }
    FactorySignatureWitness::parse(&raw)
        .unwrap()
        .participants_commitment()
}
fn factory_authorization(
    plan: &FactoryMultiAssetMaterialisation,
    n: u8,
) -> (Bytes32, Vec<FactoryParticipantSignature>) {
    let digest = plan.signing_digest().unwrap();
    let authorization = (1..=n)
        .map(|seed| {
            let key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let signature: Signature = key.sign_prehash(&digest).unwrap();
            FactoryParticipantSignature {
                participant: [seed; 32],
                pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
            }
        })
        .collect::<Vec<_>>();
    let mut raw = vec![1, 0, n, n];
    for sig in &authorization {
        raw.extend_from_slice(&sig.participant);
        raw.extend_from_slice(&sig.pubkey_sec1);
        raw.extend_from_slice(&sig.signature);
    }
    (
        FactorySignatureWitness::parse(&raw)
            .unwrap()
            .participants_commitment(),
        authorization,
    )
}

#[test]
fn factory_public_fuzz_corpus_matches_current_encoders() {
    let mut frames = Vec::new();
    for (assets, children, retained, members) in
        [(2, 1, true, 2), (8, 4, true, 16), (8, 1, false, 16)]
    {
        let mut plan = plan(assets, children, retained);
        plan.participants_commitment = factory_members(members);
        let (commitment, authorization) = factory_authorization(&plan, members);
        frames.push(serde_json::json!({
            "target": "factory-materialisation",
            "assets": assets, "children": children, "retained": retained, "members": members,
            "frame_hex": hex::encode(plan.encode_witness(&commitment, &authorization).unwrap())
        }));
        for kind in [
            factory::FACTORY_STATE_WITNESS_ROOT,
            factory::FACTORY_STATE_WITNESS_ACTIVATE,
            factory::FACTORY_STATE_WITNESS_UPDATE,
        ] {
            // FS corpus exercises framing, not authority: these are FM-domain
            // signatures, deliberately not valid root/update approvals.
            let points = if kind == factory::FACTORY_STATE_WITNESS_ROOT {
                &[][..]
            } else {
                &plan.source_outpoints
            };
            let signatures = if kind == factory::FACTORY_STATE_WITNESS_ACTIVATE {
                &[][..]
            } else {
                &authorization
            };
            frames.push(serde_json::json!({
                "target": "factory-state", "kind": kind, "assets": assets, "members": members,
                "frame_hex": hex::encode(encode_factory_multi_asset_state_witness(
                    kind, &plan.source, points, signatures).unwrap())
            }));
        }
    }
    let value = serde_json::json!({
        "schema": "morph.factory_public_fuzz_corpus.v1",
        "provenance": "Synthetic current Core constructors. Public FS/FM frames only; no private child exits. FS is structural corpus with FM-domain signatures; FM verifies synthetic parent signatures, not physical transactions.",
        "cases": frames
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/protocol/factory-public-frames.json");
    if std::env::var("MORPH_UPDATE_FIXTURES").as_deref() == Ok("1") {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        )
        .unwrap();
    }
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        saved, value,
        "regenerate with MORPH_UPDATE_FIXTURES=1 cargo test -p morph-core --test multi_asset factory_public_fuzz_corpus_matches_current_encoders"
    );
}
#[test]
fn factory_partition_has_complete_child_exits_separate_carriers_and_n_of_n_authority() {
    for (assets, children, retained) in [(2, 1, true), (8, 4, true), (8, 1, false)] {
        let plan = plan(assets, children, retained);
        plan.validate_contents().unwrap();
        assert_eq!(
            plan.signing_digest().unwrap(),
            factory::materialisation_commitment(&plan.encode_intent().unwrap())
        );
        for n in [2, 3, 16] {
            let mut plan = plan.clone();
            plan.participants_commitment = factory_members(n);
            let (members, authorization) = factory_authorization(&plan, n);
            plan.verify_authorization(&members, &authorization).unwrap();
            if n > 2 {
                let mut downgraded = plan.clone();
                downgraded.participants_commitment = factory_members(2);
                assert!(
                    downgraded
                        .verify_authorization(&factory_members(2), &authorization[..2])
                        .is_err()
                );
            }
            assert!(
                plan.verify_authorization(&members, &authorization[..authorization.len() - 1])
                    .is_err()
            );
            let mut changed = plan.clone();
            changed.factory_id = [52; 32];
            assert!(
                changed
                    .verify_authorization(&members, &authorization)
                    .is_err()
            );
            let mut changed = plan.clone();
            changed.source_outpoints[0].index += 100;
            assert!(
                changed
                    .verify_authorization(&members, &authorization)
                    .is_err()
            );
        }
    }
}
#[test]
fn factory_partition_rejects_cross_asset_minting_reserve_subsidies_and_custody_overlap() {
    let good = plan(2, 1, true);
    for mutation in 0..14 {
        let mut bad = good.clone();
        match mutation {
            0 => {
                bad.source.vaults[0].value.amount += 1;
                bad.source.vaults[1].value.amount -= 1;
            }
            1 => {
                bad.source.vaults[0].value.reserve += 1;
                bad.source.vaults[0].value.business_ckb -= 1;
            }
            2 => bad.external_carrier_contribution = 0,
            3 => bad.external_carrier_contribution += 1,
            4 => {
                bad.children[0].recovery.authorization.signatures.pop();
            }
            5 => {
                bad.children[0].recovery.state.header.state_number = 0;
            }
            6 => bad.children[0].state_output_index = 0,
            7 => bad.children[0].state_output_index = 1,
            8 => bad.transaction_hash = [45; 32],
            9 => bad.source_outpoints[0] = bad.old_state.clone(),
            10 => bad.source_outpoints[1] = bad.source_outpoints[0].clone(),
            11 => {
                bad.retained.as_mut().unwrap().vaults[0].lock_hash = [89; 32];
            }
            12 => bad.carrier_refund_lock = script(4, &[1; 20]),
            _ => bad.children.clear(),
        }
        assert!(bad.validate_contents().is_err(), "mutation {mutation}");
    }
    let mut bad = plan(2, 1, false);
    bad.carrier_refund_lock.clear();
    assert!(bad.validate_contents().is_err());
    let mut bad = plan(2, 2, true);
    bad.children[1] = bad.children[0].clone();
    assert!(bad.validate_contents().is_err());
}
#[test]
fn factory_partition_accepts_outside_child_parties_but_preserves_parent_and_exit_authority() {
    let mut plan = plan(2, 1, true);
    let (members, mut auth) = factory_authorization(&plan, 2);
    let digest = plan.signing_digest().unwrap();
    for (i, sig) in auth.iter_mut().enumerate() {
        let key = SigningKey::from_slice(&[10 + i as u8; 32]).unwrap();
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        sig.pubkey_sec1 = key.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        sig.signature = signature.to_bytes().to_vec();
    }
    let mut raw = vec![1, 0, 2, 2];
    for sig in &auth {
        raw.extend_from_slice(&sig.participant);
        raw.extend_from_slice(&sig.pubkey_sec1);
        raw.extend_from_slice(&sig.signature);
    }
    let foreign_members = FactorySignatureWitness::parse(&raw)
        .unwrap()
        .participants_commitment();
    plan.participants_commitment = foreign_members;
    let digest = plan.signing_digest().unwrap();
    for (i, sig) in auth.iter_mut().enumerate() {
        let key = SigningKey::from_slice(&[10 + i as u8; 32]).unwrap();
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        sig.signature = signature.to_bytes().to_vec();
    }
    // The committed parent roster is 10/11 while the independently signed
    // child is 1/2. Receiving the released value needs no parent membership.
    plan.verify_authorization(&foreign_members, &auth).unwrap();
    assert!(plan.verify_authorization(&members, &auth).is_err());
    let mut wrong_parent_signature = auth.clone();
    wrong_parent_signature[0].signature[0] ^= 1;
    assert!(
        plan.verify_authorization(&foreign_members, &wrong_parent_signature)
            .is_err()
    );
    plan.children[0].recovery.authorization.signatures[0].signature[0] ^= 1;
    assert!(plan.verify_authorization(&foreign_members, &auth).is_err());
}

#[test]
fn factory_partition_handles_plain_ckb_and_rejects_underfunded_retained_reserve() {
    let mut good = plan(3, 1, true);
    good.source.vaults[0].asset = VaultAsset::Ckb;
    good.source.vaults[0].value.amount = 0;
    let retained = good.retained.as_mut().unwrap();
    retained.vaults[0].asset = VaultAsset::Ckb;
    retained.vaults[0].value.amount = 0;
    good.type_scripts.remove(0);
    let child = &mut good.children[0];
    child.recovery.manifest.vaults[0].asset = VaultAsset::Ckb;
    child.recovery.manifest.vaults[0].value.amount = 0;
    child.recovery.settlement.payouts[0].asset = VaultAsset::Ckb;
    for allocation in &mut child.recovery.settlement.payouts[0].values {
        allocation.amount = 0;
    }
    child.recovery.scripts.type_scripts.remove(0);
    resign_child(child);
    good.validate_contents().unwrap();
    let mut bad = good.clone();
    let retained = bad.retained.as_mut().unwrap();
    let removed = retained.vaults[0].value.reserve - 1;
    retained.vaults[0].value.reserve = 1;
    bad.source.vaults[0].value.reserve -= removed;
    assert!(bad.validate_contents().is_err());
    let mut bad = good.clone();
    bad.type_scripts.clear();
    assert!(bad.validate_contents().is_err());
    let mut bad = good.clone();
    bad.type_scripts.reverse();
    assert!(bad.validate_contents().is_err());
    let mut bad = good;
    bad.children = vec![bad.children[0].clone(); 5];
    assert!(bad.validate_contents().is_err());
}
#[test]
fn shared_factory_partition_rejects_u128_aggregation_overflow() {
    let good = plan(2, 1, true);
    let mut source = good.source.clone();
    source.vaults[0].value.amount = u128::MAX;
    let mut retained = good.retained.unwrap();
    retained.vaults[0].value.amount = u128::MAX;
    let mut child = good.children[0].recovery.manifest.clone();
    child.vaults[0].value.amount = 1;
    let source = source.encode().unwrap();
    let retained = retained.encode().unwrap();
    let child = child.encode().unwrap();
    assert!(
        factory::validate_materialisation_partition(
            &wire::MultiAssetVaultManifest::parse(&source).unwrap(),
            Some(&wire::MultiAssetVaultManifest::parse(&retained).unwrap()),
            &[wire::MultiAssetVaultManifest::parse(&child).unwrap()]
        )
        .is_err()
    );
}

#[test]
fn factory_public_witness_excludes_private_child_exit_signatures_and_is_strictly_framed() {
    let plan = plan(2, 1, false);
    let (members, auth) = factory_authorization(&plan, 2);
    let raw = plan.encode_witness(&members, &auth).unwrap();
    factory::FactoryMaterialisationWitness::parse(&raw)
        .unwrap()
        .verify()
        .unwrap();
    let intent_len = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
    let auth_len = u32::from_le_bytes(raw[16..20].try_into().unwrap()) as usize;
    assert_eq!(raw.len(), 24 + intent_len + auth_len + 66);
    for signature in &plan.children[0].recovery.authorization.signatures {
        assert!(
            !raw.windows(signature.signature.len())
                .any(|part| part == signature.signature)
        );
    }
    // Every incomplete frame and every trailing byte must fail. Exercise both
    // the full parser and the bounds-only view used by delegated scripts.
    for end in 0..raw.len() {
        assert!(factory::FactoryMaterialisationWitness::parse(&raw[..end]).is_err());
        assert!(factory::FactoryMaterialisationView::parse(&raw[..end]).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(factory::FactoryMaterialisationWitness::parse(&extra).is_err());
    assert!(factory::FactoryMaterialisationView::parse(&extra).is_err());
    let mut changed = raw;
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        factory::FactoryMaterialisationWitness::parse(&changed)
            .unwrap()
            .verify()
            .is_err()
    );
    let mut missing_exit = plan;
    missing_exit.children[0]
        .recovery
        .authorization
        .signatures
        .clear();
    assert!(missing_exit.signing_digest().is_err());
    assert!(missing_exit.encode_witness(&members, &auth).is_err());
}
