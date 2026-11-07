//! Shared TEST-ONLY request construction from the CKB-VM-qualified synthetic
//! corpus. Known fixture keys reconstruct private child exits locally; those
//! signatures are never added to the public SDK corpus or parent request.
use ckb_types::prelude::*;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::*;
use morph_script_common::{factory_multi_asset as wire, multi_asset as asset};

fn decode_point(raw: &[u8]) -> MultiAssetOutPoint {
    MultiAssetOutPoint {
        tx_hash: raw[..32].try_into().unwrap(),
        index: morph_script_common::read_u32(raw, 32),
    }
}
fn source_right(raw: &morph_script_common::FactoryRight<'_>) -> FactoryRight {
    FactoryRight {
        id: FactoryRightId {
            participant: raw.participant().try_into().unwrap(),
            subchannel: raw.subchannel().try_into().unwrap(),
            kind: match raw.kind() {
                0 => FactoryRightKind::Balance,
                1 => FactoryRightKind::ReserveClaim,
                2 => FactoryRightKind::Membership,
                3 => FactoryRightKind::ExitPath,
                4 => FactoryRightKind::SponsorBudgetClaim,
                _ => panic!("unknown fixture right"),
            },
            asset_type: if raw.asset_present() == 0 {
                None
            } else {
                Some(raw.asset_type().try_into().unwrap())
            },
        },
        quantity: raw.quantity(),
    }
}
fn types(
    frame: &wire::FactoryReducedReleaseWitness<'_>,
    manifest: &MultiAssetManifest,
) -> Vec<MultiAssetTypeScript> {
    manifest
        .vaults
        .iter()
        .filter_map(|vault| match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(MultiAssetTypeScript {
                type_hash: hash,
                script: frame
                    .type_script(asset::MultiAssetId::xudt(hash))
                    .unwrap()
                    .unwrap()
                    .to_vec(),
            }),
        })
        .collect()
}

pub fn reduced_child_request() -> (
    FactorySigningRequest,
    Vec<FactoryParticipantKey>,
    Vec<FactoryRight>,
    Vec<MultiAssetRecoveryPackage>,
) {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../sdk/typescript/test/fixtures/factory-transitions.json"
    ))
    .unwrap();
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["operation"] == "ReducedChild")
        .unwrap();
    let bytes = hex::decode(
        case["package"]["transaction_hex"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
    )
    .unwrap();
    let view = FactoryTransactionView::parse(&bytes).unwrap();
    let frame = view.witness().unwrap();
    let raw = view.transaction().raw();
    let state = raw.outputs().get(0).unwrap();
    let members = (0..frame.member_count())
        .map(|index| {
            let (id, key) = frame.member(index).unwrap();
            FactoryParticipantKey {
                participant: id.try_into().unwrap(),
                pubkey_sec1: key.to_vec(),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        members.len(),
        2,
        "this fixture reconstruction is intentionally specific to the known two-member corpus"
    );
    let manifest = MultiAssetManifest::decode(frame.source().as_bytes()).unwrap();
    let source = FactoryCustody {
        header: frame.before().as_bytes().to_vec(),
        state_out_point: decode_point(frame.old_state_outpoint()),
        vault_outpoints: frame
            .source_points()
            .chunks_exact(36)
            .map(decode_point)
            .collect(),
        state_type: state.type_().to_opt().unwrap().as_slice().to_vec(),
        state_lock: state.lock().as_slice().to_vec(),
        vault_lock: frame.factory_lock_script().to_vec(),
        type_scripts: types(&frame, &manifest),
        manifest,
        state_carrier_capacity: frame.carrier_capacity(),
    };
    source.validate().unwrap();
    let mut before = (0..frame.right_count())
        .map(|index| source_right(&frame.right(index).unwrap().before))
        .collect::<Vec<_>>();
    let peer = members[1].participant;
    let ckb: u128 = source
        .manifest
        .vaults
        .iter()
        .map(|vault| u128::from(vault.value.capacity().unwrap()))
        .sum();
    let owner_claim: u128 = before
        .iter()
        .filter(|right| right.id.asset_type.is_none())
        .map(|right| right.quantity)
        .sum();
    before.push(FactoryRight {
        id: FactoryRightId {
            participant: peer,
            subchannel: [0; 32],
            kind: FactoryRightKind::ReserveClaim,
            asset_type: None,
        },
        quantity: ckb - owner_claim,
    });
    for vault in &source.manifest.vaults {
        if let VaultAsset::Xudt(hash) = vault.asset {
            let owner_claim: u128 = before
                .iter()
                .filter(|right| right.id.participant != peer && right.id.asset_type == Some(hash))
                .map(|right| right.quantity)
                .sum();
            before.push(FactoryRight {
                id: FactoryRightId {
                    participant: peer,
                    subchannel: [0; 32],
                    kind: FactoryRightKind::ReserveClaim,
                    asset_type: Some(hash),
                },
                quantity: vault.value.amount - owner_claim,
            });
        }
    }
    before.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(
        factory_right_sparse_root(&before).unwrap(),
        frame.before().state_root(),
        "fixture complete rights must reproduce the exact committed root"
    );
    let mut after = before.clone();
    for index in 0..frame.right_count() {
        let updated = source_right(&frame.right(index).unwrap().after);
        let id = updated.id.clone();
        *after.iter_mut().find(|right| right.id == id).unwrap() = updated;
    }
    assert_eq!(
        factory_right_sparse_root(&after).unwrap(),
        frame.after().state_root()
    );
    let manifest = MultiAssetManifest::decode(frame.retained().as_bytes()).unwrap();
    let hash: Bytes32 = raw.calc_tx_hash().unpack();
    let points = (0..manifest.vaults.len())
        .map(|index| MultiAssetOutPoint {
            tx_hash: hash,
            index: index as u32 + 1,
        })
        .collect::<Vec<_>>();
    let mut header = frame.after().fields();
    header.outpoint_root = multi_asset_outpoint_commitment(&manifest, &points).unwrap();
    let target = FactoryCustody {
        header: header.encode().unwrap().to_vec(),
        state_out_point: MultiAssetOutPoint {
            tx_hash: hash,
            index: 0,
        },
        vault_outpoints: points,
        state_type: source.state_type.clone(),
        state_lock: source.state_lock.clone(),
        vault_lock: source.vault_lock.clone(),
        type_scripts: types(&frame, &manifest),
        manifest,
        state_carrier_capacity: source.state_carrier_capacity,
    };
    let intent = frame.child_intent().unwrap();
    let children = (0..intent.child_count())
        .map(|index| {
            let child = intent.child(index).unwrap();
            let mut recovery = MultiAssetRecoveryPackage::decode_contents(
                child.header.as_bytes(),
                child.evidence.as_bytes(),
                child.carrier_capacity,
            )
            .unwrap();
            recovery.authorization = StateAuthorization {
                threshold: 2,
                signatures: (1..=2)
                    .map(|seed| {
                        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                        let signature: Signature = key
                            .sign_prehash(&recovery.state.signing_digest().unwrap())
                            .unwrap();
                        ParticipantSignature {
                            pubkey_sec1: key
                                .verifying_key()
                                .to_sec1_point(true)
                                .as_bytes()
                                .to_vec(),
                            signature: signature.to_bytes().to_vec(),
                        }
                    })
                    .collect(),
            };
            recovery
                .authorization
                .signatures
                .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
            recovery.validate().unwrap();
            recovery
        })
        .collect::<Vec<_>>();
    let request = FactorySigningRequest {
        role: FactorySigningRole::Transition,
        source: Some(source),
        target: Some(target),
        transaction: raw.as_slice().to_vec(),
        witness: unsigned_factory_transition(frame.as_bytes()).unwrap(),
        target_rights: after,
        deliveries: vec![],
    };
    request.validate_for_review(&members).unwrap();
    (request, members, before, children)
}
