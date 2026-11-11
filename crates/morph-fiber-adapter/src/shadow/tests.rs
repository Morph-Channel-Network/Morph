mod model;

use std::{
    sync::{Arc, Barrier},
    thread,
};

use super::*;
use crate::tests::{edge, policy};

fn register(edge: &ProviderEdgeDescriptor, previous: Option<Bytes32>) -> ShadowMutation {
    ShadowMutation::Register(RegisterExternalEdgeRequest {
        edge: FiberExternalEdge::try_from(edge).unwrap(),
        expected_previous_edge_id: previous.map(|id| hex32(&id)),
        callback_endpoint: "http://127.0.0.1:4621/callback".into(),
    })
}
fn state_request(edge: &ProviderEdgeDescriptor, revision: u64) -> SetExternalEdgeStateRequest {
    SetExternalEdgeStateRequest {
        morph_edge_id: hex32(&edge.edge_id),
        expected_provider_revision: revision,
        reason: "canonical context retired".into(),
    }
}
fn update(edge: &ProviderEdgeDescriptor, revision: u64) -> ShadowMutation {
    ShadowMutation::Update(UpdateExternalEdgeRequest {
        edge: FiberExternalEdge::try_from(edge).unwrap(),
        expected_provider_revision: revision,
    })
}
fn changed(edge: &ProviderEdgeDescriptor) -> ProviderEdgeDescriptor {
    let mut result = edge.clone();
    result.state_number += 1;
    result.opaque_morph_commitment = [44; 32];
    result.directional_liquidity = [50, 50];
    result
}

#[test]
fn register_update_drain_disable_replies_survive_restart_without_reapplying() {
    let dir = private_dir();
    let path = dir.path().join("shadow.sqlite");
    let first = edge(1);
    let updated = changed(&first);
    let requests = [
        register(&first, None),
        update(&updated, 1),
        ShadowMutation::Drain(state_request(&first, 2)),
        ShadowMutation::Disable(state_request(&first, 3)),
    ];
    let mut acks = Vec::new();
    for request in &requests {
        let store = ShadowStore::open(&path, policy()).unwrap();
        let ack = store.apply(request.clone()).unwrap();
        assert!(!ack.forwarding);
        acks.push(ack);
    }
    let store = ShadowStore::open(&path, policy()).unwrap();
    for (request, ack) in requests.iter().zip(&acks) {
        assert_eq!(&store.apply(request.clone()).unwrap(), ack);
    }
    let current = store.list().unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].provider_revision, 4);
    assert_eq!(current[0].state, MirrorState::Disabled);
    assert!(!current[0].forwarding);
    assert!(matches!(
        store.apply(ShadowMutation::Drain(state_request(&first, 4))),
        Err(ShadowError::Conflict)
    ));
    // A cached registration acknowledgement is not the current list/state.
    assert_eq!(acks[0].state, MirrorState::Active);
    assert_eq!(store.list().unwrap()[0].state, MirrorState::Disabled);
}

#[test]
fn same_revision_conflicts_and_state_regression_cannot_change_mirror() {
    let dir = private_dir();
    let store = ShadowStore::open(&dir.path().join("shadow.sqlite"), policy()).unwrap();
    let first = edge(1);
    store.apply(register(&first, None)).unwrap();
    assert!(matches!(
        store.apply(register(&changed(&first), None)),
        Err(ShadowError::Conflict)
    ));
    let mut bad = first.clone();
    bad.directional_liquidity = [80, 20];
    assert!(matches!(
        store.apply(update(&bad, 1)),
        Err(ShadowError::Conflict)
    ));
    bad = changed(&first);
    store.apply(update(&bad, 1)).unwrap();
    assert!(matches!(
        store.apply(update(&first, 2)),
        Err(ShadowError::Conflict)
    ));
    assert!(matches!(
        store.apply(ShadowMutation::Disable(state_request(&first, 1))),
        Err(ShadowError::Conflict)
    ));
    assert_eq!(store.list().unwrap()[0].provider_revision, 2);
}

#[test]
fn two_connections_lost_reply_retry_has_one_durable_transition() {
    let dir = private_dir();
    let path = dir.path().join("shadow.sqlite");
    let a = ShadowStore::open(&path, policy()).unwrap();
    let b = ShadowStore::open(&path, policy()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let request = register(&edge(1), None);
    let task = |store: ShadowStore, barrier: Arc<Barrier>, request: ShadowMutation| {
        thread::spawn(move || {
            barrier.wait();
            store.apply(request).unwrap()
        })
    };
    let left = task(a, barrier.clone(), request.clone());
    let right = task(b, barrier, request.clone());
    assert_eq!(left.join().unwrap(), right.join().unwrap());
    let reopened = ShadowStore::open(&path, policy()).unwrap();
    assert_eq!(reopened.apply(request).unwrap().provider_revision, 1);
    assert_eq!(reopened.list().unwrap().len(), 1);
    assert_eq!(reopened.store.validate().unwrap().intents, 2); // install + registration
}

#[test]
fn splice_requires_all_old_assets_disabled_and_cannot_resurrect_old_context() {
    let dir = private_dir();
    let store = ShadowStore::open(&dir.path().join("shadow.sqlite"), policy()).unwrap();
    let first = edge(1);
    let mut token = first.clone();
    token.asset = GatewayAsset::Xudt {
        ckb_genesis_hash: [5; 32],
        type_script_hash: [81; 32],
    };
    token.edge_id = token.derive_id().unwrap();
    store.apply(register(&first, None)).unwrap();
    store.apply(register(&token, None)).unwrap();
    let mut successor = first.clone();
    successor.funding_context_id = [91; 32];
    successor.funding_epoch += 1;
    successor.edge_id = successor.derive_id().unwrap();
    let request = register(&successor, Some(first.edge_id));
    assert!(matches!(
        store.apply(request.clone()),
        Err(ShadowError::Conflict)
    ));
    store
        .apply(ShadowMutation::Drain(state_request(&first, 1)))
        .unwrap();
    assert!(matches!(
        store.apply(request.clone()),
        Err(ShadowError::Conflict)
    ));
    store
        .apply(ShadowMutation::Disable(state_request(&first, 2)))
        .unwrap();
    assert!(matches!(
        store.apply(request.clone()),
        Err(ShadowError::Conflict)
    ));
    store
        .apply(ShadowMutation::Disable(state_request(&token, 1)))
        .unwrap();
    assert!(matches!(
        store.apply(register(&successor, None)),
        Err(ShadowError::Conflict)
    ));
    store.apply(request).unwrap();
    store
        .apply(ShadowMutation::Disable(state_request(&successor, 1)))
        .unwrap();
    assert!(matches!(
        store.apply(update(&first, 3)),
        Err(ShadowError::Conflict)
    ));
    assert!(
        store
            .list()
            .unwrap()
            .iter()
            .all(|e| e.state == MirrorState::Disabled && !e.forwarding)
    );
}

#[test]
fn malformed_identity_wrong_network_and_asset_alias_are_rejected() {
    let dir = private_dir();
    let store = ShadowStore::open(&dir.path().join("shadow.sqlite"), policy()).unwrap();
    let mut request = register(&edge(1), None);
    if let ShadowMutation::Register(r) = &mut request {
        r.edge.factory_reservation_id = None;
    }
    assert!(matches!(store.apply(request), Err(ShadowError::Invalid)));
    assert!(matches!(
        store.apply(register(&edge(2), None)),
        Err(ShadowError::Invalid)
    ));
    let mut native = edge(1);
    native.asset = GatewayAsset::Xudt {
        ckb_genesis_hash: [5; 32],
        type_script_hash: [81; 32],
    };
    native.edge_id = native.derive_id().unwrap();
    store.apply(register(&native, None)).unwrap();
    let mut alias = native.clone();
    alias.asset = GatewayAsset::Rgbpp(morph_core::RgbppAssetId {
        ckb_genesis_hash: [5; 32],
        xudt_type_script_hash: [81; 32],
        bitcoin_network: morph_core::BitcoinNetwork::Regtest,
        binding_code_hash: [82; 32],
    });
    alias.edge_id = alias.derive_id().unwrap();
    assert!(matches!(
        store.apply(register(&alias, None)),
        Err(ShadowError::Conflict)
    ));
}

#[test]
fn store_reopen_requires_same_installed_fiber_patch_and_genesis() {
    let dir = private_dir();
    let path = dir.path().join("shadow.sqlite");
    drop(ShadowStore::open(&path, policy()).unwrap());
    for change in 0..3 {
        let mut p = policy();
        match change {
            0 => p.fiber_commit = "1".repeat(40),
            1 => p.patch_hash = hex32(&[99; 32]),
            _ => p.ckb_genesis_hash = hex32(&[99; 32]),
        }
        assert!(matches!(
            ShadowStore::open(&path, p),
            Err(ShadowError::Corrupt)
        ));
    }
    assert!(
        !ShadowStore::open(&path, policy())
            .unwrap()
            .capabilities()
            .unwrap()
            .forwarding
    );
}

#[test]
fn descriptor_round_trip_preserves_factory_identity_and_public_scalars_are_strict() {
    let original = edge(1);
    let wire = FiberExternalEdge::try_from(&original).unwrap();
    assert_eq!(ProviderEdgeDescriptor::try_from(&wire).unwrap(), original);
    let value = serde_json::to_value(&wire).unwrap();
    for field in [
        "factory_id",
        "factory_update_number",
        "factory_reservation_id",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<FiberExternalEdge>(missing).is_err(),
            "{field}"
        );
    }
    for invalid in [
        json!(1),
        json!("01"),
        json!("18446744073709551616"),
        json!("+1"),
    ] {
        let mut bad = value.clone();
        bad["state_number"] = invalid;
        assert!(serde_json::from_value::<FiberExternalEdge>(bad).is_err());
    }
    let mut unknown = value;
    unknown["forwarding"] = json!(true);
    assert!(serde_json::from_value::<FiberExternalEdge>(unknown).is_err());
    let mut bad = wire;
    bad.directional_liquidity[0] = "060".into();
    assert!(ProviderEdgeDescriptor::try_from(&bad).is_err());
}

#[test]
fn bounded_registry_never_evicts_retired_identity_to_make_room() {
    let dir = private_dir();
    let store = ShadowStore::open(&dir.path().join("shadow.sqlite"), policy()).unwrap();
    let original = edge(1);
    for index in 0..MAX_SHADOW_EDGES {
        let mut current = original.clone();
        current.channel_id = morph_core::blake2b256(&index.to_le_bytes());
        current.edge_id = current.derive_id().unwrap();
        store.apply(register(&current, None)).unwrap();
        if index == 0 {
            store
                .apply(ShadowMutation::Disable(state_request(&current, 1)))
                .unwrap();
        }
    }
    assert!(matches!(
        store.apply(register(&original, None)),
        Err(ShadowError::Full)
    ));
    let all = store.list().unwrap();
    assert_eq!(all.len(), MAX_SHADOW_EDGES);
    assert_eq!(
        all.iter()
            .filter(|edge| edge.state == MirrorState::Disabled)
            .count(),
        1
    );
    assert!(all.iter().all(|edge| !edge.forwarding));
}

#[test]
fn dispatch_exposes_only_six_shadow_methods_with_strict_parameters() {
    let dir = private_dir();
    let store = ShadowStore::open(&dir.path().join("shadow.sqlite"), policy()).unwrap();
    assert_eq!(SHADOW_METHODS.len(), 6);
    for unknown in [
        "graph_channels",
        "send_payment",
        "morph_prepare_payment",
        "morph_commit_payment",
    ] {
        assert_eq!(store.dispatch(unknown, json!({})).unwrap_err().code, -32601);
    }
    for malformed in [json!(null), json!([]), json!({"unknown":true})] {
        assert_eq!(
            store
                .dispatch(LIST_EXTERNAL_EDGES_METHOD, malformed)
                .unwrap_err()
                .code,
            -32602
        );
    }
    let request = register(&edge(1), None);
    let ShadowMutation::Register(request) = request else {
        unreachable!()
    };
    let value = serde_json::to_value(request).unwrap();
    let reply = store
        .dispatch(REGISTER_EXTERNAL_EDGE_METHOD, value.clone())
        .unwrap();
    assert_eq!(reply["provider_revision"], "1");
    assert_eq!(
        store
            .dispatch(REGISTER_EXTERNAL_EDGE_METHOD, value)
            .unwrap(),
        reply
    );
    assert_eq!(reply["forwarding"], false);
    let mut invalid = json!({"padding":"x".repeat(MAX_REQUEST_BYTES)});
    assert_eq!(
        store
            .dispatch(LIST_EXTERNAL_EDGES_METHOD, invalid.clone())
            .unwrap_err()
            .code,
        -32602
    );
    invalid["padding"] = json!("private-error-marker");
    let error = store
        .dispatch(REGISTER_EXTERNAL_EDGE_METHOD, invalid)
        .unwrap_err();
    assert!(!format!("{error:?}").contains("private-error-marker"));
}

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
