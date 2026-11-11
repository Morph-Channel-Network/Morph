//! Independent sequential edge oracle: a consumed revision slot has one reply,
//! retries are observations, and restart cannot change the current projection.
use super::*;

struct Model {
    edge: ProviderEdgeDescriptor,
    state: MirrorState,
    revision: u64,
    receipts: Vec<(ShadowMutation, FiberHookAck)>,
}
impl Model {
    fn accepted(&mut self, request: ShadowMutation, state: MirrorState, store: &ShadowStore) {
        self.revision += 1;
        self.state = state;
        let expected = FiberHookAck {
            morph_edge_id: hex32(&self.edge.edge_id),
            provider_revision: self.revision,
            state,
            forwarding: false,
            opaque_morph_commitment: hex32(&self.edge.opaque_morph_commitment),
        };
        assert_eq!(store.apply(request.clone()).unwrap(), expected);
        self.receipts.push((request, expected));
    }
    fn verify(&self, store: &ShadowStore) {
        assert_eq!(
            store.list().unwrap(),
            vec![MirroredFiberEdge {
                channel_id: hex32(&self.edge.channel_id),
                funding_epoch: self.edge.funding_epoch,
                morph_edge_id: hex32(&self.edge.edge_id),
                funding_context_id: hex32(&self.edge.funding_context_id),
                provider_revision: self.revision,
                state: self.state,
                forwarding: false,
                opaque_morph_commitment: hex32(&self.edge.opaque_morph_commitment),
            }]
        );
        let integrity = store.store.validate().unwrap();
        assert_eq!(integrity.revision, self.revision + 1); // installation
        assert_eq!(integrity.intents, self.receipts.len() as u64 + 1);
        assert_eq!(integrity.records, 1);
        assert_eq!(integrity.events, 0);
        assert_eq!(integrity.attempts, 0);
        assert!(!store.capabilities().unwrap().forwarding);
    }
}

#[test]
fn seeded_edge_revision_model_preserves_replies_projection_and_restart() {
    // Fixed xorshift64 seeds and bounded command count are reproducible in PR
    // and scheduled tests. No network, wall clock or probabilistic stopping rule.
    for seed in [1u64, 17, 332_043_276_360] {
        let directory = private_dir();
        let path = directory.path().join("model.sqlite");
        let mut store = ShadowStore::open(&path, policy()).unwrap();
        let mut model = Model {
            edge: edge(1),
            state: MirrorState::Active,
            revision: 0,
            receipts: vec![],
        };
        model.accepted(register(&model.edge, None), MirrorState::Active, &store);
        let mut rng = seed;
        let mut covered = [false; 11];
        for step in 0..128 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let command = if step < 11 { step } else { (rng % 11) as usize };
            covered[command] = true;
            let prior = model.receipts[(rng as usize) % model.receipts.len()].clone();
            match command {
                0 => {
                    model.edge.state_number += 1;
                    let left = u128::from(rng % 99 + 1);
                    model.edge.directional_liquidity = [left, 100 - left];
                    model.edge.opaque_morph_commitment = morph_core::blake2b256(&rng.to_le_bytes());
                    model.accepted(
                        update(&model.edge, model.revision),
                        MirrorState::Active,
                        &store,
                    );
                }
                1 => {
                    let request = ShadowMutation::Drain(state_request(&model.edge, model.revision));
                    if model.state == MirrorState::Disabled {
                        assert!(matches!(store.apply(request), Err(ShadowError::Conflict)));
                    } else {
                        model.accepted(request, MirrorState::Draining, &store);
                    }
                }
                2 => {
                    let request =
                        ShadowMutation::Disable(state_request(&model.edge, model.revision));
                    model.accepted(request, MirrorState::Disabled, &store);
                }
                3 => assert_eq!(store.apply(prior.0).unwrap(), prior.1),
                4 => {
                    // Different request at an already consumed revision slot.
                    let mut request = state_request(&model.edge, model.revision - 1);
                    request.reason = format!("stale-{seed}-{step}");
                    assert!(matches!(
                        store.apply(ShadowMutation::Disable(request)),
                        Err(ShadowError::Conflict)
                    ));
                }
                5 => {
                    let mut conflicting = model.edge.clone();
                    conflicting.directional_liquidity.swap(0, 1);
                    conflicting.opaque_morph_commitment[0] ^= 1;
                    assert!(matches!(
                        store.apply(update(&conflicting, model.revision)),
                        Err(ShadowError::Conflict)
                    ));
                }
                6 => {
                    let mut regressed = model.edge.clone();
                    regressed.state_number -= 1;
                    assert!(matches!(
                        store.apply(update(&regressed, model.revision)),
                        Err(ShadowError::Conflict)
                    ));
                }
                7 => {
                    drop(store);
                    store = ShadowStore::open(&path, policy()).unwrap();
                }
                8 => {
                    let mut unknown = state_request(&model.edge, 1);
                    unknown.morph_edge_id = hex32(&[0xee; 32]);
                    assert!(matches!(
                        store.apply(ShadowMutation::Disable(unknown)),
                        Err(ShadowError::NotFound)
                    ));
                }
                9 => {
                    // Mutating a saved request must never receive its old reply.
                    let mut conflict = prior.0;
                    match &mut conflict {
                        ShadowMutation::Register(r) => {
                            r.callback_endpoint = "http://127.0.0.1:4622/callback".into()
                        }
                        ShadowMutation::Update(r) => {
                            r.edge.opaque_morph_commitment = hex32(&[0xee; 32])
                        }
                        ShadowMutation::Drain(r) | ShadowMutation::Disable(r) => {
                            r.reason.push_str(" changed")
                        }
                    }
                    assert!(matches!(store.apply(conflict), Err(ShadowError::Conflict)));
                }
                10 => {
                    let request =
                        ShadowMutation::Disable(state_request(&model.edge, model.revision + 1));
                    assert!(matches!(store.apply(request), Err(ShadowError::Conflict)));
                }
                _ => unreachable!(),
            }
            model.verify(&store);
        }
        assert!(covered.into_iter().all(|covered| covered));
        drop(store);
        let store = ShadowStore::open(&path, policy()).unwrap();
        // Replaying every historical reply, newest to oldest, must leave the
        // final projection and durable history unchanged.
        for (request, expected) in model.receipts.iter().rev() {
            assert_eq!(store.apply(request.clone()).unwrap(), *expected);
            model.verify(&store);
        }
    }
}
