use super::*;

fn deployment() -> TrustedMorphDeployment {
    let identity = |code| TrustedScriptIdentity {
        code_hash: [code; 32],
        hash_type: 2,
    };
    TrustedMorphDeployment {
        ckb_genesis_hash: [1; 32],
        state_type: identity(3),
        state_lock: identity(2),
        vault_lock: identity(1),
        factory_type: identity(7),
        factory_vault_lock: identity(8),
    }
}

fn factory_origin(package: &mut MultiAssetRecoveryPackage) -> FactoryOriginEvidence {
    let factory_type = script(
        7,
        &morph_script_common::factory_multi_asset::encode_factory_multi_asset_type_args(&[7; 32])
            .unwrap(),
    );
    let hash = blake2b256(&factory_type);
    let mut reserve_args = [7; 32].to_vec();
    reserve_args.extend_from_slice(&hash);
    let vault_lock = script(8, &reserve_args);
    let mut source_manifest = package.manifest.clone();
    for vault in &mut source_manifest.vaults {
        vault.lock_hash = blake2b256(&vault_lock);
    }
    let points = (0..source_manifest.vaults.len())
        .map(|index| MultiAssetOutPoint {
            tx_hash: [71; 32],
            index: index as u32 + 1,
        })
        .collect::<Vec<_>>();
    let mut members = package
        .authorization
        .signatures
        .iter()
        .map(|signature| FactoryParticipantKey {
            participant: blake2b256(&signature.pubkey_sec1),
            pubkey_sec1: signature.pubkey_sec1.clone(),
        })
        .collect::<Vec<_>>();
    members.sort_by_key(|member| member.participant);
    let header = morph_script_common::factory_multi_asset::FactoryMultiAssetHeaderFields {
        chain_id: package.state.header.chain_id,
        factory_id: [7; 32],
        update_number: 9,
        state_root: [6; 32],
        participants_commitment: factory_membership_commitment(&members).unwrap(),
        access_manifest_root: [8; 32],
        non_interference_digest: [0; 32],
        challenge_policy_commitment: [3; 32],
        content_root: source_manifest.commitment().unwrap(),
        outpoint_root: multi_asset_outpoint_commitment(&source_manifest, &points).unwrap(),
        vault_count: source_manifest.vaults.len() as u16,
    };
    let origin = FactoryOriginEvidence {
        source: FactoryCustody {
            header: header.encode().unwrap().to_vec(),
            state_out_point: MultiAssetOutPoint {
                tx_hash: [70; 32],
                index: 0,
            },
            manifest: source_manifest,
            vault_outpoints: points,
            state_type: factory_type.clone(),
            state_lock: script(2, &hash),
            vault_lock,
            type_scripts: package.scripts.type_scripts.clone(),
            state_carrier_capacity: package.state_carrier_capacity,
        },
        members,
    };
    let mut args = package.state.header.funding_anchor.to_vec();
    args.extend_from_slice(&hash);
    args.extend_from_slice(
        &morph_script_common::relative_block_since(6)
            .unwrap()
            .to_le_bytes(),
    );
    package.scripts.state_type = script(3, &args);
    package.scripts.state_lock = script(2, &blake2b256(&package.scripts.state_type));
    let vault_args = wire::encode_multi_asset_vault_args(
        &package.state.header.funding_anchor,
        morph_script_common::relative_block_since(6).unwrap(),
        &blake2b256(&package.scripts.state_type),
        &blake2b256(&package.scripts.state_lock),
    )
    .unwrap();
    package.scripts.vault_lock = script(1, &vault_args);
    for vault in &mut package.manifest.vaults {
        vault.lock_hash = blake2b256(&package.scripts.vault_lock);
    }
    package.state.vault_content_set_root = package.manifest.commitment().unwrap();
    package.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&package.manifest, &package.outpoints).unwrap();
    sign(package);
    origin
}

fn evidence(factory: bool) -> MaterializedChannelEvidence {
    let mut recovery = fixture(2);
    let origin = factory.then(|| factory_origin(&mut recovery));
    evidence_from_recovery(recovery, origin)
}

fn evidence_from_recovery(
    recovery: MultiAssetRecoveryPackage,
    origin: Option<FactoryOriginEvidence>,
) -> MaterializedChannelEvidence {
    let mut actual = recovery.state.clone();
    actual.header.phase = Phase::Active;
    actual.header.state_number = 0;
    let state = MaterializedCellEvidence {
        out_point: CkbOutPoint {
            tx_hash: [88; 32],
            index: 0,
        },
        lock: recovery.scripts.state_lock.clone(),
        type_script: Some(recovery.scripts.state_type.clone()),
        capacity: recovery.state_carrier_capacity,
        data: actual.encode().unwrap().to_vec(),
    };
    let vaults = recovery
        .manifest
        .vaults
        .iter()
        .zip(&recovery.outpoints)
        .map(|(vault, point)| MaterializedCellEvidence {
            out_point: CkbOutPoint {
                tx_hash: point.tx_hash,
                index: point.index,
            },
            lock: recovery.scripts.vault_lock.clone(),
            type_script: match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => Some(
                    recovery
                        .scripts
                        .type_scripts
                        .iter()
                        .find(|entry| entry.type_hash == hash)
                        .unwrap()
                        .script
                        .clone(),
                ),
            },
            capacity: vault.value.capacity().unwrap(),
            data: match vault.asset {
                VaultAsset::Ckb => vec![],
                VaultAsset::Xudt(_) => vault.value.amount.to_le_bytes().to_vec(),
            },
        })
        .collect();
    MaterializedChannelEvidence {
        state,
        vaults,
        participants: [1, 2].map(|key| ChannelParticipant {
            node_id: blake2b256(&participant_pubkey(key)),
            settlement_lock_hash: recovery.settlement.participant_lock_hashes[usize::from(key - 1)],
        }),
        asset: GatewayAsset::Ckb {
            ckb_genesis_hash: [1; 32],
        },
        recovery,
        factory_reservation_id: None,
        factory_origin: origin,
        committed_block_hash: [89; 32],
        committed_block_number: 100,
        confirmations: 6,
        rgbpp_proof_commitment: None,
    }
}

fn reservation(materialized: &MaterializedChannelEvidence, now: u64) -> FactoryRightReservation {
    let asset_type = match &materialized.asset {
        GatewayAsset::Ckb { .. } => None,
        GatewayAsset::Xudt {
            type_script_hash, ..
        } => Some(*type_script_hash),
        GatewayAsset::Rgbpp(asset) => Some(asset.xudt_type_script_hash),
    };
    let right = FactoryRightId {
        participant: materialized.participants[0].node_id,
        subchannel: materialized.recovery.state.header.channel_id,
        kind: FactoryRightKind::Balance,
        asset_type,
    };
    let quantity = if asset_type.is_none() {
        6_000_000_000
    } else {
        500
    };
    let rights = vec![FactoryRight {
        id: right.clone(),
        quantity,
    }];
    let proof = factory_right_sparse_proof(&rights, &right).unwrap();
    let mut reservation = FactoryRightReservation {
        reservation_id: [0; 32],
        factory_id: [7; 32],
        factory_update_number: 9,
        right,
        quantity,
        factory_state_root: factory_right_sparse_root(&rights).unwrap(),
        access_manifest_root: [11; 32],
        proof_commitment: factory_right_proof_commitment(&proof),
        right_proof: proof,
        idempotency_key: [13; 32],
        reserved_at_unix: now,
        expires_at_unix: now + 100,
    };
    reservation.reservation_id = reservation.derive_id().unwrap();
    reservation
}

fn reserve_child(registry: &mut SovereignEdgeRegistry) -> MaterializedChannelEvidence {
    let mut materialized = evidence(true);
    let reserved = reservation(&materialized, 100);
    let origin = materialized.factory_origin.as_mut().unwrap();
    let mut header = origin.source.state().unwrap().fields();
    header.state_root = reserved.factory_state_root;
    origin.source.header = header.encode().unwrap().to_vec();
    assert_eq!(
        reserved.validate(99),
        Err(BridgeError::ReservationNotYetValid)
    );
    let id = registry.reserve(reserved.clone(), 100).unwrap();
    assert_eq!(registry.reserve(reserved, 100).unwrap(), id);
    registry.begin_materialisation(&id).unwrap();
    materialized.factory_reservation_id = Some(id);
    materialized
}

fn select_token(materialized: &mut MaterializedChannelEvidence, index: usize) {
    let VaultAsset::Xudt(hash) = materialized.recovery.manifest.vaults[index].asset else {
        panic!("typed fixture")
    };
    materialized.asset = GatewayAsset::Xudt {
        ckb_genesis_hash: [1; 32],
        type_script_hash: hash,
    };
}

fn refresh_state(materialized: &mut MaterializedChannelEvidence) {
    materialized.recovery.state.header.state_number += 1;
    materialized.recovery.settlement.payouts[0].values[0].business_ckb -= 500_000_000;
    materialized.recovery.settlement.payouts[0].values[1].business_ckb += 500_000_000;
    materialized
        .recovery
        .state
        .header
        .settlement_descriptor_commitment = materialized.recovery.settlement.commitment().unwrap();
    sign(&mut materialized.recovery);
    materialized.committed_block_number += 1;
    materialized.committed_block_hash = [90; 32];
}

#[test]
fn current_factory_child_materialises_without_old_factory_state_mode() {
    let mut registry = SovereignEdgeRegistry::default();
    let materialized = reserve_child(&mut registry);
    assert_eq!(
        materialized.recovery.state.header.mode,
        Mode::BilateralPlain
    );
    assert_eq!(materialized.recovery.scripts.state_type.len() - 53, 72);
    let edge = registry
        .activate(materialized.clone(), &deployment(), 6, 101)
        .unwrap();
    assert_eq!(edge.factory_id, Some([7; 32]));
    assert_eq!(edge.directional_liquidity, [12_000_000_000, 8_000_000_000]);
    // Reserves (80 billion) and the carrier (100 billion) are not liquidity.
    assert_eq!(
        registry
            .activate(materialized.clone(), &deployment(), 6, 101)
            .unwrap(),
        edge
    );
    assert!(matches!(
        registry.lifecycle(&materialized.factory_reservation_id.unwrap()),
        Some(EdgeLifecycle::Active(_))
    ));
    let restored: SovereignEdgeRegistry =
        serde_json::from_slice(&serde_json::to_vec(&registry).unwrap()).unwrap();
    assert_eq!(restored, registry);
}

#[test]
fn current_edge_liquidity_aligns_with_participants_and_selected_type() {
    let mut materialized = evidence(false);
    select_token(&mut materialized, 1);
    materialized.participants.reverse();
    let edge = SovereignEdgeRegistry::default()
        .activate(materialized.clone(), &deployment(), 6, 101)
        .unwrap();
    assert_eq!(
        edge.participants,
        [
            blake2b256(&participant_pubkey(2)),
            blake2b256(&participant_pubkey(1))
        ]
    );
    assert_eq!(edge.directional_liquidity, [300, 700]);
    assert_eq!(edge.asset, materialized.asset);
}

#[test]
fn current_bridge_rejects_incomplete_cloned_reordered_or_aliased_custody() {
    let original = evidence(false);
    let mut cases = vec![];
    let mut missing = original.clone();
    missing.vaults.pop();
    cases.push(missing);
    let mut extra = original.clone();
    extra.vaults.push(extra.vaults[0].clone());
    cases.push(extra);
    let mut reordered = original.clone();
    reordered.vaults.reverse();
    cases.push(reordered);
    let mut duplicate = original.clone();
    duplicate.vaults[1] = duplicate.vaults[0].clone();
    cases.push(duplicate);
    let mut cloned = original.clone();
    cloned.vaults[0].out_point.tx_hash = [99; 32];
    cases.push(cloned);
    let mut state_alias = original.clone();
    state_alias.state.out_point = state_alias.vaults[0].out_point;
    cases.push(state_alias);
    let mut wrong_type = original.clone();
    wrong_type.vaults[0].type_script = wrong_type.vaults[1].type_script.clone();
    cases.push(wrong_type);
    let mut wrong_lock = original.clone();
    wrong_lock.vaults[0].lock[16] ^= 1;
    cases.push(wrong_lock);
    let mut wrong_capacity = original.clone();
    wrong_capacity.vaults[0].capacity += 1;
    cases.push(wrong_capacity);
    let mut wrong_amount = original.clone();
    wrong_amount.vaults[0].data[0] ^= 1;
    cases.push(wrong_amount);
    for bad in cases {
        assert_eq!(
            SovereignEdgeRegistry::default().activate(bad, &deployment(), 6, 101),
            Err(BridgeError::InvalidMaterialisation)
        );
    }
}

#[test]
fn current_bridge_checks_real_state_and_full_script_identity() {
    let original = evidence(false);
    let mut cases = vec![];
    let mut fake_state = original.clone();
    fake_state.state.type_script = None;
    cases.push(fake_state);
    let mut fake_lock = original.clone();
    fake_lock.state.lock[16] ^= 1;
    cases.push(fake_lock);
    let mut old_layout = original.clone();
    old_layout.state.data = vec![0; 346];
    cases.push(old_layout);
    let mut no_exit = original.clone();
    no_exit.recovery.state.header.phase = Phase::Active;
    no_exit.recovery.state.header.state_number = 0;
    sign(&mut no_exit.recovery);
    cases.push(no_exit);
    let mut stale_package = original.clone();
    let mut newer = stale_package.recovery.state.clone();
    newer.header.state_number += 1;
    stale_package.state.data = newer.encode().unwrap().to_vec();
    cases.push(stale_package);
    let mut mismatched_equal = original.clone();
    let mut header = mismatched_equal.recovery.state.clone();
    header.header.settlement_descriptor_commitment = [99; 32];
    mismatched_equal.state.data = header.encode().unwrap().to_vec();
    cases.push(mismatched_equal);
    for bad in cases {
        assert_eq!(
            SovereignEdgeRegistry::default().activate(bad, &deployment(), 6, 101),
            Err(BridgeError::InvalidMaterialisation)
        );
    }
    let mut wrong_code = deployment();
    wrong_code.vault_lock.code_hash = [99; 32];
    assert_eq!(
        SovereignEdgeRegistry::default().activate(original.clone(), &wrong_code, 6, 101),
        Err(BridgeError::UntrustedDeployment)
    );
    let mut wrong_vm = deployment();
    wrong_vm.state_type.hash_type = 4;
    assert_eq!(
        SovereignEdgeRegistry::default().activate(original.clone(), &wrong_vm, 6, 101),
        Err(BridgeError::UntrustedDeployment)
    );
    assert_eq!(
        SovereignEdgeRegistry::default().activate(original, &deployment(), 7, 101),
        Err(BridgeError::InsufficientConfirmations)
    );
}

#[test]
fn current_factory_origin_must_bind_actual_factory_and_child_type_args() {
    let mut registry = SovereignEdgeRegistry::default();
    let materialized = reserve_child(&mut registry);
    let mut missing_origin = materialized.clone();
    missing_origin.factory_origin = None;
    assert_eq!(
        registry.activate(missing_origin, &deployment(), 6, 101),
        Err(BridgeError::FactoryOriginMismatch)
    );
    let mut wrong_factory = materialized.clone();
    wrong_factory
        .factory_origin
        .as_mut()
        .unwrap()
        .source
        .state_type[65] ^= 1;
    assert_eq!(
        registry.activate(wrong_factory, &deployment(), 6, 101),
        Err(BridgeError::FactoryOriginMismatch)
    );
    let mut wrong_reserve = materialized.clone();
    wrong_reserve
        .factory_origin
        .as_mut()
        .unwrap()
        .source
        .vault_lock[53] ^= 1;
    assert_eq!(
        registry.activate(wrong_reserve, &deployment(), 6, 101),
        Err(BridgeError::FactoryOriginMismatch)
    );
    let mut wrong_code = materialized.clone();
    wrong_code
        .factory_origin
        .as_mut()
        .unwrap()
        .source
        .state_type[16] ^= 1;
    assert_eq!(
        registry.activate(wrong_code, &deployment(), 6, 101),
        Err(BridgeError::UntrustedDeployment)
    );
    let mut unattached_child = materialized;
    unattached_child.factory_origin = None;
    unattached_child.factory_reservation_id = None;
    assert_eq!(
        registry.activate(unattached_child, &deployment(), 6, 101),
        Err(BridgeError::FactoryOriginMismatch)
    );
}

#[test]
fn current_bridge_refresh_preserves_identity_and_disables_before_reanchor() {
    let mut registry = SovereignEdgeRegistry::default();
    let mut materialized = evidence(false);
    let initial = registry
        .activate(materialized.clone(), &deployment(), 6, 101)
        .unwrap();
    refresh_state(&mut materialized);
    let refreshed = registry
        .refresh(materialized.clone(), &deployment(), 6)
        .unwrap();
    assert_eq!(refreshed.edge_id, initial.edge_id);
    assert_eq!(refreshed.state_number, initial.state_number + 1);
    assert_eq!(
        refreshed.directional_liquidity,
        [11_500_000_000, 8_500_000_000]
    );
    assert_eq!(
        registry.refresh(materialized.clone(), &deployment(), 6),
        Err(BridgeError::StaleEdgeEvidence)
    );
    registry
        .begin_draining(&initial.channel_id, &initial.asset)
        .unwrap();
    registry
        .disable(&initial.channel_id, &initial.asset, "splice".into(), 103)
        .unwrap();
    assert!(matches!(
        registry.lifecycle(&initial.edge_id),
        Some(EdgeLifecycle::Disabled { .. })
    ));
    registry
        .invalidate(
            &initial.channel_id,
            &initial.asset,
            "funding orphaned".into(),
            104,
        )
        .unwrap();
    assert!(matches!(
        registry.lifecycle(&initial.edge_id),
        Some(EdgeLifecycle::Invalidated { .. })
    ));
}

#[test]
fn current_bridge_keeps_assets_distinct_but_shares_channel_state_freshness() {
    let mut registry = SovereignEdgeRegistry::default();
    let mut ckb = evidence(false);
    let first = registry
        .activate(ckb.clone(), &deployment(), 6, 101)
        .unwrap();
    let mut token = ckb.clone();
    select_token(&mut token, 0);
    let second = registry
        .activate(token.clone(), &deployment(), 6, 101)
        .unwrap();
    assert_ne!(first.edge_id, second.edge_id);
    validate_provider_edge_set(&[first.clone(), second.clone()]).unwrap();
    assert_eq!(
        registry
            .edge_for_channel(&first.channel_id, &second.asset)
            .unwrap(),
        Some(&second)
    );
    refresh_state(&mut ckb);
    let latest = registry.refresh(ckb.clone(), &deployment(), 6).unwrap();
    assert_eq!(
        validate_provider_edge_set(&[latest.clone(), second.clone()]),
        Err(BridgeError::StaleEdgeEvidence)
    );
    assert_eq!(
        registry.edge_for_channel(&first.channel_id, &second.asset),
        Err(BridgeError::StaleEdgeEvidence)
    );
    assert_eq!(
        registry.refresh(token, &deployment(), 6),
        Err(BridgeError::StaleEdgeEvidence)
    );
    let mut current_token = ckb.clone();
    select_token(&mut current_token, 0);
    let token = registry.refresh(current_token, &deployment(), 6).unwrap();
    assert_eq!(token.edge_id, second.edge_id);
    assert_eq!(token.directional_liquidity, [700, 300]);
    validate_provider_edge_set(&[latest, token]).unwrap();
    assert!(
        registry
            .edge_for_channel(&first.channel_id, &second.asset)
            .unwrap()
            .is_some()
    );
    registry
        .disable(
            &first.channel_id,
            &first.asset,
            "operator pause".into(),
            102,
        )
        .unwrap();
    assert!(matches!(
        registry.lifecycle(&second.edge_id),
        Some(EdgeLifecycle::Active(_))
    ));
}

#[test]
fn current_bridge_reservation_proof_idempotence_and_durable_map_shape_are_strict() {
    let materialized = evidence(true);
    let mut reserved = reservation(&materialized, 100);
    let mut registry = SovereignEdgeRegistry::default();
    registry.reserve(reserved.clone(), 100).unwrap();
    reserved.quantity -= 1;
    reserved.reservation_id = reserved.derive_id().unwrap();
    assert_eq!(
        registry.reserve(reserved, 100),
        Err(BridgeError::IdempotencyConflict)
    );
    let mut invalid = reservation(&materialized, 100);
    invalid.right_proof.right.quantity += 1;
    assert_eq!(
        registry.reserve(invalid, 100),
        Err(BridgeError::InvalidFactoryProof)
    );
    let mut json = serde_json::to_value(&registry).unwrap();
    let entry = json["reservations"][0].clone();
    json["reservations"].as_array_mut().unwrap().push(entry);
    assert!(serde_json::from_value::<SovereignEdgeRegistry>(json).is_err());
    let mut evidence_json = serde_json::to_value(evidence(false)).unwrap();
    evidence_json
        .as_object_mut()
        .unwrap()
        .remove("factory_origin");
    assert!(serde_json::from_value::<MaterializedChannelEvidence>(evidence_json).is_err());
}

#[test]
fn current_bridge_excludes_conditional_pending_ckb_from_every_advertised_edge() {
    let mut backend = super::conditional_backend::engine();
    let mut actual = backend.current().state.clone();
    actual.header.phase = Phase::Active;
    actual.header.state_number = 0;
    let mut service = ChannelConditionalBatches::new(&backend).unwrap();
    super::conditional_backend::arm(&mut backend, &mut service);
    let mut materialized = evidence_from_recovery(backend.current().clone(), None);
    materialized.state.data = actual.encode().unwrap().to_vec();
    let edge = SovereignEdgeRegistry::default()
        .activate(materialized, &deployment(), 6, 101)
        .unwrap();
    assert_eq!(edge.directional_liquidity, [11_000_000_000, 7_500_000_000]);
}

#[test]
fn current_bridge_requires_all_asset_edges_to_drain_before_new_context_activation() {
    let mut registry = SovereignEdgeRegistry::default();
    let mut materialized = evidence(false);
    let first = registry
        .activate(materialized.clone(), &deployment(), 6, 101)
        .unwrap();
    let mut token = materialized.clone();
    select_token(&mut token, 0);
    let second = registry.activate(token, &deployment(), 6, 101).unwrap();
    let recovery = &mut materialized.recovery;
    recovery.state.header.funding_anchor = [22; 32];
    recovery.state.header.funding_epoch += 1;
    let since = morph_script_common::relative_block_since(6).unwrap();
    let mut args = recovery.state.header.funding_anchor.to_vec();
    args.extend_from_slice(&since.to_le_bytes());
    recovery.scripts.state_type = script(3, &args);
    recovery.scripts.state_lock = script(2, &blake2b256(&recovery.scripts.state_type));
    recovery.scripts.vault_lock = script(
        1,
        &wire::encode_multi_asset_vault_args(
            &recovery.state.header.funding_anchor,
            since,
            &blake2b256(&recovery.scripts.state_type),
            &blake2b256(&recovery.scripts.state_lock),
        )
        .unwrap(),
    );
    for (vault, point) in recovery
        .manifest
        .vaults
        .iter_mut()
        .zip(&mut recovery.outpoints)
    {
        vault.lock_hash = blake2b256(&recovery.scripts.vault_lock);
        point.tx_hash = [91; 32];
    }
    recovery.state.vault_content_set_root = recovery.manifest.commitment().unwrap();
    recovery.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&recovery.manifest, &recovery.outpoints).unwrap();
    sign(recovery);
    let replacement = evidence_from_recovery(recovery.clone(), None);
    assert_eq!(
        registry.activate(replacement.clone(), &deployment(), 6, 101),
        Err(BridgeError::ActiveEdgeConflict)
    );
    registry
        .begin_draining(&first.channel_id, &first.asset)
        .unwrap();
    registry
        .disable(&first.channel_id, &first.asset, "splice".into(), 102)
        .unwrap();
    assert_eq!(
        registry.activate(replacement.clone(), &deployment(), 6, 102),
        Err(BridgeError::ActiveEdgeConflict)
    );
    registry
        .begin_draining(&second.channel_id, &second.asset)
        .unwrap();
    registry
        .disable(&second.channel_id, &second.asset, "splice".into(), 102)
        .unwrap();
    let replacement = registry
        .activate(replacement, &deployment(), 6, 103)
        .unwrap();
    assert_ne!(replacement.funding_context_id, first.funding_context_id);
    assert_ne!(replacement.edge_id, first.edge_id);
}

#[test]
fn native_and_rgbpp_aliases_cannot_double_advertise_the_same_type_balance() {
    let mut registry = SovereignEdgeRegistry::default();
    let mut native = evidence(false);
    select_token(&mut native, 0);
    let edge = registry
        .activate(native.clone(), &deployment(), 6, 101)
        .unwrap();
    let GatewayAsset::Xudt {
        type_script_hash, ..
    } = native.asset
    else {
        unreachable!()
    };
    let mut rgbpp = native;
    rgbpp.asset = GatewayAsset::Rgbpp(RgbppAssetId {
        ckb_genesis_hash: [1; 32],
        xudt_type_script_hash: type_script_hash,
        bitcoin_network: BitcoinNetwork::Regtest,
        binding_code_hash: [72; 32],
    });
    rgbpp.rgbpp_proof_commitment = Some([73; 32]);
    assert_eq!(
        registry.activate(rgbpp.clone(), &deployment(), 6, 101),
        Err(BridgeError::ActiveEdgeConflict)
    );
    assert_eq!(
        registry.edge_for_channel(&edge.channel_id, &rgbpp.asset),
        Err(BridgeError::AssetAliasConflict)
    );
    assert_eq!(
        registry.disable(&edge.channel_id, &rgbpp.asset, "wrong alias".into(), 102),
        Err(BridgeError::AssetAliasConflict)
    );
    registry
        .disable(
            &edge.channel_id,
            &edge.asset,
            "switch proof policy".into(),
            102,
        )
        .unwrap();
    let replacement = registry.activate(rgbpp, &deployment(), 6, 103).unwrap();
    assert_ne!(replacement.edge_id, edge.edge_id);
    assert_eq!(
        replacement.directional_liquidity,
        edge.directional_liquidity
    );
}

#[test]
fn arbitrary_factory_member_ids_map_through_committed_keys_to_channel_nodes() {
    let mut materialized = evidence(true);
    let origin = materialized.factory_origin.as_mut().unwrap();
    for member in &mut origin.members {
        member.participant = if member.pubkey_sec1 == participant_pubkey(1) {
            [61; 32]
        } else {
            [62; 32]
        };
    }
    origin.members.sort_by_key(|member| member.participant);
    let mut reserved = reservation(&materialized, 100);
    let old_id = reserved.right.clone();
    reserved.right.participant = [61; 32];
    let right = FactoryRight {
        id: reserved.right.clone(),
        quantity: reserved.quantity,
    };
    reserved.right_proof =
        factory_right_sparse_proof(std::slice::from_ref(&right), &right.id).unwrap();
    reserved.factory_state_root = factory_right_sparse_root(std::slice::from_ref(&right)).unwrap();
    reserved.proof_commitment = factory_right_proof_commitment(&reserved.right_proof);
    reserved.reservation_id = reserved.derive_id().unwrap();
    assert_ne!(old_id.participant, reserved.right.participant);
    let origin = materialized.factory_origin.as_mut().unwrap();
    let mut header = origin.source.state().unwrap().fields();
    header.state_root = reserved.factory_state_root;
    header.participants_commitment = factory_membership_commitment(&origin.members).unwrap();
    origin.source.header = header.encode().unwrap().to_vec();
    let mut registry = SovereignEdgeRegistry::default();
    let id = registry.reserve(reserved, 100).unwrap();
    registry.begin_materialisation(&id).unwrap();
    materialized.factory_reservation_id = Some(id);
    let edge = registry
        .activate(materialized, &deployment(), 6, 101)
        .unwrap();
    assert_eq!(edge.participants[0], blake2b256(&participant_pubkey(1)));
}
