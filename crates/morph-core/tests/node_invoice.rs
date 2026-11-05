use std::collections::BTreeSet;

use k256::ecdsa::SigningKey;
use morph_core::{
    MorphAsset, MorphAssetBalance, MorphBusinessFlow, MorphChannelRecord, MorphFactoryRecord,
    MorphInvoice, MorphInvoiceStatus, MorphNetwork, MorphNodeState, MorphPeer, NewMorphInvoice,
    NodeError, Phase, blake2b256,
};

fn bytes32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn node_id_for_key(key: &SigningKey) -> [u8; 32] {
    blake2b256(key.verifying_key().to_sec1_point(true).as_bytes())
}

fn invoice_request(preimage: [u8; 32]) -> NewMorphInvoice {
    let payee_key = signing_key(1);
    NewMorphInvoice {
        network: MorphNetwork::Devnet,
        payee_node_id: node_id_for_key(&payee_key),
        channel_id: Some(bytes32(2)),
        asset: MorphAsset::Ckb,
        amount: 42_000,
        created_at_unix: 1_000,
        expires_at_unix: 1_600,
        payment_preimage: Some(preimage),
        payment_hash: None,
        description: "coffee over a Morph channel".to_string(),
    }
}

fn channel(id: u8, peer: u8, funding_context: u8) -> MorphChannelRecord {
    MorphChannelRecord {
        channel_id: bytes32(id),
        counterparty_node_id: bytes32(peer),
        funding_epoch: 0,
        funding_context_id: bytes32(funding_context),
        state_number: 1,
        phase: Phase::Active,
        balances: vec![MorphAssetBalance {
            asset: MorphAsset::Ckb,
            local: 60_000,
            remote: 40_000,
            pending: 0,
        }],
        sponsor_budget: 10_000,
    }
}

#[test]
fn invoice_round_trips_and_rejects_tampering() {
    let payee_key = signing_key(1);
    let invoice = MorphInvoice::new_signed(invoice_request(bytes32(9)), &payee_key).unwrap();
    let encoded = invoice.encode();
    let decoded = MorphInvoice::decode(&encoded).unwrap();
    assert_eq!(decoded, invoice);

    let mut tampered = encoded.clone();
    let replacement = if tampered.ends_with('0') { "1" } else { "0" };
    tampered.replace_range(encoded.len() - 1..encoded.len(), replacement);
    assert_eq!(
        MorphInvoice::decode(&tampered).unwrap_err(),
        NodeError::InvoiceChecksumMismatch
    );

    let mut bad_signature = invoice.clone();
    bad_signature.payee_signature[0] ^= 1;
    assert_eq!(
        MorphInvoice::decode(&bad_signature.encode()).unwrap_err(),
        NodeError::InvoiceSignatureInvalid
    );
}

#[test]
fn invoice_rejects_zero_payment_preimage() {
    let payee_key = signing_key(1);

    assert_eq!(
        MorphInvoice::new_signed(invoice_request([0u8; 32]), &payee_key).unwrap_err(),
        NodeError::ZeroPaymentPreimage
    );
}

#[test]
fn invoice_settlement_requires_matching_preimage_and_live_invoice() {
    let preimage = bytes32(11);
    let payee_key = signing_key(1);
    let mut node = MorphNodeState::new(node_id_for_key(&payee_key), MorphNetwork::Devnet).unwrap();
    let stored = node
        .create_invoice(invoice_request(preimage), &payee_key)
        .unwrap();
    let invoice_id = stored.invoice.invoice_id;

    assert_eq!(
        node.settle_invoice(&invoice_id, bytes32(12), 1_100)
            .unwrap_err(),
        NodeError::InvoicePreimageMismatch
    );
    assert_eq!(
        node.settle_invoice(&invoice_id, [0u8; 32], 1_110)
            .unwrap_err(),
        NodeError::ZeroPaymentPreimage
    );
    node.receive_invoice(&invoice_id, 1_120).unwrap();
    node.settle_invoice(&invoice_id, preimage, 1_130).unwrap();
    assert_eq!(
        node.invoices.get(&invoice_id).unwrap().status,
        MorphInvoiceStatus::Paid
    );

    let expired_key = signing_key(3);
    let mut expired =
        MorphNodeState::new(node_id_for_key(&expired_key), MorphNetwork::Devnet).unwrap();
    let expired_invoice = expired
        .create_invoice(invoice_request(bytes32(13)), &expired_key)
        .unwrap();
    assert_eq!(
        expired
            .settle_invoice(&expired_invoice.invoice.invoice_id, bytes32(13), 1_600)
            .unwrap_err(),
        NodeError::InvoiceExpired
    );
}

#[test]
fn receiving_decoded_invoice_rejects_self_and_wrong_network() {
    let local_key = signing_key(1);
    let mut local_node =
        MorphNodeState::new(node_id_for_key(&local_key), MorphNetwork::Devnet).unwrap();
    let self_invoice = MorphInvoice::new_signed(invoice_request(bytes32(21)), &local_key).unwrap();

    assert_eq!(
        local_node
            .receive_decoded_invoice(&self_invoice.encode(), 1_100)
            .unwrap_err(),
        NodeError::SelfInvoice
    );

    let external_key = signing_key(2);
    let mut wrong_network_request = invoice_request(bytes32(22));
    wrong_network_request.network = MorphNetwork::Testnet;
    wrong_network_request.payee_node_id = node_id_for_key(&external_key);
    let wrong_network_invoice =
        MorphInvoice::new_signed(wrong_network_request, &external_key).unwrap();

    assert_eq!(
        local_node
            .receive_decoded_invoice(&wrong_network_invoice.encode(), 1_100)
            .unwrap_err(),
        NodeError::InvoiceNetworkMismatch
    );
}

#[test]
fn node_channel_lifecycle_publishes_and_finalises_current_context() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();
    node.connect_peer(MorphPeer {
        node_id: bytes32(7),
        alias: "bob".to_string(),
    })
    .unwrap();
    node.open_channel(channel(2, 7, 30)).unwrap();

    assert_eq!(
        node.publish_state(&bytes32(2), bytes32(31), 2).unwrap_err(),
        NodeError::FundingContextMismatch
    );
    node.publish_state(&bytes32(2), bytes32(30), 2).unwrap();
    node.finalise_channel(&bytes32(2)).unwrap();
    assert_eq!(node.channels[&bytes32(2)].phase, Phase::Closed);
}

#[test]
fn node_rejects_self_peer_and_self_channel() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();

    assert_eq!(
        node.connect_peer(MorphPeer {
            node_id: bytes32(1),
            alias: "self".to_string(),
        })
        .unwrap_err(),
        NodeError::SelfPeer
    );

    assert_eq!(
        node.open_channel(channel(2, 1, 30)).unwrap_err(),
        NodeError::SelfPeer
    );
}

#[test]
fn peer_alias_is_trimmed_required_and_bounded() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();

    assert_eq!(
        node.connect_peer(MorphPeer {
            node_id: bytes32(2),
            alias: "  ".to_string(),
        })
        .unwrap_err(),
        NodeError::PeerAliasEmpty
    );

    assert_eq!(
        node.connect_peer(MorphPeer {
            node_id: bytes32(2),
            alias: "x".repeat(81),
        })
        .unwrap_err(),
        NodeError::PeerAliasTooLong
    );

    node.connect_peer(MorphPeer {
        node_id: bytes32(2),
        alias: "  bob  ".to_string(),
    })
    .unwrap();

    assert_eq!(node.peers.get(&bytes32(2)).unwrap().alias, "bob");
}

#[test]
fn splice_advances_funding_context_without_allowing_stale_publication() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();
    node.connect_peer(MorphPeer {
        node_id: bytes32(7),
        alias: "bob".to_string(),
    })
    .unwrap();
    node.open_channel(channel(2, 7, 30)).unwrap();
    node.splice_channel(&bytes32(2), 1, bytes32(31)).unwrap();

    assert_eq!(
        node.publish_state(&bytes32(2), bytes32(30), 2).unwrap_err(),
        NodeError::FundingContextMismatch
    );
    node.publish_state(&bytes32(2), bytes32(31), 2).unwrap();
}

#[test]
fn factory_requires_local_participant_and_child_counterparty_membership() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();
    node.connect_peer(MorphPeer {
        node_id: bytes32(7),
        alias: "bob".to_string(),
    })
    .unwrap();
    node.connect_peer(MorphPeer {
        node_id: bytes32(8),
        alias: "carol".to_string(),
    })
    .unwrap();

    assert_eq!(
        node.open_factory(MorphFactoryRecord {
            factory_id: bytes32(39),
            participant_node_ids: BTreeSet::from([bytes32(7), bytes32(8)]),
            update_number: 0,
            reserve_balances: vec![MorphAssetBalance {
                asset: MorphAsset::Ckb,
                local: 100_000,
                remote: 100_000,
                pending: 0,
            }],
            materialised_child_channels: BTreeSet::new(),
        })
        .unwrap_err(),
        NodeError::FactoryMissingLocalParticipant
    );

    node.open_factory(MorphFactoryRecord {
        factory_id: bytes32(40),
        participant_node_ids: BTreeSet::from([node.node_id, bytes32(7)]),
        update_number: 0,
        reserve_balances: vec![MorphAssetBalance {
            asset: MorphAsset::Ckb,
            local: 100_000,
            remote: 100_000,
            pending: 0,
        }],
        materialised_child_channels: BTreeSet::new(),
    })
    .unwrap();

    assert_eq!(
        node.materialise_child_channel(&bytes32(40), channel(41, 8, 42))
            .unwrap_err(),
        NodeError::FactoryChildCounterpartyNotParticipant
    );
}

#[test]
fn factory_projection_accepts_dynamic_participant_bounds() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();

    node.open_factory(MorphFactoryRecord {
        factory_id: bytes32(38),
        participant_node_ids: BTreeSet::from([bytes32(1), bytes32(7), bytes32(8)]),
        update_number: 0,
        reserve_balances: vec![],
        materialised_child_channels: BTreeSet::new(),
    })
    .unwrap();

    node.open_factory(MorphFactoryRecord {
        factory_id: bytes32(39),
        participant_node_ids: (1..=16).map(bytes32).collect(),
        update_number: 0,
        reserve_balances: vec![],
        materialised_child_channels: BTreeSet::new(),
    })
    .unwrap();

    for (factory_id, participant_node_ids) in [
        (bytes32(40), BTreeSet::from([bytes32(1)])),
        (bytes32(41), (1..=17).map(bytes32).collect()),
    ] {
        assert_eq!(
            node.open_factory(MorphFactoryRecord {
                factory_id,
                participant_node_ids,
                update_number: 0,
                reserve_balances: vec![],
                materialised_child_channels: BTreeSet::new(),
            })
            .unwrap_err(),
            NodeError::FactoryParticipantCountUnsupported
        );
    }
}

#[test]
fn factory_materialises_child_channel_once() {
    let mut node = MorphNodeState::new(bytes32(1), MorphNetwork::Devnet).unwrap();
    node.connect_peer(MorphPeer {
        node_id: bytes32(7),
        alias: "bob".to_string(),
    })
    .unwrap();
    node.open_factory(MorphFactoryRecord {
        factory_id: bytes32(40),
        participant_node_ids: BTreeSet::from([node.node_id, bytes32(7)]),
        update_number: 0,
        reserve_balances: vec![MorphAssetBalance {
            asset: MorphAsset::Ckb,
            local: 100_000,
            remote: 100_000,
            pending: 0,
        }],
        materialised_child_channels: BTreeSet::new(),
    })
    .unwrap();
    node.advance_factory(&bytes32(40), 1).unwrap();
    node.materialise_child_channel(&bytes32(40), channel(41, 7, 42))
        .unwrap();

    assert_eq!(
        node.materialise_child_channel(&bytes32(40), channel(41, 7, 43))
            .unwrap_err(),
        NodeError::ChannelAlreadyExists
    );
}

#[test]
fn node_records_all_business_flows_when_sequence_completes() {
    let preimage = bytes32(50);
    let payee_key = signing_key(1);
    let mut node = MorphNodeState::new(node_id_for_key(&payee_key), MorphNetwork::Devnet).unwrap();
    node.connect_peer(MorphPeer {
        node_id: bytes32(7),
        alias: "bob".to_string(),
    })
    .unwrap();
    let stored = node
        .create_invoice(invoice_request(preimage), &payee_key)
        .unwrap();
    node.receive_invoice(&stored.invoice.invoice_id, 1_010)
        .unwrap();
    node.settle_invoice(&stored.invoice.invoice_id, preimage, 1_020)
        .unwrap();

    node.open_channel(channel(2, 7, 30)).unwrap();
    node.splice_channel(&bytes32(2), 1, bytes32(31)).unwrap();
    node.publish_state(&bytes32(2), bytes32(31), 2).unwrap();
    node.finalise_channel(&bytes32(2)).unwrap();

    node.open_factory(MorphFactoryRecord {
        factory_id: bytes32(40),
        participant_node_ids: BTreeSet::from([node.node_id, bytes32(7)]),
        update_number: 0,
        reserve_balances: vec![MorphAssetBalance {
            asset: MorphAsset::Xudt(blake2b256(b"xudt")),
            local: 1_000,
            remote: 1_000,
            pending: 0,
        }],
        materialised_child_channels: BTreeSet::new(),
    })
    .unwrap();
    node.advance_factory(&bytes32(40), 1).unwrap();
    node.materialise_child_channel(&bytes32(40), channel(41, 7, 42))
        .unwrap();

    assert_eq!(node.missing_business_flows(), BTreeSet::new());
    assert_eq!(
        node.completed_flows,
        MorphNodeState::required_business_flows()
    );
    assert!(
        node.completed_flows
            .contains(&MorphBusinessFlow::InvoiceSettled)
    );
}
