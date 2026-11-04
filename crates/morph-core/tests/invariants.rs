use morph_core::*;
use std::collections::BTreeSet;

fn registry() -> AssetRegistry {
    AssetRegistry {
        xudt_types: BTreeSet::from([bytes32(42)]),
    }
}

fn good_partition() -> PartitionedTransaction {
    PartitionedTransaction {
        inputs: vec![
            ClassifiedCell::channel_reserve(1_000, 700),
            ClassifiedCell::business_ckb(1_500, 700, 800),
            ClassifiedCell::xudt(bytes32(42), 1_000, 700, 10),
            ClassifiedCell::state_carrier(10_000, 1_000),
            ClassifiedCell::sponsor(500, 100),
        ],
        outputs: vec![
            ClassifiedCell::channel_reserve(1_000, 700),
            ClassifiedCell::business_ckb(1_500, 700, 800),
            ClassifiedCell::xudt(bytes32(42), 1_000, 700, 10),
            ClassifiedCell::state_carrier(10_000, 1_000),
            ClassifiedCell::sponsor(400, 100),
        ],
        tx_fee: 100,
        authorised_reserve_refund: 0,
    }
}

#[test]
fn asset_registry_commitment_is_canonical_and_complete() {
    let first = AssetRegistry {
        xudt_types: BTreeSet::from([bytes32(42), bytes32(7)]),
    };
    let second = AssetRegistry {
        xudt_types: [bytes32(7), bytes32(42)].into_iter().collect(),
    };
    let changed = AssetRegistry {
        xudt_types: BTreeSet::from([bytes32(42)]),
    };

    assert_eq!(
        asset_registry_commitment(&first),
        asset_registry_commitment(&second)
    );
    assert_ne!(
        asset_registry_commitment(&first),
        asset_registry_commitment(&changed)
    );
}

#[test]
fn partition_conservation_accepts_valid_partition() {
    let totals = validate_partition_conservation(&good_partition(), &registry()).unwrap();
    assert_eq!(totals.state_carrier_in, 10_000);
    assert_eq!(totals.state_carrier_out, 10_000);
    assert_eq!(totals.sponsor_in - totals.sponsor_out, 100);
}

#[test]
fn rejects_channel_paid_fee_leakage() {
    let mut tx = good_partition();
    tx.outputs[0].capacity -= 1;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::ReserveNotConserved);
}

#[test]
fn rejects_state_carrier_capacity_leakage() {
    let mut tx = good_partition();
    tx.outputs[3].capacity -= 1;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::StateCarrierNotConserved);
}

#[test]
fn rejects_business_ckb_confusion() {
    let mut tx = good_partition();
    tx.outputs[1].business_ckb += 1;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::InvalidCellClassification);
}

#[test]
fn rejects_ckb_leakage_from_xudt_cells() {
    let mut tx = good_partition();
    tx.outputs[2] = ClassifiedCell::xudt(bytes32(42), 999, 700, 10);

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::BusinessCkbNotConserved);
}

#[test]
fn rejects_hidden_business_value_in_sponsor_classification() {
    let mut tx = good_partition();
    tx.outputs[4].business_ckb = 1;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::InvalidCellClassification);
}

#[test]
fn rejects_xudt_type_mismatch() {
    let mut tx = good_partition();
    tx.outputs[2] = ClassifiedCell::xudt(bytes32(43), 1_000, 700, 10);

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::UnregisteredXudtType);
}

#[test]
fn rejects_xudt_amount_mismatch() {
    let mut tx = good_partition();
    tx.outputs[2].xudt_amount = 9;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::XudtNotConserved);
}

#[test]
fn rejects_xudt_amount_overflow_in_partition_totals() {
    let mut tx = good_partition();
    tx.inputs
        .push(ClassifiedCell::xudt(bytes32(42), 1_000, 700, u128::MAX));
    tx.outputs
        .push(ClassifiedCell::xudt(bytes32(42), 1_000, 700, u128::MAX));

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::XudtNotConserved);
}

#[test]
fn rejects_reserve_refund_overflow_in_partition_totals() {
    let tx = PartitionedTransaction {
        inputs: vec![ClassifiedCell::channel_reserve(u64::MAX, 700)],
        outputs: vec![ClassifiedCell::channel_reserve(u64::MAX, 700)],
        tx_fee: 0,
        authorised_reserve_refund: 1,
    };

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::ReserveNotConserved);
}

#[test]
fn rejects_sponsor_output_exceeding_input_without_fee_underflow() {
    let tx = PartitionedTransaction {
        inputs: vec![ClassifiedCell::sponsor(100, 50)],
        outputs: vec![ClassifiedCell::sponsor(101, 50)],
        tx_fee: 0,
        authorised_reserve_refund: 0,
    };

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::SponsorFeeMismatch);
}

#[test]
fn rejects_sponsor_change_contamination() {
    let mut tx = good_partition();
    tx.outputs[4].carries_registered_xudt = true;

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::SponsorChangeContaminated);
}

#[test]
fn rejects_unrelated_cell_used_for_channel_semantics() {
    let mut tx = good_partition();
    let mut helper = ClassifiedCell::unrelated(100, 50);
    helper.read_by_channel_script = true;
    tx.inputs.push(helper);

    let err = validate_partition_conservation(&tx, &registry()).unwrap_err();
    assert_eq!(err, MorphError::UnrelatedCellUsed);
}

#[test]
fn sponsor_policy_accepts_bounded_publication_fee() {
    let policy = SponsorPolicy {
        channel_id: bytes32(2),
        min_state_number: 1,
        max_state_number: 10,
        max_fee_per_tx: 200,
        max_total_fee: 1_000,
        already_spent: 100,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
    };
    let spend = SponsorSpend {
        channel_id: bytes32(2),
        state_number: 2,
        fee: 150,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
        operation: ChannelOperation::Publish,
    };

    validate_sponsor_policy(&policy, &spend).unwrap();
}

#[test]
fn sponsor_policy_rejects_drain_attempt() {
    let policy = SponsorPolicy {
        channel_id: bytes32(2),
        min_state_number: 1,
        max_state_number: 10,
        max_fee_per_tx: 200,
        max_total_fee: 1_000,
        already_spent: 950,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
    };
    let spend = SponsorSpend {
        channel_id: bytes32(2),
        state_number: 2,
        fee: 100,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
        operation: ChannelOperation::Publish,
    };

    let err = validate_sponsor_policy(&policy, &spend).unwrap_err();
    assert_eq!(err, MorphError::SponsorBudgetExceeded);
}

#[test]
fn sponsor_policy_rejects_wrong_publication_state_type() {
    let policy = SponsorPolicy {
        channel_id: bytes32(2),
        min_state_number: 1,
        max_state_number: 10,
        max_fee_per_tx: 200,
        max_total_fee: 1_000,
        already_spent: 100,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
    };
    let spend = SponsorSpend {
        channel_id: bytes32(2),
        state_number: 2,
        fee: 100,
        publication_state_type_hash: bytes32(99),
        change_lock: bytes32(11),
        operation: ChannelOperation::Publish,
    };

    let err = validate_sponsor_policy(&policy, &spend).unwrap_err();
    assert_eq!(err, MorphError::SponsorStateTypeMismatch);
}

#[test]
fn sponsor_policy_rejects_fund_operation() {
    let policy = SponsorPolicy {
        channel_id: bytes32(2),
        min_state_number: 1,
        max_state_number: 10,
        max_fee_per_tx: 200,
        max_total_fee: 1_000,
        already_spent: 100,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
    };
    let spend = SponsorSpend {
        channel_id: bytes32(2),
        state_number: 2,
        fee: 100,
        publication_state_type_hash: bytes32(10),
        change_lock: bytes32(11),
        operation: ChannelOperation::Fund,
    };

    let err = validate_sponsor_policy(&policy, &spend).unwrap_err();
    assert_eq!(err, MorphError::SponsorOperationNotAllowed);
}
