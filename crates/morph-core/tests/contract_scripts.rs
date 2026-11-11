use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellDep, CellInput, CellOutput, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::types::{FactoryRight, FactoryRightId, FactoryRightKind};
use morph_core::validation::{factory_right_sparse_proof_compact, factory_right_sparse_root};
use morph_core::{
    ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant, ConditionalResolution,
    ConditionalTransferSpec, derive_conditional_payment_hash,
};
use morph_script_common::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[path = "contract_scripts/multi_asset.rs"]
mod multi_asset;

const MAX_CYCLES: u64 = 50_000_000;
const CELL_CAPACITY: u64 = 100_000_000_000;
const ALICE_CAPACITY: u64 = 60_000_000_000;
const BOB_CAPACITY: u64 = 40_000_000_000;
const ALICE_XUDT_AMOUNT: u128 = 70;
const BOB_XUDT_AMOUNT: u128 = 30;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crates dir")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn contract_bin(name: &str) -> Bytes {
    let path = repo_root()
        .join("target/riscv64imac-unknown-none-elf/release")
        .join(name);
    fs::read(&path)
        .unwrap_or_else(|err| {
            panic!(
                "read contract binary {}: {}; run `make build-contracts` first",
                path.display(),
                err
            )
        })
        .into()
}

fn deploy_always_success(context: &mut Context) -> ckb_testtool::ckb_types::packed::Script {
    deploy_always_success_with_args(context, Bytes::new())
}

fn deploy_always_success_with_args(
    context: &mut Context,
    args: Bytes,
) -> ckb_testtool::ckb_types::packed::Script {
    let out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    context
        .build_script_with_hash_type(&out_point, ScriptHashType::Data1, args)
        .expect("always-success script")
}

fn deploy_contract(
    context: &mut Context,
    name: &str,
    args: Vec<u8>,
) -> ckb_testtool::ckb_types::packed::Script {
    let out_point = context.deploy_cell(contract_bin(name));
    context
        .build_script(&out_point, args.into())
        .expect("contract script")
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn state_args_with_anchor(anchor: [u8; 32], finalise_since: u64) -> Vec<u8> {
    let mut args = anchor.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args
}

fn relative_since(value: u64) -> u64 {
    relative_block_since(value).expect("relative block since")
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_sec1_point(true);
    let mut out = [0u8; COMPRESSED_SECP256K1_PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn signature(key: &SigningKey, digest: &[u8; 32]) -> [u8; ECDSA_SIGNATURE_LEN] {
    let sig: Signature = key.sign_prehash(digest).unwrap();
    let mut out = [0u8; ECDSA_SIGNATURE_LEN];
    let signature_bytes = sig.to_bytes();
    out.copy_from_slice(signature_bytes.as_ref());
    out
}

fn derived_funding_anchor(input: &CellInput, output_index: u64) -> [u8; 32] {
    blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
}

fn witness_with_input_type(input_type: Bytes) -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .input_type(Some(input_type).pack())
        .build()
        .as_bytes()
        .pack()
}

fn xudt_amount_data(amount: u128) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes())
}

fn sponsor_policy(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    max_fee: u64,
) -> Vec<u8> {
    sponsor_policy_with_bounds(
        change_lock_hash,
        publication_state_type_hash,
        0,
        u64::MAX,
        max_fee,
        max_fee,
    )
}

fn sponsor_policy_with_bounds(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    min_state_number: u64,
    max_state_number: u64,
    max_fee_per_tx: u64,
    max_total_fee: u64,
) -> Vec<u8> {
    let mut raw = [0u8; SPONSOR_POLICY_LEN];
    raw[0..32].fill(3);
    put_u64(&mut raw, 32, min_state_number);
    put_u64(&mut raw, 40, max_state_number);
    put_u64(&mut raw, 48, max_fee_per_tx);
    put_u64(&mut raw, 56, max_total_fee);
    put_u64(&mut raw, 64, 0);
    raw[72..104].copy_from_slice(publication_state_type_hash);
    raw[104..136].copy_from_slice(change_lock_hash);
    raw.to_vec()
}

fn sponsor_policy_with_already_spent(
    change_lock_hash: &[u8; 32],
    publication_state_type_hash: &[u8; 32],
    max_fee_per_tx: u64,
    max_total_fee: u64,
    already_spent: u64,
) -> Vec<u8> {
    let mut raw = sponsor_policy_with_bounds(
        change_lock_hash,
        publication_state_type_hash,
        0,
        u64::MAX,
        max_fee_per_tx,
        max_total_fee,
    );
    put_u64(&mut raw, 64, already_spent);
    raw
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConditionalBatchTamper {
    None,
    WrongPreimage,
    PrematureRefund,
    OutputCapacity,
    DescriptorCommitment,
    RetiredArgs,
    ZeroFundingContext,
}

fn conditional_batch_resolution_tx(tamper: ConditionalBatchTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let first_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![31]));
    let second_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![32]));
    let mut locks = [first_lock, second_lock];
    locks.sort_by_key(|lock| lock.calc_script_hash().as_slice().to_vec());
    let lock_hashes: [[u8; 32]; 2] = [
        locks[0].calc_script_hash().unpack(),
        locks[1].calc_script_hash().unpack(),
    ];
    let sha_preimage = [7u8; 32];
    let blake_preimage = [8u8; 32];
    let batch = ConditionalBatch {
        asset: morph_core::VaultAsset::Ckb,
        batch_id: [3; 32],
        application_context_commitment: [4; 32],
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: lock_hashes[0],
                settled_capacity: CELL_CAPACITY / 2 - 1_000,
                settled_amount: 0,
            },
            ConditionalParticipant {
                settlement_lock_hash: lock_hashes[1],
                settled_capacity: CELL_CAPACITY / 2 - 2_000,
                settled_amount: 0,
            },
        ],
        transfers: vec![
            ConditionalTransferSpec {
                transfer_id: [5; 32],
                payer_lock_hash: lock_hashes[0],
                hash_algorithm: ConditionalHashAlgorithm::Sha256,
                payment_hash: derive_conditional_payment_hash(
                    ConditionalHashAlgorithm::Sha256,
                    &sha_preimage,
                )
                .unwrap(),
                amount: 1_000,
                refund_after_block: 500,
            },
            ConditionalTransferSpec {
                transfer_id: [6; 32],
                payer_lock_hash: lock_hashes[1],
                hash_algorithm: ConditionalHashAlgorithm::CkbBlake2b,
                payment_hash: derive_conditional_payment_hash(
                    ConditionalHashAlgorithm::CkbBlake2b,
                    &blake_preimage,
                )
                .unwrap(),
                amount: 2_000,
                refund_after_block: 600,
            },
        ],
    };
    let resolutions = BTreeMap::from([
        (
            [5; 32],
            ConditionalResolution::Fulfill {
                preimage: if tamper == ConditionalBatchTamper::WrongPreimage {
                    [9; 32]
                } else {
                    sha_preimage
                },
            },
        ),
        ([6; 32], ConditionalResolution::Refund),
    ]);
    let descriptor = batch.encode_descriptor().unwrap();
    let witness = batch.encode_resolution_witness(&resolutions).unwrap();
    let mut descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    if tamper == ConditionalBatchTamper::DescriptorCommitment {
        descriptor_commitment[0] ^= 1;
    }
    let mut args = [0u8; 2 * BYTE32_LEN + 8 + BYTE32_LEN];
    args[..BYTE32_LEN].fill(3);
    args[BYTE32_LEN..2 * BYTE32_LEN].fill(9);
    args[2 * BYTE32_LEN..2 * BYTE32_LEN + 8].copy_from_slice(&1u64.to_le_bytes());
    args[2 * BYTE32_LEN + 8..].copy_from_slice(&descriptor_commitment);
    let mut args = args.to_vec();
    if tamper == ConditionalBatchTamper::RetiredArgs {
        args.drain(BYTE32_LEN..2 * BYTE32_LEN);
    }
    if tamper == ConditionalBatchTamper::ZeroFundingContext {
        args[BYTE32_LEN..2 * BYTE32_LEN].fill(0);
    }
    let batch_lock = deploy_contract(&mut context, "morph-batch-lock", args);
    let batch_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(batch_lock)
            .build(),
        Bytes::new(),
    );
    let since_block = if tamper == ConditionalBatchTamper::PrematureRefund {
        599
    } else {
        600
    };
    let mut first_capacity = CELL_CAPACITY / 2 - 1_000;
    if tamper == ConditionalBatchTamper::OutputCapacity {
        first_capacity -= 1;
    }
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(batch_out_point)
                .since(absolute_block_since(since_block).unwrap())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(first_capacity)
                .lock(locks[0].clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY / 2 + 1_000)
                .lock(locks[1].clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(witness.to_vec().into()))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_lock_accepts_input_with_expected_state_type() {
    let mut context = Context::default();
    let state_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let refund_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let state_lock = deploy_contract(
        &mut context,
        "morph-state-lock",
        state_type.calc_script_hash().as_slice().to_vec(),
    );
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(refund_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("state lock should accept expected typed input");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_lock_rejects_untyped_input() {
    let mut context = Context::default();
    let state_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let refund_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let state_lock = deploy_contract(
        &mut context,
        "morph-state-lock",
        state_type.calc_script_hash().as_slice().to_vec(),
    );
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(refund_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn devnet_xudt_allows_owner_mint_and_conserves_transfer() {
    let mut context = Context::default();
    let owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        owner_lock.calc_script_hash().as_slice().to_vec(),
    );

    let owner_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(owner_lock.clone())
            .build(),
        Bytes::new(),
    );
    let mint_tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(owner_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(alice_lock.clone())
                .type_(Some(xudt_type.clone()).pack())
                .build(),
        )
        .output_data(xudt_amount_data(100).pack())
        .build();
    let mint_tx = context.complete_tx(mint_tx);
    context
        .verify_tx(&mint_tx, MAX_CYCLES)
        .expect("owner mint should verify");

    let xudt_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(100),
    );
    let transfer_tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(xudt_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .type_(Some(xudt_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output_data(xudt_amount_data(ALICE_XUDT_AMOUNT).pack())
        .output_data(xudt_amount_data(BOB_XUDT_AMOUNT).pack())
        .build();
    let transfer_tx = context.complete_tx(transfer_tx);
    context
        .verify_tx(&transfer_tx, MAX_CYCLES)
        .expect("xUDT amount conservation should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn devnet_xudt_rejects_transfer_sum_overflow() {
    let mut context = Context::default();
    let owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        owner_lock.calc_script_hash().as_slice().to_vec(),
    );

    let xudt_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(alice_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(u128::MAX),
    );
    let transfer_tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(xudt_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .type_(Some(xudt_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output_data(xudt_amount_data(u128::MAX).pack())
        .output_data(xudt_amount_data(1).pack())
        .build();
    let transfer_tx = context.complete_tx(transfer_tx);

    assert!(context.verify_tx(&transfer_tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn batch_lock_resolves_mixed_fulfill_and_refund() {
    let (context, tx) = conditional_batch_resolution_tx(ConditionalBatchTamper::None);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("conditional batch resolution should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn batch_lock_rejects_wrong_preimage() {
    let (context, tx) = conditional_batch_resolution_tx(ConditionalBatchTamper::WrongPreimage);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn batch_lock_rejects_premature_refund() {
    let (context, tx) = conditional_batch_resolution_tx(ConditionalBatchTamper::PrematureRefund);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn batch_lock_rejects_output_capacity_mismatch() {
    let (context, valid) = conditional_batch_resolution_tx(ConditionalBatchTamper::None);
    context
        .verify_tx(&valid, MAX_CYCLES)
        .expect("unchanged Batch payouts must verify before the one-shannon mutation");
    let (context, tx) = conditional_batch_resolution_tx(ConditionalBatchTamper::OutputCapacity);
    let error = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("one-shannon Batch payout mismatch must be rejected");
    assert!(error.to_string().contains("error code 56 "), "{error:?}");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn batch_lock_rejects_descriptor_commitment_mismatch() {
    let (context, tx) =
        conditional_batch_resolution_tx(ConditionalBatchTamper::DescriptorCommitment);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn batch_lock_rejects_retired_args_and_zero_funding_context() {
    for tamper in [
        ConditionalBatchTamper::RetiredArgs,
        ConditionalBatchTamper::ZeroFundingContext,
    ] {
        let (context, tx) = conditional_batch_resolution_tx(tamper);
        let error = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect_err("Batch funding context is mandatory");
        assert!(error.to_string().contains("error code 7 "), "{error:?}");
    }
}
