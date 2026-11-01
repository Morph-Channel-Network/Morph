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
use morph_core::types::{
    FactoryCompactMerkleSibling, FactoryMerkleSibling, FactoryRight, FactoryRightId,
    FactoryRightKind,
};
use morph_core::validation::{
    factory_right_sparse_proof, factory_right_sparse_proof_compact, factory_right_sparse_root,
};
use morph_core::{
    ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant, ConditionalResolution,
    ConditionalTransferSpec, derive_conditional_payment_hash,
};
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT,
    BILATERAL_CKB_DESCRIPTOR_VERSION, BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT,
    BILATERAL_CKB_XUDT_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION,
    BILATERAL_SIGNATURE_COUNT, BILATERAL_SIGNATURE_THRESHOLD, BILATERAL_SIGNATURE_WITNESS_LEN,
    BILATERAL_SIGNATURE_WITNESS_VERSION, BYTE32_LEN, COMPRESSED_SECP256K1_PUBKEY_LEN,
    ECDSA_SIGNATURE_LEN, FACTORY_COMPACT_PROOF_LEN, FACTORY_COMPACT_PROOF_MAX_SIBLINGS,
    FACTORY_COMPACT_PROOF_PAIR_LEN, FACTORY_LOCAL_EXIT_WITNESS_VERSION,
    FACTORY_MERKLE_UPDATE_RIGHT_COUNT, FACTORY_MERKLE_UPDATE_WITNESS_VERSION,
    FACTORY_MIN_PARTICIPANTS, FACTORY_MULTI_RIGHT_UPDATE_WITNESS_VERSION,
    FACTORY_REDUCED_EXIT_RIGHTS_COUNT, FACTORY_REDUCED_EXIT_WITNESS_VERSION,
    FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT, FACTORY_REDUCED_RIGHTS_COUNT,
    FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION,
    FACTORY_REDUCED_SPLICE_WITNESS_VERSION, FACTORY_RIGHT_KIND_RESERVE_CLAIM, FACTORY_RIGHT_LEN,
    FACTORY_SIGNATURE_WITNESS_VERSION, FACTORY_SPARSE_MERKLE_DEPTH, FACTORY_SPLICE_HEADER_LEN,
    FACTORY_SPLICE_WITNESS_VERSION, FACTORY_STATE_HEADER_LEN, FACTORY_VAULT_ASSET_AMOUNT_LEN,
    FACTORY_VAULT_DELTA_LEN, FACTORY_VAULT_DELTAS_LEN, FACTORY_VAULT_DESCRIPTOR_LEN,
    FactoryMerkleUpdateWitness, FactoryMultiRightUpdateWitness, FactoryReducedExitWitness,
    FactoryReducedRightsWitness, FactoryReducedSpliceWitness, FactorySpliceHeader,
    FactoryStateHeader, FactoryVaultDeltas, PHASE_ACTIVE, PHASE_SETTLING, SPLICE_ASSET_DELTA_LEN,
    SPLICE_ASSET_DELTAS_LEN, SPLICE_HEADER_LEN, SPLICE_KIND_IN, SPLICE_KIND_OUT,
    SPLICE_SIGNATURE_COUNT, SPLICE_SIGNATURE_THRESHOLD, SPLICE_SIGNATURE_WITNESS_LEN,
    SPLICE_SIGNATURE_WITNESS_VERSION, SPLICE_STATE_TRANSITION_WITNESS_LEN,
    SPLICE_STATE_TRANSITION_WITNESS_VERSION, SPLICE_VAULT_ASSET_AMOUNT_LEN,
    SPLICE_VAULT_DESCRIPTOR_LEN, SPONSOR_POLICY_LEN, STATE_CARRIER_ACTIVATION_FEE,
    STATE_HEADER_LEN, STATE_MODE_FACTORY_PROOF, SpliceAssetDeltas, SpliceHeader,
    SpliceStateTransitionWitness, SpliceVaultDescriptor, StateHeader, StateHeaderInput,
    VAULT_ASSET_KIND_CKB, VAULT_ASSET_KIND_XUDT, WITNESS_ENVELOPE_FORMAT,
    WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT, WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE,
    WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE, WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
    WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS, WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE,
    WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE, WITNESS_ENVELOPE_KIND_FACTORY_SPLICE,
    WITNESS_ENVELOPE_LEN, WITNESS_ENVELOPE_MAGIC, WitnessEnvelope, absolute_block_since,
    blake2b256, encode_state_header, factory_local_exit_digest, factory_local_exit_witness_len,
    factory_merkle_update_witness_len, factory_multi_right_update_witness_len,
    factory_participants_commitment, factory_reduced_exit_witness_len,
    factory_reduced_rights_witness_len, factory_reduced_splice_witness_len,
    factory_signature_witness_len, factory_splice_witness_len, participants_commitment,
    relative_block_since, settlement_descriptor_commitment, vault_cell_commitment,
    vault_outpoint_commitment, witness_envelope_body_commitment,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[path = "contract_scripts/multi_asset.rs"]
mod multi_asset;

const MAX_CYCLES: u64 = 50_000_000;
const CELL_CAPACITY: u64 = 100_000_000_000;
const ALICE_CAPACITY: u64 = 60_000_000_000;
const BOB_CAPACITY: u64 = 40_000_000_000;
const FUNDING_ANCHOR: [u8; 32] = [4u8; 32];
const NEW_FUNDING_ANCHOR: [u8; 32] = [10u8; 32];
const FACTORY_ID: [u8; 32] = [7u8; 32];
const ALICE_XUDT_AMOUNT: u128 = 70;
const BOB_XUDT_AMOUNT: u128 = 30;

fn test_out_point(tx_hash_byte: u8, index: u32) -> ckb_testtool::ckb_types::packed::OutPoint {
    ckb_testtool::ckb_types::packed::OutPoint::new_builder()
        .tx_hash([tx_hash_byte; BYTE32_LEN].pack())
        .index(index)
        .build()
}

fn fixture_vault_out_point() -> ckb_testtool::ckb_types::packed::OutPoint {
    test_out_point(77, 1)
}

fn fixture_vault_outpoint_commitment() -> [u8; BYTE32_LEN] {
    let out_point = fixture_vault_out_point();
    vault_outpoint_commitment(out_point.tx_hash().as_slice(), 1)
}

fn create_bound_vault_cell(
    context: &mut Context,
    output: CellOutput,
    data: Bytes,
) -> ckb_testtool::ckb_types::packed::OutPoint {
    let out_point = fixture_vault_out_point();
    context.create_cell_with_out_point(out_point.clone(), output, data);
    out_point
}

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

fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(raw: &mut [u8], offset: usize, value: u128) {
    raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}

fn state_args(finalise_since: u64) -> Vec<u8> {
    state_args_with_anchor(FUNDING_ANCHOR, finalise_since)
}

fn state_args_with_anchor(anchor: [u8; 32], finalise_since: u64) -> Vec<u8> {
    let mut args = anchor.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args
}

fn factory_state_args_with_anchor(
    anchor: [u8; 32],
    factory_type_hash: [u8; 32],
    finalise_since: u64,
) -> Vec<u8> {
    let mut args = anchor.to_vec();
    args.extend_from_slice(&factory_type_hash);
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args
}

fn relative_since(value: u64) -> u64 {
    relative_block_since(value).expect("relative block since")
}

fn vault_args(
    anchor: [u8; 32],
    finalise_since: u64,
    state_type: &ckb_testtool::ckb_types::packed::Script,
    state_lock: &ckb_testtool::ckb_types::packed::Script,
) -> Vec<u8> {
    let mut args = anchor.to_vec();
    args.extend_from_slice(&finalise_since.to_le_bytes());
    args.extend_from_slice(state_type.code_hash().as_slice());
    args.push(state_type.hash_type().as_slice()[0]);
    args.extend_from_slice(state_lock.code_hash().as_slice());
    args.push(state_lock.hash_type().as_slice()[0]);
    args
}

fn vault_args_v2(
    anchor: [u8; 32],
    finalise_since: u64,
    state_type: &ckb_testtool::ckb_types::packed::Script,
    state_lock: &ckb_testtool::ckb_types::packed::Script,
    batch_lock_template: &ckb_testtool::ckb_types::packed::Script,
) -> Vec<u8> {
    let mut args = vault_args(anchor, finalise_since, state_type, state_lock);
    args.extend_from_slice(batch_lock_template.code_hash().as_slice());
    args.push(batch_lock_template.hash_type().as_slice()[0]);
    args
}

fn set_state_vault_materialisation_root(raw: &mut [u8], commitment: [u8; 32]) {
    raw[248..280].copy_from_slice(&commitment);
}

fn set_state_vault_outpoint(raw: &mut [u8], out_point: &ckb_testtool::ckb_types::packed::OutPoint) {
    let index: u32 = out_point.index().unpack();
    raw[314..346].copy_from_slice(&vault_outpoint_commitment(
        out_point.tx_hash().as_slice(),
        index,
    ));
}

fn set_factory_vault_materialisation_root(raw: &mut [u8], commitment: [u8; 32]) {
    raw[238..270].copy_from_slice(&commitment);
}

fn set_factory_vault_outpoint(
    raw: &mut [u8],
    out_point: &ckb_testtool::ckb_types::packed::OutPoint,
) {
    let index: u32 = out_point.index().unpack();
    raw[270..302].copy_from_slice(&vault_outpoint_commitment(
        out_point.tx_hash().as_slice(),
        index,
    ));
}

fn vault_commitment(
    lock: &ckb_testtool::ckb_types::packed::Script,
    capacity: u64,
    type_hash: Option<[u8; 32]>,
    data: &[u8],
) -> [u8; 32] {
    vault_cell_commitment(
        lock.calc_script_hash().as_slice(),
        capacity,
        type_hash.as_ref().map(|hash| hash.as_slice()),
        data,
    )
}

fn bind_splice_state_payloads(
    old_state_data: Bytes,
    new_state_data: Bytes,
    old_vault_lock: &ckb_testtool::ckb_types::packed::Script,
    old_vault_capacity: u64,
    new_vault_lock: &ckb_testtool::ckb_types::packed::Script,
    new_vault_capacity: u64,
) -> (Bytes, Bytes) {
    let mut old_state = old_state_data.to_vec();
    set_state_vault_materialisation_root(
        &mut old_state,
        vault_commitment(old_vault_lock, old_vault_capacity, None, &[]),
    );
    let mut new_state = new_state_data.to_vec();
    set_state_vault_materialisation_root(
        &mut new_state,
        vault_commitment(new_vault_lock, new_vault_capacity, None, &[]),
    );
    (Bytes::from(old_state), Bytes::from(new_state))
}

fn build_state_type_from_code(
    context: &mut Context,
    code: &ckb_testtool::ckb_types::packed::OutPoint,
    anchor: [u8; 32],
    finalise_since: u64,
) -> ckb_testtool::ckb_types::packed::Script {
    context
        .build_script(code, state_args_with_anchor(anchor, finalise_since).into())
        .expect("state type script")
}

fn build_state_lock_from_code(
    context: &mut Context,
    code: &ckb_testtool::ckb_types::packed::OutPoint,
    state_type: &ckb_testtool::ckb_types::packed::Script,
) -> ckb_testtool::ckb_types::packed::Script {
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    context
        .build_script(code, state_type_hash.to_vec().into())
        .expect("state lock script")
}

fn build_vault_lock_from_code(
    context: &mut Context,
    code: &ckb_testtool::ckb_types::packed::OutPoint,
    anchor: [u8; 32],
    finalise_since: u64,
    state_type: &ckb_testtool::ckb_types::packed::Script,
    state_lock: &ckb_testtool::ckb_types::packed::Script,
) -> ckb_testtool::ckb_types::packed::Script {
    context
        .build_script(
            code,
            vault_args(anchor, finalise_since, state_type, state_lock).into(),
        )
        .expect("vault lock script")
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn pubkey(key: &SigningKey) -> [u8; COMPRESSED_SECP256K1_PUBKEY_LEN] {
    let encoded = key.verifying_key().to_encoded_point(true);
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

fn header_raw(state_number: u64, phase: u8) -> [u8; STATE_HEADER_LEN] {
    header_raw_with_anchor(state_number, phase, FUNDING_ANCHOR)
}

fn header_raw_with_anchor(
    state_number: u64,
    phase: u8,
    funding_anchor: [u8; 32],
) -> [u8; STATE_HEADER_LEN] {
    encode_state_header(&StateHeaderInput {
        protocol_version: 1,
        chain_id: [2; BYTE32_LEN],
        signature_scheme_id: 1,
        channel_id: [3; BYTE32_LEN],
        funding_epoch: 0,
        funding_anchor,
        vault_set_commitment: funding_anchor,
        state_number,
        mode: 1,
        phase,
        participants_commitment: [5; BYTE32_LEN],
        asset_registry_commitment: [6; BYTE32_LEN],
        settlement_descriptor_commitment: [7; BYTE32_LEN],
        descriptor_version: 1,
        vault_materialisation_root: [8; BYTE32_LEN],
        vault_outpoint_commitment: if state_number == 0 {
            [0; BYTE32_LEN]
        } else {
            fixture_vault_outpoint_commitment()
        },
        challenge_policy_commitment: [9; BYTE32_LEN],
        state_layout_version: 1,
    })
}

fn factory_child_header_raw_with_anchor(
    state_number: u64,
    phase: u8,
    funding_anchor: [u8; 32],
) -> [u8; STATE_HEADER_LEN] {
    let mut raw = header_raw_with_anchor(state_number, phase, funding_anchor);
    raw[148] = 2;
    raw
}

fn factory_header_raw(update_number: u64) -> [u8; FACTORY_STATE_HEADER_LEN] {
    factory_header_raw_with_id(update_number, FACTORY_ID)
}

fn factory_header_raw_with_id(
    update_number: u64,
    factory_id: [u8; 32],
) -> [u8; FACTORY_STATE_HEADER_LEN] {
    let mut raw = [0u8; FACTORY_STATE_HEADER_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].fill(2);
    put_u16(&mut raw, 34, 1);
    raw[36..68].copy_from_slice(&factory_id);
    put_u64(&mut raw, 68, update_number);
    raw[76..108].fill(4);
    raw[108..140].fill(5);
    raw[140..172].fill(6);
    raw[172..204].fill(7);
    raw[204..236].fill(8);
    put_u16(&mut raw, 236, 1);
    raw[238..270].fill(9);
    if update_number != 0 {
        raw[270..302].copy_from_slice(&fixture_vault_outpoint_commitment());
    }
    raw
}

fn derived_funding_anchor(input: &CellInput, output_index: u64) -> [u8; 32] {
    blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
}

fn derived_factory_id(input: &CellInput, output_index: u64) -> [u8; 32] {
    blake2b256(&[input.as_slice(), &output_index.to_le_bytes()])
}

fn signed_state_pair(
    old_number: u64,
    old_phase: u8,
    new_number: u64,
    new_phase: u8,
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = participants_commitment(2, &[&entries[0].0, &entries[1].0]);
    let mut old = header_raw(old_number, old_phase);
    old[150..182].copy_from_slice(&commitment);
    let mut new = header_raw(new_number, new_phase);
    new[150..182].copy_from_slice(&commitment);

    let header = StateHeader::parse(&new).unwrap();
    let digest = header.signing_digest();
    let mut witness = [0u8; BILATERAL_SIGNATURE_WITNESS_LEN];
    put_u16(&mut witness, 0, BILATERAL_SIGNATURE_WITNESS_VERSION);
    witness[2] = BILATERAL_SIGNATURE_THRESHOLD;
    witness[3] = BILATERAL_SIGNATURE_COUNT;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_initial_state_header(
    funding_anchor: [u8; BYTE32_LEN],
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes) {
    signed_initial_state_header_with_mutation(funding_anchor, vault_materialisation_root, |_| {})
}

fn signed_initial_state_header_with_mutation(
    funding_anchor: [u8; BYTE32_LEN],
    vault_materialisation_root: [u8; BYTE32_LEN],
    mutate: impl FnOnce(&mut [u8; STATE_HEADER_LEN]),
) -> (Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = participants_commitment(2, &[&entries[0].0, &entries[1].0]);
    let mut header_raw = header_raw_with_anchor(0, PHASE_ACTIVE, funding_anchor);
    header_raw[150..182].copy_from_slice(&commitment);
    header_raw[248..280].copy_from_slice(&vault_materialisation_root);
    mutate(&mut header_raw);
    let digest = StateHeader::parse(&header_raw).unwrap().signing_digest();
    let mut witness = [0u8; BILATERAL_SIGNATURE_WITNESS_LEN];
    put_u16(&mut witness, 0, BILATERAL_SIGNATURE_WITNESS_VERSION);
    witness[2] = BILATERAL_SIGNATURE_THRESHOLD;
    witness[3] = BILATERAL_SIGNATURE_COUNT;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }
    (header_raw.to_vec().into(), witness.to_vec().into())
}

fn signed_state_pair_with_new_descriptor(
    old_number: u64,
    old_phase: u8,
    new_number: u64,
    new_phase: u8,
    descriptor_commitment: [u8; BYTE32_LEN],
    descriptor_version: u16,
) -> (Bytes, Bytes, Bytes) {
    signed_state_pair_with_updates(
        old_number,
        old_phase,
        new_number,
        new_phase,
        descriptor_commitment,
        descriptor_version,
        [8; BYTE32_LEN],
    )
}

fn signed_state_pair_with_new_materialisation_root(
    old_number: u64,
    old_phase: u8,
    new_number: u64,
    new_phase: u8,
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_state_pair_with_updates(
        old_number,
        old_phase,
        new_number,
        new_phase,
        [7; BYTE32_LEN],
        1,
        vault_materialisation_root,
    )
}

fn signed_state_pair_with_updates(
    old_number: u64,
    old_phase: u8,
    new_number: u64,
    new_phase: u8,
    descriptor_commitment: [u8; BYTE32_LEN],
    descriptor_version: u16,
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = participants_commitment(2, &[&entries[0].0, &entries[1].0]);
    let mut old = header_raw(old_number, old_phase);
    old[150..182].copy_from_slice(&commitment);
    let mut new = header_raw(new_number, new_phase);
    new[150..182].copy_from_slice(&commitment);
    new[214..246].copy_from_slice(&descriptor_commitment);
    put_u16(&mut new, 246, descriptor_version);
    new[248..280].copy_from_slice(&vault_materialisation_root);

    let header = StateHeader::parse(&new).unwrap();
    let digest = header.signing_digest();
    let mut witness = [0u8; BILATERAL_SIGNATURE_WITNESS_LEN];
    put_u16(&mut witness, 0, BILATERAL_SIGNATURE_WITNESS_VERSION);
    witness[2] = BILATERAL_SIGNATURE_THRESHOLD;
    witness[3] = BILATERAL_SIGNATURE_COUNT;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_splice_out_bundle(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
) -> (Bytes, Bytes, Bytes) {
    signed_splice_out_bundle_with_payload(
        old_anchor,
        new_anchor,
        state_number,
        old_capacity,
        new_capacity,
        [8u8; BYTE32_LEN],
        [11u8; BYTE32_LEN],
    )
}

fn signed_splice_out_bundle_with_payload(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
    vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_splice_out_bundle_with_payloads(
        old_anchor,
        new_anchor,
        state_number,
        old_capacity,
        new_capacity,
        vault_materialisation_root,
        [8u8; BYTE32_LEN],
        withdrawal_lock_hash,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_splice_out_bundle_with_payloads(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
    vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_splice_ckb_bundle(
        SPLICE_KIND_OUT,
        (old_anchor, new_anchor),
        state_number,
        (old_capacity, new_capacity),
        None,
        vault_materialisation_root,
        new_vault_materialisation_root,
        withdrawal_lock_hash,
    )
}

fn signed_splice_in_bundle_with_payloads(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
    vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_splice_ckb_bundle(
        SPLICE_KIND_IN,
        (old_anchor, new_anchor),
        state_number,
        (old_capacity, new_capacity),
        None,
        vault_materialisation_root,
        new_vault_materialisation_root,
        [0u8; BYTE32_LEN],
    )
}

fn signed_splice_out_bundle_with_channel_and_payload(
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    state_number: u64,
    old_capacity: u64,
    new_capacity: u64,
    header_channel_id: [u8; BYTE32_LEN],
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_splice_ckb_bundle(
        SPLICE_KIND_OUT,
        (old_anchor, new_anchor),
        state_number,
        (old_capacity, new_capacity),
        Some(header_channel_id),
        vault_materialisation_root,
        [8u8; BYTE32_LEN],
        [11u8; BYTE32_LEN],
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_splice_ckb_bundle(
    kind: u8,
    anchors: ([u8; BYTE32_LEN], [u8; BYTE32_LEN]),
    state_number: u64,
    capacities: (u64, u64),
    header_channel_id: Option<[u8; BYTE32_LEN]>,
    vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let (old_anchor, new_anchor) = anchors;
    let (old_capacity, new_capacity) = capacities;
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [(pubkey(&key0), key0), (pubkey(&key1), key1)];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants = participants_commitment(2, &[&entries[0].0, &entries[1].0]);

    let old_asset = splice_vault_asset_bytes(
        VAULT_ASSET_KIND_CKB,
        &[0u8; BYTE32_LEN],
        old_capacity as u128,
    );
    let old_vault_raw = splice_vault_descriptor_bytes(old_anchor, 1, &old_asset, None);
    let old_vault = SpliceVaultDescriptor::parse(&old_vault_raw).unwrap();

    let new_asset = splice_vault_asset_bytes(
        VAULT_ASSET_KIND_CKB,
        &[0u8; BYTE32_LEN],
        new_capacity as u128,
    );
    let new_vault_raw = splice_vault_descriptor_bytes(new_anchor, 1, &new_asset, None);
    let new_vault = SpliceVaultDescriptor::parse(&new_vault_raw).unwrap();

    let (external_input, withdrawal) = match kind {
        SPLICE_KIND_IN => (new_capacity - old_capacity, 0),
        SPLICE_KIND_OUT => (0, old_capacity - new_capacity),
        _ => unreachable!("test fixture only builds known splice kinds"),
    };
    let delta = splice_asset_delta_bytes(
        VAULT_ASSET_KIND_CKB,
        &[0u8; BYTE32_LEN],
        old_capacity as u128,
        new_capacity as u128,
        external_input as u128,
        withdrawal as u128,
        0,
    );
    let deltas_raw = splice_asset_deltas_bytes(1, &delta, None);
    let deltas = SpliceAssetDeltas::parse(&deltas_raw).unwrap();

    let mut splice_header_raw = splice_header_bytes(
        kind,
        old_anchor,
        new_anchor,
        state_number,
        &participants,
        (
            &old_vault.commitment().unwrap(),
            &new_vault.commitment().unwrap(),
            &deltas.commitment().unwrap(),
            &new_vault_materialisation_root,
        ),
        &vault_materialisation_root,
        &withdrawal_lock_hash,
    );
    if let Some(channel_id) = header_channel_id {
        splice_header_raw[36..68].copy_from_slice(&channel_id);
    }
    let splice_header = SpliceHeader::parse(&splice_header_raw).unwrap();
    let signature_witness =
        signed_splice_signature_witness(&entries, &splice_header.signing_digest());
    let bundle_raw = splice_state_transition_witness_bytes(
        &splice_header_raw,
        &signature_witness,
        &old_vault_raw,
        &new_vault_raw,
        &deltas_raw,
    );
    SpliceStateTransitionWitness::parse(&bundle_raw).unwrap();

    let mut old_state = header_raw_with_anchor(state_number, PHASE_ACTIVE, old_anchor);
    old_state[108..140].copy_from_slice(&old_vault.commitment().unwrap());
    old_state[150..182].copy_from_slice(&participants);
    let mut new_state = header_raw_with_anchor(state_number, PHASE_ACTIVE, new_anchor);
    new_state[314..346].fill(0);
    put_u64(&mut new_state, 68, 1);
    new_state[108..140].copy_from_slice(&new_vault.commitment().unwrap());
    new_state[150..182].copy_from_slice(&participants);
    new_state[248..280].copy_from_slice(&new_vault_materialisation_root);

    (
        old_state.to_vec().into(),
        new_state.to_vec().into(),
        bundle_raw.to_vec().into(),
    )
}

fn signed_splice_signature_witness(
    entries: &[([u8; COMPRESSED_SECP256K1_PUBKEY_LEN], SigningKey); 2],
    digest: &[u8; BYTE32_LEN],
) -> [u8; SPLICE_SIGNATURE_WITNESS_LEN] {
    let mut witness = [0u8; SPLICE_SIGNATURE_WITNESS_LEN];
    put_u16(&mut witness, 0, SPLICE_SIGNATURE_WITNESS_VERSION);
    witness[2] = SPLICE_SIGNATURE_THRESHOLD;
    witness[3] = SPLICE_SIGNATURE_COUNT;
    for (index, (pubkey, key)) in entries.iter().enumerate() {
        let offset = 4 + index * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + COMPRESSED_SECP256K1_PUBKEY_LEN].copy_from_slice(pubkey);
        witness[offset + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, digest));
    }
    witness
}

#[allow(clippy::too_many_arguments)]
fn splice_header_bytes(
    kind: u8,
    old_anchor: [u8; BYTE32_LEN],
    new_anchor: [u8; BYTE32_LEN],
    base_state_number: u64,
    participants: &[u8; BYTE32_LEN],
    commitments: (
        &[u8; BYTE32_LEN],
        &[u8; BYTE32_LEN],
        &[u8; BYTE32_LEN],
        &[u8; BYTE32_LEN],
    ),
    vault_materialisation_root: &[u8; BYTE32_LEN],
    withdrawal_lock_hash: &[u8; BYTE32_LEN],
) -> [u8; SPLICE_HEADER_LEN] {
    let mut raw = [0u8; SPLICE_HEADER_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..34].fill(2);
    put_u16(&mut raw, 34, 1);
    raw[36..68].fill(3);
    raw[68..100].copy_from_slice(&old_anchor);
    raw[100..132].copy_from_slice(&new_anchor);
    put_u64(&mut raw, 132, 0);
    put_u64(&mut raw, 140, 1);
    put_u64(&mut raw, 148, base_state_number);
    put_u64(&mut raw, 156, 1);
    raw[164] = kind;
    raw[165..197].copy_from_slice(commitments.0);
    raw[197..229].copy_from_slice(commitments.1);
    raw[229..261].copy_from_slice(commitments.2);
    raw[261..293].copy_from_slice(participants);
    raw[293..325].copy_from_slice(vault_materialisation_root);
    raw[325..357].copy_from_slice(commitments.3);
    raw[357..389].fill(9);
    raw[389..421].copy_from_slice(&fixture_vault_outpoint_commitment());
    raw[421..453].fill(0);
    raw[453..485].copy_from_slice(withdrawal_lock_hash);
    raw
}

fn splice_vault_asset_bytes(
    kind: u8,
    type_hash: &[u8; BYTE32_LEN],
    amount: u128,
) -> [u8; SPLICE_VAULT_ASSET_AMOUNT_LEN] {
    let mut raw = [0u8; SPLICE_VAULT_ASSET_AMOUNT_LEN];
    raw[0] = kind;
    raw[1..33].copy_from_slice(type_hash);
    put_u128(&mut raw, 33, amount);
    raw
}

fn splice_vault_descriptor_bytes(
    funding_anchor: [u8; BYTE32_LEN],
    count: u16,
    asset_0: &[u8; SPLICE_VAULT_ASSET_AMOUNT_LEN],
    asset_1: Option<&[u8; SPLICE_VAULT_ASSET_AMOUNT_LEN]>,
) -> [u8; SPLICE_VAULT_DESCRIPTOR_LEN] {
    let mut raw = [0u8; SPLICE_VAULT_DESCRIPTOR_LEN];
    raw[0..32].copy_from_slice(&funding_anchor);
    put_u16(&mut raw, 32, count);
    raw[34..34 + SPLICE_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(asset_0);
    if let Some(asset) = asset_1 {
        let offset = 34 + SPLICE_VAULT_ASSET_AMOUNT_LEN;
        raw[offset..offset + SPLICE_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(asset);
    }
    raw
}

fn splice_asset_delta_bytes(
    kind: u8,
    type_hash: &[u8; BYTE32_LEN],
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    signed_fee: u128,
) -> [u8; SPLICE_ASSET_DELTA_LEN] {
    let mut raw = [0u8; SPLICE_ASSET_DELTA_LEN];
    raw[0] = kind;
    raw[1..33].copy_from_slice(type_hash);
    put_u128(&mut raw, 33, old_amount);
    put_u128(&mut raw, 49, new_amount);
    put_u128(&mut raw, 65, external_input);
    put_u128(&mut raw, 81, withdrawal);
    put_u128(&mut raw, 97, signed_fee);
    raw
}

fn splice_asset_deltas_bytes(
    count: u16,
    delta_0: &[u8; SPLICE_ASSET_DELTA_LEN],
    delta_1: Option<&[u8; SPLICE_ASSET_DELTA_LEN]>,
) -> [u8; SPLICE_ASSET_DELTAS_LEN] {
    let mut raw = [0u8; SPLICE_ASSET_DELTAS_LEN];
    put_u16(&mut raw, 0, count);
    raw[2..2 + SPLICE_ASSET_DELTA_LEN].copy_from_slice(delta_0);
    if let Some(delta) = delta_1 {
        let offset = 2 + SPLICE_ASSET_DELTA_LEN;
        raw[offset..offset + SPLICE_ASSET_DELTA_LEN].copy_from_slice(delta);
    }
    raw
}

fn splice_state_transition_witness_bytes(
    header: &[u8; SPLICE_HEADER_LEN],
    signatures: &[u8; SPLICE_SIGNATURE_WITNESS_LEN],
    old_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_LEN],
    new_vault: &[u8; SPLICE_VAULT_DESCRIPTOR_LEN],
    deltas: &[u8; SPLICE_ASSET_DELTAS_LEN],
) -> [u8; SPLICE_STATE_TRANSITION_WITNESS_LEN] {
    let mut raw = [0u8; SPLICE_STATE_TRANSITION_WITNESS_LEN];
    put_u16(&mut raw, 0, SPLICE_STATE_TRANSITION_WITNESS_VERSION);
    let mut offset = 2;
    raw[offset..offset + SPLICE_HEADER_LEN].copy_from_slice(header);
    offset += SPLICE_HEADER_LEN;
    raw[offset..offset + SPLICE_SIGNATURE_WITNESS_LEN].copy_from_slice(signatures);
    offset += SPLICE_SIGNATURE_WITNESS_LEN;
    raw[offset..offset + SPLICE_VAULT_DESCRIPTOR_LEN].copy_from_slice(old_vault);
    offset += SPLICE_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + SPLICE_VAULT_DESCRIPTOR_LEN].copy_from_slice(new_vault);
    offset += SPLICE_VAULT_DESCRIPTOR_LEN;
    raw[offset..offset + SPLICE_ASSET_DELTAS_LEN].copy_from_slice(deltas);
    raw
}

fn signed_factory_pair(old_number: u64, new_number: u64) -> (Bytes, Bytes, Bytes) {
    signed_factory_pair_with_vault_roots(
        old_number,
        new_number,
        [9u8; BYTE32_LEN],
        [9u8; BYTE32_LEN],
    )
}

fn signed_factory_pair_with_vault_roots(
    old_number: u64,
    new_number: u64,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0), key0),
        ([2u8; BYTE32_LEN], pubkey(&key1), key1),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let mut old = factory_header_raw(old_number);
    old[108..140].copy_from_slice(&commitment);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let mut new = factory_header_raw(new_number);
    new[108..140].copy_from_slice(&commitment);
    new[76..108].fill(9);
    new[140..172].fill(10);
    new[172..204].fill(11);
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);

    let header = FactoryStateHeader::parse(&new).unwrap();
    let digest = header.signing_digest();
    let mut witness = [0u8; factory_signature_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    witness[2] = FACTORY_MIN_PARTICIPANTS;
    witness[3] = FACTORY_MIN_PARTICIPANTS;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_dynamic_factory_pair(
    old_number: u64,
    new_number: u64,
    tamper_last_signature: bool,
) -> (Bytes, Bytes, Bytes) {
    let mut entries = (1u8..=3)
        .map(|participant| {
            let key = signing_key(participant);
            ([participant; BYTE32_LEN], pubkey(&key), key)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participant_refs = entries
        .iter()
        .map(|entry| (entry.0.as_slice(), entry.1.as_slice()))
        .collect::<Vec<_>>();
    let commitment = factory_participants_commitment(3, &participant_refs);

    let mut old = factory_header_raw(old_number);
    old[108..140].copy_from_slice(&commitment);
    let mut new = factory_header_raw(new_number);
    new[108..140].copy_from_slice(&commitment);
    new[76..108].fill(9);
    new[140..172].fill(10);
    new[172..204].fill(11);
    let header = FactoryStateHeader::parse(&new).unwrap();
    let digest = header.signing_digest();
    let mut witness = vec![0u8; factory_signature_witness_len(3)];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    witness[2] = 3;
    witness[3] = 3;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }
    if tamper_last_signature {
        *witness.last_mut().unwrap() ^= 1;
    }
    (old.to_vec().into(), new.to_vec().into(), witness.into())
}

fn signed_dynamic_initial_factory_header(
    factory_id: [u8; BYTE32_LEN],
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes) {
    let mut entries = (1u8..=3)
        .map(|participant| {
            let key = signing_key(participant);
            ([participant; BYTE32_LEN], pubkey(&key), key)
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participant_refs = entries
        .iter()
        .map(|entry| (entry.0.as_slice(), entry.1.as_slice()))
        .collect::<Vec<_>>();
    let commitment = factory_participants_commitment(3, &participant_refs);
    let mut header_raw = factory_header_raw_with_id(0, factory_id);
    header_raw[108..140].copy_from_slice(&commitment);
    set_factory_vault_materialisation_root(&mut header_raw, vault_materialisation_root);
    let header = FactoryStateHeader::parse(&header_raw).unwrap();
    let digest = header.signing_digest();
    let mut witness = vec![0u8; factory_signature_witness_len(3)];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    witness[2] = 3;
    witness[3] = 3;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }
    (header_raw.to_vec().into(), witness.into())
}

fn signed_initial_factory_header(
    factory_id: [u8; BYTE32_LEN],
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0), key0),
        ([2u8; BYTE32_LEN], pubkey(&key1), key1),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let mut header_raw = factory_header_raw_with_id(0, factory_id);
    header_raw[108..140].copy_from_slice(&commitment);
    set_factory_vault_materialisation_root(&mut header_raw, vault_materialisation_root);
    let digest = FactoryStateHeader::parse(&header_raw)
        .unwrap()
        .signing_digest();
    let mut witness = [0u8; factory_signature_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    witness[2] = FACTORY_MIN_PARTICIPANTS;
    witness[3] = FACTORY_MIN_PARTICIPANTS;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }
    (header_raw.to_vec().into(), witness.to_vec().into())
}

fn factory_splice_signature_witness(
    key0: &SigningKey,
    key1: &SigningKey,
    digest: &[u8; 32],
) -> [u8; factory_signature_witness_len(2)] {
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(key0), signature(key0, digest)),
        ([2u8; BYTE32_LEN], pubkey(key1), signature(key1, digest)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; factory_signature_witness_len(2)];
    put_u16(&mut raw, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    raw[2] = FACTORY_MIN_PARTICIPANTS;
    raw[3] = FACTORY_MIN_PARTICIPANTS;
    for (index, (participant, pubkey, sig)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(sig);
    }
    raw
}

fn factory_vault_asset_bytes(kind: u8, amount: u128) -> [u8; FACTORY_VAULT_ASSET_AMOUNT_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_ASSET_AMOUNT_LEN];
    raw[0] = kind;
    put_u128(&mut raw, 1 + BYTE32_LEN, amount);
    raw
}

fn factory_vault_asset_bytes_with_type(
    kind: u8,
    asset_type: [u8; BYTE32_LEN],
    amount: u128,
) -> [u8; FACTORY_VAULT_ASSET_AMOUNT_LEN] {
    let mut raw = factory_vault_asset_bytes(kind, amount);
    raw[1..1 + BYTE32_LEN].copy_from_slice(&asset_type);
    raw
}

fn factory_vault_descriptor_bytes(
    factory_id: [u8; BYTE32_LEN],
    asset: &[u8; FACTORY_VAULT_ASSET_AMOUNT_LEN],
) -> [u8; FACTORY_VAULT_DESCRIPTOR_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DESCRIPTOR_LEN];
    raw[0..BYTE32_LEN].copy_from_slice(&factory_id);
    put_u16(&mut raw, BYTE32_LEN, 1);
    raw[BYTE32_LEN + 2..BYTE32_LEN + 2 + FACTORY_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(asset);
    raw
}

fn factory_vault_descriptor_two_assets_bytes(
    factory_id: [u8; BYTE32_LEN],
    first: &[u8; FACTORY_VAULT_ASSET_AMOUNT_LEN],
    second: &[u8; FACTORY_VAULT_ASSET_AMOUNT_LEN],
) -> [u8; FACTORY_VAULT_DESCRIPTOR_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DESCRIPTOR_LEN];
    raw[0..BYTE32_LEN].copy_from_slice(&factory_id);
    put_u16(&mut raw, BYTE32_LEN, 2);
    let mut offset = BYTE32_LEN + 2;
    raw[offset..offset + FACTORY_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(first);
    offset += FACTORY_VAULT_ASSET_AMOUNT_LEN;
    raw[offset..offset + FACTORY_VAULT_ASSET_AMOUNT_LEN].copy_from_slice(second);
    raw
}

fn factory_vault_delta_bytes(
    kind: u8,
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
) -> [u8; FACTORY_VAULT_DELTA_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DELTA_LEN];
    raw[0] = kind;
    put_u128(&mut raw, 1 + BYTE32_LEN, old_amount);
    put_u128(&mut raw, 1 + BYTE32_LEN + 16, new_amount);
    put_u128(&mut raw, 1 + BYTE32_LEN + 32, external_input);
    put_u128(&mut raw, 1 + BYTE32_LEN + 48, withdrawal);
    raw
}

fn factory_vault_delta_bytes_with_type(
    kind: u8,
    asset_type: [u8; BYTE32_LEN],
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
) -> [u8; FACTORY_VAULT_DELTA_LEN] {
    let mut raw =
        factory_vault_delta_bytes(kind, old_amount, new_amount, external_input, withdrawal);
    raw[1..1 + BYTE32_LEN].copy_from_slice(&asset_type);
    raw
}

fn factory_vault_deltas_bytes(
    delta: &[u8; FACTORY_VAULT_DELTA_LEN],
) -> [u8; FACTORY_VAULT_DELTAS_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DELTAS_LEN];
    put_u16(&mut raw, 0, 1);
    raw[2..2 + FACTORY_VAULT_DELTA_LEN].copy_from_slice(delta);
    raw
}

fn factory_vault_deltas_two_bytes(
    first: &[u8; FACTORY_VAULT_DELTA_LEN],
    second: &[u8; FACTORY_VAULT_DELTA_LEN],
) -> [u8; FACTORY_VAULT_DELTAS_LEN] {
    let mut raw = [0u8; FACTORY_VAULT_DELTAS_LEN];
    put_u16(&mut raw, 0, 2);
    let mut offset = 2;
    raw[offset..offset + FACTORY_VAULT_DELTA_LEN].copy_from_slice(first);
    offset += FACTORY_VAULT_DELTA_LEN;
    raw[offset..offset + FACTORY_VAULT_DELTA_LEN].copy_from_slice(second);
    raw
}

fn signed_factory_splice_pair(
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut old = factory_header_raw(1);
    old[108..140].copy_from_slice(&factory_participants);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let old_header = FactoryStateHeader::parse(&old).unwrap();
    let mut new = factory_header_raw(2);
    new[270..302].fill(0);
    new[76..108].fill(9);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].fill(10);
    new[172..204].fill(11);
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);
    let new_header = FactoryStateHeader::parse(&new).unwrap();

    let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, old_amount);
    let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, new_amount);
    let old_vault = factory_vault_descriptor_bytes(FACTORY_ID, &old_asset);
    let new_vault = factory_vault_descriptor_bytes(FACTORY_ID, &new_asset);
    let delta = factory_vault_delta_bytes(
        VAULT_ASSET_KIND_CKB,
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    );
    let deltas = factory_vault_deltas_bytes(&delta);
    let vault_delta_commitment = FactoryVaultDeltas::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let kind = if external_input > 0 {
        SPLICE_KIND_IN
    } else {
        SPLICE_KIND_OUT
    };
    let mut header = [0u8; FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.chain_id());
    put_u16(&mut header, 34, old_header.signature_scheme_id());
    header[36..68].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 68, old_header.update_number());
    put_u64(&mut header, 76, new_header.update_number());
    header[84..116].copy_from_slice(old_header.state_root());
    header[116..148].copy_from_slice(new_header.state_root());
    header[148..180].copy_from_slice(old_header.access_manifest_root());
    header[180..212].copy_from_slice(new_header.access_manifest_root());
    header[212] = kind;
    header[213..245].copy_from_slice(&vault_delta_commitment);
    header[245..277].copy_from_slice(new_header.non_interference_digest());
    header[277..309].copy_from_slice(&splice_participants);
    header[309..341].copy_from_slice(&old_vault_materialisation_root);
    header[341..373].copy_from_slice(&new_vault_materialisation_root);
    header[373..405].copy_from_slice(old_header.vault_outpoint_commitment());
    header[405..437].copy_from_slice(new_header.vault_outpoint_commitment());
    header[437..469].copy_from_slice(&withdrawal_lock_hash);
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();
    let signatures =
        factory_splice_signature_witness(&key0, &key1, &splice_header.signing_digest());

    let mut witness = [0u8; factory_splice_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    witness[offset..offset + factory_signature_witness_len(2)].copy_from_slice(&signatures);
    offset += factory_signature_witness_len(2);
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_dynamic_factory_splice_pair(
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let (old, new, fixed) = signed_factory_splice_pair(
        old_amount,
        new_amount,
        external_input,
        withdrawal,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        withdrawal_lock_hash,
    );
    let keys = [signing_key(1), signing_key(2), signing_key(3)];
    let participants = [
        ([1u8; BYTE32_LEN], pubkey(&keys[0])),
        ([2u8; BYTE32_LEN], pubkey(&keys[1])),
        ([3u8; BYTE32_LEN], pubkey(&keys[2])),
    ];
    let factory_commitment = factory_participants_commitment(
        3,
        &[
            (participants[0].0.as_slice(), participants[0].1.as_slice()),
            (participants[1].0.as_slice(), participants[1].1.as_slice()),
            (participants[2].0.as_slice(), participants[2].1.as_slice()),
        ],
    );
    let splice_commitment = participants_commitment(
        3,
        &[
            participants[0].1.as_slice(),
            participants[1].1.as_slice(),
            participants[2].1.as_slice(),
        ],
    );
    let mut old = old.to_vec();
    let mut new = new.to_vec();
    old[108..140].copy_from_slice(&factory_commitment);
    new[108..140].copy_from_slice(&factory_commitment);

    let fixed = fixed.to_vec();
    let mut header = fixed[2..2 + FACTORY_SPLICE_HEADER_LEN].to_vec();
    header[277..309].copy_from_slice(&splice_commitment);
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();
    let signature_len = factory_signature_witness_len(3);
    let mut signatures = vec![0u8; signature_len];
    put_u16(&mut signatures, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    signatures[2] = 3;
    signatures[3] = 3;
    for (index, ((participant, participant_pubkey), key)) in
        participants.iter().zip(keys.iter()).enumerate()
    {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        signatures[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        signatures[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(participant_pubkey);
        signatures[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &splice_header.signing_digest()));
    }
    let mut witness = vec![0u8; factory_splice_witness_len(3)];
    put_u16(&mut witness, 0, FACTORY_SPLICE_WITNESS_VERSION);
    witness[2..2 + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    let signature_offset = 2 + FACTORY_SPLICE_HEADER_LEN;
    witness[signature_offset..signature_offset + signatures.len()].copy_from_slice(&signatures);
    let fixed_suffix = 2 + FACTORY_SPLICE_HEADER_LEN + factory_signature_witness_len(2);
    witness[signature_offset + signatures.len()..].copy_from_slice(&fixed[fixed_suffix..]);
    (old.into(), new.into(), witness.into())
}

#[allow(clippy::too_many_arguments)]
fn signed_factory_xudt_splice_pair(
    ckb_amount: u128,
    old_xudt_amount: u128,
    new_xudt_amount: u128,
    xudt_type_hash: [u8; BYTE32_LEN],
    external_input: u128,
    withdrawal: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut old = factory_header_raw(1);
    old[108..140].copy_from_slice(&factory_participants);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let old_header = FactoryStateHeader::parse(&old).unwrap();
    let mut new = factory_header_raw(2);
    new[270..302].fill(0);
    new[76..108].fill(9);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].fill(10);
    new[172..204].fill(11);
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);
    let new_header = FactoryStateHeader::parse(&new).unwrap();

    let ckb_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, ckb_amount);
    let old_xudt_asset =
        factory_vault_asset_bytes_with_type(VAULT_ASSET_KIND_XUDT, xudt_type_hash, old_xudt_amount);
    let new_xudt_asset =
        factory_vault_asset_bytes_with_type(VAULT_ASSET_KIND_XUDT, xudt_type_hash, new_xudt_amount);
    let old_vault =
        factory_vault_descriptor_two_assets_bytes(FACTORY_ID, &ckb_asset, &old_xudt_asset);
    let new_vault =
        factory_vault_descriptor_two_assets_bytes(FACTORY_ID, &ckb_asset, &new_xudt_asset);
    let delta = factory_vault_delta_bytes_with_type(
        VAULT_ASSET_KIND_XUDT,
        xudt_type_hash,
        old_xudt_amount,
        new_xudt_amount,
        external_input,
        withdrawal,
    );
    let deltas = factory_vault_deltas_bytes(&delta);
    let vault_delta_commitment = FactoryVaultDeltas::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let kind = if external_input > 0 {
        SPLICE_KIND_IN
    } else {
        SPLICE_KIND_OUT
    };
    let mut header = [0u8; FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.chain_id());
    put_u16(&mut header, 34, old_header.signature_scheme_id());
    header[36..68].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 68, old_header.update_number());
    put_u64(&mut header, 76, new_header.update_number());
    header[84..116].copy_from_slice(old_header.state_root());
    header[116..148].copy_from_slice(new_header.state_root());
    header[148..180].copy_from_slice(old_header.access_manifest_root());
    header[180..212].copy_from_slice(new_header.access_manifest_root());
    header[212] = kind;
    header[213..245].copy_from_slice(&vault_delta_commitment);
    header[245..277].copy_from_slice(new_header.non_interference_digest());
    header[277..309].copy_from_slice(&splice_participants);
    header[309..341].copy_from_slice(&old_vault_materialisation_root);
    header[341..373].copy_from_slice(&new_vault_materialisation_root);
    header[373..405].copy_from_slice(old_header.vault_outpoint_commitment());
    header[405..437].copy_from_slice(new_header.vault_outpoint_commitment());
    if kind == SPLICE_KIND_OUT {
        header[437..469].fill(11);
    }
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();
    let signatures =
        factory_splice_signature_witness(&key0, &key1, &splice_header.signing_digest());

    let mut witness = [0u8; factory_splice_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    witness[offset..offset + factory_signature_witness_len(2)].copy_from_slice(&signatures);
    offset += factory_signature_witness_len(2);
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_factory_dual_asset_splice_pair(
    old_ckb_amount: u128,
    new_ckb_amount: u128,
    old_xudt_amount: u128,
    new_xudt_amount: u128,
    xudt_type_hash: [u8; BYTE32_LEN],
    ckb_external_input: u128,
    xudt_external_input: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut old = factory_header_raw(1);
    old[108..140].copy_from_slice(&factory_participants);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let old_header = FactoryStateHeader::parse(&old).unwrap();
    let mut new = factory_header_raw(2);
    new[270..302].fill(0);
    new[76..108].fill(9);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].fill(10);
    new[172..204].fill(11);
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);
    let new_header = FactoryStateHeader::parse(&new).unwrap();

    let old_ckb_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, old_ckb_amount);
    let new_ckb_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, new_ckb_amount);
    let old_xudt_asset =
        factory_vault_asset_bytes_with_type(VAULT_ASSET_KIND_XUDT, xudt_type_hash, old_xudt_amount);
    let new_xudt_asset =
        factory_vault_asset_bytes_with_type(VAULT_ASSET_KIND_XUDT, xudt_type_hash, new_xudt_amount);
    let old_vault =
        factory_vault_descriptor_two_assets_bytes(FACTORY_ID, &old_ckb_asset, &old_xudt_asset);
    let new_vault =
        factory_vault_descriptor_two_assets_bytes(FACTORY_ID, &new_ckb_asset, &new_xudt_asset);
    let ckb_delta = factory_vault_delta_bytes(
        VAULT_ASSET_KIND_CKB,
        old_ckb_amount,
        new_ckb_amount,
        ckb_external_input,
        0,
    );
    let xudt_delta = factory_vault_delta_bytes_with_type(
        VAULT_ASSET_KIND_XUDT,
        xudt_type_hash,
        old_xudt_amount,
        new_xudt_amount,
        xudt_external_input,
        0,
    );
    let deltas = factory_vault_deltas_two_bytes(&ckb_delta, &xudt_delta);
    let vault_delta_commitment = FactoryVaultDeltas::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let mut header = [0u8; FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.chain_id());
    put_u16(&mut header, 34, old_header.signature_scheme_id());
    header[36..68].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 68, old_header.update_number());
    put_u64(&mut header, 76, new_header.update_number());
    header[84..116].copy_from_slice(old_header.state_root());
    header[116..148].copy_from_slice(new_header.state_root());
    header[148..180].copy_from_slice(old_header.access_manifest_root());
    header[180..212].copy_from_slice(new_header.access_manifest_root());
    header[212] = SPLICE_KIND_IN;
    header[213..245].copy_from_slice(&vault_delta_commitment);
    header[245..277].copy_from_slice(new_header.non_interference_digest());
    header[277..309].copy_from_slice(&splice_participants);
    header[309..341].copy_from_slice(&old_vault_materialisation_root);
    header[341..373].copy_from_slice(&new_vault_materialisation_root);
    header[373..405].copy_from_slice(old_header.vault_outpoint_commitment());
    header[405..437].copy_from_slice(new_header.vault_outpoint_commitment());
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();
    let signatures =
        factory_splice_signature_witness(&key0, &key1, &splice_header.signing_digest());

    let mut witness = [0u8; factory_splice_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    witness[offset..offset + factory_signature_witness_len(2)].copy_from_slice(&signatures);
    offset += factory_signature_witness_len(2);
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_factory_reduced_splice_pair(
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut before = large_factory_rights();
    let mut after = before.clone();
    let changed_index = before
        .iter()
        .position(|right| {
            right.id.participant == [1u8; BYTE32_LEN]
                && right.id.subchannel == [10u8; BYTE32_LEN]
                && right.id.kind == FactoryRightKind::ReserveClaim
                && right.id.asset_type.is_none()
        })
        .expect("fixture reserve claim");
    before[changed_index].quantity = old_amount;
    after[changed_index].quantity = new_amount;
    let changed_id = before[changed_index].id.clone();
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();
    let before_proof = factory_right_sparse_proof(&before, &changed_id).unwrap();
    let after_proof = factory_right_sparse_proof(&after, &changed_id).unwrap();
    assert_eq!(before_proof.siblings, after_proof.siblings);

    let (mut merkle_witness, _, _) = merkle_update_witness_raw(
        &before_proof.right,
        &after_proof.right,
        &before_proof.siblings,
    );
    let merkle = FactoryMerkleUpdateWitness::parse(&merkle_witness).unwrap();
    assert_eq!(merkle.rights_root(false).unwrap(), before_root);
    assert_eq!(merkle.rights_root(true).unwrap(), after_root);

    let mut old = factory_header_raw(1);
    old[76..108].copy_from_slice(&before_root);
    old[108..140].copy_from_slice(&factory_participants);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let old_header = FactoryStateHeader::parse(&old).unwrap();

    let mut new = factory_header_raw(2);
    new[270..302].fill(0);
    new[76..108].copy_from_slice(&after_root);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].copy_from_slice(old_header.access_manifest_root());
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);
    let preliminary_new = FactoryStateHeader::parse(&new).unwrap();
    let digest = merkle
        .non_interference_digest(&old_header, &preliminary_new)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeader::parse(&new).unwrap();

    let old_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, old_amount);
    let new_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, new_amount);
    let old_vault = factory_vault_descriptor_bytes(FACTORY_ID, &old_asset);
    let new_vault = factory_vault_descriptor_bytes(FACTORY_ID, &new_asset);
    let delta = factory_vault_delta_bytes(
        VAULT_ASSET_KIND_CKB,
        old_amount,
        new_amount,
        external_input,
        withdrawal,
    );
    let deltas = factory_vault_deltas_bytes(&delta);
    let vault_delta_commitment = FactoryVaultDeltas::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let kind = if external_input > 0 {
        SPLICE_KIND_IN
    } else {
        SPLICE_KIND_OUT
    };
    let mut header = [0u8; FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.chain_id());
    put_u16(&mut header, 34, old_header.signature_scheme_id());
    header[36..68].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 68, old_header.update_number());
    put_u64(&mut header, 76, new_header.update_number());
    header[84..116].copy_from_slice(old_header.state_root());
    header[116..148].copy_from_slice(new_header.state_root());
    header[148..180].copy_from_slice(old_header.access_manifest_root());
    header[180..212].copy_from_slice(new_header.access_manifest_root());
    header[212] = kind;
    header[213..245].copy_from_slice(&vault_delta_commitment);
    header[245..277].copy_from_slice(new_header.non_interference_digest());
    header[277..309].copy_from_slice(&splice_participants);
    header[309..341].copy_from_slice(&old_vault_materialisation_root);
    header[341..373].copy_from_slice(&new_vault_materialisation_root);
    header[373..405].copy_from_slice(old_header.vault_outpoint_commitment());
    header[405..437].copy_from_slice(new_header.vault_outpoint_commitment());
    header[437..469].copy_from_slice(&withdrawal_lock_hash);
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();
    sign_merkle_update_witness(
        &mut merkle_witness,
        [1u8; BYTE32_LEN],
        &key0,
        &splice_header.signing_digest(),
    );

    let mut witness = [0u8; factory_reduced_splice_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    witness[offset..offset + factory_merkle_update_witness_len(2)].copy_from_slice(&merkle_witness);
    offset += factory_merkle_update_witness_len(2);
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);
    FactoryReducedSpliceWitness::parse(&witness).unwrap();

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn signed_dynamic_factory_reduced_splice_pair(
    old_amount: u128,
    new_amount: u128,
    external_input: u128,
    withdrawal: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
    withdrawal_lock_hash: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let (old, new, fixed) = signed_factory_reduced_splice_pair(
        old_amount,
        new_amount,
        external_input,
        withdrawal,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        withdrawal_lock_hash,
    );
    let keys = [signing_key(1), signing_key(2), signing_key(3)];
    let participants = [
        ([1u8; BYTE32_LEN], pubkey(&keys[0])),
        ([2u8; BYTE32_LEN], pubkey(&keys[1])),
        ([3u8; BYTE32_LEN], pubkey(&keys[2])),
    ];
    let factory_commitment = factory_participants_commitment(
        3,
        &[
            (participants[0].0.as_slice(), participants[0].1.as_slice()),
            (participants[1].0.as_slice(), participants[1].1.as_slice()),
            (participants[2].0.as_slice(), participants[2].1.as_slice()),
        ],
    );
    let splice_commitment = participants_commitment(
        3,
        &[
            participants[0].1.as_slice(),
            participants[1].1.as_slice(),
            participants[2].1.as_slice(),
        ],
    );
    let mut old = old.to_vec();
    let mut new = new.to_vec();
    old[108..140].copy_from_slice(&factory_commitment);
    new[108..140].copy_from_slice(&factory_commitment);

    let fixed = fixed.to_vec();
    let mut header = fixed[2..2 + FACTORY_SPLICE_HEADER_LEN].to_vec();
    header[277..309].copy_from_slice(&splice_commitment);
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();

    let fixed_merkle_offset = 2 + FACTORY_SPLICE_HEADER_LEN;
    let fixed_merkle =
        &fixed[fixed_merkle_offset..fixed_merkle_offset + factory_merkle_update_witness_len(2)];
    let dynamic_merkle_len = factory_merkle_update_witness_len(3);
    let mut dynamic_merkle = vec![0u8; dynamic_merkle_len];
    put_u16(
        &mut dynamic_merkle,
        0,
        FACTORY_MERKLE_UPDATE_WITNESS_VERSION,
    );
    dynamic_merkle[2] = 3;
    dynamic_merkle[3] = 3;
    dynamic_merkle[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    dynamic_merkle[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT;
    for (index, (participant, participant_pubkey)) in participants.iter().enumerate() {
        let offset = merkle_participant_offset(index);
        dynamic_merkle[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        dynamic_merkle[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(participant_pubkey);
        dynamic_merkle[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(index == 0);
        if index == 0 {
            let signature_offset = offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            dynamic_merkle[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(&signature(&keys[0], &splice_header.signing_digest()));
        }
    }
    let dynamic_touched_offset = 8 + 3 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    dynamic_merkle[dynamic_touched_offset..]
        .copy_from_slice(&fixed_merkle[merkle_touched_offset()..]);
    FactoryMerkleUpdateWitness::parse(&dynamic_merkle).unwrap();

    let mut witness = vec![0u8; factory_reduced_splice_witness_len(3)];
    put_u16(&mut witness, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION);
    witness[2..2 + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    let dynamic_merkle_offset = 2 + FACTORY_SPLICE_HEADER_LEN;
    witness[dynamic_merkle_offset..dynamic_merkle_offset + dynamic_merkle_len]
        .copy_from_slice(&dynamic_merkle);
    let fixed_suffix_offset = 2 + FACTORY_SPLICE_HEADER_LEN + factory_merkle_update_witness_len(2);
    witness[dynamic_merkle_offset + dynamic_merkle_len..]
        .copy_from_slice(&fixed[fixed_suffix_offset..]);
    FactoryReducedSpliceWitness::parse(&witness).unwrap();

    (old.into(), new.into(), witness.into())
}

#[allow(clippy::too_many_arguments)]
fn signed_factory_reduced_xudt_splice_pair(
    ckb_amount: u128,
    old_xudt_amount: u128,
    new_xudt_amount: u128,
    xudt_type_hash: [u8; BYTE32_LEN],
    external_input: u128,
    withdrawal: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let factory_participants = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let splice_participants =
        participants_commitment(2, &[entries[0].1.as_slice(), entries[1].1.as_slice()]);

    let mut before = large_factory_rights();
    let mut after = before.clone();
    let changed_index = before
        .iter()
        .position(|right| {
            right.id.participant == [1u8; BYTE32_LEN]
                && right.id.subchannel == [10u8; BYTE32_LEN]
                && right.id.kind == FactoryRightKind::ReserveClaim
                && right.id.asset_type.is_none()
        })
        .expect("fixture reserve claim");
    before[changed_index].id.asset_type = Some(xudt_type_hash);
    before[changed_index].quantity = old_xudt_amount;
    after[changed_index].id.asset_type = Some(xudt_type_hash);
    after[changed_index].quantity = new_xudt_amount;
    let changed_id = before[changed_index].id.clone();
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();
    let before_proof = factory_right_sparse_proof(&before, &changed_id).unwrap();
    let after_proof = factory_right_sparse_proof(&after, &changed_id).unwrap();
    assert_eq!(before_proof.siblings, after_proof.siblings);

    let (mut merkle_witness, _, _) = merkle_update_witness_raw(
        &before_proof.right,
        &after_proof.right,
        &before_proof.siblings,
    );
    let merkle = FactoryMerkleUpdateWitness::parse(&merkle_witness).unwrap();
    assert_eq!(merkle.rights_root(false).unwrap(), before_root);
    assert_eq!(merkle.rights_root(true).unwrap(), after_root);

    let mut old = factory_header_raw(1);
    old[76..108].copy_from_slice(&before_root);
    old[108..140].copy_from_slice(&factory_participants);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let old_header = FactoryStateHeader::parse(&old).unwrap();

    let mut new = factory_header_raw(2);
    new[270..302].fill(0);
    new[76..108].copy_from_slice(&after_root);
    new[108..140].copy_from_slice(&factory_participants);
    new[140..172].copy_from_slice(old_header.access_manifest_root());
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);
    let preliminary_new = FactoryStateHeader::parse(&new).unwrap();
    let digest = merkle
        .non_interference_digest(&old_header, &preliminary_new)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeader::parse(&new).unwrap();

    let ckb_asset = factory_vault_asset_bytes(VAULT_ASSET_KIND_CKB, ckb_amount);
    let old_xudt_asset =
        factory_vault_asset_bytes_with_type(VAULT_ASSET_KIND_XUDT, xudt_type_hash, old_xudt_amount);
    let new_xudt_asset =
        factory_vault_asset_bytes_with_type(VAULT_ASSET_KIND_XUDT, xudt_type_hash, new_xudt_amount);
    let old_vault =
        factory_vault_descriptor_two_assets_bytes(FACTORY_ID, &ckb_asset, &old_xudt_asset);
    let new_vault =
        factory_vault_descriptor_two_assets_bytes(FACTORY_ID, &ckb_asset, &new_xudt_asset);
    let delta = factory_vault_delta_bytes_with_type(
        VAULT_ASSET_KIND_XUDT,
        xudt_type_hash,
        old_xudt_amount,
        new_xudt_amount,
        external_input,
        withdrawal,
    );
    let deltas = factory_vault_deltas_bytes(&delta);
    let vault_delta_commitment = FactoryVaultDeltas::parse(&deltas)
        .unwrap()
        .commitment()
        .unwrap();

    let kind = if external_input > 0 {
        SPLICE_KIND_IN
    } else {
        SPLICE_KIND_OUT
    };
    let mut header = [0u8; FACTORY_SPLICE_HEADER_LEN];
    put_u16(&mut header, 0, 1);
    header[2..34].copy_from_slice(old_header.chain_id());
    put_u16(&mut header, 34, old_header.signature_scheme_id());
    header[36..68].copy_from_slice(old_header.factory_id());
    put_u64(&mut header, 68, old_header.update_number());
    put_u64(&mut header, 76, new_header.update_number());
    header[84..116].copy_from_slice(old_header.state_root());
    header[116..148].copy_from_slice(new_header.state_root());
    header[148..180].copy_from_slice(old_header.access_manifest_root());
    header[180..212].copy_from_slice(new_header.access_manifest_root());
    header[212] = kind;
    header[213..245].copy_from_slice(&vault_delta_commitment);
    header[245..277].copy_from_slice(new_header.non_interference_digest());
    header[277..309].copy_from_slice(&splice_participants);
    header[309..341].copy_from_slice(&old_vault_materialisation_root);
    header[341..373].copy_from_slice(&new_vault_materialisation_root);
    header[373..405].copy_from_slice(old_header.vault_outpoint_commitment());
    header[405..437].copy_from_slice(new_header.vault_outpoint_commitment());
    if kind == SPLICE_KIND_OUT {
        header[437..469].fill(11);
    }
    let splice_header = FactorySpliceHeader::parse(&header).unwrap();
    sign_merkle_update_witness(
        &mut merkle_witness,
        [1u8; BYTE32_LEN],
        &key0,
        &splice_header.signing_digest(),
    );

    let mut witness = [0u8; factory_reduced_splice_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_REDUCED_SPLICE_WITNESS_VERSION);
    let mut offset = 2;
    witness[offset..offset + FACTORY_SPLICE_HEADER_LEN].copy_from_slice(&header);
    offset += FACTORY_SPLICE_HEADER_LEN;
    witness[offset..offset + factory_merkle_update_witness_len(2)].copy_from_slice(&merkle_witness);
    offset += factory_merkle_update_witness_len(2);
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&old_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DESCRIPTOR_LEN].copy_from_slice(&new_vault);
    offset += FACTORY_VAULT_DESCRIPTOR_LEN;
    witness[offset..offset + FACTORY_VAULT_DELTAS_LEN].copy_from_slice(&deltas);
    FactoryReducedSpliceWitness::parse(&witness).unwrap();

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

fn reduced_splice_merkle_offset() -> usize {
    2 + FACTORY_SPLICE_HEADER_LEN
}

fn reduced_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn reduced_touched_offset() -> usize {
    8 + FACTORY_MIN_PARTICIPANTS as usize * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn reduced_right_offset(after: bool, index: usize) -> usize {
    let before_offset = reduced_touched_offset() + BYTE32_LEN;
    if after {
        before_offset
            + FACTORY_REDUCED_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN
            + index * FACTORY_RIGHT_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_LEN
    }
}

fn merkle_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn merkle_touched_offset() -> usize {
    8 + FACTORY_MIN_PARTICIPANTS as usize * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn merkle_right_offset(after: bool) -> usize {
    let before_offset = merkle_touched_offset() + BYTE32_LEN;
    if after {
        before_offset + FACTORY_RIGHT_LEN
    } else {
        before_offset
    }
}

fn merkle_sibling_offset(depth: usize) -> usize {
    merkle_right_offset(true) + FACTORY_RIGHT_LEN + depth * BYTE32_LEN
}

fn factory_right_bytes(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
) -> [u8; FACTORY_RIGHT_LEN] {
    factory_right_bytes_with_asset(participant, subchannel, kind, quantity, None)
}

fn factory_right_bytes_with_asset(
    participant: u8,
    subchannel: u8,
    kind: u8,
    quantity: u128,
    asset_type: Option<[u8; BYTE32_LEN]>,
) -> [u8; FACTORY_RIGHT_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_LEN];
    raw[0..BYTE32_LEN].fill(participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].fill(subchannel);
    raw[2 * BYTE32_LEN] = kind;
    if let Some(asset_type) = asset_type {
        raw[2 * BYTE32_LEN + 1] = 1;
        raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
    }
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, quantity);
    raw
}

fn factory_right_kind_byte(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    }
}

fn core_factory_right_bytes(right: &FactoryRight) -> [u8; FACTORY_RIGHT_LEN] {
    let mut raw = [0u8; FACTORY_RIGHT_LEN];
    raw[0..BYTE32_LEN].copy_from_slice(&right.id.participant);
    raw[BYTE32_LEN..2 * BYTE32_LEN].copy_from_slice(&right.id.subchannel);
    raw[2 * BYTE32_LEN] = factory_right_kind_byte(right.id.kind);
    match right.id.asset_type {
        Some(asset_type) => {
            raw[2 * BYTE32_LEN + 1] = 1;
            raw[2 * BYTE32_LEN + 2..2 * BYTE32_LEN + 2 + BYTE32_LEN].copy_from_slice(&asset_type);
        }
        None => {
            raw[2 * BYTE32_LEN + 1] = 0;
        }
    }
    put_u128(&mut raw, 2 * BYTE32_LEN + 2 + BYTE32_LEN, right.quantity);
    raw
}

fn large_factory_rights() -> Vec<FactoryRight> {
    let mut rights = Vec::new();
    for participant in 1u8..=8 {
        for subchannel in 10u8..=13 {
            for (kind, quantity) in [
                (FactoryRightKind::Balance, 1_000u128),
                (FactoryRightKind::ReserveClaim, 250u128),
                (FactoryRightKind::ExitPath, 1u128),
            ] {
                rights.push(FactoryRight {
                    id: FactoryRightId {
                        participant: [participant; BYTE32_LEN],
                        subchannel: [subchannel; BYTE32_LEN],
                        kind,
                        asset_type: None,
                    },
                    quantity,
                });
            }
        }
    }
    rights
}

fn reduced_rights_pair(
    touched_after_balance: u128,
) -> (
    [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_RIGHTS_COUNT as usize],
    [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_RIGHTS_COUNT as usize],
) {
    let before = [
        factory_right_bytes(1, 10, 0, 100),
        factory_right_bytes(1, 10, 1, 50),
        factory_right_bytes(1, 10, 2, 1),
        factory_right_bytes(1, 10, 3, 1),
        factory_right_bytes(1, 10, 4, 20),
        factory_right_bytes(2, 10, 0, 100),
        factory_right_bytes(2, 10, 1, 50),
        factory_right_bytes(2, 10, 2, 1),
        factory_right_bytes(2, 10, 3, 1),
        factory_right_bytes(2, 10, 4, 20),
    ];
    let mut after = before;
    after[0] = factory_right_bytes(1, 10, 0, touched_after_balance);
    (before, after)
}

fn reduced_rights_witness_raw(
    touched_after_balance: u128,
) -> (
    [u8; factory_reduced_rights_witness_len(2)],
    SigningKey,
    SigningKey,
) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let (before, after) = reduced_rights_pair(touched_after_balance);

    let mut raw = [0u8; factory_reduced_rights_witness_len(2)];
    put_u16(&mut raw, 0, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION);
    raw[2] = FACTORY_MIN_PARTICIPANTS;
    raw[3] = FACTORY_MIN_PARTICIPANTS;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = FACTORY_REDUCED_RIGHTS_COUNT;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = reduced_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant == &[1u8; BYTE32_LEN]);
    }
    raw[reduced_touched_offset()..reduced_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&[1u8; BYTE32_LEN]);
    for index in 0..FACTORY_REDUCED_RIGHTS_COUNT as usize {
        let before_offset = reduced_right_offset(false, index);
        raw[before_offset..before_offset + FACTORY_RIGHT_LEN].copy_from_slice(&before[index]);
        let after_offset = reduced_right_offset(true, index);
        raw[after_offset..after_offset + FACTORY_RIGHT_LEN].copy_from_slice(&after[index]);
    }

    (raw, key0, key1)
}

fn signed_reduced_factory_rights_pair(
    old_number: u64,
    new_number: u64,
    touched_after_balance: u128,
) -> (Bytes, Bytes, Bytes) {
    let (mut witness_raw, key0, key1) = reduced_rights_witness_raw(touched_after_balance);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryReducedRightsWitness::parse(&witness_raw).unwrap();

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&participants_commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    let old_header = FactoryStateHeader::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
    let preliminary_new_header = FactoryStateHeader::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeader::parse(&new).unwrap();
    let sig = signature(&key0, &new_header.signing_digest());
    let signature_offset =
        reduced_participant_offset(0) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
    witness_raw[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness_raw.to_vec().into(),
    )
}

fn signed_dynamic_reduced_factory_rights_pair(
    old_number: u64,
    new_number: u64,
    touched_after_balance: u128,
) -> (Bytes, Bytes, Bytes) {
    let (fixed, key0, key1) = reduced_rights_witness_raw(touched_after_balance);
    let key2 = signing_key(3);
    let participant_count = 3u8;
    let mut raw = vec![0u8; factory_reduced_rights_witness_len(participant_count)];
    raw[..8].copy_from_slice(&fixed[..8]);
    put_u16(&mut raw, 0, FACTORY_REDUCED_RIGHTS_WITNESS_VERSION);
    raw[2] = participant_count;
    raw[3] = participant_count;
    for index in 0..2 {
        let source = reduced_participant_offset(index);
        let target = 8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
        raw[target..target + FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN]
            .copy_from_slice(&fixed[source..source + FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN]);
    }
    let third = 8 + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    raw[third..third + BYTE32_LEN].fill(3);
    raw[third + BYTE32_LEN..third + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
        .copy_from_slice(&pubkey(&key2));
    let dynamic_touched = 8 + 3 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    raw[dynamic_touched..].copy_from_slice(&fixed[reduced_touched_offset()..]);
    let witness = FactoryReducedRightsWitness::parse(&raw).unwrap();
    let participants = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
        ([3u8; BYTE32_LEN], pubkey(&key2)),
    ];
    let commitment = factory_participants_commitment(
        3,
        &[
            (participants[0].0.as_slice(), participants[0].1.as_slice()),
            (participants[1].0.as_slice(), participants[1].1.as_slice()),
            (participants[2].0.as_slice(), participants[2].1.as_slice()),
        ],
    );
    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    let old_header = FactoryStateHeader::parse(&old).unwrap();
    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
    new[108..140].copy_from_slice(&commitment);
    new[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
    let preliminary = FactoryStateHeader::parse(&new).unwrap();
    let non_interference = witness
        .non_interference_digest(&old_header, &preliminary)
        .unwrap();
    new[172..204].copy_from_slice(&non_interference);
    let new_header = FactoryStateHeader::parse(&new).unwrap();
    let signature_offset = 8 + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
    raw[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN]
        .copy_from_slice(&signature(&key0, &new_header.signing_digest()));
    FactoryReducedRightsWitness::parse(&raw).unwrap();
    (old.to_vec().into(), new.to_vec().into(), raw.into())
}

fn merkle_update_witness_raw(
    before_right: &FactoryRight,
    after_right: &FactoryRight,
    siblings: &[FactoryMerkleSibling],
) -> (Vec<u8>, SigningKey, SigningKey) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let touched = before_right.id.participant;
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = vec![0u8; factory_merkle_update_witness_len(2)];
    put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
    raw[2] = FACTORY_MIN_PARTICIPANTS;
    raw[3] = FACTORY_MIN_PARTICIPANTS;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = FACTORY_MERKLE_UPDATE_RIGHT_COUNT;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = merkle_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant.as_slice() == touched.as_slice());
    }
    raw[merkle_touched_offset()..merkle_touched_offset() + BYTE32_LEN].copy_from_slice(&touched);
    raw[merkle_right_offset(false)..merkle_right_offset(false) + FACTORY_RIGHT_LEN]
        .copy_from_slice(&core_factory_right_bytes(before_right));
    raw[merkle_right_offset(true)..merkle_right_offset(true) + FACTORY_RIGHT_LEN]
        .copy_from_slice(&core_factory_right_bytes(after_right));
    assert_eq!(siblings.len(), FACTORY_SPARSE_MERKLE_DEPTH);
    for (depth, sibling) in siblings.iter().enumerate() {
        let offset = merkle_sibling_offset(depth);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(&sibling.hash);
    }

    (raw, key0, key1)
}

fn sign_merkle_update_witness(
    raw: &mut [u8],
    participant: [u8; BYTE32_LEN],
    key: &SigningKey,
    digest: &[u8; 32],
) {
    let sig = signature(key, digest);
    for index in 0..FACTORY_MIN_PARTICIPANTS as usize {
        if &raw[merkle_participant_offset(index)..merkle_participant_offset(index) + BYTE32_LEN]
            == participant.as_slice()
        {
            let offset =
                merkle_participant_offset(index) + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
        }
    }
}

fn signed_factory_merkle_update_pair(old_number: u64, new_number: u64) -> (Bytes, Bytes, Bytes) {
    signed_factory_merkle_update_pair_with_quantity(old_number, new_number, 900)
}

fn signed_factory_merkle_update_pair_with_quantity(
    old_number: u64,
    new_number: u64,
    after_quantity: u128,
) -> (Bytes, Bytes, Bytes) {
    let before = large_factory_rights();
    let mut after = before.clone();
    after[0].quantity = after_quantity;
    let changed_id = before[0].id.clone();
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();
    let before_proof = factory_right_sparse_proof(&before, &changed_id).unwrap();
    let after_proof = factory_right_sparse_proof(&after, &changed_id).unwrap();
    assert_eq!(before_proof.siblings, after_proof.siblings);

    let (mut witness_raw, key0, key1) = merkle_update_witness_raw(
        &before_proof.right,
        &after_proof.right,
        &before_proof.siblings,
    );
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryMerkleUpdateWitness::parse(&witness_raw).unwrap();
    assert_eq!(witness.rights_root(false).unwrap(), before_root);
    assert_eq!(witness.rights_root(true).unwrap(), after_root);

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&before_root);
    old[108..140].copy_from_slice(&participants_commitment);
    let old_header = FactoryStateHeader::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&after_root);
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(old_header.access_manifest_root());
    let preliminary_new_header = FactoryStateHeader::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeader::parse(&new).unwrap();
    sign_merkle_update_witness(
        &mut witness_raw,
        [1u8; BYTE32_LEN],
        &key0,
        &new_header.signing_digest(),
    );

    (old.to_vec().into(), new.to_vec().into(), witness_raw.into())
}

fn signed_dynamic_factory_merkle_update_pair(
    old_number: u64,
    new_number: u64,
) -> (Bytes, Bytes, Bytes) {
    let (old, new, fixed) = signed_factory_merkle_update_pair(old_number, new_number);
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let key2 = signing_key(3);
    let participant_count = 3u8;
    let fixed = fixed.to_vec();
    let mut raw = vec![0u8; factory_merkle_update_witness_len(participant_count)];
    raw[..8].copy_from_slice(&fixed[..8]);
    put_u16(&mut raw, 0, FACTORY_MERKLE_UPDATE_WITNESS_VERSION);
    raw[2] = participant_count;
    raw[3] = participant_count;
    for index in 0..2 {
        let source = merkle_participant_offset(index);
        let target = 8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
        raw[target..target + FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN]
            .copy_from_slice(&fixed[source..source + FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN]);
    }
    let third = 8 + 2 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    raw[third..third + BYTE32_LEN].fill(3);
    raw[third + BYTE32_LEN..third + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
        .copy_from_slice(&pubkey(&key2));
    let dynamic_touched = 8 + 3 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
    raw[dynamic_touched..].copy_from_slice(&fixed[merkle_touched_offset()..]);
    let participants = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
        ([3u8; BYTE32_LEN], pubkey(&key2)),
    ];
    let commitment = factory_participants_commitment(
        3,
        &[
            (participants[0].0.as_slice(), participants[0].1.as_slice()),
            (participants[1].0.as_slice(), participants[1].1.as_slice()),
            (participants[2].0.as_slice(), participants[2].1.as_slice()),
        ],
    );
    let mut old = old.to_vec();
    let mut new = new.to_vec();
    old[108..140].copy_from_slice(&commitment);
    new[108..140].copy_from_slice(&commitment);
    let new_header = FactoryStateHeader::parse(&new).unwrap();
    let signature_offset = 8 + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
    raw[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN]
        .copy_from_slice(&signature(&key0, &new_header.signing_digest()));
    FactoryMerkleUpdateWitness::parse(&raw).unwrap();
    (old.into(), new.into(), raw.into())
}

fn reduced_exit_participant_offset(index: usize) -> usize {
    8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn multi_right_touched_offset() -> usize {
    8 + FACTORY_MIN_PARTICIPANTS as usize * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn multi_right_capacity_offset() -> usize {
    multi_right_touched_offset() + BYTE32_LEN
}

fn multi_right_right_offset(right_count: u8, after: bool, index: usize) -> usize {
    let before_offset = multi_right_capacity_offset() + 2 + 2;
    if after {
        before_offset + right_count as usize * FACTORY_RIGHT_LEN + index * FACTORY_RIGHT_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_LEN
    }
}

fn multi_right_proof_offset(right_count: u8, after: bool, index: usize) -> usize {
    let proofs_offset =
        multi_right_right_offset(right_count, true, 0) + right_count as usize * FACTORY_RIGHT_LEN;
    if after {
        proofs_offset
            + right_count as usize * FACTORY_COMPACT_PROOF_LEN
            + index * FACTORY_COMPACT_PROOF_LEN
    } else {
        proofs_offset + index * FACTORY_COMPACT_PROOF_LEN
    }
}

fn write_compact_proof_pairs(
    raw: &mut [u8],
    offset: usize,
    siblings: &[FactoryCompactMerkleSibling],
) {
    put_u16(raw, offset, siblings.len() as u16);
    for (pair, sibling) in siblings.iter().enumerate() {
        let pair_offset = offset + 2 + pair * FACTORY_COMPACT_PROOF_PAIR_LEN;
        put_u16(raw, pair_offset, sibling.depth);
        raw[pair_offset + 2..pair_offset + 2 + BYTE32_LEN].copy_from_slice(&sibling.hash);
    }
}

#[allow(clippy::type_complexity)]
fn signed_multi_right_update_pair_with_quantities(
    old_number: u64,
    new_number: u64,
    after_balance: u128,
    after_reserve: u128,
    foreign_bump: Option<u128>,
) -> (Bytes, Bytes, Bytes) {
    signed_multi_right_update_pair_with_assets(
        old_number,
        new_number,
        after_balance,
        after_reserve,
        foreign_bump,
        None,
    )
}

#[allow(clippy::type_complexity)]
fn signed_multi_right_update_pair_with_assets(
    old_number: u64,
    new_number: u64,
    after_balance: u128,
    after_reserve: u128,
    foreign_bump: Option<u128>,
    changed_assets: Option<([u8; BYTE32_LEN], [u8; BYTE32_LEN])>,
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let touched = [1u8; BYTE32_LEN];
    let mut before = large_factory_rights();
    if let Some((balance_asset, reserve_asset)) = changed_assets {
        before[0].id.asset_type = Some(balance_asset);
        before[1].id.asset_type = Some(reserve_asset);
    }
    let mut after = before.clone();
    after[0].quantity = after_balance;
    after[1].quantity = after_reserve;
    if let Some(bump) = foreign_bump {
        // Participant 8's subchannel-10 balance (participant-major layout,
        // index 7 * 12): an unlisted right the touched participant must not
        // be able to change between the committed roots.
        after[84].quantity += bump;
    }
    let mut proof_pairs = [
        (
            factory_right_sparse_proof_compact(&before, &before[0].id).unwrap(),
            factory_right_sparse_proof_compact(&after, &after[0].id).unwrap(),
        ),
        (
            factory_right_sparse_proof_compact(&before, &before[1].id).unwrap(),
            factory_right_sparse_proof_compact(&after, &after[1].id).unwrap(),
        ),
    ];
    proof_pairs.sort_by(|(left, _), (right, _)| left.right.id.cmp(&right.right.id));
    let before_root = factory_right_sparse_root(&before).unwrap();
    let after_root = factory_right_sparse_root(&after).unwrap();

    let right_count = 2u8;
    let mut raw = vec![0u8; factory_multi_right_update_witness_len(2, right_count)];
    put_u16(&mut raw, 0, FACTORY_MULTI_RIGHT_UPDATE_WITNESS_VERSION);
    raw[2] = FACTORY_MIN_PARTICIPANTS;
    raw[3] = FACTORY_MIN_PARTICIPANTS;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = right_count;
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = 8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(*participant == touched);
    }
    raw[multi_right_touched_offset()..multi_right_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&touched);
    put_u16(
        &mut raw,
        multi_right_capacity_offset(),
        FACTORY_COMPACT_PROOF_MAX_SIBLINGS as u16,
    );
    for (index, (before_proof, after_proof)) in proof_pairs.iter().enumerate() {
        let before_offset = multi_right_right_offset(right_count, false, index);
        raw[before_offset..before_offset + FACTORY_RIGHT_LEN]
            .copy_from_slice(&core_factory_right_bytes(&before_proof.right));
        let after_offset = multi_right_right_offset(right_count, true, index);
        raw[after_offset..after_offset + FACTORY_RIGHT_LEN]
            .copy_from_slice(&core_factory_right_bytes(&after_proof.right));
        write_compact_proof_pairs(
            &mut raw,
            multi_right_proof_offset(right_count, false, index),
            &before_proof.siblings,
        );
        write_compact_proof_pairs(
            &mut raw,
            multi_right_proof_offset(right_count, true, index),
            &after_proof.siblings,
        );
    }

    let witness = FactoryMultiRightUpdateWitness::parse(&raw).unwrap();
    for index in 0..right_count as usize {
        assert_eq!(witness.proof_root(false, index).unwrap(), before_root);
        assert_eq!(witness.proof_root(true, index).unwrap(), after_root);
    }

    let participants_commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&before_root);
    old[108..140].copy_from_slice(&participants_commitment);
    let old_header = FactoryStateHeader::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[76..108].copy_from_slice(&after_root);
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(old_header.access_manifest_root());
    let preliminary_new_header = FactoryStateHeader::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeader::parse(&new).unwrap();
    let authorisation = signature(&key0, &new_header.signing_digest());
    for index in 0..FACTORY_MIN_PARTICIPANTS as usize {
        let offset = 8 + index * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN;
        if raw[offset..offset + BYTE32_LEN] == touched {
            let signature_offset = offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
            raw[signature_offset..signature_offset + ECDSA_SIGNATURE_LEN]
                .copy_from_slice(&authorisation);
        }
    }

    (old.to_vec().into(), new.to_vec().into(), raw.into())
}

fn signed_multi_right_update_pair(old_number: u64, new_number: u64) -> (Bytes, Bytes, Bytes) {
    signed_multi_right_update_pair_with_quantities(old_number, new_number, 700, 300, None)
}

fn reduced_exit_touched_offset() -> usize {
    8 + FACTORY_MIN_PARTICIPANTS as usize * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
}

fn reduced_exit_release_quantity_offset() -> usize {
    reduced_exit_touched_offset() + BYTE32_LEN
}

fn reduced_exit_state_output_index_offset() -> usize {
    reduced_exit_release_quantity_offset() + 16
}

fn reduced_exit_vault_output_index_offset() -> usize {
    reduced_exit_state_output_index_offset() + 4
}

fn reduced_exit_state_type_hash_offset() -> usize {
    reduced_exit_vault_output_index_offset() + 4
}

fn reduced_exit_vault_lock_hash_offset() -> usize {
    reduced_exit_state_type_hash_offset() + BYTE32_LEN
}

fn reduced_exit_state_lock_hash_offset() -> usize {
    reduced_exit_vault_lock_hash_offset() + BYTE32_LEN
}

fn reduced_exit_state_header_offset() -> usize {
    reduced_exit_state_lock_hash_offset() + BYTE32_LEN
}

fn reduced_exit_descriptor_offset() -> usize {
    reduced_exit_state_header_offset() + STATE_HEADER_LEN
}

fn reduced_exit_right_offset(after: bool, descriptor_len: usize, index: usize) -> usize {
    let before_offset = reduced_exit_descriptor_offset() + descriptor_len;
    if after {
        before_offset
            + FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize * FACTORY_RIGHT_LEN
            + index * FACTORY_RIGHT_LEN
    } else {
        before_offset + index * FACTORY_RIGHT_LEN
    }
}

#[allow(clippy::too_many_arguments)]
fn reduced_exit_rights_pair(
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
    ckb_reserve_claim_before_quantity: u128,
    ckb_reserve_claim_after_quantity: u128,
) -> (
    [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
    [[u8; FACTORY_RIGHT_LEN]; FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize],
) {
    let before = [
        factory_right_bytes(1, 10, 0, 100),
        factory_right_bytes_with_asset(
            1,
            10,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            reserve_claim_before_quantity,
            reserve_asset_type,
        ),
        factory_right_bytes(1, 10, 2, 1),
        factory_right_bytes(1, 10, 3, 1),
        factory_right_bytes(1, 10, 4, 20),
        factory_right_bytes_with_asset(
            1,
            11,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            ckb_reserve_claim_before_quantity,
            None,
        ),
        factory_right_bytes(2, 10, 0, 100),
        factory_right_bytes(2, 10, FACTORY_RIGHT_KIND_RESERVE_CLAIM, 50),
        factory_right_bytes(2, 10, 2, 1),
        factory_right_bytes(2, 10, 3, 1),
        factory_right_bytes(2, 10, 4, 20),
        factory_right_bytes_with_asset(
            2,
            11,
            FACTORY_RIGHT_KIND_RESERVE_CLAIM,
            ckb_reserve_claim_before_quantity,
            None,
        ),
    ];
    let mut after = before;
    after[1] = factory_right_bytes_with_asset(
        1,
        10,
        FACTORY_RIGHT_KIND_RESERVE_CLAIM,
        reserve_claim_after_quantity,
        reserve_asset_type,
    );
    after[5] = factory_right_bytes_with_asset(
        1,
        11,
        FACTORY_RIGHT_KIND_RESERVE_CLAIM,
        ckb_reserve_claim_after_quantity,
        None,
    );
    (before, after)
}

#[allow(clippy::too_many_arguments)]
fn reduced_exit_witness_raw_with_reserve_asset(
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
    ckb_reserve_claim_before_quantity: u128,
    ckb_reserve_claim_after_quantity: u128,
) -> (Vec<u8>, SigningKey, SigningKey) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let touched = [1u8; BYTE32_LEN];
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let (before, after) = reduced_exit_rights_pair(
        reserve_claim_before_quantity,
        reserve_claim_after_quantity,
        reserve_asset_type,
        ckb_reserve_claim_before_quantity,
        ckb_reserve_claim_after_quantity,
    );

    let mut raw = vec![
        0u8;
        factory_reduced_exit_witness_len(2, BILATERAL_CKB_DESCRIPTOR_LEN)
            - BILATERAL_CKB_DESCRIPTOR_LEN
            + descriptor.len()
    ];
    put_u16(&mut raw, 0, FACTORY_REDUCED_EXIT_WITNESS_VERSION);
    raw[2] = FACTORY_MIN_PARTICIPANTS;
    raw[3] = FACTORY_MIN_PARTICIPANTS;
    raw[4] = FACTORY_REDUCED_RIGHTS_AUTHORISED_COUNT;
    raw[5] = FACTORY_REDUCED_EXIT_RIGHTS_COUNT;
    for (index, (participant, pubkey)) in entries.iter().enumerate() {
        let offset = reduced_exit_participant_offset(index);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        raw[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        raw[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN] =
            u8::from(participant.as_slice() == touched.as_slice());
    }
    raw[reduced_exit_touched_offset()..reduced_exit_touched_offset() + BYTE32_LEN]
        .copy_from_slice(&touched);
    put_u128(
        &mut raw,
        reduced_exit_release_quantity_offset(),
        release_quantity,
    );
    put_u32(
        &mut raw,
        reduced_exit_state_output_index_offset(),
        state_output_index,
    );
    put_u32(
        &mut raw,
        reduced_exit_vault_output_index_offset(),
        vault_output_index,
    );
    raw[reduced_exit_state_type_hash_offset()..reduced_exit_state_type_hash_offset() + BYTE32_LEN]
        .copy_from_slice(&state_type_hash);
    raw[reduced_exit_vault_lock_hash_offset()..reduced_exit_vault_lock_hash_offset() + BYTE32_LEN]
        .copy_from_slice(&vault_lock_hash);
    raw[reduced_exit_state_lock_hash_offset()..reduced_exit_state_lock_hash_offset() + BYTE32_LEN]
        .copy_from_slice(&state_lock_hash);
    raw[reduced_exit_state_header_offset()..reduced_exit_state_header_offset() + STATE_HEADER_LEN]
        .copy_from_slice(state_header);
    raw[reduced_exit_descriptor_offset()..reduced_exit_descriptor_offset() + descriptor.len()]
        .copy_from_slice(descriptor);
    for index in 0..FACTORY_REDUCED_EXIT_RIGHTS_COUNT as usize {
        let before_offset = reduced_exit_right_offset(false, descriptor.len(), index);
        raw[before_offset..before_offset + FACTORY_RIGHT_LEN].copy_from_slice(&before[index]);
        let after_offset = reduced_exit_right_offset(true, descriptor.len(), index);
        raw[after_offset..after_offset + FACTORY_RIGHT_LEN].copy_from_slice(&after[index]);
    }

    (raw, key0, key1)
}

fn sign_reduced_exit_witness(
    raw: &mut [u8],
    participant: [u8; BYTE32_LEN],
    key: &SigningKey,
    digest: &[u8; 32],
) {
    let sig = signature(key, digest);
    for index in 0..FACTORY_MIN_PARTICIPANTS as usize {
        if &raw[reduced_exit_participant_offset(index)
            ..reduced_exit_participant_offset(index) + BYTE32_LEN]
            == participant.as_slice()
        {
            let offset = reduced_exit_participant_offset(index)
                + BYTE32_LEN
                + COMPRESSED_SECP256K1_PUBKEY_LEN
                + 1;
            raw[offset..offset + ECDSA_SIGNATURE_LEN].copy_from_slice(&sig);
        }
    }
}

fn reduced_exit_old_factory_data(
    old_number: u64,
    reserve_claim_before_quantity: u128,
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> Bytes {
    reduced_exit_old_factory_data_with_reserve_asset(
        old_number,
        reserve_claim_before_quantity,
        None,
        100,
        100,
        vault_materialisation_root,
    )
}

fn reduced_exit_old_factory_data_with_reserve_asset(
    old_number: u64,
    reserve_claim_before_quantity: u128,
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
    ckb_reserve_claim_before_quantity: u128,
    ckb_reserve_claim_after_quantity: u128,
    vault_materialisation_root: [u8; BYTE32_LEN],
) -> Bytes {
    let descriptor = descriptor_bytes([1u8; 32], 1, [2u8; 32], 2);
    let child_state = header_raw(0, PHASE_ACTIVE);
    let (witness_raw, key0, key1) = reduced_exit_witness_raw_with_reserve_asset(
        1,
        reserve_claim_before_quantity,
        reserve_claim_before_quantity - 1,
        1,
        2,
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        &child_state,
        &descriptor,
        reserve_asset_type,
        ckb_reserve_claim_before_quantity,
        ckb_reserve_claim_after_quantity,
    );
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&participants_commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    set_factory_vault_materialisation_root(&mut old, vault_materialisation_root);
    old.to_vec().into()
}

#[allow(clippy::too_many_arguments)]
fn signed_reduced_factory_exit_pair(
    old_number: u64,
    new_number: u64,
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    signed_reduced_factory_exit_pair_with_reserve_asset(
        old_number,
        new_number,
        release_quantity,
        reserve_claim_before_quantity,
        reserve_claim_after_quantity,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        state_header,
        descriptor,
        None,
        100,
        100,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_reduced_factory_exit_pair_with_reserve_asset(
    old_number: u64,
    new_number: u64,
    release_quantity: u128,
    reserve_claim_before_quantity: u128,
    reserve_claim_after_quantity: u128,
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
    reserve_asset_type: Option<[u8; BYTE32_LEN]>,
    ckb_reserve_claim_before_quantity: u128,
    ckb_reserve_claim_after_quantity: u128,
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let (mut witness_raw, key0, key1) = reduced_exit_witness_raw_with_reserve_asset(
        release_quantity,
        reserve_claim_before_quantity,
        reserve_claim_after_quantity,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        state_header,
        descriptor,
        reserve_asset_type,
        ckb_reserve_claim_before_quantity,
        ckb_reserve_claim_after_quantity,
    );
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0)),
        ([2u8; BYTE32_LEN], pubkey(&key1)),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let participants_commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let witness = FactoryReducedExitWitness::parse(&witness_raw).unwrap();

    let mut old = factory_header_raw(old_number);
    old[76..108].copy_from_slice(&witness.rights_root(false).unwrap());
    old[108..140].copy_from_slice(&participants_commitment);
    old[140..172].copy_from_slice(&witness.access_manifest_root(false).unwrap());
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let old_header = FactoryStateHeader::parse(&old).unwrap();

    let mut new = factory_header_raw(new_number);
    new[270..302].fill(0);
    new[76..108].copy_from_slice(&witness.rights_root(true).unwrap());
    new[108..140].copy_from_slice(&participants_commitment);
    new[140..172].copy_from_slice(&witness.access_manifest_root(true).unwrap());
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);
    let preliminary_new_header = FactoryStateHeader::parse(&new).unwrap();
    let digest = witness
        .non_interference_digest(&old_header, &preliminary_new_header)
        .unwrap();
    new[172..204].copy_from_slice(&digest);
    let new_header = FactoryStateHeader::parse(&new).unwrap();
    sign_reduced_exit_witness(
        &mut witness_raw,
        [1u8; BYTE32_LEN],
        &key0,
        &new_header.signing_digest(),
    );

    (old.to_vec().into(), new.to_vec().into(), witness_raw.into())
}

fn signed_factory_pair_with_exit_digest(
    old_number: u64,
    new_number: u64,
    exit_digest: [u8; 32],
) -> (Bytes, Bytes, Bytes) {
    signed_factory_pair_with_exit_digest_and_vault_roots(
        old_number,
        new_number,
        exit_digest,
        [9u8; BYTE32_LEN],
        [9u8; BYTE32_LEN],
    )
}

fn signed_factory_pair_with_exit_digest_and_vault_roots(
    old_number: u64,
    new_number: u64,
    exit_digest: [u8; 32],
    old_vault_materialisation_root: [u8; BYTE32_LEN],
    new_vault_materialisation_root: [u8; BYTE32_LEN],
) -> (Bytes, Bytes, Bytes) {
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut entries = [
        ([1u8; BYTE32_LEN], pubkey(&key0), key0),
        ([2u8; BYTE32_LEN], pubkey(&key1), key1),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let commitment = factory_participants_commitment(
        2,
        &[
            (entries[0].0.as_slice(), entries[0].1.as_slice()),
            (entries[1].0.as_slice(), entries[1].1.as_slice()),
        ],
    );
    let mut old = factory_header_raw(old_number);
    old[108..140].copy_from_slice(&commitment);
    set_factory_vault_materialisation_root(&mut old, old_vault_materialisation_root);
    let mut new = factory_header_raw(new_number);
    new[270..302].fill(0);
    new[108..140].copy_from_slice(&commitment);
    new[76..108].fill(9);
    new[140..172].fill(10);
    new[172..204].copy_from_slice(&exit_digest);
    set_factory_vault_materialisation_root(&mut new, new_vault_materialisation_root);

    let header = FactoryStateHeader::parse(&new).unwrap();
    let digest = header.signing_digest();
    let mut witness = [0u8; factory_signature_witness_len(2)];
    put_u16(&mut witness, 0, FACTORY_SIGNATURE_WITNESS_VERSION);
    witness[2] = FACTORY_MIN_PARTICIPANTS;
    witness[3] = FACTORY_MIN_PARTICIPANTS;
    for (index, (participant, pubkey, key)) in entries.iter().enumerate() {
        let offset =
            4 + index * (BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        witness[offset..offset + BYTE32_LEN].copy_from_slice(participant);
        witness[offset + BYTE32_LEN..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN]
            .copy_from_slice(pubkey);
        witness[offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN
            ..offset + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN]
            .copy_from_slice(&signature(key, &digest));
    }

    (
        old.to_vec().into(),
        new.to_vec().into(),
        witness.to_vec().into(),
    )
}

#[allow(clippy::too_many_arguments)]
fn factory_local_exit_witness(
    factory_signature: &[u8],
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: [u8; 32],
    vault_lock_hash: [u8; 32],
    state_lock_hash: [u8; 32],
    state_header: &[u8],
    descriptor: &[u8],
) -> Bytes {
    let mut witness = vec![
        0u8;
        factory_local_exit_witness_len(2, BILATERAL_CKB_DESCRIPTOR_LEN)
            - BILATERAL_CKB_DESCRIPTOR_LEN
            + descriptor.len()
    ];
    put_u16(&mut witness, 0, FACTORY_LOCAL_EXIT_WITNESS_VERSION);
    witness[2..2 + factory_signature_witness_len(2)].copy_from_slice(factory_signature);
    let offset = 2 + factory_signature_witness_len(2);
    witness[offset..offset + 4].copy_from_slice(&state_output_index.to_le_bytes());
    witness[offset + 4..offset + 8].copy_from_slice(&vault_output_index.to_le_bytes());
    witness[offset + 8..offset + 8 + BYTE32_LEN].copy_from_slice(&state_type_hash);
    witness[offset + 8 + BYTE32_LEN..offset + 8 + 2 * BYTE32_LEN].copy_from_slice(&vault_lock_hash);
    witness[offset + 8 + 2 * BYTE32_LEN..offset + 8 + 3 * BYTE32_LEN]
        .copy_from_slice(&state_lock_hash);
    witness[offset + 8 + 3 * BYTE32_LEN..offset + 8 + 3 * BYTE32_LEN + STATE_HEADER_LEN]
        .copy_from_slice(state_header);
    witness[offset + 8 + 3 * BYTE32_LEN + STATE_HEADER_LEN..].copy_from_slice(descriptor);
    witness.into()
}

fn witness_with_input_type(input_type: Bytes) -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::new_builder()
        .input_type(Some(input_type).pack())
        .build()
        .as_bytes()
        .pack()
}

fn factory_witness_with_input_type(
    kind: u16,
    body: impl AsRef<[u8]>,
) -> ckb_testtool::ckb_types::packed::Bytes {
    witness_with_input_type(factory_witness_envelope(kind, body.as_ref()).into())
}

fn factory_witness_envelope(kind: u16, body: &[u8]) -> Vec<u8> {
    let body_len: u32 = body
        .len()
        .try_into()
        .expect("factory witness body length fits in u32");
    let mut raw = vec![0u8; WITNESS_ENVELOPE_LEN + body.len()];
    raw[0..WITNESS_ENVELOPE_MAGIC.len()].copy_from_slice(WITNESS_ENVELOPE_MAGIC);
    put_u16(&mut raw, 8, WITNESS_ENVELOPE_FORMAT);
    put_u16(&mut raw, 10, kind);
    put_u16(&mut raw, 12, 0);
    put_u32(&mut raw, 14, body_len);
    raw[18..50].copy_from_slice(&witness_envelope_body_commitment(kind, body));
    raw[WITNESS_ENVELOPE_LEN..].copy_from_slice(body);
    WitnessEnvelope::parse(&raw).expect("factory witness envelope should parse");
    raw
}

fn empty_witness() -> ckb_testtool::ckb_types::packed::Bytes {
    WitnessArgs::default().as_bytes().pack()
}

fn descriptor_bytes(
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
) -> Bytes {
    let mut entries = [
        (left_lock_hash, left_capacity),
        (right_lock_hash, right_capacity),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_DESCRIPTOR_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_DESCRIPTOR_VERSION);
    raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
    raw[3] = 0;
    for (index, (lock_hash, capacity)) in entries.iter().enumerate() {
        let offset = 4 + index * (BYTE32_LEN + 8);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
    }
    raw.to_vec().into()
}

fn ckb_xudt_descriptor_bytes(
    xudt_type_hash: [u8; 32],
    left_lock_hash: [u8; 32],
    left_capacity: u64,
    left_amount: u128,
    right_lock_hash: [u8; 32],
    right_capacity: u64,
    right_amount: u128,
) -> Bytes {
    let mut entries = [
        (left_lock_hash, left_capacity, left_amount),
        (right_lock_hash, right_capacity, right_amount),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut raw = [0u8; BILATERAL_CKB_XUDT_DESCRIPTOR_LEN];
    put_u16(&mut raw, 0, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    raw[2] = BILATERAL_CKB_DESCRIPTOR_OUTPUT_COUNT;
    raw[3] = BILATERAL_CKB_XUDT_DESCRIPTOR_ASSET_COUNT;
    raw[4..36].copy_from_slice(&xudt_type_hash);
    for (index, (lock_hash, capacity, amount)) in entries.iter().enumerate() {
        let offset = 36 + index * (BYTE32_LEN + 8 + 16);
        raw[offset..offset + BYTE32_LEN].copy_from_slice(lock_hash);
        put_u64(&mut raw, offset + BYTE32_LEN, *capacity);
        put_u128(&mut raw, offset + BYTE32_LEN + 8, *amount);
    }
    raw.to_vec().into()
}

fn xudt_amount_data(amount: u128) -> Bytes {
    Bytes::copy_from_slice(&amount.to_le_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultCkbSettlementTamper {
    NonEmptyData,
    TypedOutput,
    TypedVaultInput,
    SplitOutput,
    DescriptorVersionMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultXudtSettlementTamper {
    NonzeroWrongAmountData,
    ZeroRecipientTypedCell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactoryXudtExitTamper {
    None,
    StateFactoryTypeHashMismatch,
    ChildAmountMinusOneWithConservedSupply,
    ChildTypeMismatchWithAuthorisedMint,
    FactoryVaultInputTypeMismatch,
    FactoryVaultChangeAmountMismatch,
    FactoryVaultChangeMissingOnPartial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactoryReducedXudtExitTamper {
    None,
    FullReleaseNoTypedChange,
    ChildAmountMinusOneWithConservedSupply,
    ChildTypeMismatchWithAuthorisedMint,
    ClaimAssetTypeMismatch,
    FactoryVaultChangeAmountMismatch,
    FactoryVaultChangeMissing,
    CapacityMismatch,
    DrainsCkbWithoutClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReducedFactorySpliceTamper {
    None,
    VaultCapacity,
    SparseMerkleSibling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactoryXudtSpliceCapacityTamper {
    None,
    InputCapacity,
    OutputCapacity,
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
fn state_type_accepts_canonical_initial_state() {
    let mut context = Context::default();
    let funding_lock = deploy_always_success(&mut context);
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(2 * CELL_CAPACITY)
            .lock(funding_lock)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let funding_anchor = derived_funding_anchor(&input, 0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(funding_anchor, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let vault_materialisation_root = vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]);
    let (initial_data, signature_witness) =
        signed_initial_state_header(funding_anchor, vault_materialisation_root);

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let vault_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(vault_lock)
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output(vault_output)
        .output_data(initial_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(signature_witness))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("canonical initial state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_signed_unknown_protocol_profile() {
    let mut context = Context::default();
    let funding_lock = deploy_always_success(&mut context);
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(2 * CELL_CAPACITY)
            .lock(funding_lock)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let funding_anchor = derived_funding_anchor(&input, 0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(funding_anchor, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let vault_materialisation_root = vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]);
    let (initial_data, signature_witness) = signed_initial_state_header_with_mutation(
        funding_anchor,
        vault_materialisation_root,
        |raw| put_u16(raw, 0, 2),
    );

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let vault_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(vault_lock)
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output(vault_output)
        .output_data(initial_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(signature_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_unsigned_initial_state() {
    let mut context = Context::default();
    let funding_lock = deploy_always_success(&mut context);
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(2 * CELL_CAPACITY)
            .lock(funding_lock)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let funding_anchor = derived_funding_anchor(&input, 0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(funding_anchor, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let vault_materialisation_root = vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]);
    let (initial_data, _) = signed_initial_state_header(funding_anchor, vault_materialisation_root);
    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let vault_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(vault_lock)
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output(vault_output)
        .output_data(initial_data.pack())
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_initial_state_without_committed_vault() {
    let mut context = Context::default();
    let funding_lock = deploy_always_success(&mut context);
    let absent_vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(funding_lock)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let funding_anchor = derived_funding_anchor(&input, 0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(funding_anchor, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let absent_vault_root = vault_commitment(&absent_vault_lock, CELL_CAPACITY, None, &[]);
    let (initial_data, signature_witness) =
        signed_initial_state_header(funding_anchor, absent_vault_root);
    let state_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(state_output)
        .output_data(initial_data.pack())
        .witness(witness_with_input_type(signature_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_initial_state_with_ambiguous_committed_vault() {
    let mut context = Context::default();
    let funding_lock = deploy_always_success(&mut context);
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(3 * CELL_CAPACITY)
            .lock(funding_lock)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let funding_anchor = derived_funding_anchor(&input, 0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(funding_anchor, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let vault_root = vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]);
    let (initial_data, signature_witness) = signed_initial_state_header(funding_anchor, vault_root);
    let state_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let vault_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(vault_lock)
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(state_output)
        .output(vault_output.clone())
        .output(vault_output)
        .output_data(initial_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(signature_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn state_vault_activation_tx(
    committed_vault_out_point: ckb_testtool::ckb_types::packed::OutPoint,
    actual_vault_out_point: ckb_testtool::ckb_types::packed::OutPoint,
    drift_output_lock: bool,
    drift_carrier_capacity: bool,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(FUNDING_ANCHOR, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let vault_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(vault_lock.clone())
        .build();
    let vault_root = vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]);
    let mut old_data = header_raw(0, PHASE_ACTIVE);
    set_state_vault_materialisation_root(&mut old_data, vault_root);
    old_data[314..346].fill(0);
    let mut new_data = old_data;
    set_state_vault_outpoint(&mut new_data, &committed_vault_out_point);

    let state_out_point = test_out_point(77, 0);
    context.create_cell_with_out_point(
        state_out_point.clone(),
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        Bytes::copy_from_slice(&old_data),
    );
    context.create_cell_with_out_point(actual_vault_out_point.clone(), vault_output, Bytes::new());
    let output_lock = if drift_output_lock {
        deploy_always_success_with_args(&mut context, Bytes::from(vec![10]))
    } else {
        state_lock
    };
    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(actual_vault_out_point)
                .build(),
        )
        .input(CellInput::new(state_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(
                    CELL_CAPACITY
                        - STATE_CARRIER_ACTIVATION_FEE
                        - u64::from(drift_carrier_capacity),
                )
                .lock(output_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output_data(Bytes::copy_from_slice(&new_data).pack())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_accepts_exact_sibling_vault_activation() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) =
        state_vault_activation_tx(vault_out_point.clone(), vault_out_point, false, false);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("exact sibling VaultCell activation should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_byte_identical_clone_vault_activation() {
    let (context, tx) = state_vault_activation_tx(
        fixture_vault_out_point(),
        test_out_point(88, 1),
        false,
        false,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_vault_activation_lock_drift() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) =
        state_vault_activation_tx(vault_out_point.clone(), vault_out_point, true, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_vault_activation_carrier_drain() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) =
        state_vault_activation_tx(vault_out_point.clone(), vault_out_point, false, true);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_initial_state_with_non_canonical_anchor() {
    let mut context = Context::default();
    let funding_lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(funding_lock)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let mut wrong_anchor = derived_funding_anchor(&input, 0);
    wrong_anchor[0] ^= 1;
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        state_args_with_anchor(wrong_anchor, 0),
    );
    let state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(state_type.calc_script_hash().as_slice().to_vec()),
    );
    let initial_data = Bytes::from(header_raw_with_anchor(0, PHASE_ACTIVE, wrong_anchor).to_vec());

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(state_lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(initial_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_canonical_initial_factory_state() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);

    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let factory_id = derived_factory_id(&input, 0);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", factory_id.to_vec());
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = factory_id.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let factory_state_capacity = CELL_CAPACITY / 2;
    let factory_vault_capacity = CELL_CAPACITY - factory_state_capacity;
    let vault_root = vault_commitment(&factory_vault_lock, factory_vault_capacity, None, &[]);
    let (initial_data, signature_witness) = signed_initial_factory_header(factory_id, vault_root);

    let output = CellOutput::new_builder()
        .capacity(factory_state_capacity)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let vault_output = CellOutput::new_builder()
        .capacity(factory_vault_capacity)
        .lock(factory_vault_lock)
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output(vault_output)
        .output_data(initial_data.pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            signature_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("canonical initial factory state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_three_party_dynamic_initial_state() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let factory_id = derived_factory_id(&input, 0);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", factory_id.to_vec());
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = factory_id.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let factory_state_capacity = CELL_CAPACITY / 2;
    let factory_vault_capacity = CELL_CAPACITY - factory_state_capacity;
    let vault_root = vault_commitment(&factory_vault_lock, factory_vault_capacity, None, &[]);
    let (initial_data, signature_witness) =
        signed_dynamic_initial_factory_header(factory_id, vault_root);
    let tx = TransactionBuilder::default()
        .input(input)
        .output(
            CellOutput::new_builder()
                .capacity(factory_state_capacity)
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_capacity)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(initial_data.pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            signature_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("three-party dynamic initial factory state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_unsigned_initial_factory_state() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let factory_id = derived_factory_id(&input, 0);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", factory_id.to_vec());
    let (initial_data, _) = signed_initial_factory_header(factory_id, [9u8; BYTE32_LEN]);
    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(initial_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn factory_creation_tx(
    vault_output_count: usize,
    commit_actual_vault: bool,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let owner_lock = deploy_always_success(&mut context);
    let funding_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(owner_lock.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(funding_out_point)
        .build();
    let factory_id = derived_factory_id(&input, 0);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", factory_id.to_vec());
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = factory_id.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let factory_state_capacity = CELL_CAPACITY / 2;
    let vault_capacity = if vault_output_count == 0 {
        0
    } else {
        (CELL_CAPACITY - factory_state_capacity) / vault_output_count as u64
    };
    let vault_root = if commit_actual_vault && vault_output_count > 0 {
        vault_commitment(&factory_vault_lock, vault_capacity, None, &[])
    } else {
        [0xabu8; BYTE32_LEN]
    };
    let (initial_data, signature_witness) = signed_initial_factory_header(factory_id, vault_root);
    let factory_output = CellOutput::new_builder()
        .capacity(factory_state_capacity)
        .lock(owner_lock)
        .type_(Some(factory_type).pack())
        .build();
    let mut builder = TransactionBuilder::default()
        .input(input)
        .output(factory_output)
        .output_data(initial_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            signature_witness,
        ));
    for _ in 0..vault_output_count {
        builder = builder
            .output(
                CellOutput::new_builder()
                    .capacity(vault_capacity)
                    .lock(factory_vault_lock.clone())
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }
    let tx = context.complete_tx(builder.build());
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_initial_state_without_committed_factory_vault() {
    let (context, tx) = factory_creation_tx(0, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_initial_state_with_wrong_factory_vault_commitment() {
    let (context, tx) = factory_creation_tx(1, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_initial_state_with_ambiguous_factory_vaults() {
    let (context, tx) = factory_creation_tx(2, true);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn factory_vault_activation_tx(
    committed_vault_out_point: ckb_testtool::ckb_types::packed::OutPoint,
    actual_vault_out_point: ckb_testtool::ckb_types::packed::OutPoint,
    drift_output_lock: bool,
    prefix_dummy_dep: bool,
    drift_carrier_capacity: bool,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let owner_lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; BYTE32_LEN] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_always_success_with_args(&mut context, Bytes::from(factory_vault_args));
    let vault_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(factory_vault_lock.clone())
        .build();
    let vault_root = vault_commitment(&factory_vault_lock, CELL_CAPACITY, None, &[]);
    let mut old_data = factory_header_raw(0);
    set_factory_vault_materialisation_root(&mut old_data, vault_root);
    old_data[270..302].fill(0);
    let mut new_data = old_data;
    set_factory_vault_outpoint(&mut new_data, &committed_vault_out_point);

    let factory_out_point = test_out_point(77, 0);
    context.create_cell_with_out_point(
        factory_out_point.clone(),
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(owner_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        Bytes::copy_from_slice(&old_data),
    );
    context.create_cell_with_out_point(actual_vault_out_point.clone(), vault_output, Bytes::new());
    let output_lock = if drift_output_lock {
        deploy_always_success_with_args(&mut context, Bytes::from(vec![10]))
    } else {
        owner_lock
    };
    let dummy_dep = if prefix_dummy_dep {
        let dummy_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![11]));
        Some(
            context.create_cell(
                CellOutput::new_builder()
                    .capacity(CELL_CAPACITY)
                    .lock(dummy_lock)
                    .build(),
                Bytes::new(),
            ),
        )
    } else {
        None
    };
    let mut builder = TransactionBuilder::default();
    if let Some(dummy_dep) = dummy_dep {
        builder = builder.cell_dep(CellDep::new_builder().out_point(dummy_dep).build());
    }
    let tx = builder
        .cell_dep(
            CellDep::new_builder()
                .out_point(actual_vault_out_point)
                .build(),
        )
        .input(CellInput::new(factory_out_point, 0))
        .output(
            CellOutput::new_builder()
                .capacity(
                    CELL_CAPACITY
                        - STATE_CARRIER_ACTIVATION_FEE
                        - u64::from(drift_carrier_capacity),
                )
                .lock(output_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(Bytes::copy_from_slice(&new_data).pack())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_exact_sibling_vault_activation() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) = factory_vault_activation_tx(
        vault_out_point.clone(),
        vault_out_point,
        false,
        false,
        false,
    );
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("exact sibling FactoryVaultCell activation should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_byte_identical_clone_vault_activation() {
    let (context, tx) = factory_vault_activation_tx(
        fixture_vault_out_point(),
        test_out_point(88, 1),
        false,
        false,
        false,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_vault_activation_lock_drift() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) =
        factory_vault_activation_tx(vault_out_point.clone(), vault_out_point, true, false, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_noncanonical_vault_activation_dep_position() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) =
        factory_vault_activation_tx(vault_out_point.clone(), vault_out_point, false, true, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_vault_activation_carrier_drain() {
    let vault_out_point = fixture_vault_out_point();
    let (context, tx) =
        factory_vault_activation_tx(vault_out_point.clone(), vault_out_point, false, false, true);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_signed_factory_update() {
    let (context, tx) = signed_factory_update_tx(CELL_CAPACITY);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_three_party_dynamic_factory_update() {
    let (context, tx) = dynamic_factory_update_tx(false);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("three-party dynamic factory update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_three_party_dynamic_factory_update_with_bad_signature() {
    let (context, tx) = dynamic_factory_update_tx(true);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn dynamic_factory_update_tx(tamper_last_signature: bool) -> (Context, TransactionView) {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) =
        signed_dynamic_factory_pair(1, 2, tamper_last_signature);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            sig_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_signed_factory_update_carrier_drain() {
    let (context, tx) = signed_factory_update_tx(CELL_CAPACITY - 1);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn signed_factory_update_tx(output_capacity: u64) -> (Context, TransactionView) {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) = signed_factory_pair(1, 2);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(output_capacity)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            sig_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_signed_ordinary_update_with_factory_vault_root_drift() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) =
        signed_factory_pair_with_vault_roots(1, 2, [9u8; BYTE32_LEN], [10u8; BYTE32_LEN]);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            sig_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_factory_splice_in() {
    let (context, tx) = factory_splice_ckb_tx(false);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_three_party_dynamic_factory_splice_in() {
    let (context, tx) =
        factory_splice_ckb_tx_with_carrier(false, STATE_CARRIER_ACTIVATION_FEE, true);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("three-party dynamic factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_splice_without_carrier_activation_reserve() {
    let (context, tx) = factory_splice_ckb_tx_with_carrier(false, 0, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_factory_splice_capacity_mismatch() {
    let (context, tx) = factory_splice_ckb_tx(true);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_factory_xudt_splice_in() {
    let (context, tx) = factory_xudt_splice_tx(false, FactoryXudtSpliceCapacityTamper::None);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("xUDT factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_accepts_dual_asset_ckb_xudt_splice_in() {
    let (context, tx) = factory_dual_asset_splice_tx();

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("dual-asset factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_factory_xudt_splice_output_capacity_mismatch() {
    let (context, tx) =
        factory_xudt_splice_tx(false, FactoryXudtSpliceCapacityTamper::OutputCapacity);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_factory_xudt_splice_input_capacity_mismatch() {
    let (context, tx) =
        factory_xudt_splice_tx(false, FactoryXudtSpliceCapacityTamper::InputCapacity);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_factory_splice_in() {
    let (context, tx) = factory_reduced_splice_ckb_tx(ReducedFactorySpliceTamper::None);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_factory_splice_out() {
    let (context, tx) = factory_reduced_splice_out_tx(false, false);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory splice-out should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_splice_out_with_substituted_withdrawal_lock() {
    let (context, tx) = factory_reduced_splice_out_tx(true, false);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_splice_out_with_typed_ckb_withdrawal() {
    let (context, tx) = factory_reduced_splice_out_tx(false, true);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_three_party_dynamic_reduced_factory_splice_in() {
    let (context, tx) =
        factory_reduced_splice_ckb_tx_with_mode(ReducedFactorySpliceTamper::None, true);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("three-party dynamic reduced factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_factory_splice_sparse_merkle_tamper() {
    let (context, tx) =
        factory_reduced_splice_ckb_tx(ReducedFactorySpliceTamper::SparseMerkleSibling);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_factory_splice_capacity_mismatch() {
    let (context, tx) = factory_reduced_splice_ckb_tx(ReducedFactorySpliceTamper::VaultCapacity);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_factory_xudt_splice_in() {
    let (context, tx) = factory_xudt_splice_tx(true, FactoryXudtSpliceCapacityTamper::None);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced xUDT factory splice-in should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_factory_xudt_splice_output_capacity_mismatch() {
    let (context, tx) =
        factory_xudt_splice_tx(true, FactoryXudtSpliceCapacityTamper::OutputCapacity);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_factory_xudt_splice_input_capacity_mismatch() {
    let (context, tx) =
        factory_xudt_splice_tx(true, FactoryXudtSpliceCapacityTamper::InputCapacity);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_reduced_rights_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, reduced_witness) = signed_reduced_factory_rights_pair(1, 2, 90);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS,
            reduced_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory rights update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_three_party_dynamic_reduced_rights_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) = signed_dynamic_reduced_factory_rights_pair(1, 2, 90);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("three-party dynamic reduced-rights update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_sparse_merkle_right_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, merkle_witness) = signed_factory_merkle_update_pair(1, 2);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE,
            merkle_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("sparse Merkle factory right update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_three_party_dynamic_sparse_merkle_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) = signed_dynamic_factory_merkle_update_pair(1, 2);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("three-party dynamic sparse-Merkle update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_sparse_merkle_right_increase() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, merkle_witness) =
        signed_factory_merkle_update_pair_with_quantity(1, 2, 1_001);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE,
            merkle_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_sparse_merkle_sibling_tamper() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, merkle_witness) = signed_factory_merkle_update_pair(1, 2);
    let mut merkle_witness = merkle_witness.to_vec();
    merkle_witness[merkle_sibling_offset(42)] ^= 1;

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE,
            merkle_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_accepts_multi_right_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) = signed_multi_right_update_pair(1, 2);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("multi-right factory update should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_multi_right_total_increase() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) =
        signed_multi_right_update_pair_with_quantities(1, 2, 1_500, 250, None);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_multi_right_cross_asset_rebalance() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) = signed_multi_right_update_pair_with_assets(
        1,
        2,
        0,
        1_250,
        None,
        Some(([41u8; BYTE32_LEN], [42u8; BYTE32_LEN])),
    );

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_multi_right_compact_pair_tamper() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) = signed_multi_right_update_pair(1, 2);
    let mut witness = witness.to_vec();
    witness[multi_right_proof_offset(2, false, 0) + 2 + 2] ^= 1;

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_multi_right_unlisted_change() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) =
        signed_multi_right_update_pair_with_quantities(1, 2, 700, 300, Some(1_000));

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[test]
#[ignore = "requires `make build-contracts`"]
fn factory_type_rejects_multi_right_foreign_signature() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, witness) = signed_multi_right_update_pair(1, 2);
    let mut witness = witness.to_vec();
    let key1 = signing_key(2);
    let new_data_vec = new_data.to_vec();
    let new_header = FactoryStateHeader::parse(&new_data_vec).unwrap();
    let foreign_signature = signature(&key1, &new_header.signing_digest());
    let touched_signature_offset = 8 + BYTE32_LEN + COMPRESSED_SECP256K1_PUBKEY_LEN + 1;
    witness[touched_signature_offset..touched_signature_offset + ECDSA_SIGNATURE_LEN]
        .copy_from_slice(&foreign_signature);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
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
                .lock(lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
            witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_rights_increase() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, reduced_witness) = signed_reduced_factory_rights_pair(1, 2, 110);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS,
            reduced_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_equal_update_number() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) = signed_factory_pair(2, 2);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            sig_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_invalid_participant_signature() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let (old_data, new_data, sig_witness) = signed_factory_pair(1, 2);
    let mut sig_witness = sig_witness.to_vec();
    let last = sig_witness.len() - 1;
    sig_witness[last] ^= 1;

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(factory_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
            sig_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn factory_splice_ckb_tx(tamper_capacity: bool) -> (Context, TransactionView) {
    factory_splice_ckb_tx_with_carrier(tamper_capacity, STATE_CARRIER_ACTIVATION_FEE, false)
}

fn factory_splice_ckb_tx_with_carrier(
    tamper_capacity: bool,
    carrier_activation_reserve: u64,
    dynamic: bool,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let external_input_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let old_reserve = 200_000_000_000u64;
    let splice_amount = 20_000_000_000u64;
    let new_reserve = old_reserve + splice_amount;
    let old_vault_root = vault_commitment(&factory_vault_lock, old_reserve, None, &[]);
    let new_vault_root = vault_commitment(&factory_vault_lock, new_reserve, None, &[]);
    let (old_factory_data, new_factory_data, splice_witness) = if dynamic {
        signed_dynamic_factory_splice_pair(
            old_reserve as u128,
            new_reserve as u128,
            splice_amount as u128,
            0,
            old_vault_root,
            new_vault_root,
            [0u8; BYTE32_LEN],
        )
    } else {
        signed_factory_splice_pair(
            old_reserve as u128,
            new_reserve as u128,
            splice_amount as u128,
            0,
            old_vault_root,
            new_vault_root,
            [0u8; BYTE32_LEN],
        )
    };
    let witness_kind = WITNESS_ENVELOPE_KIND_FACTORY_SPLICE;

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(old_reserve)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let external_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(external_input_lock.clone())
            .build(),
        Bytes::new(),
    );

    let output_reserve = if tamper_capacity {
        new_reserve - 1
    } else {
        new_reserve
    };
    let change_capacity = CELL_CAPACITY - splice_amount - STATE_CARRIER_ACTIVATION_FEE;
    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(external_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + carrier_activation_reserve)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(output_reserve)
                .lock(factory_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(external_input_lock)
                .build(),
        )
        .output_data(new_factory_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            witness_kind,
            &splice_witness,
        ))
        .witness(factory_witness_with_input_type(
            witness_kind,
            splice_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

fn factory_reduced_splice_ckb_tx(tamper: ReducedFactorySpliceTamper) -> (Context, TransactionView) {
    factory_reduced_splice_ckb_tx_with_mode(tamper, false)
}

fn factory_reduced_splice_ckb_tx_with_mode(
    tamper: ReducedFactorySpliceTamper,
    dynamic: bool,
) -> (Context, TransactionView) {
    factory_reduced_splice_ckb_tx_with_options(tamper, dynamic, false, false, false)
}

fn factory_reduced_splice_out_tx(
    substitute_withdrawal: bool,
    type_lock_withdrawal: bool,
) -> (Context, TransactionView) {
    factory_reduced_splice_ckb_tx_with_options(
        ReducedFactorySpliceTamper::None,
        false,
        true,
        substitute_withdrawal,
        type_lock_withdrawal,
    )
}

fn factory_reduced_splice_ckb_tx_with_options(
    tamper: ReducedFactorySpliceTamper,
    dynamic: bool,
    splice_out: bool,
    substitute_withdrawal: bool,
    type_lock_withdrawal: bool,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let external_input_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let signed_withdrawal_lock =
        deploy_always_success_with_args(&mut context, Bytes::from(vec![10]));
    let withdrawal_lock = if substitute_withdrawal {
        deploy_always_success_with_args(&mut context, Bytes::from(vec![11]))
    } else {
        signed_withdrawal_lock.clone()
    };
    let withdrawal_type = if type_lock_withdrawal {
        Some(deploy_always_success_with_args(
            &mut context,
            Bytes::from(vec![12]),
        ))
    } else {
        None
    };

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let old_reserve = 200_000_000_000u64;
    let splice_amount = 20_000_000_000u64;
    let new_reserve = if splice_out {
        old_reserve - splice_amount
    } else {
        old_reserve + splice_amount
    };
    let external_input = if splice_out { 0 } else { splice_amount };
    let withdrawal = if splice_out { splice_amount } else { 0 };
    let withdrawal_lock_hash = if splice_out {
        signed_withdrawal_lock.calc_script_hash().unpack()
    } else {
        [0u8; BYTE32_LEN]
    };
    let old_vault_root = vault_commitment(&factory_vault_lock, old_reserve, None, &[]);
    let new_vault_root = vault_commitment(&factory_vault_lock, new_reserve, None, &[]);
    let (old_factory_data, new_factory_data, splice_witness) = if dynamic {
        signed_dynamic_factory_reduced_splice_pair(
            old_reserve as u128,
            new_reserve as u128,
            external_input as u128,
            withdrawal as u128,
            old_vault_root,
            new_vault_root,
            withdrawal_lock_hash,
        )
    } else {
        signed_factory_reduced_splice_pair(
            old_reserve as u128,
            new_reserve as u128,
            external_input as u128,
            withdrawal as u128,
            old_vault_root,
            new_vault_root,
            withdrawal_lock_hash,
        )
    };
    let mut splice_witness = splice_witness.to_vec();
    if tamper == ReducedFactorySpliceTamper::SparseMerkleSibling {
        let sibling_offset = if dynamic {
            2 + FACTORY_SPLICE_HEADER_LEN
                + 8
                + 3 * FACTORY_REDUCED_RIGHTS_PARTICIPANT_ENTRY_LEN
                + BYTE32_LEN
                + 2 * FACTORY_RIGHT_LEN
                + 42 * BYTE32_LEN
        } else {
            reduced_splice_merkle_offset() + merkle_sibling_offset(42)
        };
        splice_witness[sibling_offset] ^= 1;
    }
    let splice_witness: Bytes = splice_witness.into();
    let witness_kind = WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE;

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(old_reserve)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let external_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(external_input_lock.clone())
            .build(),
        Bytes::new(),
    );

    let output_reserve = if tamper == ReducedFactorySpliceTamper::VaultCapacity {
        new_reserve - 1
    } else {
        new_reserve
    };
    let change_capacity = if splice_out {
        CELL_CAPACITY - STATE_CARRIER_ACTIVATION_FEE
    } else {
        CELL_CAPACITY - splice_amount - STATE_CARRIER_ACTIVATION_FEE
    };
    let mut tx_builder = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(external_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(output_reserve)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_factory_data.pack())
        .output_data(Bytes::new().pack());
    if splice_out {
        tx_builder = tx_builder
            .output(
                CellOutput::new_builder()
                    .capacity(splice_amount)
                    .lock(withdrawal_lock)
                    .type_(withdrawal_type.pack())
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }
    let tx = tx_builder
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(external_input_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            witness_kind,
            &splice_witness,
        ))
        .witness(factory_witness_with_input_type(
            witness_kind,
            splice_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

fn factory_xudt_splice_tx(
    reduced: bool,
    tamper: FactoryXudtSpliceCapacityTamper,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let external_input_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![10]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();

    let descriptor_ckb_amount = 300_000_000_000u64;
    let old_xudt_amount = 100u128;
    let splice_xudt_amount = 40u128;
    let new_xudt_amount = old_xudt_amount + splice_xudt_amount;
    let old_vault_root = vault_commitment(
        &factory_vault_lock,
        descriptor_ckb_amount,
        Some(xudt_type_hash),
        &xudt_amount_data(old_xudt_amount),
    );
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        descriptor_ckb_amount,
        Some(xudt_type_hash),
        &xudt_amount_data(new_xudt_amount),
    );
    let (old_factory_data, new_factory_data, splice_witness) = if reduced {
        signed_factory_reduced_xudt_splice_pair(
            descriptor_ckb_amount as u128,
            old_xudt_amount,
            new_xudt_amount,
            xudt_type_hash,
            splice_xudt_amount,
            0,
            old_vault_root,
            new_vault_root,
        )
    } else {
        signed_factory_xudt_splice_pair(
            descriptor_ckb_amount as u128,
            old_xudt_amount,
            new_xudt_amount,
            xudt_type_hash,
            splice_xudt_amount,
            0,
            old_vault_root,
            new_vault_root,
        )
    };

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let input_capacity = match tamper {
        FactoryXudtSpliceCapacityTamper::InputCapacity => descriptor_ckb_amount - 1,
        _ => descriptor_ckb_amount,
    };
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(input_capacity)
            .lock(factory_vault_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(old_xudt_amount),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let external_input_capacity = CELL_CAPACITY;
    let external_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(external_input_capacity)
            .lock(external_input_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(splice_xudt_amount),
    );

    let output_capacity = match tamper {
        FactoryXudtSpliceCapacityTamper::OutputCapacity => descriptor_ckb_amount - 1,
        _ => descriptor_ckb_amount,
    };
    let change_capacity =
        input_capacity + external_input_capacity - output_capacity - STATE_CARRIER_ACTIVATION_FEE;
    let witness_kind = if reduced {
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE
    } else {
        WITNESS_ENVELOPE_KIND_FACTORY_SPLICE
    };
    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(external_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(output_capacity)
                .lock(factory_vault_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(external_input_lock)
                .build(),
        )
        .output_data(new_factory_data.pack())
        .output_data(xudt_amount_data(new_xudt_amount).pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            witness_kind,
            &splice_witness,
        ))
        .witness(factory_witness_with_input_type(
            witness_kind,
            splice_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

fn factory_dual_asset_splice_tx() -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let external_input_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![10]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();

    let old_ckb_amount = 300_000_000_000u64;
    let ckb_splice_amount = 20_000_000_000u64;
    let new_ckb_amount = old_ckb_amount + ckb_splice_amount;
    let old_xudt_amount = 100u128;
    let xudt_splice_amount = 40u128;
    let new_xudt_amount = old_xudt_amount + xudt_splice_amount;
    let old_vault_root = vault_commitment(
        &factory_vault_lock,
        old_ckb_amount,
        Some(xudt_type_hash),
        &xudt_amount_data(old_xudt_amount),
    );
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        new_ckb_amount,
        Some(xudt_type_hash),
        &xudt_amount_data(new_xudt_amount),
    );
    let (old_factory_data, new_factory_data, splice_witness) =
        signed_factory_dual_asset_splice_pair(
            old_ckb_amount as u128,
            new_ckb_amount as u128,
            old_xudt_amount,
            new_xudt_amount,
            xudt_type_hash,
            ckb_splice_amount as u128,
            xudt_splice_amount,
            old_vault_root,
            new_vault_root,
        );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(old_ckb_amount)
            .lock(factory_vault_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(old_xudt_amount),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let external_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(external_input_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(xudt_splice_amount),
    );

    let change_capacity =
        old_ckb_amount + CELL_CAPACITY - new_ckb_amount - STATE_CARRIER_ACTIVATION_FEE;
    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(external_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(new_ckb_amount)
                .lock(factory_vault_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(change_capacity)
                .lock(external_input_lock)
                .build(),
        )
        .output_data(new_factory_data.pack())
        .output_data(xudt_amount_data(new_xudt_amount).pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SPLICE,
            &splice_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_SPLICE,
            splice_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_exit_reserve_release() {
    let mut context = Context::default();
    let reserve_owner_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let factory_lock =
        deploy_contract(&mut context, "morph-state-lock", factory_type_hash.to_vec());
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let released_capacity = ALICE_CAPACITY + BOB_CAPACITY;
    let reserve_claim_before_quantity = released_capacity as u128;
    let factory_vault_input_capacity = 300_000_000_000u64;
    let factory_vault_change_capacity = factory_vault_input_capacity - released_capacity;
    let old_vault_root =
        vault_commitment(&factory_vault_lock, factory_vault_input_capacity, None, &[]);
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        factory_vault_change_capacity,
        None,
        &[],
    );
    let old_factory_data =
        reduced_exit_old_factory_data(1, reserve_claim_before_quantity, old_vault_root);

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data.clone(),
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(factory_vault_input_capacity)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_owner_lock)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    set_state_vault_materialisation_root(
        &mut child_state,
        vault_commitment(&vault_lock, released_capacity, None, &[]),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[150..182].copy_from_slice(&participants_commitment(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let (expected_old_data, new_data, reduced_witness) = signed_reduced_factory_exit_pair(
        1,
        2,
        reserve_claim_before_quantity,
        reserve_claim_before_quantity,
        0,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
        old_vault_root,
        new_vault_root,
    );
    assert_eq!(old_factory_data, expected_old_data);

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(released_capacity)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_change_capacity)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
            &reduced_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
            reduced_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("reduced factory exit should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_typed_claim_for_ckb_release() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_owner_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let released_capacity = ALICE_CAPACITY + BOB_CAPACITY;
    let reserve_asset_type = [7u8; BYTE32_LEN];
    let reserve_claim_before_quantity = released_capacity as u128;
    let factory_vault_input_capacity = 300_000_000_000u64;
    let factory_vault_change_capacity = factory_vault_input_capacity - released_capacity;
    let old_vault_root =
        vault_commitment(&factory_vault_lock, factory_vault_input_capacity, None, &[]);
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        factory_vault_change_capacity,
        None,
        &[],
    );
    let old_factory_data = reduced_exit_old_factory_data_with_reserve_asset(
        1,
        reserve_claim_before_quantity,
        Some(reserve_asset_type),
        100,
        100,
        old_vault_root,
    );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data.clone(),
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(factory_vault_input_capacity)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_owner_lock)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    set_state_vault_materialisation_root(
        &mut child_state,
        vault_commitment(&vault_lock, released_capacity, None, &[]),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[150..182].copy_from_slice(&participants_commitment(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let (expected_old_data, new_data, reduced_witness) =
        signed_reduced_factory_exit_pair_with_reserve_asset(
            1,
            2,
            reserve_claim_before_quantity,
            reserve_claim_before_quantity,
            0,
            state_output_index,
            vault_output_index,
            state_type_hash,
            vault_lock_hash,
            state_lock_hash,
            &child_state,
            &descriptor,
            Some(reserve_asset_type),
            100,
            100,
            old_vault_root,
            new_vault_root,
        );
    assert_eq!(old_factory_data, expected_old_data);

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(released_capacity)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_change_capacity)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
            &reduced_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
            reduced_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[test]
fn reduced_exit_xudt_witness_parses_with_typed_claim() {
    let xudt_type_hash = [9u8; 32];
    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        [1u8; 32],
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        [2u8; 32],
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let release_quantity = ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT;
    let mut child_state = header_raw(0, PHASE_ACTIVE);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    put_u16(&mut child_state, 246, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    let (witness, _, _) = reduced_exit_witness_raw_with_reserve_asset(
        release_quantity,
        release_quantity + 1,
        1,
        1,
        2,
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        &child_state,
        &descriptor,
        Some(xudt_type_hash),
        100,
        100,
    );
    assert_eq!(
        witness.len(),
        factory_reduced_exit_witness_len(2, BILATERAL_CKB_XUDT_DESCRIPTOR_LEN)
    );
    let witness = FactoryReducedExitWitness::parse(&witness).unwrap();
    assert_eq!(
        witness.settlement_descriptor().len(),
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN
    );
    assert_eq!(witness.release_quantity(), release_quantity);
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_exit_xudt_reserve_release() {
    let (context, tx) = factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::None);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("xUDT reduced factory exit should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_reduced_exit_xudt_full_release_without_typed_change() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::FullReleaseNoTypedChange);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("full xUDT reduced factory exit should verify with CKB-only factory change");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_amount_mismatch() {
    let (context, tx) = factory_reduced_xudt_exit_tx(
        FactoryReducedXudtExitTamper::ChildAmountMinusOneWithConservedSupply,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_type_mismatch() {
    let (context, tx) = factory_reduced_xudt_exit_tx(
        FactoryReducedXudtExitTamper::ChildTypeMismatchWithAuthorisedMint,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_claim_asset_type_mismatch() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::ClaimAssetTypeMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_exit_xudt_change_amount_mismatch() {
    let (context, tx) = factory_reduced_xudt_exit_tx(
        FactoryReducedXudtExitTamper::FactoryVaultChangeAmountMismatch,
    );
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_reduced_exit_xudt_missing_typed_change() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::FactoryVaultChangeMissing);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_capacity_mismatch() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::CapacityMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_reduced_exit_xudt_ckb_drain_without_claim() {
    let (context, tx) =
        factory_reduced_xudt_exit_tx(FactoryReducedXudtExitTamper::DrainsCkbWithoutClaim);
    assert!(
        context.verify_tx(&tx, MAX_CYCLES).is_err(),
        "xUDT reduced-exit must reject when descriptor total_capacity exceeds the touched participant's CKB reserve claim"
    );
}

fn factory_reduced_xudt_exit_tx(
    tamper: FactoryReducedXudtExitTamper,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_owner_lock = deploy_always_success(&mut context);
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
    let wrong_xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        factory_lock.calc_script_hash().as_slice().to_vec(),
    );

    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let released_xudt_amount = ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT;
    let factory_vault_xudt_surplus = match tamper {
        FactoryReducedXudtExitTamper::FullReleaseNoTypedChange => 0,
        _ => 40u128,
    };
    let reserve_claim_before_quantity = released_xudt_amount + factory_vault_xudt_surplus;
    let reserve_claim_after_quantity = factory_vault_xudt_surplus;
    let reserve_asset_type = match tamper {
        FactoryReducedXudtExitTamper::ClaimAssetTypeMismatch => [8u8; BYTE32_LEN],
        _ => xudt_type_hash,
    };
    let child_vault_capacity_for_claim = (ALICE_CAPACITY + BOB_CAPACITY) as u128;
    let ckb_reserve_claim_before_quantity = match tamper {
        FactoryReducedXudtExitTamper::DrainsCkbWithoutClaim => child_vault_capacity_for_claim - 1,
        _ => child_vault_capacity_for_claim,
    };
    let ckb_reserve_claim_after_quantity = 0;
    let factory_vault_input_capacity = 300_000_000_000u64;
    let expected_factory_vault_change_capacity =
        factory_vault_input_capacity - (ALICE_CAPACITY + BOB_CAPACITY);
    let old_vault_root = vault_commitment(
        &factory_vault_lock,
        factory_vault_input_capacity,
        Some(xudt_type_hash),
        &xudt_amount_data(reserve_claim_before_quantity),
    );
    let (expected_change_type, expected_change_data) = if factory_vault_xudt_surplus > 0 {
        (
            Some(xudt_type_hash),
            xudt_amount_data(factory_vault_xudt_surplus),
        )
    } else {
        (None, Bytes::new())
    };
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        expected_factory_vault_change_capacity,
        expected_change_type,
        expected_change_data.as_ref(),
    );
    let old_factory_data = reduced_exit_old_factory_data_with_reserve_asset(
        1,
        reserve_claim_before_quantity,
        Some(reserve_asset_type),
        ckb_reserve_claim_before_quantity,
        ckb_reserve_claim_after_quantity,
        old_vault_root,
    );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data.clone(),
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(factory_vault_input_capacity)
            .lock(factory_vault_lock.clone())
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        xudt_amount_data(reserve_claim_before_quantity),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_owner_lock)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let child_vault_capacity = ALICE_CAPACITY + BOB_CAPACITY;
    let child_vault_data = xudt_amount_data(released_xudt_amount);
    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    put_u16(&mut child_state, 246, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    set_state_vault_materialisation_root(
        &mut child_state,
        vault_commitment(
            &vault_lock,
            child_vault_capacity,
            Some(xudt_type_hash),
            child_vault_data.as_ref(),
        ),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[150..182].copy_from_slice(&participants_commitment(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let (expected_old_data, new_data, reduced_witness) =
        signed_reduced_factory_exit_pair_with_reserve_asset(
            1,
            2,
            released_xudt_amount,
            reserve_claim_before_quantity,
            reserve_claim_after_quantity,
            state_output_index,
            vault_output_index,
            state_type_hash,
            vault_lock_hash,
            state_lock_hash,
            &child_state,
            &descriptor,
            Some(reserve_asset_type),
            ckb_reserve_claim_before_quantity,
            ckb_reserve_claim_after_quantity,
            old_vault_root,
            new_vault_root,
        );
    assert_eq!(old_factory_data, expected_old_data);

    let actual_child_vault_capacity = match tamper {
        FactoryReducedXudtExitTamper::CapacityMismatch => child_vault_capacity - 1,
        _ => child_vault_capacity,
    };
    let child_vault_amount = match tamper {
        FactoryReducedXudtExitTamper::ChildAmountMinusOneWithConservedSupply => {
            released_xudt_amount - 1
        }
        _ => released_xudt_amount,
    };
    let child_vault_type = match tamper {
        FactoryReducedXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => wrong_xudt_type,
        _ => xudt_type.clone(),
    };
    let factory_vault_change_capacity = factory_vault_input_capacity - actual_child_vault_capacity;
    let factory_vault_change_type = match tamper {
        FactoryReducedXudtExitTamper::FullReleaseNoTypedChange
        | FactoryReducedXudtExitTamper::FactoryVaultChangeMissing => None,
        _ => Some(xudt_type),
    };
    let factory_vault_change_amount = match tamper {
        FactoryReducedXudtExitTamper::FullReleaseNoTypedChange => 0,
        FactoryReducedXudtExitTamper::ChildAmountMinusOneWithConservedSupply => {
            factory_vault_xudt_surplus + 1
        }
        FactoryReducedXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => {
            reserve_claim_before_quantity
        }
        FactoryReducedXudtExitTamper::FactoryVaultChangeAmountMismatch => {
            factory_vault_xudt_surplus - 1
        }
        _ => factory_vault_xudt_surplus,
    };
    let factory_vault_change_data = if factory_vault_change_type.is_some() {
        xudt_amount_data(factory_vault_change_amount)
    } else {
        Bytes::new()
    };

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(actual_child_vault_capacity)
                .lock(vault_lock)
                .type_(Some(child_vault_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_change_capacity)
                .lock(factory_vault_lock)
                .type_(factory_vault_change_type.pack())
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(xudt_amount_data(child_vault_amount).pack())
        .output_data(factory_vault_change_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
            &reduced_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
            reduced_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_local_exit_materialisation() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_owner_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let factory_vault_input_capacity = 300_000_000_000u64;
    let factory_vault_change_capacity = 200_000_000_000u64;
    let old_vault_root =
        vault_commitment(&factory_vault_lock, factory_vault_input_capacity, None, &[]);
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        factory_vault_change_capacity,
        None,
        &[],
    );

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest_and_vault_roots(
        1,
        2,
        [0u8; 32],
        old_vault_root,
        new_vault_root,
    );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(factory_vault_input_capacity)
            .lock(factory_vault_lock.clone())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_owner_lock)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    set_state_vault_materialisation_root(
        &mut child_state,
        vault_commitment(&vault_lock, ALICE_CAPACITY + BOB_CAPACITY, None, &[]),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[150..182].copy_from_slice(&participants_commitment(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let exit_digest = factory_local_exit_digest(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest_and_vault_roots(
        1,
        2,
        exit_digest,
        old_vault_root,
        new_vault_root,
    );
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input.clone())
        .input(reserve_input.clone())
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock.clone())
                .type_(Some(factory_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock.clone())
                .type_(Some(state_type.clone()).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_change_capacity)
                .lock(factory_vault_lock.clone())
                .build(),
        )
        .output_data(new_data.clone().pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            &exit_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            &exit_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory local exit should verify");

    let split_fee_lock = deploy_always_success(&mut context);
    let split_fee_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(split_fee_lock)
            .build(),
        Bytes::new(),
    );
    let split_reserve_tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(split_fee_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .lock(factory_vault_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(100_000_000_000u64)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            &exit_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            exit_witness,
        ))
        .witness(empty_witness())
        .build();
    let split_reserve_tx = context.complete_tx(split_reserve_tx);
    assert!(context.verify_tx(&split_reserve_tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_ckb_typed_factory_vault_input() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_owner_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let reserve_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![77]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);

    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(300_000_000_000u64)
            .lock(factory_vault_lock.clone())
            .type_(Some(reserve_type).pack())
            .build(),
        Bytes::new(),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_owner_lock)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, relative_since(0)),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    set_state_vault_materialisation_root(
        &mut child_state,
        vault_commitment(&vault_lock, ALICE_CAPACITY + BOB_CAPACITY, None, &[]),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[150..182].copy_from_slice(&participants_commitment(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let exit_digest = factory_local_exit_digest(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, exit_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(200_000_000_000u64)
                .lock(factory_vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            &exit_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            exit_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_and_vault_accept_local_exit_xudt_materialisation() {
    let (context, tx) = factory_xudt_local_exit_tx(FactoryXudtExitTamper::None);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory xUDT local exit should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_factory_exit_without_bound_factory_authority() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::StateFactoryTypeHashMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_xudt_amount_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_xudt_type_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_xudt_input_type_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::FactoryVaultInputTypeMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_xudt_change_amount_mismatch() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_vault_rejects_local_exit_xudt_missing_typed_change() {
    let (context, tx) =
        factory_xudt_local_exit_tx(FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn factory_xudt_local_exit_tx(tamper: FactoryXudtExitTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let reserve_owner_lock = deploy_always_success(&mut context);
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));

    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let mut factory_vault_args = FACTORY_ID.to_vec();
    factory_vault_args.extend_from_slice(&factory_type_hash);
    let factory_vault_lock =
        deploy_contract(&mut context, "morph-factory-vault-lock", factory_vault_args);
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
    let wrong_xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        factory_lock.calc_script_hash().as_slice().to_vec(),
    );

    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let partial_release = matches!(
        tamper,
        FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch
            | FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial
    );
    let factory_vault_input_type = match tamper {
        FactoryXudtExitTamper::FactoryVaultInputTypeMismatch => wrong_xudt_type.clone(),
        _ => xudt_type.clone(),
    };
    let factory_vault_input_amount =
        ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT + if partial_release { 1 } else { 0 };
    let factory_vault_change_type = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply
        | FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint
        | FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch => Some(xudt_type.clone()),
        FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial
        | FactoryXudtExitTamper::FactoryVaultInputTypeMismatch
        | FactoryXudtExitTamper::StateFactoryTypeHashMismatch
        | FactoryXudtExitTamper::None => None,
    };
    let factory_vault_change_data = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply => xudt_amount_data(1),
        FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => {
            xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT)
        }
        FactoryXudtExitTamper::FactoryVaultChangeAmountMismatch => xudt_amount_data(2),
        FactoryXudtExitTamper::FactoryVaultChangeMissingOnPartial
        | FactoryXudtExitTamper::FactoryVaultInputTypeMismatch
        | FactoryXudtExitTamper::StateFactoryTypeHashMismatch
        | FactoryXudtExitTamper::None => Bytes::new(),
    };
    let factory_vault_input_capacity = 300_000_000_000u64;
    let factory_vault_change_capacity = 200_000_000_000u64;
    let input_type_hash: [u8; BYTE32_LEN] = factory_vault_input_type.calc_script_hash().unpack();
    let change_type_hash = factory_vault_change_type
        .as_ref()
        .map(|script| script.calc_script_hash().unpack());
    let old_vault_root = vault_commitment(
        &factory_vault_lock,
        factory_vault_input_capacity,
        Some(input_type_hash),
        &xudt_amount_data(factory_vault_input_amount),
    );
    let new_vault_root = vault_commitment(
        &factory_vault_lock,
        factory_vault_change_capacity,
        change_type_hash,
        factory_vault_change_data.as_ref(),
    );
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest_and_vault_roots(
        1,
        2,
        [0u8; 32],
        old_vault_root,
        new_vault_root,
    );

    let factory_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(factory_input_out_point)
        .build();
    let factory_vault_input_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(factory_vault_input_capacity)
            .lock(factory_vault_lock.clone())
            .type_(Some(factory_vault_input_type).pack())
            .build(),
        xudt_amount_data(factory_vault_input_amount),
    );
    let reserve_input = CellInput::new_builder()
        .previous_output(factory_vault_input_out_point)
        .build();
    let fee_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(reserve_owner_lock)
            .build(),
        Bytes::new(),
    );

    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(
            child_anchor,
            if tamper == FactoryXudtExitTamper::StateFactoryTypeHashMismatch {
                [0xee; 32]
            } else {
                factory_type_hash
            },
            relative_since(0),
        ),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(child_anchor, relative_since(0), &state_type, &state_lock),
    );
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();

    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));
    put_u16(&mut child_state, 246, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    let child_vault_data = xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT);
    set_state_vault_materialisation_root(
        &mut child_state,
        vault_commitment(
            &vault_lock,
            ALICE_CAPACITY + BOB_CAPACITY,
            Some(xudt_type_hash),
            child_vault_data.as_ref(),
        ),
    );
    let key0 = signing_key(1);
    let key1 = signing_key(2);
    let mut child_pubkeys = [pubkey(&key0), pubkey(&key1)];
    child_pubkeys.sort();
    child_state[150..182].copy_from_slice(&participants_commitment(
        2,
        &[&child_pubkeys[0], &child_pubkeys[1]],
    ));

    let exit_digest = factory_local_exit_digest(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest_and_vault_roots(
        1,
        2,
        exit_digest,
        old_vault_root,
        new_vault_root,
    );
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let child_vault_type = match tamper {
        FactoryXudtExitTamper::ChildTypeMismatchWithAuthorisedMint => wrong_xudt_type,
        _ => xudt_type.clone(),
    };
    let child_vault_amount = match tamper {
        FactoryXudtExitTamper::ChildAmountMinusOneWithConservedSupply => {
            ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT - 1
        }
        _ => ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT,
    };
    let tx = TransactionBuilder::default()
        .input(factory_input)
        .input(reserve_input)
        .input(
            CellInput::new_builder()
                .previous_output(fee_input_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .type_(Some(child_vault_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(factory_vault_change_capacity)
                .lock(factory_vault_lock)
                .type_(factory_vault_change_type.pack())
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(xudt_amount_data(child_vault_amount).pack())
        .output_data(factory_vault_change_data.pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            &exit_witness,
        ))
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            exit_witness,
        ))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_digest_mismatch() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let descriptor = descriptor_bytes([1u8; 32], ALICE_CAPACITY, [2u8; 32], BOB_CAPACITY);
    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, 0),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();
    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));

    let correct_digest = factory_local_exit_digest(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let mut wrong_digest = correct_digest;
    wrong_digest[0] ^= 1;
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, wrong_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            exit_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn factory_type_rejects_local_exit_state_lock_mismatch() {
    let mut context = Context::default();
    let factory_lock = deploy_always_success(&mut context);
    let factory_type = deploy_contract(&mut context, "morph-factory-type", FACTORY_ID.to_vec());
    let factory_type_hash: [u8; 32] = factory_type.calc_script_hash().unpack();
    let descriptor = descriptor_bytes([1u8; 32], ALICE_CAPACITY, [2u8; 32], BOB_CAPACITY);
    let state_output_index = 1u32;
    let vault_output_index = 2u32;
    let (old_factory_data, _, _) = signed_factory_pair_with_exit_digest(1, 2, [0u8; 32]);
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(factory_lock.clone())
            .type_(Some(factory_type.clone()).pack())
            .build(),
        old_factory_data,
    );
    let factory_input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let child_anchor = derived_funding_anchor(&factory_input, state_output_index as u64);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(child_anchor, factory_type_hash, 0),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let state_lock_hash: [u8; 32] = state_lock.calc_script_hash().unpack();
    let wrong_state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![4]));
    let vault_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![3]));
    let vault_lock_hash: [u8; 32] = vault_lock.calc_script_hash().unpack();
    let mut child_state = factory_child_header_raw_with_anchor(0, PHASE_ACTIVE, child_anchor);
    child_state[214..246].copy_from_slice(&settlement_descriptor_commitment(&descriptor));

    let exit_digest = factory_local_exit_digest(
        state_output_index,
        vault_output_index,
        &state_type_hash,
        &vault_lock_hash,
        &state_lock_hash,
        &child_state,
        &descriptor,
    );
    let (_, new_data, factory_sig) = signed_factory_pair_with_exit_digest(1, 2, exit_digest);
    let exit_witness = factory_local_exit_witness(
        &factory_sig,
        state_output_index,
        vault_output_index,
        state_type_hash,
        vault_lock_hash,
        state_lock_hash,
        &child_state,
        &descriptor,
    );

    let tx = TransactionBuilder::default()
        .input(factory_input)
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(factory_lock)
                .type_(Some(factory_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wrong_state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY + BOB_CAPACITY)
                .lock(vault_lock)
                .build(),
        )
        .output_data(new_data.pack())
        .output_data(Bytes::from(child_state.to_vec()).pack())
        .output_data(Bytes::new().pack())
        .witness(factory_witness_with_input_type(
            WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
            exit_witness,
        ))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_accepts_newer_settling_state() {
    let (context, tx) = signed_state_supersede_tx(CELL_CAPACITY);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("newer state should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_signed_supersede_carrier_drain() {
    let (context, tx) = signed_state_supersede_tx(CELL_CAPACITY - 1);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_signed_supersede_carrier_top_up() {
    let (context, tx) = signed_state_supersede_tx(CELL_CAPACITY + 1);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn signed_state_supersede_tx(output_capacity: u64) -> (Context, TransactionView) {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(output_capacity)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_supersede_output_lock_drift() {
    let mut context = Context::default();
    let lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let wrong_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock)
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(wrong_lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_accepts_signed_descriptor_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let descriptor = descriptor_bytes([1u8; 32], ALICE_CAPACITY, [2u8; 32], BOB_CAPACITY);
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let (old_data, new_data, sig_witness) = signed_state_pair_with_new_descriptor(
        1,
        PHASE_ACTIVE,
        2,
        PHASE_SETTLING,
        descriptor_commitment,
        BILATERAL_CKB_DESCRIPTOR_VERSION,
    );

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("a participant-signed settlement update must be valid state progress");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_signed_materialisation_update() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair_with_new_materialisation_root(
        1,
        PHASE_ACTIVE,
        2,
        PHASE_SETTLING,
        [42; BYTE32_LEN],
    );

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(
        context.verify_tx(&tx, MAX_CYCLES).is_err(),
        "ordinary state progress must not retarget the materialised vault"
    );
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_equal_state_number() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair(2, 1, 2, PHASE_SETTLING);

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_invalid_participant_signature() {
    let mut context = Context::default();
    let lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let (old_data, new_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let mut sig_witness = sig_witness.to_vec();
    let last = sig_witness.len() - 1;
    sig_witness[last] ^= 1;

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_data,
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY)
        .lock(lock)
        .type_(Some(state_type).pack())
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(new_data.pack())
        .witness(witness_with_input_type(sig_witness.into()))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_accepts_finalise_with_current_state_and_v2_args() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let batch_code = context.deploy_cell(contract_bin("morph-batch-lock"));
    let batch_template = context
        .build_script(&batch_code, Bytes::new())
        .expect("batch lock template");
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args_v2(
            FUNDING_ANCHOR,
            finalise_since,
            &state_type,
            &state_lock,
            &batch_template,
        ),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );
    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("vault finalise should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_accepts_factory_materialised_state_finalise() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(
        &mut context,
        "morph-state-type",
        factory_state_args_with_anchor(FUNDING_ANCHOR, [0x44; 32], finalise_since),
    );
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[148] = STATE_MODE_FACTORY_PROOF;
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );
    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("factory-materialised vault finalise should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_descriptor_output_mismatch() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY - 1)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn ckb_vault_finalise_tx_with_tamper(
    tamper: VaultCkbSettlementTamper,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let extra_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![99]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let vault_input_type_hash = if tamper == VaultCkbSettlementTamper::TypedVaultInput {
        Some(extra_type.calc_script_hash().unpack())
    } else {
        None
    };
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, vault_input_type_hash, &[]),
    );
    if tamper == VaultCkbSettlementTamper::DescriptorVersionMismatch {
        put_u16(&mut state_data, 246, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    }

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .type_(
                (tamper == VaultCkbSettlementTamper::TypedVaultInput)
                    .then_some(extra_type.clone())
                    .pack(),
            )
            .build(),
        Bytes::new(),
    );

    let mut tx_builder = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        );

    let mut outputs = Vec::new();
    match tamper {
        VaultCkbSettlementTamper::NonEmptyData => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY)
                    .lock(alice_lock)
                    .build(),
                Bytes::from(vec![1]),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
        VaultCkbSettlementTamper::TypedOutput => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY)
                    .lock(alice_lock)
                    .type_(Some(extra_type).pack())
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
        VaultCkbSettlementTamper::TypedVaultInput => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY)
                    .lock(alice_lock)
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
        VaultCkbSettlementTamper::SplitOutput => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY / 2)
                    .lock(alice_lock.clone())
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY - ALICE_CAPACITY / 2)
                    .lock(alice_lock)
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
        VaultCkbSettlementTamper::DescriptorVersionMismatch => {
            outputs.push((
                CellOutput::new_builder()
                    .capacity(ALICE_CAPACITY)
                    .lock(alice_lock)
                    .build(),
                Bytes::new(),
            ));
            outputs.push((
                CellOutput::new_builder()
                    .capacity(BOB_CAPACITY)
                    .lock(bob_lock)
                    .build(),
                Bytes::new(),
            ));
        }
    }

    for (output, data) in outputs {
        tx_builder = tx_builder.output(output).output_data(data.pack());
    }
    let tx = tx_builder
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_ckb_settlement_output_with_data() {
    let (context, tx) = ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::NonEmptyData);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_ckb_settlement_output_with_type() {
    let (context, tx) = ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::TypedOutput);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_ckb_only_settlement_with_typed_vault_input() {
    let (context, tx) =
        ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::TypedVaultInput);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_split_settlement_outputs_for_same_lock() {
    let (context, tx) = ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::SplitOutput);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_descriptor_version_mismatch() {
    let (context, tx) =
        ckb_vault_finalise_tx_with_tamper(VaultCkbSettlementTamper::DescriptorVersionMismatch);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_fake_state_header_without_state_type() {
    let mut context = Context::default();
    let fake_state_lock = deploy_always_success(&mut context);
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut fake_state_data = header_raw(3, PHASE_SETTLING);
    fake_state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut fake_state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let fake_state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(fake_state_lock)
            .build(),
        Bytes::from(fake_state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(fake_state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_state_type_since_args_mismatch() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let mismatched_since = relative_since(1);
    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let expected_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let mismatched_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, mismatched_since);
    let expected_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &expected_state_type);
    let mismatched_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &mismatched_state_type);
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(
            FUNDING_ANCHOR,
            finalise_since,
            &expected_state_type,
            &expected_state_lock,
        ),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(mismatched_state_lock)
            .type_(Some(mismatched_state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_raw_absolute_since() {
    let mut context = Context::default();
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let descriptor = descriptor_bytes(
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(0u64)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_standalone_settling_close_without_matching_vault() {
    let mut context = Context::default();
    let state_refund_lock = deploy_always_success(&mut context);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let mut state_data = header_raw(3, PHASE_SETTLING);
    set_state_vault_materialisation_root(&mut state_data, [99u8; 32]);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_refund_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_standalone_active_splice_retire_without_matching_vault() {
    let mut context = Context::default();
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
    );
    let mut old_state_data = old_state_data.to_vec();
    set_state_vault_materialisation_root(&mut old_state_data, [99u8; BYTE32_LEN]);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        Bytes::from(old_state_data),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output_data(new_state_data.pack())
        .witness(witness_with_input_type(splice_witness))
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn state_and_vault_splice_out_tx(
    substitute_withdrawal: bool,
    type_lock_withdrawal: bool,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let signed_withdrawal_lock =
        deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let withdrawal_lock = if substitute_withdrawal {
        deploy_always_success_with_args(&mut context, Bytes::from(vec![10]))
    } else {
        signed_withdrawal_lock.clone()
    };
    let withdrawal_type = if type_lock_withdrawal {
        Some(deploy_always_success_with_args(
            &mut context,
            Bytes::from(vec![12]),
        ))
    } else {
        None
    };
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let new_vault_materialisation_root =
        vault_commitment(&new_vault_lock, ALICE_CAPACITY, None, &[]);
    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle_with_payloads(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        signed_withdrawal_lock.calc_script_hash().unpack(),
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        ALICE_CAPACITY,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + STATE_CARRIER_ACTIVATION_FEE)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .type_(withdrawal_type.pack())
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_and_vault_accept_splice_out_bridge() {
    let (context, tx) = state_and_vault_splice_out_tx(false, false);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("state and vault splice bridge should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_out_with_substituted_withdrawal_lock() {
    let (context, tx) = state_and_vault_splice_out_tx(true, false);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_out_with_typed_ckb_withdrawal() {
    let (context, tx) = state_and_vault_splice_out_tx(false, true);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_and_vault_accept_splice_in_bridge() {
    let (context, tx) = state_and_vault_splice_in_tx(STATE_CARRIER_ACTIVATION_FEE);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("state and vault splice-in bridge should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_type_rejects_splice_without_carrier_activation_reserve() {
    let (context, tx) = state_and_vault_splice_in_tx(0);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn state_and_vault_splice_in_tx(carrier_activation_reserve: u64) -> (Context, TransactionView) {
    let mut context = Context::default();
    let external_funding_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let new_vault_capacity = CELL_CAPACITY + BOB_CAPACITY;
    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let new_vault_materialisation_root =
        vault_commitment(&new_vault_lock, new_vault_capacity, None, &[]);
    let (old_state_data, new_state_data, splice_witness) = signed_splice_in_bundle_with_payloads(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        new_vault_capacity,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        new_vault_capacity,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );
    let external_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(BOB_CAPACITY)
            .lock(external_funding_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(external_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY + carrier_activation_reserve)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(new_vault_capacity)
                .lock(new_vault_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConditionalBatchTamper {
    None,
    WrongPreimage,
    PrematureRefund,
    OutputCapacity,
    DescriptorCommitment,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConditionalVaultTamper {
    None,
    LegacyVaultArgs,
    WrongBatchCode,
    WrongBatchArgs,
    BatchCapacity,
}

fn conditional_vault_finalise_tx(tamper: ConditionalVaultTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let first_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![41]));
    let second_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![42]));
    let mut participant_locks = [first_lock, second_lock];
    participant_locks.sort_by_key(|lock| lock.calc_script_hash().as_slice().to_vec());
    let participant_hashes: [[u8; 32]; 2] = [
        participant_locks[0].calc_script_hash().unpack(),
        participant_locks[1].calc_script_hash().unpack(),
    ];
    let preimage = [7u8; 32];
    let batch = ConditionalBatch {
        batch_id: [3; 32],
        application_context_commitment: [4; 32],
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: participant_hashes[0],
                settled_capacity: ALICE_CAPACITY - 1_000,
            },
            ConditionalParticipant {
                settlement_lock_hash: participant_hashes[1],
                settled_capacity: BOB_CAPACITY,
            },
        ],
        transfers: vec![ConditionalTransferSpec {
            transfer_id: [5; 32],
            payer_lock_hash: participant_hashes[0],
            hash_algorithm: ConditionalHashAlgorithm::Sha256,
            payment_hash: derive_conditional_payment_hash(
                ConditionalHashAlgorithm::Sha256,
                &preimage,
            )
            .unwrap(),
            amount: 1_000,
            refund_after_block: 500,
        }],
    };
    let descriptor = batch.encode_descriptor().unwrap();
    assert_eq!(batch.total_capacity().unwrap(), CELL_CAPACITY);
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());

    let batch_code = context.deploy_cell(contract_bin("morph-batch-lock"));
    let batch_template = context
        .build_script(&batch_code, Bytes::new())
        .expect("batch lock template");
    let vault_lock_args = if tamper == ConditionalVaultTamper::LegacyVaultArgs {
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock)
    } else {
        vault_args_v2(
            FUNDING_ANCHOR,
            finalise_since,
            &state_type,
            &state_lock,
            &batch_template,
        )
    };
    let vault_lock = deploy_contract(&mut context, "morph-vault-lock", vault_lock_args);
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    put_u16(
        &mut state_data,
        246,
        morph_script_common::BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
    );
    set_state_vault_materialisation_root(
        &mut state_data,
        vault_commitment(&vault_lock, CELL_CAPACITY, None, &[]),
    );
    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .build(),
        Bytes::new(),
    );

    let mut batch_args = [0u8; BYTE32_LEN + 8 + BYTE32_LEN];
    batch_args[..BYTE32_LEN].fill(3);
    let batch_state_number = if tamper == ConditionalVaultTamper::WrongBatchArgs {
        4u64
    } else {
        3u64
    };
    batch_args[BYTE32_LEN..BYTE32_LEN + 8].copy_from_slice(&batch_state_number.to_le_bytes());
    batch_args[BYTE32_LEN + 8..].copy_from_slice(&descriptor_commitment);
    let batch_lock = if tamper == ConditionalVaultTamper::WrongBatchCode {
        deploy_always_success_with_args(&mut context, Bytes::from(batch_args.to_vec()))
    } else {
        context
            .build_script(&batch_code, Bytes::from(batch_args.to_vec()))
            .expect("batch lock")
    };
    let batch_capacity = if tamper == ConditionalVaultTamper::BatchCapacity {
        CELL_CAPACITY - 1
    } else {
        CELL_CAPACITY
    };
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(batch_capacity)
                .lock(batch_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor.to_vec().into()))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_materialises_conditional_batch_cell() {
    let (context, tx) = conditional_vault_finalise_tx(ConditionalVaultTamper::None);
    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("conditional vault finalisation should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_conditional_descriptor_under_legacy_args() {
    let (context, tx) = conditional_vault_finalise_tx(ConditionalVaultTamper::LegacyVaultArgs);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_wrong_conditional_batch_code() {
    let (context, tx) = conditional_vault_finalise_tx(ConditionalVaultTamper::WrongBatchCode);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_wrong_conditional_batch_args() {
    let (context, tx) = conditional_vault_finalise_tx(ConditionalVaultTamper::WrongBatchArgs);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_conditional_batch_capacity_loss() {
    let (context, tx) = conditional_vault_finalise_tx(ConditionalVaultTamper::BatchCapacity);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
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
        batch_id: [3; 32],
        application_context_commitment: [4; 32],
        participants: [
            ConditionalParticipant {
                settlement_lock_hash: lock_hashes[0],
                settled_capacity: CELL_CAPACITY / 2 - 1_000,
            },
            ConditionalParticipant {
                settlement_lock_hash: lock_hashes[1],
                settled_capacity: CELL_CAPACITY / 2 - 2_000,
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
    let mut args = [0u8; BYTE32_LEN + 8 + BYTE32_LEN];
    args[..BYTE32_LEN].fill(3);
    args[BYTE32_LEN..BYTE32_LEN + 8].copy_from_slice(&1u64.to_le_bytes());
    args[BYTE32_LEN + 8..].copy_from_slice(&descriptor_commitment);
    let batch_lock = deploy_contract(&mut context, "morph-batch-lock", args.to_vec());
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
    let (context, tx) = conditional_batch_resolution_tx(ConditionalBatchTamper::OutputCapacity);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
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
fn state_type_rejects_splice_new_state_lock_drift() {
    let mut context = Context::default();
    let external_funding_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);
    let wrong_new_state_lock = deploy_always_success_with_args(
        &mut context,
        Bytes::from(new_state_type.calc_script_hash().as_slice().to_vec()),
    );

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_capacity = CELL_CAPACITY + BOB_CAPACITY;
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let new_vault_materialisation_root =
        vault_commitment(&new_vault_lock, new_vault_capacity, None, &[]);
    let (old_state_data, new_state_data, splice_witness) = signed_splice_in_bundle_with_payloads(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        new_vault_capacity,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        new_vault_capacity,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );
    let external_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(BOB_CAPACITY)
            .lock(external_funding_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(external_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wrong_new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(new_vault_capacity)
                .lock(new_vault_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn state_and_vault_reject_splice_wrong_channel_header() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let (old_state_data, new_state_data, splice_witness) =
        signed_splice_out_bundle_with_channel_and_payload(
            FUNDING_ANCHOR,
            NEW_FUNDING_ANCHOR,
            7,
            CELL_CAPACITY,
            ALICE_CAPACITY,
            [99u8; BYTE32_LEN],
            old_vault_materialisation_root,
        );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_new_vault_capacity_mismatch() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let new_vault_materialisation_root =
        vault_commitment(&new_vault_lock, ALICE_CAPACITY, None, &[]);
    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle_with_payloads(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        withdrawal_lock.calc_script_hash().unpack(),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY - 1)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY + 1)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_new_state_payload_mismatch() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let new_vault_materialisation_root =
        vault_commitment(&new_vault_lock, ALICE_CAPACITY, None, &[]);
    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle_with_payloads(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        withdrawal_lock.calc_script_hash().unpack(),
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        ALICE_CAPACITY,
    );
    let mut new_state_data = new_state_data.to_vec();
    set_state_vault_materialisation_root(&mut new_state_data, [99u8; BYTE32_LEN]);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(Bytes::from(new_state_data).pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_splice_split_new_vault_outputs() {
    let mut context = Context::default();
    let withdrawal_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let finalise_since = relative_since(0);

    let state_code = context.deploy_cell(contract_bin("morph-state-type"));
    let state_lock_code = context.deploy_cell(contract_bin("morph-state-lock"));
    let old_state_type =
        build_state_type_from_code(&mut context, &state_code, FUNDING_ANCHOR, finalise_since);
    let new_state_type = build_state_type_from_code(
        &mut context,
        &state_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
    );
    let old_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &old_state_type);
    let new_state_lock =
        build_state_lock_from_code(&mut context, &state_lock_code, &new_state_type);

    let vault_code = context.deploy_cell(contract_bin("morph-vault-lock"));
    let old_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        FUNDING_ANCHOR,
        finalise_since,
        &old_state_type,
        &old_state_lock,
    );
    let new_vault_lock = build_vault_lock_from_code(
        &mut context,
        &vault_code,
        NEW_FUNDING_ANCHOR,
        finalise_since,
        &new_state_type,
        &new_state_lock,
    );

    let old_vault_materialisation_root =
        vault_commitment(&old_vault_lock, CELL_CAPACITY, None, &[]);
    let new_vault_materialisation_root =
        vault_commitment(&new_vault_lock, ALICE_CAPACITY, None, &[]);
    let (old_state_data, new_state_data, splice_witness) = signed_splice_out_bundle_with_payloads(
        FUNDING_ANCHOR,
        NEW_FUNDING_ANCHOR,
        7,
        CELL_CAPACITY,
        ALICE_CAPACITY,
        old_vault_materialisation_root,
        new_vault_materialisation_root,
        withdrawal_lock.calc_script_hash().unpack(),
    );
    let (old_state_data, new_state_data) = bind_splice_state_payloads(
        old_state_data,
        new_state_data,
        &old_vault_lock,
        CELL_CAPACITY,
        &new_vault_lock,
        ALICE_CAPACITY,
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_state_lock)
            .type_(Some(old_state_type).pack())
            .build(),
        old_state_data,
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(old_vault_lock)
            .build(),
        Bytes::new(),
    );
    let first_split = ALICE_CAPACITY / 2;
    let second_split = ALICE_CAPACITY - first_split;

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(new_state_lock)
                .type_(Some(new_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(first_split)
                .lock(new_vault_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(second_split)
                .lock(new_vault_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(withdrawal_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(splice_witness))
        .witness(empty_witness())
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
fn vault_lock_accepts_xudt_finalise_with_descriptor_amounts() {
    let mut context = Context::default();
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        ALICE_XUDT_AMOUNT,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        BOB_XUDT_AMOUNT,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let vault_data = xudt_amount_data(ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT);
    let vault_commitment = vault_commitment(
        &vault_lock,
        CELL_CAPACITY,
        Some(xudt_type_hash),
        vault_data.as_ref(),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    put_u16(&mut state_data, 246, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    set_state_vault_materialisation_root(&mut state_data, vault_commitment);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        vault_data,
    );

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
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
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("xUDT vault finalise should verify");
}

fn xudt_vault_finalise_tx_with_tamper(
    tamper: VaultXudtSettlementTamper,
) -> (Context, TransactionView) {
    let mut context = Context::default();
    let xudt_owner_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![9]));
    let alice_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![1]));
    let bob_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![2]));
    let xudt_type = deploy_contract(
        &mut context,
        "morph-devnet-xudt",
        xudt_owner_lock.calc_script_hash().as_slice().to_vec(),
    );
    let xudt_type_hash: [u8; 32] = xudt_type.calc_script_hash().unpack();
    let (alice_descriptor_amount, bob_descriptor_amount) = match tamper {
        VaultXudtSettlementTamper::NonzeroWrongAmountData => (ALICE_XUDT_AMOUNT, BOB_XUDT_AMOUNT),
        VaultXudtSettlementTamper::ZeroRecipientTypedCell => {
            (ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT, 0)
        }
    };
    let descriptor = ckb_xudt_descriptor_bytes(
        xudt_type_hash,
        alice_lock.calc_script_hash().unpack(),
        ALICE_CAPACITY,
        alice_descriptor_amount,
        bob_lock.calc_script_hash().unpack(),
        BOB_CAPACITY,
        bob_descriptor_amount,
    );
    let descriptor_commitment = settlement_descriptor_commitment(&descriptor);
    let finalise_since = relative_since(0);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(finalise_since));
    let state_type_hash: [u8; 32] = state_type.calc_script_hash().unpack();
    let state_lock = deploy_contract(&mut context, "morph-state-lock", state_type_hash.to_vec());
    let vault_lock = deploy_contract(
        &mut context,
        "morph-vault-lock",
        vault_args(FUNDING_ANCHOR, finalise_since, &state_type, &state_lock),
    );
    let total_amount = ALICE_XUDT_AMOUNT + BOB_XUDT_AMOUNT;
    let vault_data = xudt_amount_data(total_amount);
    let vault_commitment = vault_commitment(
        &vault_lock,
        CELL_CAPACITY,
        Some(xudt_type_hash),
        vault_data.as_ref(),
    );
    let mut state_data = header_raw(3, PHASE_SETTLING);
    state_data[214..246].copy_from_slice(&descriptor_commitment);
    put_u16(&mut state_data, 246, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION);
    set_state_vault_materialisation_root(&mut state_data, vault_commitment);

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type).pack())
            .build(),
        Bytes::from(state_data.to_vec()),
    );
    let vault_out_point = create_bound_vault_cell(
        &mut context,
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(vault_lock)
            .type_(Some(xudt_type.clone()).pack())
            .build(),
        vault_data,
    );

    let (alice_output_amount, bob_output_amount, bob_output_type) = match tamper {
        VaultXudtSettlementTamper::NonzeroWrongAmountData => (
            ALICE_XUDT_AMOUNT - 1,
            BOB_XUDT_AMOUNT + 1,
            Some(xudt_type.clone()),
        ),
        VaultXudtSettlementTamper::ZeroRecipientTypedCell => {
            (total_amount, 0, Some(xudt_type.clone()))
        }
    };
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .since(finalise_since)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(vault_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(ALICE_CAPACITY)
                .lock(alice_lock)
                .type_(Some(xudt_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(BOB_CAPACITY)
                .lock(bob_lock)
                .type_(bob_output_type.pack())
                .build(),
        )
        .output_data(xudt_amount_data(alice_output_amount).pack())
        .output_data(xudt_amount_data(bob_output_amount).pack())
        .witness(empty_witness())
        .witness(witness_with_input_type(descriptor))
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_xudt_nonzero_wrong_amount_data() {
    let (context, tx) =
        xudt_vault_finalise_tx_with_tamper(VaultXudtSettlementTamper::NonzeroWrongAmountData);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn vault_lock_rejects_xudt_zero_recipient_typed_cell() {
    let (context, tx) =
        xudt_vault_finalise_tx_with_tamper(VaultXudtSettlementTamper::ZeroRecipientTypedCell);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_accepts_bounded_fee_with_wallet_change() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("bounded sponsor fee should verify");
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_third_party_capacity_diversion() {
    const DIVERTED_CAPACITY: u64 = 10_000_000_000;
    const ACTUAL_FEE: u64 = 100;

    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let attacker_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![99]));
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            DIVERTED_CAPACITY + ACTUAL_FEE,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - DIVERTED_CAPACITY - ACTUAL_FEE)
                .lock(wallet_lock)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(DIVERTED_CAPACITY)
                .lock(attacker_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_unbacked_non_initial_publication_when_min_state_zero() {
    let (context, tx) = unbacked_sponsor_publication_tx(2);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_unbacked_initial_publication_when_min_state_zero() {
    let (context, tx) = unbacked_sponsor_publication_tx(0);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

fn unbacked_sponsor_publication_tx(state_number: u64) -> (Context, TransactionView) {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let fake_state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let fake_state_type = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let fake_state_type_hash: [u8; BYTE32_LEN] = fake_state_type.calc_script_hash().unpack();
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &fake_state_type_hash,
            1_000,
        ),
    );

    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(fake_state_lock)
                .type_(Some(fake_state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(Bytes::from(header_raw(state_number, PHASE_SETTLING).to_vec()).pack())
        .output_data(Bytes::new().pack())
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SponsorChangeTamper {
    TypedChange,
    DataChange,
    BudgetOverflow,
}

fn sponsor_change_tamper_tx(tamper: SponsorChangeTamper) -> (Context, TransactionView) {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let policy = if tamper == SponsorChangeTamper::BudgetOverflow {
        sponsor_policy_with_already_spent(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
            u64::MAX,
            u64::MAX - 50,
        )
    } else {
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        )
    };
    let sponsor_lock = deploy_contract(&mut context, "morph-sponsor-lock", policy);
    let dirty_type = if tamper == SponsorChangeTamper::TypedChange {
        Some(deploy_always_success_with_args(
            &mut context,
            Bytes::from(vec![42]),
        ))
    } else {
        None
    };

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let mut change_output = CellOutput::new_builder()
        .capacity(CELL_CAPACITY - 100)
        .lock(wallet_lock)
        .build();
    if let Some(dirty_type) = dirty_type {
        change_output = change_output
            .as_builder()
            .type_(Some(dirty_type).pack())
            .build();
    }
    let change_data = if tamper == SponsorChangeTamper::DataChange {
        Bytes::from(vec![1])
    } else {
        Bytes::new()
    };

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(change_output)
        .output_data(new_state_data.pack())
        .output_data(change_data.pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);
    (context, tx)
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_typed_change_output() {
    let (context, tx) = sponsor_change_tamper_tx(SponsorChangeTamper::TypedChange);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_change_output_with_data() {
    let (context, tx) = sponsor_change_tamper_tx(SponsorChangeTamper::DataChange);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_budget_add_overflow() {
    let (context, tx) = sponsor_change_tamper_tx(SponsorChangeTamper::BudgetOverflow);
    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_does_not_mask_wrong_state_output_lock() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let wrong_state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![8]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock)
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wrong_state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_fee_above_per_tx_limit() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            50,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_state_number_outside_policy_range() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_lock = deploy_always_success_with_args(&mut context, Bytes::from(vec![7]));
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (old_state_data, new_state_data, sig_witness) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy_with_bounds(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            3,
            10,
            1_000,
            1_000,
        ),
    );

    let state_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build(),
        old_state_data,
    );
    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(state_out_point)
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(state_lock)
                .type_(Some(state_type).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(new_state_data.pack())
        .output_data(Bytes::new().pack())
        .witness(witness_with_input_type(sig_witness))
        .witness(empty_witness())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_fee_without_state_publication() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &[9u8; BYTE32_LEN],
            1_000,
        ),
    );

    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[ignore = "requires `make build-contracts`"]
#[test]
fn sponsor_lock_rejects_fake_state_header_without_state_type() {
    let mut context = Context::default();
    let wallet_lock = deploy_always_success(&mut context);
    let state_type = deploy_contract(&mut context, "morph-state-type", state_args(0));
    let state_type_hash: [u8; BYTE32_LEN] = state_type.calc_script_hash().unpack();
    let (_, fake_state_data, _) = signed_state_pair(1, 1, 2, PHASE_SETTLING);
    let change_hash = wallet_lock.calc_script_hash();
    let sponsor_lock = deploy_contract(
        &mut context,
        "morph-sponsor-lock",
        sponsor_policy(
            change_hash.as_slice().try_into().unwrap(),
            &state_type_hash,
            1_000,
        ),
    );

    let sponsor_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(CELL_CAPACITY * 2)
            .lock(sponsor_lock)
            .build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(sponsor_out_point)
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY)
                .lock(wallet_lock.clone())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(CELL_CAPACITY - 100)
                .lock(wallet_lock)
                .build(),
        )
        .output_data(fake_state_data.pack())
        .output_data(Bytes::new().pack())
        .build();
    let tx = context.complete_tx(tx);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}
