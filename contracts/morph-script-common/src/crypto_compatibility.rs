//! Pin the byte-level prehash and strict low-S behavior across RustCrypto upgrades.
extern crate alloc;

use super::*;
use alloc::vec::Vec;
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};

const DIGEST: [u8; 32] = [0x42; 32];
// Captured with k256 0.13.4 using private keys [1; 32] and [2; 32].
const PUBKEYS: [[u8; 33]; 2] = [
    [
        0x03, 0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40, 0x99, 0x5d, 0x3e, 0xd5, 0xaa, 0xba,
        0x05, 0x65, 0xd7, 0x1e, 0x18, 0x34, 0x60, 0x48, 0x19, 0xff, 0x9c, 0x17, 0xf5, 0xe9, 0xd5,
        0xdd, 0x07, 0x8f,
    ],
    [
        0x02, 0x4d, 0x4b, 0x6c, 0xd1, 0x36, 0x10, 0x32, 0xca, 0x9b, 0xd2, 0xae, 0xb9, 0xd9, 0x00,
        0xaa, 0x4d, 0x45, 0xd9, 0xea, 0xd8, 0x0a, 0xc9, 0x42, 0x33, 0x74, 0xc4, 0x51, 0xa7, 0x25,
        0x4d, 0x07, 0x66,
    ],
];

const SIGNATURES: [[u8; 64]; 2] = [
    [
        0x35, 0x1f, 0x77, 0x75, 0x54, 0x8e, 0x4c, 0x56, 0x1d, 0xd9, 0x72, 0x6a, 0x9c, 0xe4, 0x77,
        0xc7, 0x8f, 0x68, 0x54, 0xab, 0x2d, 0xb3, 0x81, 0x5e, 0x69, 0x79, 0x24, 0x63, 0xfa, 0x54,
        0xf1, 0xfa, 0x46, 0x19, 0x27, 0x78, 0x74, 0x0b, 0x11, 0x5a, 0xdf, 0x05, 0x29, 0xc6, 0xd1,
        0x73, 0x0b, 0x22, 0xd5, 0xa0, 0x63, 0x6f, 0xf8, 0xa0, 0xd3, 0xea, 0x6d, 0x7e, 0x02, 0x1a,
        0x14, 0x4c, 0x0f, 0x03,
    ],
    [
        0x21, 0xcf, 0x1f, 0x4f, 0x98, 0x09, 0x8f, 0xa1, 0x07, 0xd6, 0x1b, 0x76, 0x6f, 0xa6, 0x26,
        0x10, 0x73, 0xf7, 0xd9, 0x81, 0x8b, 0x7a, 0x7f, 0x23, 0x96, 0x8f, 0xc1, 0xcd, 0x38, 0x8b,
        0x1d, 0xb4, 0x0a, 0xbb, 0x41, 0x08, 0xd6, 0x4c, 0x76, 0xde, 0x11, 0x56, 0x68, 0x0f, 0xbd,
        0x03, 0x5d, 0x07, 0x89, 0x47, 0xb8, 0x0e, 0xd6, 0x1e, 0xee, 0x6d, 0x4c, 0xe4, 0x3f, 0x0d,
        0x27, 0x71, 0xfc, 0x14,
    ],
];

fn bilateral() -> [u8; BILATERAL_SIGNATURE_WITNESS_LEN] {
    let mut raw = [0; BILATERAL_SIGNATURE_WITNESS_LEN];
    raw[..4].copy_from_slice(&[1, 0, 2, 2]);
    // Bilateral witnesses sort keys, so key [2; 32] precedes key [1; 32].
    for (position, key) in [1, 0].into_iter().enumerate() {
        let offset = 4 + position * (COMPRESSED_SECP256K1_PUBKEY_LEN + ECDSA_SIGNATURE_LEN);
        raw[offset..offset + 33].copy_from_slice(&PUBKEYS[key]);
        raw[offset + 33..offset + 97].copy_from_slice(&SIGNATURES[key]);
    }
    raw
}

fn factory() -> Vec<u8> {
    let mut raw = alloc::vec![0; factory_signature_witness_len(2)];
    raw[..4].copy_from_slice(&[1, 0, 2, 2]);
    for index in 0..2 {
        let offset = 4 + index * FACTORY_SIGNATURE_ENTRY_LEN;
        raw[offset..offset + 32].fill(index as u8 + 1);
        raw[offset + 32..offset + 65].copy_from_slice(&PUBKEYS[index]);
        raw[offset + 65..offset + 129].copy_from_slice(&SIGNATURES[index]);
    }
    raw
}

fn verify_bilateral(raw: &[u8], digest: &[u8; 32]) -> Result<()> {
    let witness = BilateralSignatureWitness::parse(raw)?;
    multi_asset::verify_multi_asset_signatures(&witness.participants_commitment(), digest, &witness)
}

fn verify_factory(raw: &[u8], digest: &[u8; 32]) -> Result<()> {
    verify_factory_signatures_for_digest(digest, &FactorySignatureWitness::parse(raw)?)
}

fn high_s(signature: &[u8]) -> [u8; 64] {
    let signature = Signature::from_slice(signature).unwrap();
    let (r, s) = signature.split_scalars();
    let twin = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    assert_ne!(twin.normalize_s(), twin);
    assert_eq!(twin.normalize_s(), signature);
    twin.to_bytes().into()
}

#[test]
fn prehashed_signature_bytes_match_previous_rustcrypto_release() {
    for index in 0..2 {
        let key = SigningKey::from_slice(&[index as u8 + 1; 32]).unwrap();
        assert_eq!(
            key.verifying_key().to_sec1_point(true).as_bytes(),
            PUBKEYS[index]
        );
        let signature: Signature = key.sign_prehash(&DIGEST).unwrap();
        assert_eq!(signature.to_bytes().as_slice(), SIGNATURES[index]);
        assert_eq!(signature.normalize_s(), signature);
    }
    assert_eq!(verify_bilateral(&bilateral(), &DIGEST), Ok(()));
    assert_eq!(verify_factory(&factory(), &DIGEST), Ok(()));
}

#[test]
fn bilateral_and_factory_reject_valid_high_s_twins() {
    let mut bilateral = bilateral();
    bilateral[37..101].copy_from_slice(&high_s(&SIGNATURES[1]));
    assert_eq!(
        verify_bilateral(&bilateral, &DIGEST),
        Err(ScriptError::InvalidParticipantSignature)
    );
    let mut factory = factory();
    factory[69..133].copy_from_slice(&high_s(&SIGNATURES[0]));
    assert_eq!(
        verify_factory(&factory, &DIGEST),
        Err(ScriptError::InvalidParticipantSignature)
    );
}

#[test]
fn bilateral_and_factory_reject_changed_digest_and_wrong_signer() {
    let mut digest = DIGEST;
    digest[0] ^= 1;
    assert_eq!(
        verify_bilateral(&bilateral(), &digest),
        Err(ScriptError::InvalidParticipantSignature)
    );
    assert_eq!(
        verify_factory(&factory(), &digest),
        Err(ScriptError::InvalidParticipantSignature)
    );
    let mut bilateral = bilateral();
    bilateral[37..101].copy_from_slice(&SIGNATURES[0]);
    assert_eq!(
        verify_bilateral(&bilateral, &DIGEST),
        Err(ScriptError::InvalidParticipantSignature)
    );
    let mut factory = factory();
    factory[69..133].copy_from_slice(&SIGNATURES[1]);
    assert_eq!(
        verify_factory(&factory, &DIGEST),
        Err(ScriptError::InvalidParticipantSignature)
    );
}

#[test]
fn bilateral_and_factory_reject_malformed_keys_scalars_and_widths() {
    let bilateral = bilateral();
    let factory = factory();
    assert_eq!(
        verify_bilateral(&bilateral[..bilateral.len() - 1], &DIGEST),
        Err(ScriptError::ParticipantWitnessEncoding)
    );
    assert_eq!(
        verify_factory(&factory[..factory.len() - 1], &DIGEST),
        Err(ScriptError::ParticipantWitnessEncoding)
    );
    let mut bad_key = bilateral;
    bad_key[4..37].fill(0);
    assert_eq!(
        verify_bilateral(&bad_key, &DIGEST),
        Err(ScriptError::ParticipantWitnessEncoding)
    );
    let mut bad_key = factory.clone();
    bad_key[36..69].fill(0);
    assert_eq!(
        verify_factory(&bad_key, &DIGEST),
        Err(ScriptError::ParticipantWitnessEncoding)
    );
    let mut bad_scalar = bilateral;
    bad_scalar[37..69].fill(0);
    assert_eq!(
        verify_bilateral(&bad_scalar, &DIGEST),
        Err(ScriptError::ParticipantWitnessEncoding)
    );
    let mut bad_scalar = factory;
    bad_scalar[69..101].fill(0);
    assert_eq!(
        verify_factory(&bad_scalar, &DIGEST),
        Err(ScriptError::ParticipantWitnessEncoding)
    );
}
