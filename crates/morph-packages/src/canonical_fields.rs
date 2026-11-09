//! Canonical public financial quantities, hashes and compressed signing keys.
use anyhow::{Context, Result, anyhow, ensure};
use morph_core::Bytes32;

use crate::multi_asset_packages::decode_hex;

pub fn decimal_u64(value: &str) -> Result<u64> {
    let result = value.parse::<u64>()?;
    ensure!(
        result.to_string() == value,
        "quantity must be canonical unsigned decimal"
    );
    Ok(result)
}
pub fn decimal_u128(value: &str) -> Result<u128> {
    let result = value.parse::<u128>()?;
    ensure!(
        result.to_string() == value,
        "quantity must be canonical unsigned decimal"
    );
    Ok(result)
}
pub fn hash(value: &str) -> Result<Bytes32> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("hash must be 32 bytes"))
}
pub fn public(value: &str) -> Result<Vec<u8>> {
    let raw = decode_hex(value, 33)?;
    ensure!(raw.len() == 33, "compressed key must be 33 bytes");
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
        .map_err(|_| anyhow!("invalid compressed public key"))?;
    Ok(raw)
}

pub fn canonical_hex32(value: &str) -> Result<String> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        stripped.len() == 64,
        "expected 32-byte hex string, got {} hex characters",
        stripped.len()
    );
    let bytes = hex::decode(stripped).context("hex string is not valid")?;
    ensure!(bytes.len() == 32, "expected 32 bytes");
    Ok(crate::multi_asset_packages::canonical_hex(&bytes))
}
