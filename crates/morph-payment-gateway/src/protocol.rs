use std::time::{SystemTime, UNIX_EPOCH};

use ckb_types::prelude::*;
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use morph_core::{
    BitcoinNetwork, GatewayAsset, PaymentIntent, RgbppAssetId, TerminalPaymentStatus,
    TerminalSettlementReceipt, blake2b256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const X402_SCHEME: &str = "exact";
pub const X402_NETWORK: &str = "morph-ckb";
pub const PAYMENT_RAIL_FIBER: &str = "fiber";
pub const PAYMENT_HASH_ALGORITHM: &str = "sha256";
pub const PAYMENT_REQUIRED_HEADER: &str = "payment-required";
pub const PAYMENT_SIGNATURE_HEADER: &str = "payment-signature";
pub const PAYMENT_RESPONSE_HEADER: &str = "payment-response";
pub const MORPH_REQUIREMENT_RECORD_KEY: u32 = 0x4d50;
pub const MORPH_RESULT_RECORD_KEY: u32 = 0x4d51;
pub const MORPH_PAYER_RECORD_KEY: u32 = 0x4d52;
const PAYER_AUTHORIZATION_DOMAIN: &[u8] = b"CKB_MORPH_X402_PAYER_AUTH_V1";
const MAX_RESOURCE_LEN: usize = 2_048;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("network identifier must be non-empty")]
    InvalidNetwork,
    #[error("RGB++ asset Type Script hash must be a non-zero 0x-prefixed byte32")]
    InvalidAssetHash,
    #[error("RGB++ assets require the canonical Type Script JSON")]
    MissingTypeScript,
    #[error("RGB++ Type Script JSON does not hash to the committed Type Script hash")]
    TypeScriptHashMismatch,
    #[error("RGB++ assets require Bitcoin network and binding code identities")]
    MissingRgbppIdentity,
    #[error("CKB requirements must not contain an RGB++ Type Script")]
    UnexpectedTypeScript,
    #[error("amount must be a positive base-10 u128")]
    InvalidAmount,
    #[error("payment hash, nonce, or identifier is malformed")]
    InvalidIdentifier,
    #[error("payment requirement is expired")]
    Expired,
    #[error("unsupported scheme, network, or hash algorithm")]
    UnsupportedProtocol,
    #[error("resource path must be absolute and must not contain a URL authority")]
    InvalidResource,
    #[error("payer authorization is malformed, mismatched, or has an invalid signature")]
    InvalidPayerAuthorization,
    #[error("terminal payment receipt is malformed or does not match its signed intent")]
    InvalidReceipt,
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Ckb,
    Rgbpp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RgbppAsset {
    pub kind: AssetKind,
    /// Stable CKB network/genesis identifier, not a display name.
    pub ckb_network_id: String,
    /// Required for RGB++ and absent for CKB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_script_hash: Option<String>,
    /// Canonical CKB JSON Script. Display metadata never replaces this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "crate::wire::optional_script")]
    #[schemars(with = "Option<crate::wire::PublicScript>")]
    pub type_script: Option<Value>,
    /// Required for RGB++; absent for CKB.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "crate::wire::optional_bitcoin_network")]
    #[schemars(with = "Option<crate::wire::BitcoinNetworkWire>")]
    pub bitcoin_network: Option<BitcoinNetwork>,
    /// Code hash of the RGB++ binding lock/profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_code_hash: Option<String>,
    pub symbol: String,
    pub decimals: u8,
}

impl RgbppAsset {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_nonzero_byte32(&self.ckb_network_id).map_err(|_| ProtocolError::InvalidNetwork)?;
        match self.kind {
            AssetKind::Ckb => {
                if self.type_script_hash.is_some()
                    || self.type_script.is_some()
                    || self.bitcoin_network.is_some()
                    || self.binding_code_hash.is_some()
                {
                    return Err(ProtocolError::UnexpectedTypeScript);
                }
            }
            AssetKind::Rgbpp => {
                let hash = self
                    .type_script_hash
                    .as_deref()
                    .ok_or(ProtocolError::InvalidAssetHash)?;
                validate_nonzero_byte32(hash).map_err(|_| ProtocolError::InvalidAssetHash)?;
                if !self.type_script.as_ref().is_some_and(Value::is_object) {
                    return Err(ProtocolError::MissingTypeScript);
                }
                let type_script = self
                    .type_script
                    .clone()
                    .ok_or(ProtocolError::MissingTypeScript)?;
                let public: crate::wire::PublicScript = serde_json::from_value(type_script.clone())
                    .map_err(|_| ProtocolError::MissingTypeScript)?;
                if !public.validate() {
                    return Err(ProtocolError::MissingTypeScript);
                }
                let json_script: ckb_jsonrpc_types::Script = serde_json::from_value(type_script)
                    .map_err(|_| ProtocolError::MissingTypeScript)?;
                let packed_script: ckb_types::packed::Script = json_script.into();
                let actual_hash: [u8; 32] = packed_script.calc_script_hash().unpack();
                if actual_hash != decode_byte32(hash)? {
                    return Err(ProtocolError::TypeScriptHashMismatch);
                }
                let binding_code_hash = self
                    .binding_code_hash
                    .as_deref()
                    .ok_or(ProtocolError::MissingRgbppIdentity)?;
                validate_nonzero_byte32(binding_code_hash)
                    .map_err(|_| ProtocolError::MissingRgbppIdentity)?;
                if self.bitcoin_network.is_none() {
                    return Err(ProtocolError::MissingRgbppIdentity);
                }
            }
        }
        Ok(())
    }

    pub fn canonical_id(&self) -> ProtocolResult<String> {
        let commitment = self
            .to_gateway_asset()?
            .commitment()
            .map_err(|_| ProtocolError::InvalidAssetHash)?;
        Ok(format!("morph:{}", hex::encode(commitment)))
    }

    pub fn to_gateway_asset(&self) -> ProtocolResult<GatewayAsset> {
        self.validate()?;
        let ckb_genesis_hash = decode_byte32(&self.ckb_network_id)?;
        Ok(match self.kind {
            AssetKind::Ckb => GatewayAsset::Ckb { ckb_genesis_hash },
            AssetKind::Rgbpp => GatewayAsset::Rgbpp(RgbppAssetId {
                ckb_genesis_hash,
                xudt_type_script_hash: decode_byte32(
                    self.type_script_hash
                        .as_deref()
                        .ok_or(ProtocolError::MissingRgbppIdentity)?,
                )?,
                bitcoin_network: self
                    .bitcoin_network
                    .ok_or(ProtocolError::MissingRgbppIdentity)?,
                binding_code_hash: decode_byte32(
                    self.binding_code_hash
                        .as_deref()
                        .ok_or(ProtocolError::MissingRgbppIdentity)?,
                )?,
            }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentRequirements {
    pub requirement_id: String,
    pub scheme: String,
    pub network: String,
    pub payment_rail: String,
    pub asset: RgbppAsset,
    /// Raw integer amount in the asset's smallest unit.
    pub amount: String,
    /// Morph account that requested this challenge and is allowed to claim it.
    pub payer: String,
    pub payee: String,
    pub invoice: String,
    pub payment_hash: String,
    pub hash_algorithm: String,
    pub resource: String,
    /// Upper-case HTTP method authorized by this payment.
    pub operation: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rgbpp_proof_commitment: Option<String>,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::decimal::schema")]
    pub expires_at: u64,
}

impl PaymentRequirements {
    pub fn validate(&self, now: u64) -> ProtocolResult<()> {
        if self.scheme != X402_SCHEME
            || self.network != X402_NETWORK
            || self.payment_rail != PAYMENT_RAIL_FIBER
            || self.hash_algorithm != PAYMENT_HASH_ALGORITHM
        {
            return Err(ProtocolError::UnsupportedProtocol);
        }
        self.asset.validate()?;
        parse_amount(&self.amount)?;
        validate_nonzero_byte32(&self.payer)?;
        validate_nonzero_byte32(&self.payee)?;
        if self.payer == self.payee {
            return Err(ProtocolError::InvalidPayerAuthorization);
        }
        validate_byte32(&self.payment_hash)?;
        validate_byte32(&self.nonce)?;
        validate_byte32(&self.requirement_id)?;
        if self.invoice.trim().is_empty() {
            return Err(ProtocolError::InvalidIdentifier);
        }
        match (&self.asset.kind, &self.rgbpp_proof_commitment) {
            (AssetKind::Rgbpp, Some(commitment)) => validate_nonzero_byte32(commitment)?,
            (AssetKind::Rgbpp, None) | (AssetKind::Ckb, Some(_)) => {
                return Err(ProtocolError::MissingRgbppIdentity);
            }
            (AssetKind::Ckb, None) => {}
        }
        if self.resource.is_empty()
            || self.resource.len() > MAX_RESOURCE_LEN
            || !self.resource.starts_with('/')
            || self.resource.starts_with("//")
            || self.resource.contains("://")
        {
            return Err(ProtocolError::InvalidResource);
        }
        if !matches!(
            self.operation.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            return Err(ProtocolError::InvalidResource);
        }
        if now >= self.expires_at {
            return Err(ProtocolError::Expired);
        }
        if self.requirement_id != self.expected_id()? {
            return Err(ProtocolError::InvalidIdentifier);
        }
        Ok(())
    }

    pub fn expected_id(&self) -> ProtocolResult<String> {
        // Object insertion order must never depend on serde_json/preserve_order.
        let type_script = self.asset.type_script.clone().map(|mut value| {
            value.sort_all_objects();
            value
        });
        let canonical = RequirementCommitment {
            scheme: &self.scheme,
            network: &self.network,
            payment_rail: &self.payment_rail,
            asset_id: self.asset.canonical_id()?,
            type_script: type_script.as_ref(),
            amount: &self.amount,
            payer: &self.payer,
            payee: &self.payee,
            invoice: &self.invoice,
            payment_hash: &self.payment_hash,
            hash_algorithm: &self.hash_algorithm,
            resource: &self.resource,
            operation: &self.operation,
            nonce: &self.nonce,
            rgbpp_proof_commitment: self.rgbpp_proof_commitment.as_deref(),
            expires_at: self.expires_at,
        };
        let raw = serde_json::to_vec(&canonical).map_err(|_| ProtocolError::InvalidIdentifier)?;
        Ok(hex32(&Sha256::digest(raw)))
    }

    pub fn amount_u128(&self) -> ProtocolResult<u128> {
        parse_amount(&self.amount)
    }
}

#[derive(Serialize)]
struct RequirementCommitment<'a> {
    scheme: &'a str,
    network: &'a str,
    payment_rail: &'a str,
    asset_id: String,
    type_script: Option<&'a Value>,
    amount: &'a str,
    payer: &'a str,
    payee: &'a str,
    invoice: &'a str,
    payment_hash: &'a str,
    hash_algorithm: &'a str,
    resource: &'a str,
    operation: &'a str,
    nonce: &'a str,
    rgbpp_proof_commitment: Option<&'a str>,
    expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentPayload {
    pub requirement_id: String,
    pub payment_hash: String,
    /// Morph account identity: blake2b-256(compressed secp256k1 public key).
    pub payer: String,
    /// SEC1-compressed secp256k1 public key, encoded as 0x-prefixed hex.
    pub payer_pubkey_sec1: String,
    /// Raw 64-byte secp256k1 ECDSA signature over the canonical authorization digest.
    pub payer_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_preimage: Option<String>,
}

impl PaymentPayload {
    pub fn new_signed(
        requirements: &PaymentRequirements,
        payment_preimage: Option<String>,
        signing_key: &SigningKey,
    ) -> ProtocolResult<Self> {
        let public_key = signing_key.verifying_key().to_sec1_point(true);
        let public_key_bytes = public_key.as_bytes();
        let payer = hex32(&blake2b256(public_key_bytes));
        if payer != requirements.payer {
            return Err(ProtocolError::InvalidPayerAuthorization);
        }
        let mut payload = Self {
            requirement_id: requirements.requirement_id.clone(),
            payment_hash: requirements.payment_hash.clone(),
            payer,
            payer_pubkey_sec1: hex32(public_key_bytes),
            payer_signature: String::new(),
            payment_preimage,
        };
        let digest = payload.signing_digest(requirements)?;
        let signature: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        payload.payer_signature = hex32(signature.to_bytes().as_ref());
        Ok(payload)
    }

    pub fn validate(&self, requirements: &PaymentRequirements) -> ProtocolResult<()> {
        let public_key_bytes = decode_fixed_hex::<33>(&self.payer_pubkey_sec1)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        if verifying_key.to_sec1_point(true).as_bytes() != public_key_bytes
            || self.payer != hex32(&blake2b256(&public_key_bytes))
        {
            return Err(ProtocolError::InvalidPayerAuthorization);
        }
        let signature_bytes = decode_fixed_hex::<64>(&self.payer_signature)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        if signature.normalize_s() != signature {
            return Err(ProtocolError::InvalidPayerAuthorization);
        }
        let digest = self.signing_digest(requirements)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)
    }

    fn signing_digest(&self, requirements: &PaymentRequirements) -> ProtocolResult<[u8; 32]> {
        if requirements.requirement_id != requirements.expected_id()?
            || self.requirement_id != requirements.requirement_id
            || self.payment_hash != requirements.payment_hash
            || self.payer != requirements.payer
            || self.payer == requirements.payee
        {
            return Err(ProtocolError::InvalidPayerAuthorization);
        }
        let requirement_id = decode_byte32(&self.requirement_id)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        let payment_hash = decode_byte32(&self.payment_hash)
            .map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        let payer =
            decode_byte32(&self.payer).map_err(|_| ProtocolError::InvalidPayerAuthorization)?;
        let mut canonical = Vec::with_capacity(PAYER_AUTHORIZATION_DOMAIN.len() + 32 * 4 + 1);
        canonical.extend_from_slice(PAYER_AUTHORIZATION_DOMAIN);
        canonical.extend_from_slice(&requirement_id);
        canonical.extend_from_slice(&payment_hash);
        canonical.extend_from_slice(&payer);
        match &self.payment_preimage {
            Some(value) => {
                canonical.push(1);
                canonical.extend_from_slice(
                    &decode_byte32(value).map_err(|_| ProtocolError::InvalidPayerAuthorization)?,
                );
            }
            None => canonical.push(0),
        }
        Ok(Sha256::digest(canonical).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentReceipt {
    pub receipt_id: String,
    pub credential_id: String,
    pub requirement_id: String,
    pub payment_hash: String,
    pub payer: String,
    pub asset_id: String,
    pub amount: String,
    pub resource: String,
    pub operation: String,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::decimal::schema")]
    pub paid_at: u64,
    pub fiber_status: String,
    pub credential: String,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::decimal::schema")]
    pub credential_expires_at: u64,
    /// Full canonical intent needed for independent receipt verification.
    #[serde(with = "crate::wire::PaymentIntentWire")]
    #[schemars(with = "crate::wire::PaymentIntentWire")]
    pub intent: PaymentIntent,
    /// Canonical, independently signed terminal settlement event.
    #[serde(with = "crate::wire::TerminalSettlementReceiptWire")]
    #[schemars(with = "crate::wire::TerminalSettlementReceiptWire")]
    pub terminal_receipt: TerminalSettlementReceipt,
}

impl PaymentReceipt {
    pub fn validate_for_signer(&self, expected_pubkey_sec1: &[u8]) -> ProtocolResult<()> {
        self.terminal_receipt
            .validate_for_signer(expected_pubkey_sec1)
            .map_err(|_| ProtocolError::InvalidReceipt)?;
        self.terminal_receipt
            .validate_against_intent(&self.intent)
            .map_err(|_| ProtocolError::InvalidReceipt)?;
        let asset_id = format!(
            "morph:{}",
            hex::encode(
                self.intent
                    .asset
                    .commitment()
                    .map_err(|_| ProtocolError::InvalidReceipt)?
            )
        );
        let expected_opaque_commitment: [u8; 32] = Sha256::digest(
            format!(
                "morph-fiber-settlement-v1\0{}\0{}\0{}",
                self.requirement_id, self.payment_hash, self.fiber_status
            )
            .as_bytes(),
        )
        .into();
        if self.receipt_id != hex32(&self.terminal_receipt.receipt_id)
            || self.requirement_id != hex32(&self.intent.idempotency_key)
            || self.payment_hash != hex32(&self.intent.payment_hash)
            || self.payer != hex32(&self.intent.payer)
            || self.asset_id != asset_id
            || self.amount != self.intent.amount.to_string()
            || self.resource != self.intent.resource
            || self.operation != self.intent.operation.as_str()
            || self.paid_at != self.terminal_receipt.finalised_at_unix
            || self.terminal_receipt.status != TerminalPaymentStatus::Settled
            || !matches!(self.fiber_status.as_str(), "Paid" | "preimage_verified")
            || self.terminal_receipt.evidence.provider_id != "fiber-json-rpc"
            || self.terminal_receipt.evidence.settlement_id != self.intent.payment_hash
            || self.terminal_receipt.evidence.opaque_commitment != expected_opaque_commitment
            || self.credential_id.trim().is_empty()
            || self.credential.trim().is_empty()
            || self.credential_expires_at <= self.paid_at
        {
            return Err(ProtocolError::InvalidReceipt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FairExchangeEnvelope {
    pub offer_id: String,
    pub requirement: PaymentRequirements,
    pub nonce: String,
    pub ciphertext: String,
    pub result_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FairExchangeClaim {
    pub offer_id: String,
    pub decryption_key: String,
    pub receipt: PaymentReceipt,
}

pub fn parse_amount(value: &str) -> ProtocolResult<u128> {
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(ProtocolError::InvalidAmount);
    }
    let amount = value
        .parse::<u128>()
        .map_err(|_| ProtocolError::InvalidAmount)?;
    if amount == 0 || amount.to_string() != value {
        return Err(ProtocolError::InvalidAmount);
    }
    Ok(amount)
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn strip_hex(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

pub fn decode_byte32(value: &str) -> ProtocolResult<[u8; 32]> {
    decode_fixed_hex(value)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> ProtocolResult<[u8; N]> {
    if value.len() != 2 + N * 2
        || !value.starts_with("0x")
        || !value.as_bytes()[2..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(ProtocolError::InvalidIdentifier);
    }
    let raw = hex::decode(strip_hex(value)).map_err(|_| ProtocolError::InvalidIdentifier)?;
    raw.try_into().map_err(|_| ProtocolError::InvalidIdentifier)
}

pub fn validate_byte32(value: &str) -> ProtocolResult<()> {
    decode_byte32(value).map(|_| ())
}

pub fn validate_nonzero_byte32(value: &str) -> ProtocolResult<()> {
    let decoded = decode_byte32(value)?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidIdentifier);
    }
    Ok(())
}

pub fn hex32(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgbpp_asset() -> RgbppAsset {
        let type_script = serde_json::json!({
            "code_hash": format!("0x{}", "22".repeat(32)),
            "hash_type": "type",
            "args": "0x1234"
        });
        let json_script: ckb_jsonrpc_types::Script =
            serde_json::from_value(type_script.clone()).unwrap();
        let packed_script: ckb_types::packed::Script = json_script.into();
        let type_script_hash: [u8; 32] = packed_script.calc_script_hash().unpack();
        RgbppAsset {
            kind: AssetKind::Rgbpp,
            ckb_network_id: format!("0x{}", "01".repeat(32)),
            type_script_hash: Some(hex32(&type_script_hash)),
            type_script: Some(type_script),
            bitcoin_network: Some(BitcoinNetwork::Testnet),
            binding_code_hash: Some(format!("0x{}", "03".repeat(32))),
            symbol: "USDI".to_string(),
            decimals: 6,
        }
    }

    fn requirement() -> PaymentRequirements {
        let mut requirement = PaymentRequirements {
            requirement_id: format!("0x{}", "00".repeat(32)),
            scheme: X402_SCHEME.to_string(),
            network: X402_NETWORK.to_string(),
            payment_rail: PAYMENT_RAIL_FIBER.to_string(),
            asset: rgbpp_asset(),
            amount: "1000000".to_string(),
            payer: hex32(&blake2b256(
                SigningKey::from_slice(&[7; 32])
                    .unwrap()
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes(),
            )),
            payee: format!("0x{}", "09".repeat(32)),
            invoice: "fibt1invoice".to_string(),
            payment_hash: format!("0x{}", "33".repeat(32)),
            hash_algorithm: PAYMENT_HASH_ALGORITHM.to_string(),
            resource: "/api/data".to_string(),
            operation: "GET".to_string(),
            nonce: format!("0x{}", "44".repeat(32)),
            rgbpp_proof_commitment: Some(format!("0x{}", "45".repeat(32))),
            expires_at: u64::MAX,
        };
        requirement.requirement_id = requirement.expected_id().unwrap();
        requirement
    }

    #[test]
    fn asset_identity_uses_type_script_not_ticker() {
        let mut renamed = rgbpp_asset();
        let original = renamed.canonical_id().unwrap();
        renamed.symbol = "FAKE".to_string();
        renamed.decimals = 18;
        assert_eq!(renamed.canonical_id().unwrap(), original);
    }

    #[test]
    fn requirement_id_binds_every_authoritative_field() {
        let mut requirement = requirement();
        requirement.validate(1).unwrap();
        let original = requirement.requirement_id.clone();
        requirement.amount = "1000001".to_string();
        assert_ne!(requirement.expected_id().unwrap(), original);
    }

    #[test]
    fn payer_authorization_binds_identity_requirement_and_preimage() {
        let requirement = requirement();
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let preimage = Some(format!("0x{}", "55".repeat(32)));
        let payload = PaymentPayload::new_signed(&requirement, preimage, &key).unwrap();
        payload.validate(&requirement).unwrap();

        let mut altered_payer = payload.clone();
        altered_payer.payer = format!("0x{}", "66".repeat(32));
        assert_eq!(
            altered_payer.validate(&requirement),
            Err(ProtocolError::InvalidPayerAuthorization)
        );

        let mut altered_preimage = payload.clone();
        altered_preimage.payment_preimage = Some(format!("0x{}", "77".repeat(32)));
        assert_eq!(
            altered_preimage.validate(&requirement),
            Err(ProtocolError::InvalidPayerAuthorization)
        );

        let mut altered_requirement = requirement.clone();
        altered_requirement.resource = "/api/other".to_string();
        assert!(payload.validate(&altered_requirement).is_err());

        assert_eq!(
            PaymentPayload::new_signed(
                &requirement,
                None,
                &SigningKey::from_slice(&[8; 32]).unwrap(),
            ),
            Err(ProtocolError::InvalidPayerAuthorization)
        );
    }

    #[test]
    fn public_terms_round_trip_without_changing_authority_and_reject_ambiguous_inputs() {
        let original = requirement();
        let value = serde_json::to_value(&original).unwrap();
        assert_eq!(value["expires_at"], u64::MAX.to_string());
        let restored: PaymentRequirements = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(restored, original);
        assert_eq!(restored.expected_id().unwrap(), original.requirement_id);
        let mut reordered = original.clone();
        let mut object = serde_json::Map::new();
        let script = original
            .asset
            .type_script
            .as_ref()
            .unwrap()
            .as_object()
            .unwrap();
        for key in ["hash_type", "code_hash", "args"] {
            object.insert(key.into(), script[key].clone());
        }
        reordered.asset.type_script = Some(Value::Object(object));
        assert_eq!(reordered.expected_id().unwrap(), original.requirement_id);
        for invalid in [
            serde_json::json!(1),
            serde_json::json!("01"),
            serde_json::json!("18446744073709551616"),
        ] {
            let mut bad = value.clone();
            bad["expires_at"] = invalid;
            assert!(serde_json::from_value::<PaymentRequirements>(bad).is_err());
        }
        let mut bad = value.clone();
        bad["asset"]["type_script"]["ignored"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PaymentRequirements>(bad).is_err());
        let mut bad = value;
        bad["asset"]["type_script"]["args"] = serde_json::json!("0xAB");
        assert!(serde_json::from_value::<PaymentRequirements>(bad).is_err());
        for invalid in [
            format!("0x{}", "AB".repeat(32)),
            "11".repeat(32),
            format!("0x{}\n", "11".repeat(32)),
        ] {
            assert!(decode_byte32(&invalid).is_err());
        }
    }

    #[test]
    fn amounts_are_canonical_u128_strings() {
        assert_eq!(parse_amount("1").unwrap(), 1);
        assert!(parse_amount("0").is_err());
        assert!(parse_amount("01").is_err());
        assert!(parse_amount("1.0").is_err());
    }
}
