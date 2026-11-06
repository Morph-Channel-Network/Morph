//! Provider-neutral Payment Gateway payment intents and terminal receipts.
//!
//! These types deliberately contain no Fiber RPC structures. A routing
//! provider may execute an intent, but the canonical commitment and receipt
//! remain Morph-owned and independently verifiable.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::rgbpp::{CkbOutPoint, RgbppAssetId};
use crate::{Amount, Bytes32, blake2b256};

const PAYMENT_GATEWAY_ASSET_DOMAIN: &[u8] = b"CKB_MORPH_PAYMENT_GATEWAY_ASSET_V1";
const PAYMENT_INTENT_DOMAIN: &[u8] = b"CKB_MORPH_PAYMENT_INTENT_V1";
const TERMINAL_RECEIPT_ID_DOMAIN: &[u8] = b"CKB_MORPH_TERMINAL_RECEIPT_ID_V1";
const TERMINAL_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"CKB_MORPH_TERMINAL_RECEIPT_SIGNATURE_V1";
const RECEIPT_SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B: u16 = 1;
const COMPRESSED_PUBKEY_LEN: usize = 33;
const ECDSA_SIGNATURE_LEN: usize = 64;
const MAX_RESOURCE_LEN: usize = 2_048;
const MAX_PROVIDER_ID_LEN: usize = 64;
const MAX_FAILURE_CODE_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GatewayAsset {
    Ckb {
        ckb_genesis_hash: Bytes32,
    },
    Xudt {
        ckb_genesis_hash: Bytes32,
        type_script_hash: Bytes32,
    },
    Rgbpp(RgbppAssetId),
}

impl GatewayAsset {
    pub fn validate(&self) -> GatewayResult<()> {
        match self {
            Self::Ckb { ckb_genesis_hash } => require_nonzero(ckb_genesis_hash),
            Self::Xudt {
                ckb_genesis_hash,
                type_script_hash,
            } => {
                require_nonzero(ckb_genesis_hash)?;
                require_nonzero(type_script_hash)
            }
            Self::Rgbpp(asset) => asset.validate().map_err(GatewayError::Rgbpp),
        }
    }

    pub fn commitment(&self) -> GatewayResult<Bytes32> {
        self.validate()?;
        let mut raw = Vec::with_capacity(PAYMENT_GATEWAY_ASSET_DOMAIN.len() + 130);
        raw.extend_from_slice(PAYMENT_GATEWAY_ASSET_DOMAIN);
        match self {
            Self::Ckb { ckb_genesis_hash } => {
                raw.push(0);
                raw.extend_from_slice(ckb_genesis_hash);
            }
            Self::Xudt {
                ckb_genesis_hash,
                type_script_hash,
            } => {
                raw.push(1);
                raw.extend_from_slice(ckb_genesis_hash);
                raw.extend_from_slice(type_script_hash);
            }
            Self::Rgbpp(asset) => {
                raw.push(2);
                raw.extend_from_slice(&asset.commitment().map_err(GatewayError::Rgbpp)?);
            }
        }
        Ok(blake2b256(&raw))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentHashAlgorithm {
    CkbBlake2b,
    Sha256,
}

impl PaymentHashAlgorithm {
    const fn as_u8(self) -> u8 {
        match self {
            Self::CkbBlake2b => 0,
            Self::Sha256 => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpOperation {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::Get => 0,
            Self::Head => 1,
            Self::Post => 2,
            Self::Put => 3,
            Self::Patch => 4,
            Self::Delete => 5,
        }
    }
}

/// Optional binding to the exact signed Morph state that must result from a
/// successful payment. A Fiber-only payment can omit it; a sovereign Morph
/// channel settlement must include it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphChannelPaymentBinding {
    pub channel_id: Bytes32,
    pub funding_context_id: Bytes32,
    pub expected_settlement_descriptor_commitment: Bytes32,
}

impl MorphChannelPaymentBinding {
    fn validate(&self) -> GatewayResult<()> {
        require_nonzero(&self.channel_id)?;
        require_nonzero(&self.funding_context_id)?;
        require_nonzero(&self.expected_settlement_descriptor_commitment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub intent_id: Bytes32,
    pub payer: Bytes32,
    pub payee: Bytes32,
    pub asset: GatewayAsset,
    pub amount: Amount,
    pub payment_hash: Bytes32,
    pub hash_algorithm: PaymentHashAlgorithm,
    pub resource: String,
    pub operation: HttpOperation,
    pub nonce: Bytes32,
    pub idempotency_key: Bytes32,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    /// Required for RGB++ and forbidden for ordinary CKB/xUDT payments.
    pub required_rgbpp_proof_commitment: Option<Bytes32>,
    pub channel_binding: Option<MorphChannelPaymentBinding>,
}

impl PaymentIntent {
    pub fn derive_id(&self) -> GatewayResult<Bytes32> {
        self.validate_fields(false)?;
        let mut raw = Vec::with_capacity(PAYMENT_INTENT_DOMAIN.len() + self.resource.len() + 384);
        raw.extend_from_slice(PAYMENT_INTENT_DOMAIN);
        raw.extend_from_slice(&self.payer);
        raw.extend_from_slice(&self.payee);
        raw.extend_from_slice(&self.asset.commitment()?);
        raw.extend_from_slice(&self.amount.to_le_bytes());
        raw.extend_from_slice(&self.payment_hash);
        raw.push(self.hash_algorithm.as_u8());
        raw.extend_from_slice(&(self.resource.len() as u16).to_le_bytes());
        raw.extend_from_slice(self.resource.as_bytes());
        raw.push(self.operation.as_u8());
        raw.extend_from_slice(&self.nonce);
        raw.extend_from_slice(&self.idempotency_key);
        raw.extend_from_slice(&self.created_at_unix.to_le_bytes());
        raw.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        match self.required_rgbpp_proof_commitment {
            Some(commitment) => {
                raw.push(1);
                raw.extend_from_slice(&commitment);
            }
            None => raw.push(0),
        }
        match &self.channel_binding {
            Some(binding) => {
                raw.push(1);
                raw.extend_from_slice(&binding.channel_id);
                raw.extend_from_slice(&binding.funding_context_id);
                raw.extend_from_slice(&binding.expected_settlement_descriptor_commitment);
            }
            None => raw.push(0),
        }
        Ok(blake2b256(&raw))
    }

    pub fn validate(&self, now_unix: u64) -> GatewayResult<()> {
        self.validate_fields(true)?;
        if self.intent_id != self.derive_id()? {
            return Err(GatewayError::IntentIdMismatch);
        }
        if now_unix < self.created_at_unix {
            return Err(GatewayError::NotYetValid);
        }
        if now_unix >= self.expires_at_unix {
            return Err(GatewayError::Expired);
        }
        Ok(())
    }

    fn validate_fields(&self, check_intent_id: bool) -> GatewayResult<()> {
        if check_intent_id {
            require_nonzero(&self.intent_id)?;
        }
        require_nonzero(&self.payer)?;
        require_nonzero(&self.payee)?;
        if self.payer == self.payee {
            return Err(GatewayError::SelfPayment);
        }
        self.asset.validate()?;
        if self.amount == 0 {
            return Err(GatewayError::ZeroAmount);
        }
        require_nonzero(&self.payment_hash)?;
        require_nonzero(&self.nonce)?;
        require_nonzero(&self.idempotency_key)?;
        if self.resource.is_empty()
            || self.resource.len() > MAX_RESOURCE_LEN
            || !self.resource.starts_with('/')
            || self.resource.starts_with("//")
            || self.resource.contains("://")
        {
            return Err(GatewayError::InvalidResource);
        }
        if self.expires_at_unix <= self.created_at_unix {
            return Err(GatewayError::InvalidExpiry);
        }
        match (&self.asset, self.required_rgbpp_proof_commitment) {
            (GatewayAsset::Rgbpp(_), Some(commitment)) if !is_zero(&commitment) => {}
            (GatewayAsset::Rgbpp(_), _) | (_, Some(_)) => {
                return Err(GatewayError::InvalidRgbppBinding);
            }
            (_, None) => {}
        }
        if let Some(binding) = &self.channel_binding {
            binding.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalPaymentStatus {
    Settled,
    Cancelled,
    Expired,
    Failed,
}

impl TerminalPaymentStatus {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Settled => 0,
            Self::Cancelled => 1,
            Self::Expired => 2,
            Self::Failed => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphStateSettlementEvidence {
    pub channel_id: Bytes32,
    pub funding_context_id: Bytes32,
    pub state_number: u64,
    pub state_header_commitment: Bytes32,
    pub settlement_descriptor_commitment: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CkbSettlementAnchor {
    pub transaction: CkbOutPoint,
    pub block_hash: Bytes32,
    pub block_number: u64,
    pub confirmations: u64,
}

/// Provider evidence is opaque to the Payment Gateway protocol except for stable Morph
/// and optional CKB anchors. This lets Fiber be replaced without changing the
/// terminal receipt format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSettlementEvidence {
    pub provider_id: String,
    pub settlement_id: Bytes32,
    pub opaque_commitment: Bytes32,
    pub morph_state: Option<MorphStateSettlementEvidence>,
    pub ckb_anchor: Option<CkbSettlementAnchor>,
    pub rgbpp_proof_commitment: Option<Bytes32>,
    pub failure_code: Option<String>,
}

impl BackendSettlementEvidence {
    fn validate(&self, status: TerminalPaymentStatus) -> GatewayResult<()> {
        if self.provider_id.is_empty() || self.provider_id.len() > MAX_PROVIDER_ID_LEN {
            return Err(GatewayError::InvalidBackendEvidence);
        }
        require_nonzero(&self.settlement_id)?;
        require_nonzero(&self.opaque_commitment)?;
        if let Some(state) = &self.morph_state {
            require_nonzero(&state.channel_id)?;
            require_nonzero(&state.funding_context_id)?;
            require_nonzero(&state.state_header_commitment)?;
            require_nonzero(&state.settlement_descriptor_commitment)?;
        }
        if let Some(anchor) = &self.ckb_anchor {
            require_nonzero(&anchor.transaction.tx_hash)?;
            require_nonzero(&anchor.block_hash)?;
            if anchor.confirmations == 0 {
                return Err(GatewayError::InvalidBackendEvidence);
            }
        }
        if self
            .rgbpp_proof_commitment
            .is_some_and(|value| is_zero(&value))
        {
            return Err(GatewayError::InvalidBackendEvidence);
        }
        match status {
            TerminalPaymentStatus::Failed => {
                let code = self
                    .failure_code
                    .as_deref()
                    .ok_or(GatewayError::InvalidBackendEvidence)?;
                if code.is_empty() || code.len() > MAX_FAILURE_CODE_LEN {
                    return Err(GatewayError::InvalidBackendEvidence);
                }
                Ok(())
            }
            _ if self.failure_code.is_none() => Ok(()),
            _ => Err(GatewayError::InvalidBackendEvidence),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.provider_id.len() as u16).to_le_bytes());
        out.extend_from_slice(self.provider_id.as_bytes());
        out.extend_from_slice(&self.settlement_id);
        out.extend_from_slice(&self.opaque_commitment);
        match &self.morph_state {
            Some(state) => {
                out.push(1);
                out.extend_from_slice(&state.channel_id);
                out.extend_from_slice(&state.funding_context_id);
                out.extend_from_slice(&state.state_number.to_le_bytes());
                out.extend_from_slice(&state.state_header_commitment);
                out.extend_from_slice(&state.settlement_descriptor_commitment);
            }
            None => out.push(0),
        }
        match &self.ckb_anchor {
            Some(anchor) => {
                out.push(1);
                out.extend_from_slice(&anchor.transaction.tx_hash);
                out.extend_from_slice(&anchor.transaction.index.to_le_bytes());
                out.extend_from_slice(&anchor.block_hash);
                out.extend_from_slice(&anchor.block_number.to_le_bytes());
                out.extend_from_slice(&anchor.confirmations.to_le_bytes());
            }
            None => out.push(0),
        }
        match self.rgbpp_proof_commitment {
            Some(commitment) => {
                out.push(1);
                out.extend_from_slice(&commitment);
            }
            None => out.push(0),
        }
        match &self.failure_code {
            Some(code) => {
                out.push(1);
                out.extend_from_slice(&(code.len() as u16).to_le_bytes());
                out.extend_from_slice(code.as_bytes());
            }
            None => out.push(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSettlementReceipt {
    pub receipt_id: Bytes32,
    pub intent_id: Bytes32,
    pub status: TerminalPaymentStatus,
    pub evidence: BackendSettlementEvidence,
    pub finalised_at_unix: u64,
    pub signer_pubkey_sec1: Vec<u8>,
    pub signature_scheme_id: u16,
    pub signature: Vec<u8>,
}

impl TerminalSettlementReceipt {
    pub fn new_signed(
        intent: &PaymentIntent,
        status: TerminalPaymentStatus,
        evidence: BackendSettlementEvidence,
        finalised_at_unix: u64,
        signing_key: &SigningKey,
    ) -> GatewayResult<Self> {
        intent.validate_fields(true)?;
        if intent.intent_id != intent.derive_id()? {
            return Err(GatewayError::IntentIdMismatch);
        }
        evidence.validate(status)?;
        let signer_pubkey_sec1 = signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        let mut receipt = Self {
            receipt_id: [0; 32],
            intent_id: intent.intent_id,
            status,
            evidence,
            finalised_at_unix,
            signer_pubkey_sec1,
            signature_scheme_id: RECEIPT_SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
            signature: Vec::new(),
        };
        receipt.validate_against_intent(intent)?;
        receipt.receipt_id = receipt.derive_id();
        let signature: Signature = signing_key
            .sign_prehash(&receipt.signing_digest())
            .map_err(|_| GatewayError::InvalidSignature)?;
        receipt.signature = signature.to_bytes().to_vec();
        receipt.validate_for_signer(signing_key.verifying_key().to_sec1_point(true).as_bytes())?;
        Ok(receipt)
    }

    pub fn validate(&self) -> GatewayResult<()> {
        require_nonzero(&self.intent_id)?;
        self.evidence.validate(self.status)?;
        if self.receipt_id != self.derive_id()
            || self.signature_scheme_id != RECEIPT_SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B
            || self.signer_pubkey_sec1.len() != COMPRESSED_PUBKEY_LEN
            || self.signature.len() != ECDSA_SIGNATURE_LEN
        {
            return Err(GatewayError::InvalidReceipt);
        }
        let key = VerifyingKey::from_sec1_bytes(&self.signer_pubkey_sec1)
            .map_err(|_| GatewayError::InvalidSignature)?;
        if key.to_sec1_point(true).as_bytes() != self.signer_pubkey_sec1 {
            return Err(GatewayError::InvalidSignature);
        }
        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|_| GatewayError::InvalidSignature)?;
        if signature.normalize_s() != signature {
            return Err(GatewayError::InvalidSignature);
        }
        key.verify_prehash(&self.signing_digest(), &signature)
            .map_err(|_| GatewayError::InvalidSignature)
    }

    /// Validate the receipt signature against a deployment-pinned signer.
    /// A self-contained public key is not, by itself, an identity trust root.
    pub fn validate_for_signer(&self, expected_pubkey_sec1: &[u8]) -> GatewayResult<()> {
        self.validate()?;
        if self.signer_pubkey_sec1 != expected_pubkey_sec1 {
            return Err(GatewayError::UnexpectedReceiptSigner);
        }
        Ok(())
    }

    /// Validate time, RGB++, and Morph state evidence against the canonical
    /// intent whose identifier is carried by this receipt.
    pub fn validate_against_intent(&self, intent: &PaymentIntent) -> GatewayResult<()> {
        intent.validate_fields(true)?;
        if intent.intent_id != intent.derive_id()? || self.intent_id != intent.intent_id {
            return Err(GatewayError::IntentIdMismatch);
        }
        if self.finalised_at_unix < intent.created_at_unix {
            return Err(GatewayError::InvalidReceipt);
        }
        match self.status {
            TerminalPaymentStatus::Expired if self.finalised_at_unix < intent.expires_at_unix => {
                return Err(GatewayError::InvalidReceipt);
            }
            TerminalPaymentStatus::Settled
            | TerminalPaymentStatus::Cancelled
            | TerminalPaymentStatus::Failed
                if self.finalised_at_unix >= intent.expires_at_unix =>
            {
                return Err(GatewayError::Expired);
            }
            _ => {}
        }
        if self.status == TerminalPaymentStatus::Settled {
            if self.evidence.rgbpp_proof_commitment != intent.required_rgbpp_proof_commitment {
                return Err(GatewayError::InvalidRgbppBinding);
            }
            match (&intent.channel_binding, &self.evidence.morph_state) {
                (Some(binding), Some(state))
                    if state.channel_id == binding.channel_id
                        && state.funding_context_id == binding.funding_context_id
                        && state.settlement_descriptor_commitment
                            == binding.expected_settlement_descriptor_commitment =>
                {
                    Ok(())
                }
                (None, None) => Ok(()),
                _ => Err(GatewayError::InvalidBackendEvidence),
            }?;
        } else if self.evidence.morph_state.is_some()
            || self.evidence.ckb_anchor.is_some()
            || self.evidence.rgbpp_proof_commitment.is_some()
        {
            return Err(GatewayError::InvalidBackendEvidence);
        }
        Ok(())
    }

    pub fn derive_id(&self) -> Bytes32 {
        let mut raw = Vec::with_capacity(TERMINAL_RECEIPT_ID_DOMAIN.len() + 512);
        raw.extend_from_slice(TERMINAL_RECEIPT_ID_DOMAIN);
        raw.extend_from_slice(&self.intent_id);
        raw.push(self.status.as_u8());
        self.evidence.encode(&mut raw);
        raw.extend_from_slice(&self.finalised_at_unix.to_le_bytes());
        raw.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        raw.extend_from_slice(&self.signer_pubkey_sec1);
        blake2b256(&raw)
    }

    pub fn signing_digest(&self) -> Bytes32 {
        let mut raw = Vec::with_capacity(TERMINAL_RECEIPT_SIGNATURE_DOMAIN.len() + 64);
        raw.extend_from_slice(TERMINAL_RECEIPT_SIGNATURE_DOMAIN);
        raw.extend_from_slice(&self.receipt_id);
        blake2b256(&raw)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatewayError {
    #[error("Payment Gateway protocol identifier must not be zero")]
    ZeroIdentifier,
    #[error("Payment Gateway payment amount must be positive")]
    ZeroAmount,
    #[error("payer and payee must differ")]
    SelfPayment,
    #[error("payment intent resource is invalid")]
    InvalidResource,
    #[error("payment intent expiry is invalid")]
    InvalidExpiry,
    #[error("payment intent has expired")]
    Expired,
    #[error("payment intent is not yet valid")]
    NotYetValid,
    #[error("payment intent id does not match its canonical fields")]
    IntentIdMismatch,
    #[error("payment intent RGB++ proof binding is missing or unexpected")]
    InvalidRgbppBinding,
    #[error("backend settlement evidence is invalid")]
    InvalidBackendEvidence,
    #[error("terminal receipt is invalid")]
    InvalidReceipt,
    #[error("terminal receipt signature is invalid")]
    InvalidSignature,
    #[error("terminal receipt signer does not match the trusted deployment identity")]
    UnexpectedReceiptSigner,
    #[error(transparent)]
    Rgbpp(#[from] crate::rgbpp::RgbppError),
}

pub type GatewayResult<T> = Result<T, GatewayError>;

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn require_nonzero(value: &Bytes32) -> GatewayResult<()> {
    if is_zero(value) {
        Err(GatewayError::ZeroIdentifier)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> PaymentIntent {
        let mut intent = PaymentIntent {
            intent_id: [0; 32],
            payer: [1; 32],
            payee: [2; 32],
            asset: GatewayAsset::Xudt {
                ckb_genesis_hash: [3; 32],
                type_script_hash: [4; 32],
            },
            amount: 42,
            payment_hash: [5; 32],
            hash_algorithm: PaymentHashAlgorithm::Sha256,
            resource: "/v1/result".to_string(),
            operation: HttpOperation::Get,
            nonce: [6; 32],
            idempotency_key: [7; 32],
            created_at_unix: 100,
            expires_at_unix: 200,
            required_rgbpp_proof_commitment: None,
            channel_binding: Some(MorphChannelPaymentBinding {
                channel_id: [8; 32],
                funding_context_id: [9; 32],
                expected_settlement_descriptor_commitment: [10; 32],
            }),
        };
        intent.intent_id = intent.derive_id().unwrap();
        intent
    }

    fn evidence() -> BackendSettlementEvidence {
        BackendSettlementEvidence {
            provider_id: "morph-bilateral".to_string(),
            settlement_id: [11; 32],
            opaque_commitment: [12; 32],
            morph_state: Some(MorphStateSettlementEvidence {
                channel_id: [8; 32],
                funding_context_id: [9; 32],
                state_number: 3,
                state_header_commitment: [13; 32],
                settlement_descriptor_commitment: [10; 32],
            }),
            ckb_anchor: None,
            rgbpp_proof_commitment: None,
            failure_code: None,
        }
    }

    #[test]
    fn intent_id_binds_asset_resource_and_channel_result() {
        let intent = intent();
        assert_eq!(intent.validate(99), Err(GatewayError::NotYetValid));
        intent.validate(150).unwrap();

        let mut substituted = intent.clone();
        substituted.resource = "/v1/other".to_string();
        assert_eq!(
            substituted.validate(150),
            Err(GatewayError::IntentIdMismatch)
        );

        let mut descriptor = intent;
        descriptor
            .channel_binding
            .as_mut()
            .unwrap()
            .expected_settlement_descriptor_commitment = [14; 32];
        assert_eq!(
            descriptor.validate(150),
            Err(GatewayError::IntentIdMismatch)
        );
    }

    #[test]
    fn signed_terminal_receipt_detects_evidence_tampering() {
        let key = SigningKey::from_slice(&[15; 32]).unwrap();
        let receipt = TerminalSettlementReceipt::new_signed(
            &intent(),
            TerminalPaymentStatus::Settled,
            evidence(),
            160,
            &key,
        )
        .unwrap();
        receipt.validate().unwrap();

        let mut tampered = receipt;
        tampered.evidence.opaque_commitment = [16; 32];
        assert_eq!(tampered.validate(), Err(GatewayError::InvalidReceipt));
    }

    #[test]
    fn terminal_receipt_requires_the_pinned_signer_and_exact_morph_binding() {
        let key = SigningKey::from_slice(&[15; 32]).unwrap();
        let other_key = SigningKey::from_slice(&[16; 32]).unwrap();
        let receipt = TerminalSettlementReceipt::new_signed(
            &intent(),
            TerminalPaymentStatus::Settled,
            evidence(),
            160,
            &key,
        )
        .unwrap();
        assert_eq!(
            receipt.validate_for_signer(other_key.verifying_key().to_sec1_point(true).as_bytes(),),
            Err(GatewayError::UnexpectedReceiptSigner)
        );

        let mut wrong_binding = evidence();
        wrong_binding
            .morph_state
            .as_mut()
            .unwrap()
            .funding_context_id = [18; 32];
        assert_eq!(
            TerminalSettlementReceipt::new_signed(
                &intent(),
                TerminalPaymentStatus::Settled,
                wrong_binding,
                160,
                &key,
            ),
            Err(GatewayError::InvalidBackendEvidence)
        );
    }

    #[test]
    fn terminal_status_time_cannot_cross_the_intent_expiry() {
        let key = SigningKey::from_slice(&[19; 32]).unwrap();
        assert_eq!(
            TerminalSettlementReceipt::new_signed(
                &intent(),
                TerminalPaymentStatus::Settled,
                evidence(),
                200,
                &key,
            ),
            Err(GatewayError::Expired)
        );
        let mut expired_evidence = evidence();
        expired_evidence.morph_state = None;
        assert_eq!(
            TerminalSettlementReceipt::new_signed(
                &intent(),
                TerminalPaymentStatus::Expired,
                expired_evidence.clone(),
                199,
                &key,
            ),
            Err(GatewayError::InvalidReceipt)
        );
        TerminalSettlementReceipt::new_signed(
            &intent(),
            TerminalPaymentStatus::Expired,
            expired_evidence,
            200,
            &key,
        )
        .unwrap();
    }

    #[test]
    fn failed_receipt_requires_a_failure_code() {
        let key = SigningKey::from_slice(&[17; 32]).unwrap();
        assert_eq!(
            TerminalSettlementReceipt::new_signed(
                &intent(),
                TerminalPaymentStatus::Failed,
                evidence(),
                160,
                &key,
            ),
            Err(GatewayError::InvalidBackendEvidence)
        );
    }
}
