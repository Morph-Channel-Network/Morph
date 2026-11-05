use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::blake2b256;
use crate::types::{Amount, Bytes32, Capacity, Phase};

const INVOICE_PAYLOAD_MAGIC: &[u8] = b"CKB_MORPH_INVOICE";
const INVOICE_ID_DOMAIN: &[u8] = b"CKB_MORPH_INVOICE_ID";
const INVOICE_SIGNATURE_DOMAIN: &[u8] = b"CKB_MORPH_INVOICE_SIGNATURE";
const INVOICE_SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B: u16 = 1;
const INVOICE_PAYEE_PUBKEY_LEN: usize = 33;
const INVOICE_SIGNATURE_LEN: usize = 64;
const INVOICE_HRP: &str = "morph";
const MAX_INVOICE_DESCRIPTION_LEN: usize = 280;
const MAX_CKB_INVOICE_AMOUNT: Amount = u64::MAX as Amount;
const MAX_PEER_ALIAS_LEN: usize = 80;
pub const FACTORY_MIN_PARTICIPANTS: usize = morph_script_common::FACTORY_MIN_PARTICIPANTS as usize;
pub const FACTORY_MAX_PARTICIPANTS: usize = morph_script_common::FACTORY_MAX_PARTICIPANTS as usize;
const BECH32M_CHECKSUM_CONST: u32 = 0x2bc8_30a3;
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NodeError {
    #[error("node id must not be zero")]
    ZeroNodeId,
    #[error("identifier must not be zero")]
    ZeroIdentifier,
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("CKB invoice amount exceeds the maximum shannon quantity")]
    InvoiceAmountTooLarge,
    #[error("invoice expiry must be later than creation time")]
    InvoiceExpiryNotAfterCreation,
    #[error("invoice description is too long")]
    InvoiceDescriptionTooLong,
    #[error("invoice has an unsupported prefix")]
    InvoicePrefixMismatch,
    #[error("invoice checksum mismatch")]
    InvoiceChecksumMismatch,
    #[error("invoice payload is malformed")]
    InvoicePayloadMalformed,
    #[error("invoice id does not match its canonical fields")]
    InvoiceIdMismatch,
    #[error("invoice has expired")]
    InvoiceExpired,
    #[error("invoice is not open")]
    InvoiceNotOpen,
    #[error("payment preimage does not match invoice hash")]
    InvoicePreimageMismatch,
    #[error("payment preimage must not be zero")]
    ZeroPaymentPreimage,
    #[error("invoice already exists")]
    InvoiceAlreadyExists,
    #[error("invoice was not found")]
    InvoiceNotFound,
    #[error("invoice network does not match the local node network")]
    InvoiceNetworkMismatch,
    #[error("invoice payee is the local node")]
    SelfInvoice,
    #[error("invoice payee public key encoding is invalid")]
    InvoicePayeePubkeyEncoding,
    #[error("invoice payee public key does not match the payee node id")]
    InvoicePayeePubkeyMismatch,
    #[error("invoice signature scheme is unsupported")]
    InvoiceUnsupportedSignatureScheme,
    #[error("invoice payee signature encoding is invalid")]
    InvoiceSignatureEncoding,
    #[error("invoice payee signature is invalid")]
    InvoiceSignatureInvalid,
    #[error("peer was not found")]
    PeerNotFound,
    #[error("peer already exists")]
    PeerAlreadyExists,
    #[error("peer must not be the local node")]
    SelfPeer,
    #[error("peer alias must not be empty")]
    PeerAliasEmpty,
    #[error("peer alias is too long")]
    PeerAliasTooLong,
    #[error("channel already exists")]
    ChannelAlreadyExists,
    #[error("channel was not found")]
    ChannelNotFound,
    #[error("channel is not active")]
    ChannelNotActive,
    #[error("channel is not settling")]
    ChannelNotSettling,
    #[error("state number must advance")]
    StateNumberNotAdvanced,
    #[error("funding epoch must advance")]
    FundingEpochNotAdvanced,
    #[error("funding context must change")]
    FundingContextUnchanged,
    #[error("published state uses the wrong funding context")]
    FundingContextMismatch,
    #[error("factory already exists")]
    FactoryAlreadyExists,
    #[error("factory was not found")]
    FactoryNotFound,
    #[error("factory must include the local node")]
    FactoryMissingLocalParticipant,
    #[error("factory participant count is outside the supported dynamic range")]
    FactoryParticipantCountUnsupported,
    #[error("factory child counterparty is not a factory participant")]
    FactoryChildCounterpartyNotParticipant,
    #[error("factory update number must advance")]
    FactoryUpdateNotAdvanced,
    #[error("factory child channel id is already in use")]
    FactoryChildAlreadyMaterialised,
    #[error("asset balance total overflow")]
    AssetBalanceOverflow,
}

pub type NodeResult<T> = std::result::Result<T, NodeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MorphNetwork {
    Devnet,
    Testnet,
    Mainnet,
}

impl MorphNetwork {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Devnet => 1,
            Self::Testnet => 2,
            Self::Mainnet => 3,
        }
    }

    const fn from_u8(value: u8) -> NodeResult<Self> {
        match value {
            1 => Ok(Self::Devnet),
            2 => Ok(Self::Testnet),
            3 => Ok(Self::Mainnet),
            _ => Err(NodeError::InvoicePayloadMalformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MorphAsset {
    Ckb,
    Xudt(Bytes32),
}

impl MorphAsset {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ckb => out.push(0),
            Self::Xudt(type_hash) => {
                out.push(1);
                out.extend_from_slice(type_hash);
            }
        }
    }

    fn decode(cursor: &mut ByteCursor<'_>) -> NodeResult<Self> {
        match cursor.read_u8()? {
            0 => Ok(Self::Ckb),
            1 => Ok(Self::Xudt(cursor.read_bytes32()?)),
            _ => Err(NodeError::InvoicePayloadMalformed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphInvoice {
    pub invoice_id: Bytes32,
    pub network: MorphNetwork,
    pub payee_node_id: Bytes32,
    pub payee_pubkey_sec1: Vec<u8>,
    pub channel_id: Option<Bytes32>,
    pub asset: MorphAsset,
    pub amount: Amount,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub payment_hash: Bytes32,
    pub description: String,
    pub signature_scheme_id: u16,
    pub payee_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMorphInvoice {
    pub network: MorphNetwork,
    pub payee_node_id: Bytes32,
    pub channel_id: Option<Bytes32>,
    pub asset: MorphAsset,
    pub amount: Amount,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub payment_preimage: Option<Bytes32>,
    pub payment_hash: Option<Bytes32>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MorphInvoiceStatus {
    Open,
    Received,
    Paid,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMorphInvoice {
    pub invoice: MorphInvoice,
    pub encoded_invoice: String,
    pub status: MorphInvoiceStatus,
    pub received_at_unix: Option<u64>,
    pub paid_at_unix: Option<u64>,
    pub cancelled_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphInvoiceBook {
    invoices: BTreeMap<Bytes32, StoredMorphInvoice>,
}

impl MorphInvoice {
    pub fn new_signed(
        request: NewMorphInvoice,
        payee_signing_key: &SigningKey,
    ) -> NodeResult<Self> {
        let payee_pubkey_sec1 = payee_pubkey_sec1(payee_signing_key);
        let mut invoice = Self::new_unsigned(request, payee_pubkey_sec1)?;
        let digest = invoice.signing_digest();
        let signature: Signature = payee_signing_key
            .sign_prehash(&digest)
            .map_err(|_| NodeError::InvoiceSignatureInvalid)?;
        invoice.payee_signature = signature.to_bytes().to_vec();
        invoice.validate()?;
        Ok(invoice)
    }

    fn new_unsigned(request: NewMorphInvoice, payee_pubkey_sec1: Vec<u8>) -> NodeResult<Self> {
        validate_bytes32_nonzero(&request.payee_node_id, NodeError::ZeroNodeId)?;
        validate_payee_pubkey(&request.payee_node_id, &payee_pubkey_sec1)?;
        if let Some(channel_id) = request.channel_id {
            validate_bytes32_nonzero(&channel_id, NodeError::ZeroIdentifier)?;
        }
        validate_invoice_amount(&request.asset, request.amount)?;
        if request.expires_at_unix <= request.created_at_unix {
            return Err(NodeError::InvoiceExpiryNotAfterCreation);
        }
        if request.description.len() > MAX_INVOICE_DESCRIPTION_LEN {
            return Err(NodeError::InvoiceDescriptionTooLong);
        }
        let payment_hash = match (request.payment_preimage, request.payment_hash) {
            (Some(preimage), None) => {
                validate_bytes32_nonzero(&preimage, NodeError::ZeroPaymentPreimage)?;
                blake2b256(&preimage)
            }
            (None, Some(hash)) => hash,
            (Some(_), Some(_)) | (None, None) => return Err(NodeError::InvoicePayloadMalformed),
        };
        validate_bytes32_nonzero(&payment_hash, NodeError::ZeroIdentifier)?;

        let mut invoice = Self {
            invoice_id: [0u8; 32],
            network: request.network,
            payee_node_id: request.payee_node_id,
            payee_pubkey_sec1,
            channel_id: request.channel_id,
            asset: request.asset,
            amount: request.amount,
            created_at_unix: request.created_at_unix,
            expires_at_unix: request.expires_at_unix,
            payment_hash,
            description: request.description,
            signature_scheme_id: INVOICE_SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B,
            payee_signature: Vec::new(),
        };
        invoice.invoice_id = invoice.derived_invoice_id();
        Ok(invoice)
    }

    pub fn encode(&self) -> String {
        let payload = self.payload_bytes();
        encode_bech32m(INVOICE_HRP, &payload)
    }

    pub fn decode(encoded: &str) -> NodeResult<Self> {
        let payload = decode_bech32m(INVOICE_HRP, encoded)?;
        let invoice = Self::from_payload_bytes(&payload)?;
        if invoice.invoice_id != invoice.derived_invoice_id() {
            return Err(NodeError::InvoiceIdMismatch);
        }
        invoice.validate()?;
        Ok(invoice)
    }

    pub fn validate(&self) -> NodeResult<()> {
        validate_bytes32_nonzero(&self.payee_node_id, NodeError::ZeroNodeId)?;
        validate_bytes32_nonzero(&self.invoice_id, NodeError::ZeroIdentifier)?;
        validate_bytes32_nonzero(&self.payment_hash, NodeError::ZeroIdentifier)?;
        if let Some(channel_id) = self.channel_id {
            validate_bytes32_nonzero(&channel_id, NodeError::ZeroIdentifier)?;
        }
        validate_invoice_amount(&self.asset, self.amount)?;
        if self.expires_at_unix <= self.created_at_unix {
            return Err(NodeError::InvoiceExpiryNotAfterCreation);
        }
        if self.description.len() > MAX_INVOICE_DESCRIPTION_LEN {
            return Err(NodeError::InvoiceDescriptionTooLong);
        }
        if self.invoice_id != self.derived_invoice_id() {
            return Err(NodeError::InvoiceIdMismatch);
        }
        self.verify_payee_signature()?;
        Ok(())
    }

    pub fn is_expired_at(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    pub fn verify_preimage(&self, payment_preimage: &Bytes32) -> NodeResult<()> {
        if blake2b256(payment_preimage) != self.payment_hash {
            return Err(NodeError::InvoicePreimageMismatch);
        }
        Ok(())
    }

    pub fn signing_digest(&self) -> Bytes32 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INVOICE_SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&self.invoice_id);
        self.encode_fields_without_invoice_id(&mut bytes);
        bytes.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        bytes.extend_from_slice(&self.payee_pubkey_sec1);
        blake2b256(&bytes)
    }

    fn verify_payee_signature(&self) -> NodeResult<()> {
        validate_payee_pubkey(&self.payee_node_id, &self.payee_pubkey_sec1)?;
        if self.signature_scheme_id != INVOICE_SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B {
            return Err(NodeError::InvoiceUnsupportedSignatureScheme);
        }
        if self.payee_signature.len() != INVOICE_SIGNATURE_LEN {
            return Err(NodeError::InvoiceSignatureEncoding);
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(&self.payee_pubkey_sec1)
            .map_err(|_| NodeError::InvoicePayeePubkeyEncoding)?;
        let signature = Signature::try_from(self.payee_signature.as_slice())
            .map_err(|_| NodeError::InvoiceSignatureEncoding)?;
        verifying_key
            .verify_prehash(&self.signing_digest(), &signature)
            .map_err(|_| NodeError::InvoiceSignatureInvalid)?;
        Ok(())
    }

    fn derived_invoice_id(&self) -> Bytes32 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INVOICE_ID_DOMAIN);
        self.encode_fields_without_invoice_id(&mut bytes);
        blake2b256(&bytes)
    }

    fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INVOICE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&self.invoice_id);
        self.encode_fields_without_invoice_id(&mut bytes);
        bytes.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        bytes.extend_from_slice(&self.payee_pubkey_sec1);
        bytes.extend_from_slice(&self.payee_signature);
        bytes
    }

    fn encode_fields_without_invoice_id(&self, out: &mut Vec<u8>) {
        out.push(self.network.as_u8());
        out.extend_from_slice(&self.payee_node_id);
        encode_option_bytes32(self.channel_id, out);
        self.asset.encode(out);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.created_at_unix.to_le_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        out.extend_from_slice(&self.payment_hash);
        let description = self.description.as_bytes();
        out.extend_from_slice(&(description.len() as u16).to_le_bytes());
        out.extend_from_slice(description);
    }

    fn from_payload_bytes(payload: &[u8]) -> NodeResult<Self> {
        if !payload.starts_with(INVOICE_PAYLOAD_MAGIC) {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        let mut cursor = ByteCursor::new(&payload[INVOICE_PAYLOAD_MAGIC.len()..]);
        let invoice_id = cursor.read_bytes32()?;
        let network = MorphNetwork::from_u8(cursor.read_u8()?)?;
        let payee_node_id = cursor.read_bytes32()?;
        let channel_id = decode_option_bytes32(&mut cursor)?;
        let asset = MorphAsset::decode(&mut cursor)?;
        let amount = cursor.read_u128()?;
        let created_at_unix = cursor.read_u64()?;
        let expires_at_unix = cursor.read_u64()?;
        let payment_hash = cursor.read_bytes32()?;
        let description_len = cursor.read_u16()? as usize;
        if description_len > MAX_INVOICE_DESCRIPTION_LEN {
            return Err(NodeError::InvoiceDescriptionTooLong);
        }
        let description = cursor.read_string(description_len)?;
        let signature_scheme_id = cursor.read_u16()?;
        let payee_pubkey_sec1 = cursor.read_exact(INVOICE_PAYEE_PUBKEY_LEN)?.to_vec();
        let payee_signature = cursor.read_exact(INVOICE_SIGNATURE_LEN)?.to_vec();
        if !cursor.is_empty() {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        Ok(Self {
            invoice_id,
            network,
            payee_node_id,
            channel_id,
            asset,
            amount,
            created_at_unix,
            expires_at_unix,
            payment_hash,
            description,
            signature_scheme_id,
            payee_signature,
            payee_pubkey_sec1,
        })
    }
}

impl MorphInvoiceBook {
    pub fn records(&self) -> impl Iterator<Item = &StoredMorphInvoice> {
        self.invoices.values()
    }

    pub fn insert_stored(&mut self, stored: StoredMorphInvoice) -> NodeResult<()> {
        stored.invoice.validate()?;
        if stored.encoded_invoice != stored.invoice.encode() {
            return Err(NodeError::InvoiceIdMismatch);
        }
        if self.invoices.contains_key(&stored.invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        self.invoices.insert(stored.invoice.invoice_id, stored);
        Ok(())
    }

    pub fn create_invoice(
        &mut self,
        request: NewMorphInvoice,
        payee_signing_key: &SigningKey,
    ) -> NodeResult<StoredMorphInvoice> {
        let invoice = MorphInvoice::new_signed(request, payee_signing_key)?;
        let encoded_invoice = invoice.encode();
        if self.invoices.contains_key(&invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        let stored = StoredMorphInvoice {
            invoice: invoice.clone(),
            encoded_invoice,
            status: MorphInvoiceStatus::Open,
            received_at_unix: None,
            paid_at_unix: None,
            cancelled_at_unix: None,
        };
        self.invoices.insert(invoice.invoice_id, stored.clone());
        Ok(stored)
    }

    pub fn insert_decoded(&mut self, encoded_invoice: &str) -> NodeResult<StoredMorphInvoice> {
        let invoice = MorphInvoice::decode(encoded_invoice)?;
        if self.invoices.contains_key(&invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        let stored = StoredMorphInvoice {
            invoice: invoice.clone(),
            encoded_invoice: encoded_invoice.to_string(),
            status: MorphInvoiceStatus::Open,
            received_at_unix: None,
            paid_at_unix: None,
            cancelled_at_unix: None,
        };
        self.invoices.insert(invoice.invoice_id, stored.clone());
        Ok(stored)
    }

    pub fn insert_received(
        &mut self,
        invoice: MorphInvoice,
        encoded_invoice: impl Into<String>,
        now_unix: u64,
    ) -> NodeResult<StoredMorphInvoice> {
        if self.invoices.contains_key(&invoice.invoice_id) {
            return Err(NodeError::InvoiceAlreadyExists);
        }
        if invoice.is_expired_at(now_unix) {
            return Err(NodeError::InvoiceExpired);
        }
        let stored = StoredMorphInvoice {
            invoice: invoice.clone(),
            encoded_invoice: encoded_invoice.into(),
            status: MorphInvoiceStatus::Received,
            received_at_unix: Some(now_unix),
            paid_at_unix: None,
            cancelled_at_unix: None,
        };
        self.invoices.insert(invoice.invoice_id, stored.clone());
        Ok(stored)
    }

    pub fn get(&self, invoice_id: &Bytes32) -> NodeResult<&StoredMorphInvoice> {
        self.invoices
            .get(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)
    }

    pub fn receive(&mut self, invoice_id: &Bytes32, now_unix: u64) -> NodeResult<()> {
        let stored = self
            .invoices
            .get_mut(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)?;
        ensure_invoice_open(stored, now_unix)?;
        stored.status = MorphInvoiceStatus::Received;
        stored.received_at_unix = Some(now_unix);
        Ok(())
    }

    pub fn settle(
        &mut self,
        invoice_id: &Bytes32,
        payment_preimage: Bytes32,
        now_unix: u64,
    ) -> NodeResult<()> {
        validate_bytes32_nonzero(&payment_preimage, NodeError::ZeroPaymentPreimage)?;
        let stored = self
            .invoices
            .get_mut(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)?;
        if stored.status != MorphInvoiceStatus::Open
            && stored.status != MorphInvoiceStatus::Received
        {
            return Err(NodeError::InvoiceNotOpen);
        }
        if stored.invoice.is_expired_at(now_unix) {
            stored.status = MorphInvoiceStatus::Expired;
            return Err(NodeError::InvoiceExpired);
        }
        stored.invoice.verify_preimage(&payment_preimage)?;
        stored.status = MorphInvoiceStatus::Paid;
        stored.paid_at_unix = Some(now_unix);
        Ok(())
    }

    pub fn cancel(&mut self, invoice_id: &Bytes32, now_unix: u64) -> NodeResult<()> {
        let stored = self
            .invoices
            .get_mut(invoice_id)
            .ok_or(NodeError::InvoiceNotFound)?;
        ensure_invoice_open(stored, now_unix)?;
        stored.status = MorphInvoiceStatus::Cancelled;
        stored.cancelled_at_unix = Some(now_unix);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphPeer {
    pub node_id: Bytes32,
    pub alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphAssetBalance {
    pub asset: MorphAsset,
    pub local: Amount,
    pub remote: Amount,
    pub pending: Amount,
}

impl MorphAssetBalance {
    pub fn total(&self) -> NodeResult<Amount> {
        self.local
            .checked_add(self.remote)
            .and_then(|value| value.checked_add(self.pending))
            .ok_or(NodeError::AssetBalanceOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphChannelRecord {
    pub channel_id: Bytes32,
    pub counterparty_node_id: Bytes32,
    pub funding_epoch: u64,
    pub funding_context_id: Bytes32,
    pub state_number: u64,
    pub phase: Phase,
    pub balances: Vec<MorphAssetBalance>,
    pub sponsor_budget: Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphFactoryRecord {
    pub factory_id: Bytes32,
    pub participant_node_ids: BTreeSet<Bytes32>,
    pub update_number: u64,
    pub reserve_balances: Vec<MorphAssetBalance>,
    pub materialised_child_channels: BTreeSet<Bytes32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MorphBusinessFlow {
    PeerConnected,
    InvoiceCreated,
    InvoiceReceived,
    InvoiceSettled,
    ChannelOpened,
    StatePublished,
    ChannelFinalised,
    ChannelSpliced,
    FactoryOpened,
    FactoryAdvanced,
    FactoryChildMaterialised,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphNodeState {
    pub node_id: Bytes32,
    pub network: MorphNetwork,
    pub peers: BTreeMap<Bytes32, MorphPeer>,
    pub channels: BTreeMap<Bytes32, MorphChannelRecord>,
    pub factories: BTreeMap<Bytes32, MorphFactoryRecord>,
    pub invoices: MorphInvoiceBook,
    pub completed_flows: BTreeSet<MorphBusinessFlow>,
}

impl MorphNodeState {
    pub fn new(node_id: Bytes32, network: MorphNetwork) -> NodeResult<Self> {
        validate_bytes32_nonzero(&node_id, NodeError::ZeroNodeId)?;
        Ok(Self {
            node_id,
            network,
            peers: BTreeMap::new(),
            channels: BTreeMap::new(),
            factories: BTreeMap::new(),
            invoices: MorphInvoiceBook::default(),
            completed_flows: BTreeSet::new(),
        })
    }

    pub fn required_business_flows() -> BTreeSet<MorphBusinessFlow> {
        BTreeSet::from([
            MorphBusinessFlow::PeerConnected,
            MorphBusinessFlow::InvoiceCreated,
            MorphBusinessFlow::InvoiceReceived,
            MorphBusinessFlow::InvoiceSettled,
            MorphBusinessFlow::ChannelOpened,
            MorphBusinessFlow::StatePublished,
            MorphBusinessFlow::ChannelFinalised,
            MorphBusinessFlow::ChannelSpliced,
            MorphBusinessFlow::FactoryOpened,
            MorphBusinessFlow::FactoryAdvanced,
            MorphBusinessFlow::FactoryChildMaterialised,
        ])
    }

    pub fn missing_business_flows(&self) -> BTreeSet<MorphBusinessFlow> {
        Self::required_business_flows()
            .difference(&self.completed_flows)
            .copied()
            .collect()
    }

    pub fn connect_peer(&mut self, mut peer: MorphPeer) -> NodeResult<()> {
        validate_bytes32_nonzero(&peer.node_id, NodeError::ZeroNodeId)?;
        peer.alias = peer.alias.trim().to_string();
        validate_peer_alias(&peer.alias)?;
        if peer.node_id == self.node_id {
            return Err(NodeError::SelfPeer);
        }
        if self.peers.contains_key(&peer.node_id) {
            return Err(NodeError::PeerAlreadyExists);
        }
        self.peers.insert(peer.node_id, peer);
        self.completed_flows
            .insert(MorphBusinessFlow::PeerConnected);
        Ok(())
    }

    pub fn create_invoice(
        &mut self,
        mut request: NewMorphInvoice,
        payee_signing_key: &SigningKey,
    ) -> NodeResult<StoredMorphInvoice> {
        request.network = self.network;
        request.payee_node_id = self.node_id;
        let stored = self.invoices.create_invoice(request, payee_signing_key)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceCreated);
        Ok(stored)
    }

    pub fn receive_invoice(&mut self, invoice_id: &Bytes32, now_unix: u64) -> NodeResult<()> {
        self.invoices.receive(invoice_id, now_unix)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceReceived);
        Ok(())
    }

    pub fn receive_decoded_invoice(
        &mut self,
        encoded_invoice: &str,
        now_unix: u64,
    ) -> NodeResult<StoredMorphInvoice> {
        let invoice = MorphInvoice::decode(encoded_invoice)?;
        if invoice.network != self.network {
            return Err(NodeError::InvoiceNetworkMismatch);
        }
        if invoice.payee_node_id == self.node_id {
            return Err(NodeError::SelfInvoice);
        }
        let stored =
            self.invoices
                .insert_received(invoice, encoded_invoice.to_string(), now_unix)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceReceived);
        Ok(stored)
    }

    pub fn settle_invoice(
        &mut self,
        invoice_id: &Bytes32,
        payment_preimage: Bytes32,
        now_unix: u64,
    ) -> NodeResult<()> {
        self.invoices
            .settle(invoice_id, payment_preimage, now_unix)?;
        self.completed_flows
            .insert(MorphBusinessFlow::InvoiceSettled);
        Ok(())
    }

    pub fn open_channel(&mut self, channel: MorphChannelRecord) -> NodeResult<()> {
        validate_channel_record(&channel)?;
        if channel.counterparty_node_id == self.node_id {
            return Err(NodeError::SelfPeer);
        }
        if !self.peers.contains_key(&channel.counterparty_node_id) {
            return Err(NodeError::PeerNotFound);
        }
        if self.channels.contains_key(&channel.channel_id) {
            return Err(NodeError::ChannelAlreadyExists);
        }
        self.channels.insert(channel.channel_id, channel);
        self.completed_flows
            .insert(MorphBusinessFlow::ChannelOpened);
        Ok(())
    }

    pub fn publish_state(
        &mut self,
        channel_id: &Bytes32,
        funding_context_id: Bytes32,
        state_number: u64,
    ) -> NodeResult<()> {
        let channel = self
            .channels
            .get_mut(channel_id)
            .ok_or(NodeError::ChannelNotFound)?;
        if channel.phase != Phase::Active && channel.phase != Phase::Settling {
            return Err(NodeError::ChannelNotActive);
        }
        if funding_context_id != channel.funding_context_id {
            return Err(NodeError::FundingContextMismatch);
        }
        if state_number <= channel.state_number {
            return Err(NodeError::StateNumberNotAdvanced);
        }
        channel.state_number = state_number;
        channel.phase = Phase::Settling;
        self.completed_flows
            .insert(MorphBusinessFlow::StatePublished);
        Ok(())
    }

    pub fn finalise_channel(&mut self, channel_id: &Bytes32) -> NodeResult<()> {
        let channel = self
            .channels
            .get_mut(channel_id)
            .ok_or(NodeError::ChannelNotFound)?;
        if channel.phase != Phase::Settling {
            return Err(NodeError::ChannelNotSettling);
        }
        channel.phase = Phase::Closed;
        self.completed_flows
            .insert(MorphBusinessFlow::ChannelFinalised);
        Ok(())
    }

    pub fn splice_channel(
        &mut self,
        channel_id: &Bytes32,
        new_funding_epoch: u64,
        new_funding_context_id: Bytes32,
    ) -> NodeResult<()> {
        validate_bytes32_nonzero(&new_funding_context_id, NodeError::ZeroIdentifier)?;
        let channel = self
            .channels
            .get_mut(channel_id)
            .ok_or(NodeError::ChannelNotFound)?;
        if channel.phase != Phase::Active {
            return Err(NodeError::ChannelNotActive);
        }
        if new_funding_epoch <= channel.funding_epoch {
            return Err(NodeError::FundingEpochNotAdvanced);
        }
        if new_funding_context_id == channel.funding_context_id {
            return Err(NodeError::FundingContextUnchanged);
        }
        channel.funding_epoch = new_funding_epoch;
        channel.funding_context_id = new_funding_context_id;
        self.completed_flows
            .insert(MorphBusinessFlow::ChannelSpliced);
        Ok(())
    }

    pub fn open_factory(&mut self, factory: MorphFactoryRecord) -> NodeResult<()> {
        validate_bytes32_nonzero(&factory.factory_id, NodeError::ZeroIdentifier)?;
        if factory.participant_node_ids.iter().any(is_zero_bytes32) {
            return Err(NodeError::ZeroNodeId);
        }
        if !(FACTORY_MIN_PARTICIPANTS..=FACTORY_MAX_PARTICIPANTS)
            .contains(&factory.participant_node_ids.len())
        {
            return Err(NodeError::FactoryParticipantCountUnsupported);
        }
        if !factory.participant_node_ids.contains(&self.node_id) {
            return Err(NodeError::FactoryMissingLocalParticipant);
        }
        if self.factories.contains_key(&factory.factory_id) {
            return Err(NodeError::FactoryAlreadyExists);
        }
        self.factories.insert(factory.factory_id, factory);
        self.completed_flows
            .insert(MorphBusinessFlow::FactoryOpened);
        Ok(())
    }

    pub fn advance_factory(
        &mut self,
        factory_id: &Bytes32,
        new_update_number: u64,
    ) -> NodeResult<()> {
        let factory = self
            .factories
            .get_mut(factory_id)
            .ok_or(NodeError::FactoryNotFound)?;
        if new_update_number <= factory.update_number {
            return Err(NodeError::FactoryUpdateNotAdvanced);
        }
        factory.update_number = new_update_number;
        self.completed_flows
            .insert(MorphBusinessFlow::FactoryAdvanced);
        Ok(())
    }

    pub fn materialise_child_channel(
        &mut self,
        factory_id: &Bytes32,
        child: MorphChannelRecord,
    ) -> NodeResult<()> {
        validate_channel_record(&child)?;
        if !self.peers.contains_key(&child.counterparty_node_id) {
            return Err(NodeError::PeerNotFound);
        }
        if self.channels.contains_key(&child.channel_id) {
            return Err(NodeError::ChannelAlreadyExists);
        }
        let factory = self
            .factories
            .get_mut(factory_id)
            .ok_or(NodeError::FactoryNotFound)?;
        if !factory
            .participant_node_ids
            .contains(&child.counterparty_node_id)
        {
            return Err(NodeError::FactoryChildCounterpartyNotParticipant);
        }
        if !factory.materialised_child_channels.insert(child.channel_id) {
            return Err(NodeError::FactoryChildAlreadyMaterialised);
        }
        self.channels.insert(child.channel_id, child);
        self.completed_flows
            .insert(MorphBusinessFlow::FactoryChildMaterialised);
        Ok(())
    }
}

fn validate_channel_record(channel: &MorphChannelRecord) -> NodeResult<()> {
    validate_bytes32_nonzero(&channel.channel_id, NodeError::ZeroIdentifier)?;
    validate_bytes32_nonzero(&channel.counterparty_node_id, NodeError::ZeroNodeId)?;
    validate_bytes32_nonzero(&channel.funding_context_id, NodeError::ZeroIdentifier)?;
    for balance in &channel.balances {
        balance.total()?;
    }
    Ok(())
}

fn validate_peer_alias(alias: &str) -> NodeResult<()> {
    if alias.is_empty() {
        return Err(NodeError::PeerAliasEmpty);
    }
    if alias.len() > MAX_PEER_ALIAS_LEN {
        return Err(NodeError::PeerAliasTooLong);
    }
    Ok(())
}

fn ensure_invoice_open(stored: &mut StoredMorphInvoice, now_unix: u64) -> NodeResult<()> {
    if stored.status != MorphInvoiceStatus::Open {
        return Err(NodeError::InvoiceNotOpen);
    }
    if stored.invoice.is_expired_at(now_unix) {
        stored.status = MorphInvoiceStatus::Expired;
        return Err(NodeError::InvoiceExpired);
    }
    Ok(())
}

fn validate_bytes32_nonzero(value: &Bytes32, error: NodeError) -> NodeResult<()> {
    if is_zero_bytes32(value) {
        return Err(error);
    }
    Ok(())
}

fn validate_payee_pubkey(payee_node_id: &Bytes32, payee_pubkey_sec1: &[u8]) -> NodeResult<()> {
    if payee_pubkey_sec1.len() != INVOICE_PAYEE_PUBKEY_LEN {
        return Err(NodeError::InvoicePayeePubkeyEncoding);
    }
    VerifyingKey::from_sec1_bytes(payee_pubkey_sec1)
        .map_err(|_| NodeError::InvoicePayeePubkeyEncoding)?;
    if blake2b256(payee_pubkey_sec1) != *payee_node_id {
        return Err(NodeError::InvoicePayeePubkeyMismatch);
    }
    Ok(())
}

fn payee_pubkey_sec1(payee_signing_key: &SigningKey) -> Vec<u8> {
    payee_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec()
}

fn is_zero_bytes32(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn validate_invoice_amount(asset: &MorphAsset, amount: Amount) -> NodeResult<()> {
    if amount == 0 {
        return Err(NodeError::ZeroAmount);
    }
    if matches!(asset, MorphAsset::Ckb) && amount > MAX_CKB_INVOICE_AMOUNT {
        return Err(NodeError::InvoiceAmountTooLarge);
    }
    Ok(())
}

fn encode_bech32m(hrp: &str, payload: &[u8]) -> String {
    let mut values = bytes_to_base32(payload);
    let checksum = bech32m_create_checksum(hrp, &values);
    values.extend_from_slice(&checksum);

    let mut encoded = String::with_capacity(hrp.len() + 1 + values.len());
    encoded.push_str(hrp);
    encoded.push('1');
    for value in values {
        encoded.push(BECH32_CHARSET[value as usize] as char);
    }
    encoded
}

fn bytes_to_base32(data: &[u8]) -> Vec<u8> {
    const TO_BITS: u32 = 5;
    const MAX_VALUE: u32 = (1 << TO_BITS) - 1;
    const MAX_ACCUMULATOR: u32 = (1 << (8 + TO_BITS - 1)) - 1;

    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(TO_BITS as usize));
    for byte in data {
        accumulator = ((accumulator << 8) | u32::from(*byte)) & MAX_ACCUMULATOR;
        bits += 8;
        while bits >= TO_BITS {
            bits -= TO_BITS;
            out.push(((accumulator >> bits) & MAX_VALUE) as u8);
        }
    }
    if bits > 0 {
        out.push(((accumulator << (TO_BITS - bits)) & MAX_VALUE) as u8);
    }
    out
}

fn decode_bech32m(hrp: &str, encoded: &str) -> NodeResult<Vec<u8>> {
    let has_lower = encoded.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = encoded.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(NodeError::InvoicePayloadMalformed);
    }
    let lower = encoded.to_ascii_lowercase();
    let separator = lower.rfind('1').ok_or(NodeError::InvoicePrefixMismatch)?;
    if separator == 0 || &lower[..separator] != hrp {
        return Err(NodeError::InvoicePrefixMismatch);
    }
    if lower.len() < separator + 1 + 6 {
        return Err(NodeError::InvoicePayloadMalformed);
    }

    let mut values = Vec::with_capacity(lower.len() - separator - 1);
    for byte in lower[separator + 1..].bytes() {
        let value = BECH32_CHARSET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(NodeError::InvoicePayloadMalformed)?;
        values.push(value as u8);
    }
    if !bech32m_verify_checksum(hrp, &values) {
        return Err(NodeError::InvoiceChecksumMismatch);
    }
    convert_bits(&values[..values.len() - 6], 5, 8, false)
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> NodeResult<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to) - 1;
    let max_acc = (1u32 << (from + to - 1)) - 1;
    let mut out = Vec::new();

    for value in data {
        let value = u32::from(*value);
        if value >> from != 0 {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        acc = ((acc << from) | value) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(NodeError::InvoicePayloadMalformed);
    }

    Ok(out)
}

fn bech32m_create_checksum(hrp: &str, values: &[u8]) -> [u8; 6] {
    let mut expanded = bech32_hrp_expand(hrp);
    expanded.extend_from_slice(values);
    expanded.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&expanded) ^ BECH32M_CHECKSUM_CONST;
    let mut checksum = [0u8; 6];
    for (index, value) in checksum.iter_mut().enumerate() {
        *value = ((polymod >> (5 * (5 - index))) & 31) as u8;
    }
    checksum
}

fn bech32m_verify_checksum(hrp: &str, values: &[u8]) -> bool {
    let mut expanded = bech32_hrp_expand(hrp);
    expanded.extend_from_slice(values);
    bech32_polymod(&expanded) == BECH32M_CHECKSUM_CONST
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1);
    for byte in hrp.bytes() {
        expanded.push(byte >> 5);
    }
    expanded.push(0);
    for byte in hrp.bytes() {
        expanded.push(byte & 31);
    }
    expanded
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    for value in values {
        let top = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5 ^ u32::from(*value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if ((top >> index) & 1) == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn encode_option_bytes32(value: Option<Bytes32>, out: &mut Vec<u8>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(&bytes);
        }
        None => out.push(0),
    }
}

fn decode_option_bytes32(cursor: &mut ByteCursor<'_>) -> NodeResult<Option<Bytes32>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.read_bytes32()?)),
        _ => Err(NodeError::InvoicePayloadMalformed),
    }
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_u8(&mut self) -> NodeResult<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> NodeResult<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u64(&mut self) -> NodeResult<u64> {
        let bytes = self.read_exact(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(raw))
    }

    fn read_u128(&mut self) -> NodeResult<u128> {
        let bytes = self.read_exact(16)?;
        let mut raw = [0u8; 16];
        raw.copy_from_slice(bytes);
        Ok(u128::from_le_bytes(raw))
    }

    fn read_bytes32(&mut self) -> NodeResult<Bytes32> {
        let bytes = self.read_exact(32)?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(bytes);
        Ok(raw)
    }

    fn read_string(&mut self, len: usize) -> NodeResult<String> {
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| NodeError::InvoicePayloadMalformed)
    }

    fn read_exact(&mut self, len: usize) -> NodeResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(NodeError::InvoicePayloadMalformed)?;
        if end > self.bytes.len() {
            return Err(NodeError::InvoicePayloadMalformed);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).unwrap()
    }

    fn node_id_for_key(key: &SigningKey) -> Bytes32 {
        blake2b256(key.verifying_key().to_sec1_point(true).as_bytes())
    }

    fn invoice_request(key: &SigningKey) -> NewMorphInvoice {
        NewMorphInvoice {
            network: MorphNetwork::Devnet,
            payee_node_id: node_id_for_key(key),
            channel_id: None,
            asset: MorphAsset::Ckb,
            amount: 42_000,
            created_at_unix: 1_000,
            expires_at_unix: 1_600,
            payment_preimage: Some([9u8; 32]),
            payment_hash: None,
            description: "coffee".to_string(),
        }
    }

    #[test]
    fn invoice_encodes_and_decodes_as_bech32m() {
        let key = signing_key(1);
        let invoice = MorphInvoice::new_signed(invoice_request(&key), &key).unwrap();
        let encoded = invoice.encode();
        assert!(encoded.starts_with("morph1"));
        assert!(
            !encoded["morph1".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
            "new invoices reject the unsupported hex payload encoding"
        );
        assert_eq!(MorphInvoice::decode(&encoded).unwrap(), invoice);
    }

    #[test]
    fn ckb_invoice_amount_is_bounded_to_u64_quantity() {
        let key = signing_key(1);
        let mut request = invoice_request(&key);
        request.amount = u64::MAX as u128 + 1;
        assert_eq!(
            MorphInvoice::new_signed(request.clone(), &key).unwrap_err(),
            NodeError::InvoiceAmountTooLarge
        );

        request.asset = MorphAsset::Xudt([7u8; 32]);
        MorphInvoice::new_signed(request, &key).unwrap();
    }
}
