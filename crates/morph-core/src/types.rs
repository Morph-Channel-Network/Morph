use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub type Bytes32 = [u8; 32];
pub type Capacity = u64;
pub type Amount = u128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Mode {
    BilateralPlain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    /// Host-side pre-State-Cell lifecycle label; not accepted by current on-chain State headers.
    Funding,
    /// Current on-chain active State phase.
    Active,
    /// Current on-chain settling State phase.
    Settling,
    /// Host-side terminal lifecycle label after local finalisation; not emitted as a State type phase.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelOperation {
    Fund,
    Publish,
    Supersede,
    Finalise,
    Splice,
    Materialise,
}
impl ChannelOperation {
    pub const fn is_publication_or_supersede(self) -> bool {
        matches!(self, Self::Publish | Self::Supersede)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantSignature {
    pub pubkey_sec1: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateAuthorization {
    pub threshold: u8,
    pub signatures: Vec<ParticipantSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRegistry {
    pub xudt_types: BTreeSet<Bytes32>,
}
impl AssetRegistry {
    pub fn contains(&self, asset_type: &Bytes32) -> bool {
        self.xudt_types.contains(asset_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengePolicy {
    pub since_value: u64,
    pub detection_depth: u32,
    pub min_emergency_rebuilds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPolicy {
    pub channel_id: Bytes32,
    pub min_state_number: u64,
    pub max_state_number: u64,
    pub max_fee_per_tx: Capacity,
    pub max_total_fee: Capacity,
    pub already_spent: Capacity,
    pub publication_state_type_hash: Bytes32,
    pub change_lock: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSpend {
    pub channel_id: Bytes32,
    pub state_number: u64,
    pub fee: Capacity,
    pub publication_state_type_hash: Bytes32,
    pub change_lock: Bytes32,
    pub operation: ChannelOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FactoryRightKind {
    Balance,
    ReserveClaim,
    Membership,
    ExitPath,
    SponsorBudgetClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FactoryRightId {
    pub participant: Bytes32,
    pub subchannel: Bytes32,
    pub kind: FactoryRightKind,
    pub asset_type: Option<Bytes32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRight {
    pub id: FactoryRightId,
    pub quantity: Amount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryMerkleSiblingSide {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryMerkleSibling {
    pub side: FactoryMerkleSiblingSide,
    pub hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRightMerkleProof {
    pub right: FactoryRight,
    pub siblings: Vec<FactoryMerkleSibling>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryCompactMerkleSibling {
    pub depth: u16,
    pub hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryCompactRightProof {
    pub right: FactoryRight,
    pub siblings: Vec<FactoryCompactMerkleSibling>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryParticipantKey {
    pub participant: Bytes32,
    pub pubkey_sec1: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryParticipantSignature {
    pub participant: Bytes32,
    pub pubkey_sec1: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CellClass {
    ChannelReserve,
    BusinessCkb,
    BusinessXudt(Bytes32),
    StateCarrier,
    Sponsor,
    Unrelated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedCell {
    pub class: CellClass,
    pub capacity: Capacity,
    pub occupied_capacity: Capacity,
    pub business_ckb: Capacity,
    pub xudt_amount: Amount,
    pub carries_registered_xudt: bool,
    pub uses_channel_vault_lock: bool,
    pub read_by_channel_script: bool,
    pub contributes_to_conservation: bool,
}
impl ClassifiedCell {
    pub fn channel_reserve(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::ChannelReserve,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: true,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn business_ckb(
        capacity: Capacity,
        occupied_capacity: Capacity,
        business_ckb: Capacity,
    ) -> Self {
        Self {
            class: CellClass::BusinessCkb,
            capacity,
            occupied_capacity,
            business_ckb,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: true,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn xudt(
        asset_type: Bytes32,
        capacity: Capacity,
        occupied_capacity: Capacity,
        amount: Amount,
    ) -> Self {
        Self {
            class: CellClass::BusinessXudt(asset_type),
            capacity,
            occupied_capacity,
            business_ckb: capacity.saturating_sub(occupied_capacity),
            xudt_amount: amount,
            carries_registered_xudt: true,
            uses_channel_vault_lock: true,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn state_carrier(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::StateCarrier,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: false,
            read_by_channel_script: true,
            contributes_to_conservation: true,
        }
    }

    pub fn sponsor(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::Sponsor,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: false,
            read_by_channel_script: false,
            contributes_to_conservation: false,
        }
    }

    pub fn unrelated(capacity: Capacity, occupied_capacity: Capacity) -> Self {
        Self {
            class: CellClass::Unrelated,
            capacity,
            occupied_capacity,
            business_ckb: 0,
            xudt_amount: 0,
            carries_registered_xudt: false,
            uses_channel_vault_lock: false,
            read_by_channel_script: false,
            contributes_to_conservation: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionedTransaction {
    pub inputs: Vec<ClassifiedCell>,
    pub outputs: Vec<ClassifiedCell>,
    pub tx_fee: Capacity,
    pub authorised_reserve_refund: Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionTotals {
    pub reserve_in: Capacity,
    pub reserve_out: Capacity,
    pub business_ckb_in: Capacity,
    pub business_ckb_out: Capacity,
    pub xudt_in: BTreeMap<Bytes32, Amount>,
    pub xudt_out: BTreeMap<Bytes32, Amount>,
    pub state_carrier_in: Capacity,
    pub state_carrier_out: Capacity,
    pub sponsor_in: Capacity,
    pub sponsor_out: Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VaultAsset {
    Ckb,
    Xudt(Bytes32),
}
pub fn bytes32(tag: u8) -> Bytes32 {
    [tag; 32]
}
