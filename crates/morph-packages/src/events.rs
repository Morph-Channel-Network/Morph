//! Public event and pagination DTOs only: no database or network dependencies.
#[derive(Debug)]
pub struct EventError;
impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid current public event")
    }
}
impl std::error::Error for EventError {}
type Result<T> = std::result::Result<T, EventError>;
fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut input = domain.to_vec();
    input.extend_from_slice(bytes);
    hex::encode(morph_core::blake2b256(&input))
}
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_EVENT_BYTES: usize = 8192;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventSchema {
    #[serde(rename = "morph.event.v1")]
    Current,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Hub,
    Gateway,
    Watch,
    Operation,
    Edge,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    LocalRecord,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
/// These describe local component records, not independently verified chain outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    EdgeObserved,
    EdgeObservationInvalidated,
    EdgeMutationQueued,
    EdgeMutationAcknowledged,
    EdgeMutationAbandoned,
    OperationRegistered,
    OperationBroadcastIntent,
    OperationObserved,
    WatchReorgDetected,
    WatchRecoveryInvalid,
    WatchPublicationFailed,
    WatchOlderStateDetected,
    WatchPublicationSubmitted,
    WatchSpliceDetected,
    WatchSplicePackageStale,
    WatchSplicePublicationSubmitted,
    WatchScanIdle,
    GatewayInitialized,
    GatewayChallengeCreated,
    GatewayOfferCreated,
    GatewayPaymentRecorded,
    GatewayReceiptIssued,
    GatewayOutgoingReserved,
    GatewayOutgoingSucceeded,
    GatewayOutgoingFailed,
    StateRestored,
    PeerConnected,
    InvoiceCreated,
    InvoiceReceived,
    InvoiceSettled,
    ChannelOpened,
    ChannelSpliced,
    StatePublished,
    ChannelFinalised,
    ConditionalBatchImported,
    RootFundingProposed,
    RootFundingSignatureReceived,
    MultiAssetRecoveryImported,
    FactoryOpened,
    FactoryAdvanced,
    FactoryChildMaterialised,
}
impl Kind {
    pub fn component(self) -> Component {
        match self {
            Self::EdgeObserved
            | Self::EdgeObservationInvalidated
            | Self::EdgeMutationQueued
            | Self::EdgeMutationAcknowledged
            | Self::EdgeMutationAbandoned => Component::Edge,
            Self::OperationRegistered
            | Self::OperationBroadcastIntent
            | Self::OperationObserved => Component::Operation,
            Self::WatchReorgDetected
            | Self::WatchRecoveryInvalid
            | Self::WatchPublicationFailed
            | Self::WatchOlderStateDetected
            | Self::WatchPublicationSubmitted
            | Self::WatchSpliceDetected
            | Self::WatchSplicePackageStale
            | Self::WatchSplicePublicationSubmitted
            | Self::WatchScanIdle => Component::Watch,
            Self::GatewayInitialized
            | Self::GatewayChallengeCreated
            | Self::GatewayOfferCreated
            | Self::GatewayPaymentRecorded
            | Self::GatewayReceiptIssued
            | Self::GatewayOutgoingReserved
            | Self::GatewayOutgoingSucceeded
            | Self::GatewayOutgoingFailed => Component::Gateway,
            _ => Component::Hub,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub schema: EventSchema,
    #[schemars(length(min = 64, max = 64), regex(pattern = "^[0-9a-f]+$"))]
    pub event_id: String,
    #[schemars(length(min = 64, max = 64), regex(pattern = "^[0-9a-f]+$"))]
    pub source_id: String,
    #[serde(with = "crate::public_encoding::decimal")]
    #[schemars(schema_with = "crate::public_encoding::decimal::schema")]
    pub source_revision: u64,
    #[serde(with = "crate::public_encoding::decimal")]
    #[schemars(schema_with = "crate::public_encoding::decimal::schema")]
    pub created_at_ms: u64,
    pub component: Component,
    pub evidence_level: EvidenceLevel,
    pub kind: Kind,
    pub severity: Severity,
    #[schemars(length(min = 64, max = 64), regex(pattern = "^[0-9a-f]+$"))]
    pub correlation_id: String,
    #[serde(deserialize_with = "required")]
    #[schemars(required)]
    pub subject_id: Option<String>,
    #[serde(deserialize_with = "required")]
    #[schemars(required)]
    pub funding_context_id: Option<String>,
    #[serde(deserialize_with = "required")]
    #[schemars(required)]
    pub payment_hash: Option<String>,
    #[serde(with = "crate::public_encoding::optional_decimal")]
    #[schemars(schema_with = "crate::public_encoding::optional_decimal::schema")]
    pub provider_revision: Option<u64>,
    /// Reference only: never embed an immutable publication attempt or private exit.
    #[serde(deserialize_with = "required")]
    #[schemars(required)]
    pub evidence_digest: Option<String>,
}
fn required<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::deserialize(d)
}
impl EventEnvelope {
    pub fn identity(source_id: &str, outbox_id: &str) -> String {
        digest(
            b"morph.event.id.v1\0",
            format!("{source_id}:{outbox_id}").as_bytes(),
        )
    }
    pub fn validate(&self) -> Result<()> {
        if self.component != self.kind.component()
            || !is_hash(&self.event_id)
            || !is_hash(&self.source_id)
            || !is_hash(&self.correlation_id)
            || self.source_revision == 0
            || self.created_at_ms == 0
            || [
                &self.subject_id,
                &self.funding_context_id,
                &self.payment_hash,
                &self.evidence_digest,
            ]
            .iter()
            .any(|v| v.as_ref().is_some_and(|s| !is_hash(s)))
        {
            return Err(EventError);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| EventError)?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(EventError);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(EventError);
        }
        let event: Self = serde_json::from_slice(bytes).map_err(|_| EventError)?;
        event.validate()?;
        Ok(event)
    }
    pub fn correlation(operation_id: &str) -> String {
        digest(b"morph.event.correlation.v1\0", operation_id.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    pub source_id: String,
    #[serde(with = "crate::public_encoding::decimal")]
    #[schemars(schema_with = "crate::public_encoding::decimal::schema")]
    pub revision: u64,
    #[schemars(length(max = 128))]
    pub outbox_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventPageRequest {
    #[serde(deserialize_with = "required_cursor")]
    #[schemars(required)]
    pub after: Option<EventCursor>,
    #[schemars(range(min = 1, max = 64))]
    pub limit: u16,
}
fn required_cursor<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<EventCursor>, D::Error> {
    Option::deserialize(d)
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventPage {
    #[schemars(length(max = 64))]
    pub events: Vec<EventEnvelope>,
    pub next: EventCursor,
    pub has_more: bool,
}

impl EventPage {
    pub fn valid_for(&self, request: &EventPageRequest) -> bool {
        if !(1..=64).contains(&request.limit)
            || self.events.len() > request.limit as usize
            || !is_hash(&self.next.source_id)
            || self.next.outbox_id.len() > 128
            || (self.has_more && self.events.len() != request.limit as usize)
            || request.after.as_ref().is_some_and(|c| {
                c.source_id != self.next.source_id || c.revision > self.next.revision
            })
        {
            return false;
        }
        if self.events.is_empty() {
            return !self.has_more
                && match &request.after {
                    Some(after) => *after == self.next,
                    None => self.next.revision == 0 && self.next.outbox_id.is_empty(),
                };
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut revision = request.after.as_ref().map_or(0, |c| c.revision);
        for event in &self.events {
            if event.validate().is_err()
                || event.source_id != self.next.source_id
                || event.source_revision < revision
                || !ids.insert(&event.event_id)
            {
                return false;
            }
            revision = event.source_revision;
        }
        self.events.last().is_some_and(|event| {
            event.source_revision == self.next.revision
                && event.event_id
                    == EventEnvelope::identity(&self.next.source_id, &self.next.outbox_id)
        })
    }
}

/// Watch-source egress permission, persisted with each checkpoint. The local
/// display projection is separate; no policy means no external delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeliveryPolicy {
    schema: DeliveryPolicySchema,
    pub allowed: bool,
}
impl SourceDeliveryPolicy {
    pub fn new(allowed: bool) -> Self {
        Self {
            schema: DeliveryPolicySchema::Current,
            allowed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum DeliveryPolicySchema {
    #[serde(rename = "morph.event.source_policy.v1")]
    Current,
}
