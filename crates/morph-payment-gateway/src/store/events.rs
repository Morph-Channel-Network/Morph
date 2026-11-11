//! Explicit public projection of a mutation. Never serialize its private
//! recovery instruction, provider response, credentials or receipt signatures.
use super::*;
use morph_packages::events::{
    Component, EventEnvelope, EventSchema, EvidenceLevel, Kind, Severity,
};

pub(super) struct Change {
    kind: Kind,
    subject: Option<String>,
    payment: Option<String>,
}
impl Change {
    pub fn initialized() -> Self {
        Self {
            kind: Kind::GatewayInitialized,
            subject: None,
            payment: None,
        }
    }
    pub fn new(
        kind: Kind,
        subject: Option<&str>,
        payment: Option<&str>,
    ) -> Result<Self, StoreError> {
        fn reference(value: &str) -> Result<String, StoreError> {
            let raw = value.strip_prefix("0x").ok_or(StoreError::Corrupt)?;
            if raw.len() != 64
                || !raw
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(StoreError::Corrupt);
            }
            Ok(raw.to_string())
        }
        if kind.component() != Component::Gateway {
            return Err(StoreError::Corrupt);
        }
        Ok(Self {
            kind,
            subject: subject.map(reference).transpose()?,
            payment: payment.map(reference).transpose()?,
        })
    }
    pub fn append(
        &self,
        store: &Store,
        operation_id: &str,
        revision: u64,
    ) -> Result<Append, StoreError> {
        let id = format!("{operation_id}:event");
        let source_id = hex::encode(store.identity());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Corrupt)?
            .as_millis();
        let created_at_ms = now.try_into().map_err(|_| StoreError::Corrupt)?;
        let event = EventEnvelope {
            schema: EventSchema::Current,
            event_id: EventEnvelope::identity(&source_id, &id),
            source_id,
            source_revision: revision,
            created_at_ms,
            component: Component::Gateway,
            evidence_level: EvidenceLevel::LocalRecord,
            kind: self.kind,
            severity: if self.kind == Kind::GatewayOutgoingFailed {
                Severity::Warning
            } else {
                Severity::Info
            },
            correlation_id: EventEnvelope::correlation(operation_id),
            subject_id: self.subject.clone(),
            funding_context_id: None,
            payment_hash: self.payment.clone(),
            provider_revision: None,
            evidence_digest: None,
        };
        Ok(Append {
            id,
            body: Body::new(event.encode().map_err(|_| StoreError::Corrupt)?)
                .map_err(runtime_error)?,
        })
    }
}
