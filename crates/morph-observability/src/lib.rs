//! Observations describe readiness; they never authorize signing or mutation.
//! No user-controlled metric label or secret-bearing error payload is accepted.
#![forbid(unsafe_code)]

pub mod clock;
pub mod metrics;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_EVIDENCE_AGE_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Hub,
    Gateway,
    Watch,
    Signer,
    Bridge,
    EventConsumer,
    SignerSupervisor,
}
impl Service {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Gateway => "gateway",
            Self::Watch => "watch",
            Self::Signer => "signer",
            Self::Bridge => "bridge",
            Self::EventConsumer => "event_consumer",
            Self::SignerSupervisor => "signer_supervisor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    LocalRegistry,
    InvoiceIssuance,
    ChannelSigning,
    PaymentSubmission,
    ChainPublication,
    EventDispatch,
    AuthoritySupervision,
}
impl Scope {
    pub const ALL: [Self; 7] = [
        Self::LocalRegistry,
        Self::InvoiceIssuance,
        Self::ChannelSigning,
        Self::PaymentSubmission,
        Self::ChainPublication,
        Self::EventDispatch,
        Self::AuthoritySupervision,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalRegistry => "local_registry",
            Self::InvoiceIssuance => "invoice_issuance",
            Self::ChannelSigning => "channel_signing",
            Self::PaymentSubmission => "payment_submission",
            Self::ChainPublication => "chain_publication",
            Self::EventDispatch => "event_dispatch",
            Self::AuthoritySupervision => "authority_supervision",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Dependency {
    Store,
    ChainIdentity,
    Deployment,
    SignerPolicy,
    Supervision,
    Outbox,
    PublicationBudget,
    Worker,
    DeliveryPolicy,
    ProviderIdentity,
    Capacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Verified,
    NotConfigured,
    NotImplemented,
    Unverified,
    Busy,
    Unavailable,
    Stale,
    WrongNetwork,
    WrongDeployment,
    StoreInconsistent,
    UnsupportedSchema,
    OutboxBlocked,
    RevisionChanged,
    ClockInvalid,
    WorkerStopped,
    DeadLetters,
    BacklogAged,
    ArchiveRequired,
    ConsumerSealed,
    PolicyDenied,
    ProviderMismatch,
    CapacityExhausted,
}

/// Constructed by an actual probe, not deserialized as an admission instruction.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub dependency: Dependency,
    pub reason: Reason,
    pub checked_at_ms: u64,
    pub valid_until_ms: u64,
}
impl Observation {
    pub fn assess(self, now_ms: u64) -> Check {
        let reason = if self.checked_at_ms > now_ms
            || self.valid_until_ms <= self.checked_at_ms
            || self.valid_until_ms - self.checked_at_ms > MAX_EVIDENCE_AGE_MS
        {
            Reason::ClockInvalid
        } else if now_ms >= self.valid_until_ms {
            Reason::Stale
        } else {
            self.reason
        };
        Check {
            dependency: self.dependency,
            reason,
            checked_at_ms: Some(self.checked_at_ms),
            valid_until_ms: Some(self.valid_until_ms),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub dependency: Dependency,
    pub reason: Reason,
    #[serde(with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub checked_at_ms: Option<u64>,
    #[serde(with = "morph_packages::public_encoding::optional_decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::optional_decimal::schema")]
    pub valid_until_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeReadiness {
    pub scope: Scope,
    /// Implemented and configured in this service. Unsupported scopes never
    /// contribute to an affirmative global readiness claim.
    pub configured: bool,
    pub ready: bool,
    #[schemars(length(max = 11))]
    pub checks: Vec<Check>,
}
impl ScopeReadiness {
    fn consistent(&self) -> bool {
        self.checks.len() <= 11
            && self.checks.iter().enumerate().all(|(i, c)| {
                !self.checks[..i]
                    .iter()
                    .any(|p| p.dependency == c.dependency)
            })
            && self.ready
                == (self.configured
                    && !self.checks.is_empty()
                    && self.checks.iter().all(|c| c.reason == Reason::Verified))
    }

    pub fn evaluate(
        scope: Scope,
        configured: bool,
        required: &[Dependency],
        observations: &[Observation],
        now_ms: u64,
    ) -> Self {
        let mut checks = Vec::new();
        for &dependency in required {
            if checks.iter().any(|c: &Check| c.dependency == dependency) {
                continue;
            }
            let mut matches = observations.iter().filter(|o| o.dependency == dependency);
            let first = matches.next();
            let check = if let Some(first) = first.filter(|_| matches.next().is_none()) {
                first.assess(now_ms)
            } else {
                Check {
                    dependency,
                    reason: Reason::Unverified,
                    checked_at_ms: None,
                    valid_until_ms: None,
                }
            };
            checks.push(check);
        }
        let ready =
            configured && !checks.is_empty() && checks.iter().all(|c| c.reason == Reason::Verified);
        Self {
            scope,
            configured,
            ready,
            checks,
        }
    }
    pub fn unsupported(scope: Scope) -> Self {
        Self {
            scope,
            configured: false,
            ready: false,
            checks: vec![Check {
                dependency: Dependency::Deployment,
                reason: Reason::NotImplemented,
                checked_at_ms: None,
                valid_until_ms: None,
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Liveness {
    pub service: Service,
    pub alive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub service: Service,
    /// Only the explicitly configured scopes below contribute to this summary.
    pub ready: bool,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    #[schemars(schema_with = "morph_packages::public_encoding::decimal::schema")]
    pub generated_at_ms: u64,
    #[schemars(length(max = 7))]
    pub scopes: Vec<ScopeReadiness>,
}
impl Readiness {
    /// Validate response consistency without treating it as authorization.
    pub fn consistent(&self) -> bool {
        self.scopes.len() <= Scope::ALL.len()
            && self.scopes.iter().all(ScopeReadiness::consistent)
            && self.scopes.iter().flat_map(|s| &s.checks).all(|check| {
                if check.reason != Reason::Verified {
                    return true;
                }
                match (check.checked_at_ms, check.valid_until_ms) {
                    (Some(checked), Some(expires)) => {
                        checked <= self.generated_at_ms
                            && self.generated_at_ms < expires
                            && expires - checked <= MAX_EVIDENCE_AGE_MS
                    }
                    _ => false,
                }
            })
            && self
                .scopes
                .iter()
                .enumerate()
                .all(|(i, s)| !self.scopes[..i].iter().any(|p| p.scope == s.scope))
            && self.ready
                == (self.scopes.iter().any(|s| s.configured)
                    && self.scopes.iter().filter(|s| s.configured).all(|s| s.ready))
    }

    pub fn new(service: Service, generated_at_ms: u64, scopes: Vec<ScopeReadiness>) -> Self {
        let has_scope = scopes.iter().any(|scope| scope.configured);
        let unique = scopes
            .iter()
            .enumerate()
            .all(|(i, item)| !scopes[..i].iter().any(|s| s.scope == item.scope));
        let ready = has_scope
            && unique
            && scopes.len() <= Scope::ALL.len()
            && scopes.iter().filter(|s| s.configured).all(|s| s.ready);
        Self {
            service,
            ready,
            generated_at_ms,
            scopes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(reason: Reason) -> Observation {
        Observation {
            dependency: Dependency::Store,
            reason,
            checked_at_ms: 100,
            valid_until_ms: 200,
        }
    }
    #[test]
    fn verified_means_exact_complete_fresh_observation_only() {
        let assess = |observations: &[Observation], now| {
            ScopeReadiness::evaluate(
                Scope::LocalRegistry,
                true,
                &[Dependency::Store],
                observations,
                now,
            )
            .ready
        };
        assert!(assess(&[observation(Reason::Verified)], 100));
        assert!(!assess(&[observation(Reason::Verified)], 200));
        assert!(!assess(&[observation(Reason::Verified)], 99));
        assert!(!assess(&[], 150));
        assert!(!assess(&[observation(Reason::Verified); 2], 150));
        for reason in [
            Reason::Busy,
            Reason::Unavailable,
            Reason::WrongNetwork,
            Reason::WrongDeployment,
            Reason::StoreInconsistent,
            Reason::UnsupportedSchema,
            Reason::OutboxBlocked,
            Reason::Unverified,
        ] {
            assert!(!assess(&[observation(reason)], 150));
        }
        assert!(!ScopeReadiness::evaluate(Scope::LocalRegistry, true, &[], &[], 150).ready);
    }
    #[test]
    fn one_affected_scope_does_not_reclassify_healthy_unrelated_work() {
        let local = ScopeReadiness::evaluate(
            Scope::LocalRegistry,
            true,
            &[Dependency::Store],
            &[observation(Reason::Verified)],
            150,
        );
        let signing = ScopeReadiness::evaluate(
            Scope::ChannelSigning,
            true,
            &[Dependency::Store, Dependency::Supervision],
            &[observation(Reason::Verified)],
            150,
        );
        let report = Readiness::new(Service::Hub, 150, vec![local.clone(), signing]);
        assert!(!report.ready);
        assert!(report.scopes[0].ready);
        assert!(
            Readiness::new(
                Service::Hub,
                150,
                vec![local, ScopeReadiness::unsupported(Scope::ChainPublication)]
            )
            .ready
        );
        assert!(!Readiness::new(Service::Hub, 150, vec![]).ready);
    }
}
