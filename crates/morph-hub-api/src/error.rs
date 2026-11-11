//! Stable machine-readable errors for the sole current Hub API.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    AuthRequired,
    InsufficientAuthScope,
    InvalidAuthToken,
    InvalidRequest,
    RateLimited,
    RateLimiterUnavailable,
    RouteNotFound,
    StateRestoreDisabled,
    TooManyConnections,
    TooManyEventStreams,
    TooManyMutations,
    UnknownEndpoint,
    RevisionConflict,
    CommitOutcomeUnknown,
    StoreUnavailable,
    InvalidMutationContext,
    UnsupportedApiVersion,
    IdempotencyConflict,
    ResponseLimit,
}
impl ApiErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::InsufficientAuthScope => "insufficient_auth_scope",
            Self::InvalidAuthToken => "invalid_auth_token",
            Self::InvalidRequest => "invalid_request",
            Self::RateLimited => "rate_limited",
            Self::RateLimiterUnavailable => "rate_limiter_unavailable",
            Self::RouteNotFound => "route_not_found",
            Self::StateRestoreDisabled => "state_restore_disabled",
            Self::TooManyConnections => "too_many_connections",
            Self::TooManyEventStreams => "too_many_event_streams",
            Self::TooManyMutations => "too_many_mutations",
            Self::UnknownEndpoint => "unknown_endpoint",
            Self::RevisionConflict => "revision_conflict",
            Self::CommitOutcomeUnknown => "commit_outcome_unknown",
            Self::StoreUnavailable => "store_unavailable",
            Self::InvalidMutationContext => "invalid_mutation_context",
            Self::UnsupportedApiVersion => "unsupported_api_version",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::ResponseLimit => "response_limit",
        }
    }
}
impl std::fmt::Display for ApiErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
