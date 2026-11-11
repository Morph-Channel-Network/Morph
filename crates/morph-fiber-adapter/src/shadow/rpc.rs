//! Shared handler for the opt-in provider module. The embedding server owns
//! transport limits and authentication; no method grants forwarding permission.
use super::*;

pub const SHADOW_METHODS: [&str; 6] = [
    CAPABILITIES_METHOD,
    REGISTER_EXTERNAL_EDGE_METHOD,
    UPDATE_EXTERNAL_EDGE_METHOD,
    DRAIN_EXTERNAL_EDGE_METHOD,
    DISABLE_EXTERNAL_EDGE_METHOD,
    LIST_EXTERNAL_EDGES_METHOD,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowRpcError {
    pub code: i32,
    pub message: &'static str,
}
impl From<ShadowError> for ShadowRpcError {
    fn from(error: ShadowError) -> Self {
        match error {
            ShadowError::Invalid => Self {
                code: -32602,
                message: "invalid shadow parameters",
            },
            ShadowError::Conflict => Self {
                code: -32041,
                message: "shadow revision or content conflict",
            },
            ShadowError::NotFound => Self {
                code: -32044,
                message: "shadow edge not found",
            },
            ShadowError::Full | ShadowError::Storage(StoreError::Full) => Self {
                code: -32048,
                message: "shadow capacity exhausted",
            },
            ShadowError::Storage(StoreError::CommitUncertain) => Self {
                code: -32049,
                message: "shadow outcome unknown; reconcile the exact request",
            },
            ShadowError::Storage(StoreError::Busy) => Self {
                code: -32053,
                message: "shadow store busy",
            },
            _ => Self {
                code: -32603,
                message: "shadow store unavailable",
            },
        }
    }
}

impl ShadowStore {
    /// Execute one JSON-RPC positional argument after authentication. Callers
    /// must reject missing/extra positional arguments, not discard them.
    pub fn dispatch(&self, method: &str, argument: Value) -> Result<Value, ShadowRpcError> {
        let invalid = || ShadowRpcError::from(ShadowError::Invalid);
        if serde_json::to_vec(&argument).map_err(|_| invalid())?.len() > MAX_REQUEST_BYTES {
            return Err(invalid());
        }
        let request = match method {
            CAPABILITIES_METHOD | LIST_EXTERNAL_EDGES_METHOD => {
                if argument != json!({}) {
                    return Err(invalid());
                }
                return if method == CAPABILITIES_METHOD {
                    serde_json::to_value(self.capabilities()?).map_err(|_| invalid())
                } else {
                    serde_json::to_value(self.list()?).map_err(|_| invalid())
                };
            }
            REGISTER_EXTERNAL_EDGE_METHOD => {
                ShadowMutation::Register(serde_json::from_value(argument).map_err(|_| invalid())?)
            }
            UPDATE_EXTERNAL_EDGE_METHOD => {
                ShadowMutation::Update(serde_json::from_value(argument).map_err(|_| invalid())?)
            }
            DRAIN_EXTERNAL_EDGE_METHOD => {
                ShadowMutation::Drain(serde_json::from_value(argument).map_err(|_| invalid())?)
            }
            DISABLE_EXTERNAL_EDGE_METHOD => {
                ShadowMutation::Disable(serde_json::from_value(argument).map_err(|_| invalid())?)
            }
            _ => {
                return Err(ShadowRpcError {
                    code: -32601,
                    message: "shadow method not found",
                });
            }
        };
        serde_json::to_value(self.apply(request)?).map_err(|_| invalid())
    }
}
