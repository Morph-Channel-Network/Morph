//! Persistent provider-side diagnostics. This module has no route graph, TLC,
//! signing, callback invocation or chain-admission authority.
use std::path::Path;

use morph_runtime_store::{Body, Commit, Family, Protection, Store, StoreError, Write};

use super::*;

mod rpc;
pub use rpc::{SHADOW_METHODS, ShadowRpcError};

const RECORD_ID: &str = "fiber-shadow";
const MAX_REQUEST_BYTES: usize = 32 * 1024;

/// One revision slot has one immutable request and reply, even after restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ShadowMutation {
    Register(RegisterExternalEdgeRequest),
    Update(UpdateExternalEdgeRequest),
    Drain(SetExternalEdgeStateRequest),
    Disable(SetExternalEdgeStateRequest),
}

impl ShadowMutation {
    fn identity(&self) -> (&str, u64) {
        match self {
            Self::Register(r) => (&r.edge.morph_edge_id, 0),
            Self::Update(r) => (&r.edge.morph_edge_id, r.expected_provider_revision),
            Self::Drain(r) | Self::Disable(r) => (&r.morph_edge_id, r.expected_provider_revision),
        }
    }
}

#[derive(Debug, Error)]
pub enum ShadowError {
    #[error("invalid shadow request or installed profile")]
    Invalid,
    #[error("shadow revision or operation content conflicts")]
    Conflict,
    #[error("shadow edge capacity is exhausted")]
    Full,
    #[error("shadow record does not exist")]
    NotFound,
    #[error("shadow record cannot be read under this installed policy")]
    Corrupt,
    #[error(transparent)]
    Storage(#[from] StoreError),
}
pub type ShadowResult<T> = Result<T, ShadowError>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEdge {
    edge: FiberExternalEdge,
    callback_endpoint: String,
    revision: u64,
    state: MirrorState,
}
impl StoredEdge {
    fn ack(&self) -> FiberHookAck {
        FiberHookAck {
            morph_edge_id: self.edge.morph_edge_id.clone(),
            provider_revision: self.revision,
            state: self.state,
            forwarding: false,
            opaque_morph_commitment: self.edge.opaque_morph_commitment.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    profile: String,
    policy: HookPolicy,
    edges: BTreeMap<String, StoredEdge>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Applied {
    request: ShadowMutation,
    ack: FiberHookAck,
}

/// A dedicated private runtime database, with no signing secrets or authority.
/// Retired entries and immutable replies are deliberately not evicted. Exhaustion
/// stops new work; a restart never grants another revision slot.
pub struct ShadowStore {
    store: Store,
    policy: HookPolicy,
}
impl ShadowStore {
    pub fn open(path: &Path, policy: HookPolicy) -> ShadowResult<Self> {
        policy.validate().map_err(|_| ShadowError::Invalid)?;
        let result = Self {
            store: Store::open(path, Protection::private_plaintext())?,
            policy,
        };
        let snapshot = result.store.read(Family::Edge, RECORD_ID)?;
        if snapshot.record.is_none() {
            let initial = Snapshot {
                profile: SHADOW_PROFILE.into(),
                policy: result.policy.clone(),
                edges: BTreeMap::new(),
            };
            let commit = Commit {
                operation_id: "fiber-shadow-install".into(),
                expected_revision: snapshot.revision,
                intent: body(&initial)?,
                writes: vec![Write {
                    family: Family::Edge,
                    id: RECORD_ID.into(),
                    value: Some(body(&initial)?),
                }],
                events: vec![],
                attempts: vec![],
            };
            match result.store.commit_new(&commit) {
                Ok(_) | Err(StoreError::Conflict | StoreError::Revision { .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        result.snapshot()?;
        Ok(result)
    }

    pub fn capabilities(&self) -> ShadowResult<HookCapabilities> {
        // A closed/corrupt/unreadable store never reports itself ready.
        self.snapshot()?;
        Ok(HookCapabilities {
            profile: SHADOW_PROFILE.into(),
            fiber_commit: self.policy.fiber_commit.clone(),
            patch_hash: self.policy.patch_hash.clone(),
            ckb_genesis_hash: self.policy.ckb_genesis_hash.clone(),
            forwarding: false,
            max_edges: MAX_SHADOW_EDGES as u64,
        })
    }

    pub fn list(&self) -> ShadowResult<Vec<MirroredFiberEdge>> {
        let (_, snapshot) = self.snapshot()?;
        Ok(snapshot
            .edges
            .into_values()
            .map(|stored| MirroredFiberEdge {
                channel_id: stored.edge.channel_id,
                funding_epoch: stored.edge.funding_epoch,
                morph_edge_id: stored.edge.morph_edge_id,
                funding_context_id: stored.edge.funding_context_id,
                provider_revision: stored.revision,
                state: stored.state,
                forwarding: false,
                opaque_morph_commitment: stored.edge.opaque_morph_commitment,
            })
            .collect())
    }

    /// Commit request, reply and mirror atomically. An exact retry returns the
    /// original reply; it does not reapply an old transition to the current edge.
    pub fn apply(&self, request: ShadowMutation) -> ShadowResult<FiberHookAck> {
        if serde_json::to_vec(&request)
            .map_err(|_| ShadowError::Invalid)?
            .len()
            > MAX_REQUEST_BYTES
        {
            return Err(ShadowError::Invalid);
        }
        let (id, expected) = request.identity();
        decode_byte32(id).map_err(|_| ShadowError::Invalid)?;
        let operation_id = format!("fiber-shadow:{}:{expected}", &id[2..]);
        let (revision, mut snapshot) = self.snapshot()?;
        if let Some(ack) = self.replayed(&operation_id, &request)? {
            return Ok(ack);
        }
        let stored = match &request {
            ShadowMutation::Register(r) => {
                self.validate_edge(&r.edge)?;
                parse_http_url(&r.callback_endpoint).map_err(|_| ShadowError::Invalid)?;
                if snapshot.edges.contains_key(id) {
                    return Err(ShadowError::Conflict);
                }
                if snapshot.edges.len() >= MAX_SHADOW_EDGES {
                    return Err(ShadowError::Full);
                }
                if let Some(previous) = &r.expected_previous_edge_id {
                    let old = snapshot.edges.get(previous).ok_or(ShadowError::Conflict)?;
                    if old.edge.channel_id != r.edge.channel_id
                        || old.edge.funding_context_id == r.edge.funding_context_id
                        || old.state != MirrorState::Disabled
                    {
                        return Err(ShadowError::Conflict);
                    }
                } else if snapshot.edges.values().any(|old| {
                    old.edge.channel_id == r.edge.channel_id
                        && old.edge.funding_context_id != r.edge.funding_context_id
                }) {
                    return Err(ShadowError::Conflict);
                }
                StoredEdge {
                    edge: r.edge.clone(),
                    callback_endpoint: r.callback_endpoint.clone(),
                    revision: 1,
                    state: MirrorState::Active,
                }
            }
            ShadowMutation::Update(r) => {
                self.validate_edge(&r.edge)?;
                let old = snapshot.edges.get(id).ok_or(ShadowError::NotFound)?;
                if old.revision != expected
                    || r.edge.state_number < old.edge.state_number
                    || (r.edge.state_number == old.edge.state_number
                        && (r.edge.directional_liquidity != old.edge.directional_liquidity
                            || r.edge.opaque_morph_commitment != old.edge.opaque_morph_commitment))
                {
                    return Err(ShadowError::Conflict);
                }
                StoredEdge {
                    edge: r.edge.clone(),
                    callback_endpoint: old.callback_endpoint.clone(),
                    revision: next(expected)?,
                    state: MirrorState::Active,
                }
            }
            ShadowMutation::Drain(r) | ShadowMutation::Disable(r) => {
                if r.reason.trim().is_empty() || r.reason.len() > 256 {
                    return Err(ShadowError::Invalid);
                }
                let old = snapshot.edges.get(id).ok_or(ShadowError::NotFound)?;
                if old.revision != expected {
                    return Err(ShadowError::Conflict);
                }
                let state = if matches!(&request, ShadowMutation::Drain(_)) {
                    MirrorState::Draining
                } else {
                    MirrorState::Disabled
                };
                if old.state == MirrorState::Disabled && state == MirrorState::Draining {
                    return Err(ShadowError::Conflict);
                }
                StoredEdge {
                    revision: next(expected)?,
                    state,
                    ..old.clone()
                }
            }
        };
        if stored.state == MirrorState::Active {
            // Once a successor has been registered, no stale request may revive
            // an earlier context, even when the successor is itself disabled.
            if snapshot.edges.values().any(|other| {
                other.edge.channel_id == stored.edge.channel_id
                    && (other.edge.funding_epoch > stored.edge.funding_epoch
                        || (other.edge.funding_epoch == stored.edge.funding_epoch
                            && other.edge.funding_context_id != stored.edge.funding_context_id))
            }) {
                return Err(ShadowError::Conflict);
            }
        }
        if stored.state != MirrorState::Disabled {
            // All old-context assets must be disabled before the successor.
            for other in snapshot.edges.values().filter(|e| {
                e.state != MirrorState::Disabled
                    && e.edge.morph_edge_id != id
                    && e.edge.channel_id == stored.edge.channel_id
            }) {
                if other.edge.funding_context_id != stored.edge.funding_context_id
                    || other.edge.funding_epoch != stored.edge.funding_epoch
                    || other.edge.deployment_id != stored.edge.deployment_id
                    || other.edge.node_ids != stored.edge.node_ids
                    || other.edge.asset.physical_type() == stored.edge.asset.physical_type()
                {
                    return Err(ShadowError::Conflict);
                }
            }
        }
        let ack = stored.ack();
        snapshot.edges.insert(id.to_owned(), stored);
        let commit = Commit {
            operation_id: operation_id.clone(),
            expected_revision: revision,
            intent: body(&Applied {
                request: request.clone(),
                ack: ack.clone(),
            })?,
            writes: vec![Write {
                family: Family::Edge,
                id: RECORD_ID.into(),
                value: Some(body(&snapshot)?),
            }],
            events: vec![],
            attempts: vec![],
        };
        match self.store.commit_new(&commit) {
            Ok(_) => Ok(ack),
            Err(StoreError::Conflict | StoreError::Revision { .. }) => self
                .replayed(&operation_id, &request)?
                .ok_or(ShadowError::Conflict),
            Err(error) => Err(error.into()),
        }
    }

    fn replayed(&self, id: &str, request: &ShadowMutation) -> ShadowResult<Option<FiberHookAck>> {
        let Some(saved) = self.store.intent(id)? else {
            return Ok(None);
        };
        let applied: Applied =
            serde_json::from_slice(saved.body.bytes()).map_err(|_| ShadowError::Corrupt)?;
        if &applied.request != request {
            return Err(ShadowError::Conflict);
        }
        if applied.ack.forwarding
            || applied.ack.provider_revision != next(request.identity().1)?
            || applied.ack.morph_edge_id != request.identity().0
        {
            return Err(ShadowError::Corrupt);
        }
        Ok(Some(applied.ack))
    }

    fn validate_edge(&self, edge: &FiberExternalEdge) -> ShadowResult<()> {
        ProviderEdgeDescriptor::try_from(edge).map_err(|_| ShadowError::Invalid)?;
        if edge.asset.genesis() != self.policy.ckb_genesis_hash {
            return Err(ShadowError::Invalid);
        }
        Ok(())
    }

    fn snapshot(&self) -> ShadowResult<(u64, Snapshot)> {
        let saved = self.store.read(Family::Edge, RECORD_ID)?;
        let record = saved.record.ok_or(ShadowError::Corrupt)?;
        let snapshot: Snapshot =
            serde_json::from_slice(record.body.bytes()).map_err(|_| ShadowError::Corrupt)?;
        if snapshot.profile != SHADOW_PROFILE
            || snapshot.policy != self.policy
            || snapshot.edges.len() > MAX_SHADOW_EDGES
        {
            return Err(ShadowError::Corrupt);
        }
        for (id, edge) in &snapshot.edges {
            if id != &edge.edge.morph_edge_id || edge.revision == 0 {
                return Err(ShadowError::Corrupt);
            }
            self.validate_edge(&edge.edge)
                .map_err(|_| ShadowError::Corrupt)?;
            parse_http_url(&edge.callback_endpoint).map_err(|_| ShadowError::Corrupt)?;
        }
        Ok((saved.revision, snapshot))
    }
}

fn next(value: u64) -> ShadowResult<u64> {
    value.checked_add(1).ok_or(ShadowError::Conflict)
}
fn body<T: Serialize>(value: &T) -> ShadowResult<Body> {
    Ok(Body::new(
        serde_json::to_vec(value).map_err(|_| ShadowError::Invalid)?,
    )?)
}

#[cfg(test)]
mod tests;
