//! Morph-owned durable diagnostics. Only the canonical observer may supply a
//! batch; neither a provider list nor an acknowledgement creates local evidence.
//! No signer journals, private recoveries, keys or routing authority live here.
use super::*;
use crate::shadow::ShadowMutation;
use morph_packages::events::{
    Component, EventEnvelope, EventSchema, EvidenceLevel, Kind, Severity,
};
use morph_runtime_store::{
    Append, Body, Commit, Family, Protection, Receipt, Store, StoreError, Write,
};
use std::path::Path;

const RECORD: &str = "morph-shadow-coordinator";
const SCHEMA: &str = "morph.shadow_coordinator.v1";
pub const MAX_OBSERVATION_AGE_MS: u64 = 60_000;

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("invalid diagnostic observation, configuration or acknowledgement")]
    Invalid,
    #[error("diagnostic revision or identity conflict")]
    Conflict,
    #[error("diagnostic identity capacity exhausted")]
    Full,
    #[error("diagnostic coordinator record is inconsistent")]
    Corrupt,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Provider(#[from] AdapterError),
}
pub type CoordinatorResult<T> = Result<T, CoordinatorError>;

/// Internal Rust/store input, not a public API or untrusted proof upload endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredEdge {
    pub edge: ProviderEdgeDescriptor,
    pub state: MirrorState,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBatch {
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
    pub edges: Vec<DesiredEdge>,
}
impl ObservedBatch {
    fn fresh(&self, now: u64) -> bool {
        self.observed_at_ms <= now && now < self.valid_until_ms
    }
    fn validate(&self) -> CoordinatorResult<()> {
        if self.edges.len() > MAX_SHADOW_EDGES
            || self
                .valid_until_ms
                .checked_sub(self.observed_at_ms)
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_OBSERVATION_AGE_MS)
            || self.edges.iter().any(|e| e.state == MirrorState::Disabled)
        {
            return Err(CoordinatorError::Invalid);
        }
        morph_core::validate_provider_edge_set(
            &self
                .edges
                .iter()
                .map(|e| e.edge.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|_| CoordinatorError::Invalid)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMutation {
    pub id: String,
    pub base_revision: u64,
    pub mutation: ShadowMutation,
    pub expected_commitment: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    policy: HookPolicy,
    rpc_url: String,
    callback: String,
    #[serde(deserialize_with = "super::required_option")]
    observation: Option<ObservedBatch>,
    seen: Vec<ProviderEdgeDescriptor>,
    #[serde(deserialize_with = "super::required_option")]
    pending: Option<PendingMutation>,
}
fn body<T: Serialize>(value: &T) -> CoordinatorResult<Body> {
    Ok(Body::new(
        serde_json::to_vec(value).map_err(|_| CoordinatorError::Invalid)?,
    )?)
}
fn digest<T: Serialize>(value: &T) -> CoordinatorResult<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| CoordinatorError::Invalid)?;
    let mut input = b"morph.shadow.coordinator.v1\0".to_vec();
    input.extend(bytes);
    Ok(hex::encode(morph_core::blake2b256(&input)))
}
fn mutation_id(m: &ShadowMutation, revision: u64) -> CoordinatorResult<String> {
    digest(&(revision, m))
}
fn mutation_identity(m: &ShadowMutation) -> (&str, u64, MirrorState) {
    match m {
        ShadowMutation::Register(r) => (r.edge.morph_edge_id.as_str(), 0, MirrorState::Active),
        ShadowMutation::Update(r) => (
            r.edge.morph_edge_id.as_str(),
            r.expected_provider_revision,
            MirrorState::Active,
        ),
        ShadowMutation::Drain(r) => (
            r.morph_edge_id.as_str(),
            r.expected_provider_revision,
            MirrorState::Draining,
        ),
        ShadowMutation::Disable(r) => (
            r.morph_edge_id.as_str(),
            r.expected_provider_revision,
            MirrorState::Disabled,
        ),
    }
}

fn wall_time_ms() -> CoordinatorResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoordinatorError::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| CoordinatorError::Invalid)
}

pub struct Coordinator {
    store: Store,
    policy: HookPolicy,
    rpc_url: String,
    callback: String,
    fresh_in_process: std::sync::atomic::AtomicBool,
}
impl Coordinator {
    pub fn open(
        path: &Path,
        policy: HookPolicy,
        rpc_url: &str,
        callback: &str,
    ) -> CoordinatorResult<Self> {
        policy.validate().map_err(|_| CoordinatorError::Invalid)?;
        let rpc_url = parse_http_url(rpc_url)
            .map_err(|_| CoordinatorError::Invalid)?
            .to_string();
        let callback = parse_http_url(callback)
            .map_err(|_| CoordinatorError::Invalid)?
            .to_string();
        let this = Self {
            store: Store::open(path, Protection::private_plaintext())?,
            policy,
            rpc_url,
            callback,
            fresh_in_process: std::sync::atomic::AtomicBool::new(false),
        };
        let current = this.store.read(Family::Edge, RECORD)?;
        if current.record.is_none() {
            let snapshot = Snapshot {
                schema: SCHEMA.into(),
                policy: this.policy.clone(),
                rpc_url: this.rpc_url.clone(),
                callback: this.callback.clone(),
                observation: None,
                seen: vec![],
                pending: None,
            };
            this.store.commit(&Commit {
                operation_id: "shadow-coordinator-install".into(),
                expected_revision: current.revision,
                intent: body(&snapshot)?,
                writes: vec![Write {
                    family: Family::Edge,
                    id: RECORD.into(),
                    value: Some(body(&snapshot)?),
                }],
                events: vec![],
                attempts: vec![],
            })?;
        }
        this.snapshot()?;
        Ok(this)
    }
    fn snapshot(&self) -> CoordinatorResult<(u64, Snapshot)> {
        let read = self.store.read(Family::Edge, RECORD)?;
        let stored = read.record.ok_or(CoordinatorError::Corrupt)?;
        let s: Snapshot =
            serde_json::from_slice(stored.body.bytes()).map_err(|_| CoordinatorError::Corrupt)?;
        if s.schema != SCHEMA
            || s.policy != self.policy
            || s.rpc_url != self.rpc_url
            || s.callback != self.callback
            || s.seen.len() > MAX_SHADOW_EDGES
        {
            return Err(CoordinatorError::Corrupt);
        }
        let mut ids = BTreeSet::new();
        for e in &s.seen {
            if e.derive_id().map_err(|_| CoordinatorError::Corrupt)? != e.edge_id
                || !ids.insert(e.edge_id)
            {
                return Err(CoordinatorError::Corrupt);
            }
        }
        if let Some(batch) = &s.observation {
            batch.validate()?;
            if batch
                .edges
                .iter()
                .any(|d| !s.seen.iter().any(|e| e == &d.edge))
            {
                return Err(CoordinatorError::Corrupt);
            }
        }
        if let Some(p) = &s.pending {
            if p.base_revision >= read.revision
                || mutation_id(&p.mutation, p.base_revision)? != p.id
                || decode_byte32(&p.expected_commitment).is_err()
            {
                return Err(CoordinatorError::Corrupt);
            }
            match &p.mutation {
                ShadowMutation::Register(r) => {
                    ProviderEdgeDescriptor::try_from(&r.edge)
                        .map_err(|_| CoordinatorError::Corrupt)?;
                    if r.callback_endpoint != s.callback
                        || r.edge.opaque_morph_commitment != p.expected_commitment
                    {
                        return Err(CoordinatorError::Corrupt);
                    }
                    if let Some(id) = &r.expected_previous_edge_id {
                        decode_byte32(id).map_err(|_| CoordinatorError::Corrupt)?;
                    }
                }
                ShadowMutation::Update(r) => {
                    ProviderEdgeDescriptor::try_from(&r.edge)
                        .map_err(|_| CoordinatorError::Corrupt)?;
                    if r.expected_provider_revision == 0
                        || r.edge.opaque_morph_commitment != p.expected_commitment
                    {
                        return Err(CoordinatorError::Corrupt);
                    }
                }
                ShadowMutation::Drain(r) | ShadowMutation::Disable(r) => {
                    if r.expected_provider_revision == 0
                        || r.reason.trim().is_empty()
                        || r.reason.len() > 256
                    {
                        return Err(CoordinatorError::Corrupt);
                    }
                    decode_byte32(&r.morph_edge_id).map_err(|_| CoordinatorError::Corrupt)?;
                }
            }
        }
        Ok((read.revision, s))
    }
    pub fn revision(&self) -> CoordinatorResult<u64> {
        Ok(self.snapshot()?.0)
    }
    pub fn identity(&self) -> [u8; 32] {
        self.store.identity()
    }
    pub fn probe(path: &Path, config_digest: &str) -> CoordinatorResult<([u8; 32], u64)> {
        let store = Store::read_only(path, Protection::private_plaintext())?;
        let owner = store
            .intent("shadow-owner")?
            .ok_or(CoordinatorError::Corrupt)?;
        if owner.body.bytes() != body(&config_digest)?.bytes() {
            return Err(CoordinatorError::Conflict);
        }
        let read = store.read(Family::Edge, RECORD)?;
        let record = read.record.ok_or(CoordinatorError::Corrupt)?;
        let snapshot: Snapshot =
            serde_json::from_slice(record.body.bytes()).map_err(|_| CoordinatorError::Corrupt)?;
        let this = Self {
            store,
            policy: snapshot.policy,
            rpc_url: snapshot.rpc_url,
            callback: snapshot.callback,
            fresh_in_process: std::sync::atomic::AtomicBool::new(false),
        };
        let revision = this.revision()?;
        if revision != read.revision {
            return Err(CoordinatorError::Conflict);
        }
        Ok((this.identity(), revision))
    }
    /// Pin the owning service configuration without persisting private paths or
    /// credentials. An existing binding can only be retrieved, never replaced.
    pub fn bind_owner(&self, config_digest: &str) -> CoordinatorResult<()> {
        decode_byte32(config_digest).map_err(|_| CoordinatorError::Invalid)?;
        let intent = body(&config_digest)?;
        if let Some(old) = self.store.intent("shadow-owner")? {
            return if old.body.bytes() == intent.bytes() {
                Ok(())
            } else {
                Err(CoordinatorError::Conflict)
            };
        }
        self.store.commit_new(&Commit {
            operation_id: "shadow-owner".into(),
            expected_revision: self.revision()?,
            intent,
            writes: vec![],
            events: vec![],
            attempts: vec![],
        })?;
        Ok(())
    }
    /// Fail closed immediately, including after clock regression. Repeated
    /// failures do not append an unbounded stream of identical invalidations.
    pub fn invalidate(&self, now: u64) -> CoordinatorResult<()> {
        self.fresh_in_process.store(false, Ordering::Release);
        let (revision, mut snapshot) = self.snapshot()?;
        if snapshot.observation.is_none() {
            return Ok(());
        }
        snapshot.observation = None;
        self.commit(
            revision,
            format!("shadow-invalidate:{revision}"),
            body(&revision)?,
            &snapshot,
            Kind::EdgeObservationInvalidated,
            now,
        )?;
        Ok(())
    }
    /// Exact historical retry returns its original receipt without reinstalling
    /// an old batch or extending its expiry. New observations use global CAS.
    pub fn observe(
        &self,
        expected_revision: u64,
        batch: ObservedBatch,
        now: u64,
    ) -> CoordinatorResult<Receipt> {
        let operation_id = format!("shadow-observe:{}", digest(&batch)?);
        let encoded = body(&batch)?;
        if let Some(previous) = self.store.intent(&operation_id)? {
            if previous.body.bytes() != encoded.bytes() {
                return Err(CoordinatorError::Conflict);
            }
            return Ok(Receipt {
                operation_id,
                revision: previous.revision,
            });
        }
        batch.validate()?;
        if !batch.fresh(now) {
            return Err(CoordinatorError::Invalid);
        }
        let (revision, mut snapshot) = self.snapshot()?;
        if revision != expected_revision {
            return Err(StoreError::Revision {
                expected: expected_revision,
                actual: revision,
            }
            .into());
        }
        // A fresh-looking batch after a wall-clock rollback must not replace
        // the last observation. Exact historical retries returned above only
        // retrieve receipts; they never renew process freshness.
        if snapshot
            .observation
            .as_ref()
            .is_some_and(|previous| batch.observed_at_ms < previous.observed_at_ms)
        {
            return Err(CoordinatorError::Conflict);
        }
        for desired in &batch.edges {
            let e = &desired.edge;
            let wire = FiberExternalEdge::try_from(e).map_err(|_| CoordinatorError::Invalid)?;
            let genesis = match &wire.asset {
                FiberEdgeAsset::Ckb { ckb_genesis_hash }
                | FiberEdgeAsset::Xudt {
                    ckb_genesis_hash, ..
                }
                | FiberEdgeAsset::Rgbpp {
                    ckb_genesis_hash, ..
                } => ckb_genesis_hash,
            };
            if genesis != &self.policy.ckb_genesis_hash {
                return Err(CoordinatorError::Invalid);
            }
            for old in &snapshot.seen {
                if old.channel_id == e.channel_id {
                    if e.funding_epoch < old.funding_epoch
                        || (e.funding_epoch == old.funding_epoch
                            && (e.funding_context_id != old.funding_context_id
                                || e.state_number < old.state_number))
                    {
                        return Err(CoordinatorError::Conflict);
                    }
                    if e.funding_context_id == old.funding_context_id
                        && e.state_number == old.state_number
                        && e.opaque_morph_commitment != old.opaque_morph_commitment
                    {
                        return Err(CoordinatorError::Conflict);
                    }
                    if e.asset == old.asset
                        && e.funding_context_id == old.funding_context_id
                        && (e.edge_id != old.edge_id
                            || (e.state_number == old.state_number
                                && e.directional_liquidity != old.directional_liquidity))
                    {
                        return Err(CoordinatorError::Conflict);
                    }
                }
            }
            if let Some(old) = snapshot
                .seen
                .iter_mut()
                .find(|old| old.edge_id == e.edge_id)
            {
                *old = e.clone();
            } else {
                if snapshot.seen.len() >= MAX_SHADOW_EDGES {
                    return Err(CoordinatorError::Full);
                }
                snapshot.seen.push(e.clone());
            }
        }
        snapshot.observation = Some(batch);
        let receipt = self.commit(
            revision,
            operation_id,
            encoded,
            &snapshot,
            Kind::EdgeObserved,
            now,
        )?;
        self.fresh_in_process.store(true, Ordering::Release);
        Ok(receipt)
    }
    fn commit(
        &self,
        revision: u64,
        id: String,
        intent: Body,
        snapshot: &Snapshot,
        kind: Kind,
        now: u64,
    ) -> CoordinatorResult<Receipt> {
        let source_id = hex::encode(self.store.identity());
        let event = EventEnvelope {
            schema: EventSchema::Current,
            event_id: EventEnvelope::identity(&source_id, &id),
            source_id,
            source_revision: revision.checked_add(1).ok_or(CoordinatorError::Full)?,
            created_at_ms: now,
            component: Component::Edge,
            evidence_level: EvidenceLevel::LocalRecord,
            kind,
            severity: Severity::Info,
            correlation_id: EventEnvelope::correlation(&id),
            subject_id: None,
            funding_context_id: None,
            payment_hash: None,
            provider_revision: None,
            evidence_digest: Some(digest(&id)?),
        };
        let event = event.encode().map_err(|_| CoordinatorError::Invalid)?;
        Ok(self.store.commit(&Commit {
            operation_id: id.clone(),
            expected_revision: revision,
            intent,
            writes: vec![Write {
                family: Family::Edge,
                id: RECORD.into(),
                value: Some(body(snapshot)?),
            }],
            events: vec![Append {
                id: id.clone(),
                body: Body::new(event)?,
            }],
            attempts: vec![Append {
                id,
                body: body(&snapshot.pending)?,
            }],
        })?)
    }
    fn pending_allowed(snapshot: &Snapshot, pending: &PendingMutation, now: u64) -> bool {
        let (id, _, state) = mutation_identity(&pending.mutation);
        if state == MirrorState::Disabled {
            return true;
        }
        let desired = snapshot
            .observation
            .as_ref()
            .filter(|b| b.fresh(now))
            .and_then(|b| b.edges.iter().find(|e| hex32(&e.edge.edge_id) == id));
        match (&pending.mutation, desired) {
            (ShadowMutation::Register(r), Some(d)) if d.state == MirrorState::Active => {
                FiberExternalEdge::try_from(&d.edge).is_ok_and(|e| e == r.edge)
            }
            (ShadowMutation::Update(r), Some(d)) if d.state == MirrorState::Active => {
                FiberExternalEdge::try_from(&d.edge).is_ok_and(|e| e == r.edge)
            }
            (ShadowMutation::Drain(_), None) => true,
            (ShadowMutation::Drain(_), Some(d)) => d.state == MirrorState::Draining,
            _ => false,
        }
    }
    /// Persist exactly one operation before network I/O. The caller must fetch
    /// a fresh provider list for each step. Old/unknown edges drain then disable.
    pub fn next(
        &self,
        mirrors: &[MirroredFiberEdge],
        now: u64,
    ) -> CoordinatorResult<Option<PendingMutation>> {
        validate_mirrors(mirrors).map_err(|_| CoordinatorError::Invalid)?;
        let (mut revision, mut snapshot) = self.snapshot()?;
        if snapshot
            .observation
            .as_ref()
            .is_some_and(|batch| !batch.fresh(now))
        {
            // Once this process detects expiry or a backward clock, merely
            // returning to the old timestamp cannot reactivate saved evidence.
            self.fresh_in_process.store(false, Ordering::Release);
        }
        if let Some(pending) = snapshot.pending.clone() {
            let (id, expected, state) = mutation_identity(&pending.mutation);
            let moved = match mirrors.iter().find(|m| m.morph_edge_id == id) {
                Some(remote) => {
                    remote.provider_revision != expected
                        && !(expected.checked_add(1) == Some(remote.provider_revision)
                            && remote.state == state
                            && remote.opaque_morph_commitment == pending.expected_commitment)
                }
                None => expected > 0,
            };
            let mut permitted = Self::pending_allowed(&snapshot, &pending, now);
            if !self.fresh_in_process.load(Ordering::Acquire) && state == MirrorState::Active {
                permitted = false;
            }
            if permitted && !moved {
                return Ok(Some(pending));
            }
            snapshot.pending = None;
            revision = self
                .commit(
                    revision,
                    format!("shadow-abandon:{}", pending.id),
                    body(&pending)?,
                    &snapshot,
                    Kind::EdgeMutationAbandoned,
                    now,
                )?
                .revision;
        }
        let desired = snapshot
            .observation
            .as_ref()
            .filter(|b| b.fresh(now) && self.fresh_in_process.load(Ordering::Acquire))
            .map(|b| b.edges.as_slice())
            .unwrap_or(&[]);
        let active = desired
            .iter()
            .filter(|d| d.state == MirrorState::Active)
            .map(|d| d.edge.clone())
            .collect::<Vec<_>>();
        let mut pending = None;
        // Remove unknown, expired and old-context mirrors before all enabling.
        for remote in mirrors {
            let wanted = desired
                .iter()
                .find(|d| hex32(&d.edge.edge_id) == remote.morph_edge_id);
            let state = match (wanted, remote.state) {
                (None, MirrorState::Active) => Some(MirrorState::Draining),
                (None, MirrorState::Draining) => Some(MirrorState::Disabled),
                (Some(d), MirrorState::Active) if d.state == MirrorState::Draining => {
                    Some(MirrorState::Draining)
                }
                _ => None,
            };
            if let Some(state) = state {
                let request = SetExternalEdgeStateRequest {
                    morph_edge_id: remote.morph_edge_id.clone(),
                    expected_provider_revision: remote.provider_revision,
                    reason: "Morph diagnostic observation retired or draining".into(),
                };
                let mutation = if state == MirrorState::Draining {
                    ShadowMutation::Drain(request)
                } else {
                    ShadowMutation::Disable(request)
                };
                pending = Some((mutation, remote.opaque_morph_commitment.clone()));
                break;
            }
        }
        if pending.is_none() {
            // Explicitly draining desired edges are not candidates for activation.
            let filtered = mirrors
                .iter()
                .filter(|m| {
                    !desired.iter().any(|d| {
                        d.state == MirrorState::Draining
                            && hex32(&d.edge.edge_id) == m.morph_edge_id
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            if let Some(action) = reconciliation_plan(&active, &filtered)
                .map_err(|_| CoordinatorError::Conflict)?
                .first()
            {
                let (id, mutation) = match action {
                    ReconcileAction::Register {
                        edge_id,
                        expected_previous_edge_id,
                    } => {
                        let edge = active
                            .iter()
                            .find(|e| e.edge_id == *edge_id)
                            .ok_or(CoordinatorError::Corrupt)?;
                        (
                            *edge_id,
                            ShadowMutation::Register(RegisterExternalEdgeRequest {
                                edge: FiberExternalEdge::try_from(edge)
                                    .map_err(|_| CoordinatorError::Invalid)?,
                                expected_previous_edge_id: expected_previous_edge_id
                                    .map(|id| hex32(&id)),
                                callback_endpoint: self.callback.clone(),
                            }),
                        )
                    }
                    ReconcileAction::Update {
                        edge_id,
                        expected_provider_revision,
                    } => {
                        let edge = active
                            .iter()
                            .find(|e| e.edge_id == *edge_id)
                            .ok_or(CoordinatorError::Corrupt)?;
                        (
                            *edge_id,
                            ShadowMutation::Update(UpdateExternalEdgeRequest {
                                edge: FiberExternalEdge::try_from(edge)
                                    .map_err(|_| CoordinatorError::Invalid)?,
                                expected_provider_revision: *expected_provider_revision,
                            }),
                        )
                    }
                    ReconcileAction::DisableUnknown { .. } => {
                        return Err(CoordinatorError::Corrupt);
                    }
                };
                let commitment = hex32(
                    &active
                        .iter()
                        .find(|e| e.edge_id == id)
                        .ok_or(CoordinatorError::Corrupt)?
                        .opaque_morph_commitment,
                );
                pending = Some((mutation, commitment));
            }
        }
        let Some((mutation, expected_commitment)) = pending else {
            return Ok(None);
        };
        let pending = PendingMutation {
            id: mutation_id(&mutation, revision)?,
            base_revision: revision,
            mutation,
            expected_commitment,
        };
        snapshot.pending = Some(pending.clone());
        self.commit(
            revision,
            format!("shadow-queue:{}", pending.id),
            body(&pending)?,
            &snapshot,
            Kind::EdgeMutationQueued,
            now,
        )?;
        Ok(Some(pending))
    }
    /// One actual HTTP reconciliation step. Does not perform canonical chain
    /// admission: the owner must supply a freshly verified batch via observe.
    /// No SQLite transaction is held across either network request.
    pub async fn reconcile_once(
        &self,
        client: &FiberHookClient,
    ) -> CoordinatorResult<Option<FiberHookAck>> {
        self.reconcile_guarded(client, || true).await
    }
    /// The owner rechecks its current authority/configuration after all pre-send
    /// network work. False revokes the entire observation before replanning.
    pub async fn reconcile_guarded(
        &self,
        client: &FiberHookClient,
        current: impl Fn() -> bool,
    ) -> CoordinatorResult<Option<FiberHookAck>> {
        if client.url.as_str() != self.rpc_url
            || client.callback_endpoint.as_str() != self.callback
            || client.policy != self.policy
        {
            return Err(CoordinatorError::Invalid);
        }
        let mirrors = client.list_edges().await?;
        let Some(pending) = self.next(&mirrors, wall_time_ms()?)? else {
            return Ok(None);
        };
        // A capability handshake can consume the remaining observation lease.
        // Finish it BEFORE the last freshness check; the private sender below
        // performs no additional pre-send network request.
        client.capabilities().await?;
        if !current() {
            self.invalidate(wall_time_ms()?)?;
        }
        if self.next(&mirrors, wall_time_ms()?)?.as_ref() != Some(&pending) {
            return Ok(None);
        }
        let ack = client.execute_checked_pending(&pending).await?;
        self.acknowledge(&pending, &ack, wall_time_ms()?)?;
        Ok(Some(ack))
    }

    pub fn acknowledge(
        &self,
        pending: &PendingMutation,
        ack: &FiberHookAck,
        now: u64,
    ) -> CoordinatorResult<Receipt> {
        let id = format!("shadow-ack:{}", pending.id);
        let intent = body(&(pending, ack))?;
        if let Some(old) = self.store.intent(&id)? {
            if old.body.bytes() != intent.bytes() {
                return Err(CoordinatorError::Conflict);
            }
            return Ok(Receipt {
                operation_id: id,
                revision: old.revision,
            });
        }
        let (revision, mut snapshot) = self.snapshot()?;
        let (edge, expected, state) = mutation_identity(&pending.mutation);
        if snapshot.pending.as_ref() != Some(pending)
            || ack.forwarding
            || ack.morph_edge_id != edge
            || ack.state != state
            || expected.checked_add(1) != Some(ack.provider_revision)
            || ack.opaque_morph_commitment != pending.expected_commitment
        {
            return Err(CoordinatorError::Invalid);
        }
        // Receipt only. It never creates/refreshes a desired observation.
        snapshot.pending = None;
        self.commit(
            revision,
            id,
            intent,
            &snapshot,
            Kind::EdgeMutationAcknowledged,
            now,
        )
    }
}

impl FiberHookClient {
    /// Only the coordinator calls this, immediately after the fresh handshake
    /// and persisted-observation check. Reuse the sole typed hook requests.
    async fn execute_checked_pending(
        &self,
        pending: &PendingMutation,
    ) -> AdapterResult<FiberHookAck> {
        let ack: FiberHookAck = match &pending.mutation {
            ShadowMutation::Register(r) => {
                if r.callback_endpoint != self.callback_endpoint.as_str() {
                    return Err(AdapterError::InvalidRequest);
                }
                self.call(REGISTER_EXTERNAL_EDGE_METHOD, r).await?
            }
            ShadowMutation::Update(r) => self.call(UPDATE_EXTERNAL_EDGE_METHOD, r).await?,
            ShadowMutation::Drain(r) => self.call(DRAIN_EXTERNAL_EDGE_METHOD, r).await?,
            ShadowMutation::Disable(r) => self.call(DISABLE_EXTERNAL_EDGE_METHOD, r).await?,
        };
        let (edge, expected, state) = mutation_identity(&pending.mutation);
        if ack.forwarding
            || ack.morph_edge_id != edge
            || ack.state != state
            || expected.checked_add(1) != Some(ack.provider_revision)
            || ack.opaque_morph_commitment != pending.expected_commitment
        {
            return Err(AdapterError::ProviderAckMismatch);
        }
        Ok(ack)
    }
}

#[cfg(test)]
mod tests;
