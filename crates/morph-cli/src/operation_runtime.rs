//! Shared exact-transaction runtime. This is broadcast/reconciliation evidence,
//! never signer authority. Operation adapters must authenticate and VM-preflight
//! a new body before registering it. No generic builder or fee bump exists here.
use crate::rpc::CkbRpcClient;
use anyhow::{Result, anyhow, ensure};
use ckb_jsonrpc_types::Status as RpcStatus;
use ckb_types::{H256, packed, prelude::*};
use morph_runtime_store::{Append, Body, Commit, Family, Protection, Store, Write};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = "morph.ckb_operation.v2";
pub(crate) mod observability;
const MAX_OPERATIONS: usize = 64;
const MAX_TX_BYTES: usize = 512 * 1024;
const MAX_BROADCASTS: u32 = 32;
const RETRY_DELAY_MS: u64 = 1000;
#[derive(Debug)]
struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation is busy")
    }
}
impl std::error::Error for Busy {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Funding,
    Activation,
    Splice,
    Publication,
    Finalisation,
    ConditionalResolution,
    CooperativeClose,
    Factory,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Spec {
    pub kind: Kind,
    pub genesis: String,
    pub rpc_url: String,
    pub context_id: String,
    pub evidence_digest: String,
    pub transaction_hex: String,
    pub required_depth: u64,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    pub replaces: Option<String>,
}
impl Spec {
    fn validate_replacement(&self, prior: &Self) -> Result<()> {
        ensure!(
            self.kind == Kind::CooperativeClose
                && prior.kind == self.kind
                && prior.context_id == self.context_id
                && prior.genesis == self.genesis
                && prior.evidence_digest == self.evidence_digest
                && prior.rpc_url == self.rpc_url
                && prior.required_depth == self.required_depth
                && prior.id()? != self.id()?,
            "replacement changes operation authority or policy"
        );
        // Close input zero is the authenticated State source. Changing that
        // source is rebasing, not a fee replacement of the same approval.
        ensure!(
            prior
                .transaction()?
                .raw()
                .inputs()
                .get(0)
                .map(|i| i.previous_output())
                == self
                    .transaction()?
                    .raw()
                    .inputs()
                    .get(0)
                    .map(|i| i.previous_output()),
            "replacement changes close source"
        );
        Ok(())
    }
    pub fn transaction(&self) -> Result<packed::Transaction> {
        ensure!(
            self.transaction_hex.len() <= MAX_TX_BYTES * 2,
            "operation transaction too large"
        );
        let bytes = hex::decode(&self.transaction_hex)?;
        ensure!(
            hex::encode(&bytes) == self.transaction_hex,
            "noncanonical operation bytes"
        );
        let tx = packed::Transaction::from_slice(&bytes)?;
        ensure!(
            !tx.raw().inputs().is_empty()
                && tx.raw().inputs().len() <= 64
                && tx.raw().outputs().len() <= 64,
            "operation transaction bound exceeded"
        );
        Ok(tx)
    }
    pub fn id(&self) -> Result<String> {
        let tx = self.transaction()?;
        for field in [&self.genesis, &self.context_id, &self.evidence_digest] {
            let bytes = hex::decode(field)?;
            ensure!(
                bytes.len() == 32 && hex::encode(bytes) == *field,
                "invalid operation identity"
            );
        }
        ensure!(
            (1..=1024).contains(&self.required_depth),
            "operation confirmation depth outside bounds"
        );
        crate::multi_asset_session_chain::rpc_endpoint(&self.rpc_url)?;
        if let Some(id) = &self.replaces {
            ensure!(
                id.len() == 64 && hex::decode(id)?.len() == 32 && id.to_lowercase() == *id,
                "invalid predecessor identity"
            );
        }
        let body = serde_json::to_vec(&(
            self.kind,
            &self.genesis,
            &self.context_id,
            hex::encode(tx.calc_tx_hash().as_slice()),
        ))?;
        Ok(hex::encode(morph_core::blake2b256(
            &[b"MORPH_CKB_OPERATION_V1\0".as_slice(), &body].concat(),
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Status {
    Ready,
    BroadcastUnknown,
    Pending,
    Proposed,
    Committed {
        block_hash: String,
        block_number: u64,
        depth: u64,
    },
    Finalised {
        block_hash: String,
        block_number: u64,
        depth: u64,
    },
    Replaced {
        by_operation_id: String,
        transaction_hash: String,
        block_hash: String,
        block_number: u64,
        depth: u64,
    },
    Unknown,
    Rejected,
    Reorged,
    OperatorAction,
    RpcUnavailable,
}
impl Status {
    pub fn depth(&self) -> u64 {
        match self {
            Self::Committed { depth, .. } | Self::Finalised { depth, .. } => *depth,
            _ => 0,
        }
    }
    fn inclusion(&self) -> bool {
        matches!(self, Self::Committed { .. } | Self::Finalised { .. })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    spec: Spec,
    preflight: Preflight,
    status: Status,
    broadcasts: u32,
    last_broadcast_ms: u64,
    observed_ms: u64,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    tip_hash: Option<String>,
    had_inclusion: bool,
    lifecycle: observability::Lifecycle,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preflight {
    pub fee: u64,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}
impl Preflight {
    fn validate(&self, spec: &Spec) -> Result<()> {
        ensure!(
            self.tx_size_bytes == spec.transaction()?.as_slice().len() && self.estimated_cycles > 0,
            "invalid operation preflight receipt"
        );
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub operation_id: String,
    pub replaces: Option<String>,
    pub transaction_hash: String,
    pub status: Status,
    pub broadcasts: u32,
    pub required_depth: u64,
    pub canonical_confirmations: u64,
    pub observed_ms: u64,
    pub tip_hash: Option<String>,
    pub preflight: Preflight,
}
pub(crate) struct Tracker {
    store: Store,
    _lock: crate::persistence::PrivateLock,
    id: String,
    spec: Spec,
    record: Option<Record>,
    can_broadcast: bool,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn body<T: Serialize>(value: &T) -> Result<Body> {
    Ok(Body::new(serde_json::to_vec(value)?)?)
}

impl Tracker {
    pub fn open(path: &Path, spec: Spec) -> Result<Self> {
        let id = spec.id()?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("operation store requires private parent"))?;
        let lock =
            crate::persistence::try_lock_private_path(&parent.join("operation-locks").join(&id))?
                .ok_or(Busy)?;
        let store = Store::open(path, Protection::private_plaintext())?;
        let snapshot = store.read(Family::Publication, &id)?;
        let record: Option<Record> = snapshot
            .record
            .map(|r| serde_json::from_slice(r.body.bytes()))
            .transpose()?;
        if let Some(record) = &record {
            ensure!(
                record.schema == SCHEMA
                    && record.spec == spec
                    && record.spec.id()? == id
                    && record.broadcasts <= MAX_BROADCASTS,
                "operation key names different or invalid contents"
            );
            record.lifecycle.validate(record)?;
            record.preflight.validate(&record.spec)?;
        }
        Ok(Self {
            store,
            _lock: lock,
            id,
            spec,
            record,
            can_broadcast: false,
        })
    }
    pub fn exists(&self) -> bool {
        self.record.is_some()
    }
    fn resume(path: &Path, id: &str) -> Result<Self> {
        ensure!(
            id.len() == 64 && hex::encode(hex::decode(id)?) == id,
            "invalid operation identity"
        );
        let store = Store::read_only(path, Protection::private_plaintext())?;
        let saved = store
            .read(Family::Publication, id)?
            .record
            .ok_or_else(|| anyhow!("unknown operation"))?;
        let record: Record = serde_json::from_slice(saved.body.bytes())?;
        ensure!(
            record.schema == SCHEMA && record.spec.id()? == id,
            "invalid operation record"
        );
        drop(store);
        Self::open(path, record.spec)
    }
    /// Called only after the adapter's full role checks and VM preflight.
    pub fn register(&mut self, preflight: Preflight) -> Result<()> {
        if self.exists() {
            ensure!(
                self.record
                    .as_ref()
                    .is_some_and(|r| r.preflight == preflight),
                "operation preflight differs from durable receipt"
            );
            return Ok(());
        }
        preflight.validate(&self.spec)?;
        let revision = self.store.revision()?;
        ensure!(
            self.store
                .records(Family::Publication, "", MAX_OPERATIONS + 1)?
                .len()
                < MAX_OPERATIONS,
            "operation queue full"
        );
        if let Some(predecessor) = &self.spec.replaces {
            let prior = self
                .store
                .read(Family::Publication, predecessor)?
                .record
                .ok_or_else(|| anyhow!("unknown replacement predecessor"))?;
            let prior: Record = serde_json::from_slice(prior.body.bytes())?;
            ensure!(
                prior.schema == SCHEMA && prior.spec.id()? == *predecessor,
                "invalid predecessor record"
            );
            self.spec.validate_replacement(&prior.spec)?;
        }
        let record = Record {
            schema: SCHEMA.into(),
            spec: self.spec.clone(),
            preflight,
            status: Status::Ready,
            broadcasts: 0,
            last_broadcast_ms: 0,
            observed_ms: 0,
            tip_hash: None,
            had_inclusion: false,
            lifecycle: observability::Lifecycle::new(now()?),
        };
        self.persist(record, revision, "register")
    }
    fn persist(&mut self, mut record: Record, revision: u64, transition: &str) -> Result<()> {
        record
            .lifecycle
            .record(self.record.as_ref(), &record.status, now()?)?;
        record.lifecycle.validate(&record)?;
        let operation_id = format!("operation:{}:{revision}:{transition}", self.id);
        let report = serde_json::json!({"schema":"morph.ckb_operation_transition.v1","operation_id":self.id,"transition":transition,"status":record.status,"broadcasts":record.broadcasts,"observed_ms":record.observed_ms,"tip_hash":record.tip_hash});
        let source_id = hex::encode(self.store.identity());
        let event = morph_events::EventEnvelope {
            schema: morph_events::EventSchema::Current,
            event_id: morph_events::EventEnvelope::identity(&source_id, &operation_id),
            source_id,
            source_revision: revision
                .checked_add(1)
                .ok_or_else(|| anyhow!("revision exhausted"))?,
            created_at_ms: now()?,
            component: morph_events::Component::Operation,
            evidence_level: morph_events::EvidenceLevel::LocalRecord,
            kind: match transition {
                "register" => morph_events::Kind::OperationRegistered,
                "broadcast" => morph_events::Kind::OperationBroadcastIntent,
                "observe" => morph_events::Kind::OperationObserved,
                _ => return Err(anyhow!("invalid operation transition")),
            },
            severity: match record.status {
                Status::OperatorAction => morph_events::Severity::Critical,
                Status::RpcUnavailable | Status::Rejected | Status::Reorged => {
                    morph_events::Severity::Warning
                }
                _ => morph_events::Severity::Info,
            },
            correlation_id: morph_events::EventEnvelope::correlation(&operation_id),
            subject_id: Some(self.id.clone()),
            funding_context_id: None,
            payment_hash: None,
            provider_revision: None,
            evidence_digest: Some(self.spec.evidence_digest.clone()),
        };
        self.store.commit_new(&Commit {
            operation_id: operation_id.clone(),
            expected_revision: revision,
            intent: body(&(
                report.clone(),
                (transition == "register").then_some(&self.spec),
            ))?,
            writes: vec![Write {
                family: Family::Publication,
                id: self.id.clone(),
                value: Some(body(&record)?),
            }],
            events: vec![Append {
                id: operation_id.clone(),
                body: Body::new(event.encode()?)?,
            }],
            attempts: vec![Append {
                id: operation_id,
                body: body(&report)?,
            }],
        })?;
        self.record = Some(record);
        Ok(())
    }
    fn report(&self) -> Result<Report> {
        let r = self
            .record
            .as_ref()
            .ok_or_else(|| anyhow!("operation is not registered"))?;
        Ok(Report {
            operation_id: self.id.clone(),
            replaces: self.spec.replaces.clone(),
            transaction_hash: format!("{:#x}", H256::from(self.spec.transaction()?.calc_tx_hash())),
            status: r.status.clone(),
            broadcasts: r.broadcasts,
            required_depth: self.spec.required_depth,
            canonical_confirmations: r.status.depth(),
            observed_ms: r.observed_ms,
            tip_hash: r.tip_hash.clone(),
            preflight: r.preflight.clone(),
        })
    }
    /// New RPC observation every time, including after a previously finalised state.
    pub fn reconcile(&mut self) -> Result<Report> {
        self.reconcile_with_budget(Duration::from_secs(5))
    }
    fn reconcile_with_budget(&mut self, budget: Duration) -> Result<Report> {
        self.can_broadcast = false;
        let revision = self.store.revision()?;
        let mut record = self
            .record
            .clone()
            .ok_or_else(|| anyhow!("operation is not registered"))?;
        let rpc = CkbRpcClient::new_signer(&self.spec.rpc_url, budget.min(Duration::from_secs(5)))?;
        let can_broadcast = match observe(&rpc, &self.store, &self.spec, record.had_inclusion) {
            Ok((status, tip, live)) => {
                record.had_inclusion |= status.inclusion();
                record.status = status;
                record.tip_hash = Some(tip);
                live
            }
            Err(_) => {
                record.status = Status::RpcUnavailable;
                record.tip_hash = None;
                false
            }
        };
        record.observed_ms = now()?;
        let same = self.record.as_ref().is_some_and(|old| {
            old.status == record.status
                && old.tip_hash == record.tip_hash
                && old.had_inclusion == record.had_inclusion
        });
        if same {
            self.record = Some(record);
        } else {
            self.persist(record, revision, "observe")?;
        }
        self.can_broadcast = can_broadcast;
        self.report()
    }
    /// Persist ambiguity before sending. A lost acknowledgment never clears this
    /// record or authorizes a changed body. Caller still owns full VM preflight.
    pub fn broadcast(&mut self) -> Result<Report> {
        ensure!(
            self.can_broadcast,
            "operation needs fresh live-input reconciliation before broadcast"
        );
        self.can_broadcast = false;
        let revision = self.store.revision()?;
        let mut record = self
            .record
            .clone()
            .ok_or_else(|| anyhow!("operation not registered"))?;
        let time = now()?;
        ensure!(
            record.broadcasts < MAX_BROADCASTS
                && (record.broadcasts == 0
                    || time
                        .checked_sub(record.last_broadcast_ms)
                        .is_some_and(|elapsed| elapsed >= RETRY_DELAY_MS)),
            "operation retry budget/cadence exhausted"
        );
        ensure!(
            time.checked_sub(record.observed_ms)
                .is_some_and(|elapsed| elapsed <= 5000),
            "operation observation expired"
        );
        record.broadcasts += 1;
        record.last_broadcast_ms = time;
        record.status = Status::BroadcastUnknown;
        record.tip_hash = None;
        self.persist(record, revision, "broadcast")?;
        #[cfg(all(test, target_os = "linux"))]
        crate::participant_signer::tests::checkpoint("operation_broadcast_intent");
        let rpc = CkbRpcClient::new_signer(&self.spec.rpc_url, Duration::from_secs(5))?;
        let transaction = self.spec.transaction()?;
        // A wrong/missing/error reply remains unknown; only canonical reconciliation
        // establishes success. Neither error text nor a returned hash is finality.
        let _result = rpc.send_transaction(transaction.into());
        self.reconcile()
    }
}

/// Offline recovery of the exact fully signed bytes. A saved observation is not
/// exported as present chain success, and this does not grant broadcast authority.
pub(crate) fn export(path: &Path, id: &str, output: &Path) -> Result<serde_json::Value> {
    let tracker = Tracker::resume(path, id)?;
    let tx = tracker.spec.transaction()?;
    crate::persistence::write_private_immutable(output, tx.as_slice())?;
    Ok(serde_json::json!({
        "operation_id": id,
        "transaction_hash": format!("{:#x}", H256::from(tx.calc_tx_hash())),
        "signed_transaction": output,
        "canonical_confirmation_checked": false
    }))
}

/// Each subscriber releases ownership between polls and chooses its own depth.
/// This endpoint never broadcasts and never changes the registered depth policy.
pub(crate) fn status(path: &Path, id: &str, depth: u64, wait_ms: u64) -> Result<serde_json::Value> {
    ensure!(
        (1..=1024).contains(&depth) && wait_ms <= 60_000,
        "operation wait/depth bound exceeded"
    );
    let start = std::time::Instant::now();
    let budget = Duration::from_millis(wait_ms);
    let mut last = None;
    loop {
        let remaining = if wait_ms == 0 {
            Duration::from_secs(5)
        } else {
            budget.saturating_sub(start.elapsed())
        };
        if remaining.is_zero() {
            break;
        }
        match Tracker::resume(path, id) {
            Ok(mut tracker) => {
                let report = tracker.reconcile_with_budget(remaining)?;
                let reached = report.canonical_confirmations >= depth;
                let needs_action = matches!(
                    report.status,
                    Status::Replaced { .. } | Status::OperatorAction | Status::Rejected
                );
                last = Some(
                    serde_json::json!({"required_depth":depth,"depth_reached":reached,"operation":report}),
                );
                if reached || needs_action || wait_ms == 0 {
                    break;
                }
            }
            Err(error) if error.downcast_ref::<Busy>().is_some() && wait_ms > 0 => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(250).min(budget.saturating_sub(start.elapsed())));
    }
    last.ok_or_else(|| anyhow!("operation observation remained busy until wait deadline"))
}

fn observe(
    rpc: &CkbRpcClient,
    store: &Store,
    spec: &Spec,
    had_inclusion: bool,
) -> Result<(Status, String, bool)> {
    let genesis = rpc
        .genesis_block_hash()?
        .ok_or_else(|| anyhow!("missing genesis"))?;
    ensure!(
        hex::encode(genesis.0) == spec.genesis,
        "operation RPC chain changed"
    );
    let tip = rpc.tip_header()?;
    let tx = spec.transaction()?;
    let hash: H256 = tx.calc_tx_hash().unpack();
    let result = rpc.transaction(hash.clone())?;
    let (status, live) = match result.tx_status.status {
        RpcStatus::Committed => {
            let (canonical, inclusion) = crate::rpc::canonical_transaction(rpc, hash, 1)?;
            ensure!(
                canonical.raw().as_slice() == tx.raw().as_slice(),
                "canonical operation body differs"
            );
            let depth = tip
                .number_value()?
                .checked_sub(inclusion.block_number)
                .and_then(|d| d.checked_add(1))
                .ok_or_else(|| anyhow!("operation above tip"))?;
            let status = if depth >= spec.required_depth {
                Status::Finalised {
                    block_hash: inclusion.block_hash,
                    block_number: inclusion.block_number,
                    depth,
                }
            } else {
                Status::Committed {
                    block_hash: inclusion.block_hash,
                    block_number: inclusion.block_number,
                    depth,
                }
            };
            (status, false)
        }
        RpcStatus::Pending => (Status::Pending, false),
        RpcStatus::Proposed => (Status::Proposed, false),
        RpcStatus::Rejected | RpcStatus::Unknown => {
            let mut all_live = true;
            for input in tx.raw().inputs() {
                let cell = rpc.canonical_live_cell(input.previous_output().into(), false)?;
                if cell.status != "live" {
                    all_live = false;
                }
            }
            if !all_live {
                (
                    replacement_winner(rpc, store, spec, tip.number_value()?)?
                        .unwrap_or(Status::OperatorAction),
                    false,
                )
            } else if had_inclusion {
                (Status::Reorged, true)
            } else if result.tx_status.status == RpcStatus::Rejected {
                (Status::Rejected, false)
            } else {
                (Status::Unknown, true)
            }
        }
    };
    ensure!(
        rpc.tip_header()?.hash == tip.hash,
        "operation view changed during reconciliation"
    );
    rpc.ensure_deadline()?;
    Ok((status, tip.hash, live))
}

/// Only a declared replacement family is searched. A cached status or an
/// unrelated transaction sharing a channel name cannot establish the winner.
fn replacement_winner(
    rpc: &CkbRpcClient,
    store: &Store,
    spec: &Spec,
    tip: u64,
) -> Result<Option<Status>> {
    use std::collections::{BTreeMap, BTreeSet};
    let rows = store.records(Family::Publication, "", MAX_OPERATIONS + 1)?;
    ensure!(
        rows.len() <= MAX_OPERATIONS,
        "operation queue bound exceeded"
    );
    let mut specs = BTreeMap::new();
    for row in rows {
        let record: Record = serde_json::from_slice(row.body.bytes())?;
        ensure!(
            record.schema == SCHEMA && record.spec.id()? == row.id,
            "invalid operation family record"
        );
        specs.insert(row.id, record.spec);
    }
    let own_id = spec.id()?;
    let mut family = BTreeSet::from([own_id.clone()]);
    let mut neighbours: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, candidate) in &specs {
        if let Some(parent) = &candidate.replaces {
            neighbours.entry(id).or_default().push(parent);
            neighbours.entry(parent).or_default().push(id);
        }
    }
    let mut pending = vec![own_id.clone()];
    while let Some(id) = pending.pop() {
        rpc.ensure_deadline()?;
        for neighbour in neighbours.get(id.as_str()).into_iter().flatten() {
            if family.contains(*neighbour) {
                continue;
            }
            let current = specs
                .get(&id)
                .ok_or_else(|| anyhow!("missing replacement body"))?;
            let next = specs
                .get(*neighbour)
                .ok_or_else(|| anyhow!("missing replacement predecessor"))?;
            if current.replaces.as_deref() == Some(*neighbour) {
                current.validate_replacement(next)?;
            } else {
                next.validate_replacement(current)?;
            }
            family.insert((*neighbour).to_owned());
            pending.push((*neighbour).to_owned());
        }
    }
    for id in family.into_iter().filter(|id| *id != own_id) {
        rpc.ensure_deadline()?;
        let candidate = specs
            .get(&id)
            .ok_or_else(|| anyhow!("missing replacement body"))?;
        let tx = candidate.transaction()?;
        let hash: H256 = tx.calc_tx_hash().unpack();
        if rpc.transaction(hash.clone())?.tx_status.status != RpcStatus::Committed {
            continue;
        }
        let (canonical, inclusion) = crate::rpc::canonical_transaction(rpc, hash.clone(), 1)?;
        ensure!(
            canonical.raw().as_slice() == tx.raw().as_slice(),
            "canonical replacement body differs"
        );
        let depth = tip
            .checked_sub(inclusion.block_number)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| anyhow!("replacement above tip"))?;
        return Ok(Some(Status::Replaced {
            by_operation_id: id,
            transaction_hash: format!("{hash:#x}"),
            block_hash: inclusion.block_hash,
            block_number: inclusion.block_number,
            depth,
        }));
    }
    Ok(None)
}

#[cfg(all(test, feature = "devnet"))]
mod tests;
