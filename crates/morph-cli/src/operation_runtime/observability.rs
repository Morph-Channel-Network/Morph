//! Bounded durable lifecycle counts. Saved chain observations are historical;
//! a metrics scrape never reconciles, broadcasts or claims current finality.
use super::*;
use std::{path::PathBuf, time::Instant};

const BUDGET_MS: u64 = 5_000;
const STATES: [&str; 12] = [
    "ready",
    "broadcast_unknown",
    "pending",
    "proposed",
    "committed",
    "finalised",
    "replaced",
    "unknown",
    "rejected",
    "reorged",
    "operator_action",
    "rpc_unavailable",
];
const KINDS: [Kind; 8] = [
    Kind::Funding,
    Kind::Activation,
    Kind::Splice,
    Kind::Publication,
    Kind::Finalisation,
    Kind::ConditionalResolution,
    Kind::CooperativeClose,
    Kind::Factory,
];
const KIND_LABELS: [&str; 8] = [
    "funding",
    "activation",
    "splice",
    "publication",
    "finalisation",
    "conditional_resolution",
    "cooperative_close",
    "factory",
];
fn state(status: &Status) -> usize {
    match status {
        Status::Ready => 0,
        Status::BroadcastUnknown => 1,
        Status::Pending => 2,
        Status::Proposed => 3,
        Status::Committed { .. } => 4,
        Status::Finalised { .. } => 5,
        Status::Replaced { .. } => 6,
        Status::Unknown => 7,
        Status::Rejected => 8,
        Status::Reorged => 9,
        Status::OperatorAction => 10,
        Status::RpcUnavailable => 11,
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lifecycle {
    registered_ms: u64,
    entered_ms: u64,
    entries: [u64; 12],
}
impl Lifecycle {
    pub(super) fn new(time: u64) -> Self {
        Self {
            registered_ms: time,
            entered_ms: time,
            entries: [0; 12],
        }
    }
    pub(super) fn record(
        &mut self,
        prior: Option<&Record>,
        status: &Status,
        time: u64,
    ) -> Result<()> {
        let index = state(status);
        if prior.is_none_or(|old| state(&old.status) != index) {
            self.entries[index] = self.entries[index]
                .checked_add(1)
                .ok_or_else(|| anyhow!("operation lifecycle counter exhausted"))?;
            // Backward wall time cannot erase an older timestamp. Export then
            // fails closed while that timestamp is ahead of the observation.
            self.entered_ms = time.max(self.entered_ms);
        }
        Ok(())
    }
    pub(super) fn validate(&self, record: &Record) -> Result<()> {
        ensure!(
            self.registered_ms > 0
                && self.entered_ms >= self.registered_ms
                && self.entries[0] == 1
                && self.entries[state(&record.status)] > 0
                && self.entries[1] == u64::from(record.broadcasts)
                && record.broadcasts <= MAX_BROADCASTS,
            "invalid operation lifecycle evidence"
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct StateCount {
    state: &'static str,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    current_records: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    entries: u64,
}
#[derive(Serialize)]
struct Counts {
    kind: &'static str,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    records: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    broadcast_intents: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    replacements_registered: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    oldest_unresolved_ms: u64,
    states: Vec<StateCount>,
}
impl Counts {
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            records: 0,
            broadcast_intents: 0,
            replacements_registered: 0,
            oldest_unresolved_ms: 0,
            states: STATES
                .into_iter()
                .map(|state| StateCount {
                    state,
                    current_records: 0,
                    entries: 0,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Snapshot {
    #[serde(with = "morph_packages::public_encoding::decimal")]
    revision: u64,
    counts: Vec<Counts>,
}
fn load(path: &Path, wall: u64) -> Result<Snapshot> {
    let store = Store::read_only(path, Protection::private_plaintext())?;
    let revision = store.validate()?.revision;
    let rows = store.records(Family::Publication, "", MAX_OPERATIONS + 1)?;
    ensure!(
        rows.len() <= MAX_OPERATIONS,
        "operation count bound exceeded"
    );
    // Reopen at the end to detect a replaced path, not just changes to the old
    // database handle. Each record's identity/body remains independently checked.
    let identity = store.identity();
    let mut counts: Vec<_> = KIND_LABELS.into_iter().map(Counts::new).collect();
    for row in rows {
        let record: Record = serde_json::from_slice(row.body.bytes())?;
        ensure!(
            record.schema == SCHEMA && record.spec.id()? == row.id,
            "invalid operation record"
        );
        record.lifecycle.validate(&record)?;
        let entries = record
            .lifecycle
            .entries
            .iter()
            .try_fold(0u64, |sum, value| sum.checked_add(*value))
            .ok_or_else(|| anyhow!("lifecycle counter overflow"))?;
        ensure!(
            entries <= row.revision,
            "lifecycle entries exceed persisted revisions"
        );
        ensure!(
            record.lifecycle.entered_ms <= wall
                && record.observed_ms <= wall
                && record.last_broadcast_ms <= wall,
            "operation clock is ahead of observation"
        );
        record.preflight.validate(&record.spec)?;
        let index = KINDS
            .iter()
            .position(|kind| *kind == record.spec.kind)
            .ok_or_else(|| anyhow!("unknown operation kind"))?;
        let count = &mut counts[index];
        count.records += 1;
        count.broadcast_intents += u64::from(record.broadcasts);
        count.replacements_registered += u64::from(record.spec.replaces.is_some());
        count.states[state(&record.status)].current_records += 1;
        for (value, entry) in count.states.iter_mut().zip(record.lifecycle.entries) {
            value.entries = value
                .entries
                .checked_add(entry)
                .ok_or_else(|| anyhow!("lifecycle totals overflow"))?;
        }
        let resolved = matches!(record.status, Status::Finalised { .. })
            || matches!(record.status, Status::Replaced { depth, .. } if depth >= record.spec.required_depth);
        if !resolved {
            count.oldest_unresolved_ms = count
                .oldest_unresolved_ms
                .max(wall - record.lifecycle.registered_ms);
        }
    }
    let current = Store::read_only(path, Protection::private_plaintext())?;
    ensure!(
        store.revision()? == revision
            && current.revision()? == revision
            && current.identity() == identity,
        "operation store changed during observation"
    );
    Ok(Snapshot { revision, counts })
}

#[derive(Serialize)]
struct Observation {
    schema: &'static str,
    scope: &'static str,
    store_available: bool,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    checked_at_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    valid_until_ms: u64,
    snapshot: Option<Snapshot>,
}
fn metrics(observation: &Observation) -> String {
    use std::fmt::Write;
    let mut text = format!(
        "# TYPE morph_operation_store_available gauge\nmorph_operation_store_available {}\n",
        u8::from(observation.store_available)
    );
    for (name, kind) in [
        ("records", "gauge"),
        ("broadcast_intents_total", "counter"),
        ("replacements_registered_total", "counter"),
        ("oldest_unresolved_milliseconds", "gauge"),
        ("state_records", "gauge"),
        ("state_entries_total", "counter"),
    ] {
        let _ = writeln!(text, "# TYPE morph_operation_{name} {kind}");
    }
    for (index, kind) in KIND_LABELS.iter().enumerate() {
        let count = observation.snapshot.as_ref().map(|s| &s.counts[index]);
        for (name, value) in [
            ("records", count.map(|c| c.records)),
            (
                "broadcast_intents_total",
                count.map(|c| c.broadcast_intents),
            ),
            (
                "replacements_registered_total",
                count.map(|c| c.replacements_registered),
            ),
            (
                "oldest_unresolved_milliseconds",
                count.map(|c| c.oldest_unresolved_ms),
            ),
        ] {
            let value = value.map(|n| n.to_string()).unwrap_or_else(|| "NaN".into());
            let _ = writeln!(text, "morph_operation_{name}{{kind=\"{kind}\"}} {value}");
        }
        for (index, state) in STATES.iter().enumerate() {
            for (name, value) in [
                (
                    "state_records",
                    count.map(|c| c.states[index].current_records),
                ),
                (
                    "state_entries_total",
                    count.map(|c| c.states[index].entries),
                ),
            ] {
                let value = value.map(|n| n.to_string()).unwrap_or_else(|| "NaN".into());
                let _ = writeln!(
                    text,
                    "morph_operation_{name}{{kind=\"{kind}\",state=\"{state}\"}} {value}"
                );
            }
        }
    }
    text
}

pub(crate) fn run(path: PathBuf, as_metrics: bool) -> Result<()> {
    let started = Instant::now();
    let checked = now()?;
    let boot = morph_observability::clock::read().ok();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("morph-operation-observation".into())
        .spawn(move || {
            let _ = tx.send(load(&path, checked).ok());
        })?;
    let snapshot = rx
        .recv_timeout(Duration::from_millis(BUDGET_MS).saturating_sub(started.elapsed()))
        .ok()
        .flatten();
    let wall = now()?;
    let end = morph_observability::clock::read().ok();
    let fresh = started.elapsed() < Duration::from_millis(BUDGET_MS)
        && wall >= checked
        && wall - checked < BUDGET_MS
        && boot
            .as_ref()
            .zip(end.as_ref())
            .is_some_and(|(a, b)| a.id == b.id && b.ms >= a.ms && b.ms - a.ms < BUDGET_MS);
    let snapshot = snapshot.filter(|_| fresh);
    let observation = Observation {
        schema: "morph.operation_observability.v1",
        scope: "saved_operation_history",
        store_available: snapshot.is_some(),
        checked_at_ms: checked,
        valid_until_ms: checked.saturating_add(BUDGET_MS),
        snapshot,
    };
    if as_metrics {
        print!("{}", metrics(&observation));
    } else {
        println!("{}", serde_json::to_string(&observation)?);
        ensure!(
            observation.store_available,
            "operation observations unavailable"
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "devnet"))]
mod tests;
