//! A consumer owns a separate runtime database. Copying an immutable source page
//! and advancing its cursor is one transaction; business revisions never move.
use crate::{Error, EventEnvelope, Result, digest, is_hash};
use morph_runtime_store::{
    Append, Body, Commit, Cursor, Family, History, Store, StoreError, Write,
};
use serde::{Deserialize, Serialize};

pub(crate) mod archive;
pub use archive::ArchiveReport;

pub const MAX_JOBS: usize = 1024;
/// Leave durable headroom for a final sealing transaction before the shared
/// store's hard history limit. Queue bodies/history are independently bounded.
pub const MAX_GENERATION_REVISIONS: u64 = 8000;
pub const MAX_ATTEMPTS: u8 = 8;
pub const MAX_REPLAYS: u8 = 3;
pub const MAX_IN_FLIGHT: usize = 4;
pub const LEASE_MS: u64 = 30_000;
pub const MAX_AGE_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Transport,
    HttpStatus,
    InvalidAck,
    Expired,
    Interrupted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    InFlight,
    Acknowledged,
    DeadLetter,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    schema: String,
    source: String,
    target: String,
    cursor_revision: u64,
    cursor_id: String,
    total: usize,
    phase: Phase,
    #[serde(deserialize_with = "required_link")]
    predecessor: Option<ArchiveLink>,
    #[serde(deserialize_with = "required_link")]
    successor: Option<ArchiveLink>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Active,
    Prepared,
    Sealed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveLink {
    peer_id: String,
    sealed_revision: u64,
    checkpoint: String,
}
fn required_link<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<ArchiveLink>, D::Error> {
    Option::deserialize(d)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    event_id: String,
    body: Body,
    enrolled_at_ms: u64,
    generation: u8,
    attempts: u8,
    status: Status,
    next_due_ms: u64,
    #[serde(deserialize_with = "required_failure")]
    failure: Option<Failure>,
    #[serde(deserialize_with = "required_string")]
    acknowledgement: Option<String>,
}
fn required_failure<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Failure>, D::Error> {
    Option::deserialize(d)
}
fn required_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::deserialize(d)
}

/// Private fields prevent a transport from inventing a different durable body.
pub struct Delivery {
    job: Job,
    target: String,
}
impl Delivery {
    pub(crate) fn target(&self) -> &str {
        &self.target
    }
    pub fn event_id(&self) -> &str {
        &self.job.event_id
    }
    pub fn body(&self) -> &[u8] {
        self.job.body.bytes()
    }
    pub fn attempt(&self) -> u8 {
        self.job.attempts
    }
    pub fn generation(&self) -> u8 {
        self.job.generation
    }
}
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Acknowledged,
    Failed(Failure),
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Health {
    pub retained: usize,
    pub pending: usize,
    pub in_flight: usize,
    pub acknowledged: usize,
    pub dead_letter: usize,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    pub oldest_pending_age_ms: u64,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    pub source_cursor_revision: u64,
    pub source_pending: bool,
    pub source_blocked: bool,
    pub archive_required: bool,
    pub sealed: bool,
    pub critical_pending: usize,
    pub critical_dead_letter: usize,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    pub oldest_critical_age_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub source_id: String,
    pub consumer_id: String,
    pub policy: String,
}
pub struct QueueObservation {
    pub binding: Binding,
    pub health: Health,
    pub delivery_allowed: bool,
    pub source_revision: u64,
    pub consumer_revision: u64,
}
pub struct Queue {
    source: Store,
    consumer: Store,
    target: String,
}
fn body<T: Serialize>(value: &T) -> Result<Body> {
    Ok(Body::new(
        serde_json::to_vec(value).map_err(|_| Error::Invalid)?,
    )?)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
}
fn write<T: Serialize>(id: String, value: &T) -> Result<Write> {
    Ok(Write {
        family: Family::Delivery,
        id,
        value: Some(body(value)?),
    })
}
fn job_id(event: &str) -> String {
    format!("job:{event}")
}
fn add_time(now: u64, delta: u64) -> Result<u64> {
    now.checked_add(delta)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(Error::Invalid)
}
fn valid_time(now: u64) -> Result<()> {
    if now == 0 || now > i64::MAX as u64 - MAX_AGE_MS {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
impl Queue {
    pub fn open(source: Store, consumer: Store, target: String) -> Result<Self> {
        if source.identity() == consumer.identity() || !is_hash(&target) {
            return Err(Error::Policy);
        }
        // Both ownership and payload integrity are verified before any dispatch.
        source.validate()?;
        consumer.validate()?;
        let snapshot = consumer.read(Family::Delivery, "consumer")?;
        if snapshot.record.is_none() {
            if snapshot.revision != 0 {
                return Err(Error::Policy);
            }
            let meta = Meta {
                schema: "morph.event.consumer.v2".into(),
                source: hex::encode(source.identity()),
                target: target.clone(),
                cursor_revision: 0,
                cursor_id: String::new(),
                total: 0,
                phase: Phase::Active,
                predecessor: None,
                successor: None,
            };
            consumer.commit(&Commit {
                operation_id: "consumer:init".into(),
                expected_revision: 0,
                intent: body(&meta)?,
                writes: vec![write("consumer".into(), &meta)?],
                events: vec![],
                attempts: vec![],
            })?;
        }
        let queue = Self {
            source,
            consumer,
            target,
        };
        let (_, meta) = queue.meta()?;
        if meta.phase == Phase::Prepared {
            return Err(Error::ArchiveRequired);
        }
        let jobs = queue.jobs()?;
        let report = queue.consumer.validate()?;
        if jobs.len() != meta.total || report.records != meta.total as u64 + 1 || report.events != 0
        {
            return Err(Error::Invalid);
        }
        Ok(queue)
    }
    fn check_delivery_policy(&self) -> Result<()> {
        if self.source.read(Family::Watch, "cursor")?.record.is_some() {
            let policy = self
                .source
                .read(Family::Watch, "delivery-policy")?
                .record
                .ok_or(Error::Policy)?;
            let policy: crate::SourceDeliveryPolicy = decode(policy.body.bytes())?;
            if !policy.allowed {
                return Err(Error::Policy);
            }
        }
        Ok(())
    }
    fn meta(&self) -> Result<(u64, Meta)> {
        let state = self.consumer.read(Family::Delivery, "consumer")?;
        let record = state.record.ok_or(Error::Policy)?;
        let meta: Meta = decode(record.body.bytes())?;
        if meta.schema != "morph.event.consumer.v2"
            || meta.source != hex::encode(self.source.identity())
            || meta.target != self.target
            || meta.total > MAX_JOBS
            || (meta.cursor_revision == 0) != meta.cursor_id.is_empty()
        {
            return Err(Error::Policy);
        }
        for link in [&meta.predecessor, &meta.successor].into_iter().flatten() {
            if !is_hash(&link.peer_id) || !is_hash(&link.checkpoint) || link.sealed_revision == 0 {
                return Err(Error::Invalid);
            }
        }
        if (meta.phase == Phase::Sealed) != meta.successor.is_some()
            || (meta.phase == Phase::Prepared && meta.predecessor.is_none())
        {
            return Err(Error::Invalid);
        }
        if meta.cursor_revision != 0 {
            let cursor = self
                .source
                .history_entry(History::Outbox, &meta.cursor_id)?
                .ok_or(Error::Policy)?;
            if cursor.revision != meta.cursor_revision {
                return Err(Error::Policy);
            }
        }
        Ok((state.revision, meta))
    }
    fn active_meta(&self) -> Result<(u64, Meta)> {
        let (revision, meta) = self.meta()?;
        if meta.phase != Phase::Active || revision >= MAX_GENERATION_REVISIONS {
            return Err(Error::ArchiveRequired);
        }
        Ok((revision, meta))
    }
    /// No network I/O. An unreadable/malformed page cannot advance the cursor.
    pub fn ingest(&self, now: u64) -> Result<usize> {
        self.check_delivery_policy()?;
        valid_time(now)?;
        let (revision, mut meta) = self.active_meta()?;
        let page = self.source.history(
            History::Outbox,
            &Cursor {
                revision: meta.cursor_revision,
                id: meta.cursor_id.clone(),
            },
            (MAX_JOBS - meta.total).clamp(1, 32),
        )?;
        if page.is_empty() {
            return Ok(0);
        }
        if meta.total + page.len() > MAX_JOBS {
            return Err(Error::Full);
        }
        let mut writes = Vec::new();
        for item in &page {
            let event = EventEnvelope::decode(item.body.bytes())?;
            if event.component == crate::Component::Watch
                && self.source.read(Family::Watch, "cursor")?.record.is_none()
            {
                return Err(Error::Policy);
            }
            if event.source_id != meta.source
                || event.source_revision != item.revision
                || event.event_id != EventEnvelope::identity(&meta.source, &item.id)
                || event.correlation_id != EventEnvelope::correlation(&item.operation_id)
            {
                return Err(Error::Invalid);
            }
            if self
                .consumer
                .read(Family::Delivery, &job_id(&event.event_id))?
                .record
                .is_some()
            {
                return Err(Error::Conflict);
            }
            let job = Job {
                event_id: event.event_id,
                body: item.body.clone(),
                enrolled_at_ms: now,
                generation: 0,
                attempts: 0,
                status: Status::Pending,
                next_due_ms: now,
                failure: None,
                acknowledgement: None,
            };
            writes.push(write(job_id(&job.event_id), &job)?);
            meta.cursor_revision = item.revision;
            meta.cursor_id = item.id.clone();
        }
        meta.total += page.len();
        writes.push(write("consumer".into(), &meta)?);
        self.consumer.commit_new(&Commit {
            operation_id: format!(
                "ingest:{}:{}",
                meta.cursor_revision,
                digest(b"morph.event.cursor.v1\0", meta.cursor_id.as_bytes())
            ),
            expected_revision: revision,
            intent: body(&meta)?,
            writes,
            events: vec![],
            attempts: vec![],
        })?;
        Ok(page.len())
    }
    fn jobs(&self) -> Result<Vec<Job>> {
        let mut jobs = Vec::new();
        let source_id = hex::encode(self.source.identity());
        let mut after = "job:".to_string();
        loop {
            let records = self.consumer.records(Family::Delivery, &after, 128)?;
            if records.is_empty() {
                break;
            }
            for record in records {
                after = record.id.clone();
                if !record.id.starts_with("job:") {
                    return Err(Error::Invalid);
                }
                let job: Job = decode(record.body.bytes())?;
                let event = EventEnvelope::decode(job.body.bytes())?;
                if job.event_id != event.event_id
                    || event.source_id != source_id
                    || record.id != job_id(&job.event_id)
                    || job.attempts > MAX_ATTEMPTS
                    || job.generation > MAX_REPLAYS
                {
                    return Err(Error::Invalid);
                }
                if (job.status == Status::Acknowledged
                    && (job.acknowledgement.as_deref()
                        != Some(
                            digest(b"morph.event.acknowledged_body.v1\0", job.body.bytes())
                                .as_str(),
                        )
                        || job.failure.is_some()
                        || job.attempts == 0))
                    || (job.status != Status::Acknowledged && job.acknowledgement.is_some())
                {
                    return Err(Error::Invalid);
                }
                jobs.push(job);
                if jobs.len() > MAX_JOBS {
                    return Err(Error::Full);
                }
            }
        }
        Ok(jobs)
    }
    pub fn binding(&self) -> Binding {
        Binding {
            source_id: hex::encode(self.source.identity()),
            consumer_id: hex::encode(self.consumer.identity()),
            policy: self.target.clone(),
        }
    }
    /// A read-only, exact-revision observation. Concurrent producer/consumer
    /// changes invalidate it rather than returning mixed green evidence.
    pub fn observe(&self, now: u64) -> Result<QueueObservation> {
        let source_revision = self.source.revision()?;
        let consumer_revision = self.consumer.revision()?;
        let health = self.health(now)?;
        let delivery_allowed = match self.check_delivery_policy() {
            Ok(()) => true,
            Err(Error::Policy) => false,
            Err(error) => return Err(error),
        };
        if self.source.revision()? != source_revision
            || self.consumer.revision()? != consumer_revision
        {
            return Err(Error::Conflict);
        }
        Ok(QueueObservation {
            binding: self.binding(),
            health,
            delivery_allowed,
            source_revision,
            consumer_revision,
        })
    }
    pub fn health(&self, now: u64) -> Result<Health> {
        valid_time(now)?;
        let (revision, meta) = self.meta()?;
        let jobs = self.jobs()?;
        if jobs.len() != meta.total {
            return Err(Error::Conflict);
        }
        let source_pending = !self
            .source
            .history(
                History::Outbox,
                &Cursor {
                    revision: meta.cursor_revision,
                    id: meta.cursor_id.clone(),
                },
                1,
            )?
            .is_empty();
        let mut result = Health {
            source_pending,
            source_blocked: source_pending
                && (meta.total == MAX_JOBS
                    || revision >= MAX_GENERATION_REVISIONS
                    || meta.phase != Phase::Active),
            archive_required: revision >= MAX_GENERATION_REVISIONS
                || meta.total == MAX_JOBS
                || meta.phase != Phase::Active,
            sealed: meta.phase == Phase::Sealed,
            retained: jobs.len(),
            source_cursor_revision: meta.cursor_revision,
            ..Health::default()
        };
        for job in jobs {
            let critical =
                EventEnvelope::decode(job.body.bytes())?.severity == crate::Severity::Critical;
            if critical && job.status == Status::DeadLetter {
                result.critical_dead_letter += 1;
            }
            let age = now.checked_sub(job.enrolled_at_ms).ok_or(Error::Invalid)?;
            match job.status {
                Status::Acknowledged => result.acknowledged += 1,
                Status::DeadLetter => result.dead_letter += 1,
                Status::Pending => result.pending += 1,
                Status::InFlight => result.in_flight += 1,
            }
            if matches!(job.status, Status::Pending | Status::InFlight) {
                result.oldest_pending_age_ms = result.oldest_pending_age_ms.max(age);
                if critical {
                    result.critical_pending += 1;
                    result.oldest_critical_age_ms = result.oldest_critical_age_ms.max(age);
                }
            }
        }
        Ok(result)
    }
    /// Durable claim precedes HTTP. Expired in-flight attempts may be duplicated,
    /// never silently treated as delivered. Receivers must deduplicate event_id.
    pub fn claim(&self, now: u64) -> Result<Option<Delivery>> {
        self.check_delivery_policy()?;
        valid_time(now)?;
        let (revision, _) = self.active_meta()?;
        let jobs = self.jobs()?;
        if jobs.iter().any(|j| now < j.enrolled_at_ms) {
            return Err(Error::Invalid);
        }
        if jobs
            .iter()
            .filter(|j| j.status == Status::InFlight && now < j.next_due_ms)
            .count()
            >= MAX_IN_FLIGHT
        {
            return Ok(None);
        }
        let Some(mut job) = jobs
            .into_iter()
            .filter(|j| {
                matches!(j.status, Status::Pending | Status::InFlight) && j.next_due_ms <= now
            })
            .min_by_key(|j| j.next_due_ms)
        else {
            return Ok(None);
        };
        if job.attempts >= MAX_ATTEMPTS || now - job.enrolled_at_ms >= MAX_AGE_MS {
            job.status = Status::DeadLetter;
            job.failure = Some(Failure::Expired);
            self.save(revision, &job, "expire")?;
            return Ok(None);
        }
        if job.status == Status::InFlight {
            job.failure = Some(Failure::Interrupted)
        }
        job.attempts += 1;
        job.status = Status::InFlight;
        job.next_due_ms = add_time(now, LEASE_MS)?;
        self.save(revision, &job, "start")?;
        Ok(Some(Delivery {
            job,
            target: self.target.clone(),
        }))
    }
    fn save(&self, revision: u64, job: &Job, phase: &str) -> Result<()> {
        let (current, _) = self.active_meta()?;
        if current != revision {
            return Err(Error::Conflict);
        }
        let id = format!(
            "{}:{}:{}:{phase}",
            job.event_id, job.generation, job.attempts
        );
        // Attempts are append-only and contain only safe delivery metadata.
        let evidence = serde_json::json!({"schema":"morph.event.delivery_attempt.v1","event_id":job.event_id,"generation":job.generation,"attempt":job.attempts,"phase":phase,"status":job.status,"next_due_ms":job.next_due_ms,"failure":job.failure,"acknowledgement":job.acknowledgement});
        self.consumer.commit_new(&Commit {
            operation_id: id.clone(),
            expected_revision: revision,
            intent: body(&evidence)?,
            writes: vec![write(job_id(&job.event_id), job)?],
            events: vec![],
            attempts: vec![Append {
                id,
                body: body(&evidence)?,
            }],
        })?;
        Ok(())
    }
    pub fn complete(&self, delivery: &Delivery, outcome: Outcome, now: u64) -> Result<()> {
        valid_time(now)?;
        if delivery.target != self.target {
            return Err(Error::Policy);
        }
        for _ in 0..4 {
            let snapshot = self
                .consumer
                .read(Family::Delivery, &job_id(delivery.event_id()))?;
            let mut job: Job = decode(snapshot.record.ok_or(Error::Conflict)?.body.bytes())?;
            if job.generation != delivery.job.generation
                || job.attempts != delivery.job.attempts
                || job.status != Status::InFlight
                || job.body.bytes() != delivery.body()
            {
                return Err(Error::Conflict);
            }
            if now < job.enrolled_at_ms {
                return Err(Error::Invalid);
            }
            match outcome {
                Outcome::Acknowledged => {
                    job.status = Status::Acknowledged;
                    job.failure = None;
                    job.acknowledgement = Some(digest(
                        b"morph.event.acknowledged_body.v1\0",
                        delivery.body(),
                    ));
                }
                Outcome::Failed(reason) => {
                    job.failure = Some(reason);
                    job.status =
                        if job.attempts >= MAX_ATTEMPTS || now - job.enrolled_at_ms >= MAX_AGE_MS {
                            Status::DeadLetter
                        } else {
                            Status::Pending
                        };
                    job.next_due_ms = add_time(now, 1000u64 << job.attempts.min(8))?;
                }
            }
            match self.save(snapshot.revision, &job, "finish") {
                Err(Error::Store(StoreError::Revision { .. })) => continue,
                result => return result,
            }
        }
        Err(Error::Conflict)
    }
    /// Operator-local repair only; same target, identity and bytes. No HTTP
    /// endpoint can erase evidence, redirect a queued event or reset all history.
    pub fn replay_dead_letter(&self, event_id: &str, now: u64) -> Result<()> {
        valid_time(now)?;
        if !is_hash(event_id) {
            return Err(Error::Invalid);
        }
        let snapshot = self.consumer.read(Family::Delivery, &job_id(event_id))?;
        let mut job: Job = decode(snapshot.record.ok_or(Error::Conflict)?.body.bytes())?;
        if job.status != Status::DeadLetter
            || job.generation >= MAX_REPLAYS
            || now < job.enrolled_at_ms
        {
            return Err(Error::Conflict);
        }
        job.generation += 1;
        job.attempts = 0;
        job.status = Status::Pending;
        job.enrolled_at_ms = now;
        job.next_due_ms = now;
        self.save(snapshot.revision, &job, "replay")
    }
}
