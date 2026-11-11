//! Coordinated runtime durability. Keys, signer reservations and signing journals
//! deliberately have no record family in this store.
#![forbid(unsafe_code)]

mod native;
mod protection;

use std::{collections::BTreeSet, path::Path, sync::Mutex, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub use protection::Protection;

pub const SCHEMA_VERSION: u32 = 1;
pub const SCHEMA_SQL: &str = include_str!("schema.sql");
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TRANSACTION_BYTES: usize = 72 * 1024 * 1024;
pub const MAX_STORED_BYTES: i64 = 256 * 1024 * 1024;
pub const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RECORDS: i64 = 4096;
pub const MAX_HISTORY_ROWS: i64 = 16384;
pub const MAX_CHANGES: usize = 256;
pub const MAX_PAGE_SIZE: usize = 128;
const APPLICATION_ID: i64 = 0x4d525431;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("runtime store is busy")]
    Busy,
    #[error("runtime store I/O failed")]
    Io,
    #[error("runtime store is full")]
    Full,
    #[error("runtime store is corrupt or the encryption key is wrong")]
    Corrupt,
    #[error("unsupported runtime store schema; reset unpublished development state")]
    Schema,
    #[error("runtime store encryption mode does not match")]
    Protection,
    #[error("runtime store requires private owner-controlled regular files")]
    Permissions,
    #[error("runtime store is read-only")]
    ReadOnly,
    #[error("runtime transaction exceeds a configured limit or has invalid identifiers")]
    Invalid,
    #[error("runtime revision conflict: expected {expected}, current {actual}")]
    Revision { expected: u64, actual: u64 },
    #[error("runtime operation ID already names different contents")]
    Conflict,
    #[error("runtime commit outcome is uncertain; reopen and retry the exact operation")]
    CommitUncertain,
    #[error("runtime store lock is poisoned")]
    Poisoned,
    #[error("runtime private storage is supported only on Linux")]
    UnsupportedPlatform,
}
pub type Result<T> = std::result::Result<T, StoreError>;

fn sql_error(error: rusqlite::Error) -> StoreError {
    use rusqlite::ErrorCode;
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreError::Busy,
        Some(ErrorCode::DiskFull) => StoreError::Full,
        Some(ErrorCode::ReadOnly) => StoreError::ReadOnly,
        Some(ErrorCode::SystemIoFailure | ErrorCode::CannotOpen) => StoreError::Io,
        Some(ErrorCode::ConstraintViolation) => StoreError::Conflict,
        _ => StoreError::Corrupt,
    }
}

/// Runtime projections only. Never add keys, votes or signer-journal snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Hub,
    Gateway,
    Payment,
    Edge,
    Publication,
    /// Consumer checkpoints only; never the producer's signer or business state.
    Delivery,
    Watch,
}
impl Family {
    fn tag(self) -> &'static str {
        match self {
            Self::Hub => "hub",
            Self::Gateway => "gateway",
            Self::Payment => "payment",
            Self::Edge => "edge",
            Self::Publication => "publication",
            Self::Delivery => "delivery",
            Self::Watch => "watch",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "hub" => Ok(Self::Hub),
            "gateway" => Ok(Self::Gateway),
            "payment" => Ok(Self::Payment),
            "edge" => Ok(Self::Edge),
            "publication" => Ok(Self::Publication),
            "delivery" => Ok(Self::Delivery),
            "watch" => Ok(Self::Watch),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// Deliberately redacted, including inside error/debug output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Body(#[serde(with = "hex_body")] Vec<u8>);
impl Body {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(StoreError::Invalid);
        }
        Ok(Self(bytes))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Body([REDACTED])")
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}
mod hex_body {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.len() > super::MAX_PAYLOAD_BYTES * 2
            || s.bytes()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("invalid bounded runtime body"));
        }
        hex::decode(s).map_err(|_| serde::de::Error::custom("invalid runtime body"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Write {
    pub family: Family,
    pub id: String,
    /// None deletes a mutable projection, never an immutable recovery record.
    #[serde(deserialize_with = "required_value")]
    pub value: Option<Body>,
}
fn required_value<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Body>, D::Error> {
    Option::<Body>::deserialize(d)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Append {
    pub id: String,
    pub body: Body,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub operation_id: String,
    pub expected_revision: u64,
    /// Exact recovery instruction, not a mutable summary or a signing request.
    pub intent: Body,
    pub writes: Vec<Write>,
    pub events: Vec<Append>,
    pub attempts: Vec<Append>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub operation_id: String,
    pub revision: u64,
}
#[derive(Debug)]
pub struct Record {
    pub id: String,
    pub revision: u64,
    pub body: Body,
}
#[derive(Debug)]
pub struct Snapshot {
    pub revision: u64,
    pub record: Option<Record>,
}
#[derive(Debug)]
pub struct HistoryRecord {
    pub id: String,
    pub operation_id: String,
    pub revision: u64,
    pub body: Body,
}
#[derive(Debug, Clone, Default)]
pub struct Cursor {
    pub revision: u64,
    pub id: String,
}
impl HistoryRecord {
    pub fn cursor(&self) -> Cursor {
        Cursor {
            revision: self.revision,
            id: self.id.clone(),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub enum History {
    Intent,
    Outbox,
    Attempt,
}
impl History {
    fn table(self) -> &'static str {
        match self {
            Self::Intent => "commits",
            Self::Outbox => "outbox",
            Self::Attempt => "attempts",
        }
    }
    fn id(self) -> &'static str {
        match self {
            Self::Intent => "operation_id",
            Self::Outbox => "event_id",
            Self::Attempt => "attempt_id",
        }
    }
    fn column(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            _ => "payload",
        }
    }
}
#[derive(Debug, Serialize)]
pub struct ValidationReport {
    pub schema_version: u32,
    pub revision: u64,
    pub encrypted: bool,
    pub records: u64,
    pub intents: u64,
    pub events: u64,
    pub attempts: u64,
    pub payload_bytes: u64,
}

pub struct Store {
    connection: Mutex<Connection>,
    protection: Protection,
    store_id: [u8; 32],
    writable: bool,
}

impl Store {
    /// Public database identity; binds consumer cursors to this exact source.
    pub fn identity(&self) -> [u8; 32] {
        self.store_id
    }

    pub fn memory(protection: Protection) -> Result<Self> {
        Self::initialize(
            Connection::open_in_memory().map_err(sql_error)?,
            protection,
            true,
            true,
        )
    }
    /// Create only at a missing path; an empty/truncated existing file is corruption.
    pub fn open(path: &Path, protection: Protection) -> Result<Self> {
        let (connection, created) = native::open(path, false)?;
        let store = Self::initialize(connection, protection, created, true)?;
        if created {
            native::sync_parent(path)?;
        }
        Ok(store)
    }
    /// Never creates or repairs files. Validate before reporting health.
    pub fn read_only(path: &Path, protection: Protection) -> Result<Self> {
        let (connection, _) = native::open(path, true)?;
        Self::initialize(connection, protection, false, false)
    }
    fn initialize(
        mut connection: Connection,
        protection: Protection,
        created: bool,
        writable: bool,
    ) -> Result<Self> {
        connection
            .busy_timeout(Duration::from_millis(250))
            .map_err(sql_error)?;
        connection
            .set_limit(
                rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
                (MAX_TRANSACTION_BYTES * 2) as i32,
            )
            .map_err(sql_error)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;",
            )
            .map_err(sql_error)?;
        if writable {
            connection
                .execute_batch("PRAGMA synchronous=EXTRA;")
                .map_err(sql_error)?;
        }
        if created {
            connection
                .pragma_update(None, "page_size", 4096)
                .map_err(sql_error)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            transaction.execute_batch(SCHEMA_SQL).map_err(sql_error)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(sql_error)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(sql_error)?;
            let mut id = [0; 32];
            getrandom::fill(&mut id).map_err(|_| StoreError::Io)?;
            let check =
                protection.seal(&id, "metadata", "key_check", 0, b"morph runtime store v1")?;
            transaction
                .execute(
                    "INSERT INTO metadata VALUES(1,1,?1,?2,?3,0)",
                    params![id.as_slice(), protection.is_encrypted(), check],
                )
                .map_err(sql_error)?;
            transaction
                .commit()
                .map_err(|_| StoreError::CommitUncertain)?;
        }
        check_schema(&connection)?;
        let page_size: i64 = connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .map_err(sql_error)?;
        if page_size != 4096 {
            return Err(StoreError::Schema);
        }
        let (id, encrypted, check): (Vec<u8>, bool, Vec<u8>) = connection
            .query_row(
                "SELECT store_id,encrypted,key_check FROM metadata WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(sql_error)?;
        let store_id: [u8; 32] = id.try_into().map_err(|_| StoreError::Corrupt)?;
        if protection.is_encrypted() != encrypted {
            return Err(StoreError::Protection);
        }
        if protection
            .open(&store_id, "metadata", "key_check", 0, &check)?
            .as_slice()
            != b"morph runtime store v1"
        {
            return Err(StoreError::Corrupt);
        }
        if writable {
            let mode: String = connection
                .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
                .map_err(sql_error)?;
            if mode != "delete" && mode != "memory" {
                return Err(StoreError::Schema);
            }
            connection.execute_batch("PRAGMA synchronous=EXTRA; PRAGMA secure_delete=ON; PRAGMA journal_size_limit=0; PRAGMA max_page_count=131072;").map_err(sql_error)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            protection,
            store_id,
            writable,
        })
    }

    /// Current global revision, for observational snapshot consistency checks.
    pub fn revision(&self) -> Result<u64> {
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        current_revision(&connection)
    }

    pub fn read(&self, family: Family, id: &str) -> Result<Snapshot> {
        valid_id(id)?;
        let mut connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = connection.transaction().map_err(sql_error)?;
        let revision = current_revision(&tx)?;
        let raw: Option<(u64, Vec<u8>)> = tx
            .query_row(
                "SELECT revision,payload FROM records WHERE family=?1 AND record_id=?2",
                params![family.tag(), id],
                |r| Ok((uint(r, 0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        let record = raw
            .map(|(r, p)| {
                Ok(Record {
                    id: id.into(),
                    revision: r,
                    body: self.decode(family.tag(), id, r, &p)?,
                })
            })
            .transpose()?;
        Ok(Snapshot { revision, record })
    }

    pub fn records(&self, family: Family, after_id: &str, limit: usize) -> Result<Vec<Record>> {
        valid_page(after_id, limit)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut statement = connection.prepare("SELECT record_id,revision,payload FROM records WHERE family=?1 AND record_id>?2 ORDER BY record_id LIMIT ?3").map_err(sql_error)?;
        let rows = statement
            .query_map(params![family.tag(), after_id, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, uint(r, 1)?, r.get::<_, Vec<u8>>(2)?))
            })
            .map_err(sql_error)?;
        rows.map(|row| {
            let (id, revision, p) = row.map_err(sql_error)?;
            let body = self.decode(family.tag(), &id, revision, &p)?;
            Ok(Record { id, revision, body })
        })
        .collect()
    }

    /// Revision plus ID pagination does not skip later inserts with smaller IDs.
    pub fn history(
        &self,
        kind: History,
        after: &Cursor,
        limit: usize,
    ) -> Result<Vec<HistoryRecord>> {
        valid_page(&after.id, limit)?;
        if after.revision > i64::MAX as u64 {
            return Err(StoreError::Invalid);
        }
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let query = format!(
            "SELECT {},operation_id,revision,{} FROM {} WHERE revision>?1 OR (revision=?1 AND {}>?2) ORDER BY revision,{} LIMIT ?3",
            kind.id(),
            kind.column(),
            kind.table(),
            kind.id(),
            kind.id()
        );
        let mut statement = connection.prepare(&query).map_err(sql_error)?;
        let rows = statement
            .query_map(
                params![after.revision as i64, after.id, limit as i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        uint(r, 2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .map_err(sql_error)?;
        rows.map(|row| {
            let (id, operation_id, revision, p) = row.map_err(sql_error)?;
            let body = self.decode(kind.table(), &id, revision, &p)?;
            Ok(HistoryRecord {
                id,
                operation_id,
                revision,
                body,
            })
        })
        .collect()
    }

    /// Point lookup of an immutable history record, for exact cursor/retry validation.
    pub fn history_entry(&self, kind: History, id: &str) -> Result<Option<HistoryRecord>> {
        valid_id(id)?;
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let query = format!(
            "SELECT operation_id,revision,{} FROM {} WHERE {}=?1",
            kind.column(),
            kind.table(),
            kind.id()
        );
        let value: Option<(String, u64, Vec<u8>)> = connection
            .query_row(&query, [id], |r| Ok((r.get(0)?, uint(r, 1)?, r.get(2)?)))
            .optional()
            .map_err(sql_error)?;
        value
            .map(|(operation_id, revision, payload)| {
                Ok(HistoryRecord {
                    id: id.into(),
                    operation_id,
                    revision,
                    body: self.decode(kind.table(), id, revision, &payload)?,
                })
            })
            .transpose()
    }
    /// Point lookup of an immutable intent for durable retry reconciliation.
    pub fn intent(&self, operation_id: &str) -> Result<Option<HistoryRecord>> {
        self.history_entry(History::Intent, operation_id)
    }

    pub fn commit(&self, commit: &Commit) -> Result<Receipt> {
        self.commit_observed(commit, |_| {})
    }

    /// Acquire a new durable intent exactly once. Unlike `commit`, a matching
    /// previous transaction is rejected instead of returning its receipt. Use
    /// this when only the winning invocation may start an external side effect;
    /// cached commit receipts are not fresh execution leases.
    pub fn commit_new(&self, commit: &Commit) -> Result<Receipt> {
        self.commit_inner(commit, |_| {}, false)
    }

    fn commit_observed(
        &self,
        commit: &Commit,
        observer: impl FnMut(CommitStage),
    ) -> Result<Receipt> {
        self.commit_inner(commit, observer, true)
    }

    fn commit_inner(
        &self,
        commit: &Commit,
        mut observer: impl FnMut(CommitStage),
        accept_replay: bool,
    ) -> Result<Receipt> {
        if !self.writable {
            return Err(StoreError::ReadOnly);
        }
        validate_commit(commit)?;
        let encoded = Zeroizing::new(serde_json::to_vec(commit).map_err(|_| StoreError::Invalid)?);
        let hash = protection::digest(b"morph.runtime.commit.v1\0", &encoded);
        let mut connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let prior: Option<(Vec<u8>, u64)> = tx
            .query_row(
                "SELECT request_hash,revision FROM commits WHERE operation_id=?1",
                [&commit.operation_id],
                |r| Ok((r.get(0)?, uint(r, 1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        if let Some((prior_hash, revision)) = prior {
            if prior_hash != hash || !accept_replay {
                return Err(StoreError::Conflict);
            }
            return Ok(Receipt {
                operation_id: commit.operation_id.clone(),
                revision,
            });
        }
        let actual = current_revision(&tx)?;
        if actual != commit.expected_revision {
            return Err(StoreError::Revision {
                expected: commit.expected_revision,
                actual,
            });
        }
        let revision = actual
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StoreError::Full)?;
        let intent = self.encode("commits", &commit.operation_id, revision, &commit.intent)?;
        tx.execute(
            "INSERT INTO commits VALUES(?1,?2,?3,?4)",
            params![
                commit.operation_id,
                revision as i64,
                hash.as_slice(),
                intent
            ],
        )
        .map_err(sql_error)?;
        for write in &commit.writes {
            match &write.value {
                Some(body) => {
                    let payload = self.encode(write.family.tag(), &write.id, revision, body)?;
                    tx.execute("INSERT INTO records VALUES(?1,?2,?3,?4) ON CONFLICT(family,record_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload",params![write.family.tag(),write.id,revision as i64,payload]).map_err(sql_error)?;
                }
                None => {
                    tx.execute(
                        "DELETE FROM records WHERE family=?1 AND record_id=?2",
                        params![write.family.tag(), write.id],
                    )
                    .map_err(sql_error)?;
                }
            }
        }
        for (table, entries) in [("outbox", &commit.events), ("attempts", &commit.attempts)] {
            for entry in entries {
                let payload = self.encode(table, &entry.id, revision, &entry.body)?;
                tx.execute(
                    &format!("INSERT INTO {table} VALUES(?1,?2,?3,?4)"),
                    params![entry.id, commit.operation_id, revision as i64, payload],
                )
                .map_err(sql_error)?;
            }
        }
        tx.execute(
            "UPDATE metadata SET revision=?1 WHERE singleton=1",
            [revision as i64],
        )
        .map_err(sql_error)?;
        enforce_capacity(&tx)?;
        observer(CommitStage::BeforeCommit);
        tx.commit().map_err(|e| match sql_error(e) {
            StoreError::Full => StoreError::Full,
            StoreError::Busy => StoreError::Busy,
            _ => StoreError::CommitUncertain,
        })?;
        observer(CommitStage::AfterCommit);
        Ok(Receipt {
            operation_id: commit.operation_id.clone(),
            revision,
        })
    }

    fn encode(&self, family: &str, id: &str, revision: u64, body: &Body) -> Result<Vec<u8>> {
        self.protection
            .seal(&self.store_id, family, id, revision, body.bytes())
    }
    fn decode(&self, family: &str, id: &str, revision: u64, bytes: &[u8]) -> Result<Body> {
        Body::new(
            self.protection
                .open(&self.store_id, family, id, revision, bytes)?
                .to_vec(),
        )
        .map_err(|_| StoreError::Corrupt)
    }

    /// Safe counts and identities only; validates every retained body without exposing it.
    pub fn validate(&self) -> Result<ValidationReport> {
        let mut connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = connection.transaction().map_err(sql_error)?;
        check_schema(&tx)?;
        let integrity: String = tx
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(sql_error)?;
        if integrity != "ok" {
            return Err(StoreError::Corrupt);
        }
        if tx
            .prepare("PRAGMA foreign_key_check")
            .map_err(sql_error)?
            .query([])
            .map_err(sql_error)?
            .next()
            .map_err(sql_error)?
            .is_some()
        {
            return Err(StoreError::Corrupt);
        }
        let revision = current_revision(&tx)?;
        let max: u64 = tx
            .query_row("SELECT COALESCE(MAX(revision),0) FROM commits", [], |r| {
                uint(r, 0)
            })
            .map_err(sql_error)?;
        if revision != max {
            return Err(StoreError::Corrupt);
        }
        let counts = enforce_capacity(&tx)?;
        if counts[1] as u64 != revision {
            return Err(StoreError::Corrupt);
        }
        {
            let mut statement = tx
                .prepare("SELECT family,record_id,revision,payload FROM records")
                .map_err(sql_error)?;
            let mut rows = statement.query([]).map_err(sql_error)?;
            while let Some(row) = rows.next().map_err(sql_error)? {
                let family: String = row.get(0).map_err(sql_error)?;
                let id: String = row.get(1).map_err(sql_error)?;
                Family::parse(&family)?;
                valid_id(&id).map_err(|_| StoreError::Corrupt)?;
                let r = uint(row, 2).map_err(sql_error)?;
                let p: Vec<u8> = row.get(3).map_err(sql_error)?;
                self.decode(&family, &id, r, &p)?;
            }
        }
        for kind in [History::Intent, History::Outbox, History::Attempt] {
            let mut statement = tx
                .prepare(&format!(
                    "SELECT {},revision,{} FROM {}",
                    kind.id(),
                    kind.column(),
                    kind.table()
                ))
                .map_err(sql_error)?;
            let mut rows = statement.query([]).map_err(sql_error)?;
            while let Some(row) = rows.next().map_err(sql_error)? {
                let id: String = row.get(0).map_err(sql_error)?;
                valid_id(&id).map_err(|_| StoreError::Corrupt)?;
                let r = uint(row, 1).map_err(sql_error)?;
                let p: Vec<u8> = row.get(2).map_err(sql_error)?;
                self.decode(kind.table(), &id, r, &p)?;
            }
        }
        Ok(ValidationReport {
            schema_version: SCHEMA_VERSION,
            revision,
            encrypted: self.protection.is_encrypted(),
            records: counts[0] as u64,
            intents: counts[1] as u64,
            events: counts[2] as u64,
            attempts: counts[3] as u64,
            payload_bytes: counts[4] as u64,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    BeforeCommit,
    AfterCommit,
}

fn valid_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn valid_page(after: &str, limit: usize) -> Result<()> {
    if !after.is_empty() {
        valid_id(after)?;
    }
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_commit(c: &Commit) -> Result<()> {
    valid_id(&c.operation_id)?;
    if c.expected_revision >= i64::MAX as u64
        || c.intent.bytes().is_empty()
        || c.writes.len() + c.events.len() + c.attempts.len() > MAX_CHANGES
    {
        return Err(StoreError::Invalid);
    }
    let mut bytes = c.intent.bytes().len();
    let mut keys = BTreeSet::new();
    for w in &c.writes {
        valid_id(&w.id)?;
        if !keys.insert((w.family, &w.id)) {
            return Err(StoreError::Invalid);
        }
        if let Some(body) = &w.value {
            bytes = bytes
                .checked_add(body.bytes().len())
                .ok_or(StoreError::Invalid)?;
        }
    }
    for entries in [&c.events, &c.attempts] {
        let mut ids = BTreeSet::new();
        for a in entries {
            valid_id(&a.id)?;
            if !ids.insert(&a.id) {
                return Err(StoreError::Invalid);
            }
            bytes = bytes
                .checked_add(a.body.bytes().len())
                .ok_or(StoreError::Invalid)?;
        }
    }
    if bytes > MAX_TRANSACTION_BYTES {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn uint(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
fn current_revision(c: &Connection) -> Result<u64> {
    c.query_row("SELECT revision FROM metadata WHERE singleton=1", [], |r| {
        uint(r, 0)
    })
    .map_err(sql_error)
}
fn enforce_capacity(c: &Connection) -> Result<[i64; 5]> {
    let mut counts = [0; 5];
    for (i, (table, column)) in [
        ("records", "payload"),
        ("commits", "intent"),
        ("outbox", "payload"),
        ("attempts", "payload"),
    ]
    .into_iter()
    .enumerate()
    {
        let (count, bytes): (i64, i64) = c
            .query_row(
                &format!("SELECT count(*),COALESCE(sum(length({column})),0) FROM {table}"),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(sql_error)?;
        if count
            > if i == 0 {
                MAX_RECORDS
            } else {
                MAX_HISTORY_ROWS
            }
        {
            return Err(StoreError::Full);
        }
        counts[i] = count;
        counts[4] = counts[4].checked_add(bytes).ok_or(StoreError::Full)?;
    }
    if counts[4] > MAX_STORED_BYTES {
        return Err(StoreError::Full);
    }
    Ok(counts)
}
fn schema_rows(c: &Connection) -> Result<Vec<(String, String, String)>> {
    c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name")
        .map_err(sql_error)?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(sql_error)?
        .map(|r| r.map_err(sql_error))
        .collect()
}
fn check_schema(c: &Connection) -> Result<()> {
    let app: i64 = c
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(sql_error)?;
    let version: u32 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(sql_error)?;
    if app != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err(StoreError::Schema);
    }
    let expected = Connection::open_in_memory().map_err(sql_error)?;
    expected.execute_batch(SCHEMA_SQL).map_err(sql_error)?;
    if schema_rows(c)? != schema_rows(&expected)? {
        return Err(StoreError::Schema);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
