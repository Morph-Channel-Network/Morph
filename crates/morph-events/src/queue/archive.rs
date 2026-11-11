//! Sealed generations are the archive: no histories or acknowledgement evidence
//! are deleted. A CAS seal fences old Queue handles before the successor becomes
//! active. The owner must retain old databases; this is not rollback protection.
use super::*;

#[derive(Debug, Serialize)]
pub struct ArchiveReport {
    pub archived_store_id: String,
    pub successor_store_id: String,
    pub checkpoint_digest: String,
    pub retained_in_archive: usize,
    pub carried_forward: usize,
    #[serde(with = "morph_packages::public_encoding::decimal")]
    pub sealed_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveStage {
    Prepared,
    Sealed,
    Copied,
    Activated,
}

impl Queue {
    /// Hand off to a fresh (or exactly matching interrupted) consumer database.
    /// Source history and source revision are never modified. Dead letters and
    /// in-flight leases are carried exactly; acknowledged jobs stay in the archive.
    /// A prepared or sealed database cannot issue new delivery claims.
    pub fn archive_to(&self, next: &Store) -> Result<ArchiveReport> {
        self.archive_observed(next, |_| {})
    }

    pub(crate) fn archive_observed(
        &self,
        next: &Store,
        mut observe: impl FnMut(ArchiveStage),
    ) -> Result<ArchiveReport> {
        if next.identity() == self.consumer.identity() || next.identity() == self.source.identity()
        {
            return Err(Error::Policy);
        }
        next.validate()?;
        let (current_revision, mut meta) = self.meta()?;
        if meta.phase == Phase::Prepared {
            return Err(Error::ArchiveRequired);
        }
        let all_jobs = self.jobs()?;
        if all_jobs.len() != meta.total {
            return Err(Error::Conflict);
        }
        let base_revision = if let Some(link) = &meta.successor {
            if link.sealed_revision != current_revision
                || link.peer_id != hex::encode(next.identity())
            {
                return Err(Error::Conflict);
            }
            link.sealed_revision.checked_sub(1).ok_or(Error::Invalid)?
        } else {
            current_revision
        };
        let prior_successor = meta.successor.take();
        meta.phase = Phase::Active;
        let old_id = hex::encode(self.consumer.identity());
        let checkpoint = digest(
            b"morph.event.archive_checkpoint.v1\0",
            &serde_json::to_vec(&(&old_id, base_revision, &meta, &all_jobs))
                .map_err(|_| Error::Invalid)?,
        );
        let sealed_revision = base_revision.checked_add(1).ok_or(Error::Invalid)?;
        let to = ArchiveLink {
            peer_id: hex::encode(next.identity()),
            sealed_revision,
            checkpoint: checkpoint.clone(),
        };
        if prior_successor
            .as_ref()
            .is_some_and(|previous| previous != &to)
        {
            return Err(Error::Conflict);
        }
        let from = ArchiveLink {
            peer_id: old_id.clone(),
            sealed_revision,
            checkpoint: checkpoint.clone(),
        };
        let jobs: Vec<_> = all_jobs
            .iter()
            .filter(|job| job.status != Status::Acknowledged)
            .cloned()
            .collect();
        let report = ArchiveReport {
            archived_store_id: old_id,
            successor_store_id: to.peer_id.clone(),
            checkpoint_digest: checkpoint.clone(),
            retained_in_archive: all_jobs.len() - jobs.len(),
            carried_forward: jobs.len(),
            sealed_revision,
        };
        let mut prepared = meta.clone();
        prepared.total = jobs.len();
        prepared.phase = Phase::Prepared;
        prepared.predecessor = Some(from.clone());
        let existing = next.read(Family::Delivery, "consumer")?;
        if let Some(record) = existing.record {
            let existing_meta: Meta = decode(record.body.bytes())?;
            if prior_successor.is_some()
                && existing_meta.predecessor.as_ref() == Some(&from)
                && existing_meta.source == meta.source
                && existing_meta.target == meta.target
                && existing_meta.schema == meta.schema
                && existing_meta.phase != Phase::Prepared
            {
                let activation = next.intent("archive:activate")?.ok_or(Error::Conflict)?;
                if activation.body.bytes() != body(&from)?.bytes() {
                    return Err(Error::Conflict);
                }
                // An already activated successor may itself have progressed or
                // been archived. Repeating the old handoff must not rewind it.
                return Ok(report);
            }
            if existing_meta != prepared {
                return Err(Error::Conflict);
            }
        } else {
            if existing.revision != 0 {
                return Err(Error::Policy);
            }
            next.commit_new(&Commit {
                operation_id: "archive:prepare".into(),
                expected_revision: 0,
                intent: body(&from)?,
                writes: vec![write("consumer".into(), &prepared)?],
                events: vec![],
                attempts: vec![],
            })?;
        }
        observe(ArchiveStage::Prepared);
        let mut sealed = meta.clone();
        sealed.phase = Phase::Sealed;
        sealed.successor = Some(to.clone());
        // Idempotent seal retry is safe: this transaction grants no HTTP lease.
        // Any old Queue mutation before this CAS invalidates the captured jobs;
        // every old Queue mutation after it sees Sealed or loses its CAS.
        self.consumer.commit(&Commit {
            operation_id: format!("archive:seal:{}", to.peer_id),
            expected_revision: base_revision,
            intent: body(&to)?,
            writes: vec![write("consumer".into(), &sealed)?],
            events: vec![],
            attempts: vec![],
        })?;
        observe(ArchiveStage::Sealed);
        let mut revision = 1;
        for (index, chunk) in jobs.chunks(128).enumerate() {
            next.commit(&Commit {
                operation_id: format!("archive:copy:{index}"),
                expected_revision: revision,
                intent: body(&(checkpoint.as_str(), index))?,
                writes: chunk
                    .iter()
                    .map(|job| write(job_id(&job.event_id), job))
                    .collect::<Result<_>>()?,
                events: vec![],
                attempts: vec![],
            })?;
            revision += 1;
            observe(ArchiveStage::Copied);
        }
        // Verify complete exact carried state before activation. An interrupted
        // prepared store is never usable through Queue::open.
        let mut actual = Vec::new();
        let mut after = "job:".to_owned();
        loop {
            let page = next.records(Family::Delivery, &after, 128)?;
            if page.is_empty() {
                break;
            }
            for entry in page {
                after = entry.id.clone();
                actual.push(decode::<Job>(entry.body.bytes())?);
            }
        }
        if serde_json::to_vec(&actual).map_err(|_| Error::Invalid)?
            != serde_json::to_vec(&jobs).map_err(|_| Error::Invalid)?
        {
            return Err(Error::Conflict);
        }
        let validation = next.validate()?;
        if validation.revision != revision
            || validation.records != jobs.len() as u64 + 1
            || validation.events != 0
            || validation.attempts != 0
        {
            return Err(Error::Conflict);
        }
        let (old_revision, old_meta) = self.meta()?;
        if old_revision != sealed_revision || old_meta != sealed {
            return Err(Error::Conflict);
        }
        prepared.phase = Phase::Active;
        next.commit(&Commit {
            operation_id: "archive:activate".into(),
            expected_revision: revision,
            intent: body(&from)?,
            writes: vec![write("consumer".into(), &prepared)?],
            events: vec![],
            attempts: vec![],
        })?;
        observe(ArchiveStage::Activated);
        Ok(report)
    }
}
