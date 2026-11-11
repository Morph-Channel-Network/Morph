mod model;
mod records;

use super::*;
use morph_runtime_store::{
    Append, Body, Commit, Cursor, Family, History, Protection, Store, Write,
};
use std::{
    io::{BufRead, BufReader, Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}
fn db(path: &Path) -> Store {
    Store::open(path, Protection::private_plaintext()).unwrap()
}
fn event(source: &Store, revision: u64, op: &str, id: &str) -> EventEnvelope {
    let source_id = hex::encode(source.identity());
    EventEnvelope {
        schema: EventSchema::Current,
        event_id: EventEnvelope::identity(&source_id, id),
        source_id,
        source_revision: revision,
        created_at_ms: 1000,
        component: Component::Hub,
        evidence_level: EvidenceLevel::LocalRecord,
        kind: Kind::ChannelOpened,
        severity: Severity::Info,
        correlation_id: EventEnvelope::correlation(op),
        subject_id: Some("12".repeat(32)),
        funding_context_id: None,
        payment_hash: None,
        provider_revision: None,
        evidence_digest: None,
    }
}
fn seed(source: &Store, count: usize) {
    let mut start = 0;
    while start < count {
        let revision = source.read(Family::Hub, "state").unwrap().revision;
        let op = format!("source:{revision}");
        let events = (start..(start + 32).min(count))
            .map(|index| {
                let id = format!("event:{index:05}");
                Append {
                    body: Body::new(event(source, revision + 1, &op, &id).encode().unwrap())
                        .unwrap(),
                    id,
                }
            })
            .collect();
        source
            .commit(&Commit {
                operation_id: op,
                expected_revision: revision,
                intent: Body::new(b"public change".to_vec()).unwrap(),
                writes: vec![Write {
                    family: Family::Hub,
                    id: "state".into(),
                    value: Some(Body::new(b"business projection".to_vec()).unwrap()),
                }],
                events,
                attempts: vec![],
            })
            .unwrap();
        start += 32;
    }
}
fn queue(dir: &Path, target: String) -> Queue {
    Queue::open(
        Store::read_only(&dir.join("source"), Protection::private_plaintext()).unwrap(),
        db(&dir.join("consumer")),
        target,
    )
    .unwrap()
}
fn policy() -> String {
    "cd".repeat(32)
}

#[test]
fn readonly_observation_counts_critical_backlog_and_preserves_both_store_revisions() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    let mut critical = event(&source, 1, "critical", "event:critical");
    critical.severity = Severity::Critical;
    source
        .commit_new(&Commit {
            operation_id: "critical".into(),
            expected_revision: 0,
            intent: Body::new(b"public".to_vec()).unwrap(),
            writes: vec![],
            events: vec![Append {
                id: "event:critical".into(),
                body: Body::new(critical.encode().unwrap()).unwrap(),
            }],
            attempts: vec![],
        })
        .unwrap();
    let queue = queue(dir.path(), policy());
    queue.ingest(1000).unwrap();
    let consumer = db(&dir.path().join("consumer"));
    let revision = consumer.revision().unwrap();
    let snapshot = queue.observe(31_000).unwrap();
    assert_eq!(snapshot.health.critical_pending, 1);
    assert_eq!(snapshot.health.oldest_critical_age_ms, 30_000);
    assert_eq!(snapshot.consumer_revision, revision);
    assert_eq!(snapshot.source_revision, 1);
    assert!(snapshot.delivery_allowed);
    assert!(queue.claim(1000 + MAX_AGE_MS).unwrap().is_none());
    let revision = consumer.revision().unwrap();
    let snapshot = queue.observe(1000 + MAX_AGE_MS).unwrap();
    assert_eq!(snapshot.health.critical_pending, 0);
    assert_eq!(snapshot.health.critical_dead_letter, 1);
    assert_eq!(consumer.revision().unwrap(), revision);
    assert_eq!(source.revision().unwrap(), 1);
}

#[test]
fn archive_fences_old_handles_and_preserves_dead_letters_leases_and_exact_bodies() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, 3);
    let old = queue(dir.path(), policy());
    old.ingest(1000).unwrap();
    let accepted = old.claim(1000).unwrap().unwrap();
    old.complete(&accepted, Outcome::Acknowledged, 1001)
        .unwrap();
    assert!(old.claim(1000 + MAX_AGE_MS).unwrap().is_none());
    assert!(old.claim(1000 + MAX_AGE_MS).unwrap().is_none());
    assert_eq!(old.health(1000 + MAX_AGE_MS).unwrap().dead_letter, 2);
    let old_store = db(&dir.path().join("consumer"));
    let records = old_store.records(Family::Delivery, "job:", 128).unwrap();
    let dead: Vec<_> = records
        .iter()
        .filter_map(|r| {
            let j: serde_json::Value = serde_json::from_slice(r.body.bytes()).unwrap();
            (j["status"] == "dead_letter").then(|| j["event_id"].as_str().unwrap().to_owned())
        })
        .collect();
    old.replay_dead_letter(&dead[0], 1001 + MAX_AGE_MS).unwrap();
    let flight = old.claim(1001 + MAX_AGE_MS).unwrap().unwrap();
    let next = db(&dir.path().join("next"));
    let report = old.archive_to(&next).unwrap();
    assert_eq!(report.retained_in_archive, 1);
    assert_eq!(report.carried_forward, 2);
    assert!(old.health(1002 + MAX_AGE_MS).unwrap().sealed);
    assert!(matches!(
        old.claim(1002 + MAX_AGE_MS),
        Err(Error::ArchiveRequired)
    ));
    assert!(matches!(
        old.complete(&flight, Outcome::Acknowledged, 1002 + MAX_AGE_MS),
        Err(Error::ArchiveRequired)
    ));
    assert!(matches!(
        old.replay_dead_letter(&dead[1], 1002 + MAX_AGE_MS),
        Err(Error::ArchiveRequired)
    ));
    let original_bytes = std::fs::read(dir.path().join("consumer")).unwrap();
    let successor = Queue::open(
        Store::read_only(&dir.path().join("source"), Protection::private_plaintext()).unwrap(),
        db(&dir.path().join("next")),
        policy(),
    )
    .unwrap();
    let health = successor.health(1002 + MAX_AGE_MS).unwrap();
    assert_eq!(health.dead_letter, 1);
    assert_eq!(health.in_flight, 1);
    assert_eq!(health.acknowledged, 0);
    assert_eq!(successor.ingest(1002 + MAX_AGE_MS).unwrap(), 0);
    // The old lease is not prematurely retried, then retains identity and bytes.
    assert!(successor.claim(1002 + MAX_AGE_MS).unwrap().is_none());
    let retry = successor
        .claim(1001 + MAX_AGE_MS + LEASE_MS)
        .unwrap()
        .unwrap();
    assert_eq!(retry.event_id(), flight.event_id());
    assert_eq!(retry.body(), flight.body());
    assert_eq!(retry.generation(), flight.generation());
    assert_eq!(retry.attempt(), flight.attempt() + 1);
    successor
        .complete(&retry, Outcome::Acknowledged, 1002 + MAX_AGE_MS + LEASE_MS)
        .unwrap();
    assert!(old.archive_to(&next).is_ok()); // never rewind an already active successor
    assert_eq!(
        successor
            .health(1002 + MAX_AGE_MS + LEASE_MS)
            .unwrap()
            .acknowledged,
        1
    );
    assert_eq!(
        std::fs::read(dir.path().join("consumer")).unwrap(),
        original_bytes
    );
    assert!(old.archive_to(&db(&dir.path().join("wrong-next"))).is_err());
}

#[test]
fn archive_releases_retained_job_capacity_without_resetting_source_cursor() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, MAX_JOBS + 1);
    let old = queue(dir.path(), policy());
    for _ in 0..MAX_JOBS / 32 {
        old.ingest(1000).unwrap();
    }
    assert!(matches!(old.ingest(1000), Err(Error::Full)));
    let accepted = old.claim(1000).unwrap().unwrap();
    old.complete(&accepted, Outcome::Acknowledged, 1001)
        .unwrap();
    let before = old.health(1001).unwrap();
    assert!(before.archive_required && before.source_blocked);
    let next = db(&dir.path().join("next"));
    old.archive_to(&next).unwrap();
    let new = Queue::open(
        Store::read_only(&dir.path().join("source"), Protection::private_plaintext()).unwrap(),
        next,
        policy(),
    )
    .unwrap();
    assert_eq!(
        new.health(1001).unwrap().source_cursor_revision,
        before.source_cursor_revision
    );
    assert_eq!(new.ingest(1002).unwrap(), 1);
    assert_eq!(new.health(1002).unwrap().retained, MAX_JOBS);
    assert!(!new.health(1002).unwrap().source_pending);
    assert!(
        db(&dir.path().join("next"))
            .read(Family::Delivery, &format!("job:{}", accepted.event_id()))
            .unwrap()
            .record
            .is_none()
    );
    assert!(
        db(&dir.path().join("consumer"))
            .read(Family::Delivery, &format!("job:{}", accepted.event_id()))
            .unwrap()
            .record
            .is_some()
    );
}

#[test]
fn archive_cas_rejects_a_snapshot_changed_before_seal_and_never_activates_it() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, 1);
    let old = queue(dir.path(), policy());
    old.ingest(1000).unwrap();
    let next = db(&dir.path().join("next"));
    let competing = queue(dir.path(), policy());
    let result = old.archive_observed(&next, |stage| {
        if stage == crate::queue::archive::ArchiveStage::Prepared {
            competing.claim(1000).unwrap().unwrap();
        }
    });
    assert!(result.is_err());
    assert!(!old.health(1000).unwrap().sealed);
    assert!(
        Queue::open(
            Store::read_only(&dir.path().join("source"), Protection::private_plaintext()).unwrap(),
            db(&dir.path().join("next")),
            policy()
        )
        .is_err()
    );
    assert!(old.archive_to(&next).is_err());
    old.archive_to(&db(&dir.path().join("fresh-next"))).unwrap();
}

#[test]
fn archive_crash_child() {
    let Ok(root) = std::env::var("MORPH_ARCHIVE_TEST_DIR") else {
        return;
    };
    let stage = std::env::var("MORPH_ARCHIVE_TEST_STAGE").unwrap();
    let root = Path::new(&root);
    let old = queue(root, policy());
    let next = db(&root.join("next"));
    old.archive_observed(&next, |observed| {
        if format!("{observed:?}") == stage {
            println!("ARCHIVE_KILL_BOUNDARY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park_timeout(Duration::from_secs(1));
            }
        }
    })
    .unwrap();
}

#[test]
fn history_watermark_leaves_room_to_seal_and_restart_unresolved_work() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, 1);
    let old = queue(dir.path(), policy());
    old.ingest(1000).unwrap();
    let store = db(&dir.path().join("consumer"));
    let start = store.read(Family::Delivery, "consumer").unwrap().revision;
    for revision in start..MAX_GENERATION_REVISIONS {
        store
            .commit_new(&Commit {
                operation_id: format!("retained-history:{revision}"),
                expected_revision: revision,
                intent: Body::new(b"retained evidence".to_vec()).unwrap(),
                writes: vec![],
                events: vec![],
                attempts: vec![],
            })
            .unwrap();
    }
    assert!(old.health(1000).unwrap().archive_required);
    assert!(matches!(old.claim(1000), Err(Error::ArchiveRequired)));
    let next = db(&dir.path().join("next"));
    old.archive_to(&next).unwrap();
    assert_eq!(
        store.validate().unwrap().intents,
        MAX_GENERATION_REVISIONS + 1
    );
    let new = Queue::open(
        Store::read_only(&dir.path().join("source"), Protection::private_plaintext()).unwrap(),
        next,
        policy(),
    )
    .unwrap();
    assert!(!new.health(1000).unwrap().archive_required);
    assert!(new.claim(1000).unwrap().is_some());
}

#[test]
fn real_process_kills_each_archive_handoff_boundary_are_resumable() {
    for stage in ["Prepared", "Sealed", "Copied", "Activated"] {
        let dir = directory();
        let source = db(&dir.path().join("source"));
        let count = if stage == "Copied" { 130 } else { 2 };
        seed(&source, count);
        let old = queue(dir.path(), policy());
        while old.ingest(1000).unwrap() != 0 {}
        let accepted = old.claim(1000).unwrap().unwrap();
        old.complete(&accepted, Outcome::Acknowledged, 1001)
            .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::archive_crash_child", "--nocapture"])
            .env("MORPH_ARCHIVE_TEST_DIR", dir.path())
            .env("MORPH_ARCHIVE_TEST_STAGE", stage)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                if line.unwrap().contains("ARCHIVE_KILL_BOUNDARY") {
                    let _ = tx.send(());
                    break;
                }
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(15));
        let _ = child.kill();
        let exit = child.wait().unwrap();
        assert!(ready.is_ok(), "{stage} boundary was not reached");
        assert!(!exit.success());
        let old = queue(dir.path(), policy());
        let next = db(&dir.path().join("next"));
        let report = old.archive_to(&next).unwrap();
        assert_eq!(report.carried_forward, count - 1);
        assert_eq!(report.retained_in_archive, 1);
        let new = Queue::open(
            Store::read_only(&dir.path().join("source"), Protection::private_plaintext()).unwrap(),
            next,
            policy(),
        )
        .unwrap();
        assert_eq!(new.ingest(1002).unwrap(), 0);
        for _ in 0..count - 1 {
            let delivery = new.claim(1002).unwrap().unwrap();
            assert_ne!(delivery.event_id(), accepted.event_id());
            new.complete(&delivery, Outcome::Acknowledged, 1003)
                .unwrap();
        }
        assert!(new.claim(1004).unwrap().is_none());
    }
}

#[test]
fn watch_permission_is_required_and_revocation_stops_new_claims_but_allows_ack() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    let commit_policy = |allowed: Option<bool>, emit: bool| {
        let revision = source.read(Family::Watch, "cursor").unwrap().revision;
        let op = format!("watch:{revision}");
        let id = format!("event:{revision}");
        let mut entry = event(&source, revision + 1, &op, &id);
        entry.component = Component::Watch;
        entry.kind = Kind::WatchRecoveryInvalid;
        let writes = vec![
            Write {
                family: Family::Watch,
                id: "cursor".into(),
                value: Some(Body::new(b"checkpoint".to_vec()).unwrap()),
            },
            Write {
                family: Family::Watch,
                id: "delivery-policy".into(),
                value: allowed.map(|a| {
                    Body::new(serde_json::to_vec(&SourceDeliveryPolicy::new(a)).unwrap()).unwrap()
                }),
            },
        ];
        source
            .commit_new(&Commit {
                operation_id: op,
                expected_revision: revision,
                intent: Body::new(b"watch".to_vec()).unwrap(),
                writes,
                events: if emit {
                    vec![Append {
                        id,
                        body: Body::new(entry.encode().unwrap()).unwrap(),
                    }]
                } else {
                    vec![]
                },
                attempts: vec![],
            })
            .unwrap();
    };
    commit_policy(None, true);
    let queue = queue(dir.path(), policy());
    assert!(matches!(queue.ingest(1000), Err(Error::Policy)));
    commit_policy(Some(false), false);
    assert!(matches!(queue.ingest(1000), Err(Error::Policy)));
    commit_policy(Some(true), false);
    assert_eq!(queue.ingest(1000).unwrap(), 1);
    commit_policy(Some(false), false);
    assert!(matches!(queue.claim(1000), Err(Error::Policy)));
    commit_policy(Some(true), false);
    let delivery = queue.claim(1000).unwrap().unwrap();
    commit_policy(Some(false), false);
    // Already in-flight network requests cannot be recalled; preserve a valid
    // acknowledgement while refusing to start any new request after revocation.
    queue
        .complete(&delivery, Outcome::Acknowledged, 1001)
        .unwrap();
    assert_eq!(queue.health(1001).unwrap().acknowledged, 1);
    assert!(matches!(queue.claim(1001), Err(Error::Policy)));
}

#[test]
fn atomic_ingest_reopen_exact_identity_and_separate_business_revision() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, 3);
    let original = source.validate().unwrap().revision;
    let q = queue(dir.path(), policy());
    assert_eq!(q.ingest(1000).unwrap(), 3);
    assert_eq!(q.ingest(1000).unwrap(), 0);
    let ticket = q.claim(1000).unwrap().unwrap();
    let id = ticket.event_id().to_string();
    let body = ticket.body().to_vec();
    assert!(q.claim(1001).unwrap().is_some());
    q.complete(&ticket, Outcome::Acknowledged, 1001).unwrap();
    drop(q);
    let q = queue(dir.path(), policy());
    assert_eq!(q.health(1002).unwrap().acknowledged, 1);
    assert_eq!(source.validate().unwrap().revision, original);
    let saved = source
        .history(History::Outbox, &Cursor::default(), 10)
        .unwrap();
    assert!(saved.iter().any(|v| v.body.bytes() == body));
    assert_eq!(EventEnvelope::decode(&body).unwrap().event_id, id);
    assert!(
        Queue::open(
            db(&dir.path().join("source")),
            db(&dir.path().join("consumer")),
            "ab".repeat(32)
        )
        .is_err()
    );
    assert!(
        Queue::open(
            db(&dir.path().join("different-source")),
            db(&dir.path().join("consumer")),
            policy()
        )
        .is_err()
    );
}

#[test]
fn durable_claim_excludes_competitors_and_stale_completion() {
    let dir = directory();
    seed(&db(&dir.path().join("source")), 1);
    let a = queue(dir.path(), policy());
    let b = queue(dir.path(), policy());
    a.ingest(1000).unwrap();
    let first = a.claim(1000).unwrap().unwrap();
    assert!(b.claim(1001).unwrap().is_none());
    let retry = b.claim(1000 + LEASE_MS).unwrap().unwrap();
    assert_eq!(first.body(), retry.body());
    assert_eq!(first.event_id(), retry.event_id());
    assert_eq!(retry.attempt(), 2);
    assert!(a.complete(&first, Outcome::Acknowledged, 31_001).is_err());
    b.complete(&retry, Outcome::Acknowledged, 31_001).unwrap();
    assert_eq!(a.health(31_001).unwrap().acknowledged, 1);
    assert!(a.claim(31_001).unwrap().is_none());
    let attempts = db(&dir.path().join("consumer"))
        .history(History::Attempt, &Cursor::default(), 128)
        .unwrap();
    assert_eq!(attempts.len(), 3);
}

#[test]
fn global_inflight_bound_and_clock_regression() {
    let dir = directory();
    seed(&db(&dir.path().join("source")), 8);
    let q = queue(dir.path(), policy());
    q.ingest(1000).unwrap();
    assert!(q.claim(999).is_err());
    for _ in 0..MAX_IN_FLIGHT {
        assert!(q.claim(1000).unwrap().is_some())
    }
    assert!(q.claim(1000).unwrap().is_none());
    assert_eq!(q.health(1000).unwrap().in_flight, MAX_IN_FLIGHT);
}

#[test]
fn bounded_retries_dead_letter_replay_and_immutable_attempts() {
    let dir = directory();
    seed(&db(&dir.path().join("source")), 1);
    let q = queue(dir.path(), policy());
    q.ingest(1000).unwrap();
    let mut now = 1000;
    let mut id = String::new();
    for generation in 0..=MAX_REPLAYS {
        for attempt in 1..=MAX_ATTEMPTS {
            let ticket = q.claim(now).unwrap().unwrap();
            id = ticket.event_id().into();
            assert_eq!(ticket.attempt(), attempt);
            assert_eq!(ticket.generation(), generation);
            q.complete(&ticket, Outcome::Failed(Failure::Transport), now)
                .unwrap();
            assert!(q.claim(now).unwrap().is_none());
            now += 1000u64 << attempt;
        }
        assert_eq!(q.health(now).unwrap().dead_letter, 1);
        if generation < MAX_REPLAYS {
            q.replay_dead_letter(&id, now).unwrap()
        }
    }
    assert!(q.replay_dead_letter(&id, now).is_err());
    let attempts = db(&dir.path().join("consumer"))
        .history(History::Attempt, &Cursor::default(), 128)
        .unwrap();
    assert_eq!(
        attempts.len(),
        (MAX_ATTEMPTS as usize * 2) * (MAX_REPLAYS as usize + 1) + MAX_REPLAYS as usize
    );
}

#[test]
fn capacity_and_invalid_page_never_advance_cursor_or_discard_jobs() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, MAX_JOBS + 1);
    let q = queue(dir.path(), policy());
    for _ in 0..MAX_JOBS / 32 {
        assert_eq!(q.ingest(1000).unwrap(), 32)
    }
    let cursor = q.health(1000).unwrap().source_cursor_revision;
    assert!(matches!(q.ingest(1000), Err(Error::Full)));
    assert_eq!(q.health(1000).unwrap().retained, MAX_JOBS);
    assert_eq!(q.health(1000).unwrap().source_cursor_revision, cursor);
    let invalid = directory();
    let source = db(&invalid.path().join("source"));
    let mut wrong = event(&source, 1, "bad", "e");
    wrong.source_revision = 2;
    source
        .commit(&Commit {
            operation_id: "bad".into(),
            expected_revision: 0,
            intent: Body::new(vec![1]).unwrap(),
            writes: vec![],
            events: vec![Append {
                id: "e".into(),
                body: Body::new(wrong.encode().unwrap()).unwrap(),
            }],
            attempts: vec![],
        })
        .unwrap();
    let q = queue(invalid.path(), policy());
    assert!(q.ingest(1000).is_err());
    assert_eq!(q.health(1000).unwrap().source_cursor_revision, 0);
}

#[test]
fn event_shape_is_bounded_current_and_contains_no_free_text_or_private_body() {
    let source = Store::memory(Protection::private_plaintext()).unwrap();
    let e = event(&source, 1, "op", "e");
    let bytes = e.encode().unwrap();
    assert_eq!(EventEnvelope::decode(&bytes).unwrap(), e);
    let mut mismatched = e.clone();
    mismatched.component = Component::Gateway;
    assert!(mismatched.encode().is_err());
    let mut v = serde_json::to_value(e).unwrap();
    assert_eq!(v["source_revision"], "1");
    v["secret"] = serde_json::json!("not allowed");
    assert!(EventEnvelope::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    v.as_object_mut().unwrap().remove("secret");
    v.as_object_mut().unwrap().remove("payment_hash");
    assert!(EventEnvelope::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(EventEnvelope::decode(&vec![b' '; MAX_EVENT_BYTES + 1]).is_err());
}

fn request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut data = Vec::new();
    let (end, length) = loop {
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
        assert!(data.len() < 16384);
        if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
            let headers = String::from_utf8(data[..end].to_vec()).unwrap();
            let length = headers
                .lines()
                .find_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            break (end + 4, length);
        }
    };
    while data.len() < end + length {
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buf[..n]);
    }
    (
        String::from_utf8(data[..end].to_vec()).unwrap(),
        data[end..end + length].to_vec(),
    )
}
fn header<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim())
        })
        .unwrap()
}
#[test]
fn authenticated_http_retry_keeps_exact_bytes_and_receiver_deduplicates() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let receiver_dir = directory();
        let mut bodies = Vec::new();
        for pass in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = request(&mut stream);
            let id = header(&headers, "x-morph-event-id");
            verify_request(id, &body, header(&headers, "x-morph-signature"), &[7; 32]).unwrap();
            // Receiver deduplication is persisted before acknowledgement, and
            // the connection is reopened for the next delivery.
            let receiver_store = db(&receiver_dir.path().join("dedup"));
            let previous = receiver_store.read(Family::Delivery, id).unwrap();
            if let Some(record) = previous.record {
                assert_eq!(record.body.bytes(), body);
            } else {
                receiver_store
                    .commit_new(&Commit {
                        operation_id: id.to_owned(),
                        expected_revision: previous.revision,
                        intent: Body::new(body.clone()).unwrap(),
                        writes: vec![Write {
                            family: Family::Delivery,
                            id: id.to_owned(),
                            value: Some(Body::new(body.clone()).unwrap()),
                        }],
                        events: vec![],
                        attempts: vec![],
                    })
                    .unwrap();
            }
            drop(receiver_store);
            bodies.push(body.clone());
            if pass == 1 {
                let ack = acknowledgement(id, &body, &[7; 32]).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 204 No Content\r\nX-Morph-Ack: {ack}\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
            }
            // Pass zero accepts then drops the response. Delivery remains uncertain.
        }
        assert_eq!(
            db(&receiver_dir.path().join("dedup"))
                .validate()
                .unwrap()
                .revision,
            1
        );
        assert_eq!(bodies[0], bodies[1]);
    });
    let dir = directory();
    seed(&db(&dir.path().join("source")), 1);
    let hook = Webhook::new(&url, zeroize::Zeroizing::new([7; 32])).unwrap();
    let q = queue(dir.path(), hook.fingerprint());
    q.ingest(1000).unwrap();
    let first = q.claim(1000).unwrap().unwrap();
    let result = hook.send(&first);
    assert!(matches!(result, Outcome::Failed(Failure::Transport)));
    q.complete(&first, result, 1001).unwrap();
    drop(q);
    let q = queue(dir.path(), hook.fingerprint());
    let retry = q.claim(3001).unwrap().unwrap();
    let result = hook.send(&retry);
    assert!(matches!(result, Outcome::Acknowledged));
    q.complete(&retry, result, 3002).unwrap();
    assert_eq!(q.health(3002).unwrap().acknowledged, 1);
    server.join().unwrap();
}

#[test]
fn tls_redirect_ack_auth_and_response_bounds_are_not_bypassed() {
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/?secret=x",
        "https://example.com/#x",
        "file:///tmp/x",
    ] {
        assert!(Webhook::new(url, zeroize::Zeroizing::new([7; 32])).is_err());
    }
    for mode in ["redirect", "unsigned", "wrong_key", "oversize", "duplicate"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, body) = request(&mut stream);
            let id = header(&headers, "x-morph-event-id");
            let ack =
                acknowledgement(id, &body, &[if mode == "wrong_key" { 8 } else { 7 }; 32]).unwrap();
            let response=match mode {
                "redirect"=>"HTTP/1.1 302 Found\r\nLocation: https://example.com\r\nContent-Length: 0\r\n\r\n".to_string(),
                "unsigned"=>"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string(),
                "oversize"=>format!("HTTP/1.1 200 OK\r\nX-Morph-Ack: {ack}\r\nContent-Length: 4097\r\n\r\n"),
                "duplicate"=>format!("HTTP/1.1 200 OK\r\nX-Morph-Ack: {ack}\r\nX-Morph-Ack: {ack}\r\nContent-Length: 0\r\n\r\n"),
                _=>format!("HTTP/1.1 200 OK\r\nX-Morph-Ack: {ack}\r\nContent-Length: 0\r\n\r\n"),
            };
            stream.write_all(response.as_bytes()).unwrap();
        });
        let dir = directory();
        seed(&db(&dir.path().join("source")), 1);
        let hook = Webhook::new(&url, zeroize::Zeroizing::new([7; 32])).unwrap();
        let q = queue(dir.path(), hook.fingerprint());
        q.ingest(1000).unwrap();
        let ticket = q.claim(1000).unwrap().unwrap();
        assert!(matches!(hook.send(&ticket), Outcome::Failed(_)), "{mode}");
        server.join().unwrap();
    }
}

// Production code has no fault injection or kill switches.
#[test]
fn delivery_crash_child() {
    let Ok(path) = std::env::var("MORPH_DELIVERY_TEST_DIR") else {
        return;
    };
    let stage = std::env::var("MORPH_DELIVERY_TEST_STAGE").unwrap();
    let url = std::env::var("MORPH_DELIVERY_TEST_URL").unwrap();
    let hook = Webhook::new(&url, zeroize::Zeroizing::new([7; 32])).unwrap();
    let q = queue(Path::new(&path), hook.fingerprint());
    q.ingest(1000).unwrap();
    if stage != "enrolled" {
        let ticket = q.claim(1000).unwrap().unwrap();
        if stage != "claimed" {
            let result = hook.send(&ticket);
            assert!(matches!(result, Outcome::Acknowledged));
            if stage == "acknowledged" {
                q.complete(&ticket, result, 1001).unwrap()
            }
        }
    }
    println!("DELIVERY_KILL_BOUNDARY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park_timeout(Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn real_process_kills_enrollment_send_acceptance_and_local_ack_boundaries() {
    for stage in ["enrolled", "claimed", "accepted", "acknowledged"] {
        let dir = directory();
        seed(&db(&dir.path().join("source")), 1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = if matches!(stage, "accepted" | "acknowledged") {
            Some(std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = request(&mut stream);
                let ack =
                    acknowledgement(header(&headers, "x-morph-event-id"), &body, &[7; 32]).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 204 No Content\r\nX-Morph-Ack: {ack}\r\nContent-Length: 0\r\n\r\n"
                )
                .unwrap();
                body
            }))
        } else {
            None
        };
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::delivery_crash_child", "--nocapture"])
            .env("MORPH_DELIVERY_TEST_DIR", dir.path())
            .env("MORPH_DELIVERY_TEST_STAGE", stage)
            .env("MORPH_DELIVERY_TEST_URL", &url)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                if line.unwrap().contains("DELIVERY_KILL_BOUNDARY") {
                    let _ = tx.send(());
                    break;
                }
            }
        });
        let reached = rx.recv_timeout(Duration::from_secs(15));
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(reached.is_ok(), "{stage}");
        let received = server.map(|s| s.join().unwrap());
        let hook = Webhook::new(&url, zeroize::Zeroizing::new([7; 32])).unwrap();
        let q = queue(dir.path(), hook.fingerprint());
        if stage == "acknowledged" {
            assert_eq!(q.health(31001).unwrap().acknowledged, 1);
            assert!(q.claim(31001).unwrap().is_none())
        } else {
            let retry = q.claim(31001).unwrap().unwrap();
            if let Some(body) = received {
                assert_eq!(retry.body(), body)
            }
            assert_eq!(q.health(31001).unwrap().retained, 1);
        }
    }
}

#[test]
fn durable_pages_bind_source_and_cover_same_revision_without_gaps() {
    let source = Store::memory(Protection::private_plaintext()).unwrap();
    seed(&source, 65);
    let mut cursor = None;
    let mut ids = std::collections::BTreeSet::new();
    loop {
        let page = event_page(
            &source,
            &EventPageRequest {
                after: cursor,
                limit: 7,
            },
        )
        .unwrap();
        for item in page.events {
            assert!(ids.insert(item.event_id));
        }
        cursor = Some(page.next);
        if !page.has_more {
            break;
        }
    }
    assert_eq!(ids.len(), 65);
    let end = event_page(
        &source,
        &EventPageRequest {
            after: cursor.clone(),
            limit: 7,
        },
    )
    .unwrap();
    assert!(end.events.is_empty());
    assert_eq!(Some(end.next), cursor);
    let mut wrong = cursor.unwrap();
    wrong.source_id = "ab".repeat(32);
    assert!(
        event_page(
            &source,
            &EventPageRequest {
                after: Some(wrong),
                limit: 7
            }
        )
        .is_err()
    );
    for limit in [0, 65] {
        assert!(event_page(&source, &EventPageRequest { after: None, limit }).is_err());
    }
}

#[test]
fn expired_work_is_visible_and_wrong_or_future_cursor_is_rejected() {
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, 1);
    let q = queue(dir.path(), policy());
    q.ingest(1000).unwrap();
    assert!(q.claim(1000 + MAX_AGE_MS).unwrap().is_none());
    assert_eq!(q.health(1000 + MAX_AGE_MS).unwrap().dead_letter, 1);
    let request = EventPageRequest {
        after: None,
        limit: 1,
    };
    let mut page = event_page(&source, &request).unwrap();
    assert!(page.valid_for(&request));
    let mut wrong = page.next.clone();
    wrong.revision += 1;
    assert!(
        event_page(
            &source,
            &EventPageRequest {
                after: Some(wrong),
                limit: 1
            }
        )
        .is_err()
    );
    let mut wrong = page.next.clone();
    wrong.outbox_id = "nonexistent".into();
    assert!(
        event_page(
            &source,
            &EventPageRequest {
                after: Some(wrong),
                limit: 1
            }
        )
        .is_err()
    );
    page.events[0].source_id = "cd".repeat(32);
    assert!(!page.valid_for(&request));
}

#[test]
fn blocked_http_never_holds_source_business_or_consumer_transaction() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (received_tx, received_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let receiver = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (headers, body) = request(&mut stream);
        received_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let ack = acknowledgement(header(&headers, "x-morph-event-id"), &body, &[7; 32]).unwrap();
        write!(
            stream,
            "HTTP/1.1 204 No Content\r\nX-Morph-Ack: {ack}\r\nContent-Length: 0\r\n\r\n"
        )
        .unwrap();
    });
    let dir = directory();
    let source = db(&dir.path().join("source"));
    seed(&source, 2);
    let hook = Webhook::new(&url, zeroize::Zeroizing::new([7; 32])).unwrap();
    let q = queue(dir.path(), hook.fingerprint());
    q.ingest(1000).unwrap();
    let ticket = q.claim(1000).unwrap().unwrap();
    let sender = std::thread::spawn(move || {
        let result = hook.send(&ticket);
        (ticket, result)
    });
    received_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let revision = source.validate().unwrap().revision;
    source
        .commit(&Commit {
            operation_id: "concurrent_business".into(),
            expected_revision: revision,
            intent: Body::new(b"independent mutation".to_vec()).unwrap(),
            writes: vec![Write {
                family: Family::Hub,
                id: "state".into(),
                value: Some(Body::new(b"advanced".to_vec()).unwrap()),
            }],
            events: vec![],
            attempts: vec![],
        })
        .unwrap();
    assert!(q.claim(1001).unwrap().is_some());
    release_tx.send(()).unwrap();
    let (ticket, result) = sender.join().unwrap();
    assert!(matches!(result, Outcome::Acknowledged));
    q.complete(&ticket, result, 1002).unwrap();
    receiver.join().unwrap();
}
