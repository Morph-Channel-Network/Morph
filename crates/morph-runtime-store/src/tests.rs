use super::*;
use std::{
    fs,
    io::{BufRead, BufReader, Write as _},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn body(s: &str) -> Body {
    Body::new(s.as_bytes().to_vec()).unwrap()
}
fn commit(id: &str, revision: u64) -> Commit {
    Commit {
        operation_id: id.into(),
        expected_revision: revision,
        intent: body("exact recovery instruction"),
        writes: vec![
            Write {
                family: Family::Hub,
                id: "node".into(),
                value: Some(body("hub revision")),
            },
            Write {
                family: Family::Payment,
                id: "payment-1".into(),
                value: Some(body("payment revision")),
            },
        ],
        events: vec![Append {
            id: format!("{id}:event"),
            body: body("safe event"),
        }],
        attempts: vec![Append {
            id: format!("{id}:attempt"),
            body: body("exact signed transaction reference"),
        }],
    }
}
fn assert_all(store: &Store, revision: u64) {
    let r = store.validate().unwrap();
    assert_eq!(r.revision, revision);
    assert_eq!(r.records, if revision == 0 { 0 } else { 2 });
    assert_eq!(r.intents, revision);
    assert_eq!(r.events, revision);
    assert_eq!(r.attempts, revision);
}

#[test]
fn atomic_cas_replay_and_bounded_queries_share_memory_and_disk_semantics() {
    let directory = private_dir();
    let path = directory.path().join("runtime.db");
    for store in [
        Store::memory(Protection::private_plaintext()).unwrap(),
        Store::open(&path, Protection::encrypted([7; 32])).unwrap(),
    ] {
        let first = commit("z-first", 0);
        assert_eq!(store.commit(&first).unwrap().revision, 1);
        assert_all(&store, 1);
        assert_eq!(
            store.commit(&commit("stale", 0)),
            Err(StoreError::Revision {
                expected: 0,
                actual: 1
            })
        );
        assert_eq!(store.commit(&first).unwrap().revision, 1);
        let mut changed = first.clone();
        changed.intent = body("different");
        assert_eq!(store.commit(&changed), Err(StoreError::Conflict));
        assert_all(&store, 1);
        let cursor = store
            .history(History::Outbox, &Cursor::default(), 1)
            .unwrap()[0]
            .cursor();
        store.commit(&commit("a-second", 1)).unwrap();
        let events = store.history(History::Outbox, &cursor, 1).unwrap();
        assert_eq!(events[0].id, "a-second:event");
        assert!(
            store
                .history(History::Outbox, &events[0].cursor(), 1)
                .unwrap()
                .is_empty()
        );
        assert!(store.records(Family::Hub, "", MAX_PAGE_SIZE + 1).is_err());
        let records = store.records(Family::Hub, "", 1).unwrap();
        assert_eq!(records[0].body.bytes(), b"hub revision");
        assert_eq!(
            store.read(Family::Payment, "payment-1").unwrap().revision,
            2
        );
        let mut collision = commit("third", 2);
        collision.events[0].id = "a-second:event".into();
        assert_eq!(store.commit(&collision), Err(StoreError::Conflict));
        assert_all(&store, 2);
        let mut duplicate = commit("third", 2);
        duplicate.writes.push(duplicate.writes[0].clone());
        assert_eq!(store.commit(&duplicate), Err(StoreError::Invalid));
        assert_all(&store, 2);
    }
}

#[test]
fn independent_connections_reject_stale_cas_and_preserve_exact_retry() {
    let dir = private_dir();
    let path = dir.path().join("db");
    let a = Store::open(&path, Protection::private_plaintext()).unwrap();
    let b = Store::open(&path, Protection::private_plaintext()).unwrap();
    let c = commit("one", 0);
    a.commit(&c).unwrap();
    assert_eq!(
        b.commit(&commit("two", 0)),
        Err(StoreError::Revision {
            expected: 0,
            actual: 1
        })
    );
    assert_eq!(b.commit(&c).unwrap().revision, 1);
    b.commit(&commit("two", 1)).unwrap();
    assert_all(&a, 2);
    let lock = a.connection.lock().unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(b.commit(&commit("three", 2)), Err(StoreError::Busy));
    lock.execute_batch("ROLLBACK").unwrap();
    drop(lock);
    assert_all(&a, 2);
}

#[test]
fn encrypted_bodies_never_enter_sqlite_plaintext_and_are_bound_to_identity() {
    let dir = private_dir();
    let path = dir.path().join("db");
    let store = Store::open(&path, Protection::encrypted([9; 32])).unwrap();
    store.commit(&commit("one", 0)).unwrap();
    assert_all(&store, 1);
    let bytes = fs::read(&path).unwrap();
    assert!(!bytes.windows(12).any(|w| w == b"hub revision"));
    assert!(matches!(
        Store::open(&path, Protection::encrypted([8; 32])),
        Err(StoreError::Corrupt)
    ));
    assert!(matches!(
        Store::open(&path, Protection::private_plaintext()),
        Err(StoreError::Protection)
    ));
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE records SET record_id='other' WHERE family='hub'",
            [],
        )
        .unwrap();
    assert_eq!(store.validate().unwrap_err(), StoreError::Corrupt);
    assert!(!format!("{:?}", commit("one", 0)).contains("exact recovery instruction"));
    assert!(!StoreError::Corrupt.to_string().contains("hub revision"));
}

#[test]
fn validator_is_read_only_and_schema_drift_and_truncation_fail_closed() {
    let dir = private_dir();
    let path = dir.path().join("db");
    let store = Store::open(&path, Protection::private_plaintext()).unwrap();
    store.commit(&commit("one", 0)).unwrap();
    drop(store);
    let before = fs::read(&path).unwrap();
    let validator = Store::read_only(&path, Protection::private_plaintext()).unwrap();
    assert_all(&validator, 1);
    assert_eq!(
        validator.commit(&commit("two", 1)),
        Err(StoreError::ReadOnly)
    );
    drop(validator);
    assert_eq!(fs::read(&path).unwrap(), before);
    let c = Connection::open(&path).unwrap();
    c.execute_batch("CREATE TABLE unexpected(value TEXT);")
        .unwrap();
    drop(c);
    assert!(matches!(
        Store::open(&path, Protection::private_plaintext()),
        Err(StoreError::Schema)
    ));
    fs::write(&path, b"").unwrap();
    assert!(matches!(
        Store::open(&path, Protection::private_plaintext()),
        Err(StoreError::Corrupt)
    ));
    fs::write(&path, b"{\"old\":\"snapshot\"}").unwrap();
    assert!(Store::open(&path, Protection::private_plaintext()).is_err());
    let absent = dir.path().join("absent.db");
    assert!(Store::read_only(&absent, Protection::private_plaintext()).is_err());
    assert!(!absent.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn native_permissions_links_and_shared_directories_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = private_dir();
    let path = dir.path().join("db");
    let store = Store::open(&path, Protection::private_plaintext()).unwrap();
    drop(store);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Store::open(&path, Protection::private_plaintext()),
        Err(StoreError::Permissions)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(Store::open(&link, Protection::private_plaintext()).is_err());
    let hard = dir.path().join("hard");
    fs::hard_link(&path, &hard).unwrap();
    assert!(matches!(
        Store::open(&hard, Protection::private_plaintext()),
        Err(StoreError::Permissions)
    ));
    fs::remove_file(hard).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Store::open(&path, Protection::private_plaintext()),
        Err(StoreError::Permissions)
    ));
}

#[test]
fn actual_sqlite_page_limit_causes_full_without_partial_cross_record_commit() {
    let store = Store::memory(Protection::private_plaintext()).unwrap();
    store.commit(&commit("one", 0)).unwrap();
    {
        let c = store.connection.lock().unwrap();
        let pages: i64 = c
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        c.pragma_update(None, "max_page_count", pages).unwrap();
    }
    let mut c = commit("two", 1);
    c.writes[0].value = Some(Body::new(vec![17; 1024 * 1024]).unwrap());
    assert_eq!(store.commit(&c), Err(StoreError::Full));
    assert_all(&store, 1);
}

// Child helper belongs exclusively to cfg(test). No production environment flag
// can terminate a writer or weaken its commit/synchronization behavior.
#[test]
fn crash_child() {
    let Ok(path) = std::env::var("MORPH_STORE_TEST_PATH") else {
        return;
    };
    let stage = std::env::var("MORPH_STORE_TEST_STAGE").unwrap();
    let store = Store::open(Path::new(&path), Protection::encrypted([7; 32])).unwrap();
    store
        .commit_observed(&commit("child", 0), |observed| {
            let selected = if stage == "before" {
                CommitStage::BeforeCommit
            } else {
                CommitStage::AfterCommit
            };
            if stage != "ack" && observed == selected {
                println!("KILL_BOUNDARY");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park_timeout(Duration::from_secs(1));
                }
            }
        })
        .unwrap();
    println!("KILL_BOUNDARY_ACKNOWLEDGED");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park_timeout(Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn real_process_kill_before_commit_after_commit_and_after_acknowledgement() {
    for (stage, expected) in [("before", 0), ("after", 1), ("ack", 1)] {
        let dir = private_dir();
        let path = dir.path().join("db");
        drop(Store::open(&path, Protection::encrypted([7; 32])).unwrap());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::crash_child", "--nocapture"])
            .env("MORPH_STORE_TEST_PATH", &path)
            .env("MORPH_STORE_TEST_STAGE", stage)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                if line.unwrap().contains("KILL_BOUNDARY") {
                    let _ = sender.send(());
                    break;
                }
            }
        });
        let observed = receiver.recv_timeout(Duration::from_secs(10));
        child.kill().unwrap();
        let exit = child.wait().unwrap();
        assert!(!exit.success());
        assert!(observed.is_ok());
        let store = Store::open(&path, Protection::encrypted([7; 32])).unwrap();
        assert_all(&store, expected);
        let receipt = store.commit(&commit("child", 0)).unwrap();
        assert_eq!(receipt.revision, 1);
        assert_all(&store, 1);
    }
}

#[test]
fn schema_has_one_current_layout_and_configured_durability() {
    assert_eq!(
        hex::encode(protection::digest(
            b"morph.runtime.schema.v1\0",
            SCHEMA_SQL.as_bytes()
        )),
        "35e10f11a9bb6668cbcdef2810ea2d6a21522dff1fe25feab4df664bab4dbd7b"
    );
    assert!(serde_json::from_str::<Write>(r#"{"family":"hub","id":"node"}"#).is_err());
    assert!(serde_json::from_str::<Write>(r#"{"family":"hub","id":"node","value":null}"#).is_ok());
    let dir = private_dir();
    let path = dir.path().join("db");
    let store = Store::open(&path, Protection::private_plaintext()).unwrap();
    let c = store.connection.lock().unwrap();
    assert_eq!(
        c.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        c.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    assert_eq!(
        c.pragma_query_value(None, "foreign_keys", |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    let start = Instant::now();
    check_schema(&c).unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn sync_failure_child() {
    let write_fault = std::env::var("MORPH_STORE_TEST_WRITE_FAILURE").ok();
    let marker = match write_fault
        .clone()
        .or_else(|| std::env::var("MORPH_STORE_TEST_SYNC_FAILURE").ok())
    {
        Some(marker) => marker,
        None => return,
    };
    let path = std::env::var("MORPH_STORE_TEST_PATH").unwrap();
    let store = Store::open(Path::new(&path), Protection::encrypted([7; 32])).unwrap();
    fs::write(&marker, b"inject EIO").unwrap();
    let result = store.commit(&commit("sync-failed", 0));
    fs::remove_file(&marker).unwrap();
    if write_fault.is_some() {
        assert_eq!(result, Err(StoreError::Full));
    } else {
        assert!(
            matches!(result, Err(StoreError::Io | StoreError::CommitUncertain)),
            "{result:?}"
        );
    }
    drop(store);
    let reopened = Store::open(Path::new(&path), Protection::encrypted([7; 32])).unwrap();
    let revision = reopened.validate().unwrap().revision;
    assert!(revision <= 1);
    assert_all(&reopened, revision);
    // Even an uncertain commit can only be reconciled by exact operation replay.
    assert_eq!(
        reopened.commit(&commit("sync-failed", 0)).unwrap().revision,
        1
    );
    assert_all(&reopened, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn actual_fsync_eio_and_enospc_never_acknowledge_partial_commit() {
    for fault in [
        "MORPH_STORE_TEST_SYNC_FAILURE",
        "MORPH_STORE_TEST_WRITE_FAILURE",
    ] {
        let dir = private_dir();
        let path = dir.path().join("db");
        drop(Store::open(&path, Protection::encrypted([7; 32])).unwrap());
        let library = dir.path().join("fsync-fault.so");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fsync_fault.c");
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Werror"])
                .arg(source)
                .args(["-ldl", "-o"])
                .arg(&library)
                .status()
                .unwrap()
                .success()
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::sync_failure_child", "--nocapture"])
            .env("MORPH_STORE_TEST_PATH", &path)
            .env(fault, dir.path().join("fail-sync"))
            .env("LD_PRELOAD", library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let reopened = Store::read_only(&path, Protection::encrypted([7; 32])).unwrap();
        assert_all(&reopened, 1);
    }
}

#[test]
fn new_commit_permission_cannot_be_obtained_from_an_idempotent_receipt() {
    let directory = private_dir();
    let path = directory.path().join("runtime.db");
    let first = Store::open(&path, Protection::encrypted([17; 32])).unwrap();
    let peer = Store::open(&path, Protection::encrypted([17; 32])).unwrap();
    let request = commit("send-once", 0);
    let receipt = first.commit_new(&request).unwrap();
    assert_eq!(peer.commit_new(&request), Err(StoreError::Conflict));
    assert_eq!(peer.commit(&request).unwrap(), receipt);
    assert_eq!(peer.commit_new(&request), Err(StoreError::Conflict));
    assert_all(&peer, 1);
}
