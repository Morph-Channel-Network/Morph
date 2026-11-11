//! One current watch checkpoint/event transaction. JSONL is a rebuildable local
//! display projection; publication attempt evidence remains separate and immutable.
use crate::{
    watch_alert::{WatchAlertEvent, WatchtowerAlert},
    watch_cursor::WatchCursor,
};
use anyhow::{Context, Result, ensure};
use morph_packages::events::{
    Component, EventEnvelope, EventSchema, EvidenceLevel, Kind, Severity, SourceDeliveryPolicy,
};
use morph_runtime_store::{
    Append, Body, Commit, Cursor, Family, History, Protection, Store, Write,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    alert: Option<WatchtowerAlert>,
}
fn body<T: Serialize>(value: &T) -> Result<Body> {
    Ok(Body::new(serde_json::to_vec(value)?)?)
}
pub fn read(path: &Path) -> Result<Option<WatchCursor>> {
    if !path.exists() {
        return Ok(None);
    }
    let store = Store::read_only(path, Protection::private_plaintext())?;
    let snapshot = store.read(Family::Watch, "cursor")?;
    ensure!(
        snapshot.record.is_some() || snapshot.revision == 0,
        "not a watch runtime source"
    );
    snapshot
        .record
        .map(|r| {
            let cursor: WatchCursor = serde_json::from_slice(r.body.bytes())?;
            cursor.validate()?;
            Ok(cursor)
        })
        .transpose()
}
pub fn commit(
    path: &Path,
    cursor: &WatchCursor,
    alert: Option<&WatchtowerAlert>,
    allow_delivery: bool,
    evidence: Option<String>,
) -> Result<()> {
    cursor.validate()?;
    let store = Store::open(path, Protection::private_plaintext())?;
    let previous = store.read(Family::Watch, "cursor")?;
    ensure!(
        previous.record.is_some() || previous.revision == 0,
        "not a watch runtime source"
    );
    if let Some(record) = &previous.record {
        let prior: WatchCursor = serde_json::from_slice(record.body.bytes())?;
        ensure!(
            prior.channel_id == cursor.channel_id && prior.from_block == cursor.from_block,
            "watch source identity or scan origin changed"
        );
    }
    let policy = SourceDeliveryPolicy::new(allow_delivery);
    let intent = Intent {
        schema: "morph.watch.transition.v1".into(),
        alert: alert.cloned(),
    };
    let source_revision = previous
        .revision
        .checked_add(1)
        .context("watch revision exhausted")?;
    let encoded = serde_json::to_vec(&(cursor, &intent, &policy, &evidence))?;
    let operation_id = format!(
        "watch:{}:{}",
        previous.revision,
        hex::encode(morph_core::blake2b256(&encoded))
    );
    let id = format!("{operation_id}:event");
    let source_id = hex::encode(store.identity());
    let events = if let Some(alert) = alert {
        ensure!(
            alert.channel_id == cursor.channel_id,
            "watch alert belongs to another channel"
        );
        let kind = match &alert.event {
            WatchAlertEvent::ChainReorgDetected => Kind::WatchReorgDetected,
            WatchAlertEvent::RecoveryDataInvalid => Kind::WatchRecoveryInvalid,
            WatchAlertEvent::PublicationFailed => Kind::WatchPublicationFailed,
            WatchAlertEvent::OlderStateDetected => Kind::WatchOlderStateDetected,
            WatchAlertEvent::PublicationSubmitted => Kind::WatchPublicationSubmitted,
            WatchAlertEvent::SpliceDetected => Kind::WatchSpliceDetected,
            WatchAlertEvent::SplicePackageStale => Kind::WatchSplicePackageStale,
            WatchAlertEvent::SplicePublicationSubmitted => Kind::WatchSplicePublicationSubmitted,
            WatchAlertEvent::ScanIdle => Kind::WatchScanIdle,
        };
        let event = EventEnvelope {
            schema: EventSchema::Current,
            event_id: EventEnvelope::identity(&source_id, &id),
            source_id,
            source_revision,
            created_at_ms: alert.created_unix_ms,
            component: Component::Watch,
            evidence_level: EvidenceLevel::LocalRecord,
            kind,
            severity: match alert.severity {
                crate::watch_alert::WatchAlertSeverity::Info => Severity::Info,
                crate::watch_alert::WatchAlertSeverity::Warning => Severity::Warning,
                crate::watch_alert::WatchAlertSeverity::Critical => Severity::Critical,
            },
            correlation_id: EventEnvelope::correlation(&operation_id),
            subject_id: Some(cursor.channel_id.trim_start_matches("0x").into()),
            funding_context_id: alert
                .selected_funding_context_id
                .as_ref()
                .or(cursor.current_funding_context_id.as_ref())
                .map(|s| s.trim_start_matches("0x").into()),
            payment_hash: None,
            provider_revision: None,
            evidence_digest: evidence,
        };
        vec![Append {
            id,
            body: Body::new(event.encode()?)?,
        }]
    } else {
        vec![]
    };
    store.commit_new(&Commit {
        operation_id,
        expected_revision: previous.revision,
        intent: body(&intent)?,
        writes: vec![
            Write {
                family: Family::Watch,
                id: "cursor".into(),
                value: Some(body(cursor)?),
            },
            Write {
                family: Family::Watch,
                id: "delivery-policy".into(),
                value: Some(body(&policy)?),
            },
        ],
        events,
        attempts: vec![],
    })?;
    Ok(())
}
/// Rebuild only a local display projection. No HTTP and no source mutations.
/// Replay after a crash between authoritative commit and the old display append.
pub fn export_alerts(source: &Path, destination: &Path) -> Result<()> {
    if !source.exists() {
        return Ok(());
    }
    ensure!(
        source != destination,
        "watch source and alert projection must differ"
    );
    let store = Store::read_only(source, Protection::private_plaintext())?;
    // Several channels may share this local projection. Merge under the same
    // stable lock used by appenders; never replace another channel's alerts.
    let _lock = crate::persistence::try_lock_private_path(destination)?
        .context("watch alert projection is busy")?;
    let mut known = std::collections::BTreeSet::new();
    let mut output = Vec::new();
    if destination.exists() {
        let file = std::fs::File::open(destination)?;
        crate::persistence::require_private_file(&file)?;
        ensure!(
            file.metadata()?.len() <= 32 * 1024 * 1024,
            "watch alert projection exceeds bound"
        );
        file.take(32 * 1024 * 1024 + 1).read_to_end(&mut output)?;
        ensure!(
            output.len() <= 32 * 1024 * 1024,
            "watch alert projection exceeds bound"
        );
        // Only a torn final append may be discarded. Complete foreign/invalid
        // records are errors. Their owning sources repair missing display rows.
        output.truncate(
            output
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |n| n + 1),
        );
        for line in output.split_inclusive(|b| *b == b'\n') {
            let alert: WatchtowerAlert = serde_json::from_slice(line)?;
            ensure!(
                alert.schema == "morph.watchtower_alert",
                "unsupported watch alert projection"
            );
            known.insert(morph_core::blake2b256(&serde_json::to_vec(&alert)?));
        }
    }
    let mut cursor = Cursor::default();
    loop {
        let page = store.history(History::Intent, &cursor, 128)?;
        if page.is_empty() {
            break;
        }
        for entry in page {
            cursor = entry.cursor();
            let intent: Intent = serde_json::from_slice(entry.body.bytes())?;
            ensure!(
                intent.schema == "morph.watch.transition.v1",
                "unsupported watch transition"
            );
            if let Some(alert) = intent.alert {
                let mut line = serde_json::to_vec(&alert)?;
                if !known.insert(morph_core::blake2b256(&line)) {
                    continue;
                }
                line.push(b'\n');
                ensure!(
                    output.len() + line.len() <= 32 * 1024 * 1024,
                    "watch alert projection reached bounded export capacity"
                );
                output.extend(line);
            }
        }
    }
    crate::persistence::write_private_atomic(destination, &output)
}
/// Reference a matching immutable attempt's exact JSON bytes, without rewriting
/// or normalizing the append-only evidence. Trailing partial records are rejected.
pub fn attempt_digest(path: &Path, tx_hash: &str) -> Result<String> {
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= 64 * 1024 * 1024,
        "publication log exceeds evidence bound"
    );
    let mut reader = BufReader::new(file);
    let mut found = None;
    loop {
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take(64 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        ensure!(
            n <= 64 * 1024 && line.last() == Some(&b'\n'),
            "invalid bounded publication record"
        );
        let record: crate::publication::PublicationAttemptRecord = serde_json::from_slice(&line)?;
        if record.tx_hash == tx_hash {
            let mut input = b"morph.watch.publication_evidence.v1\0".to_vec();
            input.extend(&line);
            found = Some(hex::encode(morph_core::blake2b256(&input)));
        }
    }
    found.context("publication has no matching immutable attempt evidence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch_alert::WatchAlertSeverity;
    use std::{
        fs,
        process::{Command, Stdio},
        time::Duration,
    };

    fn directory() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    fn cursor(height: u64) -> WatchCursor {
        WatchCursor::new(&format!("0x{}", "12".repeat(32)), 0, height + 1, height)
            .unwrap()
            .with_scanned_block_hash(&format!("0x{}", "34".repeat(32)))
            .unwrap()
    }
    fn alert(cursor: &WatchCursor) -> WatchtowerAlert {
        WatchtowerAlert::new(
            cursor.channel_id.clone(),
            WatchAlertSeverity::Critical,
            WatchAlertEvent::RecoveryDataInvalid,
            "private-path-and-rpc-credential".into(),
            4,
            cursor.scanned_to_block,
            cursor.next_block,
        )
        .unwrap()
    }
    fn outbox(path: &Path) -> Vec<EventEnvelope> {
        Store::read_only(path, Protection::private_plaintext())
            .unwrap()
            .history(History::Outbox, &Cursor::default(), 64)
            .unwrap()
            .into_iter()
            .map(|e| EventEnvelope::decode(e.body.bytes()).unwrap())
            .collect()
    }
    #[test]
    fn atomic_alert_checkpoint_redaction_and_rejected_transition() {
        let dir = directory();
        let path = dir.path().join("watch.db");
        commit(&path, &cursor(10), None, false, None).unwrap();
        assert!(outbox(&path).is_empty());
        let state = cursor(11);
        let record = alert(&state);
        commit(&path, &state, Some(&record), true, None).unwrap();
        let events = outbox(&path);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_revision, 2);
        assert_eq!(events[0].kind, Kind::WatchRecoveryInvalid);
        assert!(
            !String::from_utf8(events[0].encode().unwrap())
                .unwrap()
                .contains(&record.message)
        );
        assert_eq!(read(&path).unwrap().unwrap(), state);
        let mut wrong = record.clone();
        wrong.channel_id = format!("0x{}", "ff".repeat(32));
        assert!(commit(&path, &cursor(12), Some(&wrong), false, None).is_err());
        assert_eq!(read(&path).unwrap().unwrap(), state);
        assert_eq!(outbox(&path), events);
        let store = Store::read_only(&path, Protection::private_plaintext()).unwrap();
        let policy = store
            .read(Family::Watch, "delivery-policy")
            .unwrap()
            .record
            .unwrap();
        assert!(
            serde_json::from_slice::<SourceDeliveryPolicy>(policy.body.bytes())
                .unwrap()
                .allowed
        );
        // Reorg reset and its alert share the next committed revision.
        let reset = cursor(0);
        let mut reorg = alert(&reset);
        reorg.event = WatchAlertEvent::ChainReorgDetected;
        commit(&path, &reset, Some(&reorg), false, None).unwrap();
        assert_eq!(read(&path).unwrap().unwrap(), reset);
        assert_eq!(outbox(&path)[1].kind, Kind::WatchReorgDetected);
    }
    #[test]
    fn shared_projection_repairs_torn_tail_without_erasing_other_channels_or_duplicates() {
        let dir = directory();
        let path = dir.path().join("watch.db");
        let display = dir.path().join("alerts.jsonl");
        let state = cursor(10);
        let record = alert(&state);
        let mut other = record.clone();
        other.channel_id = format!("0x{}", "ab".repeat(32));
        crate::watch_alert::append_watchtower_alert(&display, &other).unwrap();
        commit(&path, &state, Some(&record), false, None).unwrap();
        use std::io::Write as _;
        fs::OpenOptions::new()
            .append(true)
            .open(&display)
            .unwrap()
            .write_all(b"{\"torn")
            .unwrap();
        export_alerts(&path, &display).unwrap();
        let bytes = fs::read(&display).unwrap();
        let records: Vec<WatchtowerAlert> = bytes
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert_eq!(records, vec![other, record]);
        export_alerts(&path, &display).unwrap();
        assert_eq!(fs::read(&display).unwrap(), bytes);
    }
    #[test]
    fn rejects_json_cursor_and_foreign_runtime_without_rewriting_either() {
        let dir = directory();
        let path = dir.path().join("old.json");
        let bytes = serde_json::to_vec(&cursor(1)).unwrap();
        crate::persistence::write_private_atomic(&path, &bytes).unwrap();
        assert!(read(&path).is_err());
        assert!(commit(&path, &cursor(2), None, false, None).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
        let other = dir.path().join("hub.db");
        let store = Store::open(&other, Protection::private_plaintext()).unwrap();
        store
            .commit_new(&Commit {
                operation_id: "hub".into(),
                expected_revision: 0,
                intent: body(&"hub").unwrap(),
                writes: vec![Write {
                    family: Family::Hub,
                    id: "state".into(),
                    value: Some(body(&"hub").unwrap()),
                }],
                events: vec![],
                attempts: vec![],
            })
            .unwrap();
        assert!(read(&other).is_err());
        assert!(commit(&other, &cursor(2), None, false, None).is_err());
        assert_eq!(store.read(Family::Hub, "state").unwrap().revision, 1);
    }
    #[test]
    fn exact_attempt_digest_never_rewrites_or_accepts_partial_evidence() {
        let dir = directory();
        let path = dir.path().join("attempts.jsonl");
        let record = serde_json::json!({"schema":"morph.publication_attempt", "recorded_unix_ms":1,
            "operator_id":"test", "intent_id":"id", "channel_id":"channel", "funding_context_id":"context",
            "target_state_number":2,"attempt":1,"fee":1000,"fee_rate":1000,"tx_size_bytes":1000,
            "tx_hash":"tx", "replaces_tx_hash":null,"node_min_replace_fee":null,"status":"submitted",
            "error_class":null,"elapsed_ms":1,"tip_number":1,"tip_hash":"tip",
            "fee_observation":{"observed_unix_ms":1,"estimator_fee_rate":1000,"confirmed_mean_fee_rate":null,
                "confirmed_median_fee_rate":null,"pool_min_fee_rate":1000,"pool_min_rbf_rate":1000,
                "pool_pending":0,"pool_proposed":0,"pool_total_tx_size":0,"rbf_enabled":true}});
        let mut bytes = serde_json::to_vec(&record).unwrap();
        bytes.push(b'\n');
        fs::write(&path, &bytes).unwrap();
        let mut expected = b"morph.watch.publication_evidence.v1\0".to_vec();
        expected.extend(&bytes);
        let digest = attempt_digest(&path, "tx").unwrap();
        assert_eq!(digest, hex::encode(morph_core::blake2b256(&expected)));
        assert!(attempt_digest(&path, "other").is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        bytes.extend(b"{");
        fs::write(&path, &bytes).unwrap();
        assert!(attempt_digest(&path, "tx").is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    #[test]
    fn crash_child() {
        let Ok(root) = std::env::var("MORPH_WATCH_TEST_DIR") else {
            return;
        };
        let root = Path::new(&root);
        let stage = std::env::var("MORPH_WATCH_TEST_STAGE").unwrap();
        let state = cursor(11);
        let record = alert(&state);
        if stage != "before" {
            commit(&root.join("watch.db"), &state, Some(&record), true, None).unwrap();
        }
        if stage == "display" {
            export_alerts(&root.join("watch.db"), &root.join("alerts.jsonl")).unwrap();
        }
        use std::io::Write as _;
        println!("WATCH_KILL_BOUNDARY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }
    #[test]
    fn actual_process_kill_preserves_atomic_cursor_event_and_repairs_display() {
        for stage in ["before", "committed", "display"] {
            let dir = directory();
            let path = dir.path().join("watch.db");
            let initial = cursor(10);
            commit(&path, &initial, None, false, None).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "watch_runtime::tests::crash_child",
                    "--nocapture",
                ])
                .env("MORPH_WATCH_TEST_DIR", dir.path())
                .env("MORPH_WATCH_TEST_STAGE", stage)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let output = child.stdout.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if line.unwrap().contains("WATCH_KILL_BOUNDARY") {
                        let _ = tx.send(());
                        break;
                    }
                }
            });
            let ready = rx.recv_timeout(Duration::from_secs(15));
            let _ = child.kill();
            let exit = child.wait().unwrap();
            assert!(ready.is_ok(), "child never reached {stage}");
            assert!(!exit.success());
            let events = outbox(&path);
            assert_eq!(events.len(), usize::from(stage != "before"));
            assert_eq!(
                read(&path).unwrap().unwrap().scanned_to_block,
                if stage == "before" { 10 } else { 11 }
            );
            export_alerts(&path, &dir.path().join("alerts.jsonl")).unwrap();
            let display = fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
            assert_eq!(display.lines().count(), events.len());
        }
    }
}
