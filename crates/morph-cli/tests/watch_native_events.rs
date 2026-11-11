//! Read-only assertions over an actual publication-reliability run. The regular
//! test suite does not pretend that synthetic records are live chain evidence.
#![cfg(target_os = "linux")]
use morph_packages::events::{Component, EventEnvelope, Kind, SourceDeliveryPolicy};
use morph_runtime_store::{Cursor, Family, History, Protection, Store};
use std::{collections::BTreeSet, fs, path::PathBuf};

#[test]
#[ignore = "requires MORPH_WATCH_NATIVE_EVIDENCE from a completed private devnet publication-reliability run"]
fn actual_watch_outbox_binds_publication_bytes_and_reorg_without_mutating_source() {
    let root =
        PathBuf::from(std::env::var_os("MORPH_WATCH_NATIVE_EVIDENCE").expect("evidence path"));
    let mut kinds = BTreeSet::new();
    let mut references = 0;
    for (database, attempts) in [
        ("operator-a/cursor.db", "operator-a/attempts.jsonl"),
        ("operator-b/cursor.db", "operator-b/attempts.jsonl"),
        (
            "operator-b/service-cursor.db",
            "operator-b/service-attempts.jsonl",
        ),
    ] {
        let path = root.join(database);
        let before = fs::read(&path).unwrap();
        let store = Store::read_only(&path, Protection::private_plaintext()).unwrap();
        let validation = store.validate().unwrap();
        let cursor = store.read(Family::Watch, "cursor").unwrap().record.unwrap();
        let cursor: serde_json::Value = serde_json::from_slice(cursor.body.bytes()).unwrap();
        assert!(cursor["scanned_to_block_hash"].is_string());
        let channel = cursor["channel_id"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x");
        let policy = store
            .read(Family::Watch, "delivery-policy")
            .unwrap()
            .record
            .unwrap();
        assert!(
            !serde_json::from_slice::<SourceDeliveryPolicy>(policy.body.bytes())
                .unwrap()
                .allowed
        );
        let mut page_cursor = Cursor::default();
        loop {
            let page = store.history(History::Outbox, &page_cursor, 64).unwrap();
            if page.is_empty() {
                break;
            }
            for row in page {
                page_cursor = row.cursor();
                let event = EventEnvelope::decode(row.body.bytes()).unwrap();
                assert_eq!(event.component, Component::Watch);
                assert_eq!(event.subject_id.as_deref(), Some(channel));
                assert_eq!(event.source_id, hex::encode(store.identity()));
                assert_eq!(event.source_revision, row.revision);
                assert!(event.source_revision <= validation.revision);
                assert_eq!(
                    event.event_id,
                    EventEnvelope::identity(&event.source_id, &row.id)
                );
                kinds.insert(serde_json::to_string(&event.kind).unwrap());
                if matches!(
                    event.kind,
                    Kind::WatchPublicationSubmitted | Kind::WatchSplicePublicationSubmitted
                ) {
                    let digest = event
                        .evidence_digest
                        .as_ref()
                        .expect("publication evidence digest");
                    let log = fs::read(root.join(attempts)).unwrap();
                    assert!(
                        log.split_inclusive(|b| *b == b'\n').any(|line| {
                            let mut material = b"morph.watch.publication_evidence.v1\0".to_vec();
                            material.extend_from_slice(line);
                            hex::encode(morph_core::blake2b256(&material)) == *digest
                        }),
                        "event does not bind an immutable attempt line"
                    );
                    references += 1;
                }
            }
        }
        drop(store);
        assert_eq!(fs::read(path).unwrap(), before);
    }
    for kind in [
        Kind::WatchReorgDetected,
        Kind::WatchOlderStateDetected,
        Kind::WatchPublicationSubmitted,
        Kind::WatchScanIdle,
    ] {
        assert!(
            kinds.contains(&serde_json::to_string(&kind).unwrap()),
            "missing actual {kind:?}"
        );
    }
    assert!(
        references >= 3,
        "missing publication / replacement / reorg records"
    );
}
