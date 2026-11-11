//! Corrupt consumer payloads through valid generic transactions, preserving the
//! private database envelope so the real queue decoder/validator is exercised.
use super::*;
use serde_json::{Value, json};

#[test]
fn damaged_consumer_metadata_and_jobs_never_reopen_or_reset_source_cursor() {
    let mut accepted = Vec::new();
    for kind in [
        "meta-json",
        "meta-future",
        "meta-retired",
        "meta-extra",
        "meta-missing-link",
        "meta-source",
        "meta-target",
        "meta-sealed",
        "meta-zero-cursor",
        "meta-count",
        "job-json",
        "job-missing-ack",
        "job-status",
        "job-attempts",
        "job-generation",
        "job-identity",
        "job-body",
        "job-source",
        "job-pending-ack",
        "job-fake-ack",
    ] {
        let dir = directory();
        let source_path = dir.path().join("source");
        let consumer_path = dir.path().join("consumer");
        let source = db(&source_path);
        seed(&source, 1);
        let q = queue(dir.path(), policy());
        assert_eq!(q.ingest(1000).unwrap(), 1);
        drop(q);
        drop(source);
        let store = db(&consumer_path);
        let records = store.records(Family::Delivery, "", 10).unwrap();
        let selected = records
            .iter()
            .find(|r| {
                if kind.starts_with("meta-") {
                    r.id == "consumer"
                } else {
                    r.id.starts_with("job:")
                }
            })
            .unwrap();
        let mut value: Value = serde_json::from_slice(selected.body.bytes()).unwrap();
        match kind {
            "meta-future" => value["schema"] = json!("morph.event.consumer.v999"),
            "meta-retired" => value["schema"] = json!("morph.event.consumer.v1"),
            "meta-extra" => value["future_authority"] = json!(true),
            "meta-missing-link" => {
                value.as_object_mut().unwrap().remove("predecessor");
            }
            "meta-source" => value["source"] = json!("99".repeat(32)),
            "meta-target" => value["target"] = json!("99".repeat(32)),
            "meta-sealed" => value["phase"] = json!("sealed"),
            "meta-zero-cursor" => value["cursor_revision"] = json!(0),
            "meta-count" => value["total"] = json!(0),
            "job-missing-ack" => {
                value.as_object_mut().unwrap().remove("acknowledgement");
            }
            "job-status" => value["status"] = json!("future"),
            "job-attempts" => value["attempts"] = json!(MAX_ATTEMPTS + 1),
            "job-generation" => value["generation"] = json!(MAX_REPLAYS + 1),
            "job-identity" => value["event_id"] = json!("99".repeat(32)),
            "job-body" => value["body"] = json!(hex::encode(b"{")),
            "job-source" => {
                let mut event: Value =
                    serde_json::from_slice(&hex::decode(value["body"].as_str().unwrap()).unwrap())
                        .unwrap();
                event["source_id"] = json!("99".repeat(32));
                value["body"] = json!(hex::encode(serde_json::to_vec(&event).unwrap()));
            }
            "job-pending-ack" => value["acknowledgement"] = json!("99".repeat(32)),
            "job-fake-ack" => value["status"] = json!("acknowledged"),
            "meta-json" | "job-json" => {}
            _ => unreachable!(),
        }
        let bytes = if kind.ends_with("-json") {
            b"{".to_vec()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let revision = store.revision().unwrap();
        store
            .commit(&Commit {
                operation_id: format!("test-{kind}"),
                expected_revision: revision,
                intent: Body::new(vec![1]).unwrap(),
                writes: vec![Write {
                    family: Family::Delivery,
                    id: selected.id.clone(),
                    value: Some(Body::new(bytes.clone()).unwrap()),
                }],
                events: vec![],
                attempts: vec![],
            })
            .unwrap();
        drop(store);
        let before_source = std::fs::read(&source_path).unwrap();
        let before_consumer = std::fs::read(&consumer_path).unwrap();
        let reopened = Queue::open(
            Store::read_only(&source_path, Protection::private_plaintext()).unwrap(),
            db(&consumer_path),
            policy(),
        );
        if reopened.is_ok() {
            accepted.push(kind);
        }
        drop(reopened);
        assert_eq!(
            std::fs::read(&source_path).unwrap(),
            before_source,
            "{kind}"
        );
        assert_eq!(
            std::fs::read(&consumer_path).unwrap(),
            before_consumer,
            "{kind}"
        );
        let reader = Store::read_only(&consumer_path, Protection::private_plaintext()).unwrap();
        let saved = reader.read(Family::Delivery, &selected.id).unwrap();
        assert_eq!(saved.revision, revision + 1);
        assert_eq!(saved.record.unwrap().body.bytes(), bytes);
    }
    assert!(
        accepted.is_empty(),
        "corrupt records were accepted: {accepted:?}"
    );
}
