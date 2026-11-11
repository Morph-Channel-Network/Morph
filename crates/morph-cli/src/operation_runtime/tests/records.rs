use super::*;

#[test]
fn corrupt_operation_records_reject_reopen_without_rebroadcast_or_record_replacement() {
    let mut accepted = Vec::new();
    for kind in [
        "json",
        "future",
        "retired",
        "extra",
        "missing-tip",
        "missing-lifecycle",
        "identity",
        "broadcasts",
        "lifecycle",
        "preflight-size",
        "preflight-cycles",
    ] {
        let (dir, _rpc, spec) = fixture();
        let path = dir.path().join("operations.db");
        let mut tracker = Tracker::open(&path, spec.clone()).unwrap();
        tracker.register(preflight(&spec)).unwrap();
        let id = spec.id().unwrap();
        let mut value = serde_json::to_value(tracker.record.as_ref().unwrap()).unwrap();
        match kind {
            "future" => value["schema"] = json!("morph.ckb_operation.v999"),
            "retired" => value["schema"] = json!("morph.ckb_operation.v1"),
            "extra" => value["future_authority"] = json!(true),
            "missing-tip" => {
                value.as_object_mut().unwrap().remove("tip_hash");
            }
            "missing-lifecycle" => {
                value.as_object_mut().unwrap().remove("lifecycle");
            }
            "identity" => value["spec"]["context_id"] = json!("99".repeat(32)),
            "broadcasts" => value["broadcasts"] = json!(MAX_BROADCASTS + 1),
            "lifecycle" => value["lifecycle"]["entries"][0] = json!(0),
            "preflight-size" => value["preflight"]["tx_size_bytes"] = json!(0),
            "preflight-cycles" => value["preflight"]["estimated_cycles"] = json!(0),
            "json" => {}
            _ => unreachable!(),
        }
        let bytes = if kind == "json" {
            b"{".to_vec()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let revision = tracker.store.revision().unwrap();
        tracker
            .store
            .commit(&Commit {
                operation_id: format!("test-{kind}"),
                expected_revision: revision,
                intent: Body::new(vec![1]).unwrap(),
                writes: vec![Write {
                    family: Family::Publication,
                    id: id.clone(),
                    value: Some(Body::new(bytes.clone()).unwrap()),
                }],
                events: vec![],
                attempts: vec![],
            })
            .unwrap();
        drop(tracker);
        let before = std::fs::read(&path).unwrap();
        if Tracker::open(&path, spec).is_ok() {
            accepted.push(kind);
        }
        assert_eq!(std::fs::read(&path).unwrap(), before, "{kind}");
        let reader = Store::read_only(&path, Protection::private_plaintext()).unwrap();
        let record = reader.read(Family::Publication, &id).unwrap();
        assert_eq!(record.revision, revision + 1);
        assert_eq!(record.record.unwrap().body.bytes(), bytes);
    }
    assert!(
        accepted.is_empty(),
        "corrupt records were accepted: {accepted:?}"
    );
}
