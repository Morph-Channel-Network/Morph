use super::*;

fn server() -> HubServer {
    let key = SigningKey::from_slice(&[42; 32]).unwrap();
    super::super::tests::test_server(&hex::encode(
        key.verifying_key().to_sec1_point(true).as_bytes(),
    ))
}
fn request(path: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        path: path.into(),
        headers: BTreeMap::new(),
        body: vec![],
    }
}
fn fill_cache(server: &HubServer, reason: Reason) {
    let revision = server.store.lock().unwrap().revision;
    server.health_cache.lock().unwrap().value = Some(Probe {
        revision,
        started: Instant::now(),
        observation: observation(reason, now_ms()),
    });
}

#[test]
fn liveness_does_not_wait_for_store_and_busy_scope_is_not_ready() {
    let server = Arc::new(server());
    let held = server.store.lock().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let concurrent = server.clone();
    let task = thread::spawn(move || {
        send.send((
            concurrent.route(request("/api/health")),
            concurrent.route(request("/api/readiness")),
        ))
        .unwrap();
    });
    let result = receive.recv_timeout(Duration::from_secs(1));
    drop(held);
    task.join().unwrap();
    let (alive, readiness) = result.unwrap();
    assert_eq!(alive.status, 200);
    let live: Liveness = serde_json::from_slice(&alive.body).unwrap();
    assert!(live.alive);
    assert_eq!(readiness.status, 503);
    let report: Readiness = serde_json::from_slice(&readiness.body).unwrap();
    assert_eq!(report.scopes[0].checks[0].reason, Reason::Busy);
    assert!(!report.ready);
}

#[test]
fn actual_store_probe_checks_revision_and_current_schema() {
    let server = server();
    let store = server.store.lock().unwrap();
    assert_eq!(probe_store(&store.path, store.revision), Reason::Verified);
    assert_eq!(
        probe_store(&store.path, store.revision + 1),
        Reason::RevisionChanged
    );
    let runtime = RuntimeStore::open(&store.path, RuntimeProtection::private_plaintext()).unwrap();
    runtime
        .commit_new(&RuntimeCommit {
            operation_id: "test-invalid-hub-shape".into(),
            expected_revision: store.revision,
            intent: RuntimeBody::new(b"test-invalid-hub-shape".to_vec()).unwrap(),
            writes: vec![RuntimeWrite {
                family: RuntimeFamily::Hub,
                id: "state".into(),
                value: Some(RuntimeBody::new(b"{}".to_vec()).unwrap()),
            }],
            events: vec![],
            attempts: vec![],
        })
        .unwrap();
    assert_eq!(
        probe_store(&store.path, store.revision + 1),
        Reason::UnsupportedSchema
    );
    assert_eq!(
        probe_store(
            &store.path.with_file_name("missing-private-marker"),
            store.revision
        ),
        Reason::Unavailable
    );
}

#[test]
fn unavailable_storage_recovers_only_after_the_real_file_is_accessible_again() {
    let server = server();
    let store = server.store.lock().unwrap();
    let absent = store.path.with_file_name("temporarily-unavailable.db");
    std::fs::rename(&store.path, &absent).unwrap();
    assert_eq!(
        probe_store(&store.path, store.revision),
        Reason::Unavailable
    );
    // Restore access to the exact same file, not an older snapshot or authority.
    std::fs::rename(absent, &store.path).unwrap();
    assert_eq!(probe_store(&store.path, store.revision), Reason::Verified);
}

#[test]
fn expired_or_revision_mismatched_observation_never_grants_readiness() {
    let server = server();
    fill_cache(&server, Reason::Verified);
    let report = report(&server);
    assert!(report.ready);
    assert!(report.scopes[0].ready);
    assert!(
        report.scopes[2..]
            .iter()
            .all(|scope| !scope.ready && !scope.configured)
    );
    {
        let mut cache = server.health_cache.lock().unwrap();
        cache.value.as_mut().unwrap().started =
            Instant::now() - Duration::from_millis(PROBE_TTL_MS + 1);
        cache.in_flight = true; // a hung probe must not cause another worker
    }
    let stale = super::report(&server);
    assert!(!stale.ready);
    assert_eq!(stale.scopes[0].checks[0].reason, Reason::Stale);
    assert!(server.health_cache.lock().unwrap().in_flight);
    fill_cache(&server, Reason::Verified);
    server
        .health_cache
        .lock()
        .unwrap()
        .value
        .as_mut()
        .unwrap()
        .revision += 1;
    let stale = super::report(&server);
    assert!(!stale.ready);
    assert_eq!(stale.scopes[0].checks[0].reason, Reason::RevisionChanged);
}

#[test]
fn asynchronous_probe_recovers_without_holding_request_lock_or_exposing_paths() {
    let server = server();
    assert!(!report(&server).ready);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let current = report(&server);
        if current.ready {
            let json = serde_json::to_string(&current).unwrap();
            assert!(!json.contains("/tmp/"));
            assert!(!json.contains("pubkey"));
            break;
        }
        assert!(Instant::now() < deadline, "store probe did not complete");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn metrics_and_liveness_keep_existing_read_scope_and_fixed_label_space() {
    let mut server = server();
    server.auth_token =
        parse_hub_auth_token(Some("read:private-marker-auth-token".into())).unwrap();
    for path in ["/api/health", "/api/readiness", "/api/metrics"] {
        assert_eq!(server.route(request(path)).status, 401);
        let mut authorised = request(path);
        authorised.headers.insert(
            "authorization".into(),
            "Bearer private-marker-auth-token".into(),
        );
        let response = server.route(authorised);
        assert!(matches!(response.status, 200 | 503));
        assert!(
            !String::from_utf8(response.body)
                .unwrap()
                .contains("private-marker")
        );
    }
    let ready = Readiness::new(Service::Hub, now_ms(), vec![]);
    let before = server.metrics.render(&ready);
    for i in 0..100 {
        server.route(request(&format!("/api/private-marker-{i}")));
    }
    let after = server.metrics.render(&ready);
    assert_eq!(before.lines().count(), after.lines().count());
    assert!(!after.contains("private-marker"));
    assert!(after.len() < morph_observability::metrics::MAX_EXPORT_BYTES);
}
