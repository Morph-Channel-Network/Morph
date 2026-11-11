use super::*;
use crate::{
    shadow::ShadowStore,
    tests::{edge, policy},
};
use std::os::unix::fs::PermissionsExt;

const ENDPOINT: &str = "http://127.0.0.1:4620/";
const CALLBACK: &str = "http://127.0.0.1:4621/callback";
fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn batch(edge: ProviderEdgeDescriptor, now: u64) -> ObservedBatch {
    ObservedBatch {
        observed_at_ms: now,
        valid_until_ms: now + 1000,
        edges: vec![DesiredEdge {
            edge,
            state: MirrorState::Active,
        }],
    }
}
fn apply(local: &Coordinator, remote: &ShadowStore, now: u64) -> PendingMutation {
    let p = local.next(&remote.list().unwrap(), now).unwrap().unwrap();
    let ack = remote.apply(p.mutation.clone()).unwrap();
    local.acknowledge(&p, &ack, now).unwrap();
    p
}
#[test]
fn response_loss_both_store_restarts_and_historical_retry_do_not_reapply() {
    let dir = directory();
    let a = dir.path().join("morph.db");
    let b = dir.path().join("fiber.db");
    let local = Coordinator::open(&a, policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&b, policy()).unwrap();
    let observed = batch(edge(1), 100);
    let receipt = local
        .observe(local.revision().unwrap(), observed.clone(), 100)
        .unwrap();
    let pending = local.next(&remote.list().unwrap(), 101).unwrap().unwrap();
    let original = remote.apply(pending.mutation.clone()).unwrap();
    drop(local);
    drop(remote);
    let local = Coordinator::open(&a, policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&b, policy()).unwrap();
    // Reopening a database is not a new canonical observation. Revalidate the
    // same edge first; the already persisted exact mutation remains replayable.
    local
        .observe(local.revision().unwrap(), batch(edge(1), 102), 102)
        .unwrap();
    assert_eq!(
        local.next(&remote.list().unwrap(), 102).unwrap(),
        Some(pending.clone())
    );
    let repeated = remote.apply(pending.mutation.clone()).unwrap();
    assert_eq!(original, repeated);
    let ack = local.acknowledge(&pending, &repeated, 102).unwrap();
    assert_eq!(local.acknowledge(&pending, &repeated, 103).unwrap(), ack);
    assert_eq!(local.observe(0, observed, 5000).unwrap(), receipt); // historical receipt, no lease renewal
    assert!(matches!(
        apply(&local, &remote, 5000).mutation,
        ShadowMutation::Drain(_)
    ));
    assert!(matches!(
        apply(&local, &remote, 5001).mutation,
        ShadowMutation::Disable(_)
    ));
    assert!(local.next(&remote.list().unwrap(), 5002).unwrap().is_none());
    assert_eq!(remote.list().unwrap()[0].state, MirrorState::Disabled);
}
#[test]
fn expired_unknown_send_outcome_cannot_replay_activation() {
    let dir = directory();
    let local =
        Coordinator::open(&dir.path().join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    local
        .observe(local.revision().unwrap(), batch(edge(1), 10), 10)
        .unwrap();
    let pending = local.next(&[], 11).unwrap().unwrap();
    let lost = remote.apply(pending.mutation.clone()).unwrap();
    let retire = local.next(&remote.list().unwrap(), 1010).unwrap().unwrap();
    assert!(matches!(retire.mutation, ShadowMutation::Drain(_)));
    assert!(local.acknowledge(&pending, &lost, 1010).is_err());
    apply(&local, &remote, 1011);
    apply(&local, &remote, 1012);
    assert_eq!(remote.list().unwrap()[0].state, MirrorState::Disabled);
}
#[test]
fn splice_retires_old_context_before_registering_successor() {
    let dir = directory();
    let local =
        Coordinator::open(&dir.path().join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    let first = edge(1);
    local
        .observe(local.revision().unwrap(), batch(first.clone(), 10), 10)
        .unwrap();
    apply(&local, &remote, 11);
    let mut next = first.clone();
    next.funding_epoch += 1;
    next.funding_context_id = [92; 32];
    next.state_number = 1;
    next.edge_id = next.derive_id().unwrap();
    local
        .observe(local.revision().unwrap(), batch(next, 12), 12)
        .unwrap();
    assert!(matches!(
        apply(&local, &remote, 13).mutation,
        ShadowMutation::Drain(_)
    ));
    assert!(matches!(
        apply(&local, &remote, 14).mutation,
        ShadowMutation::Disable(_)
    ));
    let p = apply(&local, &remote, 15);
    let ShadowMutation::Register(r) = p.mutation else {
        panic!("register successor")
    };
    assert_eq!(r.expected_previous_edge_id, Some(hex32(&first.edge_id)));
    assert!(
        local
            .observe(local.revision().unwrap(), batch(first, 16), 16)
            .is_err()
    );
}
#[test]
fn unknown_provider_mirror_cannot_create_local_rights_or_liquidity() {
    let dir = directory();
    let local =
        Coordinator::open(&dir.path().join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    remote
        .apply(ShadowMutation::Register(RegisterExternalEdgeRequest {
            edge: FiberExternalEdge::try_from(&edge(1)).unwrap(),
            expected_previous_edge_id: None,
            callback_endpoint: CALLBACK.into(),
        }))
        .unwrap();
    assert!(matches!(
        apply(&local, &remote, 1).mutation,
        ShadowMutation::Drain(_)
    ));
    apply(&local, &remote, 2);
    let (_, stored) = local.snapshot().unwrap();
    assert!(stored.seen.is_empty());
    assert!(stored.observation.is_none());
    assert!(local.next(&remote.list().unwrap(), 3).unwrap().is_none());
}
#[test]
fn same_context_refresh_strict_ack_and_typed_outbox() {
    let dir = directory();
    let local =
        Coordinator::open(&dir.path().join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    let first = edge(1);
    local
        .observe(local.revision().unwrap(), batch(first.clone(), 1), 1)
        .unwrap();
    apply(&local, &remote, 2);
    let mut next = first.clone();
    next.state_number += 1;
    next.opaque_morph_commitment = [77; 32];
    next.directional_liquidity = [3, 4];
    local
        .observe(local.revision().unwrap(), batch(next, 3), 3)
        .unwrap();
    let pending = local.next(&remote.list().unwrap(), 4).unwrap().unwrap();
    assert!(matches!(pending.mutation, ShadowMutation::Update(_)));
    let good = remote.apply(pending.mutation.clone()).unwrap();
    let mut bad = good.clone();
    bad.forwarding = true;
    let revision = local.revision().unwrap();
    assert!(local.acknowledge(&pending, &bad, 5).is_err());
    assert_eq!(local.revision().unwrap(), revision);
    local.acknowledge(&pending, &good, 5).unwrap();
    assert!(
        local
            .observe(local.revision().unwrap(), batch(first, 6), 6)
            .is_err()
    );
    for row in local
        .store
        .history(
            morph_runtime_store::History::Outbox,
            &Default::default(),
            128,
        )
        .unwrap()
    {
        let event: EventEnvelope = serde_json::from_slice(row.body.bytes()).unwrap();
        event.validate().unwrap();
        assert_eq!(event.component, Component::Edge);
    }
    local.store.validate().unwrap();
}
#[test]
fn cas_configuration_ttl_and_clock_rollback_fail_closed() {
    let dir = directory();
    let path = dir.path().join("morph.db");
    let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    let revision = local.revision().unwrap();
    let observed = batch(edge(1), 100);
    local.observe(revision, observed.clone(), 100).unwrap();
    let mut later = observed.clone();
    later.observed_at_ms += 1;
    later.valid_until_ms += 1;
    assert!(local.observe(revision, later, 101).is_err());
    assert!(local.next(&[], 99).unwrap().is_none());
    assert!(local.next(&[], 100).unwrap().is_none());
    let before = local.revision().unwrap();
    assert!(matches!(
        local.observe(before, batch(edge(1), 99), 99),
        Err(CoordinatorError::Conflict)
    ));
    assert_eq!(local.revision().unwrap(), before);
    let mut wrong = observed;
    wrong.valid_until_ms = 100 + MAX_OBSERVATION_AGE_MS + 1;
    assert!(
        local
            .observe(local.revision().unwrap(), wrong, 100)
            .is_err()
    );
    assert!(Coordinator::open(&path, policy(), ENDPOINT, "http://127.0.0.1:9/other").is_err());
}

#[test]
fn restart_without_new_observation_quarantines_even_unexpired_activation() {
    let dir = directory();
    let path = dir.path().join("morph.db");
    let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    local
        .observe(local.revision().unwrap(), batch(edge(1), 10), 10)
        .unwrap();
    assert!(local.next(&[], 11).unwrap().is_some());
    drop(local);
    let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    local.observe(0, batch(edge(1), 10), 12).unwrap(); // cached receipt cannot satisfy boot validation
    assert!(local.next(&[], 12).unwrap().is_none());
    assert!(local.snapshot().unwrap().1.pending.is_none());
}
#[test]
fn stale_provider_revision_replans_without_resetting_local_evidence() {
    let dir = directory();
    let local =
        Coordinator::open(&dir.path().join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    let original = edge(1);
    local
        .observe(local.revision().unwrap(), batch(original.clone(), 1), 1)
        .unwrap();
    apply(&local, &remote, 2);
    let mut newest = original.clone();
    newest.state_number += 2;
    newest.opaque_morph_commitment = [82; 32];
    local
        .observe(local.revision().unwrap(), batch(newest, 3), 3)
        .unwrap();
    let old = local.next(&remote.list().unwrap(), 4).unwrap().unwrap();
    let mut middle = original;
    middle.state_number += 1;
    middle.opaque_morph_commitment = [81; 32];
    remote
        .apply(ShadowMutation::Update(UpdateExternalEdgeRequest {
            edge: FiberExternalEdge::try_from(&middle).unwrap(),
            expected_provider_revision: 1,
        }))
        .unwrap();
    let next = local.next(&remote.list().unwrap(), 5).unwrap().unwrap();
    assert_ne!(old.id, next.id);
    let ShadowMutation::Update(r) = &next.mutation else {
        panic!("update")
    };
    assert_eq!(r.expected_provider_revision, 2);
    let ack = remote.apply(next.mutation.clone()).unwrap();
    local.acknowledge(&next, &ack, 6).unwrap();
    assert_eq!(
        remote.list().unwrap()[0].opaque_morph_commitment,
        hex32(&[82; 32])
    );
}

#[test]
fn crash_child() {
    let Ok(root) = std::env::var("MORPH_SHADOW_CRASH_ROOT") else {
        return;
    };
    let stage = std::env::var("MORPH_SHADOW_CRASH_STAGE").unwrap();
    let root = Path::new(&root);
    let local = Coordinator::open(&root.join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&root.join("fiber.db"), policy()).unwrap();
    local
        .observe(local.revision().unwrap(), batch(edge(1), 100), 100)
        .unwrap();
    if stage != "observed" {
        let p = local.next(&[], 101).unwrap().unwrap();
        if stage != "queued" {
            let ack = remote.apply(p.mutation.clone()).unwrap();
            if stage == "acknowledged" {
                local.acknowledge(&p, &ack, 101).unwrap();
            }
        }
    }
    std::fs::write(root.join("ready"), b"committed").unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
#[test]
fn actual_process_kill_preserves_observation_intent_and_exact_replay() {
    for stage in ["observed", "queued", "applied", "acknowledged"] {
        let dir = directory();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "coordinator::tests::crash_child", "--nocapture"])
            .env("MORPH_SHADOW_CRASH_ROOT", dir.path())
            .env("MORPH_SHADOW_CRASH_STAGE", stage)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !dir.path().join("ready").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before boundary {stage}"
            );
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("child boundary timeout");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        let local =
            Coordinator::open(&dir.path().join("morph.db"), policy(), ENDPOINT, CALLBACK).unwrap();
        let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
        local
            .observe(local.revision().unwrap(), batch(edge(1), 102), 102)
            .unwrap();
        if let Some(p) = local.next(&remote.list().unwrap(), 103).unwrap() {
            let ack = remote.apply(p.mutation.clone()).unwrap();
            local.acknowledge(&p, &ack, 103).unwrap();
        }
        let edges = remote.list().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].provider_revision, 1);
        assert!(!edges[0].forwarding);
        local.store.validate().unwrap();
    }
}

#[tokio::test]
async fn real_http_lost_success_response_and_reopened_stores_reconcile_exactly() {
    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::post,
    };
    struct Server {
        path: std::path::PathBuf,
        lose: std::sync::atomic::AtomicBool,
    }
    async fn serve(State(server): State<Arc<Server>>, Json(request): Json<Value>) -> Response {
        // Reopen the real provider database for every request.
        let store = ShadowStore::open(&server.path, policy()).unwrap();
        let method = request["method"].as_str().unwrap();
        let argument = request["params"][0].clone();
        let value = store.dispatch(method, argument).unwrap();
        if method == REGISTER_EXTERNAL_EDGE_METHOD && server.lose.swap(false, Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response(); // committed, success reply lost
        }
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":value})).into_response()
    }
    let dir = directory();
    let server = Arc::new(Server {
        path: dir.path().join("fiber.db"),
        lose: std::sync::atomic::AtomicBool::new(true),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/", post(serve))
        .with_state(server.clone());
    let worker = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let path = dir.path().join("morph.db");
    let local = Coordinator::open(&path, policy(), &url, CALLBACK).unwrap();
    let client = FiberHookClient::new(&url, None, CALLBACK, policy()).unwrap();
    let now = wall_time_ms().unwrap();
    local
        .observe(local.revision().unwrap(), batch(edge(1), now), now)
        .unwrap();
    assert!(local.reconcile_once(&client).await.is_err());
    let pending = local.snapshot().unwrap().1.pending.unwrap();
    drop(local);
    let local = Coordinator::open(&path, policy(), &url, CALLBACK).unwrap();
    let now = (wall_time_ms().unwrap()).max(now + 1);
    local
        .observe(local.revision().unwrap(), batch(edge(1), now), now)
        .unwrap();
    let ack = local.reconcile_once(&client).await.unwrap().unwrap();
    assert_eq!(ack.provider_revision, 1);
    assert!(local.snapshot().unwrap().1.pending.is_none());
    assert!(
        local
            .store
            .intent(&format!("shadow-ack:{}", pending.id))
            .unwrap()
            .is_some()
    );
    assert!(local.reconcile_once(&client).await.unwrap().is_none());
    worker.abort();
}

#[test]
fn independent_connections_cas_one_winner_and_operator_drain_persists() {
    let dir = directory();
    let path = dir.path().join("morph.db");
    let initial = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    let revision = initial.revision().unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads = (1..=2)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
                barrier.wait();
                local
                    .observe(revision, batch(edge(1), 100 + index), 100 + index)
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
    let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    local
        .observe(local.revision().unwrap(), batch(edge(1), 105), 105)
        .unwrap();
    apply(&local, &remote, 106);
    let mut draining = batch(edge(1), 107);
    draining.edges[0].state = MirrorState::Draining;
    local
        .observe(local.revision().unwrap(), draining, 107)
        .unwrap();
    assert!(matches!(
        apply(&local, &remote, 108).mutation,
        ShadowMutation::Drain(_)
    ));
    assert!(local.next(&remote.list().unwrap(), 109).unwrap().is_none());
    assert_eq!(remote.list().unwrap()[0].state, MirrorState::Draining);
}

#[tokio::test]
async fn slow_capability_handshake_cannot_send_an_expired_activation() {
    use axum::{Json, Router, extract::State, routing::post};
    struct Server {
        path: std::path::PathBuf,
        capabilities: AtomicU64,
        expires: u64,
        mutations: AtomicU64,
    }
    async fn serve(State(server): State<Arc<Server>>, Json(request): Json<Value>) -> Json<Value> {
        let method = request["method"].as_str().unwrap();
        if method == CAPABILITIES_METHOD {
            if server.capabilities.fetch_add(1, Ordering::SeqCst) == 1 {
                // Deliberately let the lease expire during the mutation's
                // handshake, after its exact intent has already been persisted.
                let remaining = server.expires.saturating_sub(wall_time_ms().unwrap());
                tokio::time::sleep(Duration::from_millis(remaining + 10)).await;
            }
        } else if method != LIST_EXTERNAL_EDGES_METHOD {
            server.mutations.fetch_add(1, Ordering::SeqCst);
        }
        let store = ShadowStore::open(&server.path, policy()).unwrap();
        let result = store
            .dispatch(method, request["params"][0].clone())
            .unwrap();
        Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }
    let dir = directory();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let local = Coordinator::open(&dir.path().join("morph.db"), policy(), &url, CALLBACK).unwrap();
    let client = FiberHookClient::new(&url, None, CALLBACK, policy()).unwrap();
    let now = wall_time_ms().unwrap();
    let observed = batch(edge(1), now);
    let server = Arc::new(Server {
        path: dir.path().join("fiber.db"),
        capabilities: AtomicU64::new(0),
        expires: observed.valid_until_ms,
        mutations: AtomicU64::new(0),
    });
    let app = Router::new()
        .route("/", post(serve))
        .with_state(server.clone());
    let worker = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    local
        .observe(local.revision().unwrap(), observed, now)
        .unwrap();
    assert!(local.reconcile_once(&client).await.unwrap().is_none());
    assert_eq!(server.capabilities.load(Ordering::SeqCst), 2);
    assert_eq!(server.mutations.load(Ordering::SeqCst), 0);
    assert!(local.snapshot().unwrap().1.pending.is_none());
    assert!(
        ShadowStore::open(&server.path, policy())
            .unwrap()
            .list()
            .unwrap()
            .is_empty()
    );
    worker.abort();
}

#[test]
fn owner_binding_and_invalidation_survive_reopen_without_new_authority() {
    let dir = directory();
    let path = dir.path().join("morph.db");
    let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    let owner = hex32(&[17; 32]);
    local.bind_owner(&owner).unwrap();
    local.bind_owner(&owner).unwrap();
    assert!(local.bind_owner(&hex32(&[18; 32])).is_err());
    let original = batch(edge(1), 100);
    local
        .observe(local.revision().unwrap(), original.clone(), 100)
        .unwrap();
    let pending = local.next(&[], 101).unwrap().unwrap();
    local.invalidate(99).unwrap(); // failure/clock regression cannot prevent revocation
    let revision = local.revision().unwrap();
    local.invalidate(98).unwrap();
    assert_eq!(local.revision().unwrap(), revision);
    let status = Coordinator::probe(&path, &owner).unwrap();
    assert_eq!(status, (local.identity(), revision));
    assert!(Coordinator::probe(&path, &hex32(&[18; 32])).is_err());
    drop(local);
    let local = Coordinator::open(&path, policy(), ENDPOINT, CALLBACK).unwrap();
    local.observe(0, original, 102).unwrap(); // historical receipt, not renewal
    assert!(local.next(&[], 102).unwrap().is_none());
    let remote = ShadowStore::open(&dir.path().join("fiber.db"), policy()).unwrap();
    let ack = remote.apply(pending.mutation.clone()).unwrap();
    assert!(local.acknowledge(&pending, &ack, 103).is_err());
    assert!(matches!(
        apply(&local, &remote, 104).mutation,
        ShadowMutation::Drain(_)
    ));
    assert!(matches!(
        apply(&local, &remote, 105).mutation,
        ShadowMutation::Disable(_)
    ));
}
