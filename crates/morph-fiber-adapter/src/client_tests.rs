use super::*;
use crate::tests::{capabilities, edge, policy};
use axum::{Json, Router, extract::State, routing::post};
use std::sync::Mutex;

struct Peer {
    caps: Value,
    error: Option<Value>,
    list: Value,
    methods: Vec<String>,
}
async fn serve(State(state): State<Arc<Mutex<Peer>>>, Json(request): Json<Value>) -> Json<Value> {
    let mut peer = state.lock().unwrap();
    let method = request["method"].as_str().unwrap();
    peer.methods.push(method.into());
    let id = request["id"].clone();
    if let Some(error) = &peer.error {
        return Json(json!({"jsonrpc":"2.0", "id":id, "error":error}));
    }
    let result = match method {
        CAPABILITIES_METHOD => peer.caps.clone(),
        LIST_EXTERNAL_EDGES_METHOD => peer.list.clone(),
        DRAIN_EXTERNAL_EDGE_METHOD | DISABLE_EXTERNAL_EDGE_METHOD => json!({
            "morph_edge_id":request["params"][0]["morph_edge_id"], "provider_revision":"2",
            "state":if method == DRAIN_EXTERNAL_EDGE_METHOD { "draining" } else { "disabled" },
            "forwarding":false, "opaque_morph_commitment":hex32(&[10;32])
        }),
        _ => json!({ "morph_edge_id":request["params"][0]["edge"]["morph_edge_id"],
            "provider_revision":"1", "state":"active", "forwarding":false,
            "opaque_morph_commitment":request["params"][0]["edge"]["opaque_morph_commitment"] }),
    };
    Json(json!({"jsonrpc":"2.0", "id":id, "result":result}))
}
async fn peer() -> (
    FiberHookClient,
    Arc<Mutex<Peer>>,
    tokio::task::JoinHandle<()>,
) {
    let state = Arc::new(Mutex::new(Peer {
        caps: serde_json::to_value(capabilities()).unwrap(),
        error: None,
        list: json!([]),
        methods: vec![],
    }));
    let app = Router::new()
        .route("/", post(serve))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = FiberHookClient::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        None,
        "http://127.0.0.1:4621/callback",
        policy(),
    )
    .unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (client, state, task)
}

#[tokio::test]
async fn incompatible_handshake_never_sends_a_mutation() {
    let (client, state, task) = peer().await;
    for (field, value) in [
        ("forwarding", json!(true)),
        ("profile", json!("native-funding")),
        ("fiber_commit", json!("1".repeat(40))),
        ("patch_hash", json!(hex32(&[99; 32]))),
        ("ckb_genesis_hash", json!(hex32(&[99; 32]))),
        ("max_edges", json!("129")),
        ("max_edges", json!("0")),
        ("max_edges", json!(128)),
        ("extra", json!(true)),
    ] {
        {
            let mut peer = state.lock().unwrap();
            peer.caps = serde_json::to_value(capabilities()).unwrap();
            peer.caps[field] = value;
            peer.methods.clear();
        }
        assert!(
            client.register_edge(&edge(1), None).await.is_err(),
            "{field}"
        );
        assert_eq!(state.lock().unwrap().methods, [CAPABILITIES_METHOD]);
    }
    task.abort();
}

#[tokio::test]
async fn missing_hook_is_explicit_and_remote_error_body_never_escapes() {
    let (client, state, task) = peer().await;
    state.lock().unwrap().error = Some(json!({"code":-32601,"message":"private-marker"}));
    assert!(matches!(
        client.list_edges().await,
        Err(AdapterError::HookUnavailable)
    ));
    state.lock().unwrap().error =
        Some(json!({"code":-32000,"message":"private-marker","data":"private-marker"}));
    let error = client.list_edges().await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-marker"));
    assert_eq!(
        state.lock().unwrap().methods,
        [CAPABILITIES_METHOD, CAPABILITIES_METHOD]
    );
    task.abort();
}

#[tokio::test]
async fn capability_is_not_cached_across_operations_and_drain_is_distinct() {
    let (client, state, task) = peer().await;
    let edge = edge(1);
    client.register_edge(&edge, None).await.unwrap();
    assert_eq!(
        client
            .drain_edge(edge.edge_id, 1, "retiring".into())
            .await
            .unwrap()
            .state,
        MirrorState::Draining
    );
    state.lock().unwrap().caps["forwarding"] = json!(true);
    assert!(matches!(
        client.disable_edge(edge.edge_id, 1, "retired".into()).await,
        Err(AdapterError::HookMismatch)
    ));
    assert_eq!(
        state.lock().unwrap().methods,
        [
            CAPABILITIES_METHOD,
            REGISTER_EXTERNAL_EDGE_METHOD,
            CAPABILITIES_METHOD,
            DRAIN_EXTERNAL_EDGE_METHOD,
            CAPABILITIES_METHOD
        ]
    );
    task.abort();
}

#[tokio::test]
async fn list_rejects_forwarding_duplicates_zero_revisions_and_over_capacity() {
    let (client, state, task) = peer().await;
    let edge = edge(1);
    let mirrored = json!({"channel_id":hex32(&edge.channel_id),"morph_edge_id":hex32(&edge.edge_id),
        "funding_context_id":hex32(&edge.funding_context_id),"provider_revision":"1","funding_epoch":"0","state":"active",
        "forwarding":false,"opaque_morph_commitment":hex32(&edge.opaque_morph_commitment)});
    state.lock().unwrap().list = json!([mirrored]);
    assert_eq!(client.list_edges().await.unwrap().len(), 1);
    let mut live = mirrored.clone();
    live["forwarding"] = json!(true);
    let mut zero = mirrored.clone();
    zero["provider_revision"] = json!("0");
    for invalid in [
        json!([live]),
        json!([zero]),
        json!([mirrored, mirrored]),
        json!(vec![mirrored; 129]),
    ] {
        state.lock().unwrap().list = invalid;
        assert!(client.list_edges().await.is_err());
    }
    task.abort();
}

#[test]
fn retire_unknown_context_precedes_successor_even_when_hash_sorts_after_it() {
    let mut local = edge(1);
    local.funding_epoch = 1;
    local.edge_id = local.derive_id().unwrap();
    let old = MirroredFiberEdge {
        funding_epoch: 0,
        channel_id: hex32(&local.channel_id),
        morph_edge_id: hex32(&[255; 32]),
        funding_context_id: hex32(&[99; 32]),
        provider_revision: 4,
        state: MirrorState::Draining,
        forwarding: false,
        opaque_morph_commitment: hex32(&[98; 32]),
    };
    assert_eq!(
        reconciliation_plan(std::slice::from_ref(&local), &[old]).unwrap(),
        vec![
            ReconcileAction::DisableUnknown {
                edge_id: [255; 32],
                expected_provider_revision: 4
            },
            ReconcileAction::Register {
                edge_id: local.edge_id,
                expected_previous_edge_id: Some([255; 32]),
            },
        ]
    );
}

#[test]
fn credentials_queries_and_fragments_are_not_transport_configuration() {
    for url in [
        "https://user:secret@fiber.example.com/",
        "https://fiber.example.com/?secret=x",
        "https://fiber.example.com/#token",
    ] {
        assert!(parse_http_url(url).is_err());
    }
}
