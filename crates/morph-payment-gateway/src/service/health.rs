//! Bounded observations of actual configured dependencies; never authorization.
use super::*;
use crate::store::StoreObservation;
use morph_observability::metrics::{Metrics, Operation, Outcome};
use morph_observability::{
    Dependency, Observation, Readiness, Reason, Scope, ScopeReadiness, Service,
};
use std::time::{SystemTime, UNIX_EPOCH};

const PROBE_MS: u64 = 2_000;

/// Explicit provider-reported identity pins. A matching node_info response is
/// not a signature or an independent CKB deployment/chain-finality proof.
#[derive(Clone)]
pub struct FiberIdentity {
    pubkey: String,
    chain_hash: String,
}
impl FiberIdentity {
    pub fn new(pubkey: &str, chain_hash: &str) -> Result<Self, ServiceError> {
        let valid_hex = |value: &str, bytes: usize| {
            value.len() == 2 + 2 * bytes
                && value.starts_with("0x")
                && value[2..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if pubkey.len() != 66
            || !pubkey
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !valid_hex(chain_hash, 32)
            || hex::decode(pubkey)
                .ok()
                .and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok())
                .is_none()
            || decode_byte32(chain_hash).is_err()
            || chain_hash == hex32(&[0; 32])
        {
            return Err(ServiceError::InvalidRequest(
                "invalid Fiber identity pins".into(),
            ));
        }
        Ok(Self {
            pubkey: pubkey.into(),
            chain_hash: chain_hash.into(),
        })
    }
    fn assess(&self, value: &Value) -> Reason {
        let Some(key) = value.get("pubkey").and_then(Value::as_str) else {
            return Reason::Unverified;
        };
        let Some(chain) = value.get("chain_hash").and_then(Value::as_str) else {
            return Reason::Unverified;
        };
        if Self::new(key, chain).is_err() {
            return Reason::Unverified;
        }
        if chain != self.chain_hash {
            Reason::WrongNetwork
        } else if key != self.pubkey {
            Reason::ProviderMismatch
        } else {
            Reason::Verified
        }
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| d.as_millis().try_into().ok())
        .unwrap_or(0)
}
struct Probe {
    store: Result<StoreObservation, Reason>,
    provider: Reason,
}
fn report(probe: &Probe, outgoing: bool, start: u64, end: u64, elapsed: Duration) -> Readiness {
    let observation = |dependency, reason| Observation {
        dependency,
        reason: if start == 0 || end < start {
            Reason::ClockInvalid
        } else if elapsed >= Duration::from_millis(PROBE_MS) {
            Reason::Stale
        } else {
            reason
        },
        checked_at_ms: start,
        valid_until_ms: start.saturating_add(PROBE_MS),
    };
    let store = observation(
        Dependency::Store,
        probe
            .store
            .as_ref()
            .map(|_| Reason::Verified)
            .unwrap_or_else(|e| *e),
    );
    let capacity = |predicate: fn(&StoreObservation) -> bool| {
        observation(
            Dependency::Capacity,
            probe
                .store
                .as_ref()
                .map(|s| {
                    if predicate(s) {
                        Reason::Verified
                    } else {
                        Reason::CapacityExhausted
                    }
                })
                .unwrap_or(Reason::Unverified),
        )
    };
    let provider = observation(Dependency::ProviderIdentity, probe.provider);
    Readiness::new(
        Service::Gateway,
        end,
        vec![
            ScopeReadiness::evaluate(
                Scope::LocalRegistry,
                true,
                &[Dependency::Store, Dependency::Capacity],
                &[store, capacity(|s| s.general_capacity)],
                end,
            ),
            ScopeReadiness::evaluate(
                Scope::InvoiceIssuance,
                true,
                &[
                    Dependency::Store,
                    Dependency::Capacity,
                    Dependency::ProviderIdentity,
                ],
                &[store, capacity(|s| s.invoice_capacity), provider],
                end,
            ),
            ScopeReadiness::evaluate(
                Scope::PaymentSubmission,
                outgoing,
                &[
                    Dependency::Store,
                    Dependency::Capacity,
                    Dependency::ProviderIdentity,
                ],
                &[store, capacity(|s| s.payment_capacity), provider],
                end,
            ),
            ScopeReadiness::unsupported(Scope::ChannelSigning),
            ScopeReadiness::unsupported(Scope::ChainPublication),
            ScopeReadiness::unsupported(Scope::EventDispatch),
        ],
    )
}
fn spawn_store_probe(
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    probe: impl FnOnce() -> Result<StoreObservation, Reason> + Send + 'static,
) -> tokio::task::JoinHandle<Result<StoreObservation, Reason>> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        probe()
    })
}
async fn observe(service: &PaymentGatewayService) -> (Readiness, Option<StoreObservation>) {
    let start = now_ms();
    let started = Instant::now();
    let probe = match service.health_permit.clone().try_acquire_owned() {
        Err(_) => Probe {
            store: Err(Reason::Busy),
            provider: Reason::Unverified,
        },
        Ok(permit) => {
            let permit = Arc::new(permit);
            let source = service.store.probe_source();
            let store_permit = permit.clone();
            // The blocking task keeps the permit after timeout. A stuck disk
            // cannot cause each scrape to create another background task.
            let store_task = spawn_store_probe(store_permit, move || source.observe(start));
            let provider = async {
                let Some(identity) = service.config.fiber_identity.as_ref() else {
                    return Reason::NotConfigured;
                };
                match service.fiber.node_info().await {
                    Ok(value) => identity.assess(&value),
                    Err(_) => Reason::Unavailable,
                }
            };
            let result = tokio::time::timeout(Duration::from_millis(PROBE_MS), async {
                let (store, provider) = tokio::join!(store_task, provider);
                Probe {
                    store: store.unwrap_or(Err(Reason::Unavailable)),
                    provider,
                }
            })
            .await;
            drop(permit);
            result.unwrap_or(Probe {
                store: Err(Reason::Stale),
                provider: Reason::Stale,
            })
        }
    };
    let result = report(
        &probe,
        service.config.outgoing_payer.is_some(),
        start,
        now_ms(),
        started.elapsed(),
    );
    let data = if result
        .scopes
        .iter()
        .flat_map(|s| &s.checks)
        .any(|c| c.dependency == Dependency::Store && c.reason == Reason::Verified)
    {
        probe.store.ok()
    } else {
        None
    };
    (result, data)
}
pub(super) async fn readiness(
    State(service): State<Arc<PaymentGatewayService>>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    service.require_api_bearer(&headers)?;
    let (report, _) = observe(&service).await;
    Ok((
        if report.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CACHE_CONTROL, "no-store")],
        Json(report),
    )
        .into_response())
}
fn store_metrics(data: Option<&StoreObservation>) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    let gauges: [(&str, Option<u64>); 10] = [
        ("store_revision", data.map(|s| s.revision)),
        ("challenges", data.map(|s| s.challenges as u64)),
        ("receipts", data.map(|s| s.receipts as u64)),
        ("offers", data.map(|s| s.offers as u64)),
        ("outgoing", data.map(|s| s.outgoing as u64)),
        ("unresolved_outgoing", data.map(|s| s.unresolved as u64)),
        (
            "overdue_unresolved_outgoing",
            data.map(|s| s.overdue_unresolved as u64),
        ),
        (
            "oldest_unresolved_age_ms",
            data.map(|s| s.oldest_unresolved_age_ms),
        ),
        ("history_rows", data.map(|s| s.history_rows)),
        ("payload_bytes", data.map(|s| s.payload_bytes)),
    ];
    for (name, value) in gauges {
        let _ = writeln!(
            text,
            "# TYPE morph_gateway_{name} gauge\nmorph_gateway_{name} {}",
            value.map(|v| v.to_string()).unwrap_or_else(|| "NaN".into())
        );
    }
    // Non-evicting authority records supply lifetime counts. Never count the
    // bounded payment display, provider strings, HTTP retries or successful sends.
    for (name, value) in [
        ("outgoing_reserved_total", data.map(|s| s.outgoing as u64)),
        (
            "outgoing_succeeded_total",
            data.map(|s| s.outgoing_succeeded as u64),
        ),
        (
            "outgoing_failed_total",
            data.map(|s| s.outgoing_failed as u64),
        ),
        ("receipts_issued_total", data.map(|s| s.receipts as u64)),
    ] {
        let _ = writeln!(
            text,
            "# TYPE morph_gateway_{name} counter\nmorph_gateway_{name} {}",
            value.map(|v| v.to_string()).unwrap_or_else(|| "NaN".into())
        );
    }
    text
}
pub(super) async fn metrics(
    State(service): State<Arc<PaymentGatewayService>>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    service.require_api_bearer(&headers)?;
    let (report, data) = observe(&service).await;
    let text = service.metrics.render(&report) + &store_metrics(data.as_ref());
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        text,
    )
        .into_response())
}
pub(super) async fn measure(
    State(metrics): State<Arc<Metrics>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Fixed classes only; never interpolate captured paths, IDs, or URLs.
    let operation = match request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
    {
        Some("/ready" | "/metrics" | "/v1/events") => Operation::Observe,
        Some("/health" | "/v1/supported" | "/v1/payments") => Operation::Read,
        Some("/v1/challenges" | "/v1/x402/challenge" | "/v1/fair-exchange/offers") => {
            Operation::Invoice
        }
        Some(
            "/v1/pay"
            | "/v1/x402/verify"
            | "/v1/x402/settle"
            | "/v1/payment-gateway/authorize"
            | "/v1/fair-exchange/claims"
            | "/v1/credentials/verify"
            | "/gateway/{*path}",
        ) => Operation::Registry,
        _ => Operation::Unknown,
    };
    let timer = metrics.begin(operation);
    let response = next.run(request).await;
    timer.finish(Outcome::http(response.status().as_u16()));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> FiberIdentity {
        FiberIdentity::new(
            &hex::encode(
                SigningKey::from_slice(&[5; 32])
                    .unwrap()
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes(),
            ),
            &hex32(&[9; 32]),
        )
        .unwrap()
    }
    fn observation() -> StoreObservation {
        StoreObservation {
            revision: 1,
            challenges: 0,
            receipts: 0,
            offers: 0,
            outgoing: 0,
            unresolved: 0,
            overdue_unresolved: 0,
            outgoing_succeeded: 0,
            outgoing_failed: 0,
            oldest_unresolved_age_ms: 0,
            history_rows: 2,
            payload_bytes: 100,
            general_capacity: true,
            invoice_capacity: true,
            payment_capacity: true,
        }
    }
    #[test]
    fn provider_identity_requires_exact_current_fiber_encoding_and_both_pins() {
        let expected = identity();
        assert_eq!(
            expected.assess(&json!({"pubkey":expected.pubkey,"chain_hash":expected.chain_hash})),
            Reason::Verified
        );
        assert_eq!(
            expected.assess(&json!({"pubkey":expected.pubkey,"chain_hash":hex32(&[8;32])})),
            Reason::WrongNetwork
        );
        let other = hex::encode(
            SigningKey::from_slice(&[6; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes(),
        );
        assert_eq!(
            expected.assess(&json!({"pubkey":other,"chain_hash":expected.chain_hash})),
            Reason::ProviderMismatch
        );
        assert_eq!(
            expected.assess(&json!({"pubkey":expected.pubkey})),
            Reason::Unverified
        );
        assert!(
            FiberIdentity::new(&format!("0x{}", expected.pubkey), &expected.chain_hash).is_err()
        );
        assert!(FiberIdentity::new(&expected.pubkey.to_uppercase(), &expected.chain_hash).is_err());
        assert!(FiberIdentity::new(&expected.pubkey, &hex32(&[0; 32])).is_err());
    }
    #[test]
    fn elapsed_probe_capacity_and_disabled_scopes_never_overstate_readiness() {
        let mut probe = Probe {
            store: Ok(observation()),
            provider: Reason::Verified,
        };
        let assess = |probe: &Probe, outgoing, end, elapsed| {
            report(probe, outgoing, 1000, end, Duration::from_millis(elapsed))
        };
        assert!(assess(&probe, true, 1100, 100).ready);
        assert!(!assess(&probe, true, 1100, 2000).ready);
        assert!(!assess(&probe, true, 999, 100).ready);
        assert!(!assess(&probe, true, 3000, 100).ready);
        probe.store.as_mut().unwrap().payment_capacity = false;
        assert!(!assess(&probe, true, 1100, 100).ready);
        let report = assess(&probe, false, 1100, 100);
        assert!(report.ready && report.consistent());
        assert!(
            !report
                .scopes
                .iter()
                .find(|s| s.scope == Scope::PaymentSubmission)
                .unwrap()
                .configured
        );
        probe.provider = Reason::NotConfigured;
        assert!(!assess(&probe, false, 1100, 100).ready);
        assert_eq!(
            store_metrics(None)
                .lines()
                .filter(|s| s.ends_with("NaN"))
                .count(),
            14
        );
    }

    #[tokio::test]
    async fn cancelled_scrape_does_not_release_a_still_running_store_probe() {
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::new(gate.clone().acquire_owned().await.unwrap());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let task = spawn_store_probe(permit.clone(), move || {
            started_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
            Ok(observation())
        });
        started_rx.await.unwrap();
        drop(permit);
        task.abort();
        assert!(gate.clone().try_acquire_owned().is_err());
        finish_tx.send(()).unwrap();
        let _ = task.await;
        assert_eq!(gate.available_permits(), 1);
    }

    #[tokio::test]
    async fn actual_gateway_http_probes_are_authenticated_readonly_and_detect_replacement() {
        let (mut service, dir) = super::super::tests::test_service(None).await;
        let bearer = "h".repeat(32);
        let raw = Arc::get_mut(&mut service).unwrap();
        raw.api_bearer_token_hash = Some(blake2b256(bearer.as_bytes()));
        // No pins: local storage can be ready while Fiber-dependent scopes are not.
        let app = service.clone().router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let plain = crate::PaymentGatewayClient::new(&url).unwrap();
        assert!(matches!(
            plain.readiness().await,
            Err(crate::PaymentGatewayClientError::Http { status: 401, .. })
        ));
        let client = plain.with_bearer_token(bearer).unwrap();
        let path = dir.path().join("private/payment-gateway.db");
        let before = std::fs::read(&path).unwrap();
        let report = client.readiness().await.unwrap();
        assert!(!report.ready && report.consistent());
        assert!(
            report
                .scopes
                .iter()
                .any(|s| s.scope == Scope::LocalRegistry && s.ready)
        );
        let text = client.metrics().await.unwrap();
        assert_eq!(
            text.lines()
                .filter(|s| !s.starts_with('#') && !s.is_empty())
                .count(),
            147
        );
        assert!(text.contains("morph_gateway_store_revision 1"));
        assert!(!text.contains(&dir.path().to_string_lossy().to_string()));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Holding the sole permit gives a bounded Busy report and does not
        // block liveness or enqueue more blocking probes.
        let permit = service.health_permit.clone().acquire_owned().await.unwrap();
        let busy = client.readiness().await.unwrap();
        assert!(
            busy.scopes
                .iter()
                .flat_map(|s| &s.checks)
                .any(|c| c.reason == Reason::Busy)
        );
        assert!(
            reqwest::get(format!("{url}/health"))
                .await
                .unwrap()
                .status()
                .is_success()
        );
        drop(permit);
        let replacement = dir.path().join("private/replacement.db");
        let _other = DurableStore::open(&replacement, service.credentials.store_key()).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let report = client.readiness().await.unwrap();
        assert!(!report.ready);
        assert!(
            report
                .scopes
                .iter()
                .flat_map(|s| &s.checks)
                .any(|c| c.reason == Reason::RevisionChanged)
        );
        server.abort();
    }

    #[tokio::test]
    async fn real_provider_probe_uses_empty_params_and_times_out_without_blocking_health() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let expected = identity();
        let reply = json!({"pubkey":expected.pubkey,"chain_hash":expected.chain_hash});
        let hang = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let h = hang.clone();
        let c = calls.clone();
        let app = Router::new().route(
            "/",
            axum::routing::post(move |Json(request): Json<Value>| {
                let h = h.clone();
                let c = c.clone();
                let reply = reply.clone();
                async move {
                    assert_eq!(request["method"], "node_info");
                    assert_eq!(request["params"], json!([]));
                    c.fetch_add(1, Ordering::SeqCst);
                    if h.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":reply}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (mut service, _dir) = super::super::tests::test_service(None).await;
        let raw = Arc::get_mut(&mut service).unwrap();
        raw.config.fiber_identity = Some(expected);
        raw.fiber = FiberRpcClient::new(&url, None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_url = format!("http://{}", listener.local_addr().unwrap());
        let gateway_app = service.clone().router();
        let gateway_server = tokio::spawn(async move {
            axum::serve(listener, gateway_app).await.unwrap();
        });
        let client = crate::PaymentGatewayClient::new(&gateway_url).unwrap();
        let ready = client.readiness().await.unwrap();
        assert!(ready.ready && ready.consistent());
        hang.store(true, Ordering::SeqCst);
        let copy = service.clone();
        let task = tokio::spawn(async move { observe(&copy).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (busy, _) = observe(&service).await;
        assert!(!busy.ready);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            reqwest::get(format!("{gateway_url}/health"))
                .await
                .unwrap()
                .status()
                .is_success()
        );
        let (expired, data) = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(!expired.ready && data.is_none());
        assert!(
            expired
                .scopes
                .iter()
                .flat_map(|s| &s.checks)
                .any(|c| c.reason == Reason::Stale)
        );
        assert_eq!(service.health_permit.available_permits(), 1);
        gateway_server.abort();
        server.abort();
    }
}
