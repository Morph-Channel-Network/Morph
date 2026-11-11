//! Kill the actual HTTP service process, retaining its encrypted database and
//! an independently running controlled Fiber endpoint. Hooks are test-only.
use super::*;
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

const CHILD: &str = "service::tests::process_faults::gateway_process_child";
const DIRECTORY: &str = "MORPH_TEST_GATEWAY_PROCESS_DIRECTORY";
const CUT: &str = "MORPH_TEST_GATEWAY_PROCESS_CUT";

pub(in crate::service) async fn checkpoint(name: &str) {
    if std::env::var(CUT).ok().as_deref() != Some(name) {
        return;
    }
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    std::fs::write(directory.join("checkpoint"), name).unwrap();
    // Parent must kill the process. No simulated error or graceful shutdown.
    std::future::pending::<()>().await;
}

struct ServiceChild(Child);
impl Drop for ServiceChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl ServiceChild {
    fn spawn(directory: &Path, cut: &str) -> Self {
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD, "--nocapture"])
                .env(DIRECTORY, directory)
                .env(CUT, cut)
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    async fn wait_file(&mut self, path: &Path) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(value) = std::fs::read_to_string(path)
                && !value.is_empty()
            {
                return value;
            }
            assert!(self.0.try_wait().unwrap().is_none(), "child exited early");
            assert!(Instant::now() < deadline, "child checkpoint timed out");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn kill_and_reap(&mut self) {
        use std::os::unix::process::ExitStatusExt;
        self.0.kill().unwrap();
        assert_eq!(self.0.wait().unwrap().signal(), Some(9));
    }
}

#[tokio::test]
async fn gateway_process_child() {
    let Some(directory) = std::env::var_os(DIRECTORY) else {
        return;
    };
    let directory = PathBuf::from(directory);
    let request: PayRequest =
        serde_json::from_slice(&std::fs::read(directory.join("request.json")).unwrap()).unwrap();
    let credentials = CredentialService::from_private_key(
        &std::fs::read_to_string(directory.join("credential.key")).unwrap(),
    )
    .unwrap();
    let fiber = FiberRpcClient::new(
        &std::fs::read_to_string(directory.join("provider")).unwrap(),
        None,
    )
    .unwrap();
    let store = Arc::new(
        DurableStore::open(
            directory.join("private/payment-gateway.db"),
            credentials.store_key(),
        )
        .unwrap(),
    );
    let service = Arc::new(
        PaymentGatewayService::new(
            PaymentGatewayConfig {
                fiber_identity: None,
                payee: request.requirements.payee.clone(),
                outgoing_payer: Some(request.payload.payer.clone()),
                outgoing_max_fee_amount: Some(5),
                outgoing_payment_timeout_seconds: 60,
                currency: "Fibd".into(),
                supported_assets: vec![request.requirements.asset.clone()],
                verified_rgbpp_proof_commitments: BTreeSet::new(),
                default_credential_ttl_seconds: 600,
                upstream_base_url: None,
                api_bearer_token: None,
            },
            fiber,
            store,
            credentials,
            SigningKey::from_slice(&[3; 32]).unwrap(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    std::fs::write(
        directory.join("ready"),
        format!("http://{}/v1/pay", listener.local_addr().unwrap()),
    )
    .unwrap();
    axum::serve(listener, service.router()).await.unwrap();
}

#[tokio::test]
async fn real_service_kills_reservation_provider_acceptance_and_terminal_reply_never_resend() {
    for (cut, failed) in [
        ("reserved", false),
        ("provider-lost-reply", false),
        ("provider-accepted", false),
        ("provider-accepted", true),
        ("terminal-persisted", false),
        ("terminal-persisted", true),
    ] {
        let (service, dir, provider, request) = outgoing_retry_fixture().await;
        {
            let mut state = provider.lock().unwrap();
            state.hold_send_reply = cut == "provider-lost-reply";
            state.fail_payment = failed;
        }
        let directory = dir.path();
        std::fs::write(
            directory.join("request.json"),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("provider"), service.fiber.endpoint()).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("credential.key"))
            .unwrap()
            .write_all(service.credentials.private_key().as_bytes())
            .unwrap();
        let credentials = service.credentials.clone();
        let endpoint = service.fiber.endpoint().to_owned();
        drop(service);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(25))
            .build()
            .unwrap();
        let mut child = ServiceChild::spawn(directory, cut);
        let url = child.wait_file(&directory.join("ready")).await;
        let pending_client = client.clone();
        let pending_request = request.clone();
        let pending =
            tokio::spawn(
                async move { pending_client.post(url).json(&pending_request).send().await },
            );
        if cut == "provider-lost-reply" {
            let deadline = Instant::now() + Duration::from_secs(20);
            while provider.lock().unwrap().send_count == 0 {
                assert!(child.0.try_wait().unwrap().is_none());
                assert!(Instant::now() < deadline, "provider did not accept payment");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } else {
            assert_eq!(child.wait_file(&directory.join("checkpoint")).await, cut);
        }
        let expected_sends = usize::from(cut != "reserved");
        assert_eq!(provider.lock().unwrap().send_count, expected_sends);
        child.kill_and_reap();
        assert!(
            pending.await.unwrap().is_err(),
            "reply escaped kill barrier"
        );
        drop(child);

        let store = DurableStore::open(
            directory.join("private/payment-gateway.db"),
            credentials.store_key(),
        )
        .unwrap();
        let before = store.outgoing(&request, &endpoint).unwrap().unwrap();
        assert_eq!(before.response.is_some(), cut == "terminal-persisted");
        drop(store);
        // A terminal replay must work even with an unavailable provider.
        provider.lock().unwrap().get_payment_error = cut == "terminal-persisted";
        let polls_before = provider.lock().unwrap().payment_poll_count;
        std::fs::remove_file(directory.join("ready")).unwrap();
        let mut restarted = ServiceChild::spawn(directory, "none");
        let url = restarted.wait_file(&directory.join("ready")).await;
        let mut previous = None;
        for _ in 0..2 {
            let response = client.post(&url).json(&request).send().await.unwrap();
            if cut == "reserved" {
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response.json::<GatewayErrorBody>().await.unwrap().code,
                    GatewayErrorCode::PaymentOutcomeUnknown
                );
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                let response: Value = response.json().await.unwrap();
                assert_eq!(response["completed"], !failed);
                assert_eq!(
                    response["fiber_result"]["status"],
                    if failed { "Failed" } else { "Success" }
                );
                assert_eq!(response["payment_hash"], request.requirements.payment_hash);
                if let Some(original) = &before.response {
                    assert_eq!(response, serde_json::to_value(original).unwrap());
                }
                if let Some(original) = &previous {
                    assert_eq!(&response, original);
                }
                previous = Some(response);
            }
            assert_eq!(provider.lock().unwrap().send_count, expected_sends);
        }
        if cut == "terminal-persisted" {
            assert_eq!(provider.lock().unwrap().payment_poll_count, polls_before);
        }
        let mut conflict = request.clone();
        conflict.timeout_seconds = Some(1);
        let response = client.post(&url).json(&conflict).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.json::<GatewayErrorBody>().await.unwrap().code,
            GatewayErrorCode::RequestConflict
        );
        assert_eq!(provider.lock().unwrap().send_count, expected_sends);
        restarted.kill_and_reap();
        let store = DurableStore::open(
            directory.join("private/payment-gateway.db"),
            credentials.store_key(),
        )
        .unwrap();
        let after = store.outgoing(&request, &endpoint).unwrap().unwrap();
        assert_eq!(after.response.is_some(), cut != "reserved");
        assert_eq!(after.submission, before.submission);
        assert_eq!(after.timeout_seconds, before.timeout_seconds);
        assert_eq!(after.created_at, before.created_at);
        eprintln!(
            "Gateway service SIGKILL/restart passed: {cut}; failed={failed}; sends={expected_sends}"
        );
    }
}
