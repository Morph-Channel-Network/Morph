use morph_sdk::{HubClient, HubClientError, api::ConnectPeerRequest};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

fn serve(response: Vec<u8>) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&bytes[..end]);
                let len = head
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + len {
                    break;
                }
            }
        }
        stream.write_all(&response).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, handle)
}
#[test]
fn endpoints_and_ids_fail_closed() {
    for url in [
        "http://example.com",
        "http://127.0.0.1.evil.test",
        "http://user:secret@localhost",
        "http://127.0.0.1/path",
        "https://hub.test?token=secret",
        "file:///tmp/hub",
    ] {
        assert!(HubClient::new(url).is_err(), "{url}");
    }
    for url in [
        "http://127.0.0.2:4617",
        "http://[::1]:4617",
        "https://hub.example",
    ] {
        assert!(HubClient::new(url).is_ok(), "{url}");
    }
}

#[tokio::test]
async fn readiness_preserves_typed_503_reports_and_rejects_status_contradictions() {
    for (status, ready, service, valid) in [
        (503, false, "hub", true),
        (200, true, "hub", true),
        (200, false, "hub", false),
        (503, true, "hub", false),
        (200, true, "gateway", false),
    ] {
        let body =
            serde_json::json!({"service":service,"ready":ready,"generated_at_ms":"100","scopes":[{"scope":"local_registry","configured":true,"ready":ready,"checks":[{"dependency":"store","checked_at_ms":"100","valid_until_ms":"200","reason":if ready {"verified"} else {"unavailable"}}]}]})
                .to_string();
        let (url, server) = serve(
            format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let result = HubClient::new(&url).unwrap().readiness().await;
        assert_eq!(result.is_ok(), valid);
        if valid {
            assert_eq!(result.unwrap().ready, ready);
        }
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("GET /api/readiness HTTP/1.1\r\n")
        );
    }
    let body =
        r#"{"error":"no read scope","code":"insufficient_auth_scope","request_id":"r-health"}"#;
    let (url, server) = serve(
        format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    assert!(matches!(
        HubClient::new(&url).unwrap().readiness().await,
        Err(HubClientError::Api { status: 403, .. })
    ));
    server.join().unwrap();
}
#[tokio::test]
async fn authorization_header_error_diagnostics_and_no_redirect_following() {
    let body = r#"{"error":"limited","code":"rate_limited","request_id":"r-7"}"#;
    let (url, server) = serve(
        format!(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\nRetry-After: 3\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let client = HubClient::new(&url)
        .unwrap()
        .with_token("test-only-secret".into())
        .unwrap();
    assert!(!format!("{client:?}").contains("secret"));
    assert!(
        matches!(client.state().await,Err(HubClientError::Api{status:429,retry_after_seconds:Some(3),ref request_id,..}) if request_id=="r-7")
    );
    let request = server.join().unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer test-only-secret")
    );
    assert!(request.starts_with("GET /api/state HTTP/1.1\r\n"));
    let (url, server) = serve(
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
    );
    assert!(matches!(
        HubClient::new(&url).unwrap().state().await,
        Err(HubClientError::Api { status: 302, .. })
    ));
    server.join().unwrap();
}
#[tokio::test]
async fn ambiguous_write_and_oversized_read_are_distinct() {
    let (url, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{".to_vec());
    let result = HubClient::new(&url)
        .unwrap()
        .with_mutation(morph_sdk::api::MutationContext {
            idempotency_key: "ab".repeat(16),
            expected_revision: 1,
        })
        .unwrap()
        .connect_peer(&ConnectPeerRequest {
            pubkey: "review-only".into(),
            alias: "A".into(),
        })
        .await;
    assert!(
        matches!(result, Err(HubClientError::OutcomeUnknown { ref mutation }) if mutation.idempotency_key=="ab".repeat(16)&&mutation.expected_revision==1)
    );
    let request = server.join().unwrap();
    assert!(request.contains("idempotency-key: abababababababababababababababab"));
    assert!(request.contains("x-morph-expected-revision: 1"));
    assert!(request.contains("x-morph-api-version: 1"));
    let (url, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 3000000\r\n\r\n".to_vec());
    assert!(matches!(
        HubClient::new(&url).unwrap().state().await,
        Err(HubClientError::InvalidResponse)
    ));
    server.join().unwrap();
}

#[tokio::test]
async fn administrative_export_is_typed_and_preserves_full_width_decimal_amounts() {
    let maximum = u128::MAX.to_string();
    let archive = serde_json::json!({
        "pubkey":"02".to_owned()+&"12".repeat(32), "network":"devnet", "peers":[],
        "channels":[{"channel_id":"0x".to_owned()+&"34".repeat(32),
            "counterparty_pubkey":"02".to_owned()+&"56".repeat(32),"funding_epoch":"0",
            "funding_context_id":"0x".to_owned()+&"78".repeat(32),"state_number":"18446744073709551615",
            "phase":"active", "sponsor_budget":"0",
            "balances":[{"asset":{"kind":"xudt","type_hash":"0x".to_owned()+&"9a".repeat(32)},
                "local":maximum,"remote":"0","pending":"0"}]}],
        "factories":[],"conditional_batches":[],"multi_asset_packages":[],"root_fundings":[],
        "invoices":[],"completed_flows":[],"events":[]
    });
    let body = serde_json::to_string(&archive).unwrap();
    let (url, server) = serve(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let result = HubClient::new(&url).unwrap().state_file().await.unwrap();
    assert_eq!(result.channels[0].balances[0].local, maximum);
    assert_eq!(result.channels[0].state_number, u64::MAX);
    assert_eq!(serde_json::to_value(result).unwrap(), archive);
    server.join().unwrap();
    let body = r#"{"snapshot_amount":340282366920938463463374607431768211455}"#;
    let (url, server) = serve(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    assert!(matches!(
        HubClient::new(&url).unwrap().state_file().await,
        Err(HubClientError::InvalidResponse)
    ));
    server.join().unwrap();
}

#[tokio::test]
async fn intermediary_error_does_not_erase_mutation_identity() {
    // A proxy can report an error after the origin committed. An untyped failure
    // is not evidence that it is safe to create a different request identity.
    let (url, server) = serve(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec());
    let context = morph_sdk::api::MutationContext {
        idempotency_key: "cd".repeat(16),
        expected_revision: 42,
    };
    let error = HubClient::new(&url)
        .unwrap()
        .with_mutation(context.clone())
        .unwrap()
        .connect_peer(&ConnectPeerRequest {
            pubkey: "public-test-input".into(),
            alias: "peer".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(error, HubClientError::OutcomeUnknown { mutation } if mutation == context));
    let request = server.join().unwrap();
    assert!(request.contains("x-morph-expected-revision: 42"));
}
