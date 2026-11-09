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
async fn authorization_header_error_diagnostics_and_no_redirect_following() {
    let body = r#"{"error":"limited","code":"mutation_rate_limited","request_id":"r-7"}"#;
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
        .connect_peer(&ConnectPeerRequest {
            pubkey: "review-only".into(),
            alias: "A".into(),
        })
        .await;
    assert!(matches!(result, Err(HubClientError::OutcomeUnknown)));
    server.join().unwrap();
    let (url, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 3000000\r\n\r\n".to_vec());
    assert!(matches!(
        HubClient::new(&url).unwrap().state().await,
        Err(HubClientError::InvalidResponse)
    ));
    server.join().unwrap();
}

#[tokio::test]
async fn state_file_passthrough_never_rounds_u128_snapshot_quantities() {
    let maximum = "340282366920938463463374607431768211455";
    let body = format!("{{\"snapshot_amount\":{maximum}}}");
    let (url, server) = serve(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let snapshot = HubClient::new(&url).unwrap().state_file().await.unwrap();
    assert_eq!(snapshot["snapshot_amount"].to_string(), maximum);
    assert_eq!(serde_json::to_string(&snapshot).unwrap(), body);
    server.join().unwrap();
}
