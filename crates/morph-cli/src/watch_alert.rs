#[cfg(test)]
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(all(test, unix))]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const WATCH_ALERT_SCHEMA: &str = "morph.watchtower_alert";

pub use morph_hub_api::{WatchAlertEvent, WatchAlertSeverity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerAlert {
    pub schema: String,
    pub created_unix_ms: u64,
    pub channel_id: String,
    pub severity: WatchAlertSeverity,
    pub event: WatchAlertEvent,
    pub message: String,
    pub selected_state_number: u64,
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_funding_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_funding_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_funding_context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_funding_context_id: Option<String>,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
}

impl WatchtowerAlert {
    pub fn new(
        channel_id: String,
        severity: WatchAlertSeverity,
        event: WatchAlertEvent,
        message: String,
        selected_state_number: u64,
        scanned_to_block: u64,
        next_from_block: u64,
    ) -> Result<Self> {
        Ok(Self {
            schema: WATCH_ALERT_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            channel_id,
            severity,
            event,
            message,
            selected_state_number,
            observed_state_number: None,
            observed_out_point: None,
            publication_tx_hash: None,
            selected_funding_anchor: None,
            observed_funding_anchor: None,
            selected_funding_context_id: None,
            observed_funding_context_id: None,
            scanned_to_block,
            next_from_block,
        })
    }

    pub fn with_observed(mut self, state_number: u64, out_point: String) -> Self {
        self.observed_state_number = Some(state_number);
        self.observed_out_point = Some(out_point);
        self
    }

    pub fn with_publication(mut self, tx_hash: String) -> Self {
        self.publication_tx_hash = Some(tx_hash);
        self
    }

    pub fn with_funding_anchors(mut self, selected: String, observed: String) -> Self {
        self.selected_funding_anchor = Some(selected);
        self.observed_funding_anchor = Some(observed);
        self
    }

    pub fn with_optional_funding_contexts(
        mut self,
        selected: Option<String>,
        observed: Option<String>,
    ) -> Self {
        self.selected_funding_context_id = selected;
        self.observed_funding_context_id = observed;
        self
    }
}

pub fn append_watchtower_alert(path: &Path, alert: &WatchtowerAlert) -> Result<()> {
    crate::persistence::append_private_jsonl(path, alert)
}

pub fn post_watchtower_alert_webhook_with_secret(
    url: &str,
    alert: &WatchtowerAlert,
    secret: Option<&str>,
) -> Result<()> {
    ensure!(!url.trim().is_empty(), "watchtower webhook URL is empty");
    let parsed = url::Url::parse(url.trim())
        .with_context(|| format!("watchtower webhook URL {url} is not a valid URL"))?;
    ensure!(
        parsed.scheme() == "https" || is_loopback_url(&parsed),
        "watchtower webhook URL {url} must use https:// or point at a loopback address; \
         plain http:// to a remote host is rejected to prevent channel-state leakage"
    );
    let body = serde_json::to_vec(alert)
        .with_context(|| "failed to encode watchtower alert for webhook")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build watchtower webhook HTTP client")?;
    let mut request = client
        .post(parsed.as_str())
        .header("content-type", "application/json")
        .body(body);
    if let Some(secret) = secret.filter(|secret| !secret.is_empty()) {
        let signature = hmac_sha256_hex(secret.as_bytes(), &request_body_for_signature(alert)?);
        request = request
            .header("x-morph-signature", &signature)
            .header("x-morph-signature-algorithm", "HMAC-SHA256");
    }
    let response = request
        .send()
        .with_context(|| format!("failed to POST watchtower alert webhook {url}"))?;
    let status = response.status();
    ensure!(
        status.is_success(),
        "watchtower alert webhook {url} returned HTTP {status}"
    );
    Ok(())
}

fn is_loopback_url(parsed: &url::Url) -> bool {
    parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
}

fn request_body_for_signature(alert: &WatchtowerAlert) -> Result<Vec<u8>> {
    serde_json::to_vec(alert).with_context(|| "failed to encode watchtower alert for HMAC")
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    hex::encode(hmac_sha256(key, message))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = sha256(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        ipad[index] = key_block[index] ^ 0x36;
        opad[index] = key_block[index] ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner = sha256(&inner_input);
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + inner.len());
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner);
    sha256(&outer_input)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn now_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    Ok(duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn read_http_request(mut stream: TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(expected_len) = expected_http_request_len(&request)
                && request.len() >= expected_len
            {
                break;
            }
        }
        String::from_utf8(request).unwrap()
    }

    fn expected_http_request_len(request: &[u8]) -> Option<usize> {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")?;
        let headers = std::str::from_utf8(&request[..header_end]).ok()?;
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        Some(header_end + 4 + content_length)
    }

    fn request_header<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
        request
            .split("\r\n\r\n")
            .next()?
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case(expected_name)
                    .then(|| value.trim())
            })
    }

    fn channel_id(seed: u8) -> String {
        let hex = (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<String>();
        format!("0x{hex}")
    }

    #[test]
    fn appends_jsonl_alerts() {
        let path =
            std::env::temp_dir().join(format!("morph-watch-alert-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);

        let alert = WatchtowerAlert::new(
            channel_id(1),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap()
        .with_observed(1, "0xabc:0".to_string());

        append_watchtower_alert(&path, &alert).unwrap();
        append_watchtower_alert(&path, &alert).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let decoded: WatchtowerAlert = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(decoded.event, WatchAlertEvent::OlderStateDetected);

        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        for (invalid, reason) in [
            ("{\"schema\":\"another_stream\"}\n", "another schema"),
            (
                "{\"schema\":\"morph.watchtower_alert\"}",
                "incomplete record",
            ),
        ] {
            fs::write(&path, invalid).unwrap();
            #[cfg(unix)]
            {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                assert!(
                    append_watchtower_alert(&path, &alert)
                        .unwrap_err()
                        .to_string()
                        .contains("0600")
                );
                assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o644
                );
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(
                append_watchtower_alert(&path, &alert)
                    .unwrap_err()
                    .to_string()
                    .contains(reason)
            );
            assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
            #[cfg(unix)]
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn appends_alert_without_parent_directory() {
        let path = std::path::PathBuf::from(format!(
            "morph-watch-alert-local-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let alert = WatchtowerAlert::new(
            channel_id(2),
            WatchAlertSeverity::Info,
            WatchAlertEvent::ScanIdle,
            "scan idle".to_string(),
            2,
            10,
            11,
        )
        .unwrap();

        append_watchtower_alert(&path, &alert).unwrap();
        assert!(path.exists());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn serializes_critical_reorg_alert_for_operator_clients() {
        let alert = WatchtowerAlert::new(
            channel_id(3),
            WatchAlertSeverity::Critical,
            WatchAlertEvent::ChainReorgDetected,
            "canonical cursor hash changed".to_string(),
            7,
            42,
            10,
        )
        .unwrap();

        let value = serde_json::to_value(alert).unwrap();
        assert_eq!(value["severity"], "critical");
        assert_eq!(value["event"], "chain_reorg_detected");
    }

    fn loopback_listener_or_skip(test_name: &str) -> Option<std::net::TcpListener> {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("{test_name}: skipping loopback webhook assertion: {err}");
                None
            }
            Err(err) => panic!("{test_name}: failed to bind loopback listener: {err}"),
        }
    }

    #[test]
    fn posts_alert_to_webhook() {
        use std::thread;

        let Some(listener) = loopback_listener_or_skip("posts_alert_to_webhook") else {
            return;
        };
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(stream.try_clone().unwrap());
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });

        let alert = WatchtowerAlert::new(
            channel_id(3),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap();

        post_watchtower_alert_webhook_with_secret(&url, &alert, None).unwrap();
        let request = handle.join().unwrap();
        assert!(request.starts_with("POST / HTTP/1.1"));
        assert!(request.contains("older_state_detected"));
        assert!(request.contains("morph.watchtower_alert"));
    }

    #[test]
    fn rejects_non_loopback_http_webhook() {
        let alert = WatchtowerAlert::new(
            channel_id(4),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap();
        let err =
            post_watchtower_alert_webhook_with_secret("http://example.com/alert", &alert, None)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains("must use https:// or point at a loopback address"),
            "got: {err}"
        );
    }

    #[test]
    fn webhook_does_not_follow_redirects() {
        use std::thread;

        let Some(listener) = loopback_listener_or_skip("webhook_does_not_follow_redirects") else {
            return;
        };
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_http_request(stream.try_clone().unwrap());
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://example.com/alert\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });

        let alert = WatchtowerAlert::new(
            channel_id(6),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap();
        let error = post_watchtower_alert_webhook_with_secret(&url, &alert, None).unwrap_err();
        assert!(error.to_string().contains("HTTP 302 Found"));
        handle.join().unwrap();
    }

    #[test]
    fn posts_alert_to_webhook_with_hmac_signature() {
        use std::thread;

        let Some(listener) =
            loopback_listener_or_skip("posts_alert_to_webhook_with_hmac_signature")
        else {
            return;
        };
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(stream.try_clone().unwrap());
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });

        let alert = WatchtowerAlert::new(
            channel_id(5),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap();

        post_watchtower_alert_webhook_with_secret(&url, &alert, Some("test-secret")).unwrap();
        let expected_body = serde_json::to_vec(&alert).unwrap();
        let expected_signature = hmac_sha256_hex(b"test-secret", &expected_body);
        let request = handle.join().unwrap();
        assert_eq!(
            request_header(&request, "x-morph-signature"),
            Some(expected_signature.as_str())
        );
        assert_eq!(
            request_header(&request, "x-morph-signature-algorithm"),
            Some("HMAC-SHA256")
        );
    }
}
