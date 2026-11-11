//! Actual delivery binary reading a real encrypted Gateway producer database.
//! No Fiber/payment execution is claimed by this transport isolation test.
#![cfg(target_os = "linux")]
use morph_packages::events::{Component, EventEnvelope, Kind};
use morph_payment_gateway::{DurableStore, PaymentDirection, TrackedPayment};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn secret(path: &Path, byte: u8) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    writeln!(f, "{}", hex::encode([byte; 32])).unwrap();
}
fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buffer[..n]);
        assert!(bytes.len() < 16384);
        if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
            let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length = header(&headers, "content-length").parse::<usize>().unwrap();
            if bytes.len() >= end + 4 + length {
                return (headers, bytes[end + 4..end + 4 + length].to_vec());
            }
        }
    }
}
fn header<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim())
        })
        .unwrap()
}
#[test]
fn encrypted_gateway_events_reach_real_consumer_without_private_projection_or_keys() {
    let dir = std::env::temp_dir().join(format!(
        "morph-gateway-events-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let source = dir.join("source/gateway.db");
    let consumer = dir.join("consumer/events.db");
    let storage_key = dir.join("storage.key");
    let webhook_key = dir.join("webhook.key");
    let wrong_key = dir.join("wrong.key");
    secret(&storage_key, 19);
    secret(&webhook_key, 23);
    secret(&wrong_key, 24);
    let gateway = DurableStore::open(&source, [19; 32]).unwrap();
    gateway.record_payment(TrackedPayment {
        payment_hash:format!("0x{}","14".repeat(32)),requirement_id:format!("0x{}","15".repeat(32)),
        direction:PaymentDirection::Incoming,status:"Paid".into(),updated_at:1,
        fiber_result:serde_json::json!({"private_proof":"private-gateway-evidence-marker","payment_preimage":"private-preimage-marker","credential":"private-credential-marker"}),
    }).unwrap();
    drop(gateway);
    let before = fs::read(&source).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let run = |key: Option<&Path>, action: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_morph-cli"));
        command
            .arg("event-delivery")
            .arg("--source")
            .arg(&source)
            .arg("--store")
            .arg(&consumer)
            .arg("--url")
            .arg(&url)
            .arg("--hmac-key-file")
            .arg(&webhook_key);
        if let Some(key) = key {
            command.arg("--source-storage-key-file").arg(key);
        }
        command.args(action).output().unwrap()
    };
    for key in [None, Some(wrong_key.as_path())] {
        let output = run(key, &["run-once", "--limit", "2"]);
        assert!(!output.status.success());
        assert!(!consumer.exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&hex::encode([19; 32])));
    }
    let receiver = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut kinds = Vec::new();
        while kinds.len() < 2 {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "delivery never arrived");
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            let (headers, body) = read_request(&mut stream);
            let event = EventEnvelope::decode(&body).unwrap();
            assert_eq!(event.component, Component::Gateway);
            morph_events::verify_request(
                &event.event_id,
                &body,
                header(&headers, "x-morph-signature"),
                &[23; 32],
            )
            .unwrap();
            let text = String::from_utf8(body.clone()).unwrap();
            assert!(!text.contains("private-"));
            assert!(!text.contains(&hex::encode([19; 32])));
            if event.kind == Kind::GatewayPaymentRecorded {
                assert_eq!(event.payment_hash, Some("14".repeat(32)));
            }
            let ack = morph_events::acknowledgement(&event.event_id, &body, &[23; 32]).unwrap();
            write!(
                stream,
                "HTTP/1.1 204 No Content\r\nX-Morph-Ack: {ack}\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
            kinds.push(event.kind);
        }
        assert!(kinds.contains(&Kind::GatewayInitialized));
        assert!(kinds.contains(&Kind::GatewayPaymentRecorded));
    });
    let output = run(Some(&storage_key), &["run-once", "--limit", "2"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let health: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(health["acknowledged"], 2);
    receiver.join().unwrap();
    let status = run(Some(&storage_key), &["status"]);
    assert!(status.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&status.stdout).unwrap()["acknowledged"],
        2
    );
    assert_eq!(fs::read(&source).unwrap(), before);
    let consumer_bytes = fs::read(&consumer).unwrap();
    for marker in [
        "private-gateway-evidence-marker",
        "private-preimage-marker",
        "private-credential-marker",
    ] {
        assert!(
            !consumer_bytes
                .windows(marker.len())
                .any(|w| w == marker.as_bytes())
        );
    }
    let next = dir.join("consumer/next.db");
    let archived = run(
        Some(&storage_key),
        &["archive", "--next-store", next.to_str().unwrap()],
    );
    assert!(
        archived.status.success(),
        "{}",
        String::from_utf8_lossy(&archived.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&archived.stdout).unwrap();
    assert_eq!(report["retained_in_archive"], 2);
    assert_eq!(report["carried_forward"], 0);
    let sealed = fs::read(&consumer).unwrap();
    let blocked = run(Some(&storage_key), &["run-once"]);
    assert!(!blocked.status.success());
    assert_eq!(fs::read(&consumer).unwrap(), sealed);
    // No receiver is running now. A successful tick on the successor proves it
    // did not re-enqueue/re-send the already acknowledged source events.
    let next_command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_morph-cli"));
        command
            .arg("event-delivery")
            .arg("--source")
            .arg(&source)
            .arg("--store")
            .arg(&next)
            .arg("--url")
            .arg(&url)
            .arg("--hmac-key-file")
            .arg(&webhook_key)
            .arg("--source-storage-key-file")
            .arg(&storage_key);
        command
    };
    let output = next_command().arg("run-once").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let health: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(health["retained"], 0);
    assert_eq!(health["source_pending"], false);
    // Readiness needs a real worker lease, not just a readable empty database.
    let unready = next_command().arg("readiness").output().unwrap();
    assert!(!unready.status.success());
    let report: serde_json::Value = serde_json::from_slice(&unready.stdout).unwrap();
    assert_eq!(report["ready"], false);
    let consumer_before_probe = fs::read(&next).unwrap();
    let mut worker = Worker(
        next_command()
            .args(["serve", "--interval-ms", "100"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ready = next_command().arg("readiness").output().unwrap();
        if ready.status.success() {
            let report: serde_json::Value = serde_json::from_slice(&ready.stdout).unwrap();
            assert_eq!(report["service"], "event_consumer");
            assert_eq!(report["scopes"][0]["scope"], "event_dispatch");
            break;
        }
        assert!(Instant::now() < deadline, "worker never became ready");
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "worker exited unexpectedly"
        );
        std::thread::sleep(Duration::from_millis(30));
    }
    let metrics = next_command().arg("metrics").output().unwrap();
    assert!(metrics.status.success());
    let text = String::from_utf8(metrics.stdout).unwrap();
    assert!(text.contains("morph_event_delivery_worker_fresh 1"));
    assert_eq!(
        text.lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .count(),
        17
    );
    assert!(!text.contains(source.to_str().unwrap()));
    assert!(!text.contains(&url));
    worker.0.kill().unwrap();
    worker.0.wait().unwrap();
    // Actual process death: no synthetic edit of the heartbeat. Its lease must
    // expire even though the queue and its old health file remain readable.
    let deadline = Instant::now() + Duration::from_secs(18);
    loop {
        let readiness = next_command().arg("readiness").output().unwrap();
        if !readiness.status.success() {
            let report: serde_json::Value = serde_json::from_slice(&readiness.stdout).unwrap();
            assert!(
                report["scopes"][0]["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|check| check["dependency"] == "worker" && check["reason"] == "stale")
            );
            break;
        }
        assert!(Instant::now() < deadline, "dead worker kept a green lease");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(fs::read(&next).unwrap(), consumer_before_probe);
    assert_eq!(fs::read(&source).unwrap(), before);
    fs::remove_dir_all(dir).unwrap();
}

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
