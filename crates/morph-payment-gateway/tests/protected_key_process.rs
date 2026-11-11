#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BISCUIT_BYTES: [u8; 32] = [0xa3; 32];
const RECEIPT_BYTES: [u8; 32] = [0xb4; 32];

fn protected_file(path: &Path, value: &str) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    writeln!(file, "{value}").unwrap();
}

fn command(directory: &Path, address: SocketAddr) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_morph-payment-gateway"));
    command.env_clear().args([
        "serve",
        "--listen",
        &address.to_string(),
        "--fiber-rpc",
        "http://127.0.0.1:1",
        "--store",
        directory.join("private/gateway.db").to_str().unwrap(),
        "--payee",
        &format!("0x{}", "11".repeat(32)),
        "--ckb-network-id",
        &format!("0x{}", "22".repeat(32)),
    ]);
    command
        .env(
            "MORPH_PAYMENT_GATEWAY_BISCUIT_PRIVATE_KEY_FILE",
            directory.join("biscuit.key"),
        )
        .env(
            "MORPH_PAYMENT_GATEWAY_RECEIPT_PRIVATE_KEY_FILE",
            directory.join("receipt.key"),
        );
    command
}

fn assert_secret_absent(bytes: &[u8]) {
    for secret in [BISCUIT_BYTES, RECEIPT_BYTES] {
        for representation in [secret.to_vec(), hex::encode(secret).into_bytes()] {
            assert!(
                !bytes
                    .windows(representation.len())
                    .any(|window| window == representation),
                "private material appeared in a process or output surface"
            );
        }
    }
}

struct RunningGateway(Option<Child>);

impl RunningGateway {
    fn stop(mut self) -> Output {
        let mut child = self.0.take().unwrap();
        child.kill().unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for RunningGateway {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_millis(200))?;
    connection.set_read_timeout(Some(Duration::from_secs(1)))?;
    write!(
        connection,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    connection.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn protected_keys_start_real_gateway_without_process_or_output_leakage() {
    let directory = tempfile::tempdir().unwrap();
    protected_file(
        &directory.path().join("biscuit.key"),
        &format!("ed25519-private/{}", hex::encode(BISCUIT_BYTES)),
    );
    protected_file(
        &directory.path().join("receipt.key"),
        &format!("0x{}", hex::encode(RECEIPT_BYTES)),
    );
    // Reserve a local address only long enough to choose an unused port. A bind
    // race fails the health/readiness check instead of producing a false pass.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let child = command(directory.path(), address)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut gateway = RunningGateway(Some(child));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(response) = get(address, "/health")
            && response.starts_with("HTTP/1.1 200")
            && response.contains("\"status\":\"ok\"")
        {
            break;
        }
        assert!(
            gateway.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "gateway exited before healthy startup"
        );
        assert!(Instant::now() < deadline, "gateway did not become healthy");
        thread::sleep(Duration::from_millis(20));
    }
    let pid = gateway.0.as_ref().unwrap().id();
    let arguments = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    let environment = fs::read(format!("/proc/{pid}/environ")).unwrap();
    assert_secret_absent(&arguments);
    assert_secret_absent(&environment);
    let entries: Vec<_> = environment
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .collect();
    assert_eq!(entries.len(), 2);
    for (name, filename) in [
        (
            "MORPH_PAYMENT_GATEWAY_BISCUIT_PRIVATE_KEY_FILE",
            "biscuit.key",
        ),
        (
            "MORPH_PAYMENT_GATEWAY_RECEIPT_PRIVATE_KEY_FILE",
            "receipt.key",
        ),
    ] {
        let expected = format!("{name}={}", directory.path().join(filename).display());
        assert!(entries.contains(&expected.as_bytes()));
    }
    // The configured receipt public key proves the healthy process loaded the
    // legitimate signer, rather than merely exposing an unrelated health port.
    let supported = get(address, "/v1/supported").unwrap();
    assert!(supported.starts_with("HTTP/1.1 200"));
    let expected_key = k256::ecdsa::SigningKey::from_slice(&RECEIPT_BYTES).unwrap();
    assert!(supported.contains(&hex::encode(
        expected_key.verifying_key().to_sec1_point(true).as_bytes()
    )));
    assert_secret_absent(supported.as_bytes());
    let output = gateway.stop();
    assert_secret_absent(&output.stdout);
    assert_secret_absent(&output.stderr);
}

#[test]
fn real_gateway_key_file_errors_never_echo_private_material() {
    let directory = tempfile::tempdir().unwrap();
    let biscuit = directory.path().join("biscuit.key");
    let receipt = directory.path().join("receipt.key");
    protected_file(&biscuit, &hex::encode(BISCUIT_BYTES));
    protected_file(&receipt, &hex::encode(RECEIPT_BYTES));
    let malformed = command(directory.path(), "127.0.0.1:0".parse().unwrap())
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    assert_secret_absent(&malformed.stdout);
    assert_secret_absent(&malformed.stderr);
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("tagged Biscuit"));

    fs::write(
        &biscuit,
        format!("ed25519-private/{}", hex::encode(BISCUIT_BYTES)),
    )
    .unwrap();
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();
    let exposed = command(directory.path(), "127.0.0.1:0".parse().unwrap())
        .output()
        .unwrap();
    assert!(!exposed.status.success());
    assert_secret_absent(&exposed.stdout);
    assert_secret_absent(&exposed.stderr);
    assert!(String::from_utf8_lossy(&exposed.stderr).contains("permissions"));
}
