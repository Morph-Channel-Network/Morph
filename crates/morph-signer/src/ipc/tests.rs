use super::*;
use crate::signer_protocol::{
    CodeIdentity, Deployment, InputResolver, Payload, Policy, ResolvedInputs, Target, VERSION,
};
use ckb_types::{packed, prelude::*};
use morph_packages::{
    multi_asset_packages::StoredMultiAssetPackage, multi_asset_signatures::SignatureMessage,
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, symlink},
        net::{UnixListener, UnixStream},
    },
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TIMEOUT: Duration = Duration::from_secs(3);
struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ms-ipc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("signer.sock")
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoInputs;
impl InputResolver for NoInputs {
    fn resolve_live(&self, _: &[morph_core::MultiAssetOutPoint]) -> anyhow::Result<ResolvedInputs> {
        anyhow::bail!("state update has no physical transaction")
    }
}
fn fixture() -> (Request, Response, Policy) {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol");
    let current: StoredMultiAssetPackage =
        serde_json::from_slice(&fs::read(fixtures.join("multi-asset.json")).unwrap()).unwrap();
    let update: Value =
        serde_json::from_slice(&fs::read(fixtures.join("multi-asset-update.json")).unwrap())
            .unwrap();
    let receipt: SignatureMessage = serde_json::from_value(update["signature"].clone()).unwrap();
    let package = current.recovery().unwrap();
    let identity = |bytes: &[u8]| {
        let script = packed::Script::from_slice(bytes).unwrap();
        CodeIdentity {
            code_hash: format!("0x{}", hex::encode(script.code_hash().as_slice())),
            hash_type: u8::from(script.hash_type()),
        }
    };
    let policy = Policy {
        expected_pubkey: receipt.pubkey.clone(),
        network_genesis: [91; 32],
        chain_id: package.state.header.chain_id,
        deployments: vec![Deployment {
            state_type: identity(&package.scripts.state_type),
            state_lock: identity(&package.scripts.state_lock),
            vault_lock: identity(&package.scripts.vault_lock),
        }],
        targets: vec![Target::Update],
        max_request_lifetime_secs: 60,
    };
    let request = Request::prepare(
        Payload::Update {
            current: Box::new(current),
            proposal: serde_json::from_value(update["proposal"].clone()).unwrap(),
        },
        Target::Update,
        150,
        &policy,
        &NoInputs,
        100,
    )
    .unwrap();
    let response = Response {
        version: VERSION.into(),
        request_id: request.request_id.clone(),
        target: Target::Update,
        receipt,
    };
    (request, response, policy)
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child(files: &Files, mode: &str) -> ChildGuard {
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ipc::tests::child_peer", "--nocapture"])
            .env("MORPH_SIGNER_IPC_TEST_DIRECTORY", &files.0)
            .env("MORPH_SIGNER_IPC_TEST_MODE", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    while !files.0.join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before binding"
        );
        assert!(start.elapsed() < TIMEOUT, "child did not bind");
        thread::sleep(Duration::from_millis(5));
    }
    child
}

/// Actual child process uses only existing fixture signatures, never a test-only
/// production key path. This proves IPC behavior, not a signer-journal crash test.
#[test]
fn child_peer() {
    let Some(directory) = std::env::var_os("MORPH_SIGNER_IPC_TEST_DIRECTORY") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let mode = std::env::var("MORPH_SIGNER_IPC_TEST_MODE").unwrap();
    let (_, response, policy) = fixture();
    let mut listener = Listener::bind(&directory.join("signer.sock")).unwrap();
    fs::write(directory.join("ready"), b"ready").unwrap();
    let incoming = listener.receive(TIMEOUT).unwrap().into_signing().unwrap();
    incoming
        .request()
        .validate(&policy, &NoInputs, 100)
        .unwrap();
    if mode == "drop" {
        return;
    }
    incoming.respond(&response).unwrap();
}

#[test]
fn separate_process_roundtrip_verifies_the_original_fixture_receipt() {
    let files = Files::new();
    let mut peer = child(&files, "respond");
    let (request, expected, _) = fixture();
    let response = exchange(&files.socket(), &request, TIMEOUT).unwrap();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert!(peer.0.wait().unwrap().success());
}

#[test]
fn separate_process_disconnect_after_receiving_is_an_unknown_outcome() {
    let files = Files::new();
    let mut peer = child(&files, "drop");
    let (request, _, _) = fixture();
    assert_eq!(
        exchange(&files.socket(), &request, TIMEOUT).unwrap_err(),
        Error::OutcomeUnknown
    );
    assert!(peer.0.wait().unwrap().success());
}

#[test]
fn endpoint_permissions_aliases_existing_files_and_replacement_are_rejected() {
    let files = Files::new();
    fs::set_permissions(&files.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Listener::bind(&files.socket()),
        Err(Error::UntrustedEndpoint)
    ));
    fs::set_permissions(&files.0, fs::Permissions::from_mode(0o700)).unwrap();
    let listener = Listener::bind(&files.socket()).unwrap();
    assert_eq!(fs::metadata(files.socket()).unwrap().mode() & 0o777, 0o600);
    assert!(matches!(
        Listener::bind(&files.socket()),
        Err(Error::Unavailable)
    ));
    let alias = files.0.join("alias.sock");
    symlink(files.socket(), &alias).unwrap();
    assert_eq!(endpoint(&alias), Err(Error::UntrustedEndpoint));
    let directory_alias = Files::new();
    symlink(&files.0, directory_alias.0.join("link")).unwrap();
    assert_eq!(
        endpoint(&directory_alias.0.join("link/signer.sock")),
        Err(Error::UntrustedEndpoint)
    );
    fs::set_permissions(files.socket(), fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(endpoint(&files.socket()), Err(Error::UntrustedEndpoint));
    fs::remove_file(files.socket()).unwrap();
    fs::write(files.socket(), b"replacement must survive drop").unwrap();
    drop(listener);
    assert_eq!(
        fs::read(files.socket()).unwrap(),
        b"replacement must survive drop"
    );
    assert!(matches!(
        Listener::bind(&files.socket()),
        Err(Error::Unavailable)
    ));
}

#[test]
fn private_ancestor_protects_descendants_but_an_exposed_writable_ancestor_is_rejected() {
    let files = Files::new();
    let shared = files.0.join("workspace");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let private = shared.join("signer");
    fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
    let path = private.join("key.sock");
    // The owner-only outer directory prevents any other UID traversing into
    // workspace, irrespective of workspace's permissive mode bits.
    let listener = Listener::bind(&path).unwrap();
    drop(listener);
    // Removing that protection exposes a writable non-sticky ancestor. A
    // private immediate parent alone does not protect its path from replacement.
    fs::set_permissions(&files.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Listener::bind(&path),
        Err(Error::UntrustedEndpoint)
    ));
}

fn send_raw(path: &Path, bytes: Vec<u8>) -> thread::JoinHandle<()> {
    let path = path.to_owned();
    thread::spawn(move || {
        let mut stream = UnixStream::connect(path).unwrap();
        // A reject may close as soon as the four-byte prefix arrives.
        let _ = stream.write_all(&bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
    })
}

#[test]
fn inbound_oversize_zero_truncated_trailing_and_malformed_frames_do_not_escape() {
    let files = Files::new();
    let mut listener = Listener::bind(&files.socket()).unwrap();
    let (request, _, _) = fixture();
    let body = request.encode().unwrap();
    let mut trailing = (body.len() as u32).to_be_bytes().to_vec();
    trailing.extend_from_slice(&body);
    trailing.push(0);
    for (bytes, expected) in [
        (
            (MAX_REQUEST_BYTES as u32 + 1).to_be_bytes().to_vec(),
            Error::InvalidFrame,
        ),
        (0u32.to_be_bytes().to_vec(), Error::InvalidFrame),
        (vec![0, 0, 0, 2, b'{'], Error::InvalidFrame),
        (trailing, Error::InvalidFrame),
        (vec![0, 0, 0, 1, b'x'], Error::InvalidRequest),
    ] {
        let thread = send_raw(&files.socket(), bytes);
        assert!(matches!(listener.receive(TIMEOUT), Err(actual) if actual == expected));
        thread.join().unwrap();
    }
}

#[test]
fn deadline_is_total_not_refreshed_by_each_partial_read() {
    let files = Files::new();
    let mut listener = Listener::bind(&files.socket()).unwrap();
    let path = files.socket();
    let sender = thread::spawn(move || {
        let mut stream = UnixStream::connect(path).unwrap();
        for byte in [0, 0, 0, 16, b'{', b' ', b' ', b' '] {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(35));
        }
    });
    let start = Instant::now();
    assert!(matches!(
        listener.receive(Duration::from_millis(100)),
        Err(Error::Deadline)
    ));
    // Loose scheduling margin, but much less than an indefinitely extended read.
    assert!(start.elapsed() < Duration::from_secs(1));
    sender.join().unwrap();
    assert!(matches!(
        listener.receive(Duration::ZERO),
        Err(Error::InvalidDeadline)
    ));
    assert!(matches!(
        listener.receive(MAX_TIMEOUT + Duration::from_secs(1)),
        Err(Error::InvalidDeadline)
    ));
}

#[test]
fn malformed_oversized_wrong_target_replies_and_silence_never_return_receipts() {
    let (request, response, _) = fixture();
    let mut wrong = response;
    wrong.target = Target::SpliceBridge;
    let invalid_response = serde_json::to_vec(&wrong).unwrap();
    let mut framed_wrong = (invalid_response.len() as u32).to_be_bytes().to_vec();
    framed_wrong.extend(invalid_response);
    for (bytes, expected) in [
        (vec![0, 0, 0, 1, b'x'], Error::InvalidResponse),
        (
            (MAX_RESPONSE_BYTES as u32 + 1).to_be_bytes().to_vec(),
            Error::OutcomeUnknown,
        ),
        (framed_wrong, Error::InvalidResponse),
        (Vec::new(), Error::OutcomeUnknown),
    ] {
        let files = Files::new();
        let listener = UnixListener::bind(files.socket()).unwrap();
        fs::set_permissions(files.socket(), fs::Permissions::from_mode(0o600)).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut body = Vec::new();
            stream.read_to_end(&mut body).unwrap();
            if bytes.is_empty() {
                thread::sleep(Duration::from_millis(250));
            } else {
                let _ = stream.write_all(&bytes);
            }
        });
        assert_eq!(
            exchange(&files.socket(), &request, Duration::from_millis(150)).unwrap_err(),
            expected
        );
        server.join().unwrap();
    }
}

#[test]
fn response_cannot_change_a_request() {
    let files = Files::new();
    let mut listener = Listener::bind(&files.socket()).unwrap();
    let (request, mut response, _) = fixture();
    let path = files.socket();
    let client = thread::spawn(move || exchange(&path, &request, TIMEOUT));
    let incoming = listener.receive(TIMEOUT).unwrap().into_signing().unwrap();
    response.request_id = "unrelated".into();
    assert_eq!(incoming.respond(&response), Err(Error::InvalidResponse));
    assert_eq!(client.join().unwrap().unwrap_err(), Error::OutcomeUnknown);
    assert!(!format!("{}", Error::InvalidRequest).contains("unrelated"));
}

#[test]
fn control_probes_are_separate_from_signatures_and_pin_current_policy() {
    for (loaded, unchanged, expected) in [
        ([2; 32], true, true),
        ([3; 32], true, false),
        ([2; 32], false, false),
    ] {
        let files = Files::new();
        let mut listener = Listener::bind(&files.socket()).unwrap();
        let path = files.socket();
        let client = thread::spawn(move || probe(&path, [1; 32], [2; 32], TIMEOUT));
        match listener.receive(TIMEOUT).unwrap() {
            Message::Probe(incoming) => incoming.respond(loaded, unchanged).unwrap(),
            Message::Sign(_) => panic!("control operation reached signing"),
        }
        assert_eq!(client.join().unwrap().unwrap(), expected);
    }
    let files = Files::new();
    let mut listener = Listener::bind(&files.socket()).unwrap();
    let path = files.socket();
    let client = thread::spawn(move || probe(&path, [1; 32], [2; 32], TIMEOUT));
    assert!(matches!(
        listener.receive(TIMEOUT).unwrap().into_signing(),
        Err(Error::InvalidRequest)
    ));
    assert!(client.join().unwrap().is_err());
}

#[test]
fn malformed_control_frames_are_rejected_without_signing() {
    let files = Files::new();
    let mut listener = Listener::bind(&files.socket()).unwrap();
    for size in [8, PROBE_LEN - 1, PROBE_LEN + 1] {
        let mut body = PROBE_MAGIC.to_vec();
        body.resize(size, 0);
        let mut framed = (body.len() as u32).to_be_bytes().to_vec();
        framed.extend(body);
        let sender = send_raw(&files.socket(), framed);
        assert!(matches!(
            listener.receive(TIMEOUT),
            Err(Error::InvalidRequest)
        ));
        sender.join().unwrap();
    }
}

#[test]
fn control_reply_replay_wrong_policy_signature_and_hang_never_report_ready() {
    let (_, signature, _) = fixture();
    let mut correct = PROBE_REPLY_MAGIC.to_vec();
    correct.extend([1; 32]);
    correct.extend([2; 32]);
    correct.push(1);
    let mut wrong_challenge = correct.clone();
    wrong_challenge[8] ^= 1;
    let mut wrong_policy = correct.clone();
    wrong_policy[40] ^= 1;
    let mut wrong_boolean = correct.clone();
    wrong_boolean[72] = 2;
    for body in [
        wrong_challenge,
        wrong_policy,
        wrong_boolean,
        serde_json::to_vec(&signature).unwrap(),
        Vec::new(),
    ] {
        let files = Files::new();
        let listener = UnixListener::bind(files.socket()).unwrap();
        fs::set_permissions(files.socket(), fs::Permissions::from_mode(0o600)).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            if body.is_empty() {
                thread::sleep(Duration::from_millis(250));
            } else {
                let _ = stream.write_all(&(body.len() as u32).to_be_bytes());
                let _ = stream.write_all(&body);
            }
        });
        let started = Instant::now();
        assert!(
            probe(
                &files.socket(),
                [1; 32],
                [2; 32],
                Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(started.elapsed() < TIMEOUT);
        server.join().unwrap();
    }
}
