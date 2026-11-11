//! Controlled-devnet harness for the actual key service. No alternate signer or
//! cryptographic path: it provisions protected fixture inputs and invokes the
//! public service command and ordinary root/session sign commands.
use super::*;
use ckb_types::{packed, prelude::*};
use morph_core::MultiAssetRecoveryPackage;
use morph_packages::signer_protocol::CodeIdentity;
use serde_json::{Value, json};
use std::{
    fs,
    process::{Child, Command, Stdio},
};

struct Service {
    directory: PathBuf,
    child: Option<Child>,
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn sign(
    rpc: &CkbRpcClient,
    session: &Path,
    target: Target,
    secret: &morph_key_input::SecretString,
    current: &MultiAssetRecoveryPackage,
    exercise_faults: bool,
) -> Result<Value> {
    sign_exact(rpc, session, target, secret, current, exercise_faults, None)
}

pub(crate) fn sign_close(
    rpc: &CkbRpcClient,
    session: &Path,
    secret: &morph_key_input::SecretString,
    current: &MultiAssetRecoveryPackage,
    exercise_faults: bool,
    hash: &Bytes32,
) -> Result<Value> {
    sign_exact(
        rpc,
        session,
        Target::CooperativeClose,
        secret,
        current,
        exercise_faults,
        Some(hash),
    )
}

fn sign_exact(
    rpc: &CkbRpcClient,
    session: &Path,
    target: Target,
    secret: &morph_key_input::SecretString,
    current: &MultiAssetRecoveryPackage,
    exercise_faults: bool,
    close_hash: Option<&Bytes32>,
) -> Result<Value> {
    ensure!(
        matches!(target, Target::CooperativeClose) == close_hash.is_some(),
        "close acceptance requires an explicit exact body"
    );
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (rpc, session, target, secret, current, exercise_faults);
        anyhow::bail!("external signing acceptance requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0; 8];
        getrandom::fill(&mut random)
            .map_err(|_| anyhow!("cannot allocate private signer directory"))?;
        let directory = std::env::temp_dir().canonicalize()?.join(format!(
            "morph-signer-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let mut service = Service {
            directory,
            child: None,
        };
        let bytes =
            zeroize::Zeroizing::new(hex::decode(secret.strip_prefix("0x").unwrap_or(secret))?);
        let key = SigningKey::from_slice(&bytes)
            .map_err(|_| anyhow!("invalid development signer key"))?;
        let pubkey = canonical_hex(key.verifying_key().to_sec1_point(true).as_bytes());
        let identity = |bytes: &[u8]| -> Result<CodeIdentity> {
            let script = packed::Script::from_slice(bytes)?;
            Ok(CodeIdentity {
                code_hash: canonical_hex(script.code_hash().as_slice()),
                hash_type: u8::from(script.hash_type()),
            })
        };
        let genesis = rpc
            .genesis_block_hash()?
            .ok_or_else(|| anyhow!("missing devnet genesis"))?;
        let config = Config {
            schema: "morph.participant_signer_config.v1".into(),
            socket: service.directory.join("key.sock"),
            journal: session.canonicalize()?,
            rpc_url: rpc.endpoint().into(),
            expected_pubkey: pubkey.clone(),
            network_genesis: canonical_hex(&genesis.0),
            chain_id: canonical_hex(&current.state.header.chain_id),
            channel_id: canonical_hex(&current.state.header.channel_id),
            deployments: vec![Deployment {
                state_type: identity(&current.scripts.state_type)?,
                state_lock: identity(&current.scripts.state_lock)?,
                vault_lock: identity(&current.scripts.vault_lock)?,
            }],
            targets: vec![target],
        };
        let config_path = service.directory.join("config.json");
        let key_path = service.directory.join("key");
        crate::persistence::write_private_atomic(&config_path, &serde_json::to_vec(&config)?)?;
        crate::persistence::write_private_atomic(&key_path, secret.as_bytes())?;
        let faults = if exercise_faults {
            Some(exercise_loss(
                &mut service,
                &config,
                &config_path,
                &key_path,
                session,
                target,
                close_hash,
            )?)
        } else {
            None
        };
        let signer_pid = start(&mut service, &config, &config_path, &key_path)?;
        let (receipt, caller_pid) = sign_command(session, target, &config_path, close_hash)?;
        ensure!(
            finish(&mut service)?.success(),
            "external signer did not complete the native request"
        );
        let cached_caller = if exercise_faults {
            let recorded = protected_read(session, MAX_JOURNAL)?;
            let (cached, cached_pid) = sign_command(session, target, &config_path, close_hash)?;
            ensure!(
                cached == receipt && cached_pid != caller_pid,
                "cached retry changed receipt"
            );
            ensure!(
                protected_read(session, MAX_JOURNAL)?.as_slice() == recorded.as_slice(),
                "cached retry rewrote authority"
            );
            Some(cached_pid)
        } else {
            None
        };
        let message: SignatureMessage = serde_json::from_value(receipt.clone())?;
        ensure!(message.pubkey == pubkey, "native receipt key mismatch");
        crate::persistence::append_private_jsonl(
            &session
                .parent()
                .ok_or_else(|| anyhow!("missing session parent"))?
                .join("external-signing.jsonl"),
            &json!({"schema":"morph.external_signer_observation.v1","target":target,"channel_id":config.channel_id,"genesis":config.network_genesis,
                "pubkey":pubkey,"signing_digest":message.signing_digest,"signer_pid":signer_pid,"caller_pid":caller_pid,"cached_caller_pid":cached_caller,"harness_pid":std::process::id(),"service_exit_code":0,"verified_and_recorded":true,"faults":faults}),
        )?;
        Ok(receipt)
    }
}

/// Every call reloads authority in a fresh CLI process, including the failed
/// pre-call reservation and the retry after a lost key-service response.
fn sign_command(
    session: &Path,
    target: Target,
    config_path: &Path,
    close_hash: Option<&Bytes32>,
) -> Result<(Value, u32)> {
    struct HostProcess(Child);
    impl Drop for HostProcess {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }
    let (command, role) = match target {
        Target::RootExit => ("multi-asset-funding-session", "exit"),
        Target::RootCreation => ("multi-asset-funding-session", "creation"),
        Target::Update => ("multi-asset-session", "update"),
        Target::SpliceCreation => ("multi-asset-session", "splice-creation"),
        Target::SpliceRecovery => ("multi-asset-session", "splice-recovery"),
        Target::SpliceBridge => ("multi-asset-session", "splice-bridge"),
        Target::CooperativeClose => ("multi-asset-session", "cooperative-close"),
    };
    let output = config_path
        .parent()
        .ok_or_else(|| anyhow!("missing private harness directory"))?
        .join("host-reply.json");
    crate::persistence::write_private_atomic(&output, b"")?;
    let mut invocation = Command::new(std::env::current_exe()?);
    invocation.arg(command).arg("--session").arg(session);
    if let Some(hash) = close_hash {
        ensure!(
            matches!(target, Target::CooperativeClose),
            "unexpected close body"
        );
        invocation
            .args(["cooperative-close", "sign", "--transaction-hash"])
            .arg(canonical_hex(hash));
    } else {
        invocation.args(["sign", "--target", role]);
    }
    let mut child = HostProcess(
        invocation
            .arg("--signer-config")
            .arg(config_path)
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::from(
                fs::OpenOptions::new().write(true).open(&output)?,
            ))
            .spawn()?,
    );
    let pid = child.0.id();
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure!(
                status.success(),
                "isolated caller rejected signing; reservation retained"
            );
            let body =
                protected_read(&output, morph_packages::signer_protocol::MAX_RESPONSE_BYTES)?;
            return Ok((serde_json::from_slice(&body)?, pid));
        }
        ensure!(
            started.elapsed() < Duration::from_secs(90),
            "native caller exceeded its harness budget"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn start(
    service: &mut Service,
    config: &Config,
    config_path: &Path,
    key_path: &Path,
) -> Result<u32> {
    // Paths, never key bytes, cross the process boundary. The service has the
    // same executable/source identity as this native runner.
    ensure!(
        service.child.is_none(),
        "previous signer child was not joined"
    );
    let child = Command::new(std::env::current_exe()?)
        .arg("participant-signer-serve")
        .arg("--config")
        .arg(config_path)
        .arg("--private-key-file")
        .arg(key_path)
        .arg("--once")
        .env("RUST_BACKTRACE", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let pid = child.id();
    service.child = Some(child);
    let started = Instant::now();
    while !config.socket.exists() {
        ensure!(
            service
                .child
                .as_mut()
                .ok_or_else(|| anyhow!("missing signer child"))?
                .try_wait()?
                .is_none(),
            "external signer exited before binding"
        );
        ensure!(
            started.elapsed() < Duration::from_secs(10),
            "external signer startup timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(pid)
}

fn finish(service: &mut Service) -> Result<std::process::ExitStatus> {
    let finished = Instant::now();
    loop {
        if let Some(status) = service
            .child
            .as_mut()
            .ok_or_else(|| anyhow!("missing signer child"))?
            .try_wait()?
        {
            service.child = None;
            return Ok(status);
        }
        ensure!(
            finished.elapsed() < Duration::from_secs(5),
            "external signer did not exit after response"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn exercise_loss(
    service: &mut Service,
    config: &Config,
    config_path: &Path,
    key_path: &Path,
    session: &Path,
    target: Target,
    close_hash: Option<&Bytes32>,
) -> Result<Value> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    // Start with no listener. The real host must reserve before discovering the
    // unavailable service; a missing receipt must not make the vote free again.
    let before = protected_read(session, MAX_JOURNAL)?;
    ensure!(
        sign_command(session, target, config_path, close_hash).is_err(),
        "unavailable signer returned a receipt"
    );
    let reserved = protected_read(session, MAX_JOURNAL)?;
    ensure!(
        reserved.as_slice() != before.as_slice(),
        "missing durable pre-call reservation"
    );
    let rpc = CkbRpcClient::new_signer(&config.rpc_url, BUDGET)?;
    let (payload, _) = match target {
        Target::CooperativeClose => crate::multi_asset_session::external_close_authority(
            &reserved,
            close_hash.ok_or_else(|| anyhow!("missing close body"))?,
            &rpc,
        )?,
        Target::RootExit | Target::RootCreation => {
            crate::multi_asset_funding_session::external_authority(&reserved, target, &rpc)?
        }
        _ => crate::multi_asset_session::external_authority(&reserved, target, &rpc)?,
    };
    let policy = config.policy()?;
    let resolver = Resolver {
        rpc: &rpc,
        genesis: policy.network_genesis,
    };
    let time = now()?;
    // This is a correctly identified, formerly valid request, not a corrupt ID.
    let expired = Request::prepare(
        payload.clone(),
        target,
        time - 60,
        &policy,
        &resolver,
        time - 90,
    )?;
    let expired_pid = start(service, config, config_path, key_path)?;
    ensure!(
        morph_signer::ipc::exchange(&config.socket, &expired, BUDGET).is_err(),
        "expired request returned a receipt"
    );
    ensure!(
        !finish(service)?.success(),
        "expired request accepted by isolated key service"
    );
    ensure!(
        protected_read(session, MAX_JOURNAL)?.as_slice() == reserved.as_slice(),
        "rejected request changed authority"
    );
    let rpc = CkbRpcClient::new_signer(&config.rpc_url, BUDGET)?;
    let time = now()?;
    let request = Request::prepare(
        payload,
        target,
        time + 30,
        &policy,
        &Resolver {
            rpc: &rpc,
            genesis: policy.network_genesis,
        },
        time,
    )?;
    let lost_pid = start(service, config, config_path, key_path)?;
    let mut stream = UnixStream::connect(&config.socket)?;
    stream.set_read_timeout(Some(BUDGET))?;
    stream.set_write_timeout(Some(BUDGET))?;
    let bytes = zeroize::Zeroizing::new(request.encode()?);
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    ensure!(
        (1..=morph_packages::signer_protocol::MAX_RESPONSE_BYTES)
            .contains(&(u32::from_be_bytes(prefix) as usize)),
        "missing signed response prefix"
    );
    // The production service writes this prefix only after key use. Discard
    // the entire body: no receipt is verified, recorded or used by the host.
    drop(stream);
    let _ = finish(service)?; // Delivery may succeed into the socket or see EPIPE.
    ensure!(
        protected_read(session, MAX_JOURNAL)?.as_slice() == reserved.as_slice(),
        "lost response released or changed reservation"
    );
    Ok(
        json!({"service_unavailable_reserved":true,"expired_request_rejected":true,"expired_process":expired_pid,"after_key_disconnect":true,"lost_response_process":lost_pid,"reservation_unchanged":true,"exact_retry_recorded":true,"cached_retry_without_service":true}),
    )
}
