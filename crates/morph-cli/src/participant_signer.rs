//! Isolated key process, bound to the existing single participant journal.
//! This is not a second authority store. Same-UID host/journal integrity remains
//! trusted; complete authority rollback is not detected by process isolation.
use crate::rpc::CkbRpcClient;
use anyhow::{Context, Result, anyhow, ensure};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::{Bytes32, MultiAssetOutPoint, ParticipantSignature};
use morph_packages::{
    canonical_fields,
    multi_asset_packages::canonical_hex,
    multi_asset_signatures::{SignatureMessage, channel_signing_key},
    signer_protocol::{
        Deployment, InputResolver, Payload, Policy, Request, ResolvedInputs, Response, Target,
        VERSION,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BUDGET: Duration = Duration::from_secs(30);
const MAX_JOURNAL: usize = 768 * 1024;

/// Only these static categories may leave the key service. Inner errors can
/// contain RPC or payload content, so never format their chains in diagnostics.
#[derive(Clone, Copy, Debug)]
enum Rejection {
    Policy,
    Read,
    Authority,
    Review,
    Other,
}
impl std::fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Policy => "request policy",
            Self::Read => "protected authority read",
            Self::Authority => "persisted authority or canonical chain",
            Self::Review => "canonical request review",
            Self::Other => "authorization",
        })
    }
}
impl std::error::Error for Rejection {}
fn rejection(error: &anyhow::Error) -> Rejection {
    error
        .downcast_ref::<Rejection>()
        .copied()
        .unwrap_or(Rejection::Other)
}

#[cfg(feature = "devnet")]
pub(crate) mod acceptance;
pub(crate) mod readiness;

pub(crate) fn development_key_file(
    path: &str,
) -> std::result::Result<morph_key_input::SecretString, String> {
    if !cfg!(any(test, feature = "devnet")) {
        return Err(
            "local participant signing requires the devnet build; use --signer-config".into(),
        );
    }
    morph_key_input::secp256k1_file(path)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    schema: String,
    socket: PathBuf,
    journal: PathBuf,
    rpc_url: String,
    expected_pubkey: String,
    network_genesis: String,
    chain_id: String,
    channel_id: String,
    deployments: Vec<Deployment>,
    targets: Vec<Target>,
}
impl Config {
    fn load(path: &Path) -> Result<Self> {
        let bytes = protected_read(path, 64 * 1024)?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid signer configuration"))?;
        ensure!(
            config.schema == "morph.participant_signer_config.v1",
            "unsupported signer configuration"
        );
        ensure!(
            config.socket.is_absolute() && config.journal.is_absolute(),
            "signer paths must be absolute"
        );
        crate::multi_asset_session_chain::rpc_endpoint(&config.rpc_url)?;
        canonical_fields::public(&config.expected_pubkey)?;
        canonical_fields::hash(&config.channel_id)?;
        config.policy()?;
        ensure!(
            (1..=16).contains(&config.deployments.len()) && (1..=7).contains(&config.targets.len()),
            "invalid signer policy bounds"
        );
        for (index, target) in config.targets.iter().enumerate() {
            ensure!(
                !config.targets[..index].contains(target),
                "duplicate signing target"
            );
        }
        for deployment in &config.deployments {
            for identity in [
                &deployment.state_type,
                &deployment.state_lock,
                &deployment.vault_lock,
            ] {
                canonical_fields::hash(&identity.code_hash)?;
                ckb_types::core::ScriptHashType::try_from(identity.hash_type)
                    .map_err(|_| anyhow!("invalid signer deployment hash type"))?;
            }
        }
        Ok(config)
    }
    fn observation_digest(&self) -> Result<Bytes32> {
        let mut bytes = b"MORPH_PARTICIPANT_PROBE_POLICY_V1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(morph_core::blake2b256(&bytes))
    }
    fn policy(&self) -> Result<Policy> {
        Ok(Policy {
            expected_pubkey: self.expected_pubkey.clone(),
            network_genesis: canonical_fields::hash(&self.network_genesis)?,
            chain_id: canonical_fields::hash(&self.chain_id)?,
            deployments: self.deployments.clone(),
            targets: self.targets.clone(),
            max_request_lifetime_secs: 30,
        })
    }
}
pub(crate) fn protected_read(path: &Path, limit: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        Ok(morph_signer::files::read(path, limit)?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, limit);
        Err(anyhow!("external participant signing requires Linux"))
    }
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(crate) struct Resolver<'a> {
    rpc: &'a CkbRpcClient,
    genesis: Bytes32,
}
impl InputResolver for Resolver<'_> {
    fn resolve_live(&self, inputs: &[MultiAssetOutPoint]) -> Result<ResolvedInputs> {
        ensure!(
            (1..=64).contains(&inputs.len()),
            "signer input bound exceeded"
        );
        let tip = self.rpc.tip_header()?.hash;
        ensure!(
            self.rpc
                .genesis_block_hash()?
                .is_some_and(|hash| hash.0 == self.genesis),
            "signer network mismatch"
        );
        let mut capacities = Vec::with_capacity(inputs.len());
        for point in inputs {
            let cell = self.rpc.canonical_live_cell(
                ckb_jsonrpc_types::OutPoint {
                    tx_hash: point.tx_hash.into(),
                    index: point.index.into(),
                },
                false,
            )?;
            ensure!(
                cell.status == "live",
                "signer input is not canonically live"
            );
            capacities.push(
                cell.cell
                    .ok_or_else(|| anyhow!("missing live signer input"))?
                    .output
                    .capacity
                    .value(),
            );
        }
        ensure!(
            self.rpc.tip_header()?.hash == tip,
            "chain advanced during signer input review; retry exact intent"
        );
        self.rpc.ensure_deadline()?;
        Ok(ResolvedInputs {
            genesis_hash: self.genesis,
            capacities,
        })
    }
}

pub(crate) enum Prepared {
    Local(SigningKey),
    External(Config),
}
impl Prepared {
    pub(crate) fn local(key: &str, expected: &[u8]) -> Result<Self> {
        ensure!(
            cfg!(any(test, feature = "devnet")),
            "local participant signing is development-only; use an external signer"
        );
        Ok(Self::Local(channel_signing_key(key, expected)?))
    }
    pub(crate) fn external(config: &Path, journal: &Path, expected: &[u8]) -> Result<Self> {
        let config = Config::load(config)?;
        ensure!(
            config.journal == journal.canonicalize()?
                && config.expected_pubkey == canonical_hex(expected),
            "signer configuration does not match session authority"
        );
        Ok(Self::External(config))
    }
    pub(crate) fn sign(
        &self,
        target: Target,
        digest: &Bytes32,
        payload: impl FnOnce() -> Result<Payload>,
    ) -> Result<ParticipantSignature> {
        match self {
            Self::Local(key) => {
                #[cfg(test)]
                tests::mark_key_use();
                let signature: Signature = key
                    .sign_prehash(digest)
                    .map_err(|_| anyhow!("participant signing failed"))?;
                Ok(ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: signature.to_bytes().to_vec(),
                })
            }
            Self::External(config) => {
                let started = Instant::now();
                let policy = config.policy()?;
                let rpc = CkbRpcClient::new_signer(&config.rpc_url, BUDGET)?;
                let resolver = Resolver {
                    rpc: &rpc,
                    genesis: policy.network_genesis,
                };
                let now = now()?;
                let request = Request::prepare(
                    payload()?,
                    target,
                    now.checked_add(30)
                        .ok_or_else(|| anyhow!("signer expiry overflow"))?,
                    &policy,
                    &resolver,
                    now,
                )?;
                ensure!(
                    request.review.channel_id == config.channel_id
                        && request.review.signing_digest == canonical_hex(digest),
                    "signer request differs from reserved intent"
                );
                let remaining = BUDGET
                    .checked_sub(started.elapsed())
                    .filter(|r| !r.is_zero())
                    .ok_or_else(|| {
                        anyhow!("signer preparation exhausted budget; reservation retained")
                    })?;
                #[cfg(target_os = "linux")]
                {
                    Ok(
                        morph_signer::ipc::exchange(&config.socket, &request, remaining)?
                            .verify(&request)?,
                    )
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = remaining;
                    Err(anyhow!("external participant signing requires Linux"))
                }
            }
        }
    }
}

fn authorize(
    config: &Config,
    request: &Request,
    rpc: &CkbRpcClient,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let policy = config.policy()?;
    request
        .validate_envelope(&policy, now()?)
        .context(Rejection::Policy)?;
    ensure!(
        request.review.channel_id == config.channel_id,
        "channel not permitted by signer policy"
    );
    let bytes = protected_read(&config.journal, MAX_JOURNAL).context(Rejection::Read)?;
    let (payload, key) = match request.review.target {
        Target::CooperativeClose => {
            let hash = morph_packages::canonical_fields::hash(
                &request
                    .review
                    .transaction
                    .as_ref()
                    .ok_or_else(|| anyhow!("close request lacks exact transaction"))?
                    .transaction_hash,
            )?;
            crate::multi_asset_session::external_close_authority(&bytes, &hash, rpc)
                .context(Rejection::Authority)?
        }
        Target::RootExit | Target::RootCreation => {
            crate::multi_asset_funding_session::external_authority(
                &bytes,
                request.review.target,
                rpc,
            )
            .context(Rejection::Authority)?
        }
        _ => crate::multi_asset_session::external_authority(&bytes, request.review.target, rpc)
            .context(Rejection::Authority)?,
    };
    ensure!(
        key == config.expected_pubkey
            && serde_json::to_value(payload)? == serde_json::to_value(&request.payload)?,
        "request does not match the persisted participant authority"
    );
    ensure!(
        rpc.genesis_block_hash()?
            .is_some_and(|h| h.0 == policy.network_genesis),
        "signer network mismatch"
    );
    request
        .validate(
            &policy,
            &Resolver {
                rpc,
                genesis: policy.network_genesis,
            },
            now()?,
        )
        .context(Rejection::Review)?;
    Ok(bytes)
}

/// No new journal is initialized here. Each request must match the existing
/// fsynced reservation at the installed stable path. Requests cannot choose it.
pub(crate) fn serve(config_path: &Path, key: &str, once: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let config = Config::load(config_path)?;
        let key = channel_signing_key(key, &canonical_fields::public(&config.expected_pubkey)?)?;
        let loaded_policy = config.observation_digest()?;
        let mut listener = morph_signer::ipc::Listener::bind(&config.socket)?;
        loop {
            let incoming = match listener.receive(BUDGET) {
                Ok(incoming) => incoming,
                Err(morph_signer::Error::Deadline) if !once => continue,
                Err(error) if once => return Err(error.into()),
                Err(_) => {
                    eprintln!("participant signer rejected transport");
                    continue;
                }
            };
            let incoming = match incoming {
                morph_signer::ipc::Message::Sign(incoming) => incoming,
                morph_signer::ipc::Message::Probe(probe) => {
                    let unchanged = Config::load(config_path)
                        .and_then(|current| current.observation_digest())
                        .is_ok_and(|digest| digest == loaded_policy);
                    let sent = probe.respond(loaded_policy, unchanged);
                    if once {
                        return Ok(sent?);
                    }
                    continue;
                }
            };
            let result = (|| -> Result<Response> {
                let rpc = CkbRpcClient::new_signer(&config.rpc_url, incoming.remaining()?)?;
                let request = incoming.request();
                let snapshot = authorize(&config, request, &rpc)?;
                #[cfg(test)]
                tests::checkpoint("reviewed");
                // The host may have timed out and advanced its authority while
                // chain checks ran. Reject an observed advance; every earlier
                // reservation remains binding even after the host timeout.
                ensure!(
                    protected_read(&config.journal, MAX_JOURNAL)?.as_slice() == snapshot.as_slice(),
                    "signer authority changed during review"
                );
                rpc.ensure_deadline()?;
                incoming.remaining()?;
                ensure!(
                    now()? < request.expires_at_unix,
                    "signer request expired before key use"
                );
                let digest = canonical_fields::hash(&request.review.signing_digest)?;
                let signature: Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| anyhow!("participant signing failed"))?;
                let receipt = SignatureMessage::new(
                    &digest,
                    &ParticipantSignature {
                        pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                        signature: signature.to_bytes().to_vec(),
                    },
                );
                Ok(Response {
                    version: VERSION.into(),
                    request_id: request.request_id.clone(),
                    target: request.review.target,
                    receipt,
                })
            })();
            match result {
                Ok(response) => {
                    let sent = incoming.respond(&response);
                    if once {
                        return Ok(sent?);
                    }
                    if sent.is_err() {
                        eprintln!(
                            "participant signer response delivery uncertain; reservation retained"
                        );
                    }
                }
                Err(error) => {
                    drop(incoming);
                    let reason = rejection(&error);
                    if once {
                        return Err(anyhow!("participant signer rejected {reason}"));
                    }
                    eprintln!("participant signer rejected {reason}");
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config_path, key, once);
        Err(anyhow!("external participant signing requires Linux"))
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use ckb_types::prelude::*;
    use std::process::{Child, Command, Stdio};
    pub(crate) fn checkpoint(stage: &str) {
        if std::env::var("MORPH_FAULT_STAGE").ok().as_deref() != Some(stage) {
            return;
        }
        let marker = std::env::var_os("MORPH_FAULT_MARKER").unwrap();
        let release = std::path::PathBuf::from(std::env::var_os("MORPH_FAULT_RELEASE").unwrap());
        std::fs::write(marker, stage).unwrap();
        let start = Instant::now();
        while !release.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "fault checkpoint not released"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub(crate) fn mark_key_use() {
        if let Some(path) = std::env::var_os("MORPH_FAULT_KEY_USE") {
            std::fs::write(path, b"key-use").unwrap();
        }
    }
    #[test]
    fn rejection_diagnostics_never_format_inner_payloads() {
        let secret_error = anyhow!("untrusted token, key or payload body");
        assert_eq!(rejection(&secret_error).to_string(), "authorization");
        let classified = secret_error.context(Rejection::Authority);
        assert_eq!(
            rejection(&classified).to_string(),
            "persisted authority or canonical chain"
        );
    }
    pub(crate) struct ChildGuard(pub Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    fn service_child() {
        let Some(config) = std::env::var_os("MORPH_SIGNER_TEST_CONFIG") else {
            return;
        };
        let key_path = std::env::var("MORPH_SIGNER_TEST_KEY_FILE").unwrap();
        let key = morph_key_input::secp256k1_file(&key_path).unwrap();
        assert!(
            serve(Path::new(&config), &key, true).is_ok(),
            "isolated signer rejected request"
        );
    }
    pub(crate) fn start(config: &Path, key_file: &Path, socket: &Path) -> ChildGuard {
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "participant_signer::tests::service_child",
                    "--nocapture",
                ])
                .env("MORPH_SIGNER_TEST_CONFIG", config)
                .env("MORPH_SIGNER_TEST_KEY_FILE", key_file)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let started = Instant::now();
        while !socket.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "signer exited before binding"
            );
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "signer did not bind"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        child
    }
    pub(crate) fn configuration(
        dir: &Path,
        journal: &Path,
        rpc: &str,
        package: &morph_core::MultiAssetRecoveryPackage,
        key: &[u8],
    ) -> (PathBuf, PathBuf, PathBuf) {
        let identity = |bytes: &[u8]| {
            let script = ckb_types::packed::Script::from_slice(bytes).unwrap();
            serde_json::json!({"code_hash":canonical_hex(script.code_hash().as_slice()),"hash_type":u8::from(script.hash_type())})
        };
        let signing = SigningKey::from_slice(key).unwrap();
        let socket = dir.join("participant.sock");
        let config = dir.join("signer.json");
        let key_file = dir.join("participant.key");
        let value = serde_json::json!({"schema":"morph.participant_signer_config.v1","socket":socket,"journal":journal,"rpc_url":rpc,
            "expected_pubkey":canonical_hex(signing.verifying_key().to_sec1_point(true).as_bytes()),
            "network_genesis":canonical_hex(&package.state.header.chain_id),"chain_id":canonical_hex(&package.state.header.chain_id),"channel_id":canonical_hex(&package.state.header.channel_id),
            "deployments":[{"state_type":identity(&package.scripts.state_type),"state_lock":identity(&package.scripts.state_lock),"vault_lock":identity(&package.scripts.vault_lock)}],
            "targets":["root_exit","root_creation","update","splice_creation","splice_recovery","splice_bridge"]});
        crate::persistence::write_private_atomic(&config, &serde_json::to_vec(&value).unwrap())
            .unwrap();
        crate::persistence::write_private_atomic(&key_file, hex::encode(key).as_bytes()).unwrap();
        (config, socket, key_file)
    }
    pub(crate) fn request(config: &Path, target: Target, payload: Payload) -> Request {
        try_request(config, target, payload).unwrap()
    }
    pub(crate) fn try_request(config: &Path, target: Target, payload: Payload) -> Result<Request> {
        let config = Config::load(config)?;
        let policy = config.policy()?;
        let rpc = CkbRpcClient::new_signer(&config.rpc_url, BUDGET)?;
        let now = now()?;
        Request::prepare(
            payload,
            target,
            now + 30,
            &policy,
            &Resolver {
                rpc: &rpc,
                genesis: policy.network_genesis,
            },
            now,
        )
    }
}
