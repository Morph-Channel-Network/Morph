//! Explicit no-value native matrix against an independently running patched
//! Fiber. Uses real CLI workers and never reads or modifies the user's nodes.
use super::*;
use crate::devnet::{self, multi_asset::MultiAssetSmokeOptions};
use ckb_types::prelude::*;
use morph_core::{MultiAssetRecoveryPackage, VaultAsset};
use std::{
    fs,
    process::{Child, Command as Process, Stdio},
};

pub(crate) struct Harness {
    child: Option<Child>,
    config: Config,
    config_path: PathBuf,
    digest: String,
    edge_id: String,
    baseline_revision: u64,
    reorg: serde_json::Value,
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn spawn(path: &Path, log: &Path) -> Result<Child> {
    let file = fs::File::create(log)?;
    Ok(Process::new(std::env::current_exe()?)
        .args(["devnet", "--devnet-only", "shadow-service", "--config"])
        .arg(path)
        .arg("run")
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(file)
        .spawn()?)
}
impl Harness {
    fn wait(&mut self, predicate: impl Fn(&Self) -> Result<bool>) -> Result<()> {
        let start = Instant::now();
        loop {
            ensure!(
                self.child
                    .as_mut()
                    .is_some_and(|c| c.try_wait().ok().flatten().is_none()),
                "shadow worker exited during native acceptance"
            );
            if predicate(self)? {
                return Ok(());
            }
            ensure!(
                start.elapsed() < Duration::from_secs(40),
                "shadow acceptance observation timed out"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    fn mirrors(&self) -> Result<Vec<morph_fiber_adapter::MirroredFiberEdge>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let client = FiberHookClient::new(
            &self.config.provider_rpc_url,
            None,
            &self.config.callback_endpoint,
            self.config.policy.clone(),
        )?;
        Ok(runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), client.list_edges()).await
        })??)
    }
    fn disabled(&self) -> Result<bool> {
        Ok(self.mirrors()?.iter().any(|m| {
            m.morph_edge_id == self.edge_id && m.state == MirrorState::Disabled && !m.forwarding
        }))
    }
    pub(crate) fn finish(&mut self) -> Result<serde_json::Value> {
        self.wait(|this| this.disabled())?;
        ensure!(
            !probe(&self.config, &self.digest).ready,
            "spent custody remained ready"
        );
        let final_mirrors = self.mirrors()?;
        ensure!(
            final_mirrors.iter().all(|m| !m.forwarding),
            "shadow enabled forwarding"
        );
        Ok(
            serde_json::json!({"registered":true,"morph_process_restarted":true,"fiber_process_restart_acknowledged":true,
            "journal_busy_disabled":true,"journal_released_reactivated":true,"spent_custody_disabled":true,
            "orphaned_activation_disabled":true,"exact_activation_replay_reactivated":true,"reorg_preserved_backend_authority":true,
            "reorg":self.reorg,"provider_revision_before_restart":self.baseline_revision.to_string(),"forwarding":false,"final_mirrors":final_mirrors}),
        )
    }
}
pub(crate) fn start(
    rpc: &crate::rpc::CkbRpcClient,
    options: &MultiAssetSmokeOptions,
    session: &Path,
    peer_session: &Path,
    recovery: &MultiAssetRecoveryPackage,
    state_point: &ckb_types::packed::OutPoint,
    endpoint: &str,
) -> Result<Harness> {
    let directory = options.store_dir.join("shadow-service");
    crate::persistence::create_private_directories(&directory)?;
    let participants = [&options.alice_private_key, &options.bob_private_key].map(
        |secret| -> Result<ChannelParticipant> {
            Ok(ChannelParticipant {
                node_id: morph_core::blake2b256(&devnet::k256_pubkey(&devnet::k256_signing_key(
                    secret,
                )?)),
                settlement_lock_hash: devnet::secp256k1_lock(&devnet::parse_privkey(secret)?)?
                    .calc_script_hash()
                    .unpack(),
            })
        },
    );
    let [left, right] = participants;
    let participants = [left?, right?];
    let VaultAsset::Xudt(type_script_hash) = recovery.manifest.vaults[0].asset else {
        return Err(anyhow!("typed native custody required"));
    };
    let asset = GatewayAsset::Xudt {
        ckb_genesis_hash: recovery.state.header.chain_id,
        type_script_hash,
    };
    let observation = shadow::capture(session, participants.clone(), asset.clone(), None)?
        .observe(Duration::from_secs(10))?;
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../integrations/fiber-shadow/manifest.json"
    ))?;
    let config = Config {
        schema: "morph.shadow_service.v1".into(),
        store: directory.join("coordinator.db"),
        chain_rpc_url: rpc.endpoint().into(),
        contracts_dir: options.contracts_dir.clone(),
        deployment_id: format!("0x{}", hex::encode(observation.edge.deployment_id)),
        min_confirmations: 4,
        provider_rpc_url: endpoint.into(),
        callback_endpoint: "http://127.0.0.1:1/non-forwarding".into(),
        bearer_token_file: None,
        policy: HookPolicy {
            fiber_commit: manifest["fiber_revision"]
                .as_str()
                .ok_or_else(|| anyhow!("missing pin"))?
                .into(),
            patch_hash: format!(
                "0x{}",
                manifest["patch_sha256"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing patch pin"))?
            ),
            ckb_genesis_hash: format!("0x{}", hex::encode(recovery.state.header.chain_id)),
        },
        sources: vec![Source {
            session: session.to_path_buf(),
            participants,
            asset,
            reservation: None,
        }],
        poll_ms: 250,
        observe_budget_ms: 3000,
        reconcile_budget_ms: 2000,
        lease_ms: 6000,
    };
    let config_path = directory.join("config.json");
    write_private_atomic(&config_path, &serde_json::to_vec(&config)?)?;
    let (_, digest) = load(&config_path)?;
    let mut h = Harness {
        child: Some(spawn(&config_path, &directory.join("worker-first.log"))?),
        config,
        config_path,
        digest,
        edge_id: format!("0x{}", hex::encode(observation.edge.edge_id)),
        baseline_revision: 0,
        reorg: serde_json::Value::Null,
    };
    h.wait(|this| Ok(probe(&this.config, &this.digest).ready))?;
    let initial = h.mirrors()?;
    h.baseline_revision = initial
        .iter()
        .find(|m| m.morph_edge_id == h.edge_id)
        .ok_or_else(|| anyhow!("registered edge missing"))?
        .provider_revision;
    // Actual Morph process loss, then actual Fiber restart by the isolated harness.
    let mut child = h.child.take().ok_or_else(|| anyhow!("worker missing"))?;
    child.kill()?;
    child.wait()?;
    write_private_atomic(
        &directory.join("provider-restart.request"),
        b"restart dedicated Fiber now\n",
    )?;
    let deadline = Instant::now() + Duration::from_secs(150);
    while !directory.join("provider-restart.ack").is_file() {
        ensure!(
            Instant::now() < deadline,
            "provider restart acknowledgement missing"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Wait out the real saved lease without rewriting the health file.
    std::thread::sleep(Duration::from_millis(h.config.lease_ms));
    ensure!(
        !probe(&h.config, &h.digest).ready,
        "dead worker remained fresh"
    );
    h.child = Some(spawn(
        &h.config_path,
        &directory.join("worker-restarted.log"),
    )?);
    h.wait(|this| Ok(probe(&this.config, &this.digest).ready))?;
    ensure!(
        h.mirrors()?
            .iter()
            .any(|m| m.morph_edge_id == h.edge_id && m.provider_revision == h.baseline_revision),
        "restart reapplied registration"
    );
    let held =
        try_lock_private_path(session)?.ok_or_else(|| anyhow!("cannot hold acceptance journal"))?;
    h.wait(|this| this.disabled())?;
    ensure!(
        !probe(&h.config, &h.digest).ready,
        "busy authority remained ready"
    );
    drop(held);
    h.wait(|this| Ok(probe(&this.config, &this.digest).ready))?;
    ensure!(
        h.mirrors()?.iter().any(|m| m.morph_edge_id == h.edge_id
            && m.state == MirrorState::Active
            && m.provider_revision > h.baseline_revision),
        "released authority did not reactivate"
    );
    // Orphan actual live custody while the worker continues. Replaying the
    // exact activation is permissionless; no participant key is requested.
    let (activation, inclusion) =
        crate::rpc::canonical_transaction(rpc, state_point.tx_hash().unpack(), 4)?;
    let predecessor = rpc
        .block_hash_at(
            inclusion
                .block_number
                .checked_sub(1)
                .ok_or_else(|| anyhow!("activation has no predecessor"))?,
        )?
        .ok_or_else(|| anyhow!("activation predecessor missing"))?;
    let journals = [fs::read(session)?, fs::read(peer_session)?];
    rpc.truncate(predecessor)?;
    ensure!(
        rpc.transaction(state_point.tx_hash().unpack())?
            .tx_status
            .status
            != ckb_jsonrpc_types::Status::Committed,
        "activation remained canonical after rollback"
    );
    h.wait(|this| this.disabled())?;
    ensure!(
        !probe(&h.config, &h.digest).ready,
        "orphaned custody remained ready"
    );
    let submitted = devnet::send_and_mine(rpc, activation.into_view(), 16);
    if submitted.is_err() {
        // A devnet truncate can retain this exact transaction in its pool.
        let status = rpc
            .transaction(state_point.tx_hash().unpack())?
            .tx_status
            .status;
        ensure!(
            matches!(
                status,
                ckb_jsonrpc_types::Status::Pending
                    | ckb_jsonrpc_types::Status::Proposed
                    | ckb_jsonrpc_types::Status::Committed
            ),
            "exact activation replay failed: {}",
            submitted
                .err()
                .ok_or_else(|| anyhow!("missing replay error"))?
        );
        devnet::mine_blocks_until_committed(rpc, state_point.tx_hash().unpack(), 16)?;
    }
    let (_, replayed) = crate::rpc::canonical_transaction(rpc, state_point.tx_hash().unpack(), 1)?;
    ensure!(
        replayed.block_hash != inclusion.block_hash,
        "replay did not establish a different canonical inclusion"
    );
    h.reorg = serde_json::json!({"first_inclusion":inclusion,"replayed_inclusion":replayed,"state_out_point":devnet::format_out_point(state_point)});
    devnet::multi_asset_splice_acceptance::mine_depth(rpc, replayed.block_number, 4)?;
    ensure!(
        [fs::read(session)?, fs::read(peer_session)?] == journals,
        "reorg changed signer journals"
    );
    let (funding, _) =
        crate::rpc::canonical_transaction(rpc, recovery.outpoints[0].tx_hash.into(), 4)?;
    let package = crate::multi_asset_packages::StoredMultiAssetPackage::from_recovery(
        recovery,
        &funding.raw().cell_deps().into_iter().collect::<Vec<_>>(),
    )?;
    let package_path = directory.join("reorg-recovery.json");
    write_private_atomic(&package_path, &serde_json::to_vec(&package)?)?;
    for (path, before) in [session, peer_session].into_iter().zip(journals) {
        crate::multi_asset_session::run(
            path,
            crate::multi_asset_session::SessionCommand::RefreshChain {
                state_out_point: devnet::format_out_point(state_point),
                package: package_path.clone(),
            },
        )?;
        let old: serde_json::Value = serde_json::from_slice(&before)?;
        let current: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            old["backend"] == current["backend"],
            "chain refresh changed signing authority"
        );
    }
    h.wait(|this| Ok(probe(&this.config, &this.digest).ready))?;
    ensure!(
        h.mirrors()?
            .iter()
            .any(|m| m.morph_edge_id == h.edge_id && m.state == MirrorState::Active),
        "exact replay changed edge identity"
    );
    Ok(h)
}
