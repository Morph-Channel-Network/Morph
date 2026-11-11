//! Read-only input for canonical shadow observation. A saved package is not an
//! authority-selection mechanism: capture the current journal under its stable
//! lock, release it before RPC, and compare again before publishing a result.
use super::*;
use crate::devnet::shadow_observer::{Candidate, Observation, Origin};
use morph_core::{ChannelParticipant, FactoryRightReservation, GatewayAsset};

const MAX_ANCESTRY: usize = 32;

pub(crate) struct Snapshot {
    path: PathBuf,
    fingerprint: Bytes32,
    candidate: Candidate,
    lineage: SessionLineage,
    pub draining: bool,
}

fn read_locked(path: &Path) -> Result<Vec<u8>> {
    let _lock = crate::persistence::try_lock_private_path(path)?
        .ok_or_else(|| anyhow!("shadow source journal is busy"))?;
    read_limited(path)
}

/// Follow immutable, hash-pinned ancestry; never load another mutable authority.
/// The bound is deliberate: exceeding it quarantines observation, not recovery.
fn factory_history(
    session: &StoredSession,
    depth: usize,
) -> Result<Option<Box<crate::factory_child_origin::FactoryChildOrigin>>> {
    ensure!(
        depth < MAX_ANCESTRY,
        "shadow ancestry exceeds observation bound"
    );
    session.package()?;
    let lineage = session
        .lineage
        .as_ref()
        .ok_or_else(|| anyhow!("shadow ancestry lacks confirmed provenance"))?;
    match &lineage.origin {
        SessionOrigin::Root { .. } => Ok(None),
        SessionOrigin::Factory {
            origin_evidence,
            origin_evidence_hash,
        } => Ok(Some(Box::new(crate::factory_child_origin::read(
            origin_evidence,
            origin_evidence_hash,
        )?))),
        SessionOrigin::Splice { .. } => {
            let ancestor = session
                .retired()?
                .ok_or_else(|| anyhow!("shadow ancestry missing retired context"))?;
            factory_history(&ancestor, depth + 1)
        }
    }
}

pub(crate) fn capture(
    path: &Path,
    participants: [ChannelParticipant; 2],
    asset: GatewayAsset,
    reservation: Option<FactoryRightReservation>,
) -> Result<Snapshot> {
    ensure!(path.is_absolute(), "shadow session path must be absolute");
    let bytes = read_locked(path)?;
    let session: StoredSession = serde_json::from_slice(&bytes)?;
    let package = session.package()?;
    let lineage = session
        .lineage
        .clone()
        .ok_or_else(|| anyhow!("shadow source requires confirmed session lineage"))?;
    let origin = match &lineage.origin {
        SessionOrigin::Root { .. } => Origin::Root {},
        SessionOrigin::Factory {
            origin_evidence,
            origin_evidence_hash,
        } => Origin::Factory {
            history: Box::new(crate::factory_child_origin::read(
                origin_evidence,
                origin_evidence_hash,
            )?),
        },
        SessionOrigin::Splice { .. } => {
            let retired = session
                .retired()?
                .ok_or_else(|| anyhow!("shadow source missing retired context"))?;
            let plan = retired
                .backend
                .splice_proposal()
                .ok_or_else(|| anyhow!("shadow source missing splice intent"))?;
            let initial = StoredMultiAssetPackage::with_dependency_records(
                &plan.initial_recovery(retired.backend.current())?,
                session.cell_deps.clone(),
            )?;
            Origin::Splice {
                old: Box::new(retired.package()?),
                initial: Box::new(initial),
                transaction_hex: canonical_hex(retired.signed_splice()?.as_slice()),
                factory_history: factory_history(&retired, 0)?,
            }
        }
    };
    Ok(Snapshot {
        path: path.to_path_buf(),
        fingerprint: blake2b256(&bytes),
        candidate: Candidate {
            schema: "morph.shadow_candidate.v1".into(),
            package,
            state_out_point: lineage.evidence.state_out_point.clone(),
            participants,
            asset,
            reservation,
            origin,
        },
        lineage,
        draining: session.backend.proposal().is_some()
            || session.backend.splice_proposal().is_some()
            || !session.backend.close_attempts().is_empty(),
    })
}

impl Snapshot {
    pub(crate) fn observe_pinned(
        &self,
        endpoint: &str,
        contracts: &Path,
        depth: u64,
        budget: std::time::Duration,
    ) -> Result<Observation> {
        ensure!(
            crate::multi_asset_session_chain::rpc_endpoint(endpoint)?
                == crate::multi_asset_session_chain::rpc_endpoint(&self.lineage.rpc_url)?
                && contracts == self.lineage.contracts_dir
                && depth >= self.lineage.min_confirmations,
            "shadow service differs from confirmed session guard"
        );
        self.observe_at(endpoint, contracts, depth, budget)
    }
    pub(crate) fn ensure_current(&self) -> Result<()> {
        ensure!(
            blake2b256(&read_locked(&self.path)?) == self.fingerprint,
            "shadow source changed during observation"
        );
        Ok(())
    }
    pub(crate) fn observe(&self, budget: std::time::Duration) -> Result<Observation> {
        self.observe_at(
            &self.lineage.rpc_url,
            &self.lineage.contracts_dir,
            self.lineage.min_confirmations,
            budget,
        )
    }
    fn observe_at(
        &self,
        endpoint: &str,
        contracts: &Path,
        depth: u64,
        budget: std::time::Duration,
    ) -> Result<Observation> {
        ensure!(
            (std::time::Duration::from_millis(100)..=std::time::Duration::from_secs(10))
                .contains(&budget),
            "shadow RPC budget outside bounds"
        );
        self.ensure_current()?;
        let rpc = crate::rpc::CkbRpcClient::new_signer(endpoint, budget)?;
        let observation =
            crate::devnet::shadow_observer::observe(&rpc, &self.candidate, contracts, depth)?;
        self.ensure_current()?;
        rpc.ensure_deadline()?;
        Ok(observation)
    }
}
