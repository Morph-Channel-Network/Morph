//! Canonical admission for diagnostic provider edges. No provider response,
//! supplied cell bytes, signer snapshot or claimed confirmation count is trusted.
use super::*;
use crate::factory_child_origin::FactoryChildOrigin;
use crate::multi_asset_packages::{StoredMultiAssetPackage, decode_hex, read_bounded_json};
use crate::multi_asset_splice_transaction::SpliceDraft;
use morph_core::{
    ChannelParticipant, FactoryOriginEvidence, FactoryRightReservation, GatewayAsset,
    MaterializedCellEvidence, MaterializedChannelEvidence, ProviderEdgeDescriptor,
    SovereignEdgeRegistry, TrustedMorphDeployment, TrustedScriptIdentity,
};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Candidate {
    pub schema: String,
    pub package: StoredMultiAssetPackage,
    pub state_out_point: String,
    pub participants: [ChannelParticipant; 2],
    pub asset: GatewayAsset,
    #[serde(deserialize_with = "crate::persistence::required_option")]
    pub reservation: Option<FactoryRightReservation>,
    pub origin: Origin,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Origin {
    Root {},
    Factory {
        history: Box<FactoryChildOrigin>,
    },
    Splice {
        old: Box<StoredMultiAssetPackage>,
        initial: Box<StoredMultiAssetPackage>,
        transaction_hex: String,
        #[serde(deserialize_with = "crate::persistence::required_option")]
        factory_history: Option<Box<FactoryChildOrigin>>,
    },
}

pub(crate) struct Observation {
    pub edge: ProviderEdgeDescriptor,
    pub tip_hash: String,
    pub tip_number: u64,
    pub confirmations: u64,
}
impl Observation {
    pub fn public(&self) -> Result<serde_json::Value> {
        let edge = morph_fiber_adapter::FiberExternalEdge::try_from(&self.edge)?;
        Ok(
            serde_json::json!({"schema":"morph.shadow_observation.v1","forwarding":false,
            "verified_tip_hash":self.tip_hash,"verified_tip_number":self.tip_number.to_string(),
            "confirmations":self.confirmations.to_string(),"edge":edge}),
        )
    }
}

pub(crate) fn run(
    endpoint: &str,
    request: &Path,
    contracts: &Path,
    depth: u64,
    budget_ms: u64,
) -> Result<serde_json::Value> {
    ensure!(
        (100..=10_000).contains(&budget_ms),
        "shadow RPC budget outside bounds"
    );
    let candidate: Candidate = read_bounded_json(request, MAX_REQUEST_BYTES)?;
    let rpc = CkbRpcClient::new_signer(endpoint, Duration::from_millis(budget_ms))?;
    observe(&rpc, &candidate, contracts, depth)?.public()
}

fn identity(directory: &Path, name: &str) -> Result<TrustedScriptIdentity> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(directory.join(name))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4 * 1024 * 1024,
        "approved artifact outside bounds"
    );
    Ok(TrustedScriptIdentity {
        code_hash: blake2b_256(&bytes),
        hash_type: 2,
    })
}
fn deployment(directory: &Path, genesis: [u8; 32]) -> Result<TrustedMorphDeployment> {
    Ok(TrustedMorphDeployment {
        ckb_genesis_hash: genesis,
        state_type: identity(directory, "morph-state-type")?,
        state_lock: identity(directory, "morph-state-lock")?,
        vault_lock: identity(directory, "morph-vault-lock")?,
        factory_type: identity(directory, "morph-factory-type")?,
        factory_vault_lock: identity(directory, "morph-factory-vault-lock")?,
    })
}
fn trusted(script: &[u8], identity: &TrustedScriptIdentity) -> Result<()> {
    let script = Script::from_slice(script)?;
    ensure!(
        script.code_hash().as_slice() == identity.code_hash
            && script.hash_type().as_slice() == [identity.hash_type],
        "unapproved historical script"
    );
    Ok(())
}
fn check_output(
    cell: &MaterializedCellEvidence,
    lock: &[u8],
    ty: Option<&[u8]>,
    capacity: u64,
    data: &[u8],
) -> Result<()> {
    ensure!(
        cell.lock == lock
            && cell.type_script.as_deref() == ty
            && cell.capacity == capacity
            && cell.data == data,
        "canonical source differs from claimed custody"
    );
    Ok(())
}

/// Fetch full bytes from a canonical block, optionally require the same live
/// output. Historical parent custody is expected to be spent, not kept alive.
fn cell(
    rpc: &CkbRpcClient,
    point: &OutPoint,
    depth: u64,
    live: bool,
) -> Result<MaterializedCellEvidence> {
    let (tx, _) = crate::rpc::canonical_transaction(rpc, point.tx_hash().unpack(), depth)?;
    let index = u32::from(point.index()) as usize;
    let output = tx
        .raw()
        .outputs()
        .get(index)
        .ok_or_else(|| anyhow!("canonical cell output missing"))?;
    let data = tx
        .raw()
        .outputs_data()
        .get(index)
        .ok_or_else(|| anyhow!("canonical cell data missing"))?
        .raw_data();
    if live {
        let current = load_canonical_live_cell(rpc, point.clone())?;
        ensure!(
            current.output == output && current.data == data,
            "live cell differs from canonical block"
        );
    }
    Ok(MaterializedCellEvidence {
        out_point: morph_core::CkbOutPoint {
            tx_hash: point.tx_hash().unpack(),
            index: index as u32,
        },
        lock: output.lock().as_slice().to_vec(),
        type_script: output.type_().to_opt().map(|s| s.as_slice().to_vec()),
        capacity: output.capacity().unpack(),
        data: data.to_vec(),
    })
}
fn historical_vaults(
    rpc: &CkbRpcClient,
    manifest: &morph_core::MultiAssetManifest,
    points: &[morph_core::MultiAssetOutPoint],
    lock: &[u8],
    types: &[morph_core::MultiAssetTypeScript],
    depth: u64,
) -> Result<()> {
    ensure!(
        manifest.vaults.len() == points.len() && (1..=8).contains(&points.len()),
        "historical custody set mismatch"
    );
    for (vault, point) in manifest.vaults.iter().zip(points) {
        let actual = cell(
            rpc,
            &OutPoint::new(point.tx_hash.pack(), point.index),
            depth,
            false,
        )?;
        let (ty, data) = match vault.asset {
            VaultAsset::Ckb => (None, Vec::new()),
            VaultAsset::Xudt(hash) => (
                Some(
                    types
                        .iter()
                        .find(|t| t.type_hash == hash)
                        .ok_or_else(|| anyhow!("missing historical asset script"))?
                        .script
                        .as_slice(),
                ),
                vault.value.amount.to_le_bytes().to_vec(),
            ),
        };
        check_output(&actual, lock, ty, vault.value.capacity()?, &data)?;
    }
    Ok(())
}
fn factory_history(
    rpc: &CkbRpcClient,
    history: &FactoryChildOrigin,
    target_channel: &[u8; 32],
    deployment: &TrustedMorphDeployment,
    directory: &Path,
    depth: u64,
) -> Result<FactoryOriginEvidence> {
    let (request, tx, initial) = history.decode()?;
    ensure!(
        &initial.state.header.channel_id == target_channel,
        "Factory child history targets another channel"
    );
    crate::factory_artifacts::validate_request_artifacts(&request, directory)?;
    let (actual, _) = crate::rpc::canonical_transaction(rpc, tx.calc_tx_hash().unpack(), depth)?;
    ensure!(
        actual.as_slice() == tx.as_slice(),
        "Factory history differs from canonical transaction"
    );
    let source = request
        .source
        .as_ref()
        .ok_or_else(|| anyhow!("Factory source missing"))?;
    trusted(&source.state_type, &deployment.factory_type)?;
    trusted(&source.state_lock, &deployment.state_lock)?;
    trusted(&source.vault_lock, &deployment.factory_vault_lock)?;
    let actual = cell(
        rpc,
        &OutPoint::new(
            source.state_out_point.tx_hash.pack(),
            source.state_out_point.index,
        ),
        depth,
        false,
    )?;
    check_output(
        &actual,
        &source.state_lock,
        Some(&source.state_type),
        source.state_carrier_capacity,
        &source.header,
    )?;
    historical_vaults(
        rpc,
        &source.manifest,
        &source.vault_outpoints,
        &source.vault_lock,
        &source.type_scripts,
        depth,
    )?;
    ensure!(
        initial.state.header.chain_id == deployment.ckb_genesis_hash,
        "Factory origin network mismatch"
    );
    Ok(FactoryOriginEvidence {
        source: source.clone(),
        members: request.members()?,
    })
}

pub(crate) fn observe(
    rpc: &CkbRpcClient,
    candidate: &Candidate,
    directory: &Path,
    depth: u64,
) -> Result<Observation> {
    ensure!(
        candidate.schema == "morph.shadow_candidate.v1" && (1..=1024).contains(&depth),
        "unsupported shadow candidate or depth"
    );
    ensure!(
        !matches!(candidate.asset, GatewayAsset::Rgbpp(_)),
        "RGB++ needs independent two-chain admission"
    );
    let current = candidate.package.recovery()?;
    let genesis = rpc
        .genesis_block_hash()?
        .ok_or_else(|| anyhow!("genesis unavailable"))?;
    ensure!(
        genesis.0 == current.state.header.chain_id,
        "shadow network mismatch"
    );
    let trusted = deployment(directory, genesis.0)?;
    let tip = rpc.tip_header()?;
    let factory;
    let context = match &candidate.origin {
        Origin::Root {} => {
            factory = None;
            super::multi_asset_splice_operator::confirm_root_context(
                rpc,
                &current,
                &candidate.state_out_point,
                depth,
                directory,
            )?
            .0
        }
        Origin::Factory { history } => {
            factory = Some(factory_history(
                rpc,
                history,
                &current.state.header.channel_id,
                &trusted,
                directory,
                depth,
            )?);
            let (request, transaction, initial) = history.decode()?;
            super::multi_asset_splice_operator::confirm_factory_child_context(
                rpc,
                super::multi_asset_splice_operator::FactoryChildContext {
                    request: &request,
                    child_index: history.child_index,
                    initial: &initial,
                    current: &current,
                    transaction: &transaction,
                    state_out_point: &candidate.state_out_point,
                    min_confirmations: depth,
                    contracts_dir: directory,
                },
            )?
        }
        Origin::Splice {
            old,
            initial,
            transaction_hex,
            factory_history: history,
        } => {
            let old = old.recovery()?;
            let initial = initial.recovery()?;
            let tx = ckb_types::packed::Transaction::from_slice(&decode_hex(
                transaction_hex,
                256 * 1024,
            )?)?;
            let (_, plan, _) = SpliceDraft::from_signed_transaction(&old, &initial, &tx)?;
            let old_state = cell(
                rpc,
                &OutPoint::new(
                    plan.old_state_outpoint.tx_hash.pack(),
                    plan.old_state_outpoint.index,
                ),
                depth,
                false,
            )?;
            self::trusted(&old.scripts.state_type, &trusted.state_type)?;
            self::trusted(&old.scripts.state_lock, &trusted.state_lock)?;
            self::trusted(&old.scripts.vault_lock, &trusted.vault_lock)?;
            // The old on-chain State may precede its latest signed allocation.
            ensure!(
                old_state.lock == old.scripts.state_lock
                    && old_state.type_script.as_ref() == Some(&old.scripts.state_type)
                    && old_state.capacity == old.state_carrier_capacity,
                "splice source authority mismatch"
            );
            let source =
                morph_script_common::multi_asset::MultiAssetStateHeader::parse(&old_state.data)
                    .map_err(|_| anyhow!("invalid old State"))?;
            let encoded = old.state.encode()?;
            let saved = morph_script_common::multi_asset::MultiAssetStateHeader::parse(&encoded)
                .map_err(|_| anyhow!("invalid saved State"))?;
            ensure!(
                source.vaults_are_bound()
                    && source.same_context_except_progress(&saved)
                    && source.state_number() <= saved.state_number()
                    && (source.state_number() != saved.state_number()
                        || source.as_bytes() == saved.as_bytes()),
                "splice source context mismatch"
            );
            historical_vaults(
                rpc,
                &old.manifest,
                &old.outpoints,
                &old.scripts.vault_lock,
                &old.scripts.type_scripts,
                depth,
            )?;
            factory = history
                .as_ref()
                .map(|h| {
                    factory_history(
                        rpc,
                        h,
                        &current.state.header.channel_id,
                        &trusted,
                        directory,
                        depth,
                    )
                })
                .transpose()?;
            super::multi_asset_splice_operator::confirm_context(
                rpc,
                super::multi_asset_splice_operator::ConfirmationOptions {
                    old: &old,
                    initial_recovery: &initial,
                    current: &current,
                    transaction: &tx,
                    state_out_point: &candidate.state_out_point,
                    min_confirmations: depth,
                    contracts_dir: directory,
                },
            )?
        }
    };
    let state = cell(
        rpc,
        &parse_out_point(&candidate.state_out_point)?,
        depth,
        true,
    )?;
    let header = morph_script_common::multi_asset::MultiAssetStateHeader::parse(&state.data)
        .map_err(|_| anyhow!("invalid live State"))?;
    ensure!(
        header.phase() == PHASE_ACTIVE && header.vaults_are_bound(),
        "settling or unbound channel cannot activate a shadow edge"
    );
    let vaults = current
        .outpoints
        .iter()
        .map(|p| cell(rpc, &OutPoint::new(p.tx_hash.pack(), p.index), depth, true))
        .collect::<Result<Vec<_>>>()?;
    let tip_number = tip.number_value()?;
    let newest = context.funding.block_number.max(context.state.block_number);
    let confirmations = tip_number
        .checked_sub(newest)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| anyhow!("custody above observation tip"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut registry = SovereignEdgeRegistry::default();
    if let Some(reservation) = &candidate.reservation {
        let id = registry.reserve(reservation.clone(), now)?;
        registry.begin_materialisation(&id)?;
    }
    let evidence = MaterializedChannelEvidence {
        recovery: current,
        state,
        vaults,
        participants: candidate.participants.clone(),
        asset: candidate.asset.clone(),
        factory_reservation_id: candidate.reservation.as_ref().map(|r| r.reservation_id),
        factory_origin: factory,
        committed_block_hash: parse_h256(&context.state.block_hash)?.0,
        committed_block_number: context.state.block_number,
        confirmations,
        rgbpp_proof_commitment: None,
    };
    let edge = registry.activate(evidence, &trusted, depth, now)?;
    ensure!(
        rpc.tip_header()?.hash == tip.hash,
        "chain changed during shadow admission"
    );
    rpc.ensure_deadline()?;
    Ok(Observation {
        edge,
        tip_hash: tip.hash,
        tip_number,
        confirmations,
    })
}

#[cfg(test)]
mod tests;
