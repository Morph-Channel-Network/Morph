//! Public root preparation and per-funder wallet signing. No issuance and no
//! participant keys belong in this module; every funding input is explicit.
use super::multi_asset_operator as operator;
use super::*;
use crate::multi_asset_funding::{MAX_FUNDING_BYTES, validate_root_funding};
use crate::multi_asset_packages::{
    canonical_hex, decode_dependency_records, read_package, write_package,
};
use crate::multi_asset_root_transaction::{
    MAX_TERMS_BYTES, PreparedRoot, RootAuthorityHashes, RootFundingCell, RootFundingTerms,
};
use crate::multi_asset_splice_transaction::{TransactionKind, write_transaction};
use serde_json::{Value, json};
use std::io::Read;

pub struct PrepareOptions {
    pub terms: PathBuf,
    pub contracts_dir: PathBuf,
    pub max_fee: u64,
    pub output: PathBuf,
}
pub struct SignOptions {
    pub terms: PathBuf,
    pub transaction: PathBuf,
    pub package: PathBuf,
    pub contracts_dir: PathBuf,
    pub max_fee: u64,
    pub store_dir: PathBuf,
    pub private_key: String,
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= max,
        "root funding artifact exceeds byte limit"
    );
    Ok(bytes)
}
struct ResolvedRoot {
    terms: RootFundingTerms,
    prepared: PreparedRoot,
    checkpoint: crate::rpc::HeaderView,
}
fn resolve(
    rpc: &CkbRpcClient,
    path: &Path,
    contracts_dir: &Path,
    max_fee: u64,
) -> Result<ResolvedRoot> {
    ensure!(max_fee > 0, "max_fee must be positive");
    let terms: RootFundingTerms = serde_json::from_slice(&read(path, MAX_TERMS_BYTES)?)?;
    let points = terms.points()?;
    let checkpoint = rpc.tip_header()?;
    let genesis = rpc
        .genesis_block_hash()?
        .ok_or_else(|| anyhow!("canonical genesis hash unavailable"))?;
    let hash =
        |name: &str| -> Result<[u8; 32]> { Ok(blake2b_256(&fs::read(contracts_dir.join(name))?)) };
    let authority = RootAuthorityHashes {
        state_type: hash("morph-state-type")?,
        state_lock: hash("morph-state-lock")?,
        vault_lock: hash("morph-vault-lock")?,
    };
    let deps = decode_dependency_records(&terms.cell_deps)?;
    let resolved = operator::live_dependencies(rpc, &deps)?;
    let mut inputs = Vec::new();
    let mut cells = Vec::new();
    for point in points {
        ensure!(
            !resolved.out_points.contains(point.as_slice())
                && !deps.iter().any(|dep| dep.out_point() == point),
            "root consumes a recovery code dependency"
        );
        let cell = load_canonical_live_cell(rpc, point.clone())?;
        for script in std::iter::once(cell.output.lock()).chain(cell.output.type_().to_opt()) {
            ensure!(
                resolved
                    .cells
                    .iter()
                    .any(|code| operator::code_matches(&script, code)),
                "root input script code unavailable"
            );
        }
        cells.push(RootFundingCell {
            point,
            output: cell.output.clone(),
            data: cell.data.clone(),
        });
        inputs.push(cell);
    }
    let prepared = terms.build(genesis.0, authority, &cells, max_fee)?;
    let creation = &prepared.creation;
    let evidence = morph_core::encode_multi_asset_witness(
        &creation.manifest,
        &creation.settlement,
        &[],
        &creation.scripts,
    )?;
    let witness = morph_script_common::multi_asset::MultiAssetWitness::parse(&evidence)
        .map_err(|error| anyhow!("invalid root creation evidence: {error:?}"))?;
    let first = inputs
        .first()
        .ok_or_else(|| anyhow!("missing funding input"))?;
    operator::validate_resolved_code(
        contracts_dir,
        &witness,
        &resolved.cells,
        &first.output.lock(),
    )?;
    let registered = creation
        .scripts
        .type_scripts
        .iter()
        .map(|entry| entry.type_hash)
        .collect();
    ensure!(
        operator::validate_funding_balances(
            &prepared.draft.transaction()?,
            &inputs,
            &registered,
            max_fee
        )? == prepared.fee,
        "constructed fee differs from declared funder shares"
    );
    ensure!(
        super::multi_asset_splice_operator::canonical_checkpoint(rpc, &checkpoint)?,
        "chain reorganized during root construction"
    );
    Ok(ResolvedRoot {
        terms,
        prepared,
        checkpoint,
    })
}
pub fn prepare(rpc: &CkbRpcClient, options: PrepareOptions) -> Result<Value> {
    let resolved = resolve(rpc, &options.terms, &options.contracts_dir, options.max_fee)?;
    let draft = &resolved.prepared.draft;
    let (creation, exit) = draft.evidence()?;
    let bytes = serde_json::to_vec_pretty(draft)?;
    let _lock = crate::packages::try_lock_private_path(&options.output)?
        .ok_or_else(|| anyhow!("root draft artifact is busy"))?;
    if options.output.exists() {
        ensure!(
            read(&options.output, 2 * MAX_FUNDING_BYTES + 4096)? == bytes,
            "root draft output already holds another intent"
        );
    } else {
        crate::packages::write_private_atomic(&options.output, &bytes)?;
    }
    let (creation_digest, exit_digest) = draft.digests()?;
    Ok(
        json!({"schema":"morph.multi_asset_root_preparation.v1","draft":options.output,
        "transaction_hash":canonical_hex(draft.transaction()?.calc_tx_hash().as_slice()),"chain_id":canonical_hex(&creation.state.header.chain_id),
        "channel_id":canonical_hex(&creation.state.header.channel_id),"funding_context_id":canonical_hex(&exit.state.funding_context_id()?),
        "creation_digest":canonical_hex(&creation_digest),"exit_digest":canonical_hex(&exit_digest),"fee":resolved.prepared.fee.to_string(),
        "state_carrier_capacity":creation.state_carrier_capacity.to_string(),"vault_count":creation.manifest.vaults.len(),
        "payouts":crate::multi_asset_session::payout_summary(&creation.settlement),"funders":resolved.terms.funders,
        "requires_participant_signatures":true,"requires_wallet_signatures":true}),
    )
}
pub fn sign_wallet(rpc: &CkbRpcClient, options: SignOptions) -> Result<Value> {
    let resolved = resolve(rpc, &options.terms, &options.contracts_dir, options.max_fee)?;
    let transaction = ckb_types::packed::Transaction::from_slice(&read(
        &options.transaction,
        MAX_FUNDING_BYTES,
    )?)?;
    ensure!(
        transaction.raw().as_slice() == resolved.prepared.draft.transaction()?.raw().as_slice(),
        "wallet signing body differs from exact approved funding terms"
    );
    let stored = read_package(&options.package)?;
    let recovery = stored.recovery()?;
    validate_root_funding(&recovery, &transaction)?;
    ensure!(
        crate::multi_asset_packages::StoredMultiAssetPackage::from_recovery(
            &recovery,
            &transaction
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>()
        )? == stored,
        "wallet exit dependencies differ from exact funding body"
    );
    let key =
        parse_privkey(&options.private_key).map_err(|_| anyhow!("invalid funding wallet key"))?;
    let public = canonical_hex(&compressed_pubkey(&key)?);
    let mut offset = 0;
    let mut group = None;
    for funder in &resolved.terms.funders {
        if funder.pubkey == public {
            group = Some((offset..offset + funder.inputs.len()).collect::<Vec<_>>());
        }
        offset += funder.inputs.len();
    }
    let group = group.ok_or_else(|| anyhow!("wallet key is not a declared funder"))?;
    let package = write_package(&options.store_dir, &stored)?;
    ensure!(
        super::multi_asset_splice_operator::canonical_checkpoint(rpc, &resolved.checkpoint)?,
        "chain reorganized before wallet signing"
    );
    let signed = super::multi_asset::sign_group(transaction.into_view(), &key, &group)?;
    ensure!(
        signed.data().as_slice().len() <= MAX_FUNDING_BYTES,
        "signed root transaction exceeds byte limit"
    );
    let path = write_transaction(
        &options
            .store_dir
            .join("wallet-signatures")
            .join(hex::encode(blake2b_256(signed.data().as_slice()))),
        &signed.data(),
        TransactionKind::Root,
    )?;
    ensure!(
        super::multi_asset_splice_operator::canonical_checkpoint(rpc, &resolved.checkpoint)?,
        "chain reorganized after wallet signing"
    );
    Ok(
        json!({"schema":"morph.multi_asset_root_wallet_signature.v1","transaction":path,"recovery_package":package,
        "transaction_hash":canonical_hex(signed.hash().as_slice()),"signed_funder":public,"input_indices":group,
        "broadcast":false}),
    )
}
