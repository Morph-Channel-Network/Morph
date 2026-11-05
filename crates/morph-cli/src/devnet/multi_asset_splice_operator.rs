//! Canonical splice submission from complete offline authorizations. Changing
//! any body field requires a new exit package and fresh bridge signatures.
use super::multi_asset_operator as operator;
use super::*;
use crate::multi_asset_packages::{read_package, write_package};
use crate::multi_asset_splice_transaction::SpliceDraft;
use crate::rpc::HeaderView;
use morph_core::{MultiAssetRecoveryPackage, MultiAssetSpliceProposal, VaultAsset};
use morph_script_common::{multi_asset as wire, multi_asset_splice as splice};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Clone, clap::Subcommand)]
pub enum FeeAuthorization {
    Presigned,
    Wallet {
        #[arg(long, env = "MORPH_DEVNET_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
    },
}
impl std::fmt::Debug for FeeAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Presigned => "Presigned",
            Self::Wallet { .. } => "Wallet",
        })
    }
}
pub struct Options {
    pub transaction: PathBuf,
    pub old_package: PathBuf,
    pub new_package: PathBuf,
    pub contracts_dir: PathBuf,
    pub store_dir: PathBuf,
    pub fee_authorization: FeeAuthorization,
    pub max_fee: u64,
    pub mine_blocks: u64,
    pub dry_run: bool,
}
fn invalid(error: ScriptError) -> anyhow::Error {
    anyhow!("invalid splice: {error:?}")
}
fn script(bytes: &[u8]) -> Result<Script> {
    Ok(Script::from_slice(bytes)?)
}

pub fn submit(rpc: &CkbRpcClient, options: Options) -> Result<Value> {
    ensure!(options.max_fee > 0, "max_fee must be positive");
    let mut bytes = Vec::new();
    fs::File::open(&options.transaction)?
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 256 * 1024,
        "splice transaction exceeds byte limit"
    );
    let transaction = ckb_types::packed::Transaction::from_slice(&bytes)?;
    let old_stored = read_package(&options.old_package)?;
    let new_stored = read_package(&options.new_package)?;
    let current = old_stored.recovery()?;
    operator::verify_chain_id(rpc, &current.state.header.chain_id)?;
    let recovery = new_stored.recovery()?;
    let (_, plan, _) = SpliceDraft::from_signed_transaction(&current, &recovery, &transaction)?;
    let expected_package = crate::multi_asset_packages::StoredMultiAssetPackage::from_recovery(
        &recovery,
        &transaction
            .raw()
            .cell_deps()
            .into_iter()
            .collect::<Vec<_>>(),
    )?;
    ensure!(
        expected_package == new_stored,
        "future recovery dependencies differ from signed transaction"
    );
    let checkpoint = rpc.tip_header()?;
    let mut inputs = Vec::new();
    for input in transaction.raw().inputs() {
        inputs.push(load_canonical_live_cell(rpc, input.previous_output())?);
    }
    validate_state(&inputs[0], &current)?;
    let old_header = wire::MultiAssetStateHeader::parse(&inputs[0].data).map_err(invalid)?;
    let evidence = morph_core::encode_multi_asset_witness(
        &current.manifest,
        &current.settlement,
        &current.outpoints,
        &current.scripts,
    )?;
    let old_witness = wire::MultiAssetWitness::parse(&evidence).map_err(invalid)?;
    operator::validate_vaults(rpc, &old_witness)?;
    let witness_bytes = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing splice witness"))?
        .raw_data();
    let witness = WitnessArgs::from_slice(&witness_bytes)?;
    let bridge_bytes = witness
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing bridge"))?
        .raw_data();
    let bridge = splice::MultiAssetSpliceWitness::parse(&bridge_bytes).map_err(invalid)?;
    bridge.validate_old_header(&old_header).map_err(invalid)?;
    let deps = transaction
        .raw()
        .cell_deps()
        .into_iter()
        .collect::<Vec<_>>();
    let resolved = operator::live_dependencies(rpc, &deps)?;
    for input in transaction.raw().inputs() {
        ensure!(
            !resolved
                .out_points
                .contains(input.previous_output().as_slice()),
            "splice consumes a recovery dep-group member"
        );
    }
    let external_start = 1 + current.outpoints.len();
    ensure!(
        inputs.len() > external_start,
        "splice requires an independent external fee input"
    );
    let fee_lock = inputs[external_start].output.lock();
    operator::validate_resolved_code(
        &options.contracts_dir,
        &old_witness,
        &resolved.cells,
        &fee_lock,
    )?;
    operator::validate_resolved_code(
        &options.contracts_dir,
        bridge.new_evidence(),
        &resolved.cells,
        &fee_lock,
    )?;
    for cell in &inputs {
        for committed in std::iter::once(cell.output.lock()).chain(cell.output.type_().to_opt()) {
            ensure!(
                resolved
                    .cells
                    .iter()
                    .any(|code| operator::code_matches(&committed, code)),
                "input script has no live code dependency"
            );
        }
    }
    for (index, output) in transaction.raw().outputs().into_iter().enumerate() {
        for committed in std::iter::once(output.lock()).chain(output.type_().to_opt()) {
            ensure!(
                resolved
                    .cells
                    .iter()
                    .any(|code| operator::code_matches(&committed, code)),
                "output script has no live code dependency"
            );
        }
        let data = transaction
            .raw()
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("missing output data"))?
            .raw_data();
        ensure!(
            u64::from(output.capacity())
                >= output
                    .occupied_capacity(Capacity::bytes(data.len())?)?
                    .as_u64(),
            "output below occupied capacity"
        );
    }
    let fee = validate_balances(&transaction, &inputs, &current, &plan, options.max_fee)?;
    let wallet_key = match &options.fee_authorization {
        FeeAuthorization::Presigned => None,
        FeeAuthorization::Wallet { private_key } => {
            let key =
                parse_privkey(private_key).map_err(|_| anyhow!("invalid external funding key"))?;
            let lock = secp256k1_lock(&key)?;
            validate_wallet(&transaction, &inputs, &current, &plan, &lock)?;
            Some(key)
        }
    };
    ensure!(
        canonical_checkpoint(rpc, &checkpoint)?,
        "chain reorganized during splice validation"
    );
    // Save both contexts before invoking any wallet signer or mutating RPC.
    let old_path = write_package(&options.store_dir, &old_stored)?;
    let new_path = write_package(&options.store_dir, &new_stored)?;
    let tx = transaction.into_view();
    let tx = if let Some(key) = wallet_key {
        super::multi_asset::sign_group(
            tx,
            &key,
            &(external_start..inputs.len()).collect::<Vec<_>>(),
        )?
    } else {
        tx
    };
    let signed_path = crate::multi_asset_splice_transaction::write_transaction(
        &options.store_dir.join("submitted-splices"),
        &tx.data(),
        crate::multi_asset_splice_transaction::TransactionKind::Splice,
    )?;
    let metrics = transaction_metrics(rpc, &tx)?;
    ensure!(
        canonical_checkpoint(rpc, &checkpoint)?,
        "chain reorganized during splice preflight"
    );
    if options.dry_run {
        return Ok(
            json!({"schema":"morph.multi_asset_splice_transaction.v1","dry_run":true,
            "transaction_hash":format!("{:#x}", H256::from(tx.hash())),"fee":fee.to_string(),"metrics":metrics,
            "old_recovery_package":old_path,"new_recovery_package":new_path,"signed_transaction":signed_path}),
        );
    }
    let sent = send_preflighted_and_mine(rpc, tx, options.mine_blocks, metrics)?;
    let confirmed = transaction_confirmations(rpc, &sent)?;
    Ok(
        json!({"schema":"morph.multi_asset_splice_transaction.v1","dry_run":false,
        "tx_hash":sent.tx_hash,"status":sent.status,"block_number":sent.block_number,"block_hash":sent.block_hash,"metrics":sent.metrics,"fee":fee.to_string(),"canonical_confirmations":confirmed,
        "old_recovery_package":old_path,"new_recovery_package":new_path,"signed_transaction":signed_path,
        "signer_context_switched":false}),
    )
}

fn validate_state(state: &LiveCellDetails, current: &MultiAssetRecoveryPackage) -> Result<()> {
    ensure!(
        state.output.lock() == script(&current.scripts.state_lock)?
            && state.output.type_().to_opt() == Some(script(&current.scripts.state_type)?)
            && state.capacity == current.state_carrier_capacity,
        "live old State authority or carrier differs"
    );
    let old_header = wire::MultiAssetStateHeader::parse(&state.data).map_err(invalid)?;
    let header_bytes = current.state.encode()?;
    let current_header = wire::MultiAssetStateHeader::parse(&header_bytes).map_err(invalid)?;
    ensure!(
        old_header.same_context_except_progress(&current_header)
            && old_header.state_number() <= current_header.state_number(),
        "old State funding context or progress differs"
    );
    if old_header.state_number() == current_header.state_number() {
        ensure!(
            old_header.settlement_descriptor_commitment()
                == current_header.settlement_descriptor_commitment(),
            "conflicting old State at same number"
        );
    }
    Ok(())
}

pub(super) fn canonical_checkpoint(rpc: &CkbRpcClient, checkpoint: &HeaderView) -> Result<bool> {
    Ok(rpc
        .block_by_number(checkpoint.number_value()?)?
        .is_some_and(|block| format!("{:#x}", block.header.hash) == checkpoint.hash))
}

fn registered_assets(
    current: &MultiAssetRecoveryPackage,
    plan: &MultiAssetSpliceProposal,
) -> BTreeSet<[u8; 32]> {
    current
        .manifest
        .vaults
        .iter()
        .chain(&plan.new_manifest.vaults)
        .filter_map(|vault| match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(hash),
        })
        .collect()
}
fn validate_balances(
    transaction: &ckb_types::packed::Transaction,
    inputs: &[LiveCellDetails],
    current: &MultiAssetRecoveryPackage,
    plan: &MultiAssetSpliceProposal,
    max_fee: u64,
) -> Result<u64> {
    operator::validate_funding_balances(
        transaction,
        inputs,
        &registered_assets(current, plan),
        max_fee,
    )
}

fn validate_wallet(
    transaction: &ckb_types::packed::Transaction,
    inputs: &[LiveCellDetails],
    current: &MultiAssetRecoveryPackage,
    plan: &MultiAssetSpliceProposal,
    lock: &Script,
) -> Result<()> {
    let registered = registered_assets(current, plan);
    for cell in &inputs[1 + current.outpoints.len()..] {
        ensure!(
            cell.output.lock() == *lock,
            "external input is not owned by wallet signer"
        );
        if let Some(ty) = cell.output.type_().to_opt() {
            let hash: [u8; 32] = ty.calc_script_hash().unpack();
            ensure!(
                registered.contains(&hash) && cell.data.len() == 16,
                "wallet input carries an unregistered asset"
            );
        } else {
            ensure!(
                cell.data.is_empty(),
                "wallet plain input carries unexpected data"
            );
        }
    }
    let withdrawals = plan
        .flows
        .iter()
        .filter(|flow| flow.withdrawal != morph_core::MultiAssetValue::default())
        .count();
    for (index, output) in transaction
        .raw()
        .outputs()
        .into_iter()
        .enumerate()
        .skip(1 + plan.new_manifest.vaults.len() + withdrawals)
    {
        ensure!(
            output.lock() == *lock,
            "external change does not return to wallet signer"
        );
        let data = transaction
            .raw()
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("missing wallet change data"))?
            .raw_data();
        if let Some(ty) = output.type_().to_opt() {
            let hash: [u8; 32] = ty.calc_script_hash().unpack();
            ensure!(
                registered.contains(&hash) && data.len() == 16,
                "wallet change carries an unregistered asset"
            );
        } else {
            ensure!(
                data.is_empty(),
                "wallet plain change carries unexpected data"
            );
        }
    }
    Ok(())
}

pub struct PrepareOptions {
    pub old_package: PathBuf,
    pub state_out_point: String,
    pub terms: PathBuf,
    pub external_inputs: Vec<String>,
    pub change_pubkey: String,
    pub fee: u64,
    pub contracts_dir: PathBuf,
    pub output: PathBuf,
}

pub fn prepare(rpc: &CkbRpcClient, options: PrepareOptions) -> Result<Value> {
    use crate::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex, decode_hex};
    use crate::multi_asset_splice_transaction::SpliceTerms;
    ensure!(
        options.fee > 0
            && !options.external_inputs.is_empty()
            && options.external_inputs.len() <= 62,
        "positive fee and bounded explicit external inputs required"
    );
    let old_stored = read_package(&options.old_package)?;
    let current = old_stored.recovery()?;
    operator::verify_chain_id(rpc, &current.state.header.chain_id)?;
    let checkpoint = rpc.tip_header()?;
    let old_point = parse_out_point(&options.state_out_point)?;
    let state = load_canonical_live_cell(rpc, old_point.clone())?;
    validate_state(&state, &current)?;
    let mut bytes = Vec::new();
    fs::File::open(&options.terms)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "splice terms exceed byte limit");
    let terms: SpliceTerms = serde_json::from_slice(&bytes)?;
    let old_host_point = morph_core::MultiAssetOutPoint {
        tx_hash: old_point.tx_hash().unpack(),
        index: old_point.index().unpack(),
    };
    let next = terms.funding(&current, &old_host_point)?;
    let dependencies =
        StoredMultiAssetPackage::with_dependency_records(&current, terms.cell_deps.clone())?
            .decode()?
            .cell_deps;
    let resolved = operator::live_dependencies(rpc, &dependencies)?;
    let old_bytes = morph_core::encode_multi_asset_witness(
        &current.manifest,
        &current.settlement,
        &current.outpoints,
        &current.scripts,
    )?;
    let old_witness = wire::MultiAssetWitness::parse(&old_bytes).map_err(invalid)?;
    let vaults = operator::validate_vaults(rpc, &old_witness)?;
    let new_bytes = morph_core::encode_multi_asset_witness(
        &next.manifest,
        &next.settlement,
        &[],
        &next.scripts,
    )?;
    let new_witness = wire::MultiAssetWitness::parse(&new_bytes).map_err(invalid)?;
    let public =
        parse_compressed_pubkey_hex(&options.change_pubkey, "external funding public key")?;
    let lock = secp256k1_lock_from_pubkey(&public)?;
    operator::validate_resolved_code(&options.contracts_dir, &old_witness, &resolved.cells, &lock)?;
    operator::validate_resolved_code(&options.contracts_dir, &new_witness, &resolved.cells, &lock)?;
    let flows = decode_hex(
        &terms.flows_hex,
        4 + splice::MULTI_ASSET_SPLICE_MAX_FLOWS * splice::MULTI_ASSET_SPLICE_FLOW_LEN,
    )?;
    let flow_table = splice::MultiAssetSpliceFlows::parse(&flows).map_err(invalid)?;
    let withdrawal_lock = decode_hex(&terms.withdrawal_lock_hex, wire::MULTI_ASSET_MAX_SCRIPT_LEN)?;
    if !withdrawal_lock.is_empty() {
        let withdrawal = script(&withdrawal_lock)?;
        ensure!(
            resolved
                .cells
                .iter()
                .any(|code| operator::code_matches(&withdrawal, code)),
            "withdrawal lock code dependency missing"
        );
    }
    let mut points = vec![old_point];
    points.extend(vaults);
    for point in &options.external_inputs {
        points.push(parse_out_point(point)?);
    }
    let mut inputs = Vec::new();
    for point in &points {
        ensure!(
            !resolved.out_points.contains(point.as_slice()),
            "splice consumes a recovery dep-group member"
        );
        inputs.push(load_canonical_live_cell(rpc, point.clone())?);
    }
    let transaction = build_unsigned(
        &current,
        &next,
        &flow_table,
        &withdrawal_lock,
        FundingInputs {
            points: &points,
            inputs: &inputs,
            dependencies: &dependencies,
            wallet_lock: &lock,
            fee: options.fee,
        },
    )?;
    let draft = SpliceDraft::from_parts(&current, &transaction, &new_bytes, &flows)?;
    let plan = draft.proposal(&current)?;
    validate_wallet(&transaction, &inputs, &current, &plan, &lock)?;
    ensure!(
        validate_balances(&transaction, &inputs, &current, &plan, options.fee)? == options.fee,
        "unexpected constructed fee"
    );
    ensure!(
        canonical_checkpoint(rpc, &checkpoint)?,
        "chain reorganized during splice preparation"
    );
    let encoded = serde_json::to_vec_pretty(&draft)?;
    let _lock = crate::persistence::lock_private_path(&options.output)?;
    if options.output.exists() {
        ensure!(
            fs::read(&options.output)? == encoded,
            "draft output already holds another intent"
        );
    } else {
        crate::persistence::write_private_atomic(&options.output, &encoded)?;
    }
    Ok(
        json!({"schema":"morph.multi_asset_splice_preparation.v1", "draft":options.output,
        "transaction_hash":canonical_hex(&plan.transaction_hash),"old_state_outpoint":options.state_out_point,
        "new_funding_anchor":canonical_hex(&plan.new_state.header.funding_anchor),"vault_count":plan.new_manifest.vaults.len(),
        "fee":options.fee.to_string(),"requires_participant_signatures":true}),
    )
}

struct FundingInputs<'a> {
    points: &'a [OutPoint],
    inputs: &'a [LiveCellDetails],
    dependencies: &'a [CellDep],
    wallet_lock: &'a Script,
    fee: u64,
}
fn build_unsigned(
    current: &MultiAssetRecoveryPackage,
    next: &MultiAssetRecoveryPackage,
    flows: &splice::MultiAssetSpliceFlows<'_>,
    withdrawal_lock: &[u8],
    funding: FundingInputs<'_>,
) -> Result<ckb_types::packed::Transaction> {
    let FundingInputs {
        points,
        inputs,
        dependencies,
        wallet_lock,
        fee,
    } = funding;
    let mut outputs = vec![
        CellOutput::new_builder()
            .capacity(current.state_carrier_capacity)
            .lock(script(&next.scripts.state_lock)?)
            .type_(Some(script(&next.scripts.state_type)?).pack())
            .build(),
    ];
    let mut data = vec![Bytes::from(next.state.encode()?.to_vec())];
    let type_script = |hash: &[u8; 32]| -> Result<Script> {
        script(
            &next
                .scripts
                .type_scripts
                .iter()
                .chain(&current.scripts.type_scripts)
                .find(|entry| entry.type_hash == *hash)
                .ok_or_else(|| anyhow!("missing registered Type Script"))?
                .script,
        )
    };
    let mut append =
        |asset: VaultAsset, value: morph_core::MultiAssetValue, lock: &[u8]| -> Result<()> {
            let ty = match asset {
                VaultAsset::Xudt(hash) if value.amount > 0 => Some(type_script(&hash)?),
                _ => None,
            };
            outputs.push(
                CellOutput::new_builder()
                    .capacity(value.capacity()?)
                    .lock(script(lock)?)
                    .type_(ty.clone().pack())
                    .build(),
            );
            data.push(Bytes::from(if ty.is_some() {
                value.amount.to_le_bytes().to_vec()
            } else {
                vec![]
            }));
            Ok(())
        };
    for vault in &next.manifest.vaults {
        append(vault.asset.clone(), vault.value, &next.scripts.vault_lock)?;
    }
    for index in 0..flows.count() {
        let flow = flows.entry(index).map_err(invalid)?;
        if flow.withdrawal != wire::MultiAssetAllocation::default() {
            append(
                if flow.asset.kind == 0 {
                    VaultAsset::Ckb
                } else {
                    VaultAsset::Xudt(flow.asset.type_hash)
                },
                morph_core::MultiAssetValue {
                    reserve: flow.withdrawal.reserve,
                    business_ckb: flow.withdrawal.business_ckb,
                    amount: flow.withdrawal.amount,
                },
                withdrawal_lock,
            )?;
        }
    }
    let mut remaining_tokens = BTreeMap::<[u8; 32], u128>::new();
    for cell in inputs {
        if let Some(ty) = cell.output.type_().to_opt() {
            let hash: [u8; 32] = ty.calc_script_hash().unpack();
            if current
                .scripts
                .type_scripts
                .iter()
                .chain(&next.scripts.type_scripts)
                .any(|entry| entry.type_hash == hash)
            {
                let amount = u128::from_le_bytes(
                    cell.data
                        .as_ref()
                        .try_into()
                        .map_err(|_| anyhow!("registered input token data must be 16 bytes"))?,
                );
                let sum = remaining_tokens.entry(hash).or_default();
                *sum = sum
                    .checked_add(amount)
                    .ok_or_else(|| anyhow!("input token total overflow"))?;
            }
        }
    }
    for (output, value) in outputs.iter().zip(&data) {
        if let Some(ty) = output.type_().to_opt() {
            let hash: [u8; 32] = ty.calc_script_hash().unpack();
            if let Some(total) = remaining_tokens.get_mut(&hash) {
                let amount = u128::from_le_bytes(
                    value
                        .as_ref()
                        .try_into()
                        .map_err(|_| anyhow!("registered output token data must be 16 bytes"))?,
                );
                *total = total.checked_sub(amount).ok_or_else(|| {
                    anyhow!("external inputs do not fund requested token allocations")
                })?;
            } else if current
                .scripts
                .type_scripts
                .iter()
                .chain(&next.scripts.type_scripts)
                .any(|entry| entry.type_hash == hash)
            {
                return Err(anyhow!("missing external token funding input"));
            }
        }
    }
    for (hash, amount) in remaining_tokens {
        if amount == 0 {
            continue;
        }
        let output = CellOutput::new_builder()
            .lock(wallet_lock.clone())
            .type_(Some(type_script(&hash)?).pack())
            .build();
        let occupied = output.occupied_capacity(Capacity::bytes(16)?)?.as_u64();
        outputs.push(output.as_builder().capacity(occupied).build());
        data.push(Bytes::from(amount.to_le_bytes().to_vec()));
    }
    let input_capacity = inputs.iter().try_fold(0u64, |sum, cell| {
        sum.checked_add(cell.capacity)
            .ok_or_else(|| anyhow!("input capacity overflow"))
    })?;
    let used_capacity = outputs.iter().try_fold(fee, |sum, output| {
        sum.checked_add(output.capacity().unpack())
            .ok_or_else(|| anyhow!("output capacity overflow"))
    })?;
    let change = input_capacity
        .checked_sub(used_capacity)
        .ok_or_else(|| anyhow!("insufficient external CKB funding"))?;
    if change > 0 {
        ensure_change_capacity(wallet_lock, change)?;
        outputs.push(
            CellOutput::new_builder()
                .capacity(change)
                .lock(wallet_lock.clone())
                .build(),
        );
        data.push(Bytes::new());
    }
    let mut tx = TransactionBuilder::default().set_cell_deps(dependencies.to_vec());
    for point in points {
        tx = tx.input(
            CellInput::new_builder()
                .previous_output(point.clone())
                .build(),
        );
    }
    for (output, data) in outputs.into_iter().zip(data) {
        tx = tx.output(output).output_data(data.pack());
    }
    Ok(tx.build().data())
}

pub struct ConfirmationOptions<'a> {
    pub old: &'a MultiAssetRecoveryPackage,
    pub initial_recovery: &'a MultiAssetRecoveryPackage,
    pub current: &'a MultiAssetRecoveryPackage,
    pub transaction: &'a ckb_types::packed::Transaction,
    pub state_out_point: &'a str,
    pub min_confirmations: u64,
    pub contracts_dir: &'a Path,
}

pub(crate) fn canonical_transaction(
    rpc: &CkbRpcClient,
    hash: H256,
    min_confirmations: u64,
) -> Result<(
    ckb_types::packed::Transaction,
    crate::multi_asset_session_chain::CanonicalInclusion,
)> {
    use crate::multi_asset_session_chain::CanonicalInclusion;
    ensure!(min_confirmations > 0, "confirmation depth must be positive");
    let status = rpc.transaction(hash.clone())?.tx_status;
    ensure!(
        status.status == Status::Committed,
        "channel lineage transaction is not committed"
    );
    let number = status
        .block_number
        .ok_or_else(|| anyhow!("missing inclusion height"))?
        .value();
    let included_hash = status
        .block_hash
        .ok_or_else(|| anyhow!("missing inclusion hash"))?;
    let block = rpc
        .block_by_number(number)?
        .ok_or_else(|| anyhow!("inclusion block is unavailable"))?;
    ensure!(
        block.header.hash == included_hash,
        "channel lineage inclusion block is not canonical"
    );
    ensure!(
        block_confirmations(number, rpc.tip_header()?.number_value()?)? >= min_confirmations,
        "channel lineage has insufficient confirmations"
    );
    let transaction = block
        .transactions
        .into_iter()
        .find(|tx| tx.hash == hash)
        .ok_or_else(|| anyhow!("transaction missing from canonical inclusion block"))?;
    let transaction: ckb_types::packed::Transaction = transaction.inner.into();
    ensure!(
        H256::from(transaction.calc_tx_hash()) == hash,
        "canonical transaction body hash mismatch"
    );
    Ok((
        transaction,
        CanonicalInclusion {
            transaction_hash: format!("{hash:#x}"),
            block_number: number,
            block_hash: format!("{included_hash:#x}"),
        },
    ))
}

pub fn confirm_context(
    rpc: &CkbRpcClient,
    options: ConfirmationOptions<'_>,
) -> Result<crate::multi_asset_session_chain::ContextChainEvidence> {
    let (_, plan, _) = SpliceDraft::from_signed_transaction(
        options.old,
        options.initial_recovery,
        options.transaction,
    )?;
    ensure!(
        options.current.state.funding_context_id()?
            == options.initial_recovery.state.funding_context_id()?,
        "current signer is outside the confirmed funding context"
    );
    let (actual, funding) = canonical_transaction(
        rpc,
        H256::from(plan.transaction_hash),
        options.min_confirmations,
    )?;
    ensure!(
        actual.raw().as_slice() == options.transaction.raw().as_slice(),
        "canonical splice differs from signed raw body"
    );
    confirm_bound_state(
        rpc,
        options.current,
        &actual,
        funding,
        options.state_out_point,
        options.min_confirmations,
        options.contracts_dir,
    )
}

fn confirm_bound_state(
    rpc: &CkbRpcClient,
    current: &MultiAssetRecoveryPackage,
    actual: &ckb_types::packed::Transaction,
    funding: crate::multi_asset_session_chain::CanonicalInclusion,
    state_out_point: &str,
    min_confirmations: u64,
    contracts_dir: &Path,
) -> Result<crate::multi_asset_session_chain::ContextChainEvidence> {
    use crate::multi_asset_session_chain::ContextChainEvidence;
    let state_point = parse_out_point(state_out_point)?;
    let (state_transaction, state_evidence) =
        canonical_transaction(rpc, H256::from(state_point.tx_hash()), min_confirmations)?;
    let state = load_canonical_live_cell(rpc, state_point.clone())?;
    validate_state(&state, current)?;
    let index: u32 = state_point.index().unpack();
    ensure!(
        state_transaction
            .raw()
            .outputs()
            .get(index as usize)
            .is_some_and(|output| output == state.output),
        "live State differs from canonical transaction output"
    );
    ensure!(
        state_transaction
            .raw()
            .outputs_data()
            .get(index as usize)
            .is_some_and(|data| data.raw_data() == state.data),
        "live State data differs from canonical transaction output"
    );
    let stored = crate::multi_asset_packages::StoredMultiAssetPackage::from_recovery(
        current,
        &actual.raw().cell_deps().into_iter().collect::<Vec<_>>(),
    )?;
    let evidence = ContextChainEvidence {
        funding,
        state: state_evidence,
        state_out_point: format_out_point(&state_point),
    };
    verify_context_guard(rpc, &evidence, min_confirmations, &stored, contracts_dir)?;
    Ok(evidence)
}

pub(crate) struct FactoryChildContext<'a> {
    pub request: &'a morph_core::FactorySigningRequest,
    pub child_index: u16,
    pub initial: &'a MultiAssetRecoveryPackage,
    pub current: &'a MultiAssetRecoveryPackage,
    pub transaction: &'a ckb_types::packed::Transaction,
    pub state_out_point: &'a str,
    pub min_confirmations: u64,
    pub contracts_dir: &'a Path,
}

/// Factory children are created by their parent's typed authorization, not by
/// the bilateral root-funding domain. Exact private initial exit data remains
/// local to each child participant and is checked against the public parent.
pub(crate) fn confirm_factory_child_context(
    rpc: &CkbRpcClient,
    options: FactoryChildContext<'_>,
) -> Result<crate::multi_asset_session_chain::ContextChainEvidence> {
    let request = options.request;
    request.verify_child_recovery(options.child_index, options.initial)?;
    request.verify_authorized_transaction(options.transaction)?;
    crate::factory_artifacts::validate_request_artifacts(request, options.contracts_dir)?;
    ensure!(
        options.current.state.funding_context_id()?
            == options.initial.state.funding_context_id()?,
        "Factory child signer is outside its initial funding context"
    );
    let (actual, funding) = canonical_transaction(
        rpc,
        request.transaction_hash()?.into(),
        options.min_confirmations,
    )?;
    ensure!(
        actual.as_slice() == options.transaction.as_slice(),
        "canonical parent differs from exact authorized Factory transaction"
    );
    request.verify_authorized_transaction(&actual)?;
    confirm_bound_state(
        rpc,
        options.current,
        &actual,
        funding,
        options.state_out_point,
        options.min_confirmations,
        options.contracts_dir,
    )
}

pub fn confirm_root_context(
    rpc: &CkbRpcClient,
    current: &MultiAssetRecoveryPackage,
    state_out_point: &str,
    min_confirmations: u64,
    contracts_dir: &Path,
) -> Result<(
    crate::multi_asset_session_chain::ContextChainEvidence,
    ckb_types::packed::Transaction,
)> {
    let point = current
        .outpoints
        .first()
        .ok_or_else(|| anyhow!("root recovery is not bound"))?;
    let (transaction, funding) =
        canonical_transaction(rpc, H256::from(point.tx_hash), min_confirmations)?;
    crate::multi_asset_funding::validate_root_funding(current, &transaction)?;
    let evidence = confirm_bound_state(
        rpc,
        current,
        &transaction,
        funding,
        state_out_point,
        min_confirmations,
        contracts_dir,
    )?;
    Ok((evidence, transaction))
}

pub fn verify_context_guard(
    rpc: &CkbRpcClient,
    evidence: &crate::multi_asset_session_chain::ContextChainEvidence,
    min_confirmations: u64,
    current: &crate::multi_asset_packages::StoredMultiAssetPackage,
    contracts_dir: &Path,
) -> Result<()> {
    let recovery = current.recovery()?;
    operator::verify_chain_id(rpc, &recovery.state.header.chain_id)?;
    fn check(
        rpc: &CkbRpcClient,
        saved: &crate::multi_asset_session_chain::CanonicalInclusion,
        depth: u64,
    ) -> Result<ckb_types::packed::Transaction> {
        let (transaction, actual) =
            canonical_transaction(rpc, parse_h256(&saved.transaction_hash)?, depth)?;
        ensure!(
            actual == *saved,
            "channel lineage changed after reorg; reconcile exact context before signing"
        );
        Ok(transaction)
    }
    check(rpc, &evidence.funding, min_confirmations)?;
    let state_transaction = check(rpc, &evidence.state, min_confirmations)?;
    let point = parse_out_point(&evidence.state_out_point)?;
    ensure!(
        point.tx_hash() == state_transaction.calc_tx_hash(),
        "lineage State is outside its canonical transaction"
    );
    let index: u32 = point.index().unpack();
    let output = state_transaction
        .raw()
        .outputs()
        .get(index as usize)
        .ok_or_else(|| anyhow!("lineage State output missing"))?;
    let data = state_transaction
        .raw()
        .outputs_data()
        .get(index as usize)
        .ok_or_else(|| anyhow!("lineage State data missing"))?
        .raw_data();
    let state = LiveCellDetails {
        capacity: output.capacity().unpack(),
        output,
        data,
    };
    validate_state(&state, &recovery)?;

    let decoded = current.decode()?;
    let witness = wire::MultiAssetWitness::parse(&decoded.witness).map_err(invalid)?;
    operator::validate_vaults(rpc, &witness)?;
    let participant = Script::from_slice(witness.scripts().script(0).map_err(invalid)?)?;
    operator::validate_code(
        rpc,
        contracts_dir,
        &witness,
        &decoded.cell_deps,
        &participant,
    )?;
    check(rpc, &evidence.state, min_confirmations).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_asset_packages::canonical_hex;

    fn fixture() -> (
        ckb_types::packed::Transaction,
        Vec<LiveCellDetails>,
        MultiAssetRecoveryPackage,
        MultiAssetSpliceProposal,
        Script,
    ) {
        let current = crate::multi_asset_packages::fixture_package()
            .unwrap()
            .recovery()
            .unwrap();
        let mut draft = crate::multi_asset_splice_transaction::fixture_draft(&current);
        let tx = draft.transaction().unwrap();
        let lock = script(&current.scripts.participant_locks[0]).unwrap();
        let mut inputs = vec![LiveCellDetails {
            output: CellOutput::new_builder()
                .capacity(current.state_carrier_capacity)
                .lock(script(&current.scripts.state_lock).unwrap())
                .type_(Some(script(&current.scripts.state_type).unwrap()).pack())
                .build(),
            capacity: current.state_carrier_capacity,
            data: Bytes::from(current.state.encode().unwrap().to_vec()),
        }];
        for vault in &current.manifest.vaults {
            let ty = match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => Some(
                    script(
                        &current
                            .scripts
                            .type_scripts
                            .iter()
                            .find(|entry| entry.type_hash == hash)
                            .unwrap()
                            .script,
                    )
                    .unwrap(),
                ),
            };
            let data = if ty.is_some() {
                vault.value.amount.to_le_bytes().to_vec()
            } else {
                vec![]
            };
            inputs.push(LiveCellDetails {
                output: CellOutput::new_builder()
                    .capacity(vault.value.capacity().unwrap())
                    .lock(script(&current.scripts.vault_lock).unwrap())
                    .type_(ty.pack())
                    .build(),
                data: Bytes::from(data),
                capacity: vault.value.capacity().unwrap(),
            });
        }
        inputs.push(LiveCellDetails {
            output: CellOutput::new_builder()
                .capacity(20_000_000_000u64)
                .lock(lock.clone())
                .build(),
            data: Bytes::new(),
            capacity: 20_000_000_000,
        });
        let mut raw_inputs = tx.raw().inputs().into_iter().collect::<Vec<_>>();
        raw_inputs.push(
            CellInput::new_builder()
                .previous_output(OutPoint::new_builder().tx_hash([88u8; 32].pack()).build())
                .build(),
        );
        let mut outputs = tx.raw().outputs().into_iter().collect::<Vec<_>>();
        outputs.push(
            CellOutput::new_builder()
                .capacity(19_000_000_000u64)
                .lock(lock.clone())
                .build(),
        );
        let mut data = tx.raw().outputs_data().into_iter().collect::<Vec<_>>();
        data.push(Bytes::new().pack());
        let tx = tx
            .clone()
            .as_builder()
            .raw(
                tx.raw()
                    .as_builder()
                    .inputs(raw_inputs.pack())
                    .outputs(outputs.pack())
                    .outputs_data(data.pack())
                    .build(),
            )
            .build();
        draft.transaction_hex = canonical_hex(tx.as_slice());
        let plan = draft.proposal(&current).unwrap();
        (tx, inputs, current, plan, lock)
    }

    #[test]
    fn splice_submission_enforces_independent_fee_and_per_type_conservation() {
        let (tx, inputs, current, plan, _) = fixture();
        assert_eq!(
            validate_balances(&tx, &inputs, &current, &plan, 1_000_000_000).unwrap(),
            1_000_000_000
        );
        assert!(validate_balances(&tx, &inputs, &current, &plan, 999_999_999).is_err());
        let mut data = tx.raw().outputs_data().into_iter().collect::<Vec<_>>();
        let amount = u128::from_le_bytes(data[1].raw_data().as_ref().try_into().unwrap());
        data[1] = Bytes::from((amount + 1).to_le_bytes().to_vec()).pack();
        let changed = tx
            .clone()
            .as_builder()
            .raw(tx.raw().as_builder().outputs_data(data.pack()).build())
            .build();
        assert!(validate_balances(&changed, &inputs, &current, &plan, 1_000_000_000).is_err());
        let mut inputs = inputs;
        inputs.last_mut().unwrap().capacity = u64::MAX;
        assert!(validate_balances(&tx, &inputs, &current, &plan, u64::MAX).is_err());
    }

    #[test]
    fn splice_wallet_refuses_foreign_inputs_stolen_change_and_unregistered_assets() {
        let (tx, mut inputs, current, plan, lock) = fixture();
        validate_wallet(&tx, &inputs, &current, &plan, &lock).unwrap();
        let other = script(&current.scripts.participant_locks[1]).unwrap();
        let mut outputs = tx.raw().outputs().into_iter().collect::<Vec<_>>();
        let last = outputs.len() - 1;
        outputs[last] = outputs[last]
            .clone()
            .as_builder()
            .lock(other.clone())
            .build();
        let changed = tx
            .clone()
            .as_builder()
            .raw(tx.raw().as_builder().outputs(outputs.pack()).build())
            .build();
        assert!(validate_wallet(&changed, &inputs, &current, &plan, &lock).is_err());
        let funding = inputs.last_mut().unwrap();
        funding.output = funding.output.clone().as_builder().lock(other).build();
        assert!(validate_wallet(&tx, &inputs, &current, &plan, &lock).is_err());
        let funding = inputs.last_mut().unwrap();
        funding.output = funding
            .output
            .clone()
            .as_builder()
            .lock(lock.clone())
            .type_(Some(Script::new_builder().code_hash([99u8; 32].pack()).build()).pack())
            .build();
        funding.data = Bytes::from(vec![0; 16]);
        assert!(validate_wallet(&tx, &inputs, &current, &plan, &lock).is_err());
    }
    #[test]
    fn native_builder_replaces_assets_and_returns_exact_typed_change() {
        use crate::multi_asset_splice_transaction::SpliceTerms;
        use morph_core::{
            MultiAssetSpliceFlow, MultiAssetValue, encode_multi_asset_splice_flows,
            encode_multi_asset_witness,
        };
        let (tx, mut inputs, current, _, lock) = fixture();
        let old_point = tx.raw().inputs().get(0).unwrap().previous_output();
        let old = morph_core::MultiAssetOutPoint {
            tx_hash: old_point.tx_hash().unpack(),
            index: old_point.index().unpack(),
        };
        let removed = current.manifest.vaults.last().unwrap();
        let admitted_script = script(&current.scripts.type_scripts[0].script)
            .unwrap()
            .as_builder()
            .args(Bytes::from_static(b"admitted-native-asset").pack())
            .build();
        let admitted_hash: [u8; 32] = admitted_script.calc_script_hash().unpack();
        let mut settlement = current.settlement.clone();
        settlement
            .payouts
            .iter_mut()
            .find(|payout| payout.asset == removed.asset)
            .unwrap()
            .asset = VaultAsset::Xudt(admitted_hash);
        settlement
            .payouts
            .sort_by_key(|payout| payout.asset.clone());
        let mut types = current
            .scripts
            .type_scripts
            .iter()
            .filter(|entry| VaultAsset::Xudt(entry.type_hash) != removed.asset)
            .map(|entry| (entry.type_hash, entry.script.clone()))
            .collect::<Vec<_>>();
        types.push((admitted_hash, admitted_script.as_slice().to_vec()));
        types.sort_by_key(|entry| entry.0);
        let mut flows = current
            .manifest
            .vaults
            .iter()
            .map(|vault| MultiAssetSpliceFlow {
                asset: vault.asset.clone(),
                deposit: MultiAssetValue::default(),
                withdrawal: if vault.asset == removed.asset {
                    vault.value
                } else {
                    MultiAssetValue::default()
                },
            })
            .collect::<Vec<_>>();
        flows.push(MultiAssetSpliceFlow {
            asset: VaultAsset::Xudt(admitted_hash),
            deposit: removed.value,
            withdrawal: MultiAssetValue::default(),
        });
        flows.sort_by_key(|flow| flow.asset.clone());
        let flow_bytes = encode_multi_asset_splice_flows(&flows).unwrap();
        let withdrawal_lock = &current.scripts.participant_locks[1];
        let terms = SpliceTerms {
            schema: "morph.multi_asset_splice_terms.v1".to_string(),
            descriptor_hex: canonical_hex(&settlement.encode().unwrap()),
            flows_hex: canonical_hex(&flow_bytes),
            new_type_scripts_hex: types.iter().map(|entry| canonical_hex(&entry.1)).collect(),
            withdrawal_lock_hex: canonical_hex(withdrawal_lock),
            cell_deps: vec![],
        };
        let next = terms.funding(&current, &old).unwrap();
        let mut points = tx
            .raw()
            .inputs()
            .into_iter()
            .map(|input| input.previous_output())
            .collect::<Vec<_>>();
        points.push(OutPoint::new_builder().tx_hash([89u8; 32].pack()).build());
        let capacity = removed.value.capacity().unwrap() + 20_000_000_000;
        inputs.push(LiveCellDetails {
            output: CellOutput::new_builder()
                .capacity(capacity)
                .lock(lock.clone())
                .type_(Some(admitted_script.clone()).pack())
                .build(),
            data: Bytes::from((removed.value.amount + 7).to_le_bytes().to_vec()),
            capacity,
        });
        let deps = tx.raw().cell_deps().into_iter().collect::<Vec<_>>();
        let table = splice::MultiAssetSpliceFlows::parse(&flow_bytes).unwrap();
        let unsigned = build_unsigned(
            &current,
            &next,
            &table,
            withdrawal_lock,
            FundingInputs {
                points: &points,
                inputs: &inputs,
                dependencies: &deps,
                wallet_lock: &lock,
                fee: 1_000_000_000,
            },
        )
        .unwrap();
        let new_evidence =
            encode_multi_asset_witness(&next.manifest, &next.settlement, &[], &next.scripts)
                .unwrap();
        let draft =
            SpliceDraft::from_parts(&current, &unsigned, &new_evidence, &flow_bytes).unwrap();
        let plan = draft.proposal(&current).unwrap();
        assert_eq!(
            validate_balances(&unsigned, &inputs, &current, &plan, 1_000_000_000).unwrap(),
            1_000_000_000
        );
        validate_wallet(&unsigned, &inputs, &current, &plan, &lock).unwrap();
        let index = unsigned.raw().outputs().len() - 2;
        let change = unsigned.raw().outputs().get(index).unwrap();
        assert_eq!(change.type_().to_opt().unwrap(), admitted_script);
        assert_eq!(
            unsigned
                .raw()
                .outputs_data()
                .get(index)
                .unwrap()
                .raw_data()
                .as_ref(),
            7u128.to_le_bytes()
        );
        assert!(
            build_unsigned(
                &current,
                &next,
                &table,
                withdrawal_lock,
                FundingInputs {
                    points: &points[..points.len() - 1],
                    inputs: &inputs[..inputs.len() - 1],
                    dependencies: &deps,
                    wallet_lock: &lock,
                    fee: 1_000_000_000
                }
            )
            .is_err()
        );
    }
}
