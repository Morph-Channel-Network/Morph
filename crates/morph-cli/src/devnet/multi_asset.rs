//! Real-node construction for the multi-asset profile. Synthetic asset
//! issuance belongs only to the devnet acceptance harness.

use super::*;
use crate::multi_asset_packages::{StoredMultiAssetPackage, write_package};
use morph_core::{
    MultiAssetManifest, MultiAssetOutPoint, MultiAssetPayout, MultiAssetRecoveryPackage,
    MultiAssetRecoveryScripts, MultiAssetSettlement, MultiAssetState, MultiAssetTypeScript,
    MultiAssetValue, MultiAssetVault, StateAuthorization, encode_multi_asset_signatures,
    encode_multi_asset_witness, multi_asset_outpoint_commitment,
};
use morph_script_common::multi_asset as wire;
use serde_json::{Value, json};

pub struct MultiAssetSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
    pub alice_private_key: String,
    pub bob_private_key: String,
    pub asset_count: usize,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
}

fn report(sent: &SentTransactionReport) -> Value {
    json!({"tx_hash": sent.tx_hash, "status": sent.status, "block_number": sent.block_number,
        "block_hash": sent.block_hash, "metrics": sent.metrics, "mined_blocks": sent.mined_blocks})
}

fn proof(package: &MultiAssetRecoveryPackage, signed: bool) -> Result<Bytes> {
    let evidence = encode_multi_asset_witness(
        &package.manifest,
        &package.settlement,
        &package.outpoints,
        &package.scripts,
    )?;
    let signatures = if signed {
        Some(Bytes::from(
            encode_multi_asset_signatures(&package.authorization)?.to_vec(),
        ))
    } else {
        None
    };
    Ok(WitnessArgs::new_builder()
        .input_type(signatures.pack())
        .output_type(Some(Bytes::from(evidence)).pack())
        .build()
        .as_bytes())
}

fn authorize(package: &mut MultiAssetRecoveryPackage, alice: &str, bob: &str) -> Result<()> {
    let mut keys = [k256_signing_key(alice)?, k256_signing_key(bob)?];
    keys.sort_by_key(k256_pubkey);
    let public = keys.each_ref().map(k256_pubkey);
    package.state.header.participants_commitment =
        core_participants_commitment(2, &[&public[0], &public[1]]);
    let digest = package.state.signing_digest()?;
    package.authorization = StateAuthorization {
        threshold: 2,
        signatures: keys
            .iter()
            .map(|key| {
                Ok(ParticipantSignature {
                    pubkey_sec1: k256_pubkey(key).to_vec(),
                    signature: ecdsa_signature(key, &digest)?.to_vec(),
                })
            })
            .collect::<Result<_>>()?,
    };
    package.validate()?;
    Ok(())
}

/// Preserve both type-witness fields while signing an arbitrary secp group.
/// The group may include several typed funding inputs or a fee input after
/// State/Vault inputs. All extra witnesses are included in SIGHASH_ALL.
fn sign_group(
    tx: ckb_types::core::TransactionView,
    key: &Privkey,
    indices: &[usize],
) -> Result<ckb_types::core::TransactionView> {
    ensure!(
        !indices.is_empty()
            && indices.windows(2).all(|pair| pair[0] < pair[1])
            && indices.iter().all(|index| *index < tx.inputs().len()),
        "invalid secp input group"
    );
    let mut witnesses: Vec<Bytes> = tx
        .witnesses()
        .into_iter()
        .map(|raw| raw.raw_data())
        .collect();
    witnesses.resize(witnesses.len().max(tx.inputs().len()), Bytes::new());
    let first = indices[0];
    let witness = if witnesses[first].is_empty() {
        WitnessArgs::default()
    } else {
        WitnessArgs::from_slice(&witnesses[first]).context("invalid funding witness")?
    };
    witnesses[first] = witness
        .clone()
        .as_builder()
        .lock(Some(Bytes::from(vec![0; 65])).pack())
        .build()
        .as_bytes();
    let mut committed = indices
        .iter()
        .map(|index| witnesses[*index].clone())
        .collect::<Vec<_>>();
    committed.extend(witnesses.iter().skip(tx.inputs().len()).cloned());
    let signature = key
        .sign_recoverable(&sighash_all_message(tx.hash(), &committed))
        .context("failed to sign multi-asset funding/fee transaction")?;
    witnesses[first] = witness
        .as_builder()
        .lock(Some(Bytes::from(signature.serialize())).pack())
        .build()
        .as_bytes();
    Ok(tx
        .as_advanced_builder()
        .set_witnesses(witnesses.into_iter().map(|raw| raw.pack()).collect())
        .build())
}

fn wallet_change(capacity: u64, spent: u64, fee: u64, lock: &Script) -> Result<CellOutput> {
    let change = capacity
        .checked_sub(spent)
        .and_then(|value| value.checked_sub(fee))
        .ok_or_else(|| anyhow!("insufficient fee/funding capacity"))?;
    ensure_change_capacity(lock, change)?;
    Ok(CellOutput::new_builder()
        .capacity(change)
        .lock(lock.clone())
        .build())
}

struct AssetInput {
    script: Script,
    point: OutPoint,
    reserve: [u64; 2],
}

pub fn smoke(rpc: &CkbRpcClient, options: MultiAssetSmokeOptions) -> Result<Value> {
    ensure!(
        rpc.chain_info()?.chain.to_lowercase().contains("dev"),
        "multi-asset smoke requires an isolated CKB devnet"
    );
    ensure!(
        (2..=wire::MULTI_ASSET_MAX_VAULTS).contains(&options.asset_count),
        "asset count must be 2..={}",
        wire::MULTI_ASSET_MAX_VAULTS
    );
    ensure!(
        options.fee > 0 && options.mine_blocks > 0,
        "smoke requires a positive fee and mining budget"
    );
    let owner =
        parse_privkey(&options.private_key).map_err(|_| anyhow!("invalid devnet funding key"))?;
    let owner_lock = secp256k1_lock(&owner)?;
    let alice =
        parse_privkey(&options.alice_private_key).map_err(|_| anyhow!("invalid Alice key"))?;
    let bob = parse_privkey(&options.bob_private_key).map_err(|_| anyhow!("invalid Bob key"))?;
    let mut locks = [secp256k1_lock(&alice)?, secp256k1_lock(&bob)?];
    locks.sort_by_key(Script::calc_script_hash);
    ensure!(
        locks[0] != locks[1],
        "channel participants must be distinct"
    );
    let tip = rpc.tip_header()?.number_value()?;
    let contracts = find_deployed_contracts(rpc, &options.contracts_dir, tip)?;
    let state_code = contract_by_name(&contracts, "morph-state-type")?;
    let lock_code = contract_by_name(&contracts, "morph-state-lock")?;
    let vault_code = contract_by_name(&contracts, "morph-vault-lock")?;
    let xudt_code = contract_by_name(&contracts, "morph-devnet-xudt")?;
    let secp = find_secp256k1_cell_dep(rpc)?;
    let recovery_deps = vec![
        state_code.cell_dep.clone(),
        lock_code.cell_dep.clone(),
        vault_code.cell_dep.clone(),
        xudt_code.cell_dep.clone(),
        secp.clone(),
    ];
    let since = relative_block_since_arg(options.finalise_since)?;
    let seed = hex::decode(options.private_key.trim_start_matches("0x"))
        .context("invalid devnet funding key")?;
    let mut assets = Vec::new();
    let mut issuance = Vec::new();
    for index in 0..options.asset_count {
        let issuer_seed = script_blake2b256(&[
            b"CKB_MORPH_DEVNET_MULTI_ASSET_ISSUER",
            &seed,
            &(index as u64).to_le_bytes(),
        ]);
        let issuer = parse_privkey(&hex::encode(issuer_seed))
            .map_err(|_| anyhow!("invalid derived devnet issuer key"))?;
        let issuer_lock = secp256k1_lock(&issuer)?;
        let script = data1_script(
            xudt_code.data_hash.clone(),
            Bytes::copy_from_slice(issuer_lock.calc_script_hash().as_slice()),
        );
        // The final Vault lock has fixed 116-byte args. Its occupied capacity
        // can be measured before the funding input fixes the actual anchor.
        let vault_template = data1_script(
            vault_code.data_hash.clone(),
            Bytes::from(vec![0; wire::MULTI_ASSET_VAULT_ARGS_LEN]),
        );
        let mut reserve = [0; 2];
        for participant in 0..2 {
            reserve[participant] = occupied_capacity(
                &CellOutput::new_builder()
                    .lock(locks[participant].clone())
                    .type_(Some(script.clone()).pack())
                    .build(),
                16,
            )?;
        }
        let vault_occupied = occupied_capacity(
            &CellOutput::new_builder()
                .lock(vault_template)
                .type_(Some(script.clone()).pack())
                .build(),
            16,
        )?;
        let payout_reserve = reserve[0]
            .checked_add(reserve[1])
            .ok_or_else(|| anyhow!("reserve overflow"))?;
        reserve[0] += vault_occupied.saturating_sub(payout_reserve);
        let vault_capacity = reserve[0]
            .checked_add(reserve[1])
            .and_then(|value| value.checked_add(10_000_000_000))
            .ok_or_else(|| anyhow!("Vault capacity overflow"))?;
        let funding = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
        let issuer_capacity = vault_capacity
            .checked_add(options.fee)
            .ok_or_else(|| anyhow!("issuer capacity overflow"))?;
        let tx = TransactionBuilder::default()
            .cell_dep(secp.clone())
            .input(CellInput::new(funding.out_point, 0))
            .output(
                CellOutput::new_builder()
                    .capacity(issuer_capacity)
                    .lock(issuer_lock)
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .output(wallet_change(
                funding.capacity,
                issuer_capacity,
                options.fee,
                &owner_lock,
            )?)
            .output_data(Bytes::new().pack())
            .build();
        let funded = send_and_mine(rpc, sign_group(tx, &owner, &[0])?, options.mine_blocks)?;
        let issuer_point = OutPoint::new(parse_h256(&funded.tx_hash)?.pack(), 0);
        let mint = TransactionBuilder::default()
            .cell_dep(secp.clone())
            .cell_dep(xudt_code.cell_dep.clone())
            .input(CellInput::new(issuer_point, 0))
            .output(
                CellOutput::new_builder()
                    .capacity(vault_capacity)
                    .lock(owner_lock.clone())
                    .type_(Some(script.clone()).pack())
                    .build(),
            )
            .output_data(Bytes::from(1000u128.to_le_bytes().to_vec()).pack())
            .build();
        let minted = send_and_mine(rpc, sign_group(mint, &issuer, &[0])?, options.mine_blocks)?;
        let point = OutPoint::new(parse_h256(&minted.tx_hash)?.pack(), 0);
        issuance.push(json!({"type_hash": format!("{:#x}", H256::from(script.calc_script_hash())), "fund": report(&funded), "mint": report(&minted)}));
        assets.push(AssetInput {
            script,
            point,
            reserve,
        });
    }
    assets.sort_by_key(|asset| asset.script.calc_script_hash());
    let funding = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let first_input = CellInput::new(funding.out_point.clone(), 0);
    let anchor = derive_funding_anchor(&first_input, 0);
    let state_type = data1_script(
        state_code.data_hash.clone(),
        state_type_args(&anchor, since),
    );
    let state_lock = data1_script(
        lock_code.data_hash.clone(),
        Bytes::copy_from_slice(state_type.calc_script_hash().as_slice()),
    );
    let vault_args = wire::encode_multi_asset_vault_args(
        &anchor,
        since,
        &state_type.calc_script_hash().unpack(),
        &state_lock.calc_script_hash().unpack(),
    )
    .map_err(|error| anyhow!("invalid Vault args: {error:?}"))?;
    let vault_lock = data1_script(
        vault_code.data_hash.clone(),
        Bytes::copy_from_slice(&vault_args),
    );
    let manifest = MultiAssetManifest {
        vaults: assets
            .iter()
            .map(|asset| MultiAssetVault {
                asset: VaultAsset::Xudt(asset.script.calc_script_hash().unpack()),
                lock_hash: vault_lock.calc_script_hash().unpack(),
                value: MultiAssetValue {
                    reserve: asset.reserve[0] + asset.reserve[1],
                    business_ckb: 10_000_000_000,
                    amount: 1000,
                },
            })
            .collect(),
    };
    let settlement = MultiAssetSettlement {
        participant_lock_hashes: locks
            .each_ref()
            .map(|lock| lock.calc_script_hash().unpack()),
        carrier_refund_lock_hash: owner_lock.calc_script_hash().unpack(),
        payouts: assets
            .iter()
            .map(|asset| MultiAssetPayout {
                asset: VaultAsset::Xudt(asset.script.calc_script_hash().unpack()),
                values: [
                    MultiAssetValue {
                        reserve: asset.reserve[0],
                        business_ckb: 6_000_000_000,
                        amount: 700,
                    },
                    MultiAssetValue {
                        reserve: asset.reserve[1],
                        business_ckb: 4_000_000_000,
                        amount: 300,
                    },
                ],
            })
            .collect(),
    };
    let content = manifest.commitment()?;
    let state_template = CellOutput::new_builder()
        .lock(state_lock.clone())
        .type_(Some(state_type.clone()).pack())
        .build();
    let carrier = occupied_capacity(&state_template, wire::MULTI_ASSET_STATE_HEADER_LEN)?;
    let chain_id = rpc
        .block_by_number(0)?
        .ok_or_else(|| anyhow!("genesis block is missing"))?
        .header
        .hash
        .0;
    let channel_id = script_blake2b256(&[b"CKB_MORPH_CHANNEL_ID", &anchor]);
    let mut package = MultiAssetRecoveryPackage {
        state: MultiAssetState {
            header: StateHeader {
                protocol_version: 1,
                chain_id,
                signature_scheme_id: 1,
                channel_id,
                funding_epoch: 0,
                funding_anchor: anchor,
                vault_set_commitment: content,
                state_number: 0,
                mode: Mode::BilateralPlain,
                phase: Phase::Active,
                participants_commitment: [0; 32],
                asset_registry_commitment: asset_registry_commitment(&manifest.registry()?),
                settlement_descriptor_commitment: settlement.commitment()?,
                descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
                vault_materialisation_root: [0; 32],
                challenge_policy_commitment: script_blake2b256(&[
                    b"CKB_MORPH_CHALLENGE_POLICY",
                    &since.to_le_bytes(),
                ]),
                state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
                vault_outpoint_commitment: [0; 32],
            },
            vault_content_set_root: content,
            vault_outpoint_set_root: [0; 32],
            vault_count: assets.len() as u16,
        },
        authorization: StateAuthorization {
            threshold: 2,
            signatures: vec![],
        },
        manifest,
        settlement,
        outpoints: vec![],
        state_carrier_capacity: carrier,
        scripts: MultiAssetRecoveryScripts {
            vault_lock: vault_lock.as_slice().to_vec(),
            participant_locks: locks.each_ref().map(|lock| lock.as_slice().to_vec()),
            carrier_refund_lock: owner_lock.as_slice().to_vec(),
            state_type: state_type.as_slice().to_vec(),
            state_lock: state_lock.as_slice().to_vec(),
            type_scripts: assets
                .iter()
                .map(|asset| MultiAssetTypeScript {
                    type_hash: asset.script.calc_script_hash().unpack(),
                    script: asset.script.as_slice().to_vec(),
                })
                .collect(),
        },
    };
    authorize(
        &mut package,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    let state_output = state_template.as_builder().capacity(carrier).build();
    let mut tx = TransactionBuilder::default()
        .cell_dep(secp.clone())
        .cell_dep(state_code.cell_dep.clone())
        .cell_dep(lock_code.cell_dep.clone())
        .cell_dep(vault_code.cell_dep.clone())
        .cell_dep(xudt_code.cell_dep.clone())
        .input(first_input)
        .output(state_output.clone())
        .output_data(Bytes::from(package.state.encode()?.to_vec()).pack());
    for (asset, vault) in assets.iter().zip(&package.manifest.vaults) {
        tx = tx
            .input(CellInput::new(asset.point.clone(), 0))
            .output(
                CellOutput::new_builder()
                    .capacity(vault.value.capacity()?)
                    .lock(vault_lock.clone())
                    .type_(Some(asset.script.clone()).pack())
                    .build(),
            )
            .output_data(Bytes::from(vault.value.amount.to_le_bytes().to_vec()).pack());
    }
    tx = tx
        .output(wallet_change(
            funding.capacity,
            carrier,
            options.fee,
            &owner_lock,
        )?)
        .output_data(Bytes::new().pack())
        .witness(proof(&package, true)?);
    let funding_transaction = tx.build();
    // CKB transaction identity excludes witnesses. Retain a signed unilateral
    // exit against the exact future Vault OutPoints before funding is sent.
    let predicted_funding_hash = funding_transaction.hash();
    let mut initial_recovery = package.clone();
    initial_recovery.outpoints = (0..assets.len())
        .map(|i| MultiAssetOutPoint {
            tx_hash: predicted_funding_hash.unpack(),
            index: i as u32 + 1,
        })
        .collect();
    initial_recovery.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&initial_recovery.manifest, &initial_recovery.outpoints)?;
    initial_recovery.state.header.phase = Phase::Settling;
    initial_recovery.state.header.state_number = 1;
    authorize(
        &mut initial_recovery,
        &options.alice_private_key,
        &options.bob_private_key,
    )?;
    let pre_funding_recovery = write_package(
        &options.store_dir,
        &StoredMultiAssetPackage::from_recovery(&initial_recovery, &recovery_deps)?,
    )?;
    let fund = send_and_mine(
        rpc,
        sign_group(
            funding_transaction,
            &owner,
            &(0..=assets.len()).collect::<Vec<_>>(),
        )?,
        options.mine_blocks,
    )?;
    ensure!(
        parse_h256(&fund.tx_hash)?.pack() == predicted_funding_hash,
        "funding transaction changed after unilateral recovery was retained"
    );
    let funding_hash = parse_h256(&fund.tx_hash)?;
    package.outpoints = (0..assets.len())
        .map(|i| MultiAssetOutPoint {
            tx_hash: funding_hash.0,
            index: i as u32 + 1,
        })
        .collect();
    package.state.vault_outpoint_set_root =
        multi_asset_outpoint_commitment(&package.manifest, &package.outpoints)?;
    let mut state_point = OutPoint::new(funding_hash.pack(), 0);
    let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let mut activation = TransactionBuilder::default();
    for point in &package.outpoints {
        activation = activation.cell_dep(direct_cell_dep(OutPoint::new(
            point.tx_hash.pack(),
            point.index,
        )));
    }
    let activation = activation
        .cell_dep(state_code.cell_dep.clone())
        .cell_dep(lock_code.cell_dep.clone())
        .cell_dep(secp.clone())
        .input(CellInput::new(state_point, 0))
        .input(CellInput::new(fee_cell.out_point, 0))
        .output(state_output.clone())
        .output_data(Bytes::from(package.state.encode()?.to_vec()).pack())
        .output(wallet_change(
            fee_cell.capacity,
            0,
            options.fee,
            &owner_lock,
        )?)
        .output_data(Bytes::new().pack())
        .witness(proof(&package, false)?)
        .build();
    let activation = send_and_mine(
        rpc,
        sign_group(activation, &owner, &[1])?,
        options.mine_blocks,
    )?;
    state_point = OutPoint::new(parse_h256(&activation.tx_hash)?.pack(), 0);
    let mut publications = Vec::new();
    let mut package_paths = Vec::new();
    for number in [1, 2] {
        package.state.header.phase = Phase::Settling;
        package.state.header.state_number = number;
        for payout in &mut package.settlement.payouts {
            payout.values[0].amount = if number == 1 { 700 } else { 400 };
            payout.values[1].amount = 1000 - payout.values[0].amount;
        }
        package.state.header.settlement_descriptor_commitment = package.settlement.commitment()?;
        authorize(
            &mut package,
            &options.alice_private_key,
            &options.bob_private_key,
        )?;
        let stored = StoredMultiAssetPackage::from_recovery(&package, &recovery_deps)?;
        let path = write_package(&options.store_dir, &stored)?;
        ensure!(
            crate::multi_asset_packages::read_package(&path)? == stored,
            "durable recovery package round trip failed"
        );
        package_paths.push(path.display().to_string());
        let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
        let publication = TransactionBuilder::default()
            .cell_dep(state_code.cell_dep.clone())
            .cell_dep(lock_code.cell_dep.clone())
            .cell_dep(secp.clone())
            .input(CellInput::new(state_point, 0))
            .input(CellInput::new(fee_cell.out_point, 0))
            .output(state_output.clone())
            .output_data(Bytes::from(package.state.encode()?.to_vec()).pack())
            .output(wallet_change(
                fee_cell.capacity,
                0,
                options.fee,
                &owner_lock,
            )?)
            .output_data(Bytes::new().pack())
            .witness(proof(&package, true)?)
            .build();
        let sent = send_and_mine(
            rpc,
            sign_group(publication, &owner, &[1])?,
            options.mine_blocks,
        )?;
        state_point = OutPoint::new(parse_h256(&sent.tx_hash)?.pack(), 0);
        publications.push(report(&sent));
    }
    mine_relative_since_maturity(rpc, options.finalise_since)?;
    let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let mut finalise = TransactionBuilder::default()
        .cell_dep(state_code.cell_dep)
        .cell_dep(lock_code.cell_dep)
        .cell_dep(vault_code.cell_dep)
        .cell_dep(xudt_code.cell_dep)
        .cell_dep(secp)
        .input(CellInput::new(state_point.clone(), since))
        .witness(proof(&package, false)?);
    for point in &package.outpoints {
        finalise = finalise.input(CellInput::new(
            OutPoint::new(point.tx_hash.pack(), point.index),
            0,
        ));
    }
    finalise = finalise.input(CellInput::new(fee_cell.out_point, 0));
    for (asset, payout) in assets.iter().zip(&package.settlement.payouts) {
        for (participant, lock) in locks.iter().enumerate() {
            let value = payout.values[participant];
            finalise = finalise
                .output(
                    CellOutput::new_builder()
                        .capacity(value.capacity()?)
                        .lock(lock.clone())
                        .type_(Some(asset.script.clone()).pack())
                        .build(),
                )
                .output_data(Bytes::from(value.amount.to_le_bytes().to_vec()).pack());
        }
    }
    finalise = finalise
        .output(
            CellOutput::new_builder()
                .capacity(carrier)
                .lock(owner_lock.clone())
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output(wallet_change(
            fee_cell.capacity,
            0,
            options.fee,
            &owner_lock,
        )?)
        .output_data(Bytes::new().pack());
    let finalise = sign_group(finalise.build(), &owner, &[assets.len() + 1])?;
    let finalise = send_and_mine(rpc, finalise, options.mine_blocks)?;
    ensure!(
        rpc.live_cell(state_point.into(), false)?.status != "live",
        "finalised State Cell remains live"
    );
    for point in &package.outpoints {
        ensure!(
            rpc.live_cell(
                OutPoint::new(point.tx_hash.pack(), point.index).into(),
                false
            )?
            .status
                != "live",
            "finalised Vault remains live"
        );
    }
    Ok(
        json!({"schema": "morph.multi_asset_devnet_acceptance.v1", "channel_id": format!("0x{}", hex::encode(channel_id)),
        "asset_count": assets.len(), "issuance": issuance, "fund": report(&fund), "activation": report(&activation),
        "publications": publications, "finalise": report(&finalise), "recovery_packages": package_paths,
        "pre_funding_recovery_package": pre_funding_recovery.display().to_string(),
        "summary": StoredMultiAssetPackage::from_recovery(&package, &recovery_deps)?.validate()?}),
    )
}
