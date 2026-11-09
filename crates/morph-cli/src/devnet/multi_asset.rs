//! Real-node construction for the multi-asset profile. Synthetic asset
//! issuance belongs only to the devnet acceptance harness.

use super::*;
use crate::funding_wallets::{FundingInput, FundingWallet, TokenContribution};
use crate::multi_asset_funding::RootFundingDraft;
use crate::multi_asset_funding_session::{
    FundingSessionCommand, FundingTarget, run as funding_run,
};
use crate::multi_asset_packages::{
    StoredMultiAssetPackage, canonical_hex as canonical_root_hex, write_package,
};
use crate::multi_asset_root_transaction::{RootAuthorityHashes, RootFundingTerms};
use crate::multi_asset_session::{SessionCommand, run};
use morph_core::{
    MultiAssetOutPoint, MultiAssetPayout, MultiAssetRecoveryPackage, MultiAssetSettlement,
    MultiAssetValue, StateAuthorization, multi_asset_outpoint_commitment,
};
use morph_script_common::multi_asset as wire;
use serde_json::{Value, json};

pub struct MultiAssetSmokeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: morph_key_input::SecretString,
    pub alice_private_key: morph_key_input::SecretString,
    pub bob_private_key: morph_key_input::SecretString,
    pub asset_count: usize,
    pub shared_funding: bool,
    pub funding_reorg: bool,
    pub splice_transitions: bool,
    pub fee: u64,
    pub finalise_since: u64,
    pub mine_blocks: u64,
    pub store_dir: PathBuf,
    pub publication_profile: Option<PathBuf>,
    pub watch_publication: bool,
    pub watch_reorg: bool,
    pub sponsor_publication: bool,
}

fn report(sent: &SentTransactionReport) -> Value {
    json!({"tx_hash": sent.tx_hash, "status": sent.status, "block_number": sent.block_number,
        "block_hash": sent.block_hash, "metrics": sent.metrics, "mined_blocks": sent.mined_blocks})
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
pub(super) fn sign_group(
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

pub(super) fn wallet_change(
    capacity: u64,
    spent: u64,
    fee: u64,
    lock: &Script,
) -> Result<CellOutput> {
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
    points: Vec<OutPoint>,
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
        !options.splice_transitions
            || (options.asset_count == 2
                && !options.watch_publication
                && !options.sponsor_publication),
        "splice trace acceptance requires exactly two assets and wallet publication"
    );
    ensure!(
        options.fee > 0 && options.mine_blocks > 0,
        "smoke requires a positive fee and mining budget"
    );
    ensure!(
        !options.watch_publication || options.publication_profile.is_some(),
        "watch acceptance requires a publication profile"
    );
    ensure!(
        !options.watch_reorg || options.watch_publication,
        "watch reorg acceptance requires watch publication"
    );
    ensure!(
        !options.funding_reorg
            || (options.shared_funding
                && !options.watch_publication
                && !options.splice_transitions),
        "funding reorg acceptance requires isolated shared funding without watch or splice"
    );
    let publication_max_fee = options
        .publication_profile
        .as_ref()
        .map(|path| read_publication_profile(path).map(|profile| profile.fee.max_fee))
        .transpose()?
        .unwrap_or(options.fee);
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
    if options.shared_funding {
        ensure!(
            owner_lock != locks[0] && owner_lock != locks[1],
            "shared-funding acceptance requires a distinct fee/carrier wallet"
        );
    }
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
    let seed = zeroize::Zeroizing::new(
        hex::decode(options.private_key.trim_start_matches("0x"))
            .context("invalid devnet funding key")?,
    );
    let mut assets = Vec::new();
    let mut issuance = Vec::new();
    for index in 0..options.asset_count {
        let issuer_seed = zeroize::Zeroizing::new(script_blake2b256(&[
            b"CKB_MORPH_DEVNET_MULTI_ASSET_ISSUER",
            seed.as_slice(),
            &(index as u64).to_le_bytes(),
        ]));
        let issuer_hex = zeroize::Zeroizing::new(hex::encode(issuer_seed.as_ref()));
        let issuer =
            parse_privkey(&issuer_hex).map_err(|_| anyhow!("invalid derived devnet issuer key"))?;
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
        let mut mint = TransactionBuilder::default()
            .cell_dep(secp.clone())
            .cell_dep(xudt_code.cell_dep.clone())
            .input(CellInput::new(issuer_point, 0));
        let funding_locks = if options.shared_funding {
            vec![&locks[0], &locks[1]]
        } else {
            vec![&owner_lock]
        };
        for (i, lock) in funding_locks.iter().enumerate() {
            let capacity = if options.shared_funding {
                reserve[i] + if i == 0 { 6_000_000_000 } else { 4_000_000_000 }
            } else {
                vault_capacity
            };
            let amount = if options.shared_funding {
                if i == 0 { 700u128 } else { 300u128 }
            } else {
                1000u128
            };
            mint = mint
                .output(
                    CellOutput::new_builder()
                        .capacity(capacity)
                        .lock((*lock).clone())
                        .type_(Some(script.clone()).pack())
                        .build(),
                )
                .output_data(Bytes::from(amount.to_le_bytes().to_vec()).pack());
        }
        let minted = send_and_mine(
            rpc,
            sign_group(mint.build(), &issuer, &[0])?,
            options.mine_blocks,
        )?;
        let mint_hash = parse_h256(&minted.tx_hash)?;
        let points = (0..funding_locks.len())
            .map(|i| OutPoint::new(mint_hash.pack(), i as u32))
            .collect();
        issuance.push(json!({"type_hash": format!("{:#x}", H256::from(script.calc_script_hash())), "fund": report(&funded), "mint": report(&minted)}));
        assets.push(AssetInput {
            script,
            points,
            reserve,
        });
    }
    assets.sort_by_key(|asset| asset.script.calc_script_hash());
    let funding = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let settlement = MultiAssetSettlement {
        capability: morph_core::MultiAssetSettlementCapability::Ordinary,
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
    let mut root_keys = [
        k256_signing_key(&options.alice_private_key)?,
        k256_signing_key(&options.bob_private_key)?,
    ];
    root_keys.sort_by_key(k256_pubkey);
    let public = root_keys.each_ref().map(k256_pubkey);
    let chain_id = rpc
        .genesis_block_hash()?
        .ok_or_else(|| anyhow!("missing genesis hash"))?
        .0;
    let authority = RootAuthorityHashes {
        state_type: state_code.data_hash.0,
        state_lock: lock_code.data_hash.0,
        vault_lock: vault_code.data_hash.0,
    };
    let mut points = vec![funding.out_point.clone()];
    if !options.shared_funding {
        points.extend(assets.iter().flat_map(|asset| asset.points.iter().cloned()));
    }
    let mut inputs = points
        .iter()
        .map(|point| FundingInput {
            tx_hash: canonical_root_hex(point.tx_hash().as_slice()),
            index: point.index().unpack(),
        })
        .collect::<Vec<_>>();
    inputs.sort_by(|a, b| (&a.tx_hash, a.index).cmp(&(&b.tx_hash, b.index)));
    let mut terms = RootFundingTerms {
        schema: "morph.multi_asset_root_terms.v1".to_string(),
        participants: public.map(|key| canonical_root_hex(&key)),
        participant_locks_hex: locks
            .each_ref()
            .map(|lock| canonical_root_hex(lock.as_slice())),
        carrier_refund_lock_hex: canonical_root_hex(owner_lock.as_slice()),
        descriptor_hex: canonical_root_hex(&settlement.encode()?),
        challenge_blocks: options.finalise_since.to_string(),
        type_scripts_hex: assets
            .iter()
            .map(|asset| canonical_root_hex(asset.script.as_slice()))
            .collect(),
        cell_deps: crate::multi_asset_packages::dependency_records(&recovery_deps)?,
        funders: vec![FundingWallet {
            pubkey: canonical_root_hex(&compressed_pubkey(&owner)?),
            inputs,
            ckb_contribution: "0".to_string(),
            fee_contribution: options.fee.to_string(),
            tokens: if options.shared_funding {
                vec![]
            } else {
                assets
                    .iter()
                    .map(|asset| TokenContribution {
                        type_hash: canonical_root_hex(asset.script.calc_script_hash().as_slice()),
                        amount: "1000".to_string(),
                    })
                    .collect()
            },
        }],
    };
    if options.shared_funding {
        for (i, lock) in locks.iter().enumerate() {
            let key = if secp256k1_lock(&alice)? == *lock {
                &alice
            } else {
                &bob
            };
            let mut inputs = assets
                .iter()
                .map(|asset| FundingInput {
                    tx_hash: canonical_root_hex(asset.points[i].tx_hash().as_slice()),
                    index: asset.points[i].index().unpack(),
                })
                .collect::<Vec<_>>();
            inputs.sort_by(|a, b| (&a.tx_hash, a.index).cmp(&(&b.tx_hash, b.index)));
            let capacity = assets.iter().try_fold(0u64, |sum, asset| {
                sum.checked_add(asset.reserve[i])
                    .and_then(|value| {
                        value.checked_add(if i == 0 { 6_000_000_000 } else { 4_000_000_000 })
                    })
                    .ok_or_else(|| anyhow!("shared funding capacity overflow"))
            })?;
            terms.funders.push(FundingWallet {
                pubkey: canonical_root_hex(&compressed_pubkey(key)?),
                inputs,
                ckb_contribution: capacity.to_string(),
                fee_contribution: "0".to_string(),
                tokens: assets
                    .iter()
                    .map(|asset| TokenContribution {
                        type_hash: canonical_root_hex(asset.script.calc_script_hash().as_slice()),
                        amount: if i == 0 { "700" } else { "300" }.to_string(),
                    })
                    .collect(),
            });
        }
    }
    terms.funders.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    let unsigned = terms.creation(chain_id, authority)?;
    let required = unsigned.manifest.vaults.iter().try_fold(
        unsigned.state_carrier_capacity,
        |total, vault| -> Result<u64> {
            total
                .checked_add(vault.value.capacity()?)
                .ok_or_else(|| anyhow!("root custody capacity overflow"))
        },
    )?;
    let owner_public = canonical_root_hex(&compressed_pubkey(&owner)?);
    terms
        .funders
        .iter_mut()
        .find(|funder| funder.pubkey == owner_public)
        .ok_or_else(|| anyhow!("missing fee/carrier funder"))?
        .ckb_contribution = if options.shared_funding {
        unsigned.state_carrier_capacity
    } else {
        required
    }
    .to_string();
    let terms_path = options.store_dir.join("root-funding-terms.json");
    ensure!(!terms_path.exists(), "root funding terms already exist");
    crate::persistence::write_private_atomic(&terms_path, &serde_json::to_vec_pretty(&terms)?)?;
    let admission_config = options.store_dir.join("bilateral-admission-config.json");
    crate::admission::create_config(
        rpc,
        crate::admission::ConfigOptions {
            envelope: PathBuf::from("release/factory-preproduction/envelope.json"),
            contracts_dir: options.contracts_dir.clone(),
            ledger: options.store_dir.join("bilateral-admission-ledger.json"),
            output: admission_config.clone(),
            admitted_asset_types: assets
                .iter()
                .map(|asset| canonical_root_hex(asset.script.calc_script_hash().as_slice()))
                .collect(),
            no_real_assets: true,
        },
    )?;
    let draft_path = options.store_dir.join("root-funding-draft.json");
    super::multi_asset_root_operator::prepare(
        rpc,
        super::multi_asset_root_operator::PrepareOptions {
            admission_config: admission_config.clone(),
            terms: terms_path.clone(),
            contracts_dir: options.contracts_dir.clone(),
            max_fee: options.fee,
            output: draft_path.clone(),
        },
    )?;
    let draft: RootFundingDraft = serde_json::from_slice(&fs::read(&draft_path)?)?;
    let (mut package, unsigned_exit) = draft.evidence()?;
    let channel_id = package.state.header.channel_id;
    let carrier = package.state_carrier_capacity;
    let predicted_funding_hash = draft.transaction()?.calc_tx_hash();
    let session_dir = options
        .store_dir
        .join("signers")
        .join(hex::encode(channel_id))
        .join(hex::encode(unsigned_exit.state.funding_context_id()?));
    let alice_session = session_dir.join("alice.json");
    let bob_session = session_dir.join("bob.json");
    for (session, secret) in [
        (&alice_session, &options.alice_private_key),
        (&bob_session, &options.bob_private_key),
    ] {
        funding_run(
            session,
            FundingSessionCommand::Init {
                admission_config: admission_config.clone(),
                draft: draft_path.clone(),
                local_pubkey: canonical_root_hex(&k256_pubkey(&k256_signing_key(secret)?)),
                contracts_dir: options.contracts_dir.clone(),
            },
        )?;
        let before = fs::read(session)?;
        ensure!(
            funding_run(
                session,
                FundingSessionCommand::Sign {
                    target: FundingTarget::Creation,
                    private_key: secret.clone()
                }
            )
            .is_err(),
            "root creation authorized before complete initial exit"
        );
        ensure!(
            fs::read(session)? == before,
            "premature root signing changed journal"
        );
    }
    for (target, label) in [
        (FundingTarget::Exit, "exit"),
        (FundingTarget::Creation, "creation"),
    ] {
        for (index, (session, secret)) in [
            (&alice_session, &options.alice_private_key),
            (&bob_session, &options.bob_private_key),
        ]
        .into_iter()
        .enumerate()
        {
            let receipt = funding_run(
                session,
                FundingSessionCommand::Sign {
                    target,
                    private_key: secret.clone(),
                },
            )?;
            crate::persistence::write_private_atomic(
                &session_dir.join(format!("root-{label}-{index}.json")),
                &serde_json::to_vec(&receipt)?,
            )?;
        }
        for (index, session) in [&alice_session, &bob_session].into_iter().enumerate() {
            if matches!(target, FundingTarget::Creation) && index == 0 {
                // A coordinator can collect Alice's approval and fund while
                // withholding Bob's final creation receipt from her. Her full
                // initial exit must remain independently usable in that case.
                continue;
            }
            funding_run(
                session,
                FundingSessionCommand::AddSignature {
                    target,
                    signature: session_dir.join(format!("root-{label}-{}.json", 1 - index)),
                },
            )?;
        }
    }
    let exported = funding_run(
        &bob_session,
        FundingSessionCommand::Export {
            store_dir: options.store_dir.clone(),
        },
    )?;
    let intent = PathBuf::from(
        exported["transaction"]
            .as_str()
            .ok_or_else(|| anyhow!("missing root transaction"))?,
    );
    let pre_funding_recovery = PathBuf::from(
        exported["recovery_package"]
            .as_str()
            .ok_or_else(|| anyhow!("missing initial exit"))?,
    );
    let independently_retained = funding_run(
        &alice_session,
        FundingSessionCommand::ExportRecovery {
            store_dir: options.store_dir.clone(),
        },
    )?;
    ensure!(
        independently_retained["recovery_package"].as_str()
            == Some(pre_funding_recovery.to_string_lossy().as_ref()),
        "withheld creation receipt prevented exact initial-exit recovery"
    );
    let initial_recovery =
        crate::multi_asset_packages::read_package(&pre_funding_recovery)?.recovery()?;
    let rejected = super::multi_asset_funding_operator::submit(
        rpc,
        super::multi_asset_funding_operator::Options {
            admission_config: admission_config.clone(),
            transaction: intent.clone(),
            package: pre_funding_recovery.clone(),
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            max_fee: options.fee,
            mine_blocks: 0,
            dry_run: true,
        },
    );
    ensure!(
        rejected.is_err(),
        "funding preflight accepted missing wallet signatures"
    );
    ensure!(
        !options
            .store_dir
            .join("submitted-funding")
            .join(format!(
                "funding-{}.tx",
                hex::encode(predicted_funding_hash.as_slice())
            ))
            .exists(),
        "failed wallet preflight poisoned the immutable funding transaction path"
    );
    let wallets = [
        (
            canonical_root_hex(&compressed_pubkey(&owner)?),
            &options.private_key,
        ),
        (
            canonical_root_hex(&compressed_pubkey(&alice)?),
            &options.alice_private_key,
        ),
        (
            canonical_root_hex(&compressed_pubkey(&bob)?),
            &options.bob_private_key,
        ),
    ];
    let mut intent = intent;
    for funder in &terms.funders {
        let secret = wallets
            .iter()
            .find(|(public, _)| *public == funder.pubkey)
            .map(|(_, secret)| (*secret).clone())
            .ok_or_else(|| anyhow!("unknown acceptance funding wallet"))?;
        let signed = super::multi_asset_root_operator::sign_wallet(
            rpc,
            super::multi_asset_root_operator::SignOptions {
                admission_config: admission_config.clone(),
                terms: terms_path.clone(),
                transaction: intent,
                package: pre_funding_recovery.clone(),
                contracts_dir: options.contracts_dir.clone(),
                max_fee: options.fee,
                store_dir: options
                    .store_dir
                    .join("funding-wallet")
                    .join(funder.pubkey.trim_start_matches("0x")),
                private_key: secret,
            },
        )?;
        intent = PathBuf::from(
            signed["transaction"]
                .as_str()
                .ok_or_else(|| anyhow!("missing wallet-signed funding"))?,
        );
    }
    let before_funding_tip = rpc.tip_header()?;
    let mut fund = super::multi_asset_funding_operator::submit(
        rpc,
        super::multi_asset_funding_operator::Options {
            admission_config: admission_config.clone(),
            transaction: intent,
            package: pre_funding_recovery.clone(),
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            dry_run: false,
        },
    )?;
    let funding_hash = parse_h256(
        fund["tx_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("funding submission has no hash"))?,
    )?;
    ensure!(
        funding_hash.pack() == predicted_funding_hash,
        "funding transaction changed after unilateral recovery was retained"
    );
    let funding_replay = if options.funding_reorg {
        let journals_before = [fs::read(&alice_session)?, fs::read(&bob_session)?];
        let signed_path = PathBuf::from(
            fund["signed_transaction"]
                .as_str()
                .ok_or_else(|| anyhow!("funding submission has no immutable binary"))?,
        );
        let exact_signed_bytes = fs::read(&signed_path)?;
        let first_inclusion = fund.clone();
        rpc.truncate(parse_h256(&before_funding_tip.hash)?)?;
        ensure!(
            rpc.tip_header()?.hash == before_funding_tip.hash,
            "funding orphan acceptance did not restore its canonical predecessor"
        );
        let orphaned = rpc.transaction(funding_hash.clone())?;
        ensure!(
            orphaned.tx_status.status != Status::Committed,
            "funding remained committed after controlled rollback"
        );
        let recovery = funding_run(
            &alice_session,
            FundingSessionCommand::ExportRecovery {
                store_dir: options.store_dir.clone(),
            },
        )?;
        ensure!(
            recovery["recovery_package"] == independently_retained["recovery_package"],
            "funding orphan changed the saved private initial exit"
        );
        let replayed = super::multi_asset_funding_operator::submit(
            rpc,
            super::multi_asset_funding_operator::Options {
                admission_config: admission_config.clone(),
                transaction: signed_path.clone(),
                package: pre_funding_recovery.clone(),
                contracts_dir: options.contracts_dir.clone(),
                store_dir: options.store_dir.clone(),
                max_fee: options.fee,
                mine_blocks: options.mine_blocks,
                dry_run: false,
            },
        )?;
        ensure!(
            replayed["tx_hash"] == first_inclusion["tx_hash"]
                && replayed["status"] == "Committed"
                && fs::read(&signed_path)? == exact_signed_bytes
                && [fs::read(&alice_session)?, fs::read(&bob_session)?] == journals_before,
            "exact root replay changed transaction bytes or signer authority"
        );
        fund = replayed;
        json!({"orphaned":true,"exact_body_and_witnesses":true,"unchanged_signer_journals":true,
            "peer_creation_receipt_withheld":true,"original":first_inclusion,"replayed":fund})
    } else {
        Value::Null
    };
    let funding_block_number = fund["block_number"]
        .as_u64()
        .ok_or_else(|| anyhow!("funding inclusion height missing"))?;
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
    let activation = super::multi_asset_operator::transact(
        rpc,
        super::multi_asset_operator::Options {
            operation: super::multi_asset_operator::Operation::Activate,
            package: pre_funding_recovery.clone(),
            state_out_point: format_out_point(&state_point),
            fee_out_point: format_out_point(&fee_cell.out_point),
            fee_authorization: super::multi_asset_operator::FeeAuthorization::Wallet {
                private_key: options.private_key.clone(),
            },
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            fee: options.fee,
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            publication_profile: None,
            attempt_log: None,
            dry_run: false,
        },
    )?;
    let activation_hash = activation["tx_hash"]
        .as_str()
        .ok_or_else(|| anyhow!("missing activation hash"))?;
    state_point = OutPoint::new(parse_h256(activation_hash)?.pack(), 0);
    let mut publications = Vec::new();
    let mut sponsor_funding = Vec::new();
    let mut watch_passes = Vec::new();
    let mut operator_checks = vec!["activation_reconstructed_from_funding_evidence"];
    let mut package_paths = Vec::new();
    // Bind while Active/0 has no running dispute window, before exposing
    // new off-chain updates or beginning the publication acceptance matrix.
    let activation_height = activation["block_number"]
        .as_u64()
        .ok_or_else(|| anyhow!("activation has no inclusion height"))?;
    for _ in 0..32 {
        if block_confirmations(activation_height, rpc.tip_header()?.number_value()?)? >= 4 {
            break;
        }
        rpc.generate_block()?;
        // IntegrationTest block generation may return before canonical tip
        // processing catches up. Observe depth instead of assuming RPC count.
        std::thread::sleep(Duration::from_millis(50));
    }
    for session in [&alice_session, &bob_session] {
        let before = fs::read(session)?;
        ensure!(
            funding_run(
                session,
                FundingSessionCommand::Confirm {
                    rpc_url: rpc.endpoint().to_string(),
                    state_out_point: format_out_point(&state_point),
                    min_confirmations: u64::MAX,
                    archive_dir: options.store_dir.join("initial-journals"),
                    contracts_dir: options.contracts_dir.clone()
                }
            )
            .is_err(),
            "root guard accepted insufficient confirmation depth"
        );
        ensure!(
            fs::read(session)? == before,
            "failed root depth check changed the journal"
        );
        let wrong_point = OutPoint::new(state_point.tx_hash(), 1);
        ensure!(
            funding_run(
                session,
                FundingSessionCommand::Confirm {
                    rpc_url: rpc.endpoint().to_string(),
                    state_out_point: format_out_point(&wrong_point),
                    min_confirmations: 4,
                    archive_dir: options.store_dir.join("initial-journals"),
                    contracts_dir: options.contracts_dir.clone()
                }
            )
            .is_err(),
            "root guard accepted a non-State output"
        );
        ensure!(
            fs::read(session)? == before,
            "failed root binding changed the signer journal"
        );
        funding_run(
            session,
            FundingSessionCommand::Confirm {
                rpc_url: rpc.endpoint().to_string(),
                state_out_point: format_out_point(&state_point),
                min_confirmations: 4,
                archive_dir: options.store_dir.join("initial-journals"),
                contracts_dir: options.contracts_dir.clone(),
            },
        )?;
    }
    operator_checks.push("root_creation_bound_without_resetting_votes");
    operator_checks.push("independent_initial_exit_before_creation_and_same_path_confirmation");
    operator_checks.push("withheld_root_creation_receipt_recovered_from_canonical_funding");
    if options.funding_reorg {
        operator_checks.push("root_funding_orphaned_and_exact_signed_replayed_without_peer");
    }
    operator_checks.push("public_root_builder_explicit_funder_budgets");
    operator_checks.push("unsigned_wallet_preflight_cannot_poison_funding_artifact");
    if options.shared_funding {
        operator_checks.push("three_distinct_funders_signed_only_their_own_groups");
    }
    if options.splice_transitions {
        let transitions = super::multi_asset_splice_acceptance::run(
            rpc,
            super::multi_asset_splice_acceptance::Context {
                options: &options,
                alice_session: &alice_session,
                bob_session: &bob_session,
                owner_lock: &owner_lock,
                recovery_deps: &recovery_deps,
            },
            initial_recovery,
            state_point,
        )?;
        return Ok(
            json!({"schema":"morph.current_splice_devnet_acceptance.v1", "fund":fund, "activation":activation, "operator_checks":operator_checks, "transitions":transitions}),
        );
    }
    if options.watch_publication {
        let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
        let pass = super::multi_asset_watch::watch(
            rpc,
            super::multi_asset_watch::Options {
                contracts_dir: options.contracts_dir.clone(),
                fee_authorization: super::multi_asset_operator::FeeAuthorization::Wallet {
                    private_key: options.private_key.clone(),
                },
                fee_out_point: format_out_point(&fee_cell.out_point),
                store_dir: options.store_dir.clone(),
                channel_id: hex32(&channel_id),
                from_block: funding_block_number,
                cursor_file: options
                    .store_dir
                    .join(format!("watch-{}.json", hex::encode(channel_id))),
                alert_file: options
                    .store_dir
                    .join(format!("watch-alerts-{}.jsonl", hex::encode(channel_id))),
                publication_profile: options
                    .publication_profile
                    .clone()
                    .ok_or_else(|| anyhow!("missing watch profile"))?,
                attempt_log: options.store_dir.join("watch-publication-attempts.jsonl"),
                detection_depth: 1,
                timeout_secs: 1,
                poll_ms: 100,
                max_fee: publication_max_fee,
                mine_blocks: options.mine_blocks,
                watch_policy: None,
                alert_webhook_url: None,
                auto_fund_sponsor: None,
            },
        )?;
        ensure!(
            pass["publication"].is_null(),
            "watch force-closed an active channel"
        );
        watch_passes.push(pass);
        operator_checks.push("watch_kept_active_channel_open");
    }
    for number in [1, 2] {
        if number == 1 {
            // Reuse the exact pre-funding unilateral state, never re-sign a
            // different descriptor at the same context/number.
            package = initial_recovery.clone();
        } else {
            let mut settlement = package.settlement.clone();
            for payout in &mut settlement.payouts {
                payout.values[0].amount = 400;
                payout.values[1].amount = 600;
            }
            let proposal = run(
                &alice_session,
                SessionCommand::Propose {
                    descriptor_hex: format!("0x{}", hex::encode(settlement.encode()?)),
                },
            )?;
            let proposal_path = session_dir.join("proposal.json");
            fs::write(&proposal_path, serde_json::to_vec(&proposal)?)?;
            run(
                &bob_session,
                SessionCommand::Accept {
                    proposal: proposal_path,
                },
            )?;
            let mut signatures = Vec::new();
            for (index, (session, secret)) in [
                (&alice_session, &options.alice_private_key),
                (&bob_session, &options.bob_private_key),
            ]
            .into_iter()
            .enumerate()
            {
                let signature = run(
                    session,
                    SessionCommand::Sign {
                        target: crate::multi_asset_session::SigningTarget::Update,
                        private_key: secret.clone(),
                    },
                )?;
                let path = session_dir.join(format!("signature-{index}.json"));
                fs::write(&path, serde_json::to_vec(&signature)?)?;
                signatures.push(path);
            }
            run(
                &alice_session,
                SessionCommand::AddSignature {
                    target: crate::multi_asset_session::SigningTarget::Update,
                    signature: signatures[1].clone(),
                },
            )?;
            run(
                &bob_session,
                SessionCommand::AddSignature {
                    target: crate::multi_asset_session::SigningTarget::Update,
                    signature: signatures[0].clone(),
                },
            )?;
            let committed = run(
                &alice_session,
                SessionCommand::Commit {
                    store_dir: options.store_dir.clone(),
                },
            )?;
            let peer = run(
                &bob_session,
                SessionCommand::Commit {
                    store_dir: options.store_dir.clone(),
                },
            )?;
            ensure!(committed == peer, "participant recovery packages disagree");
            let path = committed["recovery_package"]
                .as_str()
                .ok_or_else(|| anyhow!("missing committed recovery path"))?;
            package = crate::multi_asset_packages::read_package(Path::new(path))?.recovery()?;
            ensure!(
                package.state.header.state_number == number,
                "backend update number differs from acceptance stage"
            );
            operator_checks.push("durable_signing_sessions_committed");
        }
        let stored = StoredMultiAssetPackage::from_recovery(&package, &recovery_deps)?;
        let path = write_package(&options.store_dir, &stored)?;
        ensure!(
            crate::multi_asset_packages::read_package(&path)? == stored,
            "durable recovery package round trip failed"
        );
        package_paths.push(path.display().to_string());
        let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
        if number == 1 {
            let temporary = options.store_dir.join("operator-rejection.json");
            let operator_options = |path: PathBuf| super::multi_asset_operator::Options {
                operation: super::multi_asset_operator::Operation::Publish,
                package: path,
                state_out_point: format_out_point(&state_point),
                fee_out_point: format_out_point(&fee_cell.out_point),
                fee_authorization: super::multi_asset_operator::FeeAuthorization::Wallet {
                    private_key: options.private_key.clone(),
                },
                contracts_dir: options.contracts_dir.clone(),
                store_dir: options.store_dir.clone(),
                fee: options.fee,
                max_fee: options.fee,
                mine_blocks: 0,
                publication_profile: None,
                attempt_log: None,
                dry_run: true,
            };
            let mut missing_code = stored.clone();
            let vault_point = vault_code.cell_dep.out_point();
            let vault_index: u32 = vault_point.index().unpack();
            missing_code.cell_deps.retain(|dep| {
                dep.tx_hash != format!("0x{}", hex::encode(vault_point.tx_hash().as_slice()))
                    || dep.index != vault_index
            });
            fs::write(&temporary, serde_json::to_vec(&missing_code)?)?;
            let error =
                super::multi_asset_operator::transact(rpc, operator_options(temporary.clone()))
                    .err()
                    .ok_or_else(|| anyhow!("missing code dependency was accepted"))?;
            ensure!(
                error
                    .to_string()
                    .contains("no live dependency resolves committed script 3"),
                "unexpected missing-code rejection: {error}"
            );
            operator_checks.push("missing_code_dependency_rejected");
            let mut changed_carrier = stored.clone();
            changed_carrier.state_carrier_capacity = (carrier + 1).to_string();
            fs::write(&temporary, serde_json::to_vec(&changed_carrier)?)?;
            let error =
                super::multi_asset_operator::transact(rpc, operator_options(temporary.clone()))
                    .err()
                    .ok_or_else(|| anyhow!("changed carrier was accepted"))?;
            ensure!(
                error.to_string().contains("State authority/carrier"),
                "unexpected carrier rejection: {error}"
            );
            operator_checks.push("changed_state_carrier_rejected");
            fs::remove_file(temporary)?;
            let preview =
                super::multi_asset_operator::transact(rpc, operator_options(path.clone()))?;
            ensure!(
                preview["dry_run"] == true,
                "operator preview did not report dry run"
            );
            operator_checks.push("signed_transaction_vm_preview_passed");
        }
        let (publication_fee_point, fee_authorization) = if options.sponsor_publication {
            let change_pubkey = format!("0x{}", hex::encode(compressed_pubkey(&owner)?));
            let funded = fund_sponsor(
                rpc,
                FundSponsorOptions {
                    contracts_dir: options.contracts_dir.clone(),
                    private_key: options.private_key.clone(),
                    sponsor_change_pubkey: Some(change_pubkey.clone()),
                    state_out_point: format_out_point(&state_point),
                    sponsor_capacity: publication_max_fee
                        .checked_add(30_000_000_000)
                        .ok_or_else(|| anyhow!("acceptance sponsor capacity overflow"))?,
                    sponsor_min_state_number: number,
                    sponsor_max_state_number: number,
                    strict_sponsor_range: true,
                    sponsor_max_fee_per_tx: Some(publication_max_fee),
                    sponsor_max_total_fee: Some(publication_max_fee),
                    fee: options.fee,
                    mine_blocks: options.mine_blocks,
                },
            )?;
            let point = printable_out_point_string(&funded.sponsor_out_point);
            let report = serde_json::to_value(&funded)?;
            crate::persistence::write_private_atomic(
                &options
                    .store_dir
                    .join(format!("sponsor-funding-{number}.json")),
                &serde_json::to_vec(&report)?,
            )?;
            sponsor_funding.push(report);
            (
                point,
                super::multi_asset_operator::FeeAuthorization::Sponsor { change_pubkey },
            )
        } else {
            (
                format_out_point(&fee_cell.out_point),
                super::multi_asset_operator::FeeAuthorization::Wallet {
                    private_key: options.private_key.clone(),
                },
            )
        };
        if options.sponsor_publication {
            let operator_options = || super::multi_asset_operator::Options {
                operation: super::multi_asset_operator::Operation::Publish,
                package: path.clone(),
                state_out_point: format_out_point(&state_point),
                fee_out_point: publication_fee_point.clone(),
                fee_authorization: fee_authorization.clone(),
                contracts_dir: options.contracts_dir.clone(),
                store_dir: options.store_dir.clone(),
                fee: options.fee,
                max_fee: publication_max_fee,
                mine_blocks: 0,
                publication_profile: None,
                attempt_log: None,
                dry_run: true,
            };
            let mut wrong_change = operator_options();
            wrong_change.fee_authorization =
                super::multi_asset_operator::FeeAuthorization::Sponsor {
                    change_pubkey: format!(
                        "0x{}",
                        hex::encode(
                            if compressed_pubkey(&alice)? == compressed_pubkey(&owner)? {
                                compressed_pubkey(&bob)?
                            } else {
                                compressed_pubkey(&alice)?
                            }
                        )
                    ),
                };
            let error = super::multi_asset_operator::transact(rpc, wrong_change)
                .err()
                .ok_or_else(|| anyhow!("sponsor accepted a different change key"))?;
            ensure!(
                error.to_string().contains("sponsor change lock differs"),
                "unexpected sponsor change rejection: {error}"
            );
            let mut over_budget = operator_options();
            over_budget.fee = publication_max_fee
                .checked_add(1)
                .ok_or_else(|| anyhow!("acceptance fee overflow"))?;
            over_budget.max_fee = over_budget.fee;
            let error = super::multi_asset_operator::transact(rpc, over_budget)
                .err()
                .ok_or_else(|| anyhow!("sponsor accepted a fee above policy"))?;
            ensure!(
                error.to_string().contains("sponsor per-transaction cap"),
                "unexpected sponsor fee rejection: {error}"
            );
            let mut finalise = operator_options();
            finalise.operation = super::multi_asset_operator::Operation::Finalise;
            let error = super::multi_asset_operator::transact(rpc, finalise)
                .err()
                .ok_or_else(|| anyhow!("sponsor accepted finalisation"))?;
            ensure!(
                error.to_string().contains("publication only"),
                "unexpected sponsor operation rejection: {error}"
            );
            let preview = super::multi_asset_operator::transact(rpc, operator_options())?;
            let tx: ckb_jsonrpc_types::Transaction =
                serde_json::from_value(preview["transaction"].clone())?;
            let fee_witness = tx
                .witnesses
                .get(1)
                .ok_or_else(|| anyhow!("missing sponsor witness"))?;
            let fee_witness = WitnessArgs::from_slice(fee_witness.as_bytes())?;
            ensure!(
                preview["fee_source"] == "sponsor" && fee_witness.lock().to_opt().is_none(),
                "sponsor preview contains a fee signature or wrong authority"
            );
            if number == 1 {
                operator_checks.extend([
                    "sponsor_change_substitution_rejected",
                    "sponsor_fee_cap_rejected",
                    "sponsor_finalisation_rejected",
                    "sponsor_signatureless_vm_preview_passed",
                ]);
            }
        }
        let sent = if options.watch_publication && number == 2 {
            let profile = options
                .publication_profile
                .as_ref()
                .ok_or_else(|| anyhow!("missing watch profile"))?;
            let from_block = funding_block_number;
            let cursor_path = options
                .store_dir
                .join(format!("watch-{}.json", hex::encode(channel_id)));
            let alert_path = options
                .store_dir
                .join(format!("watch-alerts-{}.jsonl", hex::encode(channel_id)));
            let watch_options = || super::multi_asset_watch::Options {
                contracts_dir: options.contracts_dir.clone(),
                fee_authorization: fee_authorization.clone(),
                fee_out_point: publication_fee_point.clone(),
                store_dir: options.store_dir.clone(),
                channel_id: hex32(&channel_id),
                from_block,
                cursor_file: cursor_path.clone(),
                alert_file: alert_path.clone(),
                publication_profile: profile.clone(),
                attempt_log: options.store_dir.join("watch-publication-attempts.jsonl"),
                detection_depth: 1,
                timeout_secs: 1,
                poll_ms: 100,
                max_fee: publication_max_fee,
                mine_blocks: options.mine_blocks,
                watch_policy: None,
                alert_webhook_url: None,
                auto_fund_sponsor: None,
            };
            // A full signature conflict is retained outside the active store
            // after its rejection, never silently chosen by digest ordering.
            let mut conflict = package.clone();
            conflict.settlement.payouts[0].values[0].amount -= 1;
            conflict.settlement.payouts[0].values[1].amount += 1;
            conflict.state.header.settlement_descriptor_commitment =
                conflict.settlement.commitment()?;
            authorize(
                &mut conflict,
                &options.alice_private_key,
                &options.bob_private_key,
            )?;
            let conflicting = write_package(
                &options.store_dir,
                &StoredMultiAssetPackage::from_recovery(&conflict, &recovery_deps)?,
            )?;
            let error = super::multi_asset_watch::watch(rpc, watch_options())
                .err()
                .ok_or_else(|| anyhow!("watch accepted conflicting signed states"))?;
            ensure!(
                error.to_string().contains("conflicting recovery packages"),
                "unexpected conflict rejection: {error}"
            );
            fs::rename(
                conflicting,
                options.store_dir.join(format!(
                    "rejected-conflict-{}.json",
                    hex::encode(channel_id)
                )),
            )?;
            operator_checks.push("watch_rejected_conflicting_signed_states");
            // Simulate a newer complete package arriving after a canonical
            // scan has already passed the live stale State's creation block.
            let held = options
                .store_dir
                .join(format!("held-recovery-{}.json", hex::encode(channel_id)));
            fs::rename(&path, &held)?;
            let mut late_origin = watch_options();
            late_origin.from_block = from_block + 1;
            late_origin.cursor_file = options
                .store_dir
                .join(format!("late-origin-{}.json", hex::encode(channel_id)));
            let error = super::multi_asset_watch::watch(rpc, late_origin)
                .err()
                .ok_or_else(|| anyhow!("watch accepted a late scan origin"))?;
            ensure!(
                error
                    .to_string()
                    .contains("later than retained channel funding block"),
                "unexpected scan-origin rejection: {error}"
            );
            operator_checks.push("watch_rejected_late_scan_origin");
            let held_initial = options
                .store_dir
                .join(format!("held-initial-{}.json", hex::encode(channel_id)));
            fs::rename(&pre_funding_recovery, &held_initial)?;
            let mut conflicting_current = initial_recovery.clone();
            conflicting_current.settlement.payouts[0].values[0].amount -= 1;
            conflicting_current.settlement.payouts[0].values[1].amount += 1;
            conflicting_current
                .state
                .header
                .settlement_descriptor_commitment = conflicting_current.settlement.commitment()?;
            authorize(
                &mut conflicting_current,
                &options.alice_private_key,
                &options.bob_private_key,
            )?;
            let conflicting_current = write_package(
                &options.store_dir,
                &StoredMultiAssetPackage::from_recovery(&conflicting_current, &recovery_deps)?,
            )?;
            let error = super::multi_asset_watch::watch(rpc, watch_options())
                .err()
                .ok_or_else(|| anyhow!("watch accepted a same-number on-chain conflict"))?;
            ensure!(
                error.to_string().contains("live State conflicts"),
                "unexpected on-chain conflict rejection: {error}"
            );
            fs::rename(
                conflicting_current,
                options.store_dir.join(format!(
                    "rejected-on-chain-conflict-{}.json",
                    hex::encode(channel_id)
                )),
            )?;
            fs::rename(held_initial, &pre_funding_recovery)?;
            operator_checks.push("watch_rejected_same_number_on_chain_conflict");
            let idle = super::multi_asset_watch::watch(rpc, watch_options())?;
            ensure!(
                idle["publication"].is_null(),
                "watch published without newer saved evidence"
            );
            watch_passes.push(idle);
            fs::rename(held, &path)?;
            let before_publication_tip = rpc.tip_header()?;
            let corrected = if options.sponsor_publication {
                let corrected = service_watch_acceptance(
                    rpc,
                    watch_options(),
                    &options.private_key,
                    options.fee,
                )?;
                operator_checks.extend([
                    "current_watch_service_auto_sponsor_published",
                    "current_watch_service_health_verified",
                ]);
                corrected
            } else {
                super::multi_asset_watch::watch(rpc, watch_options())?
            };
            ensure!(
                corrected["retry_rescan"] == true,
                "late recovery package did not trigger rescan"
            );
            let mut sent = corrected["publication"].clone();
            ensure!(!sent.is_null(), "watch failed to publish saved newer state");
            watch_passes.push(corrected);
            operator_checks.push("watch_published_late_recovery_package");
            if options.watch_reorg {
                let caught_up = super::multi_asset_watch::watch(rpc, watch_options())?;
                ensure!(
                    caught_up["publication"].is_null(),
                    "watch republished an already corrected state"
                );
                watch_passes.push(caught_up);
                // Roll back only this isolated acceptance channel's last
                // publication branch, keeping its funding and previous state.
                rpc.truncate(parse_h256(&before_publication_tip.hash)?)?;
                let recovered = super::multi_asset_watch::watch(rpc, watch_options())?;
                ensure!(
                    !recovered["reorg_recovery"].is_null(),
                    "watch missed real chain rollback"
                );
                ensure!(
                    recovered["publication"]["canonical_confirmed"] == true,
                    "watch failed to reconfirm replacement after reorg"
                );
                sent = recovered["publication"].clone();
                watch_passes.push(recovered);
                operator_checks.push("watch_reorg_rescan_republished");
            }
            sent
        } else {
            super::multi_asset_operator::transact(
                rpc,
                super::multi_asset_operator::Options {
                    operation: super::multi_asset_operator::Operation::Publish,
                    package: path,
                    state_out_point: format_out_point(&state_point),
                    fee_out_point: publication_fee_point.clone(),
                    fee_authorization: fee_authorization.clone(),
                    contracts_dir: options.contracts_dir.clone(),
                    store_dir: options.store_dir.clone(),
                    fee: options.fee,
                    max_fee: publication_max_fee,
                    mine_blocks: options.mine_blocks,
                    publication_profile: options.publication_profile.clone(),
                    attempt_log: options
                        .publication_profile
                        .as_ref()
                        .map(|_| options.store_dir.join("publication-attempts.jsonl")),
                    dry_run: false,
                },
            )?
        };
        if options.sponsor_publication {
            ensure!(
                sent["fee_source"] == "sponsor",
                "publication silently changed fee authority"
            );
        }
        let hash = sent["tx_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("publication report has no hash"))?;
        state_point = OutPoint::new(parse_h256(hash)?.pack(), 0);
        publications.push(sent);
    }
    mine_relative_since_maturity(rpc, options.finalise_since)?;
    let fee_cell = find_largest_live_cell(rpc, &owner_lock, rpc.tip_header()?.number_value()?)?;
    let last_package = package_paths
        .last()
        .ok_or_else(|| anyhow!("missing recovery package"))?;
    let finalise = super::multi_asset_operator::transact(
        rpc,
        super::multi_asset_operator::Options {
            operation: super::multi_asset_operator::Operation::Finalise,
            package: PathBuf::from(last_package),
            state_out_point: format_out_point(&state_point),
            fee_out_point: format_out_point(&fee_cell.out_point),
            fee_authorization: super::multi_asset_operator::FeeAuthorization::Wallet {
                private_key: options.private_key.clone(),
            },
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            fee: options.fee,
            max_fee: options.fee,
            mine_blocks: options.mine_blocks,
            publication_profile: None,
            attempt_log: None,
            dry_run: false,
        },
    )?;
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
        "asset_count": assets.len(), "shared_funding":options.shared_funding, "operator_checks": operator_checks, "watch_passes":watch_passes, "issuance": issuance, "fund": fund, "funding_replay":funding_replay,"activation": activation,
        "publications": publications, "sponsor_funding": sponsor_funding, "finalise": finalise, "recovery_packages": package_paths,
        "pre_funding_recovery_package": pre_funding_recovery.display().to_string(),"root_funding_terms":terms_path,"root_funding_draft":draft_path,
        "summary": StoredMultiAssetPackage::from_recovery(&package, &recovery_deps)?.validate()?}),
    )
}

/// Exercise the public service coordinator over the same current watcher used
/// by direct passes. This creates no alternate State or publication builder.
fn service_watch_acceptance(
    rpc: &CkbRpcClient,
    options: super::multi_asset_watch::Options,
    funding_key: &str,
    funding_fee: u64,
) -> Result<Value> {
    use crate::watch_config::{
        self, WatchtowerConfig, WatchtowerConfigServiceOptions, WatchtowerRuntimeOptions,
    };
    fn absolute(path: &Path) -> Result<PathBuf> {
        Ok(if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        })
    }
    let store = absolute(&options.store_dir)?;
    let profile = read_publication_profile(&options.publication_profile)?;
    let mut config = WatchtowerConfig::fixture();
    config.operator_id = profile.operator_id;
    config.defaults.store_dir = Some(store.clone());
    config.defaults.publication_profile = Some(absolute(&options.publication_profile)?);
    config.defaults.publication_attempt_log = Some(absolute(&options.attempt_log)?);
    config.defaults.alert_file = Some(absolute(&options.alert_file)?);
    config.defaults.alert_webhook_url = None;
    config.defaults.detection_depth = Some(options.detection_depth);
    config.defaults.timeout_secs = Some(options.timeout_secs);
    config.defaults.poll_ms = Some(options.poll_ms);
    config.defaults.fee = Some(funding_fee);
    config.defaults.mine_blocks = Some(options.mine_blocks);
    config.defaults.auto_fund_sponsor = Some(true);
    let capacity = options
        .max_fee
        .checked_add(30_000_000_000)
        .ok_or_else(|| anyhow!("watch service sponsor capacity overflow"))?;
    config.defaults.auto_sponsor_capacity = Some(capacity);
    config.channels[0].channel_id = options.channel_id;
    config.channels[0].from_block = options.from_block;
    config.channels[0].cursor_file = Some(absolute(&options.cursor_file)?);
    let mut policy = crate::watch_policy::fixture_policy();
    policy.channel_id = Some(config.channels[0].channel_id.clone());
    policy.min_detection_depth = options.detection_depth;
    policy.min_timeout_secs = options.timeout_secs;
    policy.max_poll_ms = options.poll_ms;
    policy.max_fee = options.max_fee;
    policy.allow_explicit_sponsor = false;
    policy.require_auto_fund_sponsor = true;
    policy.max_auto_sponsor_capacity = capacity;
    policy.allow_webhook_alerts = false;
    let policy_path = store.join("current-watch-service-policy.json");
    config.defaults.watch_policy = Some(policy_path.clone());
    crate::persistence::write_private_atomic(&policy_path, &serde_json::to_vec_pretty(&policy)?)?;
    let config_path = store.join("current-watch-service-config.json");
    crate::persistence::write_private_atomic(&config_path, &serde_json::to_vec_pretty(&config)?)?;
    let health_path = store.join("current-watch-service-health.json");
    let service = watch_config::run_watchtower_config_service(
        rpc,
        &config_path,
        &config,
        WatchtowerRuntimeOptions {
            contracts_dir: options.contracts_dir,
            private_key: funding_key.to_string().into(),
        },
        WatchtowerConfigServiceOptions {
            max_passes: Some(1),
            sleep_ms: 1,
            error_backoff_ms: 1,
            max_consecutive_errors: 1,
            stop_after_publication: true,
            stop_file: None,
            health_file: Some(health_path.clone()),
        },
    )?;
    ensure!(
        service.completed_passes == 1
            && service.published_count == 1
            && service.stopped_reason == "publication",
        "current watch service failed canonical publication: {:?}",
        service.last_error
    );
    let mut pass = service
        .last_pass
        .as_ref()
        .and_then(|report| report.channels.first())
        .context("watch service returned no current pass")?
        .report
        .clone();
    ensure!(
        pass["publication"]["canonical_confirmed"] == true && !pass["sponsor_top_up"].is_null(),
        "watch service bypassed auto sponsor funding or canonical confirmation"
    );
    let health: serde_json::Value = serde_json::from_slice(&fs::read(health_path)?)?;
    ensure!(
        health["status"] == "stopped"
            && health["stopped_reason"] == "publication"
            && health["completed_passes"] == 1,
        "watch service health differs from terminal result"
    );
    pass["service"] = serde_json::to_value(service)?;
    Ok(pass)
}
