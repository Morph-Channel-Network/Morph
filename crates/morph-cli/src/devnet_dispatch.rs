use super::*;
use crate::packages::canonical_hex32;

pub(super) fn run_devnet(rpc_url: &str, command: DevnetCommand) -> Result<()> {
    let rpc = CkbRpcClient::new(rpc_url)?;
    match command {
        DevnetCommand::MultiAssetSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            asset_count,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json: _,
        } => {
            let report = devnet::multi_asset::smoke(
                &rpc,
                devnet::multi_asset::MultiAssetSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    asset_count,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::Check { json } => {
            let status = rpc.status()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "rpc_url": rpc_url,
                        "chain": status.chain.chain,
                        "initial_block_download": status.chain.is_initial_block_download,
                        "median_time": status.chain.median_time,
                        "median_time_number": status.chain.median_time_value()?,
                        "epoch": status.chain.epoch,
                        "node_active": status.node.active,
                        "node_id": status.node.node_id,
                        "ckb_version": status.node.version,
                        "connections": status.node.connections,
                        "connection_count": status.node.connection_count()?,
                        "tip": tip_json(&status.tip)?,
                    }))?
                );
            } else {
                println!("rpc_url={rpc_url}");
                println!("chain={}", status.chain.chain);
                println!(
                    "initial_block_download={}",
                    status.chain.is_initial_block_download
                );
                println!("node_active={}", status.node.active);
                println!("node_id={}", status.node.node_id);
                println!("connections={}", status.node.connection_count()?);
                print_tip(&status.tip)?;
            }
        }
        DevnetCommand::PublicationProfileFixture { json: _ } => {
            let profile = publication::fixture_publication_profile();
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        DevnetCommand::FeeMarket { profile, json } => {
            let profile = profile
                .as_ref()
                .map(|path| publication::read_publication_profile(path))
                .transpose()?
                .unwrap_or_else(publication::fixture_publication_profile);
            let observation = profile.observe_fee_market(&rpc)?;
            let selected_rate = publication::initial_fee_rate(&profile.fee, &observation)?;
            let profile_digest = publication::publication_profile_digest(&profile)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "profile": profile,
                        "observation": observation,
                        "selected_initial_fee_rate": selected_rate,
                        "profile_digest": profile_digest,
                    }))?
                );
            } else {
                println!("operator_id={}", profile.operator_id);
                println!("pool_min_fee_rate={}", observation.pool_min_fee_rate);
                println!("pool_min_rbf_rate={}", observation.pool_min_rbf_rate);
                println!("rbf_enabled={}", observation.rbf_enabled);
                println!("estimator_fee_rate={}", observation.estimator_fee_rate);
                println!("selected_initial_fee_rate={selected_rate}");
                println!("profile_digest={profile_digest}");
            }
        }
        DevnetCommand::DeriveOperatorPubkey { private_key, json } => {
            let pubkey = devnet::compressed_pubkey_hex_from_private(&private_key)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pubkey_sec1": pubkey,
                    }))?
                );
            } else {
                println!("pubkey_sec1={pubkey}");
            }
        }
        DevnetCommand::AssessChallengeWindow {
            contracts_dir,
            profile,
            dataset,
            expected_dataset_sha256,
            state_out_point,
            production,
            json,
        } => {
            let profile = publication::read_publication_profile(&profile)?;
            ensure!(
                !production || expected_dataset_sha256.is_some(),
                "--production requires --expected-dataset-sha256 to bind the exact input bytes"
            );
            if let Some(expected_digest) = expected_dataset_sha256.as_deref() {
                let expected_digest = canonical_hex32(expected_digest)
                    .context("--expected-dataset-sha256 must be canonical hex32")?;
                let actual_digest = publication::challenge_window_dataset_sha256(&dataset)?;
                ensure!(
                    actual_digest == expected_digest,
                    "challenge-window dataset SHA-256 {actual_digest} does not match expected digest {expected_digest}"
                );
            }
            let dataset = publication::read_challenge_window_dataset(&dataset)?;
            let genesis = rpc
                .block_by_number(0)?
                .context("CKB genesis block is unavailable")?;
            ensure!(
                dataset.genesis_hash == format!("{:#x}", genesis.header.hash),
                "challenge-window dataset genesis {} does not match connected node genesis {:#x}",
                dataset.genesis_hash,
                genesis.header.hash
            );
            let chain = rpc.chain_info()?;
            ensure!(
                dataset.network == chain.chain,
                "challenge-window dataset network {} does not match connected node network {}",
                dataset.network,
                chain.chain
            );
            let node = rpc.local_node_info()?;
            ensure!(
                dataset.ckb_version == node.version,
                "challenge-window dataset CKB version {} does not match connected node version {}",
                dataset.ckb_version,
                node.version
            );
            ensure!(
                !production || state_out_point.is_some(),
                "--production requires --state-out-point to bind the measured window to the deployed StateType"
            );
            let deployed_challenge_blocks = state_out_point
                .as_deref()
                .map(|out_point| {
                    devnet::canonical_state_challenge_blocks(&rpc, &contracts_dir, out_point)
                })
                .transpose()?;
            let now_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before Unix epoch")?
                .as_millis();
            let now_unix_ms =
                u64::try_from(now_unix_ms).context("Unix timestamp does not fit in u64")?;
            let assessment = publication::assess_challenge_window(
                &profile,
                &dataset,
                production,
                deployed_challenge_blocks,
                now_unix_ms,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&assessment)?);
            } else {
                println!("samples={}", assessment.sample_count);
                println!("overall_p999_ms={}", assessment.p999_end_to_end_ms);
                println!(
                    "effective_p999_ms={}",
                    assessment.effective_p999_end_to_end_ms
                );
                println!(
                    "required_challenge_blocks={}",
                    assessment.required_challenge_blocks
                );
                println!(
                    "configured_challenge_blocks={}",
                    assessment.configured_challenge_blocks
                );
                println!("fresh={}", assessment.fresh);
                println!("sufficient_samples={}", assessment.sufficient_samples);
                println!(
                    "production_provenance_verified={}",
                    assessment.production_provenance_verified
                );
                println!("passes={}", assessment.passes);
            }
            ensure!(
                assessment.passes,
                "challenge-window assessment did not pass"
            );
        }
        DevnetCommand::Truncate {
            target_tip_hash,
            json,
        } => {
            let target_tip_hash = target_tip_hash
                .strip_prefix("0x")
                .unwrap_or(&target_tip_hash)
                .parse::<H256>()
                .context("target tip hash must be a canonical H256")?;
            rpc.truncate(target_tip_hash)?;
            let tip = rpc.tip_header()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tip_json(&tip)?)?);
            } else {
                print_tip(&tip)?;
            }
        }
        DevnetCommand::Tip { json } => {
            let tip = rpc.tip_header()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tip_json(&tip)?)?);
            } else {
                print_tip(&tip)?;
            }
        }
        DevnetCommand::WaitTip {
            min_number,
            timeout_secs,
            poll_ms,
            json,
        } => {
            let tip = rpc.wait_for_tip(
                min_number,
                Duration::from_secs(timeout_secs),
                Duration::from_millis(poll_ms),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tip_json(&tip)?)?);
            } else {
                println!("target_tip={min_number}");
                print_tip(&tip)?;
            }
        }
        DevnetCommand::Mine { blocks, json } => {
            let mut hashes = Vec::new();
            for _ in 0..blocks {
                hashes.push(rpc.generate_block()?);
            }
            let tip = rpc.tip_header()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "generated": hashes,
                        "tip": tip_json(&tip)?,
                    }))?
                );
            } else {
                for hash in hashes {
                    println!("generated_block={hash}");
                }
                print_tip(&tip)?;
            }
        }
        DevnetCommand::DeployContracts {
            contracts_dir,
            private_key,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::deploy_contracts(
                &rpc,
                DeployContractsOptions {
                    contracts_dir,
                    private_key,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("input_capacity={}", report.input_capacity);
                println!("deployed_capacity={}", report.deployed_capacity);
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for tx in report.transactions {
                    println!(
                        "deploy_tx={} status={} scripts={} tx_size_bytes={} estimated_cycles={}",
                        tx.tx_hash,
                        tx.status,
                        tx.script_names.join(","),
                        tx.metrics.tx_size_bytes,
                        tx.metrics.estimated_cycles
                    );
                }
                for script in report.scripts {
                    println!(
                        "script={} out_point={}:{} data_hash={} hash_type={} data_len={} capacity={}",
                        script.name,
                        script.out_point.tx_hash,
                        script.out_point.index,
                        script.data_hash,
                        script.hash_type,
                        script.data_len,
                        script.capacity
                    );
                }
            }
        }
        DevnetCommand::OpenChannel {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            sponsor_min_state_number,
            sponsor_max_state_number,
            strict_sponsor_range,
            sponsor_max_fee_per_tx,
            sponsor_max_total_fee,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::open_channel(
                &rpc,
                OpenChannelOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    sponsor_min_state_number,
                    sponsor_max_state_number,
                    strict_sponsor_range,
                    sponsor_max_fee_per_tx,
                    sponsor_max_total_fee,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("finalise_since={}", report.finalise_since);
                println!("input_capacity={}", report.input_capacity);
                println!("state_capacity={}", report.state_capacity);
                println!("vault_capacity={}", report.vault_capacity);
                println!("sponsor_capacity={}", report.sponsor_capacity);
                print_sponsor_policy(&report.sponsor_policy);
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for participant in report.participants {
                    println!(
                        "participant={} lock_hash={} pubkey_sec1={} capacity={}",
                        participant.role,
                        participant.lock_hash,
                        participant.pubkey_sec1,
                        participant.capacity
                    );
                }
                for script in report.scripts {
                    println!(
                        "script={} out_point={}:{} data_hash={} hash_type={}",
                        script.name,
                        script.out_point.tx_hash,
                        script.out_point.index,
                        script.data_hash,
                        script.hash_type
                    );
                }
                for cell in report.cells {
                    println!(
                        "cell={} out_point={}:{} capacity={} lock_hash={} type_hash={} data_len={}",
                        cell.role,
                        cell.out_point.tx_hash,
                        cell.out_point.index,
                        cell.capacity,
                        cell.lock_hash,
                        cell.type_hash.as_deref().unwrap_or("none"),
                        cell.data_len
                    );
                }
            }
        }
        DevnetCommand::OpenFactory {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_capacity,
            factory_vault_capacity,
            factory_vault_xudt_amount,
            state_root,
            access_manifest_root,
            non_interference_digest,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::open_factory(
                &rpc,
                OpenFactoryOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_capacity,
                    factory_vault_capacity,
                    factory_vault_xudt_amount,
                    state_root,
                    access_manifest_root,
                    non_interference_digest,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("input_capacity={}", report.input_capacity);
                println!("factory_capacity={}", report.factory_capacity);
                println!("factory_vault_capacity={}", report.factory_vault_capacity);
                if let Some(amount) = report.factory_vault_xudt_amount {
                    println!("factory_vault_xudt_amount={amount}");
                }
                if let Some(type_hash) = &report.xudt_type_hash {
                    println!("xudt_type_hash={type_hash}");
                }
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for participant in report.participants {
                    println!(
                        "participant={} participant_id={} pubkey_sec1={}",
                        participant.role, participant.participant_id, participant.pubkey_sec1
                    );
                }
                for script in report.scripts {
                    println!(
                        "script={} out_point={}:{} data_hash={} hash_type={}",
                        script.name,
                        script.out_point.tx_hash,
                        script.out_point.index,
                        script.data_hash,
                        script.hash_type
                    );
                }
                for cell in report.cells {
                    println!(
                        "cell={} out_point={}:{} capacity={} lock_hash={} type_hash={} data_len={}",
                        cell.role,
                        cell.out_point.tx_hash,
                        cell.out_point.index,
                        cell.capacity,
                        cell.lock_hash,
                        cell.type_hash.as_deref().unwrap_or("none"),
                        cell.data_len
                    );
                }
            }
        }
        DevnetCommand::UpdateFactory {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_out_point,
            update_number,
            state_root,
            access_manifest_root,
            non_interference_digest,
            factory_state_package,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::update_factory(
                &rpc,
                UpdateFactoryOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_out_point,
                    update_number,
                    state_root,
                    access_manifest_root,
                    non_interference_digest,
                    factory_state_package,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!(
                    "factory_out_point={}:{}",
                    report.factory_out_point.tx_hash, report.factory_out_point.index
                );
                println!("factory_capacity={}", report.factory_capacity);
                println!("fee_input_capacity={}", report.fee_input_capacity);
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                println!("state_root={}", report.state_root);
                println!("access_manifest_root={}", report.access_manifest_root);
                println!("non_interference_digest={}", report.non_interference_digest);
                if let Some(path) = &report.factory_state_package {
                    println!("factory_state_package={path}");
                }
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::SaveFactoryStatePackage {
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_out_point,
            update_number,
            state_root,
            access_manifest_root,
            non_interference_digest,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_state_package(
                &rpc,
                SaveFactoryStatePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_out_point,
                    update_number,
                    state_root,
                    access_manifest_root,
                    non_interference_digest,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.package.factory_id);
                println!("update_number={}", report.package.update_number);
                println!("signing_digest={}", report.package.signing_digest);
                println!("state_root={}", report.package.state_root);
                println!(
                    "access_manifest_root={}",
                    report.package.access_manifest_root
                );
                println!(
                    "non_interference_digest={}",
                    report.package.non_interference_digest
                );
            }
        }
        DevnetCommand::SaveFactoryReducedRightsPackage {
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_out_point,
            update_number,
            touched_after_balance,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_reduced_rights_package(
                &rpc,
                SaveFactoryReducedRightsPackageOptions {
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_out_point,
                    update_number,
                    touched_after_balance,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.package.factory_id);
                println!("old_update_number={}", report.package.old_update_number);
                println!("new_update_number={}", report.package.new_update_number);
                println!("signing_digest={}", report.package.signing_digest);
                println!("old_state_root={}", report.package.old_state_root);
                println!("new_state_root={}", report.package.new_state_root);
                println!(
                    "old_access_manifest_root={}",
                    report.package.old_access_manifest_root
                );
                println!(
                    "new_access_manifest_root={}",
                    report.package.new_access_manifest_root
                );
                println!(
                    "non_interference_digest={}",
                    report.package.non_interference_digest
                );
            }
        }
        DevnetCommand::SaveFactorySplicePackage {
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_out_point,
            factory_vault_out_point,
            kind,
            asset,
            ckb_amount,
            xudt_amount,
            update_number,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_splice_package(
                &rpc,
                SaveFactorySplicePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_out_point,
                    factory_vault_out_point,
                    kind: match kind {
                        CkbSpliceKindArg::SpliceIn => DevnetSpliceKind::SpliceIn,
                        CkbSpliceKindArg::SpliceOut => DevnetSpliceKind::SpliceOut,
                    },
                    asset: match asset {
                        SpliceAssetArg::Ckb => DevnetSpliceAsset::Ckb,
                        SpliceAssetArg::Xudt => DevnetSpliceAsset::Xudt,
                    },
                    ckb_amount,
                    xudt_amount,
                    update_number,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.factory_id);
                println!("kind={}", report.kind);
                println!("asset={}", report.asset);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!("old_vault_amount={}", report.old_vault_amount);
                println!("new_vault_amount={}", report.new_vault_amount);
                println!("external_input={}", report.external_input);
                println!("withdrawal={}", report.withdrawal);
                println!("signing_digest={}", report.package.signing_digest);
                println!("contract_witness_len={}", report.contract_witness_len);
            }
        }
        DevnetCommand::SaveFactoryReducedSplicePackage {
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_out_point,
            factory_vault_out_point,
            kind,
            asset,
            ckb_amount,
            xudt_amount,
            update_number,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_reduced_splice_package(
                &rpc,
                SaveFactoryReducedSplicePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_out_point,
                    factory_vault_out_point,
                    kind: match kind {
                        CkbSpliceKindArg::SpliceIn => DevnetSpliceKind::SpliceIn,
                        CkbSpliceKindArg::SpliceOut => DevnetSpliceKind::SpliceOut,
                    },
                    asset: match asset {
                        SpliceAssetArg::Ckb => DevnetSpliceAsset::Ckb,
                        SpliceAssetArg::Xudt => DevnetSpliceAsset::Xudt,
                    },
                    ckb_amount,
                    xudt_amount,
                    update_number,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.factory_id);
                println!("kind={}", report.kind);
                println!("asset={}", report.asset);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!("old_vault_amount={}", report.old_vault_amount);
                println!("new_vault_amount={}", report.new_vault_amount);
                println!("external_input={}", report.external_input);
                println!("withdrawal={}", report.withdrawal);
                println!("proof_siblings={}", report.proof_siblings);
                println!("signing_digest={}", report.package.signing_digest);
                println!("contract_witness_len={}", report.contract_witness_len);
            }
        }
        DevnetCommand::ApplyFactorySplice {
            contracts_dir,
            private_key,
            factory_out_point,
            factory_vault_out_point,
            factory_splice_package,
            xudt_input_out_point,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::apply_factory_splice(
                &rpc,
                ApplyFactorySpliceOptions {
                    contracts_dir,
                    private_key,
                    factory_out_point,
                    factory_vault_out_point,
                    factory_splice_package,
                    xudt_input_out_point,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("kind={}", report.kind);
                println!("asset={}", report.asset);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!(
                    "factory_out_point={}:{}",
                    report.factory_out_point.tx_hash, report.factory_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.factory_vault_out_point.tx_hash, report.factory_vault_out_point.index
                );
                if let Some(out_point) = &report.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                println!("factory_splice_package={}", report.factory_splice_package);
                println!("contract_witness_len={}", report.contract_witness_len);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::ApplyFactoryReducedSplice {
            contracts_dir,
            private_key,
            factory_out_point,
            factory_vault_out_point,
            factory_reduced_splice_package,
            xudt_input_out_point,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::apply_factory_reduced_splice(
                &rpc,
                ApplyFactoryReducedSpliceOptions {
                    contracts_dir,
                    private_key,
                    factory_out_point,
                    factory_vault_out_point,
                    factory_reduced_splice_package,
                    xudt_input_out_point,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("kind={}", report.kind);
                println!("asset={}", report.asset);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!(
                    "factory_out_point={}:{}",
                    report.factory_out_point.tx_hash, report.factory_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.factory_vault_out_point.tx_hash, report.factory_vault_out_point.index
                );
                if let Some(out_point) = &report.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                println!(
                    "factory_reduced_splice_package={}",
                    report.factory_splice_package
                );
                println!("contract_witness_len={}", report.contract_witness_len);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::SaveFactoryMerkleUpdatePackage {
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            factory_out_point,
            update_number,
            touched_after_balance,
            store_dir,
            json,
        } => {
            let report = devnet::save_factory_merkle_update_package(
                &rpc,
                SaveFactoryMerkleUpdatePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    factory_out_point,
                    update_number,
                    touched_after_balance,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("factory_id={}", report.package.factory_id);
                println!("old_update_number={}", report.package.old_update_number);
                println!("new_update_number={}", report.package.new_update_number);
                println!("signing_digest={}", report.package.signing_digest);
                println!("old_state_root={}", report.package.old_state_root);
                println!("new_state_root={}", report.package.new_state_root);
                println!(
                    "non_interference_digest={}",
                    report.package.non_interference_digest
                );
                println!("proof_siblings={}", report.package.proof_siblings);
                println!("witness_len={}", report.package.witness_len);
            }
        }
        DevnetCommand::ListFactoryStatePackages {
            store_dir,
            factory_id,
            json,
        } => {
            let packages =
                packages::list_factory_state_cell_packages(&store_dir, factory_id.as_deref())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "store_dir": store_dir,
                        "packages": packages,
                    }))?
                );
            } else {
                println!("package_count={}", packages.len());
                for record in packages {
                    println!(
                        "package={} factory_id={} update_number={} signing_digest={}",
                        record.path.display(),
                        record.package.factory_id,
                        record.package.update_number,
                        record.package.signing_digest
                    );
                }
            }
        }
        DevnetCommand::LatestFactoryStatePackage {
            store_dir,
            factory_id,
            json,
        } => {
            let record = packages::latest_factory_state_cell_package(&store_dir, &factory_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!("path={}", record.path.display());
                println!("factory_id={}", record.package.factory_id);
                println!("update_number={}", record.package.update_number);
                println!("signing_digest={}", record.package.signing_digest);
            }
        }
        DevnetCommand::FactorySmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            fee,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_smoke(
                &rpc,
                FactorySmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    fee,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package={}", report.saved_package.path);
                println!(
                    "package_update_number={}",
                    report.saved_package.package.update_number
                );
                println!(
                    "selected_package={}",
                    report.selected_package.path.display()
                );
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("update_status={}", report.update.status);
                print_metrics(&report.open.metrics);
                print_metrics(&report.update.metrics);
            }
        }
        DevnetCommand::FactoryReducedRightsSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            touched_after_balance,
            fee,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_reduced_rights_smoke(
                &rpc,
                FactoryReducedRightsSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    touched_after_balance,
                    fee,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!(
                    "old_update_number={}",
                    report.package.package.old_update_number
                );
                println!(
                    "new_update_number={}",
                    report.package.package.new_update_number
                );
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("update_status={}", report.update.status);
                println!(
                    "factory_out_point={}:{}",
                    report.update.factory_out_point.tx_hash, report.update.factory_out_point.index
                );
                println!(
                    "non_interference_digest={}",
                    report.update.non_interference_digest
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.update.metrics);
                for hash in report.update.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactorySpliceInSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_splice_smoke(
                &rpc,
                FactorySpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceIn,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!("apply_tx_hash={}", report.apply.tx_hash);
                println!("apply_status={}", report.apply.status);
                println!(
                    "factory_out_point={}:{}",
                    report.apply.factory_out_point.tx_hash, report.apply.factory_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.apply.factory_vault_out_point.tx_hash,
                    report.apply.factory_vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!("contract_witness_len={}", report.apply.contract_witness_len);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("exit_status={}", report.exit.status);
                println!(
                    "child_state_out_point={}:{}",
                    report.exit.state_out_point.tx_hash, report.exit.state_out_point.index
                );
                println!(
                    "child_vault_out_point={}:{}",
                    report.exit.vault_out_point.tx_hash, report.exit.vault_out_point.index
                );
                println!(
                    "post_exit_factory_vault_out_point={}:{}",
                    report.exit.factory_vault_out_point.tx_hash,
                    report.exit.factory_vault_out_point.index
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.apply.metrics);
                print_metrics(&report.exit.metrics);
                for hash in report.apply.mined_blocks {
                    println!("mined_block={hash}");
                }
                for hash in report.exit.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactorySpliceOutSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_splice_smoke(
                &rpc,
                FactorySpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceOut,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!("apply_tx_hash={}", report.apply.tx_hash);
                println!("apply_status={}", report.apply.status);
                println!(
                    "factory_out_point={}:{}",
                    report.apply.factory_out_point.tx_hash, report.apply.factory_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.apply.factory_vault_out_point.tx_hash,
                    report.apply.factory_vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!("contract_witness_len={}", report.apply.contract_witness_len);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("exit_status={}", report.exit.status);
                println!(
                    "child_state_out_point={}:{}",
                    report.exit.state_out_point.tx_hash, report.exit.state_out_point.index
                );
                println!(
                    "child_vault_out_point={}:{}",
                    report.exit.vault_out_point.tx_hash, report.exit.vault_out_point.index
                );
                println!(
                    "post_exit_factory_vault_out_point={}:{}",
                    report.exit.factory_vault_out_point.tx_hash,
                    report.exit.factory_vault_out_point.index
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.apply.metrics);
                print_metrics(&report.exit.metrics);
                for hash in report.apply.mined_blocks {
                    println!("mined_block={hash}");
                }
                for hash in report.exit.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactoryReducedSpliceInSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_reduced_splice_smoke(
                &rpc,
                FactorySpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceIn,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!("proof_siblings={}", report.package.proof_siblings);
                println!("apply_tx_hash={}", report.apply.tx_hash);
                println!("apply_status={}", report.apply.status);
                println!(
                    "factory_out_point={}:{}",
                    report.apply.factory_out_point.tx_hash, report.apply.factory_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.apply.factory_vault_out_point.tx_hash,
                    report.apply.factory_vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!("contract_witness_len={}", report.apply.contract_witness_len);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("exit_status={}", report.exit.status);
                println!(
                    "child_state_out_point={}:{}",
                    report.exit.state_out_point.tx_hash, report.exit.state_out_point.index
                );
                println!(
                    "child_vault_out_point={}:{}",
                    report.exit.vault_out_point.tx_hash, report.exit.vault_out_point.index
                );
                println!(
                    "post_exit_factory_vault_out_point={}:{}",
                    report.exit.factory_vault_out_point.tx_hash,
                    report.exit.factory_vault_out_point.index
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.apply.metrics);
                print_metrics(&report.exit.metrics);
                for hash in report.apply.mined_blocks {
                    println!("mined_block={hash}");
                }
                for hash in report.exit.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactoryReducedSpliceOutSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_reduced_splice_smoke(
                &rpc,
                FactorySpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceOut,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!("proof_siblings={}", report.package.proof_siblings);
                println!("apply_tx_hash={}", report.apply.tx_hash);
                println!("apply_status={}", report.apply.status);
                println!(
                    "factory_out_point={}:{}",
                    report.apply.factory_out_point.tx_hash, report.apply.factory_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.apply.factory_vault_out_point.tx_hash,
                    report.apply.factory_vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!("contract_witness_len={}", report.apply.contract_witness_len);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("exit_status={}", report.exit.status);
                println!(
                    "child_state_out_point={}:{}",
                    report.exit.state_out_point.tx_hash, report.exit.state_out_point.index
                );
                println!(
                    "child_vault_out_point={}:{}",
                    report.exit.vault_out_point.tx_hash, report.exit.vault_out_point.index
                );
                println!(
                    "post_exit_factory_vault_out_point={}:{}",
                    report.exit.factory_vault_out_point.tx_hash,
                    report.exit.factory_vault_out_point.index
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.apply.metrics);
                print_metrics(&report.exit.metrics);
                for hash in report.apply.mined_blocks {
                    println!("mined_block={hash}");
                }
                for hash in report.exit.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactoryXudtSpliceInSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_xudt_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_xudt_splice_smoke(
                &rpc,
                FactoryXudtSpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceIn,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_xudt_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_factory_xudt_splice_smoke_report(&report);
            }
        }
        DevnetCommand::FactoryXudtSpliceOutSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_xudt_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_xudt_splice_smoke(
                &rpc,
                FactoryXudtSpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceOut,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_xudt_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_factory_xudt_splice_smoke_report(&report);
            }
        }
        DevnetCommand::FactoryReducedXudtSpliceInSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_xudt_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_reduced_xudt_splice_smoke(
                &rpc,
                FactoryXudtSpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceIn,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_xudt_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_factory_reduced_xudt_splice_smoke_report(&report);
            }
        }
        DevnetCommand::FactoryReducedXudtSpliceOutSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            splice_xudt_amount,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_reduced_xudt_splice_smoke(
                &rpc,
                FactoryXudtSpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceOut,
                    factory_capacity,
                    factory_vault_capacity,
                    splice_xudt_amount,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_factory_reduced_xudt_splice_smoke_report(&report);
            }
        }
        DevnetCommand::FactoryMerkleUpdateSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            touched_after_balance,
            fee,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_merkle_update_smoke(
                &rpc,
                FactoryMerkleUpdateSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    touched_after_balance,
                    fee,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("package_path={}", report.package.path);
                println!(
                    "old_update_number={}",
                    report.package.package.old_update_number
                );
                println!(
                    "new_update_number={}",
                    report.package.package.new_update_number
                );
                println!("proof_siblings={}", report.package.package.proof_siblings);
                println!("witness_len={}", report.package.package.witness_len);
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("update_status={}", report.update.status);
                println!(
                    "factory_out_point={}:{}",
                    report.update.factory_out_point.tx_hash, report.update.factory_out_point.index
                );
                println!(
                    "non_interference_digest={}",
                    report.update.non_interference_digest
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.update.metrics);
                for hash in report.update.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FactoryReducedExitSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::factory_reduced_exit_smoke(
                &rpc,
                FactoryReducedExitSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("publish_tx_hash={}", report.publish.tx_hash);
                println!("finalise_tx_hash={}", report.finalise.tx_hash);
                if let Some(reduced) = &report.exit.reduced_exit {
                    println!("release_quantity={}", reduced.release_quantity);
                    println!(
                        "non_interference_digest={}",
                        reduced.non_interference_digest
                    );
                }
                print_metrics(&report.open.metrics);
                print_metrics(&report.exit.metrics);
                print_metrics(&report.finalise.metrics);
            }
        }
        DevnetCommand::FactoryReducedXudtExitSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            factory_vault_xudt_surplus,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::factory_reduced_xudt_exit_smoke(
                &rpc,
                FactoryReducedXudtExitSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    factory_vault_xudt_surplus,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!(
                    "xudt_type_hash={}",
                    report.exit.xudt_type_hash.as_deref().unwrap_or_default()
                );
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("publish_tx_hash={}", report.publish.tx_hash);
                println!("finalise_tx_hash={}", report.finalise.tx_hash);
                println!(
                    "factory_vault_change_xudt_amount={}",
                    report
                        .exit
                        .factory_vault_change_xudt_amount
                        .unwrap_or_default()
                );
                println!(
                    "alice_xudt_amount={}",
                    report.exit.alice_xudt_amount.unwrap_or_default()
                );
                println!(
                    "bob_xudt_amount={}",
                    report.exit.bob_xudt_amount.unwrap_or_default()
                );
                if let Some(reduced) = &report.exit.reduced_exit {
                    println!("release_quantity={}", reduced.release_quantity);
                    println!("witness_len={}", reduced.witness_len);
                    println!(
                        "non_interference_digest={}",
                        reduced.non_interference_digest
                    );
                }
                print_metrics(&report.open.metrics);
                print_metrics(&report.exit.metrics);
                print_metrics(&report.finalise.metrics);
            }
        }
        DevnetCommand::FactoryReducedXudtNegativeExitSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::factory_reduced_xudt_negative_exit_smoke(
                &rpc,
                FactoryReducedXudtNegativeExitSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!(
                    "expected_child_xudt_amount={}",
                    report.expected_child_xudt_amount
                );
                println!(
                    "rejected_child_xudt_amount={}",
                    report.rejected_child_xudt_amount
                );
                println!(
                    "script_failure={}",
                    report
                        .script_failure
                        .morph_error
                        .as_deref()
                        .unwrap_or("unknown")
                );
                println!("rejection={}", report.rejection);
                print_metrics(&report.open.metrics);
            }
        }
        DevnetCommand::FactoryXudtSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_xudt_smoke(
                &rpc,
                FactoryXudtSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!(
                    "xudt_type_hash={}",
                    report.exit.xudt_type_hash.unwrap_or_default()
                );
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("update_tx_hash={}", report.update.tx_hash);
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("publish_tx_hash={}", report.publish.tx_hash);
                println!("finalise_tx_hash={}", report.finalise.tx_hash);
                println!(
                    "child_xudt_amount={}",
                    report.exit.child_xudt_amount.unwrap_or(0)
                );
                print_metrics(&report.open.metrics);
                print_metrics(&report.exit.metrics);
                print_metrics(&report.finalise.metrics);
            }
        }
        DevnetCommand::FactoryXudtNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            factory_capacity,
            factory_vault_capacity,
            child_vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::factory_xudt_negative_smoke(
                &rpc,
                FactoryXudtNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    factory_capacity,
                    factory_vault_capacity,
                    child_vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("factory_id={}", report.open.factory_id);
                println!("open_tx_hash={}", report.open.tx_hash);
                println!("update_tx_hash={}", report.update.tx_hash);
                println!(
                    "rejected_child_xudt_amount={}",
                    report.rejected_child_xudt_amount
                );
                println!(
                    "script_failure={}",
                    report
                        .script_failure
                        .morph_error
                        .as_deref()
                        .unwrap_or("unknown")
                );
                println!("exit_tx_hash={}", report.exit.tx_hash);
                println!("publish_tx_hash={}", report.publish.tx_hash);
                println!("finalise_tx_hash={}", report.finalise.tx_hash);
                print_metrics(&report.open.metrics);
                print_metrics(&report.exit.metrics);
                print_metrics(&report.finalise.metrics);
            }
        }
        DevnetCommand::FactoryExitChannel {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            additional_participant_private_keys,
            additional_participant_public_keys,
            bob_public_key,
            authorisation,
            factory_out_point,
            factory_vault_out_point,
            update_number,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::factory_exit_channel(
                &rpc,
                FactoryExitChannelOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    additional_participant_private_keys,
                    additional_participant_public_keys,
                    bob_public_key,
                    factory_out_point,
                    factory_vault_out_point,
                    update_number,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    tamper: FactoryExitChannelTamper::None,
                    authorisation: match authorisation {
                        FactoryExitAuthorisationArg::FullParticipants => {
                            FactoryExitAuthorisation::FullParticipants
                        }
                        FactoryExitAuthorisationArg::ReducedReserveClaim => {
                            FactoryExitAuthorisation::ReducedReserveClaim
                        }
                    },
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("factory_id={}", report.factory_id);
                println!("old_update_number={}", report.old_update_number);
                println!("new_update_number={}", report.new_update_number);
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("finalise_since={}", report.finalise_since);
                println!(
                    "factory_out_point={}:{}",
                    report.factory_out_point.tx_hash, report.factory_out_point.index
                );
                println!(
                    "state_out_point={}:{}",
                    report.state_out_point.tx_hash, report.state_out_point.index
                );
                println!(
                    "vault_out_point={}:{}",
                    report.vault_out_point.tx_hash, report.vault_out_point.index
                );
                println!(
                    "factory_vault_out_point={}:{}",
                    report.factory_vault_out_point.tx_hash, report.factory_vault_out_point.index
                );
                println!(
                    "sponsor_out_point={}:{}",
                    report.sponsor_out_point.tx_hash, report.sponsor_out_point.index
                );
                println!("state_capacity={}", report.state_capacity);
                println!("vault_capacity={}", report.vault_capacity);
                if let Some(amount) = report.child_xudt_amount {
                    println!("child_xudt_amount={amount}");
                }
                if let Some(type_hash) = &report.xudt_type_hash {
                    println!("xudt_type_hash={type_hash}");
                }
                println!(
                    "factory_vault_input_capacity={}",
                    report.factory_vault_input_capacity
                );
                println!(
                    "factory_vault_change_capacity={}",
                    report.factory_vault_change_capacity
                );
                if let Some(amount) = report.factory_vault_input_xudt_amount {
                    println!("factory_vault_input_xudt_amount={amount}");
                }
                if let Some(amount) = report.factory_vault_change_xudt_amount {
                    println!("factory_vault_change_xudt_amount={amount}");
                }
                println!("sponsor_capacity={}", report.sponsor_capacity);
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for participant in report.participants {
                    println!(
                        "participant={} lock_hash={} pubkey_sec1={} capacity={}",
                        participant.role,
                        participant.lock_hash,
                        participant.pubkey_sec1,
                        participant.capacity
                    );
                }
            }
        }
        DevnetCommand::PublishState {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            state_out_point,
            sponsor_out_point,
            state_number,
            state_package,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::publish_state(
                &rpc,
                PublishStateOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    sponsor_out_point,
                    state_number,
                    state_package,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("old_state_number={}", report.old_state_number);
                println!("new_state_number={}", report.new_state_number);
                println!(
                    "state_out_point={}:{}",
                    report.state_out_point.tx_hash, report.state_out_point.index
                );
                println!("sponsor_change_capacity={}", report.sponsor_change_capacity);
                println!("fee={}", report.fee);
                if let Some(path) = &report.state_package {
                    println!("state_package={path}");
                }
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::SaveSplicePackage {
            alice_private_key,
            bob_private_key,
            state_out_point,
            vault_out_point,
            kind,
            asset,
            ckb_amount,
            xudt_amount,
            signed_fee,
            old_funding_epoch,
            new_funding_epoch,
            splice_number,
            store_dir,
            json,
        } => {
            let report = devnet::save_splice_package(
                &rpc,
                SaveSplicePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    vault_out_point,
                    kind: match kind {
                        CkbSpliceKindArg::SpliceIn => DevnetSpliceKind::SpliceIn,
                        CkbSpliceKindArg::SpliceOut => DevnetSpliceKind::SpliceOut,
                    },
                    asset: match asset {
                        SpliceAssetArg::Ckb => DevnetSpliceAsset::Ckb,
                        SpliceAssetArg::Xudt => DevnetSpliceAsset::Xudt,
                    },
                    ckb_amount,
                    xudt_amount,
                    signed_fee,
                    old_funding_epoch,
                    new_funding_epoch,
                    splice_number,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("kind={}", report.kind);
                println!("channel_id={}", report.package.channel_id);
                println!("old_funding_anchor={}", report.package.old_funding_anchor);
                println!("new_funding_anchor={}", report.package.new_funding_anchor);
                println!("old_funding_epoch={}", report.old_funding_epoch);
                println!("new_funding_epoch={}", report.new_funding_epoch);
                println!("splice_number={}", report.splice_number);
                println!("asset={}", report.asset);
                println!("ckb_amount={}", report.ckb_amount);
                if let Some(amount) = report.xudt_amount {
                    println!("xudt_amount={amount}");
                }
                if let Some(type_hash) = &report.xudt_type_hash {
                    println!("xudt_type_hash={type_hash}");
                }
                println!("old_vault_capacity={}", report.old_vault_capacity);
                println!("new_vault_capacity={}", report.new_vault_capacity);
                if let Some(amount) = report.old_xudt_amount {
                    println!("old_xudt_amount={amount}");
                }
                if let Some(amount) = report.new_xudt_amount {
                    println!("new_xudt_amount={amount}");
                }
                println!("signing_digest={}", report.package.signing_digest);
                println!("contract_witness_len={}", report.contract_witness_len);
            }
        }
        DevnetCommand::ApplySplice {
            contracts_dir,
            private_key,
            state_out_point,
            vault_out_point,
            splice_package,
            xudt_input_out_point,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::apply_splice(
                &rpc,
                ApplySpliceOptions {
                    contracts_dir,
                    private_key,
                    state_out_point,
                    vault_out_point,
                    splice_package,
                    xudt_input_out_point,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("old_funding_anchor={}", report.old_funding_anchor);
                println!("new_funding_anchor={}", report.new_funding_anchor);
                println!("old_funding_epoch={}", report.old_funding_epoch);
                println!("new_funding_epoch={}", report.new_funding_epoch);
                println!("splice_number={}", report.splice_number);
                println!("old_state_number={}", report.old_state_number);
                println!("new_state_number={}", report.new_state_number);
                println!(
                    "state_out_point={}:{}",
                    report.state_out_point.tx_hash, report.state_out_point.index
                );
                println!(
                    "vault_out_point={}:{}",
                    report.vault_out_point.tx_hash, report.vault_out_point.index
                );
                if let Some(out_point) = &report.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!(
                    "withdrawal_payout_policy={}",
                    report.withdrawal_payout_policy
                );
                if let Some(pubkey) = &report.withdrawal_participant_pubkey_sec1 {
                    println!("withdrawal_participant_pubkey_sec1={pubkey}");
                }
                if let Some(lock_hash) = &report.withdrawal_lock_hash {
                    println!("withdrawal_lock_hash={lock_hash}");
                }
                println!("fee_change_capacity={}", report.fee_change_capacity);
                println!("fee={}", report.fee);
                println!("splice_package={}", report.splice_package);
                println!("contract_witness_len={}", report.contract_witness_len);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::SaveStatePackage {
            alice_private_key,
            bob_private_key,
            state_out_point,
            state_number,
            store_dir,
            json,
        } => {
            let report = devnet::save_state_package(
                &rpc,
                SaveStatePackageOptions {
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    state_number,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("path={}", report.path);
                println!("channel_id={}", report.package.channel_id);
                println!("funding_anchor={}", report.package.funding_anchor);
                println!("state_number={}", report.package.state_number);
                println!("signing_digest={}", report.package.signing_digest);
            }
        }
        DevnetCommand::ListStatePackages {
            store_dir,
            channel_id,
            json,
        } => {
            let packages = packages::list_packages(&store_dir, channel_id.as_deref())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "store_dir": store_dir,
                        "packages": packages,
                    }))?
                );
            } else {
                println!("package_count={}", packages.len());
                for record in packages {
                    println!(
                        "package={} channel_id={} state_number={} signing_digest={}",
                        record.path.display(),
                        record.package.channel_id,
                        record.package.state_number,
                        record.package.signing_digest
                    );
                }
            }
        }
        DevnetCommand::LatestStatePackage {
            store_dir,
            channel_id,
            json,
        } => {
            let record = packages::latest_package(&store_dir, &channel_id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!("path={}", record.path.display());
                println!("channel_id={}", record.package.channel_id);
                println!("funding_anchor={}", record.package.funding_anchor);
                println!("state_number={}", record.package.state_number);
                println!("signing_digest={}", record.package.signing_digest);
            }
        }
        DevnetCommand::PublishLatestPackage {
            contracts_dir,
            private_key,
            state_out_point,
            sponsor_out_point,
            store_dir,
            channel_id,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::publish_latest_state_package(
                &rpc,
                PublishLatestStatePackageOptions {
                    contracts_dir,
                    private_key,
                    state_out_point,
                    sponsor_out_point,
                    store_dir,
                    channel_id,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("package={}", report.selected_package.path.display());
                println!(
                    "package_state_number={}",
                    report.selected_package.package.state_number
                );
                println!("tx_hash={}", report.publication.tx_hash);
                println!("status={}", report.publication.status);
                println!(
                    "state_out_point={}:{}",
                    report.publication.state_out_point.tx_hash,
                    report.publication.state_out_point.index
                );
                println!("fee={}", report.publication.fee);
                print_metrics(&report.publication.metrics);
            }
        }
        DevnetCommand::WatchLatestPackage {
            contracts_dir,
            private_key,
            private_key_file,
            sponsor_out_point,
            store_dir,
            channel_id,
            from_block,
            cursor_file,
            watch_policy,
            publication_profile,
            publication_attempt_log,
            alert_file,
            alert_webhook_url,
            ignore_cursor,
            detection_depth,
            timeout_secs,
            poll_ms,
            fee,
            mine_blocks,
            auto_fund_sponsor,
            auto_sponsor_capacity,
            json,
        } => {
            let report = devnet::watch_latest_state_package(
                &rpc,
                WatchLatestStatePackageOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(
                        rpc_url,
                        private_key,
                        private_key_file,
                    )?,
                    sponsor_out_point,
                    store_dir,
                    channel_id,
                    from_block,
                    cursor_file,
                    watch_policy,
                    publication_profile,
                    publication_attempt_log,
                    alert_file,
                    alert_webhook_url,
                    ignore_cursor,
                    detection_depth,
                    timeout_secs,
                    poll_ms,
                    fee,
                    mine_blocks,
                    auto_fund_sponsor,
                    auto_sponsor_capacity,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("channel_id={}", report.channel_id);
                println!("from_block={}", report.from_block);
                println!("effective_from_block={}", report.effective_from_block);
                println!("scanned_to_block={}", report.scanned_to_block);
                println!("next_from_block={}", report.next_from_block);
                println!("detection_depth={}", report.detection_depth);
                if let Some(path) = &report.cursor_file {
                    println!("cursor_file={}", path.display());
                }
                if let Some(path) = &report.alert_file {
                    println!("alert_file={}", path.display());
                }
                if let Some(url) = &report.alert_webhook_url {
                    println!("alert_webhook_url={url}");
                }
                if let Some(cursor) = &report.loaded_cursor {
                    println!("loaded_cursor_next_block={}", cursor.next_block);
                }
                println!("package={}", report.selected_package.path.display());
                println!(
                    "package_state_number={}",
                    report.selected_package.package.state_number
                );
                println!(
                    "package_funding_anchor={}",
                    report.selected_package.package.funding_anchor
                );
                if let Some(sponsor_top_up) = &report.sponsor_top_up {
                    println!("sponsor_top_up_tx={}", sponsor_top_up.tx_hash);
                    println!(
                        "sponsor_out_point={}:{}",
                        sponsor_top_up.sponsor_out_point.tx_hash,
                        sponsor_top_up.sponsor_out_point.index
                    );
                }
                if let Some(observed) = &report.observed {
                    println!("observed_out_point={}", observed.out_point);
                    println!("observed_state_number={}", observed.state_number);
                    println!("observed_funding_anchor={}", observed.funding_anchor);
                    println!("observed_confirmations={}", observed.confirmations);
                }
                if let Some(publication) = &report.publication {
                    println!("submitted=true");
                    println!("published={}", publication.canonical_confirmed);
                    println!("tx_hash={}", publication.tx_hash);
                    println!("status={}", publication.status);
                    println!(
                        "canonical_confirmations={}",
                        publication.canonical_confirmations
                    );
                    print_metrics(&publication.metrics);
                } else {
                    println!("submitted=false");
                    println!("published=false");
                }
            }
        }
        DevnetCommand::WatchConfigOnce {
            contracts_dir,
            private_key,
            private_key_file,
            config,
            json,
        } => {
            let config_data = watch_config::read_watchtower_config(&config)?;
            let report = watch_config::run_watchtower_config_once(
                &rpc,
                &config,
                &config_data,
                watch_config::WatchtowerRuntimeOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(
                        rpc_url,
                        private_key,
                        private_key_file,
                    )?,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("config={}", report.config_path);
                println!("channels={}", report.channel_count);
                println!("published={}", report.published_count);
                println!("idle={}", report.idle_count);
                for channel in &report.channels {
                    println!(
                        "channel={} scanned_to={} next_from={} published={}",
                        channel.channel_id,
                        channel.report.scanned_to_block,
                        channel.report.next_from_block,
                        channel.report.publication.is_some()
                    );
                }
            }
        }
        DevnetCommand::WatchConfigLoop {
            contracts_dir,
            private_key,
            private_key_file,
            config,
            passes,
            sleep_ms,
            stop_after_publication,
            json,
        } => {
            let config_data = watch_config::read_watchtower_config(&config)?;
            let report = watch_config::run_watchtower_config_loop(
                &rpc,
                &config,
                &config_data,
                watch_config::WatchtowerRuntimeOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(
                        rpc_url,
                        private_key,
                        private_key_file,
                    )?,
                },
                watch_config::WatchtowerConfigLoopOptions {
                    passes,
                    sleep_ms,
                    stop_after_publication,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("config={}", report.config_path);
                println!("requested_passes={}", report.requested_passes);
                println!("completed_passes={}", report.completed_passes);
                println!("published={}", report.published_count);
                println!("idle={}", report.idle_count);
                println!(
                    "stopped_after_publication={}",
                    report.stopped_after_publication
                );
                for pass in &report.passes {
                    println!(
                        "pass={} channels={} published={} idle={}",
                        pass.pass_number,
                        pass.report.channel_count,
                        pass.report.published_count,
                        pass.report.idle_count
                    );
                }
            }
        }
        DevnetCommand::WatchConfigService {
            contracts_dir,
            private_key,
            private_key_file,
            config,
            max_passes,
            sleep_ms,
            error_backoff_ms,
            max_consecutive_errors,
            stop_after_publication,
            stop_file,
            health_file,
            json,
        } => {
            let config_data = watch_config::read_watchtower_config(&config)?;
            let report = watch_config::run_watchtower_config_service(
                &rpc,
                &config,
                &config_data,
                watch_config::WatchtowerRuntimeOptions {
                    contracts_dir,
                    private_key: resolve_watchtower_private_key(
                        rpc_url,
                        private_key,
                        private_key_file,
                    )?,
                },
                watch_config::WatchtowerConfigServiceOptions {
                    max_passes,
                    sleep_ms,
                    error_backoff_ms,
                    max_consecutive_errors,
                    stop_after_publication,
                    stop_file,
                    health_file,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("config={}", report.config_path);
                println!("completed_passes={}", report.completed_passes);
                println!("published={}", report.published_count);
                println!("idle={}", report.idle_count);
                println!("errors={}", report.error_count);
                println!("consecutive_errors={}", report.consecutive_errors);
                println!("stopped_reason={}", report.stopped_reason);
                if let Some(error) = &report.last_error {
                    println!("last_error={error}");
                }
                if let Some(path) = &report.stop_file {
                    println!("stop_file={}", path.display());
                }
                if let Some(path) = &report.health_file {
                    println!("health_file={}", path.display());
                }
            }
        }
        DevnetCommand::FundSponsor {
            contracts_dir,
            private_key,
            sponsor_change_pubkey,
            state_out_point,
            sponsor_capacity,
            sponsor_min_state_number,
            sponsor_max_state_number,
            strict_sponsor_range,
            sponsor_max_fee_per_tx,
            sponsor_max_total_fee,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::fund_sponsor(
                &rpc,
                FundSponsorOptions {
                    contracts_dir,
                    private_key,
                    sponsor_change_pubkey,
                    state_out_point,
                    sponsor_capacity,
                    sponsor_min_state_number,
                    sponsor_max_state_number,
                    strict_sponsor_range,
                    sponsor_max_fee_per_tx,
                    sponsor_max_total_fee,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("state_number={}", report.state_number);
                println!(
                    "sponsor_out_point={}:{}",
                    report.sponsor_out_point.tx_hash, report.sponsor_out_point.index
                );
                println!("sponsor_capacity={}", report.sponsor_capacity);
                print_sponsor_policy(&report.sponsor_policy);
                println!("change_capacity={}", report.change_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
            }
        }
        DevnetCommand::FinaliseChannel {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            state_out_point,
            vault_out_point,
            alice_capacity,
            bob_capacity,
            finalise_since,
            fee,
            mine_blocks,
            json,
        } => {
            let report = devnet::finalise_channel(
                &rpc,
                FinaliseChannelOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    state_out_point,
                    vault_out_point,
                    alice_capacity,
                    bob_capacity,
                    finalise_since,
                    fee,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("tx_hash={}", report.tx_hash);
                println!("status={}", report.status);
                if let Some(block_number) = report.block_number {
                    println!("block_number={block_number}");
                }
                if let Some(block_hash) = &report.block_hash {
                    println!("block_hash={block_hash}");
                }
                println!("channel_id={}", report.channel_id);
                println!("funding_anchor={}", report.funding_anchor);
                println!("state_number={}", report.state_number);
                println!("alice_capacity={}", report.alice_capacity);
                println!("bob_capacity={}", report.bob_capacity);
                println!("state_refund_capacity={}", report.state_refund_capacity);
                println!("fee={}", report.fee);
                print_metrics(&report.metrics);
                for hash in report.mined_blocks {
                    println!("mined_block={hash}");
                }
                for output in report.outputs {
                    println!(
                        "output={} out_point={}:{} capacity={} lock_hash={}",
                        output.role,
                        output.out_point.tx_hash,
                        output.out_point.index,
                        output.capacity,
                        output.lock_hash
                    );
                }
            }
        }
        DevnetCommand::SpliceInSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            splice_amount,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::splice_smoke(
                &rpc,
                SpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceIn,
                    vault_capacity,
                    splice_amount,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("open_tx={}", report.open.tx_hash);
                println!("splice_package={}", report.package.path);
                println!("apply_tx={}", report.apply.tx_hash);
                println!(
                    "post_splice_state_out_point={}:{}",
                    report.apply.state_out_point.tx_hash, report.apply.state_out_point.index
                );
                println!(
                    "post_splice_vault_out_point={}:{}",
                    report.apply.vault_out_point.tx_hash, report.apply.vault_out_point.index
                );
                println!(
                    "post_splice_sponsor_tx={}",
                    report.post_splice_sponsor.tx_hash
                );
                println!("publish_tx={}", report.publish.tx_hash);
                println!("channel_id={}", report.apply.channel_id);
                println!("new_funding_anchor={}", report.apply.new_funding_anchor);
                println!("new_vault_capacity={}", report.package.new_vault_capacity);
                println!("publish_status={}", report.publish.status);
                if let Some(finalise) = &report.finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                if let Some(finalise) = &report.xudt_finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                println!(
                    "cycles=open:{} apply:{} sponsor:{} publish:{}",
                    report.open.metrics.estimated_cycles,
                    report.apply.metrics.estimated_cycles,
                    report.post_splice_sponsor.metrics.estimated_cycles,
                    report.publish.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::SpliceOutSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            splice_amount,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::splice_smoke(
                &rpc,
                SpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    kind: DevnetSpliceKind::SpliceOut,
                    vault_capacity,
                    splice_amount,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("open_tx={}", report.open.tx_hash);
                println!("splice_package={}", report.package.path);
                println!("apply_tx={}", report.apply.tx_hash);
                println!(
                    "post_splice_state_out_point={}:{}",
                    report.apply.state_out_point.tx_hash, report.apply.state_out_point.index
                );
                println!(
                    "post_splice_vault_out_point={}:{}",
                    report.apply.vault_out_point.tx_hash, report.apply.vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!(
                    "post_splice_sponsor_tx={}",
                    report.post_splice_sponsor.tx_hash
                );
                println!("publish_tx={}", report.publish.tx_hash);
                println!("channel_id={}", report.apply.channel_id);
                println!("new_funding_anchor={}", report.apply.new_funding_anchor);
                println!("new_vault_capacity={}", report.package.new_vault_capacity);
                println!("publish_status={}", report.publish.status);
                if let Some(finalise) = &report.finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                if let Some(finalise) = &report.xudt_finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                println!(
                    "cycles=open:{} apply:{} sponsor:{} publish:{}",
                    report.open.metrics.estimated_cycles,
                    report.apply.metrics.estimated_cycles,
                    report.post_splice_sponsor.metrics.estimated_cycles,
                    report.publish.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::XudtSpliceInSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            splice_xudt_amount,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::xudt_splice_in_smoke(
                &rpc,
                XudtSpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    splice_xudt_amount,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("open_tx={}", report.open.tx_hash);
                if let Some(external_xudt) = &report.external_xudt {
                    println!("external_xudt_tx={}", external_xudt.tx_hash);
                    println!(
                        "external_xudt_out_point={}:{}",
                        external_xudt.cell_out_point.tx_hash, external_xudt.cell_out_point.index
                    );
                }
                println!("splice_package={}", report.package.path);
                println!(
                    "xudt_type_hash={}",
                    report.package.xudt_type_hash.as_deref().unwrap_or_default()
                );
                println!(
                    "xudt_amount={}",
                    report.package.xudt_amount.unwrap_or_default()
                );
                println!(
                    "new_xudt_amount={}",
                    report.package.new_xudt_amount.unwrap_or_default()
                );
                println!("apply_tx={}", report.apply.tx_hash);
                println!(
                    "post_splice_state_out_point={}:{}",
                    report.apply.state_out_point.tx_hash, report.apply.state_out_point.index
                );
                println!(
                    "post_splice_vault_out_point={}:{}",
                    report.apply.vault_out_point.tx_hash, report.apply.vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!(
                    "post_splice_sponsor_tx={}",
                    report.post_splice_sponsor.tx_hash
                );
                println!("publish_tx={}", report.publish.tx_hash);
                println!("channel_id={}", report.apply.channel_id);
                println!("new_funding_anchor={}", report.apply.new_funding_anchor);
                println!("new_vault_capacity={}", report.package.new_vault_capacity);
                println!("publish_status={}", report.publish.status);
                if let Some(finalise) = &report.finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                if let Some(finalise) = &report.xudt_finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                println!(
                    "cycles=open:{} apply:{} sponsor:{} publish:{}",
                    report.open.metrics.estimated_cycles,
                    report.apply.metrics.estimated_cycles,
                    report.post_splice_sponsor.metrics.estimated_cycles,
                    report.publish.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::XudtSpliceOutSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            splice_xudt_amount,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::xudt_splice_out_smoke(
                &rpc,
                XudtSpliceSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    splice_xudt_amount,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("kind={}", report.kind);
                println!("open_tx={}", report.open.tx_hash);
                println!("splice_package={}", report.package.path);
                println!(
                    "xudt_type_hash={}",
                    report.package.xudt_type_hash.as_deref().unwrap_or_default()
                );
                println!(
                    "xudt_amount={}",
                    report.package.xudt_amount.unwrap_or_default()
                );
                println!(
                    "new_xudt_amount={}",
                    report.package.new_xudt_amount.unwrap_or_default()
                );
                println!("apply_tx={}", report.apply.tx_hash);
                println!(
                    "post_splice_state_out_point={}:{}",
                    report.apply.state_out_point.tx_hash, report.apply.state_out_point.index
                );
                println!(
                    "post_splice_vault_out_point={}:{}",
                    report.apply.vault_out_point.tx_hash, report.apply.vault_out_point.index
                );
                if let Some(out_point) = &report.apply.withdrawal_out_point {
                    println!(
                        "withdrawal_out_point={}:{}",
                        out_point.tx_hash, out_point.index
                    );
                }
                println!(
                    "post_splice_sponsor_tx={}",
                    report.post_splice_sponsor.tx_hash
                );
                println!("publish_tx={}", report.publish.tx_hash);
                println!("channel_id={}", report.apply.channel_id);
                println!("new_funding_anchor={}", report.apply.new_funding_anchor);
                println!("new_vault_capacity={}", report.package.new_vault_capacity);
                println!("publish_status={}", report.publish.status);
                if let Some(finalise) = &report.finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                if let Some(finalise) = &report.xudt_finalise {
                    println!("finalise_tx={}", finalise.tx_hash);
                    println!("finalise_status={}", finalise.status);
                }
                println!(
                    "cycles=open:{} apply:{} sponsor:{} publish:{}",
                    report.open.metrics.estimated_cycles,
                    report.apply.metrics.estimated_cycles,
                    report.post_splice_sponsor.metrics.estimated_cycles,
                    report.publish.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::SpliceNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            splice_amount,
            splice_xudt_amount,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            json,
        } => {
            let report = devnet::splice_negative_smoke(
                &rpc,
                SpliceNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    splice_amount,
                    splice_xudt_amount,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("ckb_open_tx={}", report.ckb_open.tx_hash);
                println!("xudt_open_tx={}", report.xudt_open.tx_hash);
                println!("ckb_splice_package={}", report.ckb_package.path);
                println!("xudt_splice_package={}", report.xudt_package.path);
                println!(
                    "signed_fee_splice_package={}",
                    report.signed_fee_package.path
                );
                for rejection in &report.rejections {
                    println!(
                        "rejected_case={} stage={} package={}",
                        rejection.case, rejection.stage, rejection.rejected_package
                    );
                    println!("rejection={}", rejection.rejection);
                }
            }
        }
        DevnetCommand::SupersedeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::supersede_smoke(
                &rpc,
                SupersedeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("stale_publish_tx={}", report.stale_publish.tx_hash);
                println!("sponsor_top_up_tx={}", report.sponsor_top_up.tx_hash);
                println!("supersede_publish_tx={}", report.supersede_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!(
                    "state_numbers={}->{}",
                    report.stale_publish.new_state_number,
                    report.supersede_publish.new_state_number
                );
                println!("final_state_number={}", report.finalise.state_number);
                println!("finalise_status={}", report.finalise.status);
                println!(
                    "cycles=open:{} stale_publish:{} sponsor_top_up:{} supersede_publish:{} finalise:{}",
                    report.open.metrics.estimated_cycles,
                    report.stale_publish.metrics.estimated_cycles,
                    report.sponsor_top_up.metrics.estimated_cycles,
                    report.supersede_publish.metrics.estimated_cycles,
                    report.finalise.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::FinaliseSinceNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::finalise_since_negative_smoke(
                &rpc,
                FinaliseSinceNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("publish_tx={}", report.publish.tx_hash);
                println!("rejected_input_since={}", report.rejected_input_since);
                println!("required_finalise_since={}", report.required_finalise_since);
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                for hash in report.maturity_blocks {
                    println!("maturity_block={hash}");
                }
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::XudtSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::xudt_smoke(
                &rpc,
                XudtSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("publish_tx={}", report.publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("xudt_type_hash={}", report.finalise.xudt_type_hash);
                println!("alice_capacity={}", report.finalise.alice_capacity);
                println!("bob_capacity={}", report.finalise.bob_capacity);
                println!("alice_xudt_amount={}", report.finalise.alice_xudt_amount);
                println!("bob_xudt_amount={}", report.finalise.bob_xudt_amount);
                println!("finalise_status={}", report.finalise.status);
                println!(
                    "cycles=open:{} publish:{} finalise:{}",
                    report.open.metrics.estimated_cycles,
                    report.publish.metrics.estimated_cycles,
                    report.finalise.metrics.estimated_cycles
                );
            }
        }
        DevnetCommand::XudtNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            alice_xudt_amount,
            bob_xudt_amount,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::xudt_negative_smoke(
                &rpc,
                XudtNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    alice_xudt_amount,
                    bob_xudt_amount,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("publish_tx={}", report.publish.tx_hash);
                println!(
                    "rejected_xudt_amounts={}:{}",
                    report.rejected_alice_xudt_amount, report.rejected_bob_xudt_amount
                );
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("xudt_type_hash={}", report.finalise.xudt_type_hash);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::SponsorPolicyNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::sponsor_policy_negative_smoke(
                &rpc,
                SponsorPolicyNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("rejected_state_number={}", report.rejected_state_number);
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                println!("allowed_publish_tx={}", report.allowed_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::SponsorBudgetNegativeSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::sponsor_budget_negative_smoke(
                &rpc,
                SponsorBudgetNegativeSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("rejected_fee={}", report.rejected_fee);
                println!("sponsor_max_fee_per_tx={}", report.sponsor_max_fee_per_tx);
                println!("rejection={}", report.rejection);
                if let Some(source) = &report.script_failure.source {
                    println!("script_failure_source={source}");
                }
                if let Some(code) = report.script_failure.error_code {
                    println!("script_failure_error_code={code}");
                }
                if let Some(name) = &report.script_failure.morph_error {
                    println!("script_failure_morph_error={name}");
                }
                println!(
                    "replacement_sponsor_tx={}",
                    report.replacement_sponsor.tx_hash
                );
                println!("allowed_publish_tx={}", report.allowed_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("channel_id={}", report.finalise.channel_id);
                println!("finalise_status={}", report.finalise.status);
            }
        }
        DevnetCommand::CompetingSpendSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            vault_capacity,
            alice_capacity,
            bob_capacity,
            sponsor_capacity,
            fee,
            finalise_since,
            mine_blocks,
            json,
        } => {
            let report = devnet::competing_spend_smoke(
                &rpc,
                CompetingSpendSmokeOptions {
                    contracts_dir,
                    private_key,
                    alice_private_key,
                    bob_private_key,
                    vault_capacity,
                    alice_capacity,
                    bob_capacity,
                    sponsor_capacity,
                    fee,
                    finalise_since,
                    mine_blocks,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("open_tx={}", report.open.tx_hash);
                println!("spare_sponsor_tx={}", report.spare_sponsor.tx_hash);
                println!("pending_publish_tx={}", report.pending_publish.tx_hash);
                println!("pending_publish_status={}", report.pending_publish.status);
                println!("pending_commit_status={}", report.pending_commit.status);
                println!("rejected_state_number={}", report.rejected_state_number);
                println!(
                    "rejected_against_state_out_point={}",
                    report.rejected_against_state_out_point
                );
                println!("rejection={}", report.rejection);
                println!("rebuilt_publish_tx={}", report.rebuilt_publish.tx_hash);
                println!("finalise_tx={}", report.finalise.tx_hash);
                println!("final_state_number={}", report.finalise.state_number);
                println!("finalise_status={}", report.finalise.status);
            }
        }
    }
    Ok(())
}
