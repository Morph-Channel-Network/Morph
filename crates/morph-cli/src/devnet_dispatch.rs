use super::*;
use crate::canonical_fields::canonical_hex32;

pub(super) fn run_devnet(rpc_url: &str, command: DevnetCommand) -> Result<()> {
    let rpc = CkbRpcClient::new(rpc_url)?;
    match command {
        DevnetCommand::Factory { command } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&devnet::factory_operator::run(&rpc, command)?)?
            );
        }
        DevnetCommand::MultiAssetWatch {
            contracts_dir,
            fee_authorization,
            fee_out_point,
            store_dir,
            channel_id,
            from_block,
            cursor_file,
            alert_file,
            publication_profile,
            attempt_log,
            detection_depth,
            timeout_secs,
            poll_ms,
            max_fee,
            mine_blocks,
        } => {
            let report = devnet::multi_asset_watch::watch(
                &rpc,
                devnet::multi_asset_watch::Options {
                    contracts_dir,
                    fee_authorization,
                    fee_out_point,
                    store_dir,
                    channel_id,
                    from_block,
                    cursor_file,
                    alert_file,
                    publication_profile,
                    attempt_log,
                    detection_depth,
                    timeout_secs,
                    poll_ms,
                    max_fee,
                    mine_blocks,
                    watch_policy: None,
                    alert_webhook_url: None,
                    auto_fund_sponsor: None,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetTransact {
            operation,
            package,
            state_out_point,
            fee_out_point,
            fee_authorization,
            contracts_dir,
            store_dir,
            fee,
            max_fee,
            mine_blocks,
            publication_profile,
            attempt_log,
            dry_run,
        } => {
            let report = devnet::multi_asset_operator::transact(
                &rpc,
                devnet::multi_asset_operator::Options {
                    operation,
                    package,
                    state_out_point,
                    fee_out_point,
                    fee_authorization,
                    contracts_dir,
                    store_dir,
                    fee,
                    max_fee,
                    mine_blocks,
                    publication_profile,
                    attempt_log,
                    dry_run,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetFundingPrepare {
            terms,
            max_fee,
            contracts_dir,
            output,
        } => {
            let report = devnet::multi_asset_root_operator::prepare(
                &rpc,
                devnet::multi_asset_root_operator::PrepareOptions {
                    terms,
                    max_fee,
                    contracts_dir,
                    output,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetFundingWalletSign {
            terms,
            transaction,
            package,
            max_fee,
            contracts_dir,
            store_dir,
            private_key,
        } => {
            let report = devnet::multi_asset_root_operator::sign_wallet(
                &rpc,
                devnet::multi_asset_root_operator::SignOptions {
                    terms,
                    transaction,
                    package,
                    max_fee,
                    contracts_dir,
                    store_dir,
                    private_key,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetFundingSubmit {
            transaction,
            package,
            contracts_dir,
            store_dir,
            max_fee,
            mine_blocks,
            dry_run,
        } => {
            let report = devnet::multi_asset_funding_operator::submit(
                &rpc,
                devnet::multi_asset_funding_operator::Options {
                    transaction,
                    package,
                    contracts_dir,
                    store_dir,
                    max_fee,
                    mine_blocks,
                    dry_run,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetSplicePrepare {
            old_package,
            state_out_point,
            terms,
            external_inputs,
            change_pubkey,
            fee,
            contracts_dir,
            output,
        } => {
            let report = devnet::multi_asset_splice_operator::prepare(
                &rpc,
                devnet::multi_asset_splice_operator::PrepareOptions {
                    old_package,
                    state_out_point,
                    terms,
                    external_inputs,
                    change_pubkey,
                    fee,
                    contracts_dir,
                    output,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetSpliceSubmit {
            transaction,
            old_package,
            new_package,
            contracts_dir,
            store_dir,
            max_fee,
            mine_blocks,
            dry_run,
            fee_authorization,
        } => {
            let report = devnet::multi_asset_splice_operator::submit(
                &rpc,
                devnet::multi_asset_splice_operator::Options {
                    transaction,
                    old_package,
                    new_package,
                    contracts_dir,
                    store_dir,
                    max_fee,
                    mine_blocks,
                    dry_run,
                    fee_authorization,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        DevnetCommand::MultiAssetSmoke {
            contracts_dir,
            private_key,
            alice_private_key,
            bob_private_key,
            asset_count,
            shared_funding,
            funding_reorg,
            splice_transitions,
            fee,
            finalise_since,
            mine_blocks,
            store_dir,
            publication_profile,
            watch_publication,
            watch_reorg,
            sponsor_publication,
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
                    shared_funding,
                    funding_reorg,
                    splice_transitions,
                    fee,
                    finalise_since,
                    mine_blocks,
                    store_dir,
                    publication_profile,
                    watch_publication,
                    watch_reorg,
                    sponsor_publication,
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
                        channel.report["scanned_to_block"],
                        channel.report["next_from_block"],
                        !channel.report["publication"].is_null()
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
    }
    Ok(())
}
