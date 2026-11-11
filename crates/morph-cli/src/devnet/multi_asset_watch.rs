//! Current-profile package selection and automatic dispute publication. Cursor,
//! canonicality, alerts and bounded publication are shared with existing tools.
use super::*;
use crate::multi_asset_packages::{
    self as packages, MultiAssetPackageSummary, StoredMultiAssetPackage,
};
use crate::persistence::try_lock_private_path;
use morph_script_common::multi_asset as wire;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_PACKAGES: usize = 4096;

/// Wallet authority is used only to create a separate bounded sponsor budget.
/// Publishing from that budget uses the public sponsor change key.
pub struct AutoSponsorFunding {
    pub private_key: morph_key_input::SecretString,
    pub capacity: u64,
    pub funding_fee: u64,
}

pub struct Options {
    pub contracts_dir: PathBuf,
    pub fee_authorization: super::multi_asset_operator::FeeAuthorization,
    pub fee_out_point: String,
    pub store_dir: PathBuf,
    pub channel_id: String,
    pub from_block: u64,
    pub cursor_file: PathBuf,
    pub alert_file: PathBuf,
    pub publication_profile: PathBuf,
    pub attempt_log: PathBuf,
    pub detection_depth: u64,
    pub timeout_secs: u64,
    pub poll_ms: u64,
    pub max_fee: u64,
    pub mine_blocks: u64,
    pub watch_policy: Option<PathBuf>,
    pub auto_fund_sponsor: Option<AutoSponsorFunding>,
}

#[derive(Clone)]
struct Record {
    path: PathBuf,
    package: StoredMultiAssetPackage,
    summary: MultiAssetPackageSummary,
}

type Records = BTreeMap<(String, u64), Record>;

fn budget_quote(
    rpc: &CkbRpcClient,
    options: &Options,
    cursor: &WatchCursor,
    saved: &Records,
) -> crate::publication::PublicationBudget {
    use crate::publication::{BudgetReason, PublicationBudget};
    let unavailable = |reason| PublicationBudget::NotPrepared { reason };
    if options.auto_fund_sponsor.is_some() {
        return unavailable(BudgetReason::FundingNotPrepared);
    }
    let (Some(point), Some(context)) = (
        &cursor.last_observed_out_point,
        &cursor.current_funding_context_id,
    ) else {
        return unavailable(BudgetReason::SourceNotObserved);
    };
    let Some(selected) = latest(saved, context) else {
        return unavailable(BudgetReason::RecoveryNotAvailable);
    };
    let quote = super::multi_asset_operator::transact(
        rpc,
        super::multi_asset_operator::Options {
            operation: super::multi_asset_operator::Operation::Publish,
            package: selected.path.clone(),
            state_out_point: point.clone(),
            fee_out_point: options.fee_out_point.clone(),
            fee_authorization: options.fee_authorization.clone(),
            contracts_dir: options.contracts_dir.clone(),
            store_dir: options.store_dir.clone(),
            fee: options.max_fee,
            max_fee: options.max_fee,
            mine_blocks: 0,
            publication_profile: Some(options.publication_profile.clone()),
            attempt_log: Some(options.attempt_log.clone()),
            dry_run: true,
        },
    );
    quote
        .ok()
        .and_then(|v| serde_json::from_value(v["publication_budget"].clone()).ok())
        .unwrap_or_else(|| unavailable(BudgetReason::PreflightUnavailable))
}

fn invalid(error: ScriptError) -> anyhow::Error {
    anyhow!("invalid multi-asset recovery evidence: {error:?}")
}

fn records(dir: &Path, channel: &str) -> Result<Records> {
    let root = dir.join(channel.trim_start_matches("0x"));
    let mut records = Records::new();
    let mut count = 0;
    let mut contexts = 0;
    for entry in fs::read_dir(&root)
        .with_context(|| format!("cannot read channel recovery store {}", root.display()))?
    {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_dir(),
            "unexpected entry in channel recovery store"
        );
        contexts += 1;
        ensure!(
            contexts <= MAX_PACKAGES,
            "too many retained funding contexts"
        );
        let context = entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF8 funding-context directory"))?
            .to_owned();
        ensure!(
            context.len() == 64
                && context
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "noncanonical funding-context directory"
        );
        for file in fs::read_dir(entry.path())? {
            let file = file?;
            if file.path().extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            ensure!(
                file.file_type()?.is_file(),
                "recovery package must be a regular file"
            );
            count += 1;
            ensure!(
                count <= MAX_PACKAGES,
                "watch package limit reached; archive outside the active store explicitly"
            );
            let package = packages::read_package(&file.path())?;
            let summary = package.validate()?;
            ensure!(
                summary.channel_id == channel
                    && summary.funding_context_id == format!("0x{context}"),
                "recovery package stored under wrong channel/context"
            );
            ensure!(
                summary.phase == "settling" && summary.vaults_bound,
                "watch requires bound settling recovery packages"
            );
            let key = (
                summary.funding_context_id.clone(),
                summary.state_number.parse::<u64>()?,
            );
            if let Some(previous) = records.get(&key) {
                ensure!(
                    previous.package == package,
                    "conflicting recovery packages for funding context {} state {}",
                    key.0,
                    key.1
                );
            } else {
                records.insert(
                    key,
                    Record {
                        path: file.path(),
                        package,
                        summary,
                    },
                );
            }
        }
    }
    ensure!(
        !records.is_empty(),
        "no complete recovery packages for channel {channel}"
    );
    Ok(records)
}

fn latest<'a>(records: &'a Records, context: &str) -> Option<&'a Record> {
    records
        .iter()
        .rev()
        .find(|((ctx, _), _)| ctx == context)
        .map(|(_, record)| record)
}

fn validate_scan_identity(
    rpc: &CkbRpcClient,
    records: &Records,
    targets: &[ContractTarget],
) -> Result<()> {
    let genesis = rpc
        .genesis_block_hash()?
        .context("watch genesis unavailable")?;
    let identities = [
        contract_target_hash_by_name(targets, "morph-state-type")?,
        contract_target_hash_by_name(targets, "morph-state-lock")?,
        contract_target_hash_by_name(targets, "morph-vault-lock")?,
    ];
    for record in records.values() {
        let recovery = record.package.recovery()?;
        ensure!(
            recovery.state.header.chain_id == genesis.0,
            "watch package network mismatch"
        );
        for (bytes, expected) in [
            &recovery.scripts.state_type,
            &recovery.scripts.state_lock,
            &recovery.scripts.vault_lock,
        ]
        .into_iter()
        .zip(&identities)
        {
            let script = Script::from_slice(bytes)?;
            ensure!(
                script.code_hash().as_slice() == expected.as_bytes()
                    && script.hash_type().as_slice() == [2],
                "watch package deployment mismatch"
            );
        }
    }
    Ok(())
}

fn validate_scan_origin(rpc: &CkbRpcClient, records: &Records, from_block: u64) -> Result<()> {
    let mut checked = BTreeSet::new();
    for record in records.values() {
        if !checked.insert(&record.summary.funding_context_id) {
            continue;
        }
        let decoded = record.package.decode()?;
        let evidence = wire::MultiAssetWitness::parse(&decoded.witness).map_err(invalid)?;
        let point = evidence.outpoint(0).map_err(invalid)?;
        let status = rpc.transaction(parse_h256(&packages::canonical_hex(&point[..32]))?)?;
        if status.tx_status.status != Status::Committed {
            continue;
        }
        let number = status
            .tx_status
            .block_number
            .ok_or_else(|| anyhow!("funding transaction has no inclusion height"))?
            .value();
        let hash = status
            .tx_status
            .block_hash
            .ok_or_else(|| anyhow!("funding transaction has no inclusion hash"))?;
        ensure!(
            canonical_block_hash(rpc, number)?.as_deref() == Some(format!("{hash:#x}").as_str()),
            "funding transaction moved during canonicality check"
        );
        ensure!(
            from_block <= number,
            "from_block {from_block} is later than retained channel funding block {number}"
        );
    }
    Ok(())
}

fn retry_required(rpc: &CkbRpcClient, cursor: &WatchCursor, records: &Records) -> Result<bool> {
    let (Some(context), Some(number), Some(point)) = (
        &cursor.current_funding_context_id,
        cursor.last_observed_state_number,
        &cursor.last_observed_out_point,
    ) else {
        return Ok(false);
    };
    let Some(selected) = latest(records, context) else {
        return Ok(false);
    };
    if selected.summary.state_number.parse::<u64>()? <= number {
        return Ok(false);
    }
    live_state_is_settling(rpc, parse_out_point(point)?)
}

fn alert(
    options: &Options,
    event: WatchAlertEvent,
    severity: WatchAlertSeverity,
    message: String,
    cursor: &WatchCursor,
    selected: u64,
    observed: Option<&ObservedStateCellReport>,
) -> Result<()> {
    emit_alert(
        options,
        cursor,
        &alert_record(event, severity, message, cursor, selected, observed)?,
    )
}

fn alert_record(
    event: WatchAlertEvent,
    severity: WatchAlertSeverity,
    message: String,
    cursor: &WatchCursor,
    selected: u64,
    observed: Option<&ObservedStateCellReport>,
) -> Result<WatchtowerAlert> {
    let mut alert = WatchtowerAlert::new(
        cursor.channel_id.clone(),
        severity,
        event,
        message,
        selected,
        cursor.scanned_to_block,
        cursor.next_block,
    )?;
    if let Some(observed) = observed {
        alert = alert
            .with_observed(observed.state_number, observed.out_point.clone())
            .with_optional_funding_contexts(
                cursor.current_funding_context_id.clone(),
                Some(observed.funding_context_id.clone()),
            );
        if let Some(selected_anchor) = &cursor.current_funding_anchor {
            alert = alert
                .with_funding_anchors(selected_anchor.clone(), observed.funding_anchor.clone());
        }
    }
    Ok(alert)
}

fn delivery_allowed(options: &Options) -> Result<bool> {
    options
        .watch_policy
        .as_deref()
        .map(crate::watch_policy::read_watchtower_policy)
        .transpose()
        .map(|policy| policy.is_some_and(|p| p.allow_webhook_alerts))
}

fn checkpoint(options: &Options, cursor: &WatchCursor) -> Result<()> {
    crate::watch_runtime::commit(
        &options.cursor_file,
        cursor,
        None,
        delivery_allowed(options)?,
        None,
    )
}

fn emit_alert(options: &Options, cursor: &WatchCursor, alert: &WatchtowerAlert) -> Result<()> {
    let evidence = alert
        .publication_tx_hash
        .as_deref()
        .map(|hash| crate::watch_runtime::attempt_digest(&options.attempt_log, hash))
        .transpose()?;
    crate::watch_runtime::commit(
        &options.cursor_file,
        cursor,
        Some(alert),
        delivery_allowed(options)?,
        evidence,
    )?;
    // This local display can be rebuilt from committed intents on restart. It is
    // never an HTTP delivery acknowledgement or the authoritative scan cursor.
    if append_watchtower_alert(&options.alert_file, alert).is_err() {
        eprintln!("watch local display unavailable; committed alert retained in runtime store");
    }
    Ok(())
}

fn reset_cursor(channel: &str, from_block: u64) -> Result<WatchCursor> {
    WatchCursor::new(
        channel,
        from_block,
        from_block,
        from_block.saturating_sub(1),
    )
}

fn observed_json(observed: Option<&ObservedStateCellReport>) -> Result<Value> {
    let Some(observed) = observed else {
        return Ok(Value::Null);
    };
    let mut value = serde_json::to_value(observed)?;
    value["state_number"] = observed.state_number.to_string().into();
    Ok(value)
}

fn recover_scan(
    options: &Options,
    cursor: &mut WatchCursor,
    observed: &mut Option<ObservedStateCellReport>,
    recovery: &mut Option<WatchReorgRecoveryReport>,
    report: WatchReorgRecoveryReport,
) -> Result<()> {
    let event = reorg_alert(
        &cursor.channel_id,
        0,
        &report,
        "multi-asset watch canonical chain changed",
    )?;
    let reset = reset_cursor(&cursor.channel_id, options.from_block)?;
    emit_alert(options, &reset, &event)?;
    *cursor = reset;
    *observed = None;
    *recovery = Some(report);
    Ok(())
}

pub fn watch(rpc: &CkbRpcClient, options: Options) -> Result<Value> {
    ensure!(
        options.detection_depth > 0
            && options.timeout_secs > 0
            && options.poll_ms > 0
            && options.max_fee > 0,
        "watch bounds must be nonzero"
    );
    let channel = canonical_hex32(&options.channel_id)?;
    let profile = read_publication_profile(&options.publication_profile)?;
    ensure!(
        options.poll_ms <= profile.window.conservative_block_ms,
        "watch poll interval exceeds the profile's conservative block interval"
    );
    publication_deadline(&profile, options.detection_depth)?;
    ensure!(
        options.max_fee <= profile.fee.max_fee,
        "watch max_fee exceeds publication profile cap"
    );
    validate_funding_and_policy(&options)?;
    let _cursor_lock =
        try_lock_private_path(&options.cursor_file)?.ok_or_else(|| anyhow!("watch cursor busy"))?;
    let reconciliation = reconcile_publication_attempts(rpc, &options.attempt_log, &profile)?;
    let loaded = read_watch_cursor(&options.cursor_file)?;
    if let Some(cursor) = &loaded {
        ensure!(
            cursor.from_block == options.from_block,
            "watch cursor scan origin differs; use a fresh cursor file"
        );
        ensure!(
            cursor.channel_id == channel,
            "watch cursor belongs to another channel"
        );
    }
    if crate::watch_runtime::export_alerts(&options.cursor_file, &options.alert_file).is_err() {
        eprintln!("watch local display rebuild unavailable; durable source retained");
    }
    let mut check_checkpoint = loaded.is_some();
    let mut cursor = loaded.unwrap_or(reset_cursor(&channel, options.from_block)?);
    let mut recovery = None;
    let mut retry_rescan = false;
    let mut last_observed = None;
    let filter = state_cell_detection_filter(&options.contracts_dir)?;
    let targets = load_contract_targets(&options.contracts_dir)?;
    let fee_lock = options.fee_authorization.change_lock()?;
    let started = Instant::now();
    let timeout = Duration::from_secs(options.timeout_secs);
    'scan: loop {
        if check_checkpoint
            && let Some(reorg) = assess_watch_cursor_canonicality(rpc, &cursor, options.from_block)?
        {
            recover_scan(
                &options,
                &mut cursor,
                &mut last_observed,
                &mut recovery,
                reorg,
            )?;
            check_checkpoint = false;
        }
        let saved = match records(&options.store_dir, &channel) {
            Ok(records) => records,
            Err(error) => {
                alert(
                    &options,
                    WatchAlertEvent::RecoveryDataInvalid,
                    WatchAlertSeverity::Critical,
                    error.to_string(),
                    &cursor,
                    0,
                    None,
                )?;
                return Err(error);
            }
        };
        if let Err(error) = validate_scan_identity(rpc, &saved, &targets)
            .and_then(|_| validate_scan_origin(rpc, &saved, options.from_block))
        {
            alert(
                &options,
                WatchAlertEvent::RecoveryDataInvalid,
                WatchAlertSeverity::Critical,
                error.to_string(),
                &cursor,
                0,
                None,
            )?;
            return Err(error);
        }
        if retry_required(rpc, &cursor, &saved)? {
            cursor = reset_cursor(&channel, options.from_block)?;
            last_observed = None;
            retry_rescan = true;
            check_checkpoint = false;
        }
        let tip = rpc.tip_header()?.number_value()?;
        let mature_tip = tip
            .checked_add(1)
            .and_then(|height| height.checked_sub(options.detection_depth));
        while mature_tip.is_some_and(|height| cursor.next_block <= height) {
            let height = cursor.next_block;
            let Some(block) = rpc.block_by_number(height)? else {
                let mut report = watch_reorg_recovery(height, None, None, options.from_block);
                report.reason = "scan_block_missing".to_string();
                recover_scan(
                    &options,
                    &mut cursor,
                    &mut last_observed,
                    &mut recovery,
                    report,
                )?;
                check_checkpoint = false;
                continue 'scan;
            };
            if let Some(expected) = cursor.scanned_to_block_hash.as_deref() {
                let parent = format!("{:#x}", block.header.inner.parent_hash);
                if parent != expected {
                    let report = watch_reorg_recovery(
                        cursor.scanned_to_block,
                        Some(expected),
                        Some(&parent),
                        options.from_block,
                    );
                    recover_scan(
                        &options,
                        &mut cursor,
                        &mut last_observed,
                        &mut recovery,
                        report,
                    )?;
                    check_checkpoint = false;
                    continue 'scan;
                }
            }
            let hash = format!("{:#x}", block.header.hash);
            let canonical_hash = canonical_block_hash(rpc, height)?;
            if canonical_hash.as_deref() != Some(hash.as_str()) {
                let report = watch_reorg_recovery(
                    height,
                    Some(&hash),
                    canonical_hash.as_deref(),
                    options.from_block,
                );
                recover_scan(
                    &options,
                    &mut cursor,
                    &mut last_observed,
                    &mut recovery,
                    report,
                )?;
                check_checkpoint = false;
                continue 'scan;
            }
            let next_height = height
                .checked_add(1)
                .ok_or_else(|| anyhow!("watch height overflow"))?;
            let observations = observed_state_cells(&block, &channel, tip, &filter)?;
            for observed in observations {
                let point = parse_out_point(&observed.out_point)?;
                if rpc.canonical_live_cell(point.clone().into(), false)?.status != "live" {
                    continue;
                }
                // Revalidate the containing block after the liveness request.
                let canonical_hash = canonical_block_hash(rpc, height)?;
                if canonical_hash.as_deref() != Some(observed.block_hash.as_str()) {
                    let report = watch_reorg_recovery(
                        height,
                        Some(&observed.block_hash),
                        canonical_hash.as_deref(),
                        options.from_block,
                    );
                    recover_scan(
                        &options,
                        &mut cursor,
                        &mut last_observed,
                        &mut recovery,
                        report,
                    )?;
                    check_checkpoint = false;
                    continue 'scan;
                }
                cursor = watch_cursor_for_state(
                    &channel,
                    options.from_block,
                    next_height,
                    height,
                    Some(&observed.block_hash),
                    Some(&observed),
                    None,
                )?;
                let Some(selected) = latest(&saved, &observed.funding_context_id) else {
                    alert(
                        &options,
                        WatchAlertEvent::SplicePackageStale,
                        WatchAlertSeverity::Critical,
                        "no recovery package matches the exact observed funding context"
                            .to_string(),
                        &cursor,
                        0,
                        Some(&observed),
                    )?;
                    last_observed = Some(observed);
                    continue;
                };
                let decoded = selected.package.decode()?;
                let evidence = wire::MultiAssetWitness::parse(&decoded.witness).map_err(invalid)?;
                let live = load_canonical_live_cell(rpc, point)?;
                let expected_type = evidence.scripts().script(4).map_err(invalid)?;
                let live_header =
                    wire::MultiAssetStateHeader::parse(&live.data).map_err(invalid)?;
                let saved_header =
                    wire::MultiAssetStateHeader::parse(&decoded.header).map_err(invalid)?;
                let number = selected.summary.state_number.parse::<u64>()?;
                if number < observed.state_number
                    || (number == observed.state_number
                        && live_header.signing_digest() != saved_header.signing_digest())
                    || !live_header.same_context_except_progress(&saved_header)
                    || live.capacity != decoded.carrier_capacity
                {
                    let message =
                        "live State conflicts with, or is newer than, retained recovery evidence"
                            .to_string();
                    alert(
                        &options,
                        WatchAlertEvent::RecoveryDataInvalid,
                        WatchAlertSeverity::Critical,
                        message.clone(),
                        &cursor,
                        number,
                        Some(&observed),
                    )?;
                    return Err(anyhow!(message));
                }

                ensure!(
                    live.output.lock().as_slice()
                        == evidence.scripts().script(5).map_err(invalid)?
                        && live
                            .output
                            .type_()
                            .to_opt()
                            .is_some_and(|script| script.as_slice() == expected_type),
                    "observed State scripts differ from signed authority"
                );
                super::multi_asset_operator::validate_code(
                    rpc,
                    &options.contracts_dir,
                    &evidence,
                    &decoded.cell_deps,
                    &fee_lock,
                )?;
                if stale_settling_state_requires_defense(&observed, number) {
                    alert(
                        &options,
                        WatchAlertEvent::OlderStateDetected,
                        WatchAlertSeverity::Warning,
                        format!(
                            "saved state {number} supersedes observed state {}",
                            observed.state_number
                        ),
                        &cursor,
                        number,
                        Some(&observed),
                    )?;
                    let (fee_out_point, sponsor_top_up) =
                        match publication_sponsor(rpc, &options, &observed, number) {
                            Ok(funded) => funded,
                            Err(error) => {
                                alert(
                                    &options,
                                    WatchAlertEvent::PublicationFailed,
                                    WatchAlertSeverity::Critical,
                                    error.to_string(),
                                    &cursor,
                                    number,
                                    Some(&observed),
                                )?;
                                return Err(error);
                            }
                        };
                    let publication = super::multi_asset_operator::transact(
                        rpc,
                        super::multi_asset_operator::Options {
                            operation: super::multi_asset_operator::Operation::Publish,
                            package: selected.path.clone(),
                            state_out_point: observed.out_point.clone(),
                            fee_out_point,
                            fee_authorization: options.fee_authorization.clone(),
                            contracts_dir: options.contracts_dir.clone(),
                            store_dir: options.store_dir.clone(),
                            fee: 1,
                            max_fee: options.max_fee,
                            mine_blocks: options.mine_blocks,
                            publication_profile: Some(options.publication_profile.clone()),
                            attempt_log: Some(options.attempt_log.clone()),
                            dry_run: false,
                        },
                    );
                    match publication {
                        Ok(publication) => {
                            let selected_header = packages::decode_hex(
                                &selected.package.header_hex,
                                wire::MULTI_ASSET_STATE_HEADER_LEN,
                            )?;
                            let selected_header =
                                wire::MultiAssetStateHeader::parse(&selected_header)
                                    .map_err(invalid)?;
                            let submitted = alert_record(
                                WatchAlertEvent::PublicationSubmitted,
                                WatchAlertSeverity::Warning,
                                format!(
                                    "multi-asset publication status {} (canonical_confirmed={})",
                                    publication["status"], publication["canonical_confirmed"]
                                ),
                                &cursor,
                                number,
                                Some(&observed),
                            )?
                            .with_publication(
                                publication["tx_hash"]
                                    .as_str()
                                    .context("publication receipt lacks exact transaction hash")?
                                    .to_string(),
                            )
                            .with_funding_anchors(
                                hex32(selected_header.funding_anchor()),
                                observed.funding_anchor.clone(),
                            )
                            .with_optional_funding_contexts(
                                Some(selected.summary.funding_context_id.clone()),
                                Some(observed.funding_context_id.clone()),
                            );
                            emit_alert(&options, &cursor, &submitted)?;
                            return Ok(
                                json!({"schema":"morph.multi_asset_watch_pass.v1", "channel_id":channel,
                                "operator_id":profile.operator_id, "cursor_file":options.cursor_file, "reorg_recovery":recovery,
                                "retry_rescan":retry_rescan, "publication_reconciliation":reconciliation,
                                "scanned_to_block":cursor.scanned_to_block,"next_from_block":cursor.next_block,
                                "sponsor_top_up":sponsor_top_up,
                                "publication_budget":crate::publication::PublicationBudget::NotPrepared {
                                    reason: crate::publication::BudgetReason::SourceConsumed },
                                "selected":selected.summary, "observed":observed_json(Some(&observed))?, "publication":publication}),
                            );
                        }
                        Err(error) => {
                            alert(
                                &options,
                                WatchAlertEvent::PublicationFailed,
                                WatchAlertSeverity::Critical,
                                error.to_string(),
                                &cursor,
                                number,
                                Some(&observed),
                            )?;
                            return Err(error);
                        }
                    }
                }
                last_observed = Some(observed);
            }
            cursor = watch_cursor_for_state(
                &channel,
                options.from_block,
                next_height,
                height,
                Some(&format!("{:#x}", block.header.hash)),
                last_observed.as_ref(),
                Some(&cursor),
            )?;
            checkpoint(&options, &cursor)?;
            check_checkpoint = true;
            if started.elapsed() >= timeout {
                break;
            }
        }
        if started.elapsed() >= timeout {
            alert(
                &options,
                WatchAlertEvent::ScanIdle,
                WatchAlertSeverity::Info,
                "multi-asset watch pass ended without submitting a publication".to_string(),
                &cursor,
                0,
                last_observed.as_ref(),
            )?;
            let budget = budget_quote(rpc, &options, &cursor, &saved);
            return Ok(
                json!({"schema":"morph.multi_asset_watch_pass.v1", "channel_id":channel,
                "operator_id":profile.operator_id, "cursor_file":options.cursor_file, "reorg_recovery":recovery,
                "retry_rescan":retry_rescan, "publication_reconciliation":reconciliation,
                "scanned_to_block":cursor.scanned_to_block, "next_from_block":cursor.next_block,
                "caught_up":mature_tip.is_none_or(|height| cursor.next_block > height),
                "publication_budget":budget,
                "observed":observed_json(last_observed.as_ref())?,"publication":Value::Null}),
            );
        }
        std::thread::sleep(
            Duration::from_millis(options.poll_ms).min(timeout.saturating_sub(started.elapsed())),
        );
    }
}

fn validate_funding_and_policy(options: &Options) -> Result<()> {
    if let Some(funding) = &options.auto_fund_sponsor {
        ensure!(
            options.fee_out_point.is_empty(),
            "auto sponsor funding cannot also name an explicit fee input"
        );
        ensure!(
            matches!(
                options.fee_authorization,
                super::multi_asset_operator::FeeAuthorization::Sponsor { .. }
            ),
            "auto sponsor publication requires public sponsor authorization"
        );
        ensure!(
            options.mine_blocks > 0
                && funding.funding_fee > 0
                && funding.capacity >= options.max_fee,
            "invalid auto sponsor funding budget or confirmation count"
        );
    } else {
        ensure!(
            !options.fee_out_point.is_empty(),
            "watch requires an explicit fee input or auto sponsor funding"
        );
    }
    if let Some(path) = &options.watch_policy {
        crate::watch_policy::read_watchtower_policy(path)?.validate_run(
            &crate::watch_policy::WatchPolicyRun {
                channel_id: &options.channel_id,
                detection_depth: options.detection_depth,
                timeout_secs: options.timeout_secs,
                poll_ms: options.poll_ms,
                fee: options
                    .auto_fund_sponsor
                    .as_ref()
                    .map_or(options.max_fee, |funding| {
                        options.max_fee.max(funding.funding_fee)
                    }),
                mine_blocks: options.mine_blocks,
                sponsor_out_point_present: matches!(
                    options.fee_authorization,
                    super::multi_asset_operator::FeeAuthorization::Sponsor { .. }
                ) && options.auto_fund_sponsor.is_none(),
                auto_fund_sponsor: options.auto_fund_sponsor.is_some(),
                auto_sponsor_capacity: options
                    .auto_fund_sponsor
                    .as_ref()
                    .map_or(0, |funding| funding.capacity),
            },
        )?;
    }
    Ok(())
}

fn publication_sponsor(
    rpc: &CkbRpcClient,
    options: &Options,
    observed: &ObservedStateCellReport,
    selected: u64,
) -> Result<(String, Option<FundSponsorReport>)> {
    let Some(funding) = &options.auto_fund_sponsor else {
        return Ok((options.fee_out_point.clone(), None));
    };
    let super::multi_asset_operator::FeeAuthorization::Sponsor { change_pubkey } =
        &options.fee_authorization
    else {
        return Err(anyhow!(
            "auto sponsor requires public sponsor authorization"
        ));
    };
    let top_up = fund_sponsor(
        rpc,
        FundSponsorOptions {
            contracts_dir: options.contracts_dir.clone(),
            private_key: funding.private_key.clone(),
            sponsor_change_pubkey: Some(change_pubkey.clone()),
            state_out_point: observed.out_point.clone(),
            sponsor_capacity: funding.capacity,
            sponsor_min_state_number: selected,
            sponsor_max_state_number: selected,
            strict_sponsor_range: false,
            sponsor_max_fee_per_tx: Some(options.max_fee),
            sponsor_max_total_fee: Some(options.max_fee),
            fee: funding.funding_fee,
            mine_blocks: options.mine_blocks,
        },
    )?;
    Ok((
        printable_out_point_string(&top_up.sponsor_out_point),
        Some(top_up),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn scan_identity_checks_saved_network_and_all_three_script_identities() {
        let package = packages::fixture_package().unwrap();
        let recovery = package.recovery().unwrap();
        let summary = package.validate().unwrap();
        let mut saved = Records::new();
        saved.insert(
            (summary.funding_context_id.clone(), 1),
            Record {
                path: PathBuf::from("synthetic.json"),
                package,
                summary,
            },
        );
        let mut targets = ["morph-state-type", "morph-state-lock", "morph-vault-lock"]
            .into_iter()
            .zip([
                &recovery.scripts.state_type,
                &recovery.scripts.state_lock,
                &recovery.scripts.vault_lock,
            ])
            .map(|(name, bytes)| ContractTarget {
                name: name.into(),
                data_hash: Script::from_slice(bytes).unwrap().code_hash().unpack(),
                type_hash: None,
            })
            .collect::<Vec<_>>();
        let rpc =
            crate::admission_channel::tests::MockRpc::start(recovery.state.header.chain_id, 10);
        let client = CkbRpcClient::new_health_check(&rpc.url).unwrap();
        validate_scan_identity(&client, &saved, &targets).unwrap();
        for i in 0..targets.len() {
            let original = targets[i].data_hash.clone();
            targets[i].data_hash = H256([99; 32]);
            assert!(validate_scan_identity(&client, &saved, &targets).is_err());
            targets[i].data_hash = original;
        }
        rpc.respond(
            "get_block_hash",
            json!(["0x0"]),
            json!(format!("0x{}", hex::encode([99; 32]))),
        );
        assert!(validate_scan_identity(&client, &saved, &targets).is_err());
    }

    #[test]
    fn service_policy_checks_actual_sponsor_budget_and_webhook_before_rpc() {
        let path = std::env::temp_dir().join(format!(
            "morph-current-watch-policy-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut policy = crate::watch_policy::fixture_policy();
        policy.min_detection_depth = 1;
        policy.min_timeout_secs = 1;
        policy.allow_explicit_sponsor = false;
        policy.require_auto_fund_sponsor = true;
        policy.allow_webhook_alerts = false;
        fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        let key = SigningKey::from_slice(&[1; 32]).unwrap();
        let mut options = Options {
            contracts_dir: PathBuf::from("contracts"),
            fee_authorization: super::super::multi_asset_operator::FeeAuthorization::Sponsor {
                change_pubkey: hex::encode(key.verifying_key().to_sec1_point(true).as_bytes()),
            },
            fee_out_point: String::new(),
            store_dir: PathBuf::from("packages"),
            channel_id: format!("0x{}", "01".repeat(32)),
            from_block: 0,
            cursor_file: PathBuf::from("cursor.db"),
            alert_file: PathBuf::from("alerts.jsonl"),
            publication_profile: PathBuf::from("profile.json"),
            attempt_log: PathBuf::from("attempts.jsonl"),
            detection_depth: 1,
            timeout_secs: 1,
            poll_ms: 100,
            max_fee: policy.max_fee,
            mine_blocks: 4,
            watch_policy: Some(path.clone()),
            auto_fund_sponsor: Some(AutoSponsorFunding {
                private_key: hex::encode([1; 32]).into(),
                capacity: policy.max_auto_sponsor_capacity,
                funding_fee: 1,
            }),
        };
        validate_funding_and_policy(&options).unwrap();
        options.auto_fund_sponsor.as_mut().unwrap().funding_fee = options.max_fee + 1;
        assert!(
            validate_funding_and_policy(&options)
                .unwrap_err()
                .to_string()
                .contains("exceeds policy maximum")
        );
        options.auto_fund_sponsor.as_mut().unwrap().funding_fee = 1;
        options.fee_out_point = format!("0x{}:0", "02".repeat(32));
        assert!(validate_funding_and_policy(&options).is_err());
        options.fee_out_point.clear();
        options.auto_fund_sponsor.as_mut().unwrap().capacity = options.max_fee - 1;
        assert!(validate_funding_and_policy(&options).is_err());
        options.auto_fund_sponsor = None;
        options.fee_out_point = format!("0x{}:0", "02".repeat(32));
        assert!(
            validate_funding_and_policy(&options)
                .unwrap_err()
                .to_string()
                .contains("explicit sponsor")
        );
        fs::remove_file(path).unwrap();
    }

    fn resign(package: &mut morph_core::MultiAssetRecoveryPackage) {
        let digest = package.state.signing_digest().unwrap();
        for member in &mut package.authorization.signatures {
            let key = [1u8, 2]
                .into_iter()
                .map(|v| SigningKey::from_slice(&[v; 32]).unwrap())
                .find(|key| {
                    key.verifying_key().to_sec1_point(true).as_bytes() == member.pubkey_sec1
                })
                .unwrap();
            let signature: Signature = key.sign_prehash(&digest).unwrap();
            member.signature = signature.to_bytes().to_vec();
        }
    }

    #[test]
    fn saved_packages_are_selected_per_context_and_conflicting_votes_fail_closed() {
        let dir = std::env::temp_dir().join(format!(
            "morph-watch-packages-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let first = packages::fixture_package().unwrap();
        let summary = first.validate().unwrap();
        packages::write_package(&dir, &first).unwrap();
        let mut other = first.recovery().unwrap();
        for point in &mut other.outpoints {
            point.tx_hash = [88; 32];
        }
        other.state.vault_outpoint_set_root =
            morph_core::multi_asset_outpoint_commitment(&other.manifest, &other.outpoints).unwrap();
        other.state.header.state_number = 100;
        resign(&mut other);
        let other =
            StoredMultiAssetPackage::with_dependency_records(&other, first.cell_deps.clone())
                .unwrap();
        packages::write_package(&dir, &other).unwrap();
        let saved = records(&dir, &summary.channel_id).unwrap();
        assert_eq!(
            latest(&saved, &summary.funding_context_id)
                .unwrap()
                .summary
                .state_number,
            summary.state_number
        );
        assert_eq!(
            latest(&saved, &other.validate().unwrap().funding_context_id)
                .unwrap()
                .summary
                .state_number,
            "100"
        );
        let mut conflict = first.recovery().unwrap();
        conflict.settlement.payouts[0].values[0].amount -= 1;
        conflict.settlement.payouts[0].values[1].amount += 1;
        conflict.state.header.settlement_descriptor_commitment =
            conflict.settlement.commitment().unwrap();
        resign(&mut conflict);
        packages::write_package(
            &dir,
            &StoredMultiAssetPackage::with_dependency_records(&conflict, first.cell_deps).unwrap(),
        )
        .unwrap();
        assert!(
            records(&dir, &summary.channel_id)
                .err()
                .unwrap()
                .to_string()
                .contains("conflicting recovery packages")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shared_scanner_recognises_current_profile_and_rejects_fake_authority() {
        use ckb_types::core::{BlockBuilder, EpochNumberWithFraction};
        let package = packages::fixture_package().unwrap().recovery().unwrap();
        let output = CellOutput::new_builder()
            .capacity(package.state_carrier_capacity)
            .lock(Script::from_slice(&package.scripts.state_lock).unwrap())
            .type_(Some(Script::from_slice(&package.scripts.state_type).unwrap()).pack())
            .build();
        let filter = StateCellDetectionFilter {
            state_type_code_hash: H256([3; 32]),
            state_lock_code_hash: H256([2; 32]),
        };
        let make_block = |output: CellOutput| {
            let tx = TransactionBuilder::default()
                .output(output)
                .output_data(Bytes::from(package.state.encode().unwrap().to_vec()).pack())
                .build();
            let block = BlockBuilder::default()
                .number(10u64)
                .epoch(EpochNumberWithFraction::new(0, 10, 100).full_value())
                .transaction(tx)
                .build();
            ckb_jsonrpc_types::BlockView::from(block)
        };
        let channel = hex32(&package.state.header.channel_id);
        let block = make_block(output.clone());
        let found = observed_state_cells(&block, &channel, 10, &filter).unwrap();
        assert_eq!(found.len(), 1);
        assert!(stale_settling_state_requires_defense(
            &found[0],
            found[0].state_number + 1
        ));
        let mut active = found[0].clone();
        active.phase = "active".to_string();
        active.state_number = 0;
        assert!(!stale_settling_state_requires_defense(&active, 100));
        assert_eq!(
            found[0].funding_context_id,
            hex32(&package.state.funding_context_id().unwrap())
        );
        let mut cursor = reset_cursor(&channel, 1).unwrap();
        cursor.current_funding_anchor = Some(found[0].funding_anchor.clone());
        cursor.current_funding_context_id = Some(found[0].funding_context_id.clone());
        let submitted = alert_record(
            WatchAlertEvent::PublicationSubmitted,
            WatchAlertSeverity::Warning,
            "current publication observed".to_string(),
            &cursor,
            found[0].state_number + 1,
            Some(&found[0]),
        )
        .unwrap()
        .with_publication(hex32(&[91; 32]));
        assert_eq!(submitted.publication_tx_hash, Some(hex32(&[91; 32])));
        assert_eq!(
            submitted.selected_funding_anchor,
            Some(found[0].funding_anchor.clone())
        );
        assert_eq!(
            submitted.observed_funding_anchor,
            submitted.selected_funding_anchor
        );
        assert_eq!(
            submitted.selected_funding_context_id,
            Some(found[0].funding_context_id.clone())
        );
        let mut retired_shape = vec![0; 346];
        retired_shape[..318].copy_from_slice(&package.state.encode().unwrap());
        assert!(parse_state_observation(&retired_shape).is_err());
        let fake = make_block(output.as_builder().type_(None::<Script>.pack()).build());
        assert!(
            observed_state_cells(&fake, &channel, 10, &filter,)
                .unwrap()
                .is_empty()
        );
    }
}
