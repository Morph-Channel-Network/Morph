//! Bounded CKB reads and exact-hash submission. No automatic retry of writes.
use crate::{
    address::Network,
    transaction::{Coin, PreparedTransfer},
};
use anyhow::{Result, anyhow, ensure};
use ckb_jsonrpc_types as json;
use ckb_types::{
    core::{Capacity, TransactionView},
    packed,
    prelude::*,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::{Duration, Instant},
};

const MAINNET_GENESIS: &str = "0x92b197aa1fba0f63633922c61c92375c9c074a93e85963554f5499fe1450d0e5";
const TESTNET_GENESIS: &str = "0x10639e0895502b5688a6be8cf69460d76541bfa4821629d86d62ba0aae3f9606";
fn network_matches(network: Network, genesis: &str) -> bool {
    match network {
        Network::Mainnet => genesis == MAINNET_GENESIS,
        Network::Testnet => genesis == TESTNET_GENESIS,
        Network::Devnet => genesis != MAINNET_GENESIS && genesis != TESTNET_GENESIS,
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub network: Network,
    pub rpc_url: String,
    pub indexer_url: String,
    pub genesis_hash: String,
}
impl NetworkConfig {
    pub fn validate_identity(&self) -> Result<()> {
        ensure!(
            network_matches(self.network, &self.genesis_hash),
            "wallet.network_mismatch"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Balance {
    pub total_capacity: String,
    pub occupied_capacity: String,
    pub available_plain_capacity: String,
    pub reserved_capacity: String,
    pub token_quantities: BTreeMap<String, String>,
    pub immature_capacity: String,
    pub tip_number: u64,
    pub tip_hash: String,
    pub cell_count: usize,
}
pub struct Snapshot {
    pub balance: Balance,
    pub coins: Vec<Coin>,
    pub secp_dep: packed::CellDep,
}
pub struct Chain {
    client: Client,
    deadline: std::cell::Cell<Option<Instant>>,
    pub config: NetworkConfig,
}
#[derive(Deserialize)]
struct Cell {
    output: json::CellOutput,
    output_data: Option<json::JsonBytes>,
    out_point: json::OutPoint,
    block_number: json::BlockNumber,
    tx_index: json::Uint32,
}
#[derive(Deserialize)]
struct Page {
    objects: Vec<Cell>,
    last_cursor: String,
}
#[derive(Deserialize)]
struct Tip {
    block_hash: ckb_types::H256,
    block_number: json::BlockNumber,
}
impl Chain {
    /// Select a known public network or explicitly connect a development node; save the observed
    /// development genesis once, and verify that pin on every subsequent operation.
    pub fn discover(
        network: Network,
        rpc_url: String,
        indexer_url: String,
    ) -> Result<NetworkConfig> {
        let mut config = NetworkConfig {
            network,
            rpc_url,
            indexer_url,
            genesis_hash: format!("0x{}", "00".repeat(32)),
        };
        let probe = Self::new(config.clone())?;
        config.genesis_hash = probe.call(false, "get_block_hash", json!(["0x0"]))?;
        Self::new(config.clone())?.verify_network()?;
        Ok(config)
    }

    pub fn new(config: NetworkConfig) -> Result<Self> {
        for raw in [&config.rpc_url, &config.indexer_url] {
            let url = reqwest::Url::parse(raw)?;
            ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none()
                    && url.host_str().is_some(),
                "wallet.rpc_url"
            );
        }
        ensure!(
            config.genesis_hash.len() == 66
                && config.genesis_hash.starts_with("0x")
                && hex::decode(&config.genesis_hash[2..]).is_ok(),
            "wallet.genesis_pin_required"
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(12))
            .connect_timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            config,
            deadline: Default::default(),
        })
    }
    fn call<T: DeserializeOwned>(&self, indexer: bool, method: &str, params: Value) -> Result<T> {
        let url = if indexer {
            &self.config.indexer_url
        } else {
            &self.config.rpc_url
        };
        let remaining = self.deadline.get().map_or(Duration::from_secs(12), |d| {
            d.saturating_duration_since(Instant::now())
                .min(Duration::from_secs(12))
        });
        ensure!(!remaining.is_zero(), "wallet.sync_budget");
        let response = self
            .client
            .post(url)
            .timeout(remaining)
            .json(&json!({"id":1,"jsonrpc":"2.0","method":method,"params":params}))
            .send()?;
        ensure!(
            response.status().is_success(),
            "wallet.rpc_http {}",
            response.status()
        );
        const LIMIT: u64 = 8 * 1024 * 1024;
        ensure!(
            response.content_length().is_none_or(|v| v <= LIMIT),
            "wallet.rpc_response_limit"
        );
        let mut body = Vec::new();
        response.take(LIMIT + 1).read_to_end(&mut body)?;
        ensure!(body.len() <= LIMIT as usize, "wallet.rpc_response_limit");
        let body: Value = serde_json::from_slice(&body)?;
        ensure!(
            body["jsonrpc"] == "2.0" && body["id"] == 1,
            "wallet.rpc_invalid_response"
        );
        ensure!(
            body.get("error").is_none(),
            "wallet.rpc_rejected {}",
            body["error"]
        );
        Ok(serde_json::from_value(
            body.get("result")
                .ok_or_else(|| anyhow!("wallet.rpc_invalid_response"))?
                .clone(),
        )?)
    }
    pub fn verify_network(&self) -> Result<()> {
        let genesis: String = self.call(false, "get_block_hash", json!(["0x0"]))?;
        ensure!(
            genesis == self.config.genesis_hash,
            "wallet.network_changed"
        );
        ensure!(
            network_matches(self.config.network, &genesis),
            "wallet.network_mismatch"
        );
        Ok(())
    }
    /// All pages belong to one stable indexer checkpoint; a changing tip invalidates the snapshot.
    pub fn snapshot(
        &self,
        owner: &packed::Script,
        reserved: &BTreeSet<Vec<u8>>,
    ) -> Result<Snapshot> {
        let _budget = Budget::start(&self.deadline);
        let started = Instant::now();
        self.verify_network()?;
        let tip: Tip = self.call(true, "get_indexer_tip", json!([]))?;
        let canonical: String = self.call(false, "get_block_hash", json!([tip.block_number]))?;
        ensure!(
            canonical == format!("{:#x}", tip.block_hash),
            "wallet.indexer_fork"
        );
        let head: json::HeaderView = self.call(false, "get_tip_header", json!([]))?;
        ensure!(
            head.inner
                .number
                .value()
                .saturating_sub(tip.block_number.value())
                <= 3,
            "wallet.indexer_behind"
        );
        let search = json!({"script":json::Script::from(owner.clone()),"script_type":"lock","script_search_mode":"exact","with_data":true});
        let consensus: Value = self.call(false, "get_consensus", json!([]))?;
        let maturity = parse_hex_u64(&consensus["cellbase_maturity"])?;
        let mut epochs = BTreeMap::new();
        let mut cursor: Option<String> = None;
        let mut coins = Vec::new();
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        let mut occupied = 0u64;
        let mut available = 0u64;
        let mut held = 0u64;
        let mut immature = 0u64;
        let mut tokens = BTreeMap::<String, u128>::new();
        loop {
            ensure!(
                started.elapsed() < Duration::from_secs(30),
                "wallet.sync_budget"
            );
            let page: Page =
                self.call(true, "get_cells", json!([search, "asc", "0x64", cursor]))?;
            ensure!(page.objects.len() <= 100, "wallet.rpc_invalid_response");
            if page.objects.is_empty() {
                break;
            }
            ensure!(
                cursor.as_ref() != Some(&page.last_cursor),
                "wallet.indexer_cursor_stalled"
            );
            cursor = Some(page.last_cursor);
            for cell in page.objects {
                ensure!(
                    started.elapsed() < Duration::from_secs(30),
                    "wallet.sync_budget"
                );
                ensure!(
                    coins.len() < 4096 && seen.len() < 4096,
                    "wallet.too_many_cells"
                );
                let point: packed::OutPoint = cell.out_point.into();
                ensure!(
                    seen.insert(point.as_slice().to_vec()),
                    "wallet.duplicate_input"
                );
                let output: packed::CellOutput = cell.output.into();
                ensure!(output.lock() == *owner, "wallet.indexer_wrong_lock");
                let data = cell
                    .output_data
                    .ok_or_else(|| anyhow!("wallet.indexer_missing_data"))?
                    .into_bytes();
                let cap: u64 = output.capacity().unpack();
                let min = output
                    .occupied_capacity(Capacity::bytes(data.len())?)?
                    .as_u64();
                ensure!(cap >= min, "wallet.invalid_input_capacity");
                total = total
                    .checked_add(cap)
                    .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
                occupied = occupied
                    .checked_add(min)
                    .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
                // CKB cellbase outputs require four complete epochs on public chains. For development,
                // use the node's consensus maturity rather than treating all mined outputs as spendable.
                let mature = if cell.tx_index.value() == 0 && cell.block_number.value() != 0 {
                    let origin = if let Some(epoch) = epochs.get(&cell.block_number.value()) {
                        *epoch
                    } else {
                        let header: json::HeaderView =
                            self.call(false, "get_header_by_number", json!([cell.block_number]))?;
                        let epoch = header.inner.epoch.value();
                        epochs.insert(cell.block_number.value(), epoch);
                        epoch
                    };
                    epoch_mature(origin, head.inner.epoch.value(), maturity)?
                } else {
                    true
                };
                if !mature {
                    immature = immature
                        .checked_add(cap)
                        .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
                    continue;
                }
                if reserved.contains(point.as_slice()) {
                    held = held
                        .checked_add(cap)
                        .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
                } else if output.type_().is_none() && data.is_empty() {
                    available = available
                        .checked_add(cap)
                        .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
                }
                if let Some(script) = output.type_().to_opt()
                    && data.len() == 16
                {
                    let amount = u128::from_le_bytes(data.as_ref().try_into()?);
                    let value = tokens
                        .entry(format!("{:#x}", script.calc_script_hash()))
                        .or_default();
                    *value = value
                        .checked_add(amount)
                        .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
                }
                coins.push(Coin {
                    out_point: point,
                    output,
                    data,
                });
            }
        }
        let after: Tip = self.call(true, "get_indexer_tip", json!([]))?;
        ensure!(
            after.block_hash == tip.block_hash,
            "wallet.snapshot_changed"
        );
        let again: String = self.call(false, "get_block_hash", json!([tip.block_number]))?;
        ensure!(again == canonical, "wallet.snapshot_changed");
        let secp_dep = self.secp_dep()?;
        Ok(Snapshot {
            balance: Balance {
                total_capacity: total.to_string(),
                occupied_capacity: occupied.to_string(),
                available_plain_capacity: available.to_string(),
                reserved_capacity: held.to_string(),
                token_quantities: tokens
                    .into_iter()
                    .map(|(k, v)| (k, v.to_string()))
                    .collect(),
                immature_capacity: immature.to_string(),
                tip_number: tip.block_number.value(),
                tip_hash: canonical,
                cell_count: coins.len(),
            },
            coins,
            secp_dep,
        })
    }
    pub fn verify_inputs(&self, prepared: &PreparedTransfer) -> Result<()> {
        let _budget = Budget::start(&self.deadline);
        self.verify_network()?;
        for coin in prepared.coins() {
            let live: json::CellWithStatus = self.call(
                false,
                "get_live_cell",
                json!([json::OutPoint::from(coin.out_point.clone()), true]),
            )?;
            ensure!(live.status == "live", "wallet.input_no_longer_live");
            let cell = live
                .cell
                .ok_or_else(|| anyhow!("wallet.input_no_longer_live"))?;
            let output: packed::CellOutput = cell.output.into();
            let data = cell
                .data
                .ok_or_else(|| anyhow!("wallet.rpc_invalid_response"))?
                .content
                .into_bytes();
            ensure!(
                output == coin.output && data == coin.data,
                "wallet.input_changed"
            );
        }
        Ok(())
    }
    pub fn fee_rate(&self) -> Result<u64> {
        self.verify_network()?;
        let value: json::Uint64 = self.call(false, "estimate_fee_rate", json!([]))?;
        ensure!(
            (1..=100_000).contains(&value.value()),
            "wallet.fee_policy_limit"
        );
        Ok(value.value())
    }
    pub fn preflight(&self, tx: &TransactionView) -> Result<()> {
        let _cycles: Value = self.call(
            false,
            "estimate_cycles",
            json!([json::Transaction::from(tx.data())]),
        )?;
        Ok(())
    }
    pub fn submit(&self, tx: &TransactionView) -> Result<String> {
        self.verify_network()?;
        let hash: String = self.call(
            false,
            "send_transaction",
            json!([json::Transaction::from(tx.data()), "passthrough"]),
        )?;
        ensure!(
            hash == format!("{:#x}", tx.hash()),
            "wallet.submission_hash_mismatch"
        );
        Ok(hash)
    }
    pub fn transaction_status(&self, hash: &str) -> Result<Value> {
        self.verify_network()?;
        self.call(false, "get_transaction", json!([hash]))
    }
    pub fn inspect_transaction(&self, hash: &str, owner: &packed::Script) -> Result<Value> {
        let _budget = Budget::start(&self.deadline);
        self.verify_network()?;
        self.transaction_effects(hash, owner)
    }
    fn transaction_effects(&self, hash: &str, owner: &packed::Script) -> Result<Value> {
        let mut response: Value = self.call(false, "get_transaction", json!([hash]))?;
        if response["transaction"].is_null() {
            return Ok(response);
        }
        let tx = checked_transaction(&response, hash)?;
        ensure!(
            tx.inputs().len() <= 64 && tx.outputs().len() <= 128,
            "wallet.history_shape_limit"
        );
        let mut prior = BTreeMap::new();
        let mut changes = BTreeMap::<String, (u128, u128)>::new();
        let mut total_in = 0u128;
        let mut total_out = 0u128;
        let mut cellbase = false;
        let mut unsupported = BTreeSet::new();
        for input in tx.inputs().into_iter() {
            let point = input.previous_output();
            if point.is_null() {
                cellbase = true;
                continue;
            }
            let previous_hash = format!("{:#x}", point.tx_hash());
            if !prior.contains_key(&previous_hash) {
                let value: Value = self.call(false, "get_transaction", json!([previous_hash]))?;
                prior.insert(
                    previous_hash.clone(),
                    checked_transaction(&value, &previous_hash)?,
                );
            }
            let previous = prior
                .get(&previous_hash)
                .ok_or_else(|| anyhow!("wallet.history_unavailable"))?;
            let index: u32 = point.index().unpack();
            let output = previous
                .outputs()
                .get(index as usize)
                .ok_or_else(|| anyhow!("wallet.history_unavailable"))?;
            let data = previous
                .outputs_data()
                .get(index as usize)
                .ok_or_else(|| anyhow!("wallet.history_unavailable"))?
                .raw_data();
            total_in = total_in
                .checked_add(Unpack::<u64>::unpack(&output.capacity()) as u128)
                .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
            account_effect(&output, &data, owner, false, &mut changes, &mut unsupported)?;
        }
        for (output, data) in tx.outputs().into_iter().zip(tx.outputs_data()) {
            total_out = total_out
                .checked_add(Unpack::<u64>::unpack(&output.capacity()) as u128)
                .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
            account_effect(
                &output,
                &data.raw_data(),
                owner,
                true,
                &mut changes,
                &mut unsupported,
            )?;
        }
        let mut effects = Vec::new();
        for (asset, (debit, credit)) in changes {
            if !unsupported.contains(&asset) && debit != credit {
                effects.push(json!({"asset":asset,"direction":if credit > debit {"credit"} else {"debit"},"amount":credit.abs_diff(debit).to_string()}));
            }
        }
        response["wallet_changes"] = json!(effects);
        response["wallet_unsupported_assets"] = json!(unsupported);
        // Header-dependent capacity (notably DAO withdrawals) needs specialized fee accounting.
        // Preserve exact wallet deltas without mislabeling a raw capacity difference as its fee.
        response["wallet_fee"] = if cellbase || !tx.header_deps().is_empty() {
            Value::Null
        } else {
            total_in
                .checked_sub(total_out)
                .map_or(Value::Null, |fee| json!(fee.to_string()))
        };
        Ok(response)
    }
    pub fn history(&self, owner: &packed::Script, cursor: Option<&str>) -> Result<Value> {
        let _budget = Budget::start(&self.deadline);
        self.verify_network()?;
        let tip: Tip = self.call(true, "get_indexer_tip", json!([]))?;
        let canonical: String = self.call(false, "get_block_hash", json!([tip.block_number]))?;
        ensure!(
            canonical == format!("{:#x}", tip.block_hash),
            "wallet.indexer_fork"
        );
        let mut page: Value = self.call(true,"get_transactions",json!([{"script":json::Script::from(owner.clone()),"script_type":"lock","script_search_mode":"exact","group_by_transaction":true},"desc","0xa",cursor]))?;
        let rows = page["objects"]
            .as_array_mut()
            .ok_or_else(|| anyhow!("wallet.rpc_invalid_response"))?;
        ensure!(rows.len() <= 10, "wallet.rpc_invalid_response");
        let has_more = rows.len() == 10;
        for row in rows {
            let hash = row["tx_hash"]
                .as_str()
                .ok_or_else(|| anyhow!("wallet.rpc_invalid_response"))?;
            let inspected = self.transaction_effects(hash, owner)?;
            row["wallet_changes"] = inspected["wallet_changes"].clone();
            row["wallet_fee"] = inspected["wallet_fee"].clone();
            row["wallet_unsupported_assets"] = inspected["wallet_unsupported_assets"].clone();
            row["tx_status"] = inspected["tx_status"].clone();
        }
        let end: Tip = self.call(true, "get_indexer_tip", json!([]))?;
        ensure!(
            tip.block_hash == end.block_hash && tip.block_number == end.block_number,
            "wallet.indexer_changed"
        );
        let canonical: String = self.call(false, "get_block_hash", json!([tip.block_number]))?;
        ensure!(
            canonical == format!("{:#x}", tip.block_hash),
            "wallet.indexer_fork"
        );
        ensure!(
            !has_more
                || page["last_cursor"]
                    .as_str()
                    .is_some_and(|next| !next.is_empty() && Some(next) != cursor),
            "wallet.rpc_invalid_response"
        );
        page["has_more"] = json!(has_more);
        Ok(page)
    }
    fn secp_dep(&self) -> Result<packed::CellDep> {
        let genesis: json::BlockView = self.call(false, "get_block_by_number", json!(["0x0"]))?;
        ensure!(
            format!("{:#x}", genesis.header.hash) == self.config.genesis_hash,
            "wallet.network_changed"
        );
        let mut code = None;
        for tx in &genesis.transactions {
            for (i, o) in tx.inner.outputs.iter().enumerate() {
                let output: packed::CellOutput = o.clone().into();
                if output.type_().to_opt().is_some_and(|t| {
                    format!("{:#x}", t.calc_script_hash())
                        == morph_packages::multi_asset_funding::SECP_TYPE_HASH
                }) {
                    code = Some(packed::OutPoint::new(tx.hash.pack(), i as u32));
                }
            }
        }
        let code = code.ok_or_else(|| anyhow!("wallet.secp_dependency_missing"))?;
        for tx in &genesis.transactions {
            for (i, data) in tx.inner.outputs_data.iter().enumerate() {
                if let Ok(points) = packed::OutPointVec::from_slice(&data.clone().into_bytes())
                    && points.into_iter().any(|p| p == code)
                {
                    return Ok(packed::CellDep::new_builder()
                        .out_point(packed::OutPoint::new(tx.hash.pack(), i as u32))
                        .dep_type(1u8)
                        .build());
                }
            }
        }
        Err(anyhow!("wallet.secp_dependency_missing"))
    }
}
fn checked_transaction(response: &Value, hash: &str) -> Result<TransactionView> {
    let transaction: json::TransactionView =
        serde_json::from_value(response["transaction"].clone())
            .map_err(|_| anyhow!("wallet.history_unavailable"))?;
    let data: packed::Transaction = transaction.inner.into();
    let tx = data.into_view();
    ensure!(
        format!("{:#x}", tx.hash()) == hash && tx.outputs().len() == tx.outputs_data().len(),
        "wallet.rpc_invalid_response"
    );
    Ok(tx)
}
fn account_effect(
    output: &packed::CellOutput,
    data: &[u8],
    owner: &packed::Script,
    credit: bool,
    totals: &mut BTreeMap<String, (u128, u128)>,
    unsupported: &mut BTreeSet<String>,
) -> Result<()> {
    if output.lock() != *owner {
        return Ok(());
    }
    let mut values = vec![(
        "CKB".to_owned(),
        Unpack::<u64>::unpack(&output.capacity()) as u128,
    )];
    if let Some(script) = output.type_().to_opt() {
        let hash = format!("{:#x}", script.calc_script_hash());
        if data.len() == 16 {
            values.push((hash, u128::from_le_bytes(data.try_into()?)));
        } else {
            unsupported.insert(hash);
        }
    }
    for (asset, amount) in values {
        let entry = totals.entry(asset).or_default();
        let total = if credit { &mut entry.1 } else { &mut entry.0 };
        *total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow!("wallet.amount_overflow"))?;
    }
    Ok(())
}
fn parse_hex_u64(value: &Value) -> Result<u64> {
    Ok(u64::from_str_radix(
        value
            .as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or_else(|| anyhow!("wallet.rpc_invalid_response"))?,
        16,
    )?)
}
fn epoch_mature(origin: u64, tip: u64, maturity: u64) -> Result<bool> {
    fn parts(v: u64) -> Result<(u64, u64, u64)> {
        let number = v & 0xffffff;
        let index = (v >> 24) & 0xffff;
        let length = (v >> 40) & 0xffff;
        ensure!(
            v >> 56 == 0 && length > 0 && index < length,
            "wallet.invalid_epoch"
        );
        Ok((number, index, length))
    }
    let (on, oi, ol) = parts(origin)?;
    let (tn, ti, tl) = parts(tip)?;
    // Consensus maturity is currently an integer number of epochs. Unknown fractional policies
    // fail closed until implemented instead of rounding the maturity downward.
    let (mn, mi, _) = if maturity == 0 {
        (0, 0, 1)
    } else {
        parts(maturity)?
    };
    ensure!(mi == 0, "wallet.unsupported_maturity");
    let mature_number = on
        .checked_add(mn)
        .ok_or_else(|| anyhow!("wallet.invalid_epoch"))?;
    Ok(tn > mature_number || (tn == mature_number && ti * ol >= oi * tl))
}
struct Budget<'a>(&'a std::cell::Cell<Option<Instant>>);
impl<'a> Budget<'a> {
    fn start(cell: &'a std::cell::Cell<Option<Instant>>) -> Self {
        cell.set(Some(Instant::now() + Duration::from_secs(30)));
        Self(cell)
    }
}
impl Drop for Budget<'_> {
    fn drop(&mut self) {
        self.0.set(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_uses_net_owned_changes_and_never_merges_asset_types() {
        use ckb_types::bytes::Bytes;
        let owner = packed::Script::new_builder()
            .args(Bytes::from(vec![1]).pack())
            .build();
        let foreign = packed::Script::new_builder()
            .args(Bytes::from(vec![2]).pack())
            .build();
        let token = packed::Script::new_builder()
            .args(Bytes::from(vec![3]).pack())
            .build();
        let hash = format!("{:#x}", token.calc_script_hash());
        let cell = |lock, cap| {
            packed::CellOutput::new_builder()
                .lock(lock)
                .capacity(cap)
                .type_(Some(token.clone()).pack())
                .build()
        };
        let mut totals = BTreeMap::new();
        let mut unsupported = BTreeSet::new();
        account_effect(
            &cell(owner.clone(), 200u64),
            &100u128.to_le_bytes(),
            &owner,
            false,
            &mut totals,
            &mut unsupported,
        )
        .unwrap();
        account_effect(
            &cell(owner.clone(), 90u64),
            &40u128.to_le_bytes(),
            &owner,
            true,
            &mut totals,
            &mut unsupported,
        )
        .unwrap();
        account_effect(
            &cell(foreign, 110u64),
            &60u128.to_le_bytes(),
            &owner,
            true,
            &mut totals,
            &mut unsupported,
        )
        .unwrap();
        assert_eq!(totals["CKB"], (200, 90));
        assert_eq!(totals[&hash], (100, 40));
        assert_eq!(totals.len(), 2);
        account_effect(
            &cell(owner.clone(), 1u64),
            &[0; 8],
            &owner,
            true,
            &mut totals,
            &mut unsupported,
        )
        .unwrap();
        assert!(
            unsupported.contains(&hash),
            "unsupported data must suppress a partial token total"
        );
        assert!(
            account_effect(
                &cell(owner.clone(), 1u64),
                &u128::MAX.to_le_bytes(),
                &owner,
                true,
                &mut totals,
                &mut unsupported
            )
            .is_err()
        );
    }
    fn epoch(n: u64, i: u64, l: u64) -> u64 {
        n | (i << 24) | (l << 40)
    }
    #[test]
    fn public_networks_cannot_be_mislabeled_as_development() {
        assert!(network_matches(Network::Mainnet, MAINNET_GENESIS));
        assert!(network_matches(Network::Testnet, TESTNET_GENESIS));
        assert!(!network_matches(Network::Devnet, MAINNET_GENESIS));
        assert!(!network_matches(Network::Devnet, TESTNET_GENESIS));
        assert!(!network_matches(Network::Testnet, MAINNET_GENESIS));
        assert!(network_matches(
            Network::Devnet,
            &format!("0x{}", "11".repeat(32))
        ));
    }
    #[test]
    fn maturity_compares_epoch_fractions_without_rounding() {
        assert!(!epoch_mature(epoch(10, 2, 10), epoch(14, 1, 10), epoch(4, 0, 1)).unwrap());
        assert!(epoch_mature(epoch(10, 2, 10), epoch(14, 2, 10), epoch(4, 0, 1)).unwrap());
        assert!(!epoch_mature(epoch(10, 2, 10), epoch(14, 1, 20), epoch(4, 0, 1)).unwrap());
        assert!(epoch_mature(epoch(10, 2, 10), epoch(15, 0, 10), epoch(4, 0, 1)).unwrap());
        assert!(epoch_mature(epoch(10, 2, 10), epoch(10, 2, 10), 0).unwrap());
        assert!(epoch_mature(epoch(10, 2, 0), epoch(14, 2, 10), epoch(4, 0, 1)).is_err());
    }
}
