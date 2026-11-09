//! Native cross-stack regressions. Fixtures contain data and a closed vocabulary,
//! never a general-purpose script. An unknown action, assertion or suite fails closed.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::Path, time::Duration};
use zeroize::{Zeroize, Zeroizing};

const MAX_RPC_BYTES: usize = 8 * 1024 * 1024;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    schema: String,
    suite: String,
    steps: Vec<Step>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    id: String,
    source_sha256: String,
    source_script_sha256: String,
    sequence: u32,
    endpoint: String,
    request: Value,
    before: Vec<Action>,
    captures: Vec<Capture>,
    checks: Vec<Check>,
    after: Vec<Action>,
    #[serde(default = "one")]
    repeat: u32,
    poll: Option<Poll>,
}
fn one() -> u32 {
    1
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    variable: String,
    value: Operand,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Operand {
    Pointer { pointer: String },
    Variable { variable: String },
    Literal { literal: Value },
    Difference { difference: Box<[Operand; 2]> },
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    left: Operand,
    op: Comparison,
    right: Option<Operand>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Comparison {
    Array,
    Eq,
    Ne,
    Lt,
    Gt,
    Exists,
    Absent,
    Null,
    Length,
    Contains,
    NotContains,
    AnyContains,
    OptionalContains,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Delay {
        milliseconds: u64,
    },
    Expiry {
        seconds: u64,
    },
    Random {
        variable: String,
    },
    Inject {
        pointer: String,
        variable: String,
    },
    CaptureRequest {
        pointer: String,
        variable: String,
    },
    InvoiceUdt,
    BothReady {
        variable: String,
    },
    ExternalEconomics {
        step: u8,
    },
    ExpiredTlcs {
        channel: String,
        tlc: String,
        local: String,
        remote: String,
        peer_endpoint: String,
    },
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    kind: PollKind,
    variable: Option<String>,
    expected: Option<String>,
    attempts: u32,
    mine: bool,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PollKind {
    ChannelReady,
    ChannelClosed,
    Status,
    Checks,
}
#[derive(Debug, Serialize)]
struct Evidence {
    id: String,
    source_sha256: String,
    source_script_sha256: String,
    method: String,
    status: &'static str,
    assertions: usize,
    rpc_attempts: u32,
    facts: Value,
}

struct Runner {
    client: reqwest::Client,
    variables: BTreeMap<String, Value>,
    external_key: Option<morph_key_input::SecretString>,
    peer_facts: Vec<Value>,
}
fn environment(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}
fn integer(value: &Value) -> Result<i128> {
    if let Some(n) = value.as_i64() {
        return Ok(n.into());
    }
    if let Some(n) = value.as_u64() {
        return Ok(n.into());
    }
    let s = value.as_str().context("expected an exact integer string")?;
    Ok(if let Some(s) = s.strip_prefix("0x") {
        i128::from_str_radix(s, 16)?
    } else {
        s.parse()?
    })
}
fn field(value: &Value, pointer: &str) -> Option<Value> {
    if let Some(p) = pointer.strip_suffix("/length") {
        return value
            .pointer(p)
            .and_then(Value::as_array)
            .map(|a| json!(a.len()));
    }
    value.pointer(pointer).cloned()
}
fn public_facts(response: &Value) -> Value {
    let result = &response["result"];
    let mut facts = json!({"rpc_result_present":response.get("result").is_some()});
    for key in [
        "capacity",
        "status",
        "payment_hash",
        "channel_id",
        "funding_tx_hash",
        "failed_error",
    ] {
        if result[key].is_string() {
            facts[key] = result[key].clone();
        }
    }
    if let Some(channels) = result["channels"].as_array() {
        facts["channels"]=Value::Array(channels.iter().map(|c| {
            let mut fields=serde_json::Map::new();
            for key in ["channel_id","state","local_balance","remote_balance","offered_tlc_balance","received_tlc_balance","shutdown_transaction_hash"] {
                if let Some(v)=c.get(key){fields.insert(key.into(),v.clone());}
            }
            if let Some(tlcs)=c["pending_tlcs"].as_array(){fields.insert("pending_tlcs".into(),Value::Array(tlcs.iter().map(|t|json!({"id":t["id"],"status":t["status"],"expiry":t["expiry"]})).collect()));}
            Value::Object(fields)
        }).collect());
    }
    if let Some(outputs) = result["transaction"]["outputs"].as_array() {
        facts["shutdown_outputs"] = json!(
            outputs
                .iter()
                .map(|o| json!({"capacity":o["capacity"],"lock":o["lock"]}))
                .collect::<Vec<_>>()
        );
    }
    facts
}

fn expired_channel(c: &Value, tlc: &Value, local: &Value, remote: &Value) -> Result<()> {
    ensure!(
        c["state"]["state_name"] == "ChannelReady",
        "expiry cleanup must preserve the healthy channel"
    );
    ensure!(
        integer(&c["local_balance"])? == integer(local)?
            && integer(&c["remote_balance"])? == integer(remote)?,
        "failed expired TLC changed business balances"
    );
    ensure!(
        integer(&c["offered_tlc_balance"])? == 0 && integer(&c["received_tlc_balance"])? == 0,
        "expired TLC still locks spendable value"
    );
    let pending = c["pending_tlcs"]
        .as_array()
        .context("missing explicit TLC status evidence")?;
    ensure!(
        pending.len() <= 1,
        "unexpected additional TLC in expiry-only scenario"
    );
    for item in pending {
        ensure!(
            item["id"] == *tlc,
            "expiry evidence refers to a different TLC"
        );
        // Fiber retains failed-removal bookkeeping in all_tlcs(), which backs
        // this RPC list. These are exactly is_fail_remove_confirmed statuses;
        // zero in-flight balances above distinguish failure from fulfillment.
        let status = &item["status"];
        ensure!(
            matches!(
                status["Outbound"].as_str(),
                Some("RemoveWaitAck" | "RemoveAckConfirmed")
            ) || status["Inbound"] == "RemoveAckConfirmed",
            "expired TLC has not reached confirmed failed removal: {status}"
        );
    }
    Ok(())
}

impl Runner {
    fn new(external_key: Option<morph_key_input::SecretString>) -> Result<Self> {
        for raw in [
            "EXTERNAL_FUNDING_PRIVKEY",
            "MORPH_FIBER_EXTERNAL_PRIVATE_KEY",
        ] {
            ensure!(
                std::env::var_os(raw).is_none(),
                "raw private-key input is retired"
            );
        }
        let mut variables = BTreeMap::new();
        for (name, fallback) in [
            ("NODE1_RPC_URL", "http://127.0.0.1:21714"),
            ("NODE2_RPC_URL", "http://127.0.0.1:21715"),
            ("NODE3_RPC_URL", "http://127.0.0.1:21716"),
            ("CKB_RPC_URL", "http://127.0.0.1:8114"),
            (
                "NODE1_ADDR",
                "/ip4/127.0.0.1/tcp/8344/p2p/QmbvRjJHAQDmj3cgnUBGQ5zVnGxUKwb2qJygwNs2wk41h8",
            ),
            (
                "NODE2_ADDR",
                "/ip4/127.0.0.1/tcp/8345/p2p/QmSRcPqUn4aQrKHXyCDjGn2qBVf43tWBDS2Wj9QDUZXtZp",
            ),
            (
                "NODE3_ADDR",
                "/ip4/127.0.0.1/tcp/8346/p2p/QmaFDJb9CkMrXy7nhTWBY5y9mvuykre3EzzRsCJUAVXprZ",
            ),
            (
                "NODE1_PUBKEY",
                "02a64b8993f33b2ebd37a4de1c9441f491291a4e779da8e519bcfb7c1f3f56c9c0",
            ),
            (
                "NODE2_PUBKEY",
                "02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6",
            ),
            (
                "NODE3_PUBKEY",
                "03032b99943822e721a651c5a5b9621043017daa9dc3ec81d83215fd2e25121187",
            ),
            (
                "UDT_CODE_HASH",
                "0xe1e354d6d643ad42724d40967e334984534e0367405c5ae42a9d7d63d77df419",
            ),
        ] {
            variables.insert(
                name.into(),
                json!(environment(&format!("FIBER_{name}"), fallback)),
            );
        }
        for name in [
            "NODE1_RPC_URL",
            "NODE2_RPC_URL",
            "NODE3_RPC_URL",
            "CKB_RPC_URL",
        ] {
            let url = reqwest::Url::parse(
                variables[name]
                    .as_str()
                    .context("RPC URL must be a string")?,
            )?;
            ensure!(
                url.scheme() == "http"
                    && matches!(
                        url.host_str(),
                        Some("127.0.0.1" | "[::1]" | "::1" | "localhost")
                    )
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "Fiber test RPCs must be explicit unauthenticated loopback endpoints"
            );
        }
        Ok(Self {
            variables,
            external_key,
            peer_facts: Vec::new(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
        })
    }
    fn variable(&self, key: &str) -> Result<Value> {
        self.variables
            .get(key)
            .cloned()
            .with_context(|| format!("missing native scenario variable {key}"))
    }
    fn operand(&self, operand: &Operand, response: &Value) -> Result<Option<Value>> {
        Ok(match operand {
            Operand::Pointer { pointer } => field(response, pointer),
            Operand::Variable { variable } => Some(self.variable(variable)?),
            Operand::Literal { literal } => Some(self.substitute(literal)?),
            Operand::Difference { difference } => {
                let a = self
                    .operand(&difference[0], response)?
                    .context("missing minuend")?;
                let b = self
                    .operand(&difference[1], response)?
                    .context("missing subtrahend")?;
                Some(json!(
                    integer(&a)?
                        .checked_sub(integer(&b)?)
                        .context("integer delta overflow")?
                        .to_string()
                ))
            }
        })
    }
    fn substitute(&self, value: &Value) -> Result<Value> {
        Ok(match value {
            Value::String(s) if s.starts_with("{{") && s.ends_with("}}") => {
                self.variable(&s[2..s.len() - 2])?
            }
            Value::String(s) => {
                ensure!(
                    !s.contains("{{"),
                    "partial placeholder is not a supported request encoding"
                );
                value.clone()
            }
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| self.substitute(v))
                    .collect::<Result<_>>()?,
            ),
            Value::Object(items) => Value::Object(
                items
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), self.substitute(v)?)))
                    .collect::<Result<_>>()?,
            ),
            _ => value.clone(),
        })
    }
    fn check(&self, check: &Check, response: &Value) -> Result<()> {
        let a = self.operand(&check.left, response)?;
        let b = check
            .right
            .as_ref()
            .map(|v| self.operand(v, response))
            .transpose()?
            .flatten();
        let good = match check.op {
            Comparison::Array => a.as_ref().is_some_and(Value::is_array),
            Comparison::Exists => a.is_some(),
            Comparison::Absent => a.is_none(),
            Comparison::Null => a == Some(Value::Null),
            Comparison::Eq => a.is_some() && a == b,
            Comparison::Ne => a.is_some() && a != b,
            Comparison::Lt | Comparison::Gt => {
                let a = integer(a.as_ref().context("missing integer operand")?)?;
                let b = integer(b.as_ref().context("missing comparison bound")?)?;
                if matches!(check.op, Comparison::Lt) {
                    a < b
                } else {
                    a > b
                }
            }
            Comparison::Length => a
                .as_ref()
                .and_then(Value::as_array)
                .is_some_and(|a| b.as_ref().and_then(Value::as_u64) == Some(a.len() as u64)),
            Comparison::OptionalContains if a.is_none() => true,
            Comparison::Contains | Comparison::OptionalContains | Comparison::NotContains => {
                let a = a
                    .as_ref()
                    .and_then(Value::as_str)
                    .context("missing string for containment check")?;
                let b = b
                    .as_ref()
                    .and_then(Value::as_str)
                    .context("missing containment pattern")?;
                if matches!(check.op, Comparison::NotContains) {
                    !a.contains(b)
                } else {
                    a.contains(b)
                }
            }
            Comparison::AnyContains => {
                let a = a
                    .as_ref()
                    .and_then(Value::as_str)
                    .context("missing error text")?;
                b.as_ref()
                    .and_then(Value::as_array)
                    .context("missing allowed errors")?
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| a.contains(s)))
            }
        };
        // Diagnostics name the boundary, not a possibly sensitive response/request body.
        ensure!(good, "native assertion failed: {check:?}");
        Ok(())
    }
    async fn rpc(&self, endpoint: &str, mut request: Value) -> Result<Value> {
        let url = self.variable(endpoint)?;
        let mut secret = false;
        if request.pointer("/params/0/private_key").is_some() {
            let key = self
                .external_key
                .as_ref()
                .context("external funding signing needs --external-private-key-file")?;
            request["params"][0]["private_key"] =
                json!(format!("0x{}", key.trim_start_matches("0x")));
            secret = true;
        }
        let body = Zeroizing::new(serde_json::to_string(&request)?);
        if secret && let Some(Value::String(s)) = request.pointer_mut("/params/0/private_key") {
            s.zeroize();
        }
        let mut response = self.client.post(url.as_str().context("invalid endpoint")?).header("content-type", "application/json")
            .body(body.as_bytes().to_vec()).send().await.map_err(|_| anyhow::anyhow!("Fiber RPC transport failed; mutation outcome may be unknown; no automatic retry"))?;
        ensure!(
            response.status().is_success(),
            "Fiber RPC HTTP status {}",
            response.status()
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_RPC_BYTES as u64),
            "Fiber RPC response exceeds bound"
        );
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= MAX_RPC_BYTES,
                "Fiber RPC response exceeds bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        let mut result: Value =
            serde_json::from_slice(&bytes).context("Fiber RPC returned invalid JSON")?;
        ensure!(result.is_object(), "Fiber RPC returned a non-object");
        result["@http_status"] = json!(status);
        Ok(result)
    }
    async fn mine(&self) -> Result<()> {
        let result = self
            .rpc(
                "CKB_RPC_URL",
                json!({"id":42,"jsonrpc":"2.0","method":"generate_epochs","params":["0x1"]}),
            )
            .await?;
        ensure!(
            result.get("error").is_none(),
            "development epoch generation failed"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(())
    }
    fn channel_state<'a>(&self, response: &'a Value, variable: &str) -> Result<&'a Value> {
        let id = self.variable(variable)?;
        response["result"]["channels"]
            .as_array()
            .context("missing channel list")?
            .iter()
            .find(|c| c["channel_id"] == id)
            .context("expected channel missing from RPC")
    }
    async fn before(&mut self, action: &Action, request: &mut Value) -> Result<()> {
        match action {
            Action::Delay { milliseconds } => {
                tokio::time::sleep(Duration::from_millis(*milliseconds)).await
            }
            Action::Random { variable } => {
                let mut bytes = [0u8; 32];
                std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
                self.variables
                    .insert(variable.clone(), json!(format!("0x{}", hex::encode(bytes))));
            }
            Action::Expiry { seconds } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis();
                self.variables.insert(
                    "expiry".into(),
                    json!(format!("0x{:x}", now + u128::from(*seconds) * 1000)),
                );
            }
            Action::Inject { pointer, variable } => {
                let value = self.variable(variable)?;
                // These named fields may be absent in the original request skeleton.
                let key = pointer
                    .strip_prefix("/params/0/")
                    .context("unsupported injection location")?;
                request["params"][0]
                    .as_object_mut()
                    .context("request has no parameter object")?
                    .insert(key.into(), value);
            }
            Action::CaptureRequest { pointer, variable } => {
                self.variables.insert(
                    variable.clone(),
                    request
                        .pointer(pointer)
                        .context("missing request field")?
                        .clone(),
                );
            }
            _ => bail!("response-only action in preconditions"),
        };
        Ok(())
    }
    async fn after(&mut self, action: &Action, response: &Value) -> Result<()> {
        match action {
            Action::Delay { milliseconds } => {
                tokio::time::sleep(Duration::from_millis(*milliseconds)).await
            }
            Action::InvoiceUdt => ensure!(
                response["result"]["invoice"]["data"]["attrs"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v.get("udt_script").is_some())),
                "invoice lost UDT type binding"
            ),
            Action::BothReady { variable } => {
                let mut ready = false;
                for _ in 0..90 {
                    let mut all = true;
                    for endpoint in ["NODE1_RPC_URL", "NODE2_RPC_URL"] {
                        let r=self.rpc(endpoint,json!({"id":42,"jsonrpc":"2.0","method":"list_channels","params":[{}]})).await?;
                        all &= self
                            .channel_state(&r, variable)
                            .is_ok_and(|c| c["state"]["state_name"] == "ChannelReady");
                    }
                    if all {
                        ready = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                ensure!(ready, "both peers did not reach ChannelReady");
            }
            Action::ExternalEconomics { step } => self.external_economics(*step, response)?,
            Action::ExpiredTlcs {
                channel,
                tlc,
                local,
                remote,
                peer_endpoint,
            } => {
                let id = self.variable(channel)?;
                let tlc = self.variable(tlc)?;
                let local = self.variable(local)?;
                let remote = self.variable(remote)?;
                let find = |response: &Value| -> Result<Value> {
                    let channels = response["result"]["channels"]
                        .as_array()
                        .context("missing channel list")?;
                    let matching = channels
                        .iter()
                        .filter(|c| c["channel_id"] == id)
                        .collect::<Vec<_>>();
                    ensure!(
                        matching.len() == 1,
                        "expiry cleanup lost/duplicated the tested channel"
                    );
                    Ok(matching[0].clone())
                };
                expired_channel(&find(response)?, &tlc, &local, &remote)?;
                let peer = self
                    .rpc(
                        peer_endpoint,
                        json!({"id":42,"jsonrpc":"2.0","method":"list_channels","params":[{}]}),
                    )
                    .await?;
                ensure!(
                    peer.get("error").is_none(),
                    "expiry peer observation failed"
                );
                expired_channel(&find(&peer)?, &tlc, &remote, &local)?;
                self.peer_facts =
                    vec![json!({"endpoint":peer_endpoint,"observation":public_facts(&peer)})];
            }
            _ => bail!("request-only action in response checks"),
        };
        Ok(())
    }
    fn external_economics(&mut self, step: u8, response: &Value) -> Result<()> {
        let n = |key: &str| -> Result<i128> { integer(&self.variable(key)?) };
        if step == 19 {
            let funding = n("EXTERNAL_FUNDING_AMOUNT")?;
            let lock = self.variable("NODE2_FUNDING_SCRIPT")?;
            let outputs = response["result"]["transaction"]["outputs"]
                .as_array()
                .context("shutdown tx has no outputs")?;
            let refund = outputs.iter().filter(|o| o["lock"] == lock).try_fold(
                0i128,
                |sum, o| -> Result<i128> {
                    sum.checked_add(integer(&o["capacity"])?)
                        .context("refund overflow")
                },
            )?;
            let fee = funding.checked_sub(refund).context("refund underflow")?;
            ensure!(
                refund > 0 && refund < funding && fee > 0 && fee <= 100_000_000,
                "shutdown refund/fee violates exact funding bound"
            );
            self.variables.insert(
                "EXTERNAL_FUNDING_SHUTDOWN_REFUND".into(),
                json!(refund.to_string()),
            );
            self.variables.insert(
                "EXTERNAL_FUNDING_SHUTDOWN_FEE".into(),
                json!(fee.to_string()),
            );
            return Ok(());
        }
        let node = match step {
            13 | 20 => 1,
            14 | 21 => 2,
            15 | 22 => 3,
            _ => bail!("unknown economic check"),
        };
        let before = n(&format!("NODE{node}_BALANCE_BEFORE"))?;
        let current = integer(&response["result"]["capacity"])?;
        match step {
            13 | 20 => ensure!(before == current, "unfunded node1 balance changed"),
            14 => {
                let spent = before - current;
                let funding = n("EXTERNAL_FUNDING_AMOUNT")?;
                ensure!(
                    spent >= funding && spent <= funding + 100_000_000,
                    "external funder spend outside contribution + fee bound"
                );
            }
            15 => ensure!(
                (9_800_000_000..=10_000_000_000).contains(&(before - current)),
                "acceptor spend outside signed auto-accept amount range"
            ),
            21 => {
                let open = n("NODE2_BALANCE_AFTER")?;
                let refund = n("EXTERNAL_FUNDING_SHUTDOWN_REFUND")?;
                let funding = n("EXTERNAL_FUNDING_AMOUNT")?;
                let fee = n("EXTERNAL_FUNDING_SHUTDOWN_FEE")?;
                ensure!(
                    current < before
                        && current > open
                        && current - open == refund
                        && refund == funding - fee,
                    "external funder close delta differs from exact shutdown refund"
                );
            }
            22 => {
                let open = n("NODE3_BALANCE_AFTER")?;
                ensure!(
                    current > open && current - open < before - open && before > current,
                    "acceptor close refund/fee delta violates conservation"
                );
            }
            _ => bail!("unknown economic step"),
        }
        if (13..=15).contains(&step) {
            self.variables.insert(
                format!("NODE{node}_BALANCE_AFTER"),
                json!(current.to_string()),
            );
        }
        Ok(())
    }
    async fn execute(&mut self, step: &Step) -> Result<Evidence> {
        self.peer_facts.clear();
        ensure!(
            step.repeat <= 10 && step.repeat > 0,
            "invalid finite repetition"
        );
        if step.repeat > 1 {
            ensure!(
                step.request["method"] == "generate_block",
                "only explicit development block production may repeat"
            );
        }
        let mut request = step.request.clone();
        // Secret material is inserted only immediately before RPC encoding.
        if request.pointer("/params/0/private_key").is_some() {
            request["params"][0]["private_key"] = Value::Null;
        }
        for action in &step.before {
            self.before(action, &mut request).await?;
        }
        request = self.substitute(&request)?;
        let method = request["method"]
            .as_str()
            .context("missing RPC method")?
            .to_owned();
        let max = step.poll.as_ref().map_or(1, |p| p.attempts);
        ensure!((1..=90).contains(&max), "invalid poll bound");
        if step.poll.is_some() {
            ensure!(
                matches!(
                    method.as_str(),
                    "list_channels"
                        | "get_cells_capacity"
                        | "get_invoice"
                        | "get_payment"
                        | "get_transaction"
                ),
                "mutations cannot be polled/retried"
            );
        }
        let mut response = Value::Null;
        let mut attempts = 0;
        for attempt in 0..max {
            for _ in 0..step.repeat {
                response = self.rpc(&step.endpoint, request.clone()).await?;
                attempts += 1;
            }
            let result: Result<()> = async {
                if let Some(poll) = &step.poll {
                    match poll.kind {
                        PollKind::ChannelReady | PollKind::ChannelClosed => {
                            let c = self.channel_state(
                                &response,
                                poll.variable
                                    .as_deref()
                                    .context("missing channel identity")?,
                            )?;
                            let expected = if matches!(poll.kind, PollKind::ChannelReady) {
                                "ChannelReady"
                            } else {
                                "Closed"
                            };
                            ensure!(
                                c["state"]["state_name"] == expected,
                                "channel did not reach {expected}"
                            );
                            if matches!(poll.kind, PollKind::ChannelClosed) {
                                let hash = c["shutdown_transaction_hash"]
                                    .as_str()
                                    .context("closed channel has no shutdown tx")?
                                    .to_owned();
                                self.variables.insert(
                                    "EXTERNAL_FUNDING_SHUTDOWN_TX_HASH".into(),
                                    json!(hash),
                                );
                            }
                        }
                        PollKind::Status => ensure!(
                            response["result"]["status"]
                                == poll
                                    .expected
                                    .as_deref()
                                    .context("missing expected status")?,
                            "invoice/payment not yet terminal"
                        ),
                        PollKind::Checks => {}
                    }
                }
                for check in &step.checks {
                    self.check(check, &response)?;
                }
                // Poll semantic/economic checks, never a mutation or a delayed UI action.
                for action in &step.after {
                    if matches!(
                        action,
                        Action::ExternalEconomics { .. } | Action::ExpiredTlcs { .. }
                    ) {
                        self.after(action, &response).await?;
                    }
                }
                Ok(())
            }
            .await;
            if result.is_ok() {
                break;
            }
            if attempt + 1 == max {
                return Err(result.err().context("lost assertion error")?);
            }
            if step.poll.as_ref().is_some_and(|p| p.mine) {
                self.mine().await?;
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        for c in &step.captures {
            let value = self
                .operand(&c.value, &response)?
                .context("missing captured public field")?;
            self.variables.insert(c.variable.clone(), value);
        }
        for action in &step.after {
            if !matches!(
                action,
                Action::ExternalEconomics { .. } | Action::ExpiredTlcs { .. }
            ) {
                self.after(action, &response).await?;
            }
        }
        Ok(Evidence {
            id: step.id.clone(),
            source_sha256: step.source_sha256.clone(),
            source_script_sha256: step.source_script_sha256.clone(),
            method,
            status: "passed",
            assertions: step.checks.len()
                + step
                    .after
                    .iter()
                    .filter(|a| !matches!(a, Action::Delay { .. }))
                    .count(),
            rpc_attempts: attempts,
            facts: json!({"main_request":public_facts(&response),"peers":self.peer_facts,"economic_variables":self.variables.iter().filter(|(k,_)|k.ends_with("_BALANCE")||k.ends_with("_BALANCE_AFTER")||k.ends_with("_BALANCE_BEFORE")||k.starts_with("EXTERNAL_FUNDING_SHUTDOWN_")&& (k.ends_with("REFUND")||k.ends_with("FEE"))||k.as_str()=="EXTERNAL_FUNDING_AMOUNT").collect::<BTreeMap<_,_>>()}),
        })
    }
}

fn load(path: &Path) -> Result<Scenario> {
    let value =
        morph_sdk::packages::multi_asset_packages::read_bounded_json(path, 4 * 1024 * 1024)?;
    let scenario: Scenario = serde_json::from_value(value)?;
    ensure!(
        scenario.schema == "morph.rust_fiber_scenario.v1" && !scenario.steps.is_empty(),
        "unknown/empty scenario"
    );
    let mut previous = 0;
    let mut ids = std::collections::BTreeSet::new();
    for step in &scenario.steps {
        ensure!(
            step.id.starts_with(&format!("{}/", scenario.suite)) && ids.insert(&step.id),
            "duplicate or unrelated step"
        );
        ensure!(step.sequence >= previous, "scenario ordering regressed");
        previous = step.sequence;
        ensure!(!step.checks.is_empty(), "step has no checks");
        for hash in [&step.source_sha256, &step.source_script_sha256] {
            ensure!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid source evidence digest"
            );
        }
    }
    Ok(scenario)
}
pub async fn run(
    path: &Path,
    external_key: Option<morph_key_input::SecretString>,
    output: &Path,
) -> Result<()> {
    let scenario = load(path)?;
    let mut runner = Runner::new(external_key)?;
    let mut evidence = Vec::new();
    for step in &scenario.steps {
        eprintln!("[rust-fiber] {}", step.id);
        evidence.push(
            runner
                .execute(step)
                .await
                .with_context(|| step.id.clone())?,
        );
    }
    let summary = json!({"schema":"morph.rust_fiber_result.v1","suite":scenario.suite,"status":"passed","runner":"rust","steps":evidence,"secrets_recorded":false});
    morph_sdk::packages::persistence::write_private_immutable(
        output,
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

/// Restart only an exact node1 executable descended from the caller-owned test
/// stack. Never uses a global process-name/port kill. The replacement child is
/// reaped on every success/error path.
#[cfg(target_os = "linux")]
pub async fn restart(
    fiber_dir: &Path,
    stack_pid: u32,
    key: morph_key_input::SecretString,
    output: &Path,
    log: &Path,
) -> Result<()> {
    use std::{
        os::unix::fs::OpenOptionsExt,
        process::{Command, Stdio},
    };
    struct OwnedNode(std::process::Child);
    impl Drop for OwnedNode {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fiber_dir = fiber_dir.canonicalize()?;
    let binary = fiber_dir
        .join("target")
        .join(environment("FIBER_TEST_ENV", "debug"))
        .join("fnn")
        .canonicalize()?;
    let mut descendants = vec![stack_pid];
    let mut found = Vec::new();
    let mut cursor = 0;
    while cursor < descendants.len() {
        let pid = descendants[cursor];
        cursor += 1;
        ensure!(descendants.len() < 1024, "test process tree exceeds bound");
        if let Ok(children) = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
            for child in children.split_whitespace() {
                descendants.push(child.parse::<u32>()?);
            }
        }
        if pid == stack_pid {
            continue;
        }
        if std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| exe == binary) {
            let cmd = std::fs::read(format!("/proc/{pid}/cmdline"))?;
            let args = cmd.split(|b| *b == 0).collect::<Vec<_>>();
            if args
                .windows(2)
                .any(|pair| pair[0] == b"-d" && pair[1] == b"1")
            {
                found.push(pid);
            }
        }
    }
    ensure!(
        found.len() == 1,
        "owned stack must contain exactly one node1 process"
    );
    let mut r = Runner::new(Some(key))?;
    let peer = r.variable("NODE3_ADDR")?;
    let connected = r
        .rpc(
            "NODE1_RPC_URL",
            json!({"id":42,"jsonrpc":"2.0","method":"connect_peer","params":[{"address":peer}]}),
        )
        .await?;
    ensure!(
        connected.get("error").is_none()
            || connected["error"]["message"]
                .as_str()
                .is_some_and(|s| s.contains("Peer already connected")),
        "cannot connect external funding peers"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let info = r
        .rpc(
            "NODE2_RPC_URL",
            json!({"id":42,"jsonrpc":"2.0","method":"node_info","params":[]}),
        )
        .await?;
    let lock = info["result"]["default_funding_lock_script"].clone();
    ensure!(lock.is_object(), "missing external funder's lock");
    let opened=r.rpc("NODE1_RPC_URL",json!({"id":42,"jsonrpc":"2.0","method":"open_channel_with_external_funding","params":[{"pubkey":r.variable("NODE3_PUBKEY")?,"funding_amount":"0xba43b7400","public":true,"shutdown_script":lock,"funding_lock_script":lock}]})).await?;
    ensure!(
        opened.get("error").is_none(),
        "external funding open failed"
    );
    let id = opened["result"]["channel_id"]
        .as_str()
        .context("missing external channel id")?
        .to_owned();
    let unsigned = opened["result"]["unsigned_funding_tx"].clone();
    ensure!(
        unsigned["outputs"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "empty external funding tx"
    );
    let signed=r.rpc("NODE1_RPC_URL",json!({"id":42,"jsonrpc":"2.0","method":"sign_external_funding_tx","params":[{"unsigned_funding_tx":unsigned,"private_key":null}]})).await?;
    ensure!(
        signed.get("error").is_none(),
        "external funding signing failed"
    );
    let tx = signed["result"]["signed_funding_tx"].clone();
    ensure!(
        tx["witnesses"].is_array(),
        "missing external funding witnesses"
    );
    eprintln!("[rust-fiber-restart] opened and signed; stopping owned node1");
    // SAFETY: PID is the exact executable found in the caller-owned stack tree.
    ensure!(
        unsafe { libc::kill(i32::try_from(found[0])?, libc::SIGTERM) } == 0,
        "cannot stop owned node1"
    );
    for _ in 0..100 {
        if !Path::new(&format!("/proc/{}", found[0])).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ensure!(
        !Path::new(&format!("/proc/{}", found[0])).exists(),
        "owned node1 did not stop"
    );
    let logfile = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(log)?;
    let _node = OwnedNode(
        Command::new(&binary)
            .args(["-d", "1"])
            .current_dir(fiber_dir.join("tests/nodes"))
            .env("FIBER_SECRET_KEY_PASSWORD", "password1")
            .env("LOG_PREFIX", "[node 1 native restart]")
            .stdin(Stdio::null())
            .stdout(logfile.try_clone()?)
            .stderr(logfile)
            .spawn()?,
    );
    let mut ready = false;
    for _ in 0..180 {
        if r.rpc(
            "NODE1_RPC_URL",
            json!({"id":42,"jsonrpc":"2.0","method":"node_info","params":[]}),
        )
        .await
        .is_ok_and(|v| v.get("error").is_none())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ensure!(ready, "restarted owned node1 RPC did not become ready");
    let connected=r.rpc("NODE1_RPC_URL",json!({"id":42,"jsonrpc":"2.0","method":"connect_peer","params":[{"address":r.variable("NODE3_ADDR")?}]})).await?;
    ensure!(
        connected.get("error").is_none()
            || connected["error"]["message"]
                .as_str()
                .is_some_and(|s| s.contains("Peer already connected")),
        "restarted node did not reconnect"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let submitted=r.rpc("NODE1_RPC_URL",json!({"id":42,"jsonrpc":"2.0","method":"submit_signed_funding_tx","params":[{"channel_id":id,"signed_funding_tx":tx}]})).await?;
    ensure!(
        submitted.get("error").is_none() && submitted["result"]["funding_tx_hash"].is_string(),
        "persisted exact funding submission failed after restart"
    );
    r.variables.insert("RESTART_CHANNEL".into(), json!(id));
    let mut shutdown = Value::Null;
    for expected in ["ChannelReady", "Closed"] {
        let mut reached = false;
        for _ in 0..10 {
            let result=r.rpc("NODE3_RPC_URL",json!({"id":42,"jsonrpc":"2.0","method":"list_channels","params":[{"pubkey":r.variable("NODE1_PUBKEY")?,"include_closed":true}]})).await?;
            if let Ok(c) = r.channel_state(&result, "RESTART_CHANNEL")
                && c["state"]["state_name"] == expected
            {
                shutdown = c["shutdown_transaction_hash"].clone();
                reached = true;
                break;
            }
            r.mine().await?;
        }
        ensure!(
            reached,
            "restarted funding channel did not reach {expected}"
        );
        if expected == "ChannelReady" {
            let closed=r.rpc("NODE1_RPC_URL",json!({"id":42,"jsonrpc":"2.0","method":"shutdown_channel","params":[{"channel_id":id,"close_script":lock,"fee_rate":"0x3fc"}]})).await?;
            ensure!(
                closed.get("error").is_none(),
                "shutdown after persisted funding failed"
            );
        }
    }
    ensure!(
        shutdown.is_string(),
        "closed restarted channel lacks shutdown transaction"
    );
    let summary = json!({"schema":"morph.rust_fiber_restart.v1","suite":"e2e/external-funding-open/restart","status":"passed","runner":"rust","channel_id":id,"funding_tx_hash":submitted["result"]["funding_tx_hash"],"shutdown_tx_hash":shutdown,"checkpoints":["opening external-funded channel","restarting node1","submitting signed funding tx","waiting for Closed","success"],"secrets_recorded":false});
    morph_sdk::packages::persistence::write_private_immutable(
        output,
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

pub fn verify(scenario_path: &Path, evidence_path: &Path) -> Result<()> {
    let scenario = load(scenario_path)?;
    let value: Value = morph_sdk::packages::multi_asset_packages::read_bounded_json(
        evidence_path,
        4 * 1024 * 1024,
    )?;
    ensure!(
        value["schema"] == "morph.rust_fiber_result.v1"
            && value["suite"] == scenario.suite
            && value["runner"] == "rust"
            && value["status"] == "passed"
            && value["secrets_recorded"] == false,
        "invalid native result envelope"
    );
    let evidence = value["steps"]
        .as_array()
        .context("missing native step evidence")?;
    ensure!(
        evidence.len() == scenario.steps.len(),
        "native evidence omitted/added requests"
    );
    for (expected, actual) in scenario.steps.iter().zip(evidence) {
        let assertions = expected.checks.len()
            + expected
                .after
                .iter()
                .filter(|a| !matches!(a, Action::Delay { .. }))
                .count();
        ensure!(
            actual["id"] == expected.id
                && actual["source_sha256"] == expected.source_sha256
                && actual["source_script_sha256"] == expected.source_script_sha256
                && actual["method"] == expected.request["method"]
                && actual["status"] == "passed"
                && actual["assertions"] == assertions,
            "native evidence does not match the source-bound request/assertion ledger"
        );
        ensure!(
            actual["facts"].is_object(),
            "native evidence omitted public fact projections"
        );
        let attempts = actual["rpc_attempts"]
            .as_u64()
            .context("missing native attempt count")?;
        ensure!(
            attempts >= 1
                && attempts
                    <= u64::from(expected.repeat)
                        * u64::from(expected.poll.as_ref().map_or(1, |p| p.attempts)),
            "native evidence has an invalid RPC retry count"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_scenario_corpus_is_typed_complete_and_strictly_ordered() -> Result<()> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/fiber");
        let mut total = 0;
        let mut suites = 0;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json")
                && path.file_name().is_none_or(|s| s != "sources.json")
            {
                let scenario = load(&path)?;
                total += scenario.steps.len();
                suites += 1;
            }
        }
        assert_eq!(suites, 15);
        assert_eq!(total, 268);
        Ok(())
    }
    #[tokio::test]
    async fn writes_cannot_be_polled_and_unknown_actions_are_rejected() -> Result<()> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/fiber/router-pay.json");
        let mut document: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let index = document["steps"]
            .as_array()
            .unwrap()
            .iter()
            .position(|s| s["request"]["method"] == "send_payment")
            .unwrap();
        document["steps"][index]["poll"] = json!({"kind":"checks","attempts":2,"mine":false});
        document["steps"][index]["before"] = json!([]);
        document["steps"][index]["request"]["params"] = json!([]);
        let step: Step = serde_json::from_value(document["steps"][index].clone())?;
        assert!(
            Runner::new(None)?
                .execute(&step)
                .await
                .unwrap_err()
                .to_string()
                .contains("mutations cannot")
        );
        document["steps"][index]["before"] =
            json!([{"kind":"evaluate_script","source":"disabled"}]);
        assert!(serde_json::from_value::<Step>(document["steps"][index].clone()).is_err());
        Ok(())
    }
    #[test]
    fn retained_failed_tlc_is_not_confused_with_live_value_or_a_missing_channel() -> Result<()> {
        let mut c = json!({"state":{"state_name":"ChannelReady"},"local_balance":"0x100","remote_balance":"0x200","offered_tlc_balance":"0x0","received_tlc_balance":"0x0","pending_tlcs":[{"id":"0x0","status":{"Outbound":"RemoveWaitAck"}}]});
        let id = json!("0x0");
        let local = json!("0x100");
        let remote = json!("0x200");
        expired_channel(&c, &id, &local, &remote)?;
        c["pending_tlcs"][0]["status"] = json!({"Outbound":"Committed"});
        assert!(expired_channel(&c, &id, &local, &remote).is_err());
        c["pending_tlcs"][0]["status"] = json!({"Outbound":"RemoveWaitAck"});
        c["offered_tlc_balance"] = json!("0x1");
        assert!(expired_channel(&c, &id, &local, &remote).is_err());
        c["offered_tlc_balance"] = json!("0x0");
        c["local_balance"] = json!("0x101");
        assert!(expired_channel(&c, &id, &local, &remote).is_err());
        c["local_balance"] = local.clone();
        c["state"]["state_name"] = json!("Closed");
        assert!(expired_channel(&c, &id, &local, &remote).is_err());
        Ok(())
    }

    #[test]
    fn core_economic_assertions_reject_missing_and_wrong_precision_values() -> Result<()> {
        let r = Runner::new(None)?;
        let check: Check = serde_json::from_value(
            json!({"left":{"pointer":"/result/amount"},"op":"gt","right":{"literal":"9007199254740992"}}),
        )?;
        assert!(
            r.check(&check, &json!({"result":{"amount":"9007199254740993"}}))
                .is_ok()
        );
        assert!(
            r.check(&check, &json!({"result":{"amount":"9007199254740992"}}))
                .is_err()
        );
        assert!(r.check(&check, &json!({"result":{}})).is_err());
        Ok(())
    }

    #[test]
    fn economic_checks_keep_integer_precision_and_reject_the_wrong_refund() -> Result<()> {
        let mut r = Runner::new(None)?;
        r.variables.insert(
            "NODE2_FUNDING_SCRIPT".into(),
            json!({"args":"0x01","code_hash":"0x02","hash_type":"type"}),
        );
        r.variables
            .insert("EXTERNAL_FUNDING_AMOUNT".into(), json!("9007199254740999"));
        let lock = r.variable("NODE2_FUNDING_SCRIPT")?;
        let response = json!({"result":{"transaction":{"outputs":[{"lock":lock,"capacity":"9007199254740000"}]}}});
        r.external_economics(19, &response)?;
        assert_eq!(r.variable("EXTERNAL_FUNDING_SHUTDOWN_FEE")?, json!("999"));
        let mut wrong = response;
        wrong["result"]["transaction"]["outputs"][0]["capacity"] = json!("9007199254741000");
        assert!(r.external_economics(19, &wrong).is_err());
        Ok(())
    }
}
