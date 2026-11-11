//! Real transactions on a disposable, pinned development chain. Not a wallet product mode.
use anyhow::{Result, bail, ensure};
use morph_wallet::{
    address::Network,
    rpc::Chain,
    service::{Settings, Wallet},
};
use serde_json::{Value, json};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration};
const GENESIS: &str = "0x64fbe7063a6371844e4a9e92229dae08d3f2b6ae30660b66be9dbdaf14c5dd1a";
const PASSWORD: &str = "morph showcase development only";
fn call(url: &str, method: &str, params: Value) -> Result<Value> {
    let reply: Value = reqwest::blocking::Client::new()
        .post(url)
        .timeout(Duration::from_secs(12))
        .json(&json!({"id":1,"jsonrpc":"2.0","method":method,"params":params}))
        .send()?
        .error_for_status()?
        .json()?;
    ensure!(reply.get("error").is_none(), "{method}: {reply}");
    Ok(reply["result"].clone())
}
fn mine(url: &str, wallet: &mut Wallet, hash: &str) -> Result<()> {
    for _ in 0..16 {
        call(url, "generate_block", json!([]))?;
        std::thread::sleep(Duration::from_millis(250));
        if wallet.status(hash)?["tx_status"]["status"] == "committed" {
            return Ok(());
        }
    }
    bail!("development transaction did not commit: {hash}")
}
fn refresh(wallet: &mut Wallet, minimum: u128) -> Result<()> {
    for _ in 0..30 {
        if wallet.refresh().is_ok_and(|view| {
            view.balance.is_some_and(|b| {
                b.available_plain_capacity
                    .parse::<u128>()
                    .is_ok_and(|value| value >= minimum)
            })
        }) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("development indexer did not catch up")
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: native_showcase NEW_DIRECTORY http://127.0.0.1:PORT"
    );
    let root = PathBuf::from(&args[0]);
    let url = &args[1];
    let parsed = reqwest::Url::parse(url)?;
    ensure!(
        parsed.scheme() == "http"
            && parsed.host_str() == Some("127.0.0.1")
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "showcase requires loopback RPC"
    );
    ensure!(
        call(url, "get_block_hash", json!(["0x0"]))? == GENESIS,
        "not the pinned development chain"
    );
    ensure!(
        !root.exists(),
        "showcase directory already exists; never overwrite a wallet"
    );
    fs::create_dir_all(&root)?;
    let config = Chain::discover(Network::Devnet, url.clone(), url.clone())?;
    let settings = Settings {
        chain: config,
        assets: vec![],
    };
    let mut wallet = Wallet::open(&root.join("preferences/morph/wallet"))?;
    wallet.create("Studio", PASSWORD)?;
    wallet.configure(settings.clone())?;
    let own_address = wallet.view()?.address;
    let keyfile = root.join("public-genesis-fixture.key");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&keyfile)?;
    // Public CKB development fixture; never a real-asset key, never passed through argv/env.
    file.write_all(b"d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc")?;
    file.sync_all()?;
    drop(file);
    let mut funder = Wallet::open(&root.join("funder"))?;
    funder.import_key("Development faucet", PASSWORD, &keyfile)?;
    fs::remove_file(keyfile)?;
    funder.configure(settings.clone())?;
    let quote = funder.prepare_estimated(&own_address, None, "1000")?;
    let funding = funder.submit_reviewed(&quote.id)?;
    ensure!(funding.accepted, "funding failed: {:?}", funding.diagnostic);
    mine(url, &mut funder, &funding.transaction_hash)?;
    refresh(&mut wallet, 100_000_000_000)?;
    let mut recipient = Wallet::open(&root.join("recipient"))?;
    recipient.create("Recipient", PASSWORD)?;
    recipient.configure(settings)?;
    let to = recipient.view()?.address;
    let quote = wallet.prepare_estimated(&to, None, "120")?;
    let outgoing = wallet.submit_reviewed(&quote.id)?;
    ensure!(
        outgoing.accepted,
        "payment failed: {:?}",
        outgoing.diagnostic
    );
    mine(url, &mut wallet, &outgoing.transaction_hash)?;
    refresh(&mut wallet, 87_000_000_000)?;
    refresh(&mut recipient, 12_000_000_000)?;
    let received = recipient
        .view()?
        .balance
        .ok_or_else(|| anyhow::anyhow!("missing recipient balance"))?;
    ensure!(
        received.available_plain_capacity == "12000000000",
        "recipient did not receive 120 CKB"
    );
    let evidence = json!({"schema":"morph.native_showcase.v1","network":"devnet","genesis":GENESIS,"rpc":url,"funding_transaction":funding.transaction_hash,"payment_transaction":outgoing.transaction_hash,"recipient_amount_shannons":received.available_plain_capacity,"wallet_address":own_address,"wallet":wallet.view()?});
    fs::write(
        root.join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    // Device preferences only. All balances/history still come from the actual node/indexer.
    fs::write(
        root.join("preferences/morph/desktop-preferences.json"),
        serde_json::to_vec(
            &json!({"schema":"morph.desktop_preferences.v2","preferences":{"language":"zh-CN","scale_percent":100,"reduced_motion":false}}),
        )?,
    )?;
    wallet.lock();
    println!(
        "Development wallet ready: {}\nPublic demonstration password: {PASSWORD}\nEvidence: {}",
        root.display(),
        root.join("evidence.json").display()
    );
    Ok(())
}
