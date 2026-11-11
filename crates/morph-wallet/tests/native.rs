//! Explicit isolated-node smoke. Never runs as part of ordinary unit tests.
use morph_wallet::{
    address::{self, Network},
    keystore::UnlockedKey,
    rpc::Chain,
    service::{Settings, Wallet},
};
use serde_json::{Value, json};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, time::Duration};

const RPC: &str = "http://127.0.0.1:18314";
fn rpc(method: &str, params: Value) -> Value {
    let v: Value = reqwest::blocking::Client::new()
        .post(RPC)
        .timeout(Duration::from_secs(12))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(v.get("error").is_none(), "{method}: {v}");
    v["result"].clone()
}
#[test]
#[ignore = "requires dedicated CKB dev node + indexer on 127.0.0.1:18314"]
fn native_wallet_exact_submission_backup_and_recovery() {
    assert_eq!(
        rpc("get_block_hash", json!(["0x0"])),
        "0x64fbe7063a6371844e4a9e92229dae08d3f2b6ae30660b66be9dbdaf14c5dd1a",
        "only the isolated fixture chain is permitted"
    );
    let mut id = [0; 8];
    getrandom::fill(&mut id).unwrap();
    let root = std::env::temp_dir().join(format!("morph-native-wallet-{}", hex::encode(id)));
    fs::create_dir(&root).unwrap();
    let key_path = root.join("fixture.key");
    // Public development genesis fixture, not a user credential; never supplied via argv/env.
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap();
    f.write_all(b"d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc")
        .unwrap();
    f.sync_all().unwrap();
    let mut wallet = Wallet::open(&root.join("sender")).unwrap();
    wallet
        .import_key("Native smoke", "isolated test password", &key_path)
        .unwrap();
    let config = Chain::discover(Network::Devnet, RPC.into(), RPC.into()).unwrap();
    wallet
        .configure(Settings {
            chain: config.clone(),
            assets: vec![],
        })
        .unwrap();
    let before = wallet.refresh().unwrap();
    assert!(
        before
            .balance
            .unwrap()
            .available_plain_capacity
            .parse::<u64>()
            .unwrap()
            > 200 * 100_000_000
    );
    let recipient = UnlockedKey::generate().unwrap();
    let address = address::encode(&recipient.lock_script().unwrap(), Network::Devnet).unwrap();
    let quote = wallet
        .prepare(&address, None, "100", 1000, 100_000)
        .unwrap();
    let expected = quote.summary.transaction_hash.clone();
    let submitted = wallet.submit_reviewed(&quote.id).unwrap();
    assert!(submitted.accepted, "{:?}", submitted.diagnostic);
    assert_eq!(submitted.transaction_hash, expected);
    assert!(
        wallet.submit_reviewed(&quote.id).is_err(),
        "a reviewed intent is one-shot"
    );
    assert_eq!(wallet.view().unwrap().local_transactions.len(), 1);
    for _ in 0..8 {
        rpc("generate_block", json!([]));
        std::thread::sleep(Duration::from_millis(250));
        if wallet.status(&expected).unwrap()["tx_status"]["status"] == "committed" {
            break;
        }
    }
    assert_eq!(
        wallet.status(&expected).unwrap()["tx_status"]["status"],
        "committed"
    );
    let chain = Chain::new(config.clone()).unwrap();
    let inspected = chain
        .inspect_transaction(&expected, &recipient.lock_script().unwrap())
        .unwrap();
    assert!(
        inspected["wallet_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["asset"] == "CKB"
                && v["direction"] == "credit"
                && v["amount"] == "10000000000")
    );
    assert_eq!(inspected["wallet_fee"], quote.summary.fee);
    let mut received = None;
    for _ in 0..20 {
        if let Ok(s) = chain.snapshot(&recipient.lock_script().unwrap(), &Default::default())
            && s.balance.available_plain_capacity == "10000000000"
        {
            received = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        received.is_some(),
        "recipient must receive the exact reviewed capacity"
    );
    let secret = wallet.payment_secret(None).unwrap();
    let payment_hash = format!(
        "0x{}",
        hex::encode(morph_core::blake2b256(
            &hex::decode(secret.trim_start_matches("0x")).unwrap()
        ))
    );
    let encrypted = wallet.backup().unwrap();
    assert!(!String::from_utf8_lossy(&encrypted).contains(&*secret));
    let own_address = wallet.view().unwrap().address;
    wallet.lock();
    assert!(
        wallet
            .prepare(&address, None, "100", 1000, 100_000)
            .is_err()
    );
    drop(wallet);
    let mut restored = Wallet::open(&root.join("restored")).unwrap();
    assert!(restored.restore(&encrypted, "wrong password").is_err());
    restored
        .restore(&encrypted, "isolated test password")
        .unwrap();
    restored
        .configure(Settings {
            chain: config,
            assets: vec![],
        })
        .unwrap();
    assert_eq!(restored.view().unwrap().address, own_address);
    assert_eq!(
        &*restored.payment_secret(Some(&payment_hash)).unwrap(),
        &*secret
    );
    assert_eq!(restored.view().unwrap().local_transactions.len(), 1);
    assert!(restored.refresh().unwrap().balance.is_some());
    println!(
        "native wallet: exact signed transfer committed {expected}; recipient 100 CKB; encrypted backup restored same address"
    );
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

// Fixture-only authority used solely to deploy the isolated devnet token for this test.
fn sign_fixture(tx: ckb_types::core::TransactionView) -> ckb_types::core::TransactionView {
    use ckb_types::{bytes::Bytes, packed, prelude::*};
    let first = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0; 65])).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(first.as_bytes().pack())
        .build();
    let mut message = tx.hash().as_slice().to_vec();
    let witness = tx.witnesses().get(0).unwrap().raw_data();
    message.extend_from_slice(&(witness.len() as u64).to_le_bytes());
    message.extend_from_slice(&witness);
    let raw =
        hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc").unwrap();
    let key = ckb_crypto::secp::Privkey::from_slice(&raw);
    let sig = key
        .sign_recoverable(&morph_core::blake2b256(&message).into())
        .unwrap();
    let first = packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(sig.serialize())).pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![first.as_bytes().pack()])
        .build()
}
fn commit(chain: &Chain, tx: &ckb_types::core::TransactionView) {
    chain.preflight(tx).unwrap();
    chain.submit(tx).unwrap();
    for _ in 0..8 {
        rpc("generate_block", json!([]));
        std::thread::sleep(Duration::from_millis(250));
        if chain
            .transaction_status(&format!("{:#x}", tx.hash()))
            .unwrap()["tx_status"]["status"]
            == "committed"
        {
            return;
        }
    }
    panic!("fixture transaction did not commit");
}
fn synced(chain: &Chain, owner: &ckb_types::packed::Script) -> morph_wallet::rpc::Snapshot {
    for _ in 0..20 {
        if let Ok(s) = chain.snapshot(owner, &Default::default()) {
            return s;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("indexer did not synchronize");
}
#[test]
#[ignore = "requires dedicated CKB dev node + indexer and built devnet xUDT ELF"]
fn native_wallet_token_release_preserves_change_and_independent_ckb() {
    use ckb_types::{
        bytes::Bytes,
        core::{Capacity, TransactionBuilder},
        packed,
        prelude::*,
    };
    use morph_wallet::service::{Asset, AssetManifest};
    assert_eq!(
        rpc("get_block_hash", json!(["0x0"])),
        "0x64fbe7063a6371844e4a9e92229dae08d3f2b6ae30660b66be9dbdaf14c5dd1a"
    );
    let root = std::env::temp_dir().join(format!("morph-token-wallet-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let key_path = root.join("fixture.key");
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap()
        .write_all(b"d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc")
        .unwrap();
    let key = UnlockedKey::import_file(&key_path).unwrap();
    let owner = key.lock_script().unwrap();
    let config = Chain::discover(Network::Devnet, RPC.into(), RPC.into()).unwrap();
    let chain = Chain::new(config.clone()).unwrap();
    let snapshot = synced(&chain, &owner);
    let coin = snapshot
        .coins
        .iter()
        .filter(|c| c.output.type_().is_none() && c.data.is_empty())
        .max_by_key(|c| Unpack::<u64>::unpack(&c.output.capacity()))
        .unwrap();
    let elf = Bytes::from(
        fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/riscv64imac-unknown-none-elf/release/morph-devnet-xudt"
        ))
        .unwrap(),
    );
    let deploy_base = packed::CellOutput::new_builder()
        .lock(owner.clone())
        .build();
    let cap = deploy_base
        .occupied_capacity(Capacity::bytes(elf.len()).unwrap())
        .unwrap()
        .as_u64();
    let input_capacity: u64 = coin.output.capacity().unpack();
    let deploy = sign_fixture(
        TransactionBuilder::default()
            .cell_dep(snapshot.secp_dep.clone())
            .input(packed::CellInput::new(coin.out_point.clone(), 0))
            .output(deploy_base.clone().as_builder().capacity(cap).build())
            .output_data(elf.clone().pack())
            .output(
                deploy_base
                    .clone()
                    .as_builder()
                    .capacity(input_capacity - cap - 100_000)
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .build(),
    );
    commit(&chain, &deploy);
    let dependency = packed::CellDep::new_builder()
        .out_point(packed::OutPoint::new(deploy.hash(), 0))
        .dep_type(0u8)
        .build();
    let token = packed::Script::new_builder()
        .code_hash(morph_core::blake2b256(&elf).pack())
        .hash_type(4u8)
        .args(owner.calc_script_hash().as_bytes().pack())
        .build();
    let minted = 1000u128;
    let token_cap = 142 * 100_000_000;
    let mint = sign_fixture(
        TransactionBuilder::default()
            .cell_dep(snapshot.secp_dep)
            .cell_dep(dependency.clone())
            .input(packed::CellInput::new(
                packed::OutPoint::new(deploy.hash(), 1),
                0,
            ))
            .output(
                deploy_base
                    .clone()
                    .as_builder()
                    .type_(Some(token.clone()).pack())
                    .capacity(token_cap)
                    .build(),
            )
            .output_data(Bytes::copy_from_slice(&minted.to_le_bytes()).pack())
            .output(
                deploy_base
                    .as_builder()
                    .capacity(input_capacity - cap - 200_000 - token_cap)
                    .build(),
            )
            .output_data(Bytes::new().pack())
            .build(),
    );
    commit(&chain, &mint);
    std::thread::sleep(Duration::from_millis(500));
    let mut wallet = Wallet::open(&root.join("wallet")).unwrap();
    wallet
        .import_key("token smoke", "isolated test password", &key_path)
        .unwrap();
    wallet
        .configure(Settings {
            chain: config.clone(),
            assets: vec![],
        })
        .unwrap();
    let asset = Asset {
        symbol: "TEST".into(),
        decimals: 2,
        script: token.clone().into(),
        dependency: dependency.into(),
    };
    let hash = asset.hash();
    assert!(
        wallet
            .admit_assets(AssetManifest {
                genesis_hash: format!("0x{}", "11".repeat(32)),
                assets: vec![asset.clone()]
            })
            .is_err()
    );
    wallet
        .admit_assets(AssetManifest {
            genesis_hash: config.genesis_hash,
            assets: vec![asset],
        })
        .unwrap();
    let recipient = UnlockedKey::generate().unwrap();
    let address = address::encode(&recipient.lock_script().unwrap(), Network::Devnet).unwrap();
    let available = synced(&chain, &owner);
    let quote = wallet
        .prepare_estimated(&address, Some(&hash), "2.50")
        .unwrap();
    assert_eq!(quote.summary.amount, "250");
    let submitted = wallet.submit_reviewed(&quote.id).unwrap();
    assert!(submitted.accepted, "{:?}", submitted.diagnostic);
    let saved = wallet.view().unwrap().local_transactions.remove(0);
    let transaction =
        packed::Transaction::from_slice(&hex::decode(saved.signed_transaction).unwrap())
            .unwrap()
            .into_view();
    let selected_tokens = transaction
        .inputs()
        .into_iter()
        .map(|input| {
            let coin = available
                .coins
                .iter()
                .find(|c| c.out_point == input.previous_output())
                .unwrap();
            if coin.output.type_().to_opt().as_ref() == Some(&token) {
                u128::from_le_bytes(coin.data.as_ref().try_into().unwrap())
            } else {
                0
            }
        })
        .sum::<u128>();
    assert_eq!(
        quote.summary.token_change,
        (selected_tokens - 250).to_string()
    );
    for _ in 0..8 {
        rpc("generate_block", json!([]));
        std::thread::sleep(Duration::from_millis(250));
        if wallet.status(&submitted.transaction_hash).unwrap()["tx_status"]["status"] == "committed"
        {
            break;
        }
    }
    assert_eq!(
        wallet.status(&submitted.transaction_hash).unwrap()["tx_status"]["status"],
        "committed"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        synced(&chain, &recipient.lock_script().unwrap())
            .balance
            .token_quantities[&hash],
        "250"
    );
    let page = wallet.history(None).unwrap();
    let row = page["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["tx_hash"] == submitted.transaction_hash)
        .unwrap();
    assert!(
        row["wallet_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["asset"] == hash && v["direction"] == "debit" && v["amount"] == "250")
    );
    assert_eq!(row["wallet_fee"], quote.summary.fee);
    let prior = snapshot
        .balance
        .token_quantities
        .get(&hash)
        .map_or(0, |v| v.parse::<u128>().unwrap());
    assert_eq!(
        synced(&chain, &owner).balance.token_quantities[&hash],
        (prior + 750).to_string()
    );
    println!(
        "native xUDT: recipient 250 base units; selected-input change {}; owner total increased by 750 after mint/transfer; separate CKB change and node-estimated fee; {}",
        quote.summary.token_change, submitted.transaction_hash
    );
    drop(wallet);
    fs::remove_dir_all(root).unwrap();
}
