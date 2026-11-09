//! Real HTTP integration between the production Hub binary and the Rust client.
use morph_sdk::{HubClient, api::*};
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn public(byte: u8) -> String {
    let key = k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap();
    hex::encode(key.verifying_key().to_sec1_point(true).as_bytes())
}
fn hash(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

#[tokio::test]
async fn native_sdk_preserves_hub_mutations_permissions_and_restore_barriers_over_http() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = format!("127.0.0.1:{port}");
    let directory = std::env::temp_dir().join(format!(
        "morph-rust-client-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let key_path = directory.join("invoice.key");
    let mut key_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap();
    key_file
        .write_all(hex::encode([41; 32]).as_bytes())
        .unwrap();
    drop(key_file);
    let child = Command::new(env!("CARGO_BIN_EXE_morph-cli"))
        .args([
            "hub",
            "serve",
            "--listen",
            &address,
            "--pubkey",
            &public(41),
            "--allow-unauthenticated-loopback",
            "--allow-state-restore",
            "--invoice-private-key-file",
        ])
        .arg(&key_path)
        .arg("--state-path")
        .arg(directory.join("state.json"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut process = Process(child);
    let client = HubClient::new(&format!("http://{address}")).unwrap();
    let mut ready = false;
    for _ in 0..60 {
        if client.state().await.is_ok() {
            ready = true;
            break;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "Hub exited before readiness"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Hub did not become ready");
    let empty = client.state_file().await.unwrap();
    let preview = client.preview_restore(&empty).await.unwrap();
    assert!(preview.allowed);
    client
        .restore(&empty, &preview.confirmation_hash)
        .await
        .unwrap();
    let state = client
        .connect_peer(&ConnectPeerRequest {
            pubkey: public(42),
            alias: "Native peer 中文".into(),
        })
        .await
        .unwrap();
    assert_eq!(state.peers[0].alias, "Native peer 中文");
    assert!(!state.model.chain_actions_enabled);
    let channel = hash(51);
    let state = client
        .open_channel(&OpenChannelRequest {
            channel_id: channel.clone(),
            counterparty_pubkey: public(42),
            counterparty_alias: None,
            funding_context_id: hash(52),
            local: "20000000000".into(),
            remote: "30000000000".into(),
            pending: Some("0".into()),
            sponsor_budget: 1_000_000,
            asset: Some(AssetRequest::Ckb),
        })
        .await
        .unwrap();
    assert_eq!(state.channels[0].balances[0].local, "20000000000");
    client
        .splice_channel(
            &channel,
            &SpliceChannelRequest {
                new_funding_epoch: 1,
                new_funding_context_id: hash(53),
            },
        )
        .await
        .unwrap();
    let state = client
        .publish_channel(
            &channel,
            &PublishStateRequest {
                funding_context_id: hash(53),
                state_number: 2,
            },
        )
        .await
        .unwrap();
    assert_eq!(state.channels[0].phase, "settling");
    let state = client.finalise_channel(&channel).await.unwrap();
    assert_eq!(state.channels[0].phase, "closed");
    let factory = hash(54);
    client
        .open_factory(&OpenFactoryRequest {
            factory_id: factory.clone(),
            participant_pubkeys: vec![public(41), public(42)],
            reserve: "100000000000".into(),
            asset: Some(AssetRequest::Ckb),
        })
        .await
        .unwrap();
    client
        .advance_factory(
            &factory,
            &AdvanceFactoryRequest {
                new_update_number: 1,
            },
        )
        .await
        .unwrap();
    let state = client
        .materialise_child(
            &factory,
            &MaterialiseChildRequest {
                child_channel_id: hash(55),
                counterparty_pubkey: public(42),
                counterparty_alias: None,
                funding_context_id: hash(56),
                local: "10000000000".into(),
                remote: "10000000000".into(),
                pending: Some("0".into()),
                sponsor_budget: 1_000_000,
                asset: Some(AssetRequest::Ckb),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        state.factories[0].materialised_child_channels,
        vec![hash(55)]
    );
    let preimage = [57; 32];
    let state = client
        .create_invoice(&CreateInvoiceRequest {
            amount: "100".into(),
            description: "Native receipt".into(),
            payment_preimage: None,
            payment_hash: Some(format!(
                "0x{}",
                hex::encode(morph_core::blake2b256(&preimage))
            )),
            expiry_secs: 3600,
            channel_id: None,
            asset: Some(AssetRequest::Ckb),
        })
        .await
        .unwrap();
    let invoice = state.invoices[0].clone();
    client.receive_invoice(&invoice.invoice_id).await.unwrap();
    client
        .settle_invoice(
            &invoice.invoice_id,
            &SettleInvoiceRequest {
                payment_preimage: format!("0x{}", hex::encode(preimage)),
            },
        )
        .await
        .unwrap();
    let preview = client.preview_restore(&empty).await.unwrap();
    assert!(
        !preview.allowed,
        "cannot erase operational state through bootstrap restore"
    );
    assert!(
        client
            .restore(&empty, &preview.confirmation_hash)
            .await
            .is_err()
    );
    let current = client.state().await.unwrap();
    let value = serde_json::to_value(&current).unwrap();
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<HubView>(value.clone()).unwrap()).unwrap(),
        value
    );
    assert_eq!(current.provenance.source, "hub_state_file");
    drop(process);
    std::fs::remove_dir_all(directory).unwrap();
}
