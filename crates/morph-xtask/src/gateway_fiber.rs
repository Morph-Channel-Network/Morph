use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use morph_sdk::{PaymentGatewayClient, PaymentGatewayClientError, gateway::*};
use serde_json::{Value, json};
use std::time::Duration;
use zeroize::Zeroizing;

fn environment(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .with_context(|| format!("{name} is required"))
}
fn byte32(name: &str) -> Result<String> {
    let value = environment(name)?;
    decode_byte32(&value)?;
    Ok(value.to_lowercase())
}
fn public(name: &str) -> Result<String> {
    let value = environment(name)?.trim_start_matches("0x").to_lowercase();
    morph_sdk::packages::canonical_fields::public(&format!("0x{value}"))?;
    Ok(value)
}
fn route(result: &Value, expected: &[String; 3]) -> Result<Vec<String>> {
    let routers = result["routers"]
        .as_array()
        .context("Fiber debug result must expose routers")?;
    ensure!(
        routers.len() == 1,
        "devnet payment must use one completed part"
    );
    let nodes = routers[0]["nodes"]
        .as_array()
        .context("Fiber route must expose nodes")?;
    let actual = nodes
        .iter()
        .map(|node| {
            node["pubkey"]
                .as_str()
                .map(|s| s.trim_start_matches("0x").to_lowercase())
                .context("missing Fiber route public key")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        actual == expected,
        "payment must traverse the exact node1 -> node2 -> node3 route"
    );
    Ok(actual)
}
async fn settle(client: &PaymentGatewayClient, request: &SettleRequest) -> Result<SettleResponse> {
    for attempt in 0..40 {
        match client.settle(request).await {
            Ok(value) => return Ok(value),
            Err(PaymentGatewayClientError::Http {
                code: Some(morph_sdk::gateway::api::GatewayErrorCode::PaymentRequired),
                ..
            }) if attempt < 39 => tokio::time::sleep(Duration::from_millis(250)).await,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("settlement never became terminal")
}
async fn claim(
    client: &PaymentGatewayClient,
    request: &FairExchangeClaimRequest,
) -> Result<FairExchangeClaim> {
    for attempt in 0..40 {
        match client.claim_fair_offer(request).await {
            Ok(value) => return Ok(value),
            Err(PaymentGatewayClientError::Http {
                code: Some(morph_sdk::gateway::api::GatewayErrorCode::PaymentRequired),
                ..
            }) if attempt < 39 => tokio::time::sleep(Duration::from_millis(250)).await,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("fair exchange never became terminal")
}
pub async fn run(private_key: &morph_key_input::SecretString) -> Result<()> {
    // clap's protected-file parser has completed before any RPC configuration is read.
    ensure!(
        std::env::var_os("MORPH_PAYMENT_GATEWAY_PAYER_PRIVATE_KEY").is_none(),
        "raw private-key environment input is retired; use the protected file path"
    );
    let bytes = Zeroizing::new(hex::decode(private_key.trim_start_matches("0x"))?);
    let key = k256::ecdsa::SigningKey::from_slice(&bytes)?;
    let payer = hex32(&morph_core::blake2b256(
        key.verifying_key().to_sec1_point(true).as_bytes(),
    ));
    let payee_url = environment("MORPH_PAYMENT_GATEWAY_PAYEE_URL")?;
    let payer_url = environment("MORPH_PAYMENT_GATEWAY_PAYER_URL")?;
    let network = byte32("MORPH_PAYMENT_GATEWAY_CKB_NETWORK_ID")?;
    let payee = byte32("MORPH_PAYMENT_GATEWAY_EXPECTED_PAYEE")?;
    let expected = [
        public("MORPH_PAYMENT_GATEWAY_FIBER_NODE1_PUBKEY")?,
        public("MORPH_PAYMENT_GATEWAY_FIBER_NODE2_PUBKEY")?,
        public("MORPH_PAYMENT_GATEWAY_FIBER_NODE3_PUBKEY")?,
    ];
    ensure!(payer != payee, "payer and payee identities must differ");
    let asset: RgbppAsset = serde_json::from_value(
        json!({"kind":"ckb","ckb_network_id":network,"symbol":"CKB","decimals":8}),
    )?;
    let payee_client = PaymentGatewayClient::new(&payee_url)?;
    let payer_client = PaymentGatewayClient::new(&payer_url)?;
    let supported = payee_client.supported().await?;
    ensure!(supported.payee == payee, "payee identity differs");
    for capability in [
        "x402_exact",
        "biscuit_credentials",
        "fair_exchange_aes_256_gcm",
    ] {
        ensure!(
            supported.capabilities.iter().any(|v| v == capability),
            "missing capability {capability}"
        );
    }
    let requirements = payee_client
        .create_x402_challenge(&CreateChallengeRequest {
            asset: asset.clone(),
            amount: "400".into(),
            payer: payer.clone(),
            resource: "/devnet/payment-gateway-result".into(),
            operation: "GET".into(),
            description: Some("Morph real Fiber devnet payment from Rust".into()),
            expires_in_seconds: Some(300),
            rgbpp_proof_commitment: None,
        })
        .await?;
    ensure!(
        requirements.payer == payer && requirements.payee == payee,
        "challenge identity mismatch"
    );
    let payload = PaymentPayload::new_signed(&requirements, None, &key)?;
    payload.validate(&requirements)?;
    let settlement = SettleRequest {
        requirements: requirements.clone(),
        payload: payload.clone(),
        credential_ttl_seconds: None,
    };
    ensure!(
        matches!(
            payee_client.settle(&settlement).await,
            Err(PaymentGatewayClientError::Http {
                code: Some(morph_sdk::gateway::api::GatewayErrorCode::PaymentRequired),
                ..
            })
        ),
        "settlement must fail before Fiber reports paid"
    );
    let outgoing = payer_client
        .pay(&PayRequest {
            requirements: requirements.clone(),
            payload,
            timeout_seconds: Some(60),
            max_fee_amount: Some("1000".into()),
        })
        .await?;
    ensure!(
        outgoing.completed && outgoing.payment_hash == requirements.payment_hash,
        "Fiber payment did not complete"
    );
    let x402_route = route(&outgoing.fiber_result, &expected)?;
    let settled = settle(&payee_client, &settlement).await?;
    ensure!(
        settled.receipt.requirement_id == requirements.requirement_id
            && settled.receipt.payment_hash == requirements.payment_hash
            && settled.receipt.payer == payer
            && settled.receipt.fiber_status == "Paid",
        "terminal receipt mismatch"
    );
    let receipt = serde_json::to_value(&settled.receipt)?;
    ensure!(
        settled.receipt.terminal_receipt.status == morph_core::TerminalPaymentStatus::Settled,
        "terminal receipt is not settled"
    );
    decode_byte32(&settled.payment_preimage)?;
    verify_preimage(&requirements.payment_hash, &settled.payment_preimage)?;
    let credential = payee_client
        .verify_credential(&CredentialVerifyRequest {
            credential: settled.receipt.credential.clone(),
            receipt: settled.receipt.clone(),
            resource: requirements.resource.clone(),
        })
        .await?;
    ensure!(credential.authorized, "paid credential was rejected");
    let plaintext = b"RGB++ Morph Payment Gateway fair-exchange result over real Fiber";
    let offer = payee_client
        .create_fair_offer(&FairExchangeOfferRequest {
            asset,
            amount: "401".into(),
            payer: payer.clone(),
            resource: "/devnet/fair-exchange".into(),
            operation: "POST".into(),
            plaintext_base64: STANDARD.encode(plaintext),
            description: Some("Morph hash-locked data exchange over Fiber".into()),
            expires_in_seconds: Some(300),
            rgbpp_proof_commitment: None,
        })
        .await?;
    let fair_payload = PaymentPayload::new_signed(&offer.requirement, None, &key)?;
    let fair_outgoing = payer_client
        .pay(&PayRequest {
            requirements: offer.requirement.clone(),
            payload: fair_payload.clone(),
            timeout_seconds: Some(60),
            max_fee_amount: Some("1000".into()),
        })
        .await?;
    ensure!(
        fair_outgoing.completed,
        "fair-exchange payment did not complete"
    );
    let fair_route = route(&fair_outgoing.fiber_result, &expected)?;
    let claimed = claim(
        &payee_client,
        &FairExchangeClaimRequest {
            offer_id: offer.offer_id.clone(),
            payload: fair_payload,
            credential_ttl_seconds: None,
        },
    )
    .await?;
    ensure!(
        decrypt_fair_exchange(&offer, &claimed)? == plaintext,
        "decrypted result differs"
    );
    for (index, status) in [
        (payee_client.payments(20).await?, "Paid"),
        (payer_client.payments(20).await?, "Success"),
    ] {
        ensure!(
            index
                .payments
                .iter()
                .any(|v| v.payment_hash == requirements.payment_hash && v.status == status),
            "payment index lacks expected terminal entry {status}"
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"morph.payment_gateway_fiber_devnet_e2e","status":"passed","runner":"rust","route":"fiber-node1 -> fiber-node2 -> fiber-node3","payer":payer,"payee":payee,"ckb_network_id":network,"routing":{"x402_node_pubkeys":x402_route,"fair_exchange_node_pubkeys":fair_route},"x402":{"payment_hash":requirements.payment_hash,"receipt_id":settled.receipt.receipt_id,"credential_id":settled.receipt.credential_id,"terminal_status":receipt["terminal_receipt"]["status"]},"fair_exchange":{"payment_hash":offer.requirement.payment_hash,"offer_id":offer.offer_id,"receipt_id":claimed.receipt.receipt_id,"plaintext_sha256":offer.result_hash}})
        )?
    );
    Ok(())
}
