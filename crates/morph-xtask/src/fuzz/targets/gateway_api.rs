//! Current Gateway JSON/query contracts and independently signed receipt checks.
//! Synthetic credentials are deliberately not claims of Biscuit authorization.
use super::*;
use k256::ecdsa::SigningKey;
use morph_core::{
    BackendSettlementEvidence, HttpOperation, PaymentHashAlgorithm, PaymentIntent,
    TerminalPaymentStatus, TerminalSettlementReceipt,
};
use morph_sdk::gateway::*;
use serde::{Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, sync::OnceLock};

struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    decode: fn(&[u8]) -> Result<Vec<u8>>,
}
fn canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::from_slice::<T>(bytes)?)?)
}
fn add<T: DeserializeOwned + Serialize>(
    cases: &mut Vec<Case>,
    name: &'static str,
    value: Value,
) -> Result<()> {
    cases.push(Case {
        name,
        bytes: canonical::<T>(&serde_json::to_vec(&value)?)?,
        decode: canonical::<T>,
    });
    Ok(())
}
fn query(bytes: &[u8]) -> Result<Vec<u8>> {
    let q: PaymentListQuery = serde_json::from_slice(bytes)?;
    // The actual query DTO is Deserialize-only; produce its current canonical
    // string parameter shape, omitting None (explicit null is rejected).
    Ok(serde_json::to_vec(&match q.limit {
        Some(limit) => json!({"limit":limit.to_string()}),
        None => json!({}),
    })?)
}
fn authorization() -> Result<Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/gateway/authorization.json"
    ))?)
}
fn receipt() -> Result<PaymentReceipt> {
    let v = authorization()?;
    let req: PaymentRequirements = serde_json::from_value(v["requirements"].clone())?;
    let mut intent = PaymentIntent {
        intent_id: [0; 32],
        payer: decode_byte32(&req.payer)?,
        payee: decode_byte32(&req.payee)?,
        asset: req.asset.to_gateway_asset()?,
        amount: req.amount_u128()?,
        payment_hash: decode_byte32(&req.payment_hash)?,
        hash_algorithm: PaymentHashAlgorithm::Sha256,
        resource: req.resource.clone(),
        operation: HttpOperation::Get,
        nonce: decode_byte32(&req.nonce)?,
        idempotency_key: decode_byte32(&req.requirement_id)?,
        created_at_unix: 1,
        expires_at_unix: req.expires_at,
        required_rgbpp_proof_commitment: None,
        channel_binding: None,
    };
    intent.intent_id = intent.derive_id()?;
    let key = SigningKey::from_slice(&[8; 32])?; // Public, synthetic fixture key.
    let terminal = TerminalSettlementReceipt::new_signed(
        &intent,
        TerminalPaymentStatus::Settled,
        BackendSettlementEvidence {
            provider_id: "fiber-json-rpc".into(),
            settlement_id: intent.payment_hash,
            opaque_commitment: sha256_bytes(
                format!(
                    "morph-fiber-settlement-v1\0{}\0{}\0Paid",
                    req.requirement_id, req.payment_hash
                )
                .as_bytes(),
            ),
            morph_state: None,
            ckb_anchor: None,
            rgbpp_proof_commitment: None,
            failure_code: None,
        },
        100,
        &key,
    )?;
    let receipt = PaymentReceipt {
        receipt_id: hex32(&terminal.receipt_id),
        credential_id: hex32(&[7; 32]),
        requirement_id: req.requirement_id,
        payment_hash: req.payment_hash,
        payer: req.payer,
        asset_id: req.asset.canonical_id()?,
        amount: req.amount,
        resource: req.resource,
        operation: req.operation,
        paid_at: 100,
        fiber_status: "Paid".into(),
        credential: "synthetic-not-an-access-token".into(),
        credential_expires_at: 200,
        intent,
        terminal_receipt: terminal,
    };
    receipt.validate_for_signer(key.verifying_key().to_sec1_point(true).as_bytes())?;
    Ok(receipt)
}
fn build() -> Result<Vec<Case>> {
    let v = authorization()?;
    let req = &v["requirements"];
    let payload = &v["payload"];
    let receipt = serde_json::to_value(receipt()?)?;
    let hash = hex32(&[12; 32]);
    let mut cases = vec![];
    macro_rules! seed {
        ($ty:ty,$value:expr) => {
            add::<$ty>(&mut cases, stringify!($ty), $value)?
        };
    }
    seed!(EventPageRequest, json!({"after":null,"limit":64}));
    seed!(
        EventPageRequest,
        json!({"after":{"source_id":"12".repeat(32),"revision":"9007199254740993","outbox_id":"event-1"},"limit":1})
    );
    seed!(
        EventPage,
        json!({"events":[],"next":{"source_id":"12".repeat(32),"revision":"0","outbox_id":""},"has_more":false})
    );
    seed!(
        Readiness,
        json!({"service":"gateway","ready":false,"generated_at_ms":"100","scopes":[]})
    );
    seed!(HealthResponse, json!({"status":"ok"}));
    seed!(
        SupportedResponse,
        json!({"scheme":"exact","network":"morph-ckb","assets":[req["asset"]],"payee":req["payee"],"capabilities":["fiber"],"credential_public_key":"synthetic","terminal_receipt_public_key":hex::encode(SigningKey::from_slice(&[8;32])?.verifying_key().to_sec1_point(true).as_bytes())})
    );
    seed!(
        CreateChallengeRequest,
        json!({"asset":req["asset"],"amount":"400","payer":req["payer"],"resource":"/订阅","operation":"GET","description":"订阅 / Subscription","expires_in_seconds":"300","rgbpp_proof_commitment":null})
    );
    seed!(PaymentRequirements, req.clone());
    seed!(
        PayRequest,
        json!({"requirements":req,"payload":payload,"timeout_seconds":"60","max_fee_amount":"5"})
    );
    seed!(
        PayRequest,
        json!({"requirements":req,"payload":payload,"timeout_seconds":null,"max_fee_amount":null})
    );
    seed!(
        PayResponse,
        json!({"completed":true,"payment_hash":req["payment_hash"],"fiber_result":{"status":"Success","payment_hash":req["payment_hash"]}})
    );
    seed!(
        PayResponse,
        json!({"completed":false,"payment_hash":req["payment_hash"],"fiber_result":{"status":"Failed","payment_hash":req["payment_hash"]}})
    );
    seed!(VerifyRequest, json!({"requirements":req,"payload":payload}));
    seed!(
        VerifyResponse,
        json!({"valid":true,"payment_hash":req["payment_hash"],"fiber_status":"Paid"})
    );
    seed!(
        SettleRequest,
        json!({"requirements":req,"payload":payload,"credential_ttl_seconds":"600"})
    );
    seed!(
        SettleResponse,
        json!({"receipt":receipt,"payment_preimage":hash})
    );
    seed!(
        CredentialVerifyRequest,
        json!({"credential":"synthetic-not-an-access-token","receipt":receipt,"resource":"/test"})
    );
    seed!(CredentialVerifyResponse, json!({"authorized":false}));
    seed!(
        FairExchangeOfferRequest,
        json!({"asset":req["asset"],"amount":"400","payer":req["payer"],"resource":"/test","operation":"GET","plaintext_base64":"aGVsbG8=","description":null,"expires_in_seconds":"300","rgbpp_proof_commitment":null})
    );
    seed!(
        FairExchangeEnvelope,
        json!({"offer_id":hash,"requirement":req,"nonce":"synthetic","ciphertext":"synthetic","result_hash":hash})
    );
    seed!(
        FairExchangeClaimRequest,
        json!({"offer_id":hash,"payload":payload,"credential_ttl_seconds":"600"})
    );
    seed!(
        FairExchangeClaim,
        json!({"offer_id":hash,"decryption_key":hash,"receipt":receipt})
    );
    for value in [json!({}), json!({"limit":"1"}), json!({"limit":"1000"})] {
        cases.push(Case {
            name: "PaymentListQuery",
            bytes: query(&serde_json::to_vec(&value)?)?,
            decode: query,
        });
    }
    seed!(
        PaymentListResponse,
        json!({"payments":[{"payment_hash":hash,"requirement_id":req["requirement_id"],"direction":"outgoing","status":"Success","updated_at":"18446744073709551615"}],"source":"local_records"})
    );
    seed!(
        GatewayErrorBody,
        json!({"api_version":"1","code":"payment_outcome_unknown","request_id":"public-request","error":"Retry the exact request"})
    );
    let covered = cases.iter().map(|c| c.name).collect::<BTreeSet<_>>();
    for endpoint in endpoints::Endpoint::ALL {
        let spec = endpoint.spec();
        for body in [spec.request, spec.response] {
            if let endpoints::Body::Json(contract) | endpoints::Body::Query(contract) = body {
                ensure!(
                    covered.contains(contract.name),
                    "missing Gateway DTO corpus: {}",
                    contract.name
                );
            }
        }
    }
    Ok(cases)
}
fn cases() -> Result<&'static [Case]> {
    static CASES: OnceLock<Vec<Case>> = OnceLock::new();
    if CASES.get().is_none() {
        let _ = CASES.set(build()?);
    }
    CASES
        .get()
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow::anyhow!("missing Gateway corpus"))
}
pub(super) fn seeds(name: &str) -> Result<Vec<Vec<u8>>> {
    if name == "gateway-receipt" {
        return Ok(vec![serde_json::to_vec(&receipt()?)?]);
    }
    cases()?
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut bytes = vec![u8::try_from(i)?];
            bytes.extend(&c.bytes);
            Ok(bytes)
        })
        .collect()
}
pub(super) fn check(name: &str, bytes: &[u8]) -> Result<bool> {
    if name == "gateway-receipt" {
        let Ok(receipt) = serde_json::from_slice::<PaymentReceipt>(bytes) else {
            return Ok(false);
        };
        let key = SigningKey::from_slice(&[8; 32])?;
        let public = key.verifying_key().to_sec1_point(true);
        if receipt.validate_for_signer(public.as_bytes()).is_err() {
            return Ok(false);
        }
        let encoded = serde_json::to_vec(&receipt)?;
        let restored: PaymentReceipt = serde_json::from_slice(&encoded)?;
        restored.validate_for_signer(public.as_bytes())?;
        ensure!(
            canonical::<PaymentReceipt>(&encoded)? == encoded,
            "unstable receipt encoding"
        );
        let other = SigningKey::from_slice(&[9; 32])?;
        ensure!(
            restored
                .validate_for_signer(other.verifying_key().to_sec1_point(true).as_bytes())
                .is_err(),
            "wrong receipt authority accepted"
        );
        return Ok(true);
    }
    let Some((&selector, bytes)) = bytes.split_first() else {
        return Ok(false);
    };
    let Some(case) = cases()?.get(usize::from(selector)) else {
        return Ok(false);
    };
    let Ok(encoded) = (case.decode)(bytes) else {
        return Ok(false);
    };
    ensure!(
        (case.decode)(&encoded)? == encoded,
        "Gateway DTO encoding unstable: {}",
        case.name
    );
    if case.name == "Readiness" && !serde_json::from_slice::<Readiness>(&encoded)?.consistent() {
        return Ok(false);
    }
    if case.name == "EventPage"
        && !serde_json::from_slice::<EventPage>(&encoded)?.valid_for(&EventPageRequest {
            after: None,
            limit: 64,
        })
    {
        return Ok(false);
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_registry_dtos_and_signed_receipt_corpus_preserve_current_boundaries() {
        for name in ["gateway-api", "gateway-receipt"] {
            for seed in seeds(name).unwrap() {
                assert!(check(name, &seed).unwrap());
            }
        }
        for (index, case) in cases().unwrap().iter().enumerate() {
            eprintln!(
                "Gateway DTO corpus {index}: {} ({} JSON bytes)",
                case.name,
                case.bytes.len()
            );
            let mut value: Value = serde_json::from_slice(&case.bytes).unwrap();
            value["retired_field"] = json!(true);
            let mut bytes = vec![index as u8];
            bytes.extend(serde_json::to_vec(&value).unwrap());
            assert!(
                !check("gateway-api", &bytes).unwrap(),
                "{} ignored extra input",
                case.name
            );
            if let Some((key, v)) = serde_json::from_slice::<Value>(&case.bytes)
                .unwrap()
                .as_object()
                .unwrap()
                .iter()
                .next()
            {
                let mut bytes = vec![index as u8];
                bytes.extend(&case.bytes[..case.bytes.len() - 1]);
                bytes
                    .extend(format!(",{}:{}}}", serde_json::to_string(key).unwrap(), v).as_bytes());
                assert!(
                    !check("gateway-api", &bytes).unwrap(),
                    "{} duplicate lost before decoder",
                    case.name
                );
            }
        }
        for limit in [
            json!(null),
            json!(0),
            json!("0"),
            json!("1001"),
            json!("01"),
            json!("+1"),
            json!("18446744073709551616"),
        ] {
            assert!(query(&serde_json::to_vec(&json!({"limit":limit})).unwrap()).is_err());
        }
        let receipt = serde_json::to_value(receipt().unwrap()).unwrap();
        for field in [
            "payer",
            "payment_hash",
            "amount",
            "resource",
            "fiber_status",
        ] {
            let mut bad = receipt.clone();
            bad[field] = json!("changed");
            // Structurally valid DTO does not imply valid signed evidence.
            assert!(canonical::<PaymentReceipt>(&serde_json::to_vec(&bad).unwrap()).is_ok());
            assert!(!check("gateway-receipt", &serde_json::to_vec(&bad).unwrap()).unwrap());
        }
    }
}
