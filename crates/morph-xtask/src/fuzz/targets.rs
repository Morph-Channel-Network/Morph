use anyhow::{Result, ensure};
use morph_core::{MultiAssetManifest, MultiAssetRecoveryPackage, MultiAssetSettlement};
use morph_script_common::multi_asset as wire;
use morph_script_common::multi_asset_close as close;
use morph_sdk::packages::{events::EventEnvelope, multi_asset_packages::StoredMultiAssetPackage};
use serde_json::{Value, json};
mod documents;
mod factory;
mod gateway_api;
mod hub_api;
mod replay;
mod settlement;
mod signer;
mod splice;

pub const NAMES: &[&str] = &[
    "manifest",
    "settlement",
    "state-witness",
    "close-frame",
    "recovery-json",
    "factory-frame",
    "factory-state",
    "factory-materialisation",
    "event-json",
    "hub-mutation",
    "gateway-authorization",
    "callback-auth",
    "store-commit",
    "store-replay",
    "sdk-document",
    "sdk-receipt",
    "splice-frame",
    "splice-flows",
    "batch-resolution",
    "script-args",
    "signer-request",
    "signer-review",
    "signer-response",
    "hub-api",
    "gateway-api",
    "gateway-receipt",
];
const PACKAGE: &[u8] = include_bytes!("../../../../fixtures/protocol/multi-asset.json");
const FACTORY: &[u8] = include_bytes!("../../../../fixtures/protocol/factory-transitions.json");
fn package() -> Result<StoredMultiAssetPackage> {
    Ok(serde_json::from_slice(PACKAGE)?)
}
pub fn seeds(name: &str) -> Result<Vec<Vec<u8>>> {
    let packages = [
        package()?,
        morph_sdk::packages::conditional_packages::fixture_source_package()?,
    ];
    let recoveries = packages
        .iter()
        .map(StoredMultiAssetPackage::recovery)
        .collect::<Result<Vec<_>>>()?;
    Ok(match name {
        "gateway-api" | "gateway-receipt" => gateway_api::seeds(name)?,
        "hub-api" => hub_api::seeds()?,
        "signer-request" | "signer-review" | "signer-response" => signer::seeds(name)?,
        "factory-state" | "factory-materialisation" => factory::seeds(name)?,
        "store-replay" => replay::seeds(),
        "batch-resolution" => settlement::resolution_seeds()?,
        "script-args" => settlement::argument_seeds()?,
        "splice-frame" | "splice-flows" => splice::seeds(name == "splice-flows")?,
        "sdk-document" | "sdk-receipt" => documents::seeds(name == "sdk-receipt")?,
        "close-frame" => recoveries
            .iter()
            .map(|p| {
                let inner = morph_core::encode_multi_asset_witness(
                    &p.manifest,
                    &p.settlement,
                    &p.outpoints,
                    &p.scripts,
                )?;
                let sigs = morph_core::encode_multi_asset_signatures(&p.authorization)?;
                let mut frame = vec![0; close::MULTI_ASSET_CLOSE_FIXED_LEN + inner.len()];
                // Parser corpus only. Existing state votes deliberately do not grant
                // close authority; actual close signature enforcement has VM tests.
                close::encode_multi_asset_close(
                    &mut frame,
                    &[17; 32],
                    &p.state.encode()?,
                    &sigs,
                    &inner,
                )
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                Ok(frame)
            })
            .collect::<Result<_>>()?,
        "manifest" => recoveries
            .iter()
            .map(|p| Ok(p.manifest.encode()?))
            .collect::<Result<_>>()?,
        "settlement" => recoveries
            .iter()
            .map(|p| Ok(p.settlement.encode()?))
            .collect::<Result<_>>()?,
        "state-witness" => recoveries
            .iter()
            .map(|p| {
                let mut bytes = p.state_carrier_capacity.to_le_bytes().to_vec();
                bytes.extend(p.state.encode()?);
                bytes.extend(morph_core::encode_multi_asset_witness(
                    &p.manifest,
                    &p.settlement,
                    &p.outpoints,
                    &p.scripts,
                )?);
                Ok(bytes)
            })
            .collect::<Result<_>>()?,
        "recovery-json" => packages
            .iter()
            .map(|p| Ok(serde_json::to_vec(p)?))
            .collect::<Result<_>>()?,
        "factory-frame" => {
            let value: Value = serde_json::from_slice(FACTORY)?;
            let mut seeds = vec![];
            for case in value["cases"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("missing Factory corpus"))?
            {
                let package: morph_sdk::packages::factory_transition_packages::StoredFactoryTransitionPackage=serde_json::from_value(case["package"].clone())?;
                let view = package.validate()?;
                seeds.push(view.witness()?.as_bytes().to_vec());
            }
            seeds
        }
        "event-json" => vec![serde_json::to_vec(&json!({
            "schema":"morph.event.v1","event_id":"11".repeat(32),"source_id":"22".repeat(32),"source_revision":"1","created_at_ms":"1",
            "component":"watch","evidence_level":"local_record","kind":"watch_scan_idle","severity":"info",
            "correlation_id":"33".repeat(32),"subject_id":null,"funding_context_id":null,"payment_hash":null,"provider_revision":null,"evidence_digest":null
        }))?],
        "hub-mutation" => vec![serde_json::to_vec(
            &json!({"idempotency_key":"12".repeat(16),"expected_revision":"0"}),
        )?],
        "gateway-authorization" => {
            let v: Value = serde_json::from_slice(include_bytes!(
                "../../../../fixtures/gateway/authorization.json"
            ))?;
            vec![serde_json::to_vec(
                &json!({"requirements":v["requirements"],"payload":v["payload"]}),
            )?]
        }
        "callback-auth" => {
            let body = seeds("event-json")?.remove(0);
            let event = EventEnvelope::decode(&body)?;
            let signature = callback_mac(&event.event_id, &body)?;
            let mut bytes = event.event_id.into_bytes();
            bytes.extend(signature.as_bytes());
            bytes.extend(body);
            vec![bytes]
        }
        "store-commit" => vec![serde_json::to_vec(
            &json!({"operation_id":"fuzz-commit","expected_revision":0,"intent":"010203",
            "writes":[{"family":"hub","id":"node","value":"abcd"},{"family":"payment","id":"invoice","value":"ef01"}],
            "events":[{"id":"event-1","body":"1234"}],"attempts":[{"id":"attempt-1","body":"5678"}]}),
        )?],
        _ => anyhow::bail!("unknown fuzz target"),
    })
}
/// `false` is a normal parser rejection; `Err` is an invariant failure.
pub fn check(name: &str, bytes: &[u8]) -> Result<bool> {
    match name {
        "gateway-api" | "gateway-receipt" => return gateway_api::check(name, bytes),
        "hub-api" => return hub_api::check(bytes),
        "signer-request" | "signer-review" | "signer-response" => {
            return signer::check(name, bytes);
        }
        "factory-state" => return factory::state(bytes),
        "factory-materialisation" => return factory::materialisation(bytes),
        "close-frame" => {
            if let Ok(frame) = close::MultiAssetCloseWitness::parse(bytes) {
                let signature_offset = 48 + wire::MULTI_ASSET_STATE_HEADER_LEN;
                let mut encoded = vec![0; bytes.len()];
                close::encode_multi_asset_close(
                    &mut encoded,
                    &frame.transaction_hash(),
                    frame.target().as_bytes(),
                    &bytes[signature_offset..close::MULTI_ASSET_CLOSE_FIXED_LEN],
                    frame.evidence().as_bytes(),
                )
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                ensure!(
                    encoded == bytes,
                    "close frame canonical re-encoding differs"
                );
                return Ok(true);
            }
        }
        "manifest" => {
            let host = MultiAssetManifest::decode(bytes);
            ensure!(
                host.is_ok() == wire::MultiAssetVaultManifest::parse(bytes).is_ok(),
                "manifest host/script acceptance differs"
            );
            if let Ok(value) = host {
                ensure!(value.encode()? == bytes, "manifest re-encoding differs");
                return Ok(true);
            }
        }
        "settlement" => {
            let host = MultiAssetSettlement::decode(bytes);
            ensure!(
                host.is_ok() == wire::MultiAssetSettlementDescriptor::parse(bytes).is_ok(),
                "settlement host/script acceptance differs"
            );
            if let Ok(value) = host {
                ensure!(value.encode()? == bytes, "settlement re-encoding differs");
                return Ok(true);
            }
        }
        "state-witness" => {
            if bytes.len() < 8 + wire::MULTI_ASSET_STATE_HEADER_LEN {
                return Ok(false);
            }
            let carrier = u64::from_le_bytes(bytes[..8].try_into()?);
            let (header, witness) = bytes[8..].split_at(wire::MULTI_ASSET_STATE_HEADER_LEN);
            if let Ok(value) = MultiAssetRecoveryPackage::decode_contents(header, witness, carrier)
            {
                let state = wire::MultiAssetStateHeader::parse(header)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                wire::MultiAssetWitness::parse(witness)
                    .and_then(|w| w.validate_header(&state))
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                ensure!(
                    value.state.encode()?.as_slice() == header,
                    "State re-encoding differs"
                );
                ensure!(
                    morph_core::encode_multi_asset_witness(
                        &value.manifest,
                        &value.settlement,
                        &value.outpoints,
                        &value.scripts
                    )? == witness,
                    "witness re-encoding differs"
                );
                return Ok(true);
            }
        }
        "recovery-json" => {
            let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
                return Ok(false);
            };
            let direct = serde_json::from_value::<StoredMultiAssetPackage>(value.clone())
                .ok()
                .and_then(|p| p.validate().ok());
            let sdk = morph_sdk::inspection::inspect(&value, None);
            // This target is specifically the recovery schema, not every SDK document.
            if value["schema"] == "morph.multi_asset_recovery_package.v1" {
                ensure!(
                    direct.is_some() == sdk.is_ok(),
                    "SDK/package acceptance differs"
                );
                if let Some(summary) = direct {
                    ensure!(
                        serde_json::to_value(summary)? == sdk?,
                        "SDK summary differs"
                    );
                    return Ok(true);
                }
            }
        }
        "factory-frame" => {
            use morph_script_common::factory_multi_asset::FactoryReducedReleaseWitness;
            if let Ok(frame) = FactoryReducedReleaseWitness::parse(bytes) {
                // Walk and validate compact paired proofs, including noninterference.
                if frame.validate_transition().is_ok() {
                    ensure!(frame.as_bytes() == bytes, "Factory frame changed");
                    return Ok(true);
                }
            }
        }
        "event-json" => {
            if let Ok(event) = EventEnvelope::decode(bytes) {
                let encoded = event.encode()?;
                let next = EventEnvelope::decode(&encoded)?;
                ensure!(next == event, "event semantic roundtrip differs");
                ensure!(
                    next.encode()? == encoded,
                    "event canonical encoding unstable"
                );
                return Ok(true);
            }
        }
        "hub-mutation" => {
            let Ok(context) = serde_json::from_slice::<morph_sdk::api::MutationContext>(bytes)
            else {
                return Ok(false);
            };
            if !context.valid() {
                return Ok(false);
            }
            let encoded = serde_json::to_vec(&context)?;
            let next: morph_sdk::api::MutationContext = serde_json::from_slice(&encoded)?;
            ensure!(
                next == context && next.valid(),
                "mutation context changed on roundtrip"
            );
            let v: Value = serde_json::from_slice(&encoded)?;
            ensure!(
                v["expected_revision"].as_str()
                    == Some(context.expected_revision.to_string().as_str()),
                "revision is not canonical decimal"
            );
            return Ok(true);
        }
        "gateway-authorization" => {
            let Ok(request) = serde_json::from_slice::<morph_sdk::gateway::VerifyRequest>(bytes)
            else {
                return Ok(false);
            };
            // A fixed observation time makes this fixture/campaign reproducible.
            if request.requirements.validate(100).is_err()
                || request.payload.validate(&request.requirements).is_err()
            {
                return Ok(false);
            }
            let encoded = serde_json::to_vec(&request)?;
            let next: morph_sdk::gateway::VerifyRequest = serde_json::from_slice(&encoded)?;
            next.requirements.validate(100)?;
            next.payload.validate(&next.requirements)?;
            ensure!(
                serde_json::to_vec(&next)? == encoded,
                "Gateway authorization encoding changed"
            );
            return Ok(true);
        }
        "callback-auth" => {
            if bytes.len() < 128 {
                return Ok(false);
            }
            let Ok(id) = std::str::from_utf8(&bytes[..64]) else {
                return Ok(false);
            };
            let Ok(sig) = std::str::from_utf8(&bytes[64..128]) else {
                return Ok(false);
            };
            let body = &bytes[128..];
            if morph_events::verify_request(id, body, sig, &[7; 32]).is_ok() {
                ensure!(
                    EventEnvelope::decode(body)?.event_id == id,
                    "callback ID differs from authenticated body"
                );
                ensure!(
                    callback_mac(id, body)? == sig,
                    "accepted callback has wrong exact-body MAC"
                );
                let ack = morph_events::acknowledgement(id, body, &[7; 32])?;
                ensure!(
                    morph_events::verify_request(id, body, &ack, &[7; 32]).is_err(),
                    "acknowledgement accepted as request"
                );
                ensure!(
                    morph_events::verify_request(id, body, sig, &[8; 32]).is_err(),
                    "wrong callback key accepted"
                );
                return Ok(true);
            }
        }
        "store-commit" => return store_commit(bytes),
        "store-replay" => return replay::check(bytes),
        "batch-resolution" => return settlement::resolution(bytes),
        "script-args" => return settlement::arguments(bytes),
        "splice-frame" | "splice-flows" => return splice::check(bytes, name == "splice-flows"),
        "sdk-document" | "sdk-receipt" => return documents::check(bytes, name == "sdk-receipt"),
        _ => anyhow::bail!("unknown fuzz target"),
    }
    Ok(false)
}

fn callback_mac(id: &str, body: &[u8]) -> Result<String> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut h = <Hmac<sha2_current::Sha256> as KeyInit>::new_from_slice(&[7; 32])?;
    h.update(b"morph.event.request.v1\0");
    h.update(id.as_bytes());
    h.update(&[0]);
    h.update(body);
    Ok(hex::encode(h.finalize().into_bytes()))
}
fn store_commit(bytes: &[u8]) -> Result<bool> {
    use morph_runtime_store::{Body, Commit, History, Protection, Store, StoreError};
    let Ok(commit) = serde_json::from_slice::<Commit>(bytes) else {
        return Ok(false);
    };
    let store = Store::memory(Protection::private_plaintext())?;
    match store.commit(&commit) {
        Err(error) => {
            ensure!(
                matches!(
                    error,
                    StoreError::Invalid
                        | StoreError::Revision { .. }
                        | StoreError::Conflict
                        | StoreError::Full
                ),
                "unexpected store failure: {error}"
            );
            let report = store.validate()?;
            ensure!(
                report.revision == 0
                    && report.records == 0
                    && report.intents == 0
                    && report.events == 0
                    && report.attempts == 0,
                "failed commit leaked a partial transaction"
            );
            Ok(false)
        }
        Ok(receipt) => {
            ensure!(
                receipt.revision == 1 && receipt.operation_id == commit.operation_id,
                "receipt is not first committed operation"
            );
            ensure!(
                store.commit(&commit)? == receipt,
                "exact retry changed receipt"
            );
            ensure!(
                store.commit_new(&commit) == Err(StoreError::Conflict),
                "retry regained new-effect permission"
            );
            let mut conflict = commit.clone();
            let mut intent = conflict.intent.bytes().to_vec();
            ensure!(!intent.is_empty(), "empty intent accepted");
            intent[0] ^= 1;
            conflict.intent = Body::new(intent)?;
            ensure!(
                store.commit(&conflict) == Err(StoreError::Conflict),
                "same ID accepted changed intent"
            );
            let report = store.validate()?;
            ensure!(
                report.revision == 1 && report.intents == 1,
                "retry advanced revision or lost intent"
            );
            ensure!(
                report.events == commit.events.len() as u64
                    && report.attempts == commit.attempts.len() as u64,
                "history not atomic"
            );
            for write in &commit.writes {
                let actual = store.read(write.family, &write.id)?;
                ensure!(
                    actual.record.as_ref().map(|r| r.body.bytes())
                        == write.value.as_ref().map(|b| b.bytes()),
                    "projection differs from committed value"
                );
            }
            for (kind, items) in [
                (History::Outbox, &commit.events),
                (History::Attempt, &commit.attempts),
            ] {
                for item in items {
                    let saved = store
                        .history_entry(kind, &item.id)?
                        .ok_or_else(|| anyhow::anyhow!("missing committed immutable row"))?;
                    ensure!(
                        saved.body.bytes() == item.body.bytes()
                            && saved.revision == 1
                            && saved.operation_id == commit.operation_id,
                        "immutable row differs"
                    );
                }
            }
            Ok(true)
        }
    }
}
