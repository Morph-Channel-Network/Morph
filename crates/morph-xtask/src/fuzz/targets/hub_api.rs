//! Endpoint DTO decoding, not server-side authorization or restore permission.
//! Keep raw input until the actual serde decoder so duplicate keys are tested.
use super::*;
use morph_sdk::{
    api::*,
    packages::{
        conditional_packages::{self, StoredConditionalBatchPackage},
        multi_asset_funding::*,
    },
};
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
    let bytes = canonical::<T>(&serde_json::to_vec(&value)?)?;
    cases.push(Case {
        name,
        bytes,
        decode: canonical::<T>,
    });
    Ok(())
}
fn build() -> Result<Vec<Case>> {
    let hub: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/hub/unauthenticated-loopback.json"
    ))?;
    let root: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-root.json"
    ))?;
    let hash = format!("0x{}", "12".repeat(32));
    let peer = hub["pubkey"].clone();
    let event = json!({"id":"9007199254740993","severity":"info","event":"channel_opened","subject_id":hash,"message":"通道已记录 · Channel saved","created_at_unix":"18446744073709551615","provenance":hub["provenance"]});
    let mut archive = json!({"pubkey":peer,"network":"devnet","peers":[],"channels":[],"factories":[],"conditional_batches":[],"multi_asset_packages":[],"root_fundings":[],"invoices":[],"completed_flows":[],"events":[]});
    let mut cases = Vec::new();
    macro_rules! seed {
        ($ty:ty, $value:expr) => {
            add::<$ty>(&mut cases, stringify!($ty), $value)?
        };
    }
    seed!(
        ApiInfo,
        json!({"api_version":"1","revision":"18446744073709551615"})
    );
    seed!(Liveness, json!({"service":"hub","alive":true}));
    seed!(
        Readiness,
        json!({"service":"hub","ready":false,"generated_at_ms":"100","scopes":[]})
    );
    seed!(HubView, hub.clone());
    seed!(EventView, event.clone());
    seed!(EventPageRequest, json!({"after":null,"limit":1}));
    seed!(
        EventPageRequest,
        json!({"after":{"source_id":"12".repeat(32),"revision":"9007199254740993","outbox_id":"event-1"},"limit":64})
    );
    seed!(
        EventPage,
        json!({"events":[],"next":{"source_id":"12".repeat(32),"revision":"0","outbox_id":""},"has_more":false})
    );
    let event_seed = super::seeds("event-json")?.remove(0);
    let mut public_event: Value = serde_json::from_slice(&event_seed)?;
    public_event["event_id"] = json!(EventEnvelope::identity(&"22".repeat(32), "event-1"));
    seed!(
        EventPage,
        json!({"events":[public_event],"next":{"source_id":public_event["source_id"],"revision":"1","outbox_id":"event-1"},"has_more":false})
    );
    seed!(StateArchive, archive.clone());
    let balance =
        json!({"asset":{"kind":"ckb"},"local":"9007199254740993","remote":"10","pending":"0"});
    archive["peers"] = json!([{"pubkey":peer,"alias":"远端 / Peer"}]);
    archive["channels"] = json!([{"channel_id":hash,"counterparty_pubkey":peer,"funding_epoch":"1","funding_context_id":hash,"state_number":"9007199254740993","phase":"settling","balances":[balance],"sponsor_budget":"18446744073709551615"}]);
    archive["factories"] = json!([{"factory_id":hash,"participant_pubkeys":[peer],"update_number":"1","reserve_balances":[balance],"materialised_child_channels":[hash]}]);
    archive["multi_asset_packages"] = serde_json::to_value(vec![package()?])?;
    archive["conditional_batches"] =
        serde_json::to_value(vec![conditional_packages::fixture_package()?])?;
    archive["root_fundings"] = json!([root["collection"]]);
    let mut archive_event = event;
    archive_event
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("event fixture"))?
        .remove("provenance");
    archive["events"] = json!([archive_event]);
    archive["invoices"] = json!([{"encoded_invoice":"synthetic-not-payable","status":"expired","received_at_unix":null,"paid_at_unix":null,"cancelled_at_unix":"9007199254740993"}]);
    archive["completed_flows"] = json!(["peer_connected", "channel_opened"]);
    seed!(StateArchive, archive.clone()); // Structural nested DTO corpus; not a restorable domain fixture.
    seed!(
        RestoreArchiveRequest,
        json!({"state":archive,"confirmation_hash":hash})
    );
    let summary = json!({"peers":1,"channels":1,"factories":1,"conditional_batches":1,"multi_asset_packages":1,"root_fundings":1,"invoices":1,"completed_flows":2,"events":1,"settling_channels":1});
    seed!(
        RestorePreview,
        json!({"confirmation_hash":hash,"allowed":false,"current":summary,"candidate":summary,"ignored_completed_flows":[],"warnings":["Local projection only"]})
    );
    seed!(
        ConnectPeerRequest,
        json!({"pubkey":peer,"alias":"远端 / Peer"})
    );
    seed!(
        CreateInvoiceRequest,
        json!({"amount":"9007199254740993","description":"订阅 / Subscription","payment_preimage":null,"payment_hash":hash,"expiry_secs":"600","channel_id":null,"asset":{"kind":"ckb"}})
    );
    seed!(
        DecodeInvoiceRequest,
        json!({"encoded_invoice":"synthetic-not-payable"})
    );
    seed!(EmptyRequest, json!({}));
    seed!(SettleInvoiceRequest, json!({"payment_preimage":hash}));
    seed!(
        OpenChannelRequest,
        json!({"channel_id":hash,"counterparty_pubkey":peer,"counterparty_alias":null,"funding_context_id":hash,"local":"10","remote":"5","pending":"0","sponsor_budget":"1","asset":{"kind":"xudt","type_hash":hash}})
    );
    seed!(
        SpliceChannelRequest,
        json!({"new_funding_epoch":"18446744073709551615","new_funding_context_id":hash})
    );
    seed!(
        PublishStateRequest,
        json!({"funding_context_id":hash,"state_number":"18446744073709551615"})
    );
    seed!(
        OpenFactoryRequest,
        json!({"factory_id":hash,"participant_pubkeys":[peer],"reserve":"100","asset":{"kind":"ckb"}})
    );
    seed!(
        AdvanceFactoryRequest,
        json!({"new_update_number":"9007199254740993"})
    );
    seed!(
        MaterialiseChildRequest,
        json!({"child_channel_id":hash,"counterparty_pubkey":peer,"counterparty_alias":null,"funding_context_id":hash,"local":"10","remote":"5","pending":null,"sponsor_budget":"1","asset":{"kind":"ckb"}})
    );
    seed!(
        StoredConditionalBatchPackage,
        serde_json::to_value(conditional_packages::fixture_package()?)?
    );
    seed!(StoredMultiAssetPackage, serde_json::to_value(package()?)?);
    seed!(RootFundingDraft, root["draft"].clone());
    seed!(RootFundingCollection, root["collection"].clone());
    seed!(RootFundingExport, root["funding"].clone());
    seed!(
        RootReceiptRequest,
        json!({"target":"exit","receipt":root["exit_receipts"][0]})
    );
    seed!(
        ApiErrorBody,
        json!({"code":"revision_conflict","error":"Reload current revision","request_id":"public-request"})
    );
    let covered = cases.iter().map(|c| c.name).collect::<BTreeSet<_>>();
    for endpoint in endpoints::Endpoint::ALL {
        let spec = endpoint.spec();
        for body in [spec.request, spec.response] {
            if let endpoints::BodyContract::Json(contract)
            | endpoints::BodyContract::EventStream(contract) = body
            {
                ensure!(
                    covered.contains(contract.name),
                    "missing Hub DTO corpus: {}",
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
        .ok_or_else(|| anyhow::anyhow!("missing Hub corpus"))
}
pub(super) fn seeds() -> Result<Vec<Vec<u8>>> {
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
pub(super) fn check(bytes: &[u8]) -> Result<bool> {
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
        "Hub DTO encoding unstable: {}",
        case.name
    );
    if case.name == "Readiness" {
        let report: Readiness = serde_json::from_slice(&encoded)?;
        if !report.consistent() {
            return Ok(false);
        }
    }
    if case.name == "EventPage" {
        let page: EventPage = serde_json::from_slice(&encoded)?;
        if !page.valid_for(&EventPageRequest {
            after: None,
            limit: 64,
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hub_endpoint_dtos_have_corpus_and_strict_archives_do_not_accept_retired_or_duplicate_fields()
    {
        for seed in seeds().unwrap() {
            assert!(
                check(&seed).unwrap(),
                "{}",
                cases().unwrap()[seed[0] as usize].name
            );
            eprintln!(
                "Hub DTO corpus {}: {} ({} JSON bytes)",
                seed[0],
                cases().unwrap()[seed[0] as usize].name,
                seed.len() - 1
            );
        }
        for (index, case) in cases().unwrap().iter().enumerate() {
            if !matches!(case.name, "Readiness" | "EventPage") {
                continue;
            }
            let mut value: Value = serde_json::from_slice(&case.bytes).unwrap();
            if case.name == "Readiness" {
                value["ready"] = json!(true);
            } else {
                value["next"]["revision"] = json!("18446744073709551615");
            }
            let mut bytes = vec![index as u8];
            bytes.extend(serde_json::to_vec(&value).unwrap());
            assert!(
                !check(&bytes).unwrap(),
                "{} inconsistent summary accepted",
                case.name
            );
        }
        for name in [
            "StateArchive",
            "RestoreArchiveRequest",
            "PublishStateRequest",
            "CreateInvoiceRequest",
        ] {
            let (index, case) = cases()
                .unwrap()
                .iter()
                .enumerate()
                .find(|(_, c)| c.name == name)
                .unwrap();
            let mut value: Value = serde_json::from_slice(&case.bytes).unwrap();
            value["retired_field"] = json!(true);
            let mut bytes = vec![index as u8];
            bytes.extend(serde_json::to_vec(&value).unwrap());
            assert!(!check(&bytes).unwrap());
            let value: Value = serde_json::from_slice(&case.bytes).unwrap();
            let (key, v) = value.as_object().unwrap().iter().next().unwrap();
            let mut duplicate = case.bytes.clone();
            duplicate.pop();
            duplicate
                .extend(format!(",{}:{}}}", serde_json::to_string(key).unwrap(), v).as_bytes());
            let mut bytes = vec![index as u8];
            bytes.extend(duplicate);
            assert!(
                !check(&bytes).unwrap(),
                "{name} duplicate key lost before typed decoder"
            );
        }
        let case = cases()
            .unwrap()
            .iter()
            .find(|c| c.name == "PublishStateRequest")
            .unwrap();
        for number in [json!(1), json!("01"), json!("18446744073709551616")] {
            let mut value: Value = serde_json::from_slice(&case.bytes).unwrap();
            value["state_number"] = number;
            assert!((case.decode)(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
}
