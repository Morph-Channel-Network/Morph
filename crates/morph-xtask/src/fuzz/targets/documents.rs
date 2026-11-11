//! Canonical public fixture documents through the exact Rust SDK review API.
//! No journal, signer, RPC, private user state or alternative codec is involved.
use super::*;
use morph_sdk::packages::{
    conditional_packages, factory_packets, factory_transition_packages, multi_asset_funding,
    multi_asset_packages, multi_asset_signatures, multi_asset_splice_transaction, proposal,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    document: Value,
    base: Option<Value>,
    receipt: Option<Value>,
}
fn fixture(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(bytes)?)
}
fn encode(case: Case) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&case)?)
}

pub(super) fn seeds(signatures: bool) -> Result<Vec<Vec<u8>>> {
    let package = fixture(PACKAGE)?;
    let update = fixture(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-update.json"
    ))?;
    let factory = fixture(include_bytes!(
        "../../../../../fixtures/protocol/factory-packets.json"
    ))?;
    let mut cases = vec![Case {
        document: update["proposal"].clone(),
        base: Some(package.clone()),
        receipt: signatures.then(|| update["signature"].clone()),
    }];
    for case in factory["cases"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Factory cases missing"))?
    {
        if signatures {
            for receipt in case["signatures"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Factory receipts missing"))?
            {
                cases.push(Case {
                    document: case["request"].clone(),
                    base: None,
                    receipt: Some(receipt.clone()),
                });
            }
        } else {
            cases.push(Case {
                document: case["request"].clone(),
                base: None,
                receipt: None,
            });
        }
    }
    if signatures {
        return cases.into_iter().map(encode).collect();
    }
    for document in [
        package,
        serde_json::to_value(conditional_packages::fixture_source_package()?)?,
        serde_json::to_value(conditional_packages::fixture_package()?)?,
    ] {
        cases.push(Case {
            document,
            base: None,
            receipt: None,
        });
    }
    let root = fixture(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-root.json"
    ))?;
    for field in ["draft", "collection", "funding"] {
        cases.push(Case {
            document: root[field].clone(),
            base: None,
            receipt: None,
        });
    }
    let splice = fixture(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-splice.json"
    ))?;
    let transitions = fixture(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-splice-transitions.json"
    ))?;
    for case in std::iter::once(&splice).chain(
        transitions
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("splice corpus missing"))?,
    ) {
        for field in ["draft", "funding"] {
            cases.push(Case {
                document: case[field].clone(),
                base: Some(case["current"].clone()),
                receipt: None,
            });
        }
    }
    let transitions = fixture(FACTORY)?;
    for case in transitions["cases"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("transition corpus missing"))?
    {
        cases.push(Case {
            document: case["package"].clone(),
            base: None,
            receipt: None,
        });
    }
    cases.into_iter().map(encode).collect()
}
fn typed<T: DeserializeOwned + Serialize>(v: &Value) -> Result<Value> {
    Ok(serde_json::to_value(serde_json::from_value::<T>(
        v.clone(),
    )?)?)
}
fn canonical(document: &Value) -> Result<Value> {
    Ok(match document["schema"].as_str() {
        Some("morph.multi_asset_recovery_package.v1") => {
            typed::<multi_asset_packages::StoredMultiAssetPackage>(document)?
        }
        Some("morph.conditional_batch_package.v1") => {
            typed::<conditional_packages::StoredConditionalBatchPackage>(document)?
        }
        Some("morph.multi_asset_root_draft.v1") => {
            typed::<multi_asset_funding::RootFundingDraft>(document)?
        }
        Some("morph.multi_asset_root_collection.v1") => {
            typed::<multi_asset_funding::RootFundingCollection>(document)?
        }
        Some("morph.multi_asset_root_funding.v1") => {
            typed::<multi_asset_funding::RootFundingExport>(document)?
        }
        Some("morph.multi_asset_proposal.v1") => typed::<proposal::ProposalMessage>(document)?,
        Some("morph.multi_asset_splice_draft.v1") => {
            typed::<multi_asset_splice_transaction::SpliceDraft>(document)?
        }
        Some("morph.multi_asset_splice_funding.v1") => {
            typed::<multi_asset_splice_transaction::SpliceFundingExport>(document)?
        }
        Some("morph.factory_request.v1") => {
            typed::<factory_packets::StoredFactoryRequest>(document)?
        }
        Some("morph.factory_transition_package.v1") => {
            typed::<factory_transition_packages::StoredFactoryTransitionPackage>(document)?
        }
        _ => anyhow::bail!("untracked SDK document schema"),
    })
}
pub(super) fn check(bytes: &[u8], signatures: bool) -> Result<bool> {
    let Ok(case) = serde_json::from_slice::<Case>(bytes) else {
        return Ok(false);
    };
    let inspected = if signatures {
        let Some(receipt) = &case.receipt else {
            return Ok(false);
        };
        morph_sdk::inspection::inspect_signature(&case.document, case.base.as_ref(), receipt)
    } else {
        if case.receipt.is_some() {
            return Ok(false);
        }
        morph_sdk::inspection::inspect(&case.document, case.base.as_ref())
    };
    let Ok(expected) = inspected else {
        return Ok(false);
    };
    let document = canonical(&case.document)?;
    let needs_base = matches!(
        case.document["schema"].as_str(),
        Some(
            "morph.multi_asset_proposal.v1"
                | "morph.multi_asset_splice_draft.v1"
                | "morph.multi_asset_splice_funding.v1"
        )
    );
    let base = if needs_base {
        case.base
            .as_ref()
            .map(typed::<multi_asset_packages::StoredMultiAssetPackage>)
            .transpose()?
    } else {
        // The actual SDK intentionally ignores optional context for standalone
        // documents; this harness must not invent a stricter product contract.
        case.base.clone()
    };
    let next = if signatures {
        let receipt = case
            .receipt
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("accepted missing receipt"))?;
        let receipt = if case.document["schema"] == "morph.factory_request.v1" {
            typed::<factory_packets::FactorySignatureReceipt>(receipt)?
        } else {
            typed::<multi_asset_signatures::SignatureMessage>(receipt)?
        };
        morph_sdk::inspection::inspect_signature(&document, base.as_ref(), &receipt)?
    } else {
        morph_sdk::inspection::inspect(&document, base.as_ref())?
    };
    ensure!(
        next == expected,
        "SDK review changed after canonical typed roundtrip"
    );
    ensure!(
        canonical(&document)? == document,
        "public document encoding unstable"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_current_review_schemas_have_valid_corpus_and_wrong_authority_is_rejected() -> Result<()>
    {
        let corpus = seeds(false)?;
        let mut schemas = std::collections::BTreeSet::new();
        for seed in &corpus {
            ensure!(check(seed, false)?, "canonical document rejected");
            let case: Case = serde_json::from_slice(seed)?;
            schemas.insert(
                case.document["schema"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("schema missing"))?
                    .to_owned(),
            );
        }
        ensure!(schemas.len() == 10, "current SDK schema inventory changed");
        for seed in seeds(true)? {
            ensure!(check(&seed, true)?, "canonical signature rejected");
            let mut case: Case = serde_json::from_slice(&seed)?;
            let receipt = case
                .receipt
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("receipt missing"))?;
            receipt["signature"] = json!(format!("0x{}", "00".repeat(64)));
            ensure!(
                !check(&encode(case)?, true)?,
                "zero signature authorized review"
            );
        }
        let mut case: Case = serde_json::from_slice(&corpus[0])?;
        case.base = None;
        ensure!(
            !check(&encode(case)?, false)?,
            "proposal accepted without base"
        );
        ensure!(!check(b"{}", false)?, "missing document accepted");
        Ok(())
    }
}
