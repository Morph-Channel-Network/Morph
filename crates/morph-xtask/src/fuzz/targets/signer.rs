//! Public synthetic seven-role corpus. Policy/resolution stay outside mutated
//! input; public request hashes are not authority and an attacker can recompute
//! them. No actual signer journal, user key, network or VM is used here.
use super::*;
use ckb_types::{core::TransactionBuilder, packed, prelude::*};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use morph_core::{
    MultiAssetCloseProposal, MultiAssetOutPoint, ParticipantSignature, Phase,
    encode_multi_asset_witness, multi_asset_settlement_outputs,
};
use morph_sdk::packages::{
    multi_asset_close::CloseDraft,
    multi_asset_funding::RootFundingCollection,
    multi_asset_signatures::SignatureMessage,
    multi_asset_splice_transaction::SpliceDraft,
    signer_protocol::{
        CodeIdentity, Deployment, InputResolver, Payload, Policy, Request, ResolvedInputs,
        Response, Target, VERSION,
    },
};
use std::sync::OnceLock;

struct Resolver {
    points: Vec<MultiAssetOutPoint>,
    capacities: Vec<u64>,
}
impl InputResolver for Resolver {
    fn resolve_live(&self, inputs: &[MultiAssetOutPoint]) -> Result<ResolvedInputs> {
        ensure!(
            inputs == self.points,
            "input set changed from pinned evidence"
        );
        Ok(ResolvedInputs {
            genesis_hash: [91; 32],
            capacities: self.capacities.clone(),
        })
    }
}
struct Case {
    policy: Policy,
    resolver: Resolver,
    request: Request,
    response: Response,
}
fn code(bytes: &[u8]) -> Result<CodeIdentity> {
    let script = packed::Script::from_slice(bytes)?;
    Ok(CodeIdentity {
        code_hash: format!("0x{}", hex::encode(script.code_hash().as_slice())),
        hash_type: u8::from(script.hash_type()),
    })
}
fn close_case(
    base: &StoredMultiAssetPackage,
) -> Result<(Payload, packed::Transaction, SignatureMessage)> {
    let current = base.recovery()?;
    let header_bytes = current.state.encode()?;
    let witness_bytes = encode_multi_asset_witness(
        &current.manifest,
        &current.settlement,
        &current.outpoints,
        &current.scripts,
    )?;
    let header =
        wire::MultiAssetStateHeader::parse(&header_bytes).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let witness =
        wire::MultiAssetWitness::parse(&witness_bytes).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let source_outpoint = MultiAssetOutPoint {
        tx_hash: [77; 32],
        index: 0,
    };
    let mut builder = TransactionBuilder::default().input(packed::CellInput::new(
        packed::OutPoint::new(source_outpoint.tx_hash.pack(), 0),
        0,
    ));
    for point in &current.outpoints {
        builder = builder.input(packed::CellInput::new(
            packed::OutPoint::new(point.tx_hash.pack(), point.index),
            0,
        ));
    }
    for (output, data) in
        multi_asset_settlement_outputs(&witness, &header, current.state_carrier_capacity)?
    {
        builder = builder.output(output).output_data(data.pack());
    }
    let tx = builder.build().data();
    let mut source_state = current.state.clone();
    source_state.header.phase = Phase::Active;
    source_state.header.state_number = 0;
    let proposal = MultiAssetCloseProposal {
        source_outpoint,
        source_state,
        transaction: tx.raw().as_slice().to_vec(),
    };
    let digest = proposal.signing_digest(&current)?;
    // Known public fixture key, never production authority.
    let key = SigningKey::from_slice(&[1; 32])?;
    let signature: Signature = key.sign_prehash(&digest)?;
    let receipt = SignatureMessage::new(
        &digest,
        &ParticipantSignature {
            pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        },
    );
    Ok((
        Payload::CooperativeClose {
            current: Box::new(base.clone()),
            draft: CloseDraft::from_proposal(&proposal)?,
        },
        tx,
        receipt,
    ))
}
fn build_cases() -> Result<Vec<Case>> {
    let root: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-root.json"
    ))?;
    let splice: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-splice.json"
    ))?;
    let update: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-update.json"
    ))?;
    let base = package()?;
    let mut cases = Vec::new();
    for target in [
        Target::RootExit,
        Target::RootCreation,
        Target::Update,
        Target::SpliceCreation,
        Target::SpliceRecovery,
        Target::SpliceBridge,
        Target::CooperativeClose,
    ] {
        let (payload, package, tx, receipt): (_, _, _, SignatureMessage) = match target {
            Target::RootExit | Target::RootCreation => {
                let collection: RootFundingCollection =
                    serde_json::from_value(root["collection"].clone())?;
                let (_, package) = collection.draft.evidence()?;
                let tx = collection.draft.transaction()?;
                let receipt = serde_json::from_value(
                    root[if target == Target::RootExit {
                        "exit_receipts"
                    } else {
                        "creation_receipts"
                    }][0]
                        .clone(),
                )?;
                (
                    Payload::Root {
                        collection: Box::new(collection),
                    },
                    package,
                    Some(tx),
                    receipt,
                )
            }
            Target::Update => (
                Payload::Update {
                    current: Box::new(base.clone()),
                    proposal: serde_json::from_value(update["proposal"].clone())?,
                },
                base.recovery()?,
                None,
                serde_json::from_value(update["signature"].clone())?,
            ),
            Target::CooperativeClose => {
                let (payload, tx, receipt) = close_case(&base)?;
                (payload, base.recovery()?, Some(tx), receipt)
            }
            _ => {
                let current: StoredMultiAssetPackage =
                    serde_json::from_value(splice["current"].clone())?;
                let package = current.recovery()?;
                let draft: SpliceDraft = serde_json::from_value(splice["draft"].clone())?;
                let tx = draft.transaction()?;
                let receipt = serde_json::from_value(
                    splice[match target {
                        Target::SpliceCreation => "creation_receipts",
                        Target::SpliceRecovery => "recovery_receipts",
                        _ => "bridge_receipts",
                    }][0]
                        .clone(),
                )?;
                (
                    Payload::Splice {
                        current: Box::new(current),
                        draft,
                        creation_receipts: serde_json::from_value(
                            splice["creation_receipts"].clone(),
                        )?,
                        recovery_receipts: serde_json::from_value(
                            splice["recovery_receipts"].clone(),
                        )?,
                    },
                    package,
                    Some(tx),
                    receipt,
                )
            }
        };
        let policy = Policy {
            expected_pubkey: receipt.pubkey.clone(),
            network_genesis: [91; 32],
            chain_id: package.state.header.chain_id,
            deployments: vec![Deployment {
                state_type: code(&package.scripts.state_type)?,
                state_lock: code(&package.scripts.state_lock)?,
                vault_lock: code(&package.scripts.vault_lock)?,
            }],
            targets: vec![target],
            max_request_lifetime_secs: 60,
        };
        let resolver = if let Some(tx) = tx {
            let points = tx
                .raw()
                .inputs()
                .into_iter()
                .map(|input| MultiAssetOutPoint {
                    tx_hash: input.previous_output().tx_hash().unpack(),
                    index: u32::from(input.previous_output().index()),
                })
                .collect::<Vec<_>>();
            let total = tx
                .raw()
                .outputs()
                .into_iter()
                .try_fold(1000u64, |sum, output| {
                    sum.checked_add(u64::from(output.capacity()))
                        .ok_or_else(|| anyhow::anyhow!("fixture capacity overflow"))
                })?;
            let mut capacities = vec![0; points.len()];
            *capacities
                .first_mut()
                .ok_or_else(|| anyhow::anyhow!("fixture inputs missing"))? = total;
            Resolver { points, capacities }
        } else {
            Resolver {
                points: vec![],
                capacities: vec![],
            }
        };
        let request = Request::prepare(payload, target, 150, &policy, &resolver, 100)?;
        ensure!(
            request.review.signing_digest == receipt.signing_digest,
            "fixture digest mismatch"
        );
        let response = Response {
            version: VERSION.into(),
            request_id: request.request_id.clone(),
            target,
            receipt,
        };
        response.verify(&request)?;
        cases.push(Case {
            policy,
            resolver,
            request,
            response,
        });
    }
    Ok(cases)
}
fn cases() -> Result<&'static [Case]> {
    static CASES: OnceLock<Vec<Case>> = OnceLock::new();
    if CASES.get().is_none() {
        let _ = CASES.set(build_cases()?);
    }
    CASES
        .get()
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow::anyhow!("missing signer corpus"))
}
pub(super) fn seeds(name: &str) -> Result<Vec<Vec<u8>>> {
    cases()?
        .iter()
        .enumerate()
        .map(|(i, case)| {
            let mut bytes = vec![u8::try_from(i)?]; // Harness selector, not production wire.
            bytes.extend(if name == "signer-response" {
                serde_json::to_vec(&case.response)?
            } else {
                case.request.encode()?
            });
            Ok(bytes)
        })
        .collect()
}
fn reidentify(request: &mut Request) -> Result<()> {
    // Attacker-side public-hash recomputation; never use this to grant policy.
    let mut value = serde_json::to_value(&*request)?;
    value["request_id"] = json!("");
    value.sort_all_objects();
    let mut bytes = b"MORPH_EXTERNAL_PARTICIPANT_REQUEST_V1\0".to_vec();
    bytes.extend(serde_json::to_vec(&value)?);
    request.request_id = format!("0x{}", hex::encode(morph_core::blake2b256(&bytes)));
    Ok(())
}
pub(super) fn check(name: &str, bytes: &[u8]) -> Result<bool> {
    let Some((&selector, bytes)) = bytes.split_first() else {
        return Ok(false);
    };
    let Some(case) = cases()?.get(usize::from(selector)) else {
        return Ok(false);
    };
    if name == "signer-response" {
        let Ok(response) = Response::decode(bytes) else {
            return Ok(false);
        };
        let Ok(signature) = response.verify(&case.request) else {
            return Ok(false);
        };
        let encoded = serde_json::to_vec(&response)?;
        let again = Response::decode(&encoded)?;
        ensure!(
            again.verify(&case.request)? == signature,
            "response roundtrip changed verified signature"
        );
        ensure!(
            serde_json::to_vec(&again)? == encoded,
            "unstable response encoding"
        );
        for other in cases()? {
            if other.request.request_id != case.request.request_id {
                ensure!(
                    response.verify(&other.request).is_err(),
                    "receipt crossed role/context"
                );
            }
        }
    } else {
        let Ok(mut request) = Request::decode(bytes) else {
            return Ok(false);
        };
        if name == "signer-review" {
            reidentify(&mut request)?;
        }
        if request.validate(&case.policy, &case.resolver, 100).is_err() {
            return Ok(false);
        }
        let encoded = request.encode()?;
        let again = Request::decode(&encoded)?;
        again.validate(&case.policy, &case.resolver, 100)?;
        ensure!(again.encode()? == encoded, "unstable request encoding");
        ensure!(
            request.review.target == case.request.review.target,
            "cross-role request accepted"
        );
        ensure!(
            request.review.domain == case.request.review.domain,
            "cross-domain request accepted"
        );
        ensure!(
            request
                .validate(&case.policy, &case.resolver, request.expires_at_unix)
                .is_err(),
            "expired request accepted"
        );
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seven_signer_roles_reject_rehashed_review_substitution_and_cross_context_receipts() {
        for name in ["signer-request", "signer-review", "signer-response"] {
            let seeds = seeds(name).unwrap();
            assert_eq!(seeds.len(), 7);
            for seed in seeds {
                assert!(check(name, &seed).unwrap());
            }
        }
        for (index, case) in cases().unwrap().iter().enumerate() {
            for field in [
                "signing_digest",
                "funding_context_id",
                "chain_id",
                "carrier_refund_lock_hash",
            ] {
                let mut value = serde_json::to_value(&case.request).unwrap();
                value["review"][field] = json!(format!("0x{}", "99".repeat(32)));
                let mut bad: Request = serde_json::from_value(value).unwrap();
                reidentify(&mut bad).unwrap();
                // Prove the negative reached full review, not just ID rejection.
                bad.validate_envelope(&case.policy, 100).unwrap();
                assert!(bad.validate(&case.policy, &case.resolver, 100).is_err());
                let mut bytes = vec![index as u8];
                bytes.extend(bad.encode().unwrap());
                assert!(!check("signer-review", &bytes).unwrap());
            }
            let mut bad = case.response.clone();
            bad.receipt.signature = format!("0x{}", "00".repeat(64));
            let mut bytes = vec![index as u8];
            bytes.extend(serde_json::to_vec(&bad).unwrap());
            assert!(!check("signer-response", &bytes).unwrap());
        }
    }
}
