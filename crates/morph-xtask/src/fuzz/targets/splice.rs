use super::*;
use morph_core::{
    MultiAssetSpliceFlow, MultiAssetValue, ParticipantSignature, StateAuthorization, VaultAsset,
};
use morph_script_common::multi_asset_splice as splice;
use morph_sdk::packages::{
    multi_asset_signatures::SignatureMessage, multi_asset_splice_transaction::SpliceDraft,
};

fn error(e: morph_script_common::ScriptError) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}
fn authority(
    value: &Value,
    digest: &[u8; 32],
    participants: &[String; 2],
) -> Result<StateAuthorization> {
    let messages: Vec<SignatureMessage> = serde_json::from_value(value.clone())?;
    let mut signatures = messages
        .iter()
        .map(|s| s.verify(digest, participants))
        .collect::<Result<Vec<_>>>()?;
    signatures.sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
    Ok(StateAuthorization {
        threshold: 2,
        signatures,
    })
}
pub(super) fn seeds(flows_only: bool) -> Result<Vec<Vec<u8>>> {
    let first: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-splice.json"
    ))?;
    let others: Vec<Value> = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/multi-asset-splice-transitions.json"
    ))?;
    std::iter::once(first)
        .chain(others)
        .map(|case| {
            let current: StoredMultiAssetPackage = serde_json::from_value(case["current"].clone())?;
            let current = current.recovery()?;
            let draft: SpliceDraft = serde_json::from_value(case["draft"].clone())?;
            let mut plan = draft.proposal(&current)?;
            if flows_only {
                return Ok(morph_core::encode_multi_asset_splice_flows(&plan.flows)?);
            }
            let participants: [String; 2] = current
                .authorization
                .signatures
                .iter()
                .map(|s| format!("0x{}", hex::encode(&s.pubkey_sec1)))
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| anyhow::anyhow!("bilateral corpus membership"))?;
            plan.new_state_authorization = authority(
                &case["creation_receipts"],
                &plan.new_state.signing_digest()?,
                &participants,
            )?;
            let recovery = plan.initial_recovery_contents(&current)?;
            plan.initial_recovery_authorization = authority(
                &case["recovery_receipts"],
                &recovery.state.signing_digest()?,
                &participants,
            )?;
            let bridge = authority(
                &case["bridge_receipts"],
                &plan.intent_digest(&current)?,
                &participants,
            )?;
            // Test-only prefix supplies the old header normally loaded from CKB.
            let mut bytes = current.state.encode()?.to_vec();
            bytes.extend(plan.encode_witness(&current, &bridge)?);
            Ok(bytes)
        })
        .collect()
}
fn flows(table: &splice::MultiAssetSpliceFlows<'_>) -> Result<Vec<u8>> {
    let values = (0..table.count())
        .map(|i| {
            let flow = table.entry(i).map_err(error)?;
            let value = |v: wire::MultiAssetAllocation| MultiAssetValue {
                reserve: v.reserve,
                business_ckb: v.business_ckb,
                amount: v.amount,
            };
            Ok(MultiAssetSpliceFlow {
                asset: if flow.asset.kind == 0 {
                    VaultAsset::Ckb
                } else {
                    VaultAsset::Xudt(flow.asset.type_hash)
                },
                deposit: value(flow.deposit),
                withdrawal: value(flow.withdrawal),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let encoded = morph_core::encode_multi_asset_splice_flows(&values)?;
    ensure!(
        morph_core::multi_asset_splice_flow_commitment(&values)? == table.commitment(),
        "splice flow host/script commitment differs"
    );
    Ok(encoded)
}
pub(super) fn check(bytes: &[u8], flows_only: bool) -> Result<bool> {
    if flows_only {
        let Ok(table) = splice::MultiAssetSpliceFlows::parse(bytes) else {
            return Ok(false);
        };
        ensure!(
            flows(&table)? == bytes,
            "splice flow canonical roundtrip differs"
        );
        return Ok(true);
    }
    if bytes.len() < wire::MULTI_ASSET_STATE_HEADER_LEN {
        return Ok(false);
    }
    let (before, raw) = bytes.split_at(wire::MULTI_ASSET_STATE_HEADER_LEN);
    let (Ok(before), Ok(frame)) = (
        wire::MultiAssetStateHeader::parse(before),
        splice::MultiAssetSpliceWitness::parse(raw),
    ) else {
        return Ok(false);
    };
    // Includes per-asset conservation, old context/OutPoints and actual bridge
    // signatures. It does not simulate live cells or the complete VM transaction.
    if frame.validate_old_header(&before).is_err() {
        return Ok(false);
    }
    let h = frame.header();
    let header = splice::encode_multi_asset_splice_header(
        h.old_context().try_into()?,
        h.old_state_outpoint().try_into()?,
        h.new_state_digest().try_into()?,
        h.flow_commitment().try_into()?,
        h.withdrawal_lock_hash().try_into()?,
        h.transaction_hash().try_into()?,
    )
    .map_err(error)?;
    let flow_bytes = flows(frame.flows())?;
    let signatures = StateAuthorization {
        threshold: frame.signatures().threshold(),
        signatures: (0..usize::from(frame.signatures().count()))
            .map(|i| ParticipantSignature {
                pubkey_sec1: frame.signatures().pubkey(i).to_vec(),
                signature: frame.signatures().signature(i).to_vec(),
            })
            .collect(),
    };
    let manifest = MultiAssetManifest::decode(frame.old_manifest().as_bytes())?.encode()?;
    let evidence = frame.new_evidence().as_bytes();
    let withdrawal = frame.withdrawal_script();
    let mut encoded = vec![0; splice::MULTI_ASSET_SPLICE_PREFIX_LEN];
    encoded[..8].copy_from_slice(splice::MULTI_ASSET_SPLICE_MAGIC);
    encoded[8..10].copy_from_slice(&splice::MULTI_ASSET_SPLICE_FORMAT.to_le_bytes());
    encoded[12..16].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    encoded[16..18].copy_from_slice(&(frame.old_manifest().count() as u16).to_le_bytes());
    encoded[20..24].copy_from_slice(&(evidence.len() as u32).to_le_bytes());
    encoded[24..28].copy_from_slice(&(withdrawal.len() as u32).to_le_bytes());
    encoded[28..32].copy_from_slice(&(flow_bytes.len() as u32).to_le_bytes());
    encoded.extend(header);
    encoded.extend(frame.new_header().as_bytes());
    encoded.extend(morph_core::encode_multi_asset_signatures(&signatures)?);
    encoded.extend(manifest);
    encoded.extend(frame.old_outpoints());
    encoded.extend(evidence);
    encoded.extend(withdrawal);
    encoded.extend(flow_bytes);
    ensure!(encoded == raw, "splice frame canonical roundtrip differs");
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_splice_frames_flows_and_tampered_bridge_authority() -> Result<()> {
        for seed in seeds(false)? {
            ensure!(check(&seed, false)?, "splice seed rejected");
            let start = wire::MULTI_ASSET_STATE_HEADER_LEN + splice::MULTI_ASSET_SPLICE_PREFIX_LEN;
            let mut changed = seed.clone();
            changed[start + 168] ^= 1; // exact transaction hash is signed
            ensure!(
                !check(&changed, false)?,
                "changed transaction retains bridge authority"
            );
            let mut changed = seed;
            let sig =
                start + splice::MULTI_ASSET_SPLICE_HEADER_LEN + wire::MULTI_ASSET_STATE_HEADER_LEN;
            changed[sig + 4 + 33] ^= 1;
            ensure!(
                !check(&changed, false)?,
                "changed bridge signature accepted"
            );
        }
        for seed in seeds(true)? {
            ensure!(check(&seed, true)?, "flow seed rejected");
            let mut changed = seed;
            changed[2] = 1;
            ensure!(!check(&changed, true)?, "reserved flow bytes ignored");
        }
        Ok(())
    }
}
