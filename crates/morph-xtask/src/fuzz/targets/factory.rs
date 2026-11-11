//! Current public FS/FM corpus. A delegated view is not an authority verifier.
use anyhow::{Result, ensure};
use morph_core::{FactoryParticipantSignature, MultiAssetManifest, MultiAssetOutPoint};
use morph_script_common::{FactorySignatureWitness, factory_multi_asset as wire};

pub(super) fn seeds(target: &str) -> Result<Vec<Vec<u8>>> {
    let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/protocol/factory-public-frames.json"
    ))?;
    corpus["cases"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing public Factory corpus"))?
        .iter()
        .filter(|case| case["target"] == target)
        .map(|case| {
            Ok(hex::decode(case["frame_hex"].as_str().ok_or_else(
                || anyhow::anyhow!("missing public Factory frame"),
            )?)?)
        })
        .collect()
}

fn signatures(value: &FactorySignatureWitness<'_>) -> Result<Vec<FactoryParticipantSignature>> {
    (0..usize::from(value.count()))
        .map(|i| {
            Ok(FactoryParticipantSignature {
                participant: value.participant(i).try_into()?,
                pubkey_sec1: value.pubkey(i).to_vec(),
                signature: value.signature(i).to_vec(),
            })
        })
        .collect()
}

pub(super) fn state(bytes: &[u8]) -> Result<bool> {
    let Ok(frame) = wire::FactoryMultiAssetStateWitness::parse(bytes) else {
        return Ok(false);
    };
    let manifest = MultiAssetManifest::decode(frame.manifest().as_bytes())?;
    let points = frame
        .points()
        .chunks_exact(36)
        .map(|point| {
            Ok(MultiAssetOutPoint {
                tx_hash: point[..32].try_into()?,
                index: u32::from_le_bytes(point[32..].try_into()?),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let auth = if frame.kind() == wire::FACTORY_STATE_WITNESS_ACTIVATE {
        ensure!(frame.signatures().is_err(), "activation acquired authority");
        Vec::new()
    } else {
        signatures(frame.signatures().map_err(|e| anyhow::anyhow!("{e:?}"))?)?
    };
    let encoded = morph_core::encode_factory_multi_asset_state_witness(
        frame.kind(),
        &manifest,
        &points,
        &auth,
    )?;
    ensure!(encoded == bytes, "FS host canonical roundtrip differs");
    Ok(true)
}

pub(super) fn materialisation(bytes: &[u8]) -> Result<bool> {
    let Ok(frame) = wire::FactoryMaterialisationWitness::parse(bytes) else {
        return Ok(false);
    };
    let intent = frame.intent();
    let views = [
        wire::FactoryMaterialisationView::parse(bytes),
        wire::FactoryMaterialisationView::from_intent_bytes(intent.as_bytes()),
    ];
    // Strong parsing must agree with both delegated consumers. The reverse is
    // intentionally not required: a view delegates authorization to Factory Type.
    for view in views {
        let view = view.map_err(|e| anyhow::anyhow!("delegated view: {e:?}"))?;
        ensure!(
            view.transaction_hash() == intent.transaction_hash(),
            "FM transaction differs"
        );
        let source = view
            .source_context()
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        ensure!(
            source.chain_id() == intent.chain_id()
                && source.factory_id() == intent.factory_id()
                && source.participants_commitment() == intent.participants_commitment()
                && source.old_state_outpoint() == intent.old_state_outpoint()
                && source.factory_carrier_capacity() == intent.factory_carrier_capacity()
                && source.source() == intent.source()
                && source.source_outpoint_root() == intent.source_outpoint_root(),
            "FM delegated source differs"
        );
        for i in 0..intent.child_count() {
            let child = intent.child(i).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let delegated = view
                .child_by_anchor(child.header.funding_anchor())
                .map_err(|e| anyhow::anyhow!("delegated child: {e:?}"))?;
            ensure!(delegated == *child, "FM delegated child differs");
        }
        ensure!(
            view.child_by_anchor(&[0; 32]).is_err(),
            "FM invented zero-anchor child"
        );
    }
    if frame.validate_public_contents().is_err() {
        return Ok(false);
    }
    let keys = (0..intent.child_count())
        .map(|i| -> Result<_> {
            Ok([
                frame
                    .child_pubkey(i, 0)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?
                    .to_vec(),
                frame
                    .child_pubkey(i, 1)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?
                    .to_vec(),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let encoded = morph_core::encode_factory_materialisation_public_witness(
        intent.as_bytes(),
        &signatures(frame.factory_signatures())?,
        &keys,
    )?;
    ensure!(encoded == bytes, "FM host canonical roundtrip differs");
    // Public shape/partition and cryptographic authorization are different. Only
    // the latter is reported accepted; no physical transaction is verified here.
    Ok(frame.verify().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_corpus_covers_all_fs_roles_and_retained_terminal_fm() -> Result<()> {
        let states = seeds("factory-state")?;
        ensure!(states.len() == 9, "missing FS dimensions");
        for bytes in states {
            ensure!(state(&bytes)?, "FS seed rejected");
            let mut unknown = bytes.clone();
            unknown[12..14].copy_from_slice(&4u16.to_le_bytes());
            ensure!(!state(&unknown)?, "unknown FS kind accepted");
            let mut trailing = bytes;
            trailing.push(0);
            ensure!(!state(&trailing)?, "FS trailing byte accepted");
        }
        let frames = seeds("factory-materialisation")?;
        ensure!(frames.len() == 3, "missing FM dimensions");
        for bytes in frames {
            ensure!(materialisation(&bytes)?, "FM seed rejected");
            let frame = wire::FactoryMaterialisationWitness::parse(&bytes)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let mut bad_signature = bytes.clone();
            let signature_start = 24 + frame.intent().as_bytes().len() + 4 + 32 + 33;
            bad_signature[signature_start..signature_start + 64].fill(0);
            ensure!(
                wire::FactoryMaterialisationView::parse(&bad_signature).is_ok(),
                "structural view unexpectedly verifies authority"
            );
            ensure!(
                !materialisation(&bad_signature)?,
                "zero FM signature accepted"
            );
            let mut trailing = bytes;
            trailing.push(0);
            ensure!(!materialisation(&trailing)?, "FM trailing byte accepted");
        }
        Ok(())
    }
}
