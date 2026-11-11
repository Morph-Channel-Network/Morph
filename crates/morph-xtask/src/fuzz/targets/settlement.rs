use super::*;
use morph_core::{
    ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant, ConditionalResolution,
    ConditionalTransferSpec,
};
use morph_script_common as script;
use std::collections::BTreeMap;
fn error(e: script::ScriptError) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

pub(super) fn resolution_seeds() -> Result<Vec<Vec<u8>>> {
    let mut seeds = vec![];
    for (typed, count) in [(false, 1), (false, 8), (true, 1), (true, 8)] {
        let large = u64::MAX as u128 + 123;
        let batch = ConditionalBatch {
            asset: if typed {
                morph_core::VaultAsset::Xudt([10; 32])
            } else {
                morph_core::VaultAsset::Ckb
            },
            batch_id: [11; 32],
            application_context_commitment: [12; 32],
            participants: [1, 2].map(|tag| ConditionalParticipant {
                settlement_lock_hash: [tag; 32],
                settled_capacity: 100_000_000_000,
                settled_amount: if typed { large } else { 0 },
            }),
            transfers: (0..count)
                .map(|i| {
                    let algorithm = if i % 2 == 0 {
                        script::CONDITIONAL_HASH_CKB_BLAKE2B
                    } else {
                        script::CONDITIONAL_HASH_SHA256
                    };
                    Ok(ConditionalTransferSpec {
                        transfer_id: [20 + i; 32],
                        payer_lock_hash: [1 + i % 2; 32],
                        hash_algorithm: if i % 2 == 0 {
                            ConditionalHashAlgorithm::CkbBlake2b
                        } else {
                            ConditionalHashAlgorithm::Sha256
                        },
                        payment_hash: script::conditional_payment_hash(algorithm, &[40 + i; 32])
                            .map_err(error)?,
                        amount: if typed { large } else { 1_000_000_000 },
                        refund_after_block: 500 + u64::from(i),
                    })
                })
                .collect::<Result<_>>()?,
        };
        for mode in 0..3 {
            let resolutions = (0..count)
                .map(|i| {
                    (
                        [20 + i; 32],
                        if mode == 1 || (mode == 2 && i % 2 == 1) {
                            ConditionalResolution::Refund
                        } else {
                            ConditionalResolution::Fulfill {
                                preimage: [40 + i; 32],
                            }
                        },
                    )
                })
                .collect();
            let since = if mode == 0 { 0 } else { 1000u64 };
            let mut raw = since.to_le_bytes().to_vec();
            raw.extend(batch.encode_resolution_witness(&resolutions)?);
            seeds.push(raw);
        }
    }
    Ok(seeds)
}
pub(super) fn resolution(bytes: &[u8]) -> Result<bool> {
    if bytes.len() < 8 {
        return Ok(false);
    }
    let since = u64::from_le_bytes(bytes[..8].try_into()?);
    let raw = &bytes[8..];
    let Ok(witness) = script::ConditionalBatchResolutionWitness::parse(raw) else {
        return Ok(false);
    };
    // Decode via the host codec as well; reconstruct each actual resolution.
    let batch = ConditionalBatch::decode_descriptor(witness.descriptor().map_err(error)?.raw())?;
    let mut resolutions = BTreeMap::new();
    for (i, transfer) in batch.transfers.iter().enumerate() {
        let item = witness.resolution(i).map_err(error)?;
        resolutions.insert(
            transfer.transfer_id,
            match item.kind() {
                script::CONDITIONAL_RESOLUTION_FULFILL => ConditionalResolution::Fulfill {
                    preimage: item.preimage().try_into()?,
                },
                script::CONDITIONAL_RESOLUTION_REFUND => ConditionalResolution::Refund,
                _ => anyhow::bail!("parsed unknown resolution kind"),
            },
        );
    }
    ensure!(
        batch.encode_resolution_witness(&resolutions)?.as_slice() == raw,
        "resolution canonical roundtrip differs"
    );
    let script = witness.resolved_values(since);
    let host = batch.resolve(&resolutions, since);
    ensure!(
        script.is_ok() == host.is_ok(),
        "host/script resolution acceptance differs"
    );
    let Ok(actual) = script else {
        return Ok(false);
    };
    ensure!(
        host? == actual.map(morph_core::ConditionalValue::from),
        "host/script payouts differ"
    );
    // Independent recipient/accounting oracle; no resolve() call to compute it.
    let mut capacities = batch.participants.each_ref().map(|p| p.settled_capacity);
    let mut amounts = batch.participants.each_ref().map(|p| p.settled_amount);
    for transfer in &batch.transfers {
        let payer =
            usize::from(transfer.payer_lock_hash != batch.participants[0].settlement_lock_hash);
        let recipient = if matches!(
            resolutions[&transfer.transfer_id],
            ConditionalResolution::Refund
        ) {
            payer
        } else {
            1 - payer
        };
        if batch.asset == morph_core::VaultAsset::Ckb {
            capacities[recipient] = capacities[recipient]
                .checked_add(u64::try_from(transfer.amount)?)
                .ok_or_else(|| anyhow::anyhow!("accepted CKB resolution overflows"))?;
        } else {
            amounts[recipient] = amounts[recipient]
                .checked_add(transfer.amount)
                .ok_or_else(|| anyhow::anyhow!("accepted UDT resolution overflows"))?;
        }
    }
    ensure!(
        actual.map(|v| v.capacity) == capacities
            && actual.map(|v| v.amount) == amounts
            && capacities[0].checked_add(capacities[1]) == Some(batch.total_capacity()?)
            && amounts[0].checked_add(amounts[1]) == Some(batch.total_amount()?),
        "resolution payment conservation differs"
    );
    Ok(true)
}

pub(super) fn argument_seeds() -> Result<Vec<Vec<u8>>> {
    let since = script::relative_block_since(42).map_err(error)?;
    let mut direct = vec![0];
    direct.extend([1; 32]);
    direct.extend(since.to_le_bytes());
    let mut child = vec![0];
    child.extend([1; 32]);
    child.extend([2; 32]);
    child.extend(since.to_le_bytes());
    let mut vault = vec![1];
    vault.extend(
        wire::encode_multi_asset_vault_args(&[1; 32], since, &[2; 32], &[3; 32]).map_err(error)?,
    );
    let mut sponsor = vec![2];
    sponsor.extend([1; 32]);
    for value in [1u64, 9, 1000, 10000, 20] {
        sponsor.extend(value.to_le_bytes());
    }
    sponsor.extend([2; 32]);
    sponsor.extend([3; 32]);
    let mut factory = vec![3];
    factory.extend(
        script::factory_multi_asset::encode_factory_multi_asset_type_args(&[4; 32])
            .map_err(error)?,
    );
    Ok(vec![direct, child, vault, sponsor, factory])
}
pub(super) fn arguments(bytes: &[u8]) -> Result<bool> {
    let Some((&tag, raw)) = bytes.split_first() else {
        return Ok(false);
    };
    let encoded = match tag {
        0 => {
            let Ok(args) = wire::MultiAssetStateTypeArgs::parse(raw) else {
                return Ok(false);
            };
            let mut b = args.funding_anchor().to_vec();
            if let Some(origin) = args.factory_origin() {
                b.extend(origin);
            }
            b.extend(args.finalise_since().to_le_bytes());
            b
        }
        1 => {
            let Ok(args) = wire::MultiAssetVaultArgs::parse(raw) else {
                return Ok(false);
            };
            wire::encode_multi_asset_vault_args(
                args.funding_anchor().try_into()?,
                args.finalise_since(),
                args.state_type_hash().try_into()?,
                args.state_lock_hash().try_into()?,
            )
            .map_err(error)?
            .to_vec()
        }
        2 => {
            let Ok(args) = script::SponsorPolicy::parse(raw) else {
                return Ok(false);
            };
            let mut b = args.channel_id().to_vec();
            for v in [
                args.min_state_number(),
                args.max_state_number(),
                args.max_fee_per_tx(),
                args.max_total_fee(),
                args.already_spent(),
            ] {
                b.extend(v.to_le_bytes());
            }
            b.extend(args.publication_state_type_hash());
            b.extend(args.change_lock());
            b
        }
        3 => {
            let Ok(id) = script::factory_multi_asset::parse_factory_multi_asset_type_args(raw)
            else {
                return Ok(false);
            };
            script::factory_multi_asset::encode_factory_multi_asset_type_args(id.try_into()?)
                .map_err(error)?
                .to_vec()
        }
        _ => return Ok(false),
    };
    ensure!(encoded == raw, "script argument reconstruction differs");
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_batch_fulfill_refund_and_argument_corpus_rejects_semantic_tampering() -> Result<()> {
        let seeds = resolution_seeds()?;
        for seed in &seeds {
            ensure!(resolution(seed)?, "resolution seed rejected");
        }
        let mut preimage = seeds[0].clone();
        let descriptor_len =
            script::ConditionalBatchDescriptor::encoded_len(&preimage[12..]).map_err(error)?;
        preimage[12 + descriptor_len + 1] ^= 1;
        ensure!(!resolution(&preimage)?, "wrong preimage accepted");
        let mut immature = seeds[1].clone();
        immature[..8].copy_from_slice(&499u64.to_le_bytes());
        ensure!(!resolution(&immature)?, "immature refund accepted");
        immature[..8].copy_from_slice(
            &script::relative_block_since(1000)
                .map_err(error)?
                .to_le_bytes(),
        );
        ensure!(
            !resolution(&immature)?,
            "relative since accepted as absolute refund"
        );
        for seed in argument_seeds()? {
            ensure!(arguments(&seed)?, "argument seed rejected");
        }
        let mut child = argument_seeds()?[1].clone();
        child[33..65].fill(0);
        ensure!(!arguments(&child)?, "zero Factory origin accepted");
        let factory = argument_seeds()?[4].clone();
        for offset in [1, 9, 11, 13] {
            let mut bad = factory.clone();
            if offset == 13 {
                bad[offset..].fill(0);
            } else {
                bad[offset] ^= 1;
            }
            ensure!(!arguments(&bad)?, "invalid Factory argument accepted");
        }
        ensure!(
            !arguments(&factory[..44])?,
            "truncated Factory argument accepted"
        );
        let mut extended = factory;
        extended.push(0);
        ensure!(!arguments(&extended)?, "extended Factory argument accepted");
        Ok(())
    }
}
