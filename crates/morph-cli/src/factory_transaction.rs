//! Native current Factory preparation. Context exports are evidence, not
//! signer authority. Every constructed request passes the shared core exact
//! body validator; live-chain admission still precedes every private-key use.
use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use morph_core::*;
use morph_script_common::factory_multi_asset as wire;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::canonical_fields::{decimal_u64, decimal_u128, hash};
use crate::factory_context::FactoryPreparationContext;
use crate::factory_packets::FactoryRightTerms;
use crate::factory_root_transaction::FactoryReserveTerms;
use crate::funding_wallets::{
    FundingCell, FundingWallet, WalletTransaction, build_wallet_transaction,
};
use crate::multi_asset_packages::{StoredMultiAssetCellDep, decode_dependency_records, decode_hex};
use crate::persistence::required_option;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryPayoutTerms {
    #[serde(deserialize_with = "required_option")]
    pub type_hash: Option<String>,
    pub reserve: String,
    pub business_ckb: String,
    pub amount: String,
    pub lock_script_hex: String,
}
impl FactoryPayoutTerms {
    fn decode(&self, output_index: u16) -> Result<FactoryReducedReleasePayout> {
        Ok(FactoryReducedReleasePayout {
            asset: self
                .type_hash
                .as_deref()
                .map(hash)
                .transpose()?
                .map_or(VaultAsset::Ckb, VaultAsset::Xudt),
            value: MultiAssetValue {
                reserve: decimal_u64(&self.reserve)?,
                business_ckb: decimal_u64(&self.business_ckb)?,
                amount: decimal_u128(&self.amount)?,
            },
            lock_script: decode_hex(&self.lock_script_hex, 512)?,
            output_index,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FactoryPreparationOperation {
    Metadata {
        access_manifest_root: String,
    },
    ReducedRights {
        participant: String,
    },
    ReducedRelease {
        participant: String,
        retained: Vec<FactoryReserveTerms>,
        payouts: Vec<FactoryPayoutTerms>,
    },
    ReducedDeposit {
        participant: String,
        retained: Vec<FactoryReserveTerms>,
        type_scripts_hex: Vec<String>,
    },
    ReducedChild {
        participant: String,
        retained: Vec<FactoryReserveTerms>,
        children: Vec<FactoryChildTerms>,
    },
    Materialise {
        #[serde(deserialize_with = "required_option")]
        retained: Option<Vec<FactoryReserveTerms>>,
        children: Vec<FactoryChildTerms>,
        carrier_refund_lock_hex: String,
        access_manifest_root: String,
    },
    FullCustody {
        retained: Vec<FactoryReserveTerms>,
        payouts: Vec<FactoryPayoutTerms>,
        type_scripts_hex: Vec<String>,
        access_manifest_root: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryChildTerms {
    pub channel: crate::channel_creation::ChannelCreationTerms,
    pub state_type_code_hash: String,
    pub state_lock_code_hash: String,
    pub vault_lock_code_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryPreparationTerms {
    pub schema: String,
    pub context: FactoryPreparationContext,
    pub intent: FactoryPreparationOperation,
    pub target_rights: Vec<FactoryRightTerms>,
    pub cell_deps: Vec<StoredMultiAssetCellDep>,
    pub funders: Vec<FundingWallet>,
}
impl FactoryPreparationTerms {
    #[cfg(feature = "devnet")]
    pub(crate) fn points(&self) -> Result<Vec<packed::OutPoint>> {
        crate::funding_wallets::funding_points(&self.funders)
    }
    pub(crate) fn build(
        &self,
        cells: &[FundingCell],
        max_fee: u64,
    ) -> Result<FactorySigningRequest> {
        ensure!(
            self.schema == "morph.factory_preparation_terms.v1",
            "unsupported Factory preparation schema"
        );
        match &self.intent {
            FactoryPreparationOperation::ReducedChild {
                participant,
                retained,
                children,
            } => {
                return self.build_children(
                    cells,
                    max_fee,
                    ChildPreparation {
                        participant: Some(participant),
                        retained: Some(retained),
                        children,
                        carrier_refund_lock: None,
                        access_manifest_root: None,
                    },
                );
            }
            FactoryPreparationOperation::Materialise {
                retained,
                children,
                carrier_refund_lock_hex,
                access_manifest_root,
            } => {
                return self.build_children(
                    cells,
                    max_fee,
                    ChildPreparation {
                        participant: None,
                        retained: retained.as_deref(),
                        children,
                        carrier_refund_lock: Some(carrier_refund_lock_hex),
                        access_manifest_root: Some(access_manifest_root),
                    },
                );
            }
            _ => {}
        }

        let (source, members, before_rights) = self.context.decode()?;
        let target_rights = self
            .target_rights
            .iter()
            .map(FactoryRightTerms::decode)
            .collect::<Result<Vec<_>>>()?;
        let deps = decode_dependency_records(&self.cell_deps)?;
        let mut after = source.state()?.fields();
        after.update_number = after
            .update_number
            .checked_add(1)
            .context("Factory counter exhausted")?;
        after.state_root = factory_right_sparse_root(&target_rights)?;
        if let FactoryPreparationOperation::Metadata {
            access_manifest_root,
        } = &self.intent
        {
            after.access_manifest_root = hash(access_manifest_root)?;
            let fixed_outputs = vec![(
                state_output(&source)?,
                Bytes::from(
                    after
                        .encode()
                        .map_err(|e| anyhow!("Factory header: {e:?}"))?
                        .to_vec(),
                ),
            )];
            let (transaction, _) = build_wallet_transaction(
                &self.funders,
                cells,
                WalletTransaction {
                    prefix: source_cells(&source, false)?,
                    outputs: fixed_outputs,
                    state_indices: vec![0],
                    type_scripts: source.type_scripts.clone(),
                    cell_deps: deps,
                    witness: packed::WitnessArgs::default(),
                },
                max_fee,
            )?;
            let mut target = source.clone();
            target.header = after
                .encode()
                .map_err(|e| anyhow!("Factory header: {e:?}"))?
                .to_vec();
            target.state_out_point = MultiAssetOutPoint {
                tx_hash: transaction.calc_tx_hash().unpack(),
                index: 0,
            };
            let request = FactorySigningRequest {
                role: FactorySigningRole::MetadataUpdate,
                source: Some(source.clone()),
                target: Some(target),
                transaction: transaction.raw().as_slice().to_vec(),
                witness: encode_factory_multi_asset_state_witness(
                    wire::FACTORY_STATE_WITNESS_UPDATE,
                    &source.manifest,
                    &source.vault_outpoints,
                    &placeholders(&members),
                )?,
                target_rights,
                deliveries: vec![],
            };
            request.validate(&members)?;
            return Ok(request);
        }
        let (operation, participant, reserve_terms, payout_terms, additional_types, access) =
            match &self.intent {
                FactoryPreparationOperation::Metadata { .. }
                | FactoryPreparationOperation::ReducedChild { .. }
                | FactoryPreparationOperation::Materialise { .. } => {
                    return Err(anyhow!("specialized preparation already handled"));
                }
                FactoryPreparationOperation::ReducedRights { participant } => (
                    FactoryTransitionOperation::ReducedRights,
                    Some(participant),
                    None,
                    &[][..],
                    &[][..],
                    None,
                ),
                FactoryPreparationOperation::ReducedRelease {
                    participant,
                    retained,
                    payouts,
                } => (
                    FactoryTransitionOperation::ReducedRelease,
                    Some(participant),
                    Some(retained),
                    payouts.as_slice(),
                    &[][..],
                    None,
                ),
                FactoryPreparationOperation::ReducedDeposit {
                    participant,
                    retained,
                    type_scripts_hex,
                } => (
                    FactoryTransitionOperation::ReducedDeposit,
                    Some(participant),
                    Some(retained),
                    &[][..],
                    type_scripts_hex.as_slice(),
                    None,
                ),
                FactoryPreparationOperation::FullCustody {
                    retained,
                    payouts,
                    type_scripts_hex,
                    access_manifest_root,
                } => (
                    FactoryTransitionOperation::FullCustody,
                    None,
                    Some(retained),
                    payouts.as_slice(),
                    type_scripts_hex.as_slice(),
                    Some(access_manifest_root),
                ),
            };
        let signer_index = participant
            .map(|participant| -> Result<_> {
                let id = hash(participant)?;
                members
                    .iter()
                    .position(|member| member.participant == id)
                    .context("touched participant is not a Factory member")
            })
            .transpose()?
            .unwrap_or(0);
        let retained = match reserve_terms {
            Some(terms) => manifest(terms, blake2b256(&source.vault_lock))?,
            None => source.manifest.clone(),
        };
        let mut type_scripts = source
            .type_scripts
            .iter()
            .cloned()
            .map(|entry| (entry.type_hash, entry))
            .collect::<BTreeMap<_, _>>();
        for raw in additional_types {
            let script = decode_hex(raw, 512)?;
            let type_hash = blake2b256(&script);
            if let Some(existing) = type_scripts.insert(
                type_hash,
                MultiAssetTypeScript {
                    type_hash,
                    script: script.clone(),
                },
            ) {
                ensure!(existing.script == script, "conflicting Type Script");
            }
        }
        let type_scripts = type_scripts.into_values().collect::<Vec<_>>();
        let payouts = payout_terms
            .iter()
            .enumerate()
            .map(|(index, terms)| terms.decode((1 + retained.vaults.len() + index) as u16))
            .collect::<Result<Vec<_>>>()?;
        after.content_root = retained.commitment()?;
        after.vault_count = retained.vaults.len().try_into()?;
        if operation.moves_custody() {
            after.outpoint_root = [0; 32];
        }
        if let Some(access) = access {
            after.access_manifest_root = hash(access)?;
        }
        let changed = if operation.is_full() {
            vec![]
        } else {
            changed_rights(&before_rights, &target_rights)?
        };
        let mut plan = FactoryMultiAssetReducedRelease {
            operation,
            before: source.state()?.fields(),
            after,
            members: members.clone(),
            signer_index: signer_index.try_into()?,
            old_state: source.state_out_point.clone(),
            transaction_hash: [1; 32],
            carrier_capacity: source.state_carrier_capacity,
            source: source.manifest.clone(),
            source_outpoints: source.vault_outpoints.clone(),
            retained: retained.clone(),
            factory_lock_script: source.vault_lock.clone(),
            type_scripts: type_scripts.clone(),
            payouts,
            rights: changed,
            materialisation: None,
        };
        plan.set_locality_digest()?;
        let mut outputs = vec![(
            state_output(&source)?,
            Bytes::from(
                plan.after
                    .encode()
                    .map_err(|e| anyhow!("Factory header: {e:?}"))?
                    .to_vec(),
            ),
        )];
        if operation.moves_custody() {
            for vault in &retained.vaults {
                outputs.push(value_output(
                    &vault.asset,
                    vault.value,
                    &source.vault_lock,
                    &type_scripts,
                )?);
            }
        }
        for payout in &plan.payouts {
            outputs.push(value_output(
                &payout.asset,
                payout.value,
                &payout.lock_script,
                &type_scripts,
            )?);
        }
        let (transaction, _) = build_wallet_transaction(
            &self.funders,
            cells,
            WalletTransaction {
                prefix: source_cells(&source, operation.moves_custody())?,
                outputs,
                state_indices: vec![0],
                type_scripts: type_scripts.clone(),
                cell_deps: deps,
                witness: packed::WitnessArgs::default(),
            },
            max_fee,
        )?;
        plan.transaction_hash = transaction.calc_tx_hash().unpack();
        let vault_outpoints = if operation.moves_custody() {
            (0..retained.vaults.len())
                .map(|index| MultiAssetOutPoint {
                    tx_hash: plan.transaction_hash,
                    index: index as u32 + 1,
                })
                .collect()
        } else {
            source.vault_outpoints.clone()
        };
        let mut bound = plan.after;
        bound.outpoint_root = multi_asset_outpoint_commitment(&retained, &vault_outpoints)?;
        let registry = retained.registry()?;
        let target = FactoryCustody {
            header: bound
                .encode()
                .map_err(|e| anyhow!("Factory header: {e:?}"))?
                .to_vec(),
            state_out_point: MultiAssetOutPoint {
                tx_hash: plan.transaction_hash,
                index: 0,
            },
            manifest: retained,
            vault_outpoints,
            state_type: source.state_type.clone(),
            state_lock: source.state_lock.clone(),
            vault_lock: source.vault_lock.clone(),
            type_scripts: type_scripts
                .into_iter()
                .filter(|entry| registry.xudt_types.contains(&entry.type_hash))
                .collect(),
            state_carrier_capacity: source.state_carrier_capacity,
        };
        let request = FactorySigningRequest {
            role: FactorySigningRole::Transition,
            source: Some(source),
            target: Some(target),
            transaction: transaction.raw().as_slice().to_vec(),
            witness: plan.encode_unsigned()?,
            target_rights,
            deliveries: vec![],
        };
        request.validate(&members)?;
        Ok(request)
    }
}
struct ChildPreparation<'a> {
    participant: Option<&'a str>,
    retained: Option<&'a [FactoryReserveTerms]>,
    children: &'a [FactoryChildTerms],
    carrier_refund_lock: Option<&'a str>,
    access_manifest_root: Option<&'a str>,
}
impl FactoryPreparationTerms {
    fn build_children(
        &self,
        cells: &[FundingCell],
        max_fee: u64,
        spec: ChildPreparation<'_>,
    ) -> Result<FactorySigningRequest> {
        ensure!(
            (1..=wire::FACTORY_MULTI_ASSET_MAX_CHILDREN).contains(&spec.children.len()),
            "Factory requires 1..=4 children"
        );
        let (source, members, before_rights) = self.context.decode()?;
        let target_rights = self
            .target_rights
            .iter()
            .map(FactoryRightTerms::decode)
            .collect::<Result<Vec<_>>>()?;
        let retained = spec
            .retained
            .map(|terms| manifest(terms, blake2b256(&source.vault_lock)))
            .transpose()?;
        let mut after = source.state()?.fields();
        after.update_number = after
            .update_number
            .checked_add(1)
            .context("Factory counter exhausted")?;
        after.state_root = factory_right_sparse_root(&target_rights)?;
        if let Some(access) = spec.access_manifest_root {
            after.access_manifest_root = hash(access)?;
        }
        let refund = spec
            .carrier_refund_lock
            .map(|raw| decode_hex(raw, 512))
            .transpose()?
            .unwrap_or_default();
        let mut outputs = vec![];
        let mut state_indices = vec![];
        if let Some(retained) = &retained {
            ensure!(
                refund.is_empty(),
                "retained Factory cannot refund its carrier"
            );
            after.content_root = retained.commitment()?;
            after.outpoint_root = [0; 32];
            after.vault_count = retained.vaults.len().try_into()?;
            state_indices.push(0);
            outputs.push((state_output(&source)?, Bytes::new()));
            for vault in &retained.vaults {
                outputs.push(value_output(
                    &vault.asset,
                    vault.value,
                    &source.vault_lock,
                    &source.type_scripts,
                )?);
            }
        } else {
            ensure!(
                spec.participant.is_none() && target_rights.is_empty(),
                "terminal materialisation requires all members and no retained rights"
            );
            outputs.push((
                packed::CellOutput::new_builder()
                    .capacity(source.state_carrier_capacity)
                    .lock(packed::Script::from_slice(&refund)?)
                    .build(),
                Bytes::new(),
            ));
        }
        let mut children = vec![];
        let mut child_keys = vec![];
        let mut external_carrier = 0u64;
        for terms in spec.children {
            let output_index = outputs.len();
            let input = packed::CellInput::new_builder()
                .previous_output(packed_point(&source.state_out_point))
                .build();
            let mut anchor = input.as_slice().to_vec();
            anchor.extend_from_slice(&(output_index as u64).to_le_bytes());
            let authority = crate::multi_asset_root_transaction::RootAuthorityHashes {
                state_type: hash(&terms.state_type_code_hash)?,
                state_lock: hash(&terms.state_lock_code_hash)?,
                vault_lock: hash(&terms.vault_lock_code_hash)?,
            };
            let mut creation = terms.channel.build(
                source.state()?.fields().chain_id,
                authority,
                blake2b256(&anchor),
                Some(blake2b256(&source.state_type)),
            )?;
            let keys = terms
                .channel
                .participants
                .each_ref()
                .map(|key| crate::canonical_fields::public(key));
            let [first, second] = keys;
            let keys = [first?, second?];
            creation.authorization.signatures = keys
                .iter()
                .map(|pubkey| ParticipantSignature {
                    pubkey_sec1: pubkey.clone(),
                    signature: vec![],
                })
                .collect();
            external_carrier = external_carrier
                .checked_add(creation.state_carrier_capacity)
                .context("child carrier overflow")?;
            state_indices.push(output_index);
            outputs.push((
                packed::CellOutput::new_builder()
                    .capacity(creation.state_carrier_capacity)
                    .lock(packed::Script::from_slice(&creation.scripts.state_lock)?)
                    .type_(Some(packed::Script::from_slice(&creation.scripts.state_type)?).pack())
                    .build(),
                Bytes::from(creation.state.encode()?.to_vec()),
            ));
            for vault in &creation.manifest.vaults {
                outputs.push(value_output(
                    &vault.asset,
                    vault.value,
                    &creation.scripts.vault_lock,
                    &creation.scripts.type_scripts,
                )?);
            }
            children.push(FactoryMultiAssetChild {
                state_output_index: output_index.try_into()?,
                recovery: creation,
            });
            child_keys.push(keys);
        }
        let mut materialisation = FactoryMultiAssetMaterialisation {
            chain_id: source.state()?.fields().chain_id,
            factory_id: source.state()?.fields().factory_id,
            participants_commitment: source.state()?.fields().participants_commitment,
            old_state: source.state_out_point.clone(),
            transaction_hash: [1; 32],
            source: source.manifest.clone(),
            factory_vault_lock: source.vault_lock.clone(),
            type_scripts: source.type_scripts.clone(),
            source_outpoints: source.vault_outpoints.clone(),
            retained: retained.clone(),
            factory_carrier_capacity: source.state_carrier_capacity,
            external_carrier_contribution: external_carrier,
            carrier_refund_lock: refund,
            children,
        };
        let mut reduced = if let Some(participant) = spec.participant {
            let participant = hash(participant)?;
            let signer_index = members
                .iter()
                .position(|member| member.participant == participant)
                .context("touched participant is not a Factory member")?;
            let mut plan = FactoryMultiAssetReducedRelease {
                operation: FactoryTransitionOperation::ReducedChild,
                before: source.state()?.fields(),
                after,
                members: members.clone(),
                signer_index: signer_index.try_into()?,
                old_state: source.state_out_point.clone(),
                transaction_hash: [1; 32],
                carrier_capacity: source.state_carrier_capacity,
                source: source.manifest.clone(),
                source_outpoints: source.vault_outpoints.clone(),
                retained: retained
                    .clone()
                    .context("reduced child requires retained Factory")?,
                factory_lock_script: source.vault_lock.clone(),
                type_scripts: source.type_scripts.clone(),
                payouts: vec![],
                rights: changed_rights(&before_rights, &target_rights)?,
                materialisation: Some(materialisation.clone()),
            };
            plan.set_locality_digest()?;
            after = plan.after;
            Some(plan)
        } else {
            None
        };
        if retained.is_some() {
            outputs[0].1 = Bytes::from(
                after
                    .encode()
                    .map_err(|error| anyhow!("Factory header: {error:?}"))?
                    .to_vec(),
            );
        }
        let (transaction, _) = build_wallet_transaction(
            &self.funders,
            cells,
            WalletTransaction {
                prefix: source_cells(&source, true)?,
                outputs,
                state_indices,
                type_scripts: source.type_scripts.clone(),
                cell_deps: decode_dependency_records(&self.cell_deps)?,
                witness: packed::WitnessArgs::default(),
            },
            max_fee,
        )?;
        let tx_hash = transaction.calc_tx_hash().unpack();
        materialisation.transaction_hash = tx_hash;
        for child in &mut materialisation.children {
            let package = &mut child.recovery;
            package.state.header.phase = Phase::Settling;
            package.state.header.state_number = 1;
            package.outpoints = (0..package.manifest.vaults.len())
                .map(|index| MultiAssetOutPoint {
                    tx_hash,
                    index: child.state_output_index + 1 + index as u32,
                })
                .collect();
            package.state.vault_outpoint_set_root =
                multi_asset_outpoint_commitment(&package.manifest, &package.outpoints)?;
            package.validate_contents()?;
        }
        let (role, witness) = if let Some(plan) = &mut reduced {
            plan.transaction_hash = tx_hash;
            plan.materialisation = Some(materialisation);
            (
                FactorySigningRole::Transition,
                plan.encode_public_unsigned()?,
            )
        } else {
            let intent = materialisation.encode_public_intent()?;
            (
                FactorySigningRole::Materialisation,
                encode_factory_materialisation_public_witness(
                    &intent,
                    &placeholders(&members),
                    &child_keys,
                )?,
            )
        };
        let target = retained
            .map(|manifest| -> Result<_> {
                let vault_outpoints = (0..manifest.vaults.len())
                    .map(|index| MultiAssetOutPoint {
                        tx_hash,
                        index: 1 + index as u32,
                    })
                    .collect::<Vec<_>>();
                let mut bound = after;
                bound.outpoint_root = multi_asset_outpoint_commitment(&manifest, &vault_outpoints)?;
                let registry = manifest.registry()?;
                Ok(FactoryCustody {
                    header: bound
                        .encode()
                        .map_err(|error| anyhow!("Factory header: {error:?}"))?
                        .to_vec(),
                    state_out_point: MultiAssetOutPoint { tx_hash, index: 0 },
                    manifest,
                    vault_outpoints,
                    state_type: source.state_type.clone(),
                    state_lock: source.state_lock.clone(),
                    vault_lock: source.vault_lock.clone(),
                    type_scripts: source
                        .type_scripts
                        .iter()
                        .filter(|entry| registry.xudt_types.contains(&entry.type_hash))
                        .cloned()
                        .collect(),
                    state_carrier_capacity: source.state_carrier_capacity,
                })
            })
            .transpose()?;
        let request = FactorySigningRequest {
            role,
            source: Some(source),
            target,
            transaction: transaction.raw().as_slice().to_vec(),
            witness,
            target_rights,
            deliveries: vec![],
        };
        request.validate_for_review(&members)?;
        Ok(request)
    }
}
fn changed_rights(
    before: &[FactoryRight],
    after: &[FactoryRight],
) -> Result<Vec<FactoryReducedReleaseRight>> {
    ensure!(
        before.len() == after.len() && before.iter().zip(after).all(|(a, b)| a.id == b.id),
        "reduced preparation requires preprovisioned exact right identities, including explicit zero leaves"
    );
    before
        .iter()
        .zip(after)
        .filter(|(a, b)| a != b)
        .map(|(a, b)| {
            Ok(FactoryReducedReleaseRight {
                before: factory_right_sparse_proof_compact(before, &a.id)?,
                after: factory_right_sparse_proof_compact(after, &b.id)?,
            })
        })
        .collect()
}
fn manifest(terms: &[FactoryReserveTerms], lock_hash: Bytes32) -> Result<MultiAssetManifest> {
    let value = MultiAssetManifest {
        vaults: terms
            .iter()
            .map(|term| term.decode(lock_hash))
            .collect::<Result<Vec<_>>>()?,
    };
    value.encode()?;
    Ok(value)
}
fn placeholders(members: &[FactoryParticipantKey]) -> Vec<FactoryParticipantSignature> {
    members
        .iter()
        .map(|member| FactoryParticipantSignature {
            participant: member.participant,
            pubkey_sec1: member.pubkey_sec1.clone(),
            signature: vec![0; 64],
        })
        .collect()
}
fn packed_point(point: &MultiAssetOutPoint) -> packed::OutPoint {
    packed::OutPoint::new_builder()
        .tx_hash(point.tx_hash.pack())
        .index(point.index)
        .build()
}
fn state_output(source: &FactoryCustody) -> Result<packed::CellOutput> {
    Ok(packed::CellOutput::new_builder()
        .capacity(source.state_carrier_capacity)
        .lock(packed::Script::from_slice(&source.state_lock)?)
        .type_(Some(packed::Script::from_slice(&source.state_type)?).pack())
        .build())
}
fn value_output(
    asset: &VaultAsset,
    value: MultiAssetValue,
    lock: &[u8],
    types: &[MultiAssetTypeScript],
) -> Result<(packed::CellOutput, Bytes)> {
    let ty = match asset {
        VaultAsset::Ckb => None,
        VaultAsset::Xudt(hash) => Some(packed::Script::from_slice(
            &types
                .iter()
                .find(|ty| ty.type_hash == *hash)
                .context("missing exact Type Script")?
                .script,
        )?),
    };
    let data = if ty.is_some() {
        Bytes::from(value.amount.to_le_bytes().to_vec())
    } else {
        ensure!(value.amount == 0, "plain output cannot carry tokens");
        Bytes::new()
    };
    Ok((
        packed::CellOutput::new_builder()
            .capacity(value.capacity()?)
            .lock(packed::Script::from_slice(lock)?)
            .type_(ty.pack())
            .build(),
        data,
    ))
}
fn source_cells(source: &FactoryCustody, custody: bool) -> Result<Vec<FundingCell>> {
    let mut cells = vec![FundingCell {
        point: packed_point(&source.state_out_point),
        output: state_output(source)?,
        data: Bytes::from(source.header.clone()),
    }];
    if custody {
        for (vault, point) in source.manifest.vaults.iter().zip(&source.vault_outpoints) {
            let (output, data) = value_output(
                &vault.asset,
                vault.value,
                &source.vault_lock,
                &source.type_scripts,
            )?;
            cells.push(FundingCell {
                point: packed_point(point),
                output,
                data,
            });
        }
    }
    Ok(cells)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::funding_wallets::FundingInput;
    use crate::multi_asset_packages::canonical_hex;
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

    fn fixture() -> (FactoryPreparationTerms, Vec<FundingCell>) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../morph-core/tests/fixtures/factory-root.json"
        ))
        .unwrap();
        let request: FactorySigningRequest =
            serde_json::from_value(fixture["request"].clone()).unwrap();
        let members: Vec<FactoryParticipantKey> =
            serde_json::from_value(fixture["members"].clone()).unwrap();
        let mut journal = FactorySignerJournal::new_root(
            request.clone(),
            members.clone(),
            members[0].participant,
        )
        .unwrap();
        let id = request.request_id().unwrap();
        journal.reserve_signature(&id).unwrap();
        for seed in [1u8, 2] {
            let key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let public = key.verifying_key().to_sec1_point(true);
            let member = members
                .iter()
                .find(|m| m.pubkey_sec1 == public.as_bytes())
                .unwrap();
            let sig: Signature = key
                .sign_prehash(&request.signing_digest().unwrap())
                .unwrap();
            journal
                .record_signature(
                    &id,
                    FactoryParticipantSignature {
                        participant: member.participant,
                        pubkey_sec1: public.as_bytes().to_vec(),
                        signature: sig.to_bytes().to_vec(),
                    },
                )
                .unwrap();
        }
        journal
            .confirm_request(&id, request.target.clone())
            .unwrap();
        let context = FactoryPreparationContext::from_journal(&journal).unwrap();
        let funder = &members[0];
        let point = packed::OutPoint::new_builder()
            .tx_hash([93; 32].pack())
            .index(0u32)
            .build();
        let lock = crate::multi_asset_funding::funding_wallet_lock(&funder.pubkey_sec1).unwrap();
        let cells = vec![FundingCell {
            point: point.clone(),
            output: packed::CellOutput::new_builder()
                .capacity(30_000_000_000u64)
                .lock(lock)
                .build(),
            data: Bytes::new(),
        }];
        let terms = FactoryPreparationTerms {
            schema: "morph.factory_preparation_terms.v1".to_string(),
            target_rights: context.rights.clone(),
            context,
            intent: FactoryPreparationOperation::Metadata {
                access_manifest_root: canonical_hex(&[9; 32]),
            },
            cell_deps: serde_json::from_value(fixture["terms"]["cell_deps"].clone()).unwrap(),
            funders: vec![FundingWallet {
                pubkey: canonical_hex(&funder.pubkey_sec1),
                inputs: vec![FundingInput {
                    tx_hash: canonical_hex(&[93; 32]),
                    index: 0,
                }],
                ckb_contribution: "0".to_string(),
                fee_contribution: "1000".to_string(),
                tokens: vec![],
            }],
        };
        (terms, cells)
    }

    pub(crate) fn reduced_rights_fixture() -> (FactoryPreparationTerms, Vec<FundingCell>) {
        let (mut terms, cells) = fixture();
        let (mut source, members, mut rights) = terms.context.decode().unwrap();
        let participant = members[0].participant;
        // Keep all candidate leaves in the retained initial snapshot. Eleven
        // value leaves also let the negative exercise the ten-change bound.
        for index in 1u8..=11 {
            rights.push(FactoryRight {
                id: FactoryRightId {
                    participant,
                    subchannel: [index; 32],
                    kind: FactoryRightKind::SponsorBudgetClaim,
                    asset_type: None,
                },
                quantity: 100,
            });
        }
        rights.push(FactoryRight {
            id: FactoryRightId {
                participant,
                subchannel: [90; 32],
                kind: FactoryRightKind::Membership,
                asset_type: None,
            },
            quantity: 1,
        });
        rights.sort_by(|a, b| a.id.cmp(&b.id));
        let mut fields = source.state().unwrap().fields();
        fields.state_root = factory_right_sparse_root(&rights).unwrap();
        source.header = fields.encode().unwrap().to_vec();
        terms.context.custody =
            crate::factory_packets::StoredFactoryCustody::from_core(&source).unwrap();
        terms.context.rights = rights.iter().map(FactoryRightTerms::from_core).collect();
        terms.context.decode().unwrap();
        terms.target_rights = terms.context.rights.clone();
        terms.intent = FactoryPreparationOperation::ReducedRights {
            participant: canonical_hex(&participant),
        };
        (terms, cells)
    }

    pub(crate) fn reduce_value_rights(terms: &mut FactoryPreparationTerms, count: usize) {
        let participant = &terms.context.members[0].participant;
        let mut changed = 0;
        for right in &mut terms.target_rights {
            if right.participant == *participant
                && right.kind == FactoryRightKind::SponsorBudgetClaim
                && changed < count
            {
                right.quantity = "99".to_string();
                changed += 1;
            }
        }
        assert_eq!(changed, count);
    }
    fn released(
        terms: &FactoryPreparationTerms,
    ) -> (
        Vec<FactoryReserveTerms>,
        Vec<FactoryPayoutTerms>,
        Vec<FactoryRightTerms>,
    ) {
        let source = terms.context.custody.decode().unwrap();
        let vault = &source.manifest.vaults[0];
        let lock = crate::multi_asset_funding::funding_wallet_lock(
            &terms.context.members[0].decode().unwrap().pubkey_sec1,
        )
        .unwrap();
        let occupied = morph_script_common::multi_asset::multi_asset_occupied_capacity(
            lock.as_slice(),
            None,
            0,
        )
        .unwrap();
        let quantity = decimal_u128(&terms.target_rights[0].quantity).unwrap() as u64;
        let reserve = occupied.max(quantity.saturating_sub(vault.value.business_ckb));
        let retained = vec![FactoryReserveTerms {
            type_hash: None,
            reserve: (vault.value.reserve - reserve).to_string(),
            business_ckb: (vault.value.business_ckb - (quantity - reserve)).to_string(),
            amount: "0".to_string(),
        }];
        let payouts = vec![FactoryPayoutTerms {
            type_hash: None,
            reserve: reserve.to_string(),
            business_ckb: (quantity - reserve).to_string(),
            amount: "0".to_string(),
            lock_script_hex: canonical_hex(lock.as_slice()),
        }];
        let mut rights = terms.target_rights.clone();
        rights[0].quantity = "0".to_string();
        (retained, payouts, rights)
    }
    fn authorize(request: &FactorySigningRequest) {
        let required = request.required_members().unwrap();
        let signatures = required
            .iter()
            .map(|member| {
                let key = (1u8..=2)
                    .map(|seed| SigningKey::from_slice(&[seed; 32]).unwrap())
                    .find(|key| {
                        key.verifying_key().to_sec1_point(true).as_bytes() == member.pubkey_sec1
                    })
                    .unwrap();
                let sig: Signature = key
                    .sign_prehash(&request.signing_digest().unwrap())
                    .unwrap();
                FactoryParticipantSignature {
                    participant: member.participant,
                    pubkey_sec1: member.pubkey_sec1.clone(),
                    signature: sig.to_bytes().to_vec(),
                }
            })
            .collect::<Vec<_>>();
        let tx = crate::factory_session::authorized_transaction(
            request,
            request.authorized_witness(&signatures).unwrap(),
        )
        .unwrap();
        request.verify_authorized_transaction(&tx).unwrap();
        if request.role == FactorySigningRole::Transition {
            FactoryTransactionView::parse(tx.as_slice())
                .unwrap()
                .validate_against(request.source.as_ref().unwrap())
                .unwrap();
        }
    }
    pub(crate) fn native_child_fixture(
        directory: Option<&std::path::Path>,
    ) -> (FactoryPreparationTerms, Vec<FundingCell>) {
        let (mut terms, mut cells) = fixture();
        cells[0].output = cells[0]
            .output
            .clone()
            .as_builder()
            .capacity(100_000_000_000u64)
            .build();
        let (mut root_terms, mut root_authority, root_cells) =
            crate::factory_root_transaction::tests::fixture();
        root_terms.rights[0].quantity = "20000000000".to_string();
        let mut channel_authority = crate::multi_asset_root_transaction::RootAuthorityHashes {
            state_type: [51; 32],
            state_lock: root_authority.state_lock,
            vault_lock: [52; 32],
        };
        if let Some(directory) = directory {
            let code = |name: &str| blake2b256(&std::fs::read(directory.join(name)).unwrap());
            root_authority.factory_type = code("morph-factory-type");
            root_authority.state_lock = code("morph-state-lock");
            root_authority.vault_lock = code("morph-factory-vault-lock");
            channel_authority.state_type = code("morph-state-type");
            channel_authority.state_lock = code("morph-state-lock");
            channel_authority.vault_lock = code("morph-vault-lock");
        }
        let root = root_terms
            .build([77; 32], root_authority, &root_cells, 1_000_000_000)
            .unwrap();
        let source = root.predicted_custody().unwrap();
        terms.context = FactoryPreparationContext {
            schema: "morph.factory_preparation_context.v1".to_string(),
            custody: crate::factory_packets::StoredFactoryCustody::from_core(&source).unwrap(),
            members: root
                .creation
                .members
                .iter()
                .map(crate::factory_packets::FactoryMemberTerms::from_core)
                .collect(),
            rights: root
                .creation
                .rights
                .iter()
                .map(FactoryRightTerms::from_core)
                .collect(),
        };
        terms.target_rights = terms.context.rights.clone();
        terms.target_rights[0].quantity = "0".to_string();
        let (mut bilateral, _, _, _) = crate::multi_asset_root_transaction::tests::fixture(0, true);
        bilateral.participant_locks_hex = bilateral.participants.each_ref().map(|public| {
            canonical_hex(
                crate::multi_asset_funding::funding_wallet_lock(
                    &crate::canonical_fields::public(public).unwrap(),
                )
                .unwrap()
                .as_slice(),
            )
        });
        bilateral
            .participant_locks_hex
            .sort_by_key(|raw| blake2b256(&decode_hex(raw, 512).unwrap()));
        bilateral.carrier_refund_lock_hex = bilateral.participant_locks_hex[0].clone();
        let participant_locks = bilateral
            .participant_locks_hex
            .each_ref()
            .map(|raw| decode_hex(raw, 512).unwrap());
        let locks = participant_locks.each_ref().map(|lock| blake2b256(lock));
        let settlement = MultiAssetSettlement {
            participant_lock_hashes: locks,
            carrier_refund_lock_hash: blake2b256(
                &decode_hex(&bilateral.carrier_refund_lock_hex, 512).unwrap(),
            ),
            payouts: vec![MultiAssetPayout {
                asset: VaultAsset::Ckb,
                values: [MultiAssetValue {
                    reserve: 8_000_000_000,
                    business_ckb: 2_000_000_000,
                    amount: 0,
                }; 2],
            }],
            capability: MultiAssetSettlementCapability::Ordinary,
        };
        let channel = crate::channel_creation::ChannelCreationTerms {
            participants: bilateral.participants,
            participant_locks_hex: bilateral.participant_locks_hex,
            carrier_refund_lock_hex: bilateral.carrier_refund_lock_hex,
            descriptor_hex: canonical_hex(&settlement.encode().unwrap()),
            challenge_blocks: "10".to_string(),
            type_scripts_hex: vec![],
        };
        let child = FactoryChildTerms {
            channel: channel.clone(),
            state_type_code_hash: canonical_hex(&channel_authority.state_type),
            state_lock_code_hash: canonical_hex(&channel_authority.state_lock),
            vault_lock_code_hash: canonical_hex(&channel_authority.vault_lock),
        };
        let input = packed::CellInput::new_builder()
            .previous_output(packed_point(&source.state_out_point))
            .build();
        let mut anchor = input.as_slice().to_vec();
        anchor.extend_from_slice(&2u64.to_le_bytes());
        let creation = channel
            .build(
                [77; 32],
                channel_authority,
                blake2b256(&anchor),
                Some(blake2b256(&source.state_type)),
            )
            .unwrap();
        terms.funders[0].ckb_contribution = creation.state_carrier_capacity.to_string();
        terms.intent = FactoryPreparationOperation::ReducedChild {
            participant: terms.context.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: (source.manifest.vaults[0].value.reserve - 16_000_000_000).to_string(),
                business_ckb: (source.manifest.vaults[0].value.business_ckb - 4_000_000_000)
                    .to_string(),
                amount: "0".to_string(),
            }],
            children: vec![child],
        };
        (terms, cells)
    }
    #[test]
    fn child_preparation_is_public_only_and_parent_authority_waits_for_both_private_exits() {
        let (mut terms, cells) = native_child_fixture(None);
        let mut request = terms.build(&cells, 1000).unwrap();
        let members = request.members().unwrap();
        assert_eq!(request.child_count().unwrap(), 1);
        assert_eq!(request.missing_delivery_receipts().unwrap().len(), 2);
        assert!(request.validate(&members).is_err());
        let unsigned = request.expected_child_recovery(0).unwrap();
        assert!(unsigned.validate().is_err());
        assert_eq!(unsigned.state.header.state_number, 1);
        assert_eq!(unsigned.state.header.mode, Mode::BilateralPlain);
        assert_eq!(unsigned.scripts.state_type.len(), 125);
        assert!(
            FactorySignerJournal::from_confirmed(
                request.source.clone().unwrap(),
                terms.context.decode().unwrap().2,
                members.clone(),
                members[0].participant
            )
            .unwrap()
            .prepare_request(request.clone())
            .is_err()
        );
        let mut private = unsigned;
        private.authorization.signatures = (1u8..=2)
            .map(|seed| {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                let sig: Signature = key
                    .sign_prehash(&private.state.signing_digest().unwrap())
                    .unwrap();
                ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: sig.to_bytes().to_vec(),
                }
            })
            .collect();
        private
            .authorization
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        request.verify_child_recovery(0, &private).unwrap();
        for seed in [1u8, 2] {
            request.deliveries.push(
                FactoryChildDeliveryReceipt::new_signed(
                    &request,
                    0,
                    &private,
                    &SigningKey::from_slice(&[seed; 32]).unwrap(),
                )
                .unwrap(),
            );
        }
        request.validate(&members).unwrap();
        authorize(&request);
        let packet = crate::factory_packets::StoredFactoryRequest::from_core(&request).unwrap();
        let public = serde_json::to_string(&packet).unwrap();
        for signature in &private.authorization.signatures {
            assert!(!public.contains(&canonical_hex(&signature.signature)));
        }
        let FactoryPreparationOperation::ReducedChild {
            retained, children, ..
        } = terms.intent.clone()
        else {
            panic!()
        };
        terms.intent = FactoryPreparationOperation::Materialise {
            retained: Some(retained),
            children,
            carrier_refund_lock_hex: "0x".to_string(),
            access_manifest_root: canonical_hex(&[12; 32]),
        };
        let full = terms.build(&cells, 1000).unwrap();
        assert_eq!(full.role, FactorySigningRole::Materialisation);
        assert_eq!(full.required_members().unwrap().len(), 2);
        assert_eq!(full.missing_delivery_receipts().unwrap().len(), 2);
    }
    #[test]
    fn withheld_terminal_materialisation_keeps_explicit_reduced_escape_available() {
        let (mut terms, cells) = native_child_fixture(None);
        let FactoryPreparationOperation::ReducedChild { children, .. } = terms.intent.clone()
        else {
            panic!()
        };
        let mut child = children[0].clone();
        let mut settlement = MultiAssetSettlement::decode(
            &decode_hex(&child.channel.descriptor_hex, 16 * 1024).unwrap(),
        )
        .unwrap();
        settlement.payouts[0].values = [MultiAssetValue {
            reserve: 15_000_000_000,
            business_ckb: 5_000_000_000,
            amount: 0,
        }; 2];
        child.channel.descriptor_hex = canonical_hex(&settlement.encode().unwrap());
        terms.intent = FactoryPreparationOperation::Materialise {
            retained: None,
            children: vec![child.clone()],
            carrier_refund_lock_hex: child.channel.carrier_refund_lock_hex.clone(),
            access_manifest_root: canonical_hex(&[17; 32]),
        };
        terms.target_rights.clear();
        let mut terminal = terms.build(&cells, 1000).unwrap();
        assert!(terminal.target.is_none());
        let mut exit = terminal.expected_child_recovery(0).unwrap();
        exit.authorization.signatures = (1u8..=2)
            .map(|seed| {
                let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                let signature: Signature = key
                    .sign_prehash(&exit.state.signing_digest().unwrap())
                    .unwrap();
                ParticipantSignature {
                    pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                    signature: signature.to_bytes().to_vec(),
                }
            })
            .collect();
        exit.authorization
            .signatures
            .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
        for seed in [1u8, 2] {
            terminal.deliveries.push(
                FactoryChildDeliveryReceipt::new_signed(
                    &terminal,
                    0,
                    &exit,
                    &SigningKey::from_slice(&[seed; 32]).unwrap(),
                )
                .unwrap(),
            );
        }
        let (source, members, rights) = terms.context.decode().unwrap();
        let mut journal = FactorySignerJournal::from_confirmed(
            source.clone(),
            rights,
            members.clone(),
            members[0].participant,
        )
        .unwrap();
        let previous = journal.prepare_request(terminal.clone()).unwrap();
        let reservation = journal.reserve_signature(&previous).unwrap();
        assert_eq!(reservation.target_update_number, None);
        let key = SigningKey::from_slice(&[1; 32]).unwrap();
        let sig: Signature = key
            .sign_prehash(&terminal.signing_digest().unwrap())
            .unwrap();
        journal
            .record_signature(
                &previous,
                FactoryParticipantSignature {
                    participant: members[0].participant,
                    pubkey_sec1: members[0].pubkey_sec1.clone(),
                    signature: sig.to_bytes().to_vec(),
                },
            )
            .unwrap();
        assert!(journal.authorized_witness(&previous).is_err());
        terms.target_rights = terms.context.rights.clone();
        let (retained, payouts, rights) = released(&terms);
        terms.target_rights = rights;
        terms.intent = FactoryPreparationOperation::ReducedRelease {
            participant: terms.context.members[0].participant.clone(),
            retained,
            payouts,
        };
        terms.funders[0].ckb_contribution = "0".to_string();
        let escape = terms.build(&cells, 1000).unwrap();
        assert!(journal.prepare_request(escape.clone()).is_err());
        let replacement = journal
            .prepare_replacement(&previous, escape.clone())
            .unwrap();
        assert_eq!(
            journal.reserve_signature(&replacement).unwrap().sequence,
            reservation.sequence + 1
        );
        let sig: Signature = key.sign_prehash(&escape.signing_digest().unwrap()).unwrap();
        journal
            .record_signature(
                &replacement,
                FactoryParticipantSignature {
                    participant: members[0].participant,
                    pubkey_sec1: members[0].pubkey_sec1.clone(),
                    signature: sig.to_bytes().to_vec(),
                },
            )
            .unwrap();
        journal.authorized_witness(&replacement).unwrap();
        assert_eq!(journal.current(), Some(&source));
        assert_eq!(
            journal
                .source_authorizations(&source.state_out_point)
                .unwrap()
                .len(),
            2
        );
        // Completing the old all-member packet cannot be falsely called revoked.
        let key = SigningKey::from_slice(&[2; 32]).unwrap();
        let sig: Signature = key
            .sign_prehash(&terminal.signing_digest().unwrap())
            .unwrap();
        journal
            .record_signature(
                &previous,
                FactoryParticipantSignature {
                    participant: members[1].participant,
                    pubkey_sec1: members[1].pubkey_sec1.clone(),
                    signature: sig.to_bytes().to_vec(),
                },
            )
            .unwrap();
        journal.authorized_witness(&previous).unwrap();
    }
    #[test]
    fn native_factory_prepares_all_current_nonchild_roles_without_another_wire_or_wallet_engine() {
        let (mut terms, cells) = fixture();
        let metadata = terms.build(&cells, 1000).unwrap();
        assert_eq!(metadata.role, FactorySigningRole::MetadataUpdate);
        authorize(&metadata);
        let source = metadata.source.as_ref().unwrap();
        assert_eq!(
            metadata.target.as_ref().unwrap().vault_outpoints,
            source.vault_outpoints
        );
        terms.intent = FactoryPreparationOperation::ReducedRights {
            participant: terms.context.members[0].participant.clone(),
        };
        terms.target_rights[0].quantity = "12000000000".to_string();
        let rights = terms.build(&cells, 1000).unwrap();
        authorize(&rights);
        assert_eq!(rights.raw_transaction().unwrap().inputs().len(), 2);
        let (mut terms, cells) = fixture();
        let (retained, payouts, target_rights) = released(&terms);
        terms.target_rights = target_rights;
        terms.intent = FactoryPreparationOperation::ReducedRelease {
            participant: terms.context.members[0].participant.clone(),
            retained: retained.clone(),
            payouts: payouts.clone(),
        };
        let release = terms.build(&cells, 1000).unwrap();
        authorize(&release);
        assert!(release.requires_activation().unwrap());
        terms.intent = FactoryPreparationOperation::FullCustody {
            retained,
            payouts,
            type_scripts_hex: vec![],
            access_manifest_root: canonical_hex(&[10; 32]),
        };
        let full = terms.build(&cells, 1000).unwrap();
        authorize(&full);
        assert_eq!(full.required_members().unwrap().len(), 2);
        let (mut terms, cells) = fixture();
        let source = terms.context.custody.decode().unwrap();
        let vault = &source.manifest.vaults[0];
        terms.intent = FactoryPreparationOperation::ReducedDeposit {
            participant: terms.context.members[0].participant.clone(),
            retained: vec![FactoryReserveTerms {
                type_hash: None,
                reserve: (vault.value.reserve + 10_000_000_000).to_string(),
                business_ckb: vault.value.business_ckb.to_string(),
                amount: "0".to_string(),
            }],
            type_scripts_hex: vec![],
        };
        terms.target_rights[0].quantity = "23000000000".to_string();
        terms.funders[0].ckb_contribution = "10000000000".to_string();
        let deposit = terms.build(&cells, 1000).unwrap();
        authorize(&deposit);
    }

    #[test]
    fn native_reduced_rights_prepares_exact_one_four_and_ten_change_requests() {
        for count in [1, 4, 10] {
            let (mut terms, cells) = reduced_rights_fixture();
            reduce_value_rights(&mut terms, count);
            let request = terms.build(&cells, 1000).unwrap();
            let frame = wire::FactoryReducedReleaseWitness::parse(&request.witness).unwrap();
            assert_eq!(frame.operation(), FactoryTransitionOperation::ReducedRights);
            assert_eq!(frame.right_count(), count);
            assert_eq!(request.required_members().unwrap().len(), 1);
            let source = request.source.as_ref().unwrap();
            let target = request.target.as_ref().unwrap();
            assert_eq!(source.manifest, target.manifest);
            assert_eq!(source.vault_outpoints, target.vault_outpoints);
            assert_eq!(source.state_carrier_capacity, target.state_carrier_capacity);
            assert!(!request.requires_activation().unwrap());
            assert_eq!(request.raw_transaction().unwrap().inputs().len(), 2);
            for index in 0..count {
                let right = frame.right(index).unwrap();
                assert_eq!(right.before.quantity(), 100);
                assert_eq!(right.after.quantity(), 99);
                assert_eq!(right.before.participant(), frame.touched_participant());
                if index > 0 {
                    let previous = frame.right(index - 1).unwrap().before;
                    assert!(previous.subchannel() < right.before.subchannel());
                }
            }
            authorize(&request);
            let packet = crate::factory_packets::StoredFactoryRequest::from_core(&request).unwrap();
            let restored: crate::factory_packets::StoredFactoryRequest =
                serde_json::from_slice(&serde_json::to_vec(&packet).unwrap()).unwrap();
            assert_eq!(restored.decode().unwrap(), request);
        }
    }

    #[test]
    fn native_reduced_rights_rejects_noop_foreign_nonvalue_noncanonical_and_overbound_changes() {
        let (terms, cells) = reduced_rights_fixture();
        assert!(
            terms.build(&cells, 1000).is_err(),
            "no changed right is not an update"
        );
        let mut valid = terms.clone();
        reduce_value_rights(&mut valid, 1);
        authorize(&valid.build(&cells, 1000).unwrap());

        let mut foreign = valid.clone();
        let peer = foreign.context.members[1].participant.clone();
        let right = foreign
            .target_rights
            .iter_mut()
            .find(|r| r.participant == peer)
            .unwrap();
        right.quantity = (decimal_u128(&right.quantity).unwrap() - 1).to_string();
        assert!(
            foreign.build(&cells, 1000).is_err(),
            "the touched member cannot change a peer leaf"
        );

        let mut nonvalue = valid.clone();
        nonvalue
            .target_rights
            .iter_mut()
            .find(|r| r.kind == FactoryRightKind::Membership)
            .unwrap()
            .quantity = "0".to_string();
        assert!(
            nonvalue.build(&cells, 1000).is_err(),
            "value-only authority cannot modify membership"
        );

        let mut unordered = valid.clone();
        unordered.target_rights.swap(0, 1);
        assert!(
            unordered.build(&cells, 1000).is_err(),
            "raw right IDs remain canonically ordered"
        );
        let mut duplicate = valid;
        duplicate.target_rights[1] = duplicate.target_rights[0].clone();
        assert!(
            duplicate.build(&cells, 1000).is_err(),
            "duplicate IDs are not alternate proof ordering"
        );

        let mut overbound = terms;
        reduce_value_rights(&mut overbound, 11);
        assert!(
            overbound.build(&cells, 1000).is_err(),
            "a request cannot silently truncate its eleventh change"
        );
    }
    #[test]
    fn external_child_parties_receive_private_exits_without_gaining_factory_authority() {
        let (mut terms, cells) = native_child_fixture(None);
        let (retained, mut child) = match terms.intent.clone() {
            FactoryPreparationOperation::ReducedChild {
                retained, children, ..
            } => (retained, children[0].clone()),
            _ => panic!(),
        };
        let mut publics = (3u8..=4)
            .map(|seed| {
                SigningKey::from_slice(&[seed; 32])
                    .unwrap()
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        publics.sort();
        child.channel.participants = [canonical_hex(&publics[0]), canonical_hex(&publics[1])];
        let mut locks = publics
            .iter()
            .map(|key| crate::multi_asset_funding::funding_wallet_lock(key).unwrap())
            .collect::<Vec<_>>();
        locks.sort_by_key(|lock| lock.calc_script_hash());
        child.channel.participant_locks_hex = [
            canonical_hex(locks[0].as_slice()),
            canonical_hex(locks[1].as_slice()),
        ];
        let mut settlement = MultiAssetSettlement::decode(
            &decode_hex(&child.channel.descriptor_hex, 16 * 1024).unwrap(),
        )
        .unwrap();
        settlement.participant_lock_hashes = [
            locks[0].calc_script_hash().unpack(),
            locks[1].calc_script_hash().unpack(),
        ];
        child.channel.descriptor_hex = canonical_hex(&settlement.encode().unwrap());
        for full in [false, true] {
            terms.intent = if full {
                FactoryPreparationOperation::Materialise {
                    retained: Some(retained.clone()),
                    children: vec![child.clone()],
                    carrier_refund_lock_hex: "0x".to_string(),
                    access_manifest_root: canonical_hex(&[31; 32]),
                }
            } else {
                FactoryPreparationOperation::ReducedChild {
                    participant: terms.context.members[0].participant.clone(),
                    retained: retained.clone(),
                    children: vec![child.clone()],
                }
            };
            let mut request = terms.build(&cells, 1000).unwrap();
            let (source, members, rights) = terms.context.decode().unwrap();
            assert!(
                request
                    .required_members()
                    .unwrap()
                    .iter()
                    .all(|member| !publics.contains(&member.pubkey_sec1))
            );
            let mut exit = request.expected_child_recovery(0).unwrap();
            exit.authorization.signatures = (3u8..=4)
                .map(|seed| {
                    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
                    let sig: Signature = key
                        .sign_prehash(&exit.state.signing_digest().unwrap())
                        .unwrap();
                    ParticipantSignature {
                        pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                        signature: sig.to_bytes().to_vec(),
                    }
                })
                .collect();
            exit.authorization
                .signatures
                .sort_by(|a, b| a.pubkey_sec1.cmp(&b.pubkey_sec1));
            request.verify_child_recovery(0, &exit).unwrap();
            for seed in [3u8, 4] {
                request.deliveries.push(
                    FactoryChildDeliveryReceipt::new_signed(
                        &request,
                        0,
                        &exit,
                        &SigningKey::from_slice(&[seed; 32]).unwrap(),
                    )
                    .unwrap(),
                );
            }
            request.validate(&members).unwrap();
            authorize(&request);
            let mut parent = FactorySignerJournal::from_confirmed(
                source.clone(),
                rights.clone(),
                members.clone(),
                members[0].participant,
            )
            .unwrap();
            let id = parent.prepare_request(request.clone()).unwrap();
            parent.reserve_signature(&id).unwrap();
            let key = SigningKey::from_slice(&[3; 32]).unwrap();
            let signature: Signature = key
                .sign_prehash(&request.signing_digest().unwrap())
                .unwrap();
            let outsider = FactoryParticipantSignature {
                participant: members[0].participant,
                pubkey_sec1: key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
            };
            assert!(parent.record_signature(&id, outsider).is_err());
            assert!(
                FactorySignerJournal::from_confirmed(source, rights, members, [3; 32]).is_err()
            );
        }
    }
    #[test]
    fn typed_native_release_and_deposit_keep_token_domains_and_external_ckb_separate() {
        let (public, members, before, _) = crate::factory_journal_fixture::reduced_child_request();
        let source = public.source.unwrap();
        let (mut terms, mut cells) = fixture();
        terms.context = FactoryPreparationContext {
            schema: "morph.factory_preparation_context.v1".to_string(),
            custody: crate::factory_packets::StoredFactoryCustody::from_core(&source).unwrap(),
            members: members
                .iter()
                .map(crate::factory_packets::FactoryMemberTerms::from_core)
                .collect(),
            rights: before.iter().map(FactoryRightTerms::from_core).collect(),
        };
        terms.target_rights = terms.context.rights.clone();
        let selected = before
            .iter()
            .position(|right| {
                right.id.participant == members[0].participant
                    && right.id.kind == FactoryRightKind::ReserveClaim
                    && right.id.asset_type.is_some()
                    && right.quantity >= 10
            })
            .unwrap();
        let type_hash = before[selected].id.asset_type.unwrap();
        let ty = source
            .type_scripts
            .iter()
            .find(|entry| entry.type_hash == type_hash)
            .unwrap();
        let index = source
            .manifest
            .vaults
            .iter()
            .position(|vault| vault.asset == VaultAsset::Xudt(type_hash))
            .unwrap();
        let retained = |manifest: &MultiAssetManifest| {
            manifest
                .vaults
                .iter()
                .map(|vault| FactoryReserveTerms {
                    type_hash: match vault.asset {
                        VaultAsset::Ckb => None,
                        VaultAsset::Xudt(hash) => Some(canonical_hex(&hash)),
                    },
                    reserve: vault.value.reserve.to_string(),
                    business_ckb: vault.value.business_ckb.to_string(),
                    amount: vault.value.amount.to_string(),
                })
                .collect::<Vec<_>>()
        };
        let wallet = cells[0].output.lock();
        let occupied = morph_script_common::multi_asset::multi_asset_occupied_capacity(
            wallet.as_slice(),
            Some(&ty.script),
            16,
        )
        .unwrap();
        let mut after = source.manifest.clone();
        after.vaults[index].value.amount -= 10;
        terms.target_rights[selected].quantity = (before[selected].quantity - 10).to_string();
        terms.funders[0].ckb_contribution = occupied.to_string();
        terms.intent = FactoryPreparationOperation::ReducedRelease {
            participant: terms.context.members[0].participant.clone(),
            retained: retained(&after),
            payouts: vec![FactoryPayoutTerms {
                type_hash: Some(canonical_hex(&type_hash)),
                reserve: occupied.to_string(),
                business_ckb: "0".to_string(),
                amount: "10".to_string(),
                lock_script_hex: canonical_hex(wallet.as_slice()),
            }],
        };
        let released = terms.build(&cells, 1000).unwrap();
        authorize(&released);
        assert_eq!(
            released.target.as_ref().unwrap().manifest.vaults[index]
                .value
                .reserve,
            source.manifest.vaults[index].value.reserve
        );
        let proof = wire::FactoryReducedReleaseWitness::parse(&released.witness).unwrap();
        assert_eq!(
            proof
                .withdrawn_value(morph_script_common::multi_asset::MultiAssetId::CKB)
                .unwrap()
                .capacity()
                .unwrap(),
            0
        );
        assert_eq!(
            proof
                .deposited_value(morph_script_common::multi_asset::MultiAssetId::CKB)
                .unwrap()
                .capacity()
                .unwrap(),
            occupied
        );
        // A wallet contributes this Type, returns all unpledged tokens to its
        // own lock, and never exchanges a token quantity for another Type/CKB.
        terms.target_rights = terms.context.rights.clone();
        terms.target_rights[selected].quantity = (before[selected].quantity + 7).to_string();
        let mut after = source.manifest.clone();
        after.vaults[index].value.amount += 7;
        terms.intent = FactoryPreparationOperation::ReducedDeposit {
            participant: terms.context.members[0].participant.clone(),
            retained: retained(&after),
            type_scripts_hex: vec![],
        };
        terms.funders[0].ckb_contribution = "0".to_string();
        terms.funders[0].tokens = vec![crate::funding_wallets::TokenContribution {
            type_hash: canonical_hex(&type_hash),
            amount: "7".to_string(),
        }];
        cells[0].output = cells[0]
            .output
            .clone()
            .as_builder()
            .type_(Some(packed::Script::from_slice(&ty.script).unwrap()).pack())
            .build();
        cells[0].data = Bytes::from(10u128.to_le_bytes().to_vec());
        let deposited = terms.build(&cells, 1000).unwrap();
        authorize(&deposited);
        let raw = deposited.raw_transaction().unwrap();
        let wallet_change = raw
            .outputs()
            .into_iter()
            .zip(raw.outputs_data())
            .filter(|(output, _)| output.lock() == wallet && output.type_().to_opt().is_some())
            .map(|(_, data)| u128::from_le_bytes(data.raw_data().as_ref().try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(wallet_change, vec![3]);
        terms.funders[0].tokens[0].amount = "8".to_string();
        assert!(terms.build(&cells, 1000).is_err());
    }
    #[test]
    fn preparation_rejects_wrong_wallet_ownership_contributions_rights_and_source_data() {
        let (mut terms, mut cells) = fixture();
        cells[0].output = cells[0]
            .output
            .clone()
            .as_builder()
            .lock(packed::Script::default())
            .build();
        assert!(terms.build(&cells, 1000).is_err());
        let (_, cells) = fixture();
        terms.funders[0].ckb_contribution = "1".to_string();
        assert!(terms.build(&cells, 1000).is_err());
        terms.funders[0].ckb_contribution = "0".to_string();
        terms.context.rights[0].quantity = "1".to_string();
        assert!(terms.build(&cells, 1000).is_err());
        let (mut terms, cells) = fixture();
        terms.target_rights[0].quantity = "50000000000".to_string();
        assert!(terms.build(&cells, 1000).is_err());
        let (mut terms, cells) = fixture();
        terms.intent = FactoryPreparationOperation::ReducedRights {
            participant: terms.context.members[1].participant.clone(),
        };
        terms.target_rights[0].quantity = "0".to_string();
        assert!(terms.build(&cells, 1000).is_err());
        let (mut terms, cells) = fixture();
        terms.intent = FactoryPreparationOperation::ReducedRights {
            participant: terms.context.members[0].participant.clone(),
        };
        terms.target_rights.remove(0);
        assert!(terms.build(&cells, 1000).is_err());
        assert!(
            serde_json::from_str::<FactoryPreparationTerms>(
                &serde_json::to_string(&terms)
                    .unwrap()
                    .replace("\"fee_contribution\":\"1000\"", "\"fee_contribution\":1000")
            )
            .is_err()
        );
    }
}

#[cfg(feature = "devnet")]
#[derive(Debug, clap::Args)]
pub(crate) struct PrepareOptions {
    #[arg(long)]
    pub terms: std::path::PathBuf,
    #[arg(long, default_value = "target/riscv64imac-unknown-none-elf/release")]
    pub contracts_dir: std::path::PathBuf,
    #[arg(long)]
    pub policy: std::path::PathBuf,
    #[arg(long)]
    pub max_fee: u64,
    #[arg(long)]
    pub admission_config: std::path::PathBuf,
    #[arg(long)]
    pub output: std::path::PathBuf,
}
#[cfg(feature = "devnet")]
pub(crate) fn resolve_request(
    rpc: &crate::rpc::CkbRpcClient,
    terms_path: &std::path::Path,
    max_fee: u64,
) -> Result<(FactoryPreparationTerms, FactorySigningRequest)> {
    let terms: FactoryPreparationTerms =
        crate::multi_asset_packages::read_bounded_json(terms_path, 4 * 1024 * 1024)?;
    let cells = terms
        .points()?
        .into_iter()
        .map(|point| {
            let live = crate::devnet::load_canonical_live_cell(rpc, point.clone())?;
            Ok(FundingCell {
                point,
                output: live.output,
                data: live.data,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let request = terms.build(&cells, max_fee)?;
    Ok((terms, request))
}
#[cfg(feature = "devnet")]
pub(crate) fn prepare(
    rpc: &crate::rpc::CkbRpcClient,
    options: PrepareOptions,
) -> Result<serde_json::Value> {
    let (_, request) = resolve_request(rpc, &options.terms, options.max_fee)?;
    crate::value_limit::read_value_limit_policy(&options.policy)?
        .enforce(&ValueSubject::from_factory_request(&request)?)?;
    let checkpoint = crate::devnet::factory_operator::verify_request_for_review(
        rpc,
        &request,
        &options.contracts_dir,
        options.max_fee,
    )?;
    crate::admission::reserve_native(
        rpc,
        &options.admission_config,
        &options.contracts_dir,
        &request,
        true,
        options.max_fee,
    )?;
    let packet = crate::factory_packets::StoredFactoryRequest::from_delivery_review(&request)?;
    crate::devnet::factory_operator::verify_checkpoint(rpc, &checkpoint)?;
    crate::persistence::write_private_immutable(
        &options.output,
        &serde_json::to_vec_pretty(&packet)?,
    )?;
    Ok(
        serde_json::json!({"schema":"morph.factory_preparation.v1","request":options.output,"review":packet.inspect()?,"broadcast":false}),
    )
}
