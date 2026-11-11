//! Deterministic root construction from explicit per-wallet contributions.
//! Quantities use decimal strings; outputs and initial recovery are derived.
#[cfg(test)]
use crate::canonical_fields::decimal_u64;
#[cfg(test)]
use crate::canonical_fields::{decimal_u128, hash, public};
use crate::funding_wallets::{
    FundingCell, FundingCustody, FundingWallet, build_wallet_funding, funding_points,
};
#[cfg(test)]
use crate::funding_wallets::{FundingInput, TokenContribution};
use crate::multi_asset_funding::RootFundingDraft;
#[cfg(test)]
use crate::multi_asset_funding::funding_wallet_lock;
use crate::multi_asset_packages::{
    StoredMultiAssetCellDep, canonical_hex, decode_dependency_records,
};
use anyhow::{Context, Result, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use morph_core::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "devnet")]
pub(crate) const MAX_TERMS_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootFundingTerms {
    pub schema: String,
    pub participants: [String; 2],
    pub participant_locks_hex: [String; 2],
    pub carrier_refund_lock_hex: String,
    pub descriptor_hex: String,
    pub challenge_blocks: String,
    pub type_scripts_hex: Vec<String>,
    pub cell_deps: Vec<StoredMultiAssetCellDep>,
    pub funders: Vec<FundingWallet>,
}
#[derive(Debug, Clone, Copy)]
pub struct RootAuthorityHashes {
    pub state_type: Bytes32,
    pub state_lock: Bytes32,
    pub vault_lock: Bytes32,
}
#[derive(Debug)]
pub struct PreparedRoot {
    pub draft: RootFundingDraft,
    pub creation: MultiAssetRecoveryPackage,
    pub fee: u64,
}

impl RootFundingTerms {
    pub fn points(&self) -> Result<Vec<packed::OutPoint>> {
        ensure!(
            self.schema == "morph.multi_asset_root_terms.v1",
            "unsupported root terms schema"
        );
        funding_points(&self.funders)
    }
    /// Capacity requirements do not depend on available inputs or their value.
    /// Callers may derive their intended contributions before selecting coins.
    pub fn creation(
        &self,
        chain_id: Bytes32,
        authority: RootAuthorityHashes,
    ) -> Result<MultiAssetRecoveryPackage> {
        let points = self.points()?;
        decode_dependency_records(&self.cell_deps)?;
        let input = packed::CellInput::new_builder()
            .previous_output(points[0].clone())
            .build();
        let mut anchor = input.as_slice().to_vec();
        anchor.extend_from_slice(&0u64.to_le_bytes());
        crate::channel_creation::ChannelCreationTerms {
            participants: self.participants.clone(),
            participant_locks_hex: self.participant_locks_hex.clone(),
            carrier_refund_lock_hex: self.carrier_refund_lock_hex.clone(),
            descriptor_hex: self.descriptor_hex.clone(),
            challenge_blocks: self.challenge_blocks.clone(),
            type_scripts_hex: self.type_scripts_hex.clone(),
        }
        .build(chain_id, authority, blake2b256(&anchor), None)
    }
    pub fn build(
        &self,
        chain_id: Bytes32,
        authority: RootAuthorityHashes,
        cells: &[FundingCell],
        max_fee: u64,
    ) -> Result<PreparedRoot> {
        let creation = self.creation(chain_id, authority)?;
        let mut vaults = Vec::new();
        for vault in &creation.manifest.vaults {
            let type_script = match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => Some(packed::Script::from_slice(
                    &creation
                        .scripts
                        .type_scripts
                        .iter()
                        .find(|entry| entry.type_hash == hash)
                        .context("missing registered Type Script")?
                        .script,
                )?),
            };
            let output = packed::CellOutput::new_builder()
                .capacity(vault.value.capacity()?)
                .lock(packed::Script::from_slice(&creation.scripts.vault_lock)?)
                .type_(type_script.clone().pack())
                .build();
            let data = if type_script.is_some() {
                Bytes::from(vault.value.amount.to_le_bytes().to_vec())
            } else {
                Bytes::new()
            };
            vaults.push((output, data));
        }
        let evidence = encode_multi_asset_witness(
            &creation.manifest,
            &creation.settlement,
            &[],
            &creation.scripts,
        )?;
        let witness = packed::WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(evidence)).pack())
            .build();
        let (transaction, fee) = build_wallet_funding(
            &self.funders,
            cells,
            FundingCustody {
                state: (
                    packed::CellOutput::new_builder()
                        .capacity(creation.state_carrier_capacity)
                        .lock(packed::Script::from_slice(&creation.scripts.state_lock)?)
                        .type_(
                            Some(packed::Script::from_slice(&creation.scripts.state_type)?).pack(),
                        )
                        .build(),
                    Bytes::from(creation.state.encode()?.to_vec()),
                ),
                vaults,
                type_scripts: creation.scripts.type_scripts.clone(),
            },
            decode_dependency_records(&self.cell_deps)?,
            witness,
            max_fee,
        )?;
        let draft = RootFundingDraft {
            schema: "morph.multi_asset_root_draft.v1".to_string(),
            transaction_hex: canonical_hex(transaction.as_slice()),
            participants: self.participants.clone(),
        };
        draft.evidence()?;
        Ok(PreparedRoot {
            draft,
            creation,
            fee,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn root_funds_pending_conditions_as_business_value_without_borrowing_reserve() {
        let (mut terms, authority, cells, chain) = fixture(1, true);
        let before = terms.creation(chain, authority).unwrap();
        let mut settlement = before.settlement.clone();
        settlement.payouts[0].values[0].business_ckb -= 1_000_000_000;
        let pending = ConditionalBatch {
            asset: morph_core::VaultAsset::Ckb,
            batch_id: [71; 32],
            application_context_commitment: [72; 32],
            participants: std::array::from_fn(|i| ConditionalParticipant {
                settlement_lock_hash: settlement.participant_lock_hashes[i],
                settled_capacity: settlement.payouts[0].values[i].capacity().unwrap(),
                settled_amount: 0,
            }),
            transfers: vec![ConditionalTransferSpec {
                transfer_id: [73; 32],
                payer_lock_hash: settlement.participant_lock_hashes[0],
                hash_algorithm: ConditionalHashAlgorithm::Sha256,
                payment_hash: derive_conditional_payment_hash(
                    ConditionalHashAlgorithm::Sha256,
                    &[74; 32],
                )
                .unwrap(),
                amount: 1_000_000_000,
                refund_after_block: 100,
            }],
        };
        settlement.capability = MultiAssetSettlementCapability::Conditional {
            batch_code_hash: [75; 32],
            batch_hash_type: 2,
            batches: vec![pending],
        };
        terms.descriptor_hex = canonical_hex(&settlement.encode().unwrap());
        let prepared = terms.build(chain, authority, &cells, 100_000_000).unwrap();
        assert_eq!(prepared.creation.manifest, before.manifest);
        assert_eq!(
            prepared.creation.state_carrier_capacity,
            before.state_carrier_capacity
        );
        assert_eq!(prepared.creation.settlement, settlement);
        let (decoded, _) = prepared.draft.evidence().unwrap();
        assert_eq!(decoded.manifest, before.manifest);
        assert_eq!(decoded.settlement.capability, settlement.capability);
        terms.funders[0].ckb_contribution =
            (decimal_u64(&terms.funders[0].ckb_contribution).unwrap() - 1).to_string();
        assert!(terms.build(chain, authority, &cells, 100_000_000).is_err());
    }

    pub(crate) fn fixture(
        count: usize,
        plain: bool,
    ) -> (
        RootFundingTerms,
        RootAuthorityHashes,
        Vec<FundingCell>,
        Bytes32,
    ) {
        let draft = crate::multi_asset_funding::tests::draft_fixture();
        let (base, _) = draft.evidence().unwrap();
        let mut settlement = base.settlement.clone();
        let template = settlement.payouts[0].clone();
        let ty = packed::Script::from_slice(&base.scripts.type_scripts[0].script).unwrap();
        let mut types = (0..count)
            .map(|i| {
                ty.clone()
                    .as_builder()
                    .args([i as u8 + 10; 32].as_slice().pack())
                    .build()
            })
            .collect::<Vec<_>>();
        types.sort_by_key(|ty| ty.calc_script_hash());
        settlement.payouts = types
            .iter()
            .map(|ty| MultiAssetPayout {
                asset: VaultAsset::Xudt(ty.calc_script_hash().unpack()),
                values: template.values,
            })
            .collect();
        if plain {
            settlement.payouts.insert(
                0,
                MultiAssetPayout {
                    asset: VaultAsset::Ckb,
                    values: [MultiAssetValue {
                        reserve: 8_000_000_000,
                        business_ckb: 5_000_000_000,
                        amount: 0,
                    }; 2],
                },
            );
        }
        let mut terms = RootFundingTerms {
            schema: "morph.multi_asset_root_terms.v1".to_string(),
            participants: draft.participants,
            participant_locks_hex: base
                .scripts
                .participant_locks
                .each_ref()
                .map(|raw| canonical_hex(raw)),
            carrier_refund_lock_hex: canonical_hex(&base.scripts.carrier_refund_lock),
            descriptor_hex: canonical_hex(&settlement.encode().unwrap()),
            challenge_blocks: "4".to_string(),
            type_scripts_hex: types
                .iter()
                .map(|ty| canonical_hex(ty.as_slice()))
                .collect(),
            cell_deps: crate::multi_asset_packages::fixture_package()
                .unwrap()
                .cell_deps,
            funders: vec![],
        };
        for i in 0..2 {
            let key = k256::ecdsa::SigningKey::from_slice(&[i as u8 + 11; 32]).unwrap();
            terms.funders.push(FundingWallet {
                pubkey: canonical_hex(key.verifying_key().to_sec1_point(true).as_bytes()),
                inputs: (0..count.max(1))
                    .map(|j| FundingInput {
                        tx_hash: canonical_hex(&[40 + i as u8 * 10 + j as u8; 32]),
                        index: 0,
                    })
                    .collect(),
                ckb_contribution: "0".to_string(),
                fee_contribution: "50000000".to_string(),
                tokens: types
                    .iter()
                    .map(|ty| {
                        let payout = settlement
                            .payouts
                            .iter()
                            .find(|payout| {
                                payout.asset == VaultAsset::Xudt(ty.calc_script_hash().unpack())
                            })
                            .unwrap();
                        let total = payout.values[0].amount + payout.values[1].amount;
                        TokenContribution {
                            type_hash: canonical_hex(ty.calc_script_hash().as_slice()),
                            amount: (if i == 0 { total / 2 } else { total - total / 2 })
                                .to_string(),
                        }
                    })
                    .collect(),
            });
        }
        terms.funders.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        let code = |raw: &[u8]| -> Bytes32 {
            packed::Script::from_slice(raw)
                .unwrap()
                .code_hash()
                .unpack()
        };
        let authority = RootAuthorityHashes {
            state_type: code(&base.scripts.state_type),
            state_lock: code(&base.scripts.state_lock),
            vault_lock: code(&base.scripts.vault_lock),
        };
        let chain = [91; 32];
        let creation = terms.creation(chain, authority).unwrap();
        let total = creation
            .manifest
            .vaults
            .iter()
            .fold(creation.state_carrier_capacity, |sum, vault| {
                sum + vault.value.capacity().unwrap()
            });
        terms.funders[0].ckb_contribution = (total / 2).to_string();
        terms.funders[1].ckb_contribution = (total - total / 2).to_string();
        let mut cells = Vec::new();
        for funder in &terms.funders {
            let lock = funding_wallet_lock(&public(&funder.pubkey).unwrap()).unwrap();
            for (j, input) in funder.inputs.iter().enumerate() {
                let ty = types.get(j).cloned();
                let data = if let Some(token) = funder.tokens.get(j) {
                    Bytes::from(
                        (decimal_u128(&token.amount).unwrap() + 7)
                            .to_le_bytes()
                            .to_vec(),
                    )
                } else {
                    Bytes::new()
                };
                cells.push(FundingCell {
                    point: input.point().unwrap(),
                    output: packed::CellOutput::new_builder()
                        .capacity(100_000_000_000u64)
                        .lock(lock.clone())
                        .type_(ty.pack())
                        .build(),
                    data,
                });
            }
        }
        (terms, authority, cells, chain)
    }
    fn assert_refunds(terms: &RootFundingTerms, cells: &[FundingCell], tx: &packed::Transaction) {
        let mut offset = 0;
        for funder in &terms.funders {
            let group = &cells[offset..offset + funder.inputs.len()];
            offset += group.len();
            let lock = funding_wallet_lock(&public(&funder.pubkey).unwrap()).unwrap();
            let before = group
                .iter()
                .map(|cell| u64::from(cell.output.capacity()))
                .sum::<u64>();
            let after = tx
                .raw()
                .outputs()
                .into_iter()
                .filter(|output| output.lock() == lock)
                .map(|output| u64::from(output.capacity()))
                .sum::<u64>();
            assert_eq!(
                before - after,
                decimal_u64(&funder.ckb_contribution).unwrap()
                    + decimal_u64(&funder.fee_contribution).unwrap()
            );
            for token in &funder.tokens {
                let hash = hash(&token.type_hash).unwrap();
                let before = group
                    .iter()
                    .filter(|cell| {
                        cell.output
                            .type_()
                            .to_opt()
                            .is_some_and(|ty| ty.calc_script_hash().as_slice() == hash)
                    })
                    .map(|cell| u128::from_le_bytes(cell.data.as_ref().try_into().unwrap()))
                    .sum::<u128>();
                let after = tx
                    .raw()
                    .outputs()
                    .into_iter()
                    .enumerate()
                    .filter(|(_, output)| {
                        output.lock() == lock
                            && output
                                .type_()
                                .to_opt()
                                .is_some_and(|ty| ty.calc_script_hash().as_slice() == hash)
                    })
                    .map(|(i, _)| {
                        u128::from_le_bytes(
                            tx.raw()
                                .outputs_data()
                                .get(i)
                                .unwrap()
                                .raw_data()
                                .as_ref()
                                .try_into()
                                .unwrap(),
                        )
                    })
                    .sum::<u128>();
                assert_eq!(before - after, decimal_u128(&token.amount).unwrap());
            }
        }
    }
    #[test]
    fn root_builder_supports_multiple_wallets_plain_ckb_and_eight_assets_without_rounding() {
        for (count, plain) in [(0, true), (2, false), (2, true), (8, false)] {
            let (terms, authority, cells, chain) = fixture(count, plain);
            let prepared = terms.build(chain, authority, &cells, 100_000_000).unwrap();
            let tx = prepared.draft.transaction().unwrap();
            assert_eq!(prepared.fee, 100_000_000);
            assert_eq!(
                prepared.creation.manifest.vaults.len(),
                count + usize::from(plain)
            );
            assert_eq!(
                tx.as_slice(),
                terms
                    .build(chain, authority, &cells, 100_000_000)
                    .unwrap()
                    .draft
                    .transaction()
                    .unwrap()
                    .as_slice()
            );
            assert_refunds(&terms, &cells, &tx);
            let (creation, exit) = prepared.draft.evidence().unwrap();
            assert_eq!(exit.state.header.state_number, 1);
            assert_eq!(creation.manifest, exit.manifest);
            assert_eq!(exit.outpoints.len(), count + usize::from(plain));
            if count > 0 {
                assert!(
                    decimal_u128(&terms.funders[0].tokens[0].amount).unwrap()
                        > u128::from(u64::MAX)
                );
            }
            assert!(terms.build(chain, authority, &cells, 99_999_999).is_err());
        }
    }
    #[test]
    fn root_builder_keeps_tiny_change_with_the_owner_without_changing_fee() {
        let (terms, authority, mut cells, chain) = fixture(2, false);
        let funder = &terms.funders[0];
        let lock = funding_wallet_lock(&public(&funder.pubkey).unwrap()).unwrap();
        let minimum = |cell: &FundingCell| {
            cell.output
                .occupied_capacity(ckb_types::core::Capacity::bytes(16).unwrap())
                .unwrap()
                .as_u64()
        };
        let second = minimum(&cells[1]);
        let needed = decimal_u64(&funder.ckb_contribution).unwrap()
            + decimal_u64(&funder.fee_contribution).unwrap()
            + minimum(&cells[0])
            + second
            + 1;
        cells[0].output = cells[0]
            .output
            .clone()
            .as_builder()
            .capacity(needed - second)
            .build();
        cells[1].output = cells[1]
            .output
            .clone()
            .as_builder()
            .capacity(second)
            .build();
        let prepared = terms.build(chain, authority, &cells, 100_000_000).unwrap();
        let tx = prepared.draft.transaction().unwrap();
        assert_refunds(&terms, &cells, &tx);
        assert_eq!(
            tx.raw()
                .outputs()
                .into_iter()
                .filter(|output| output.lock() == lock)
                .count(),
            2
        );
        // With no token remainder there is no owner output that can hold dust;
        // fail instead of donating it to miners or another funder.
        for (cell, token) in cells.iter_mut().take(2).zip(&funder.tokens) {
            cell.data = Bytes::from(decimal_u128(&token.amount).unwrap().to_le_bytes().to_vec());
        }
        let remaining = decimal_u64(&funder.ckb_contribution).unwrap()
            + decimal_u64(&funder.fee_contribution).unwrap()
            + 1;
        cells[0].output = cells[0]
            .output
            .clone()
            .as_builder()
            .capacity(remaining - second)
            .build();
        assert!(
            terms
                .build(chain, authority, &cells, 100_000_000)
                .unwrap_err()
                .to_string()
                .contains("plain change")
        );
    }
    #[test]
    fn root_builder_rejects_cross_wallet_subsidies_ownership_and_cross_type_quantity_changes() {
        let (terms, authority, cells, chain) = fixture(2, true);
        let mut poor = cells.clone();
        for cell in poor.iter_mut().take(2) {
            cell.output = cell
                .output
                .clone()
                .as_builder()
                .capacity(20_000_000_000u64)
                .build();
        }
        assert!(
            terms
                .build(chain, authority, &poor, 100_000_000)
                .unwrap_err()
                .to_string()
                .contains("funder lacks pledged CKB")
        );
        let mut stolen = cells.clone();
        stolen[0].output = stolen[0]
            .output
            .clone()
            .as_builder()
            .lock(cells[2].output.lock())
            .build();
        assert!(terms.build(chain, authority, &stolen, 100_000_000).is_err());
        let mut wrong = terms.clone();
        let q = decimal_u128(&wrong.funders[0].tokens[0].amount).unwrap();
        wrong.funders[0].tokens[0].amount = (q - 1).to_string();
        let q = decimal_u128(&wrong.funders[0].tokens[1].amount).unwrap();
        wrong.funders[0].tokens[1].amount = (q + 1).to_string();
        assert!(
            wrong
                .build(chain, authority, &cells, 100_000_000)
                .unwrap_err()
                .to_string()
                .contains("per-Type contributions")
        );
        wrong = terms.clone();
        wrong.funders[0].ckb_contribution = "01".to_string();
        assert!(wrong.build(chain, authority, &cells, 100_000_000).is_err());
        wrong = terms.clone();
        wrong.funders[0].inputs[0] = wrong.funders[1].inputs[0].clone();
        assert!(wrong.points().is_err());
        let mut moved = terms.clone();
        moved.funders[0].ckb_contribution =
            (decimal_u64(&moved.funders[0].ckb_contribution).unwrap() + 1).to_string();
        moved.funders[1].ckb_contribution =
            (decimal_u64(&moved.funders[1].ckb_contribution).unwrap() - 1).to_string();
        let original = terms.build(chain, authority, &cells, 100_000_000).unwrap();
        let replacement = moved.build(chain, authority, &cells, 100_000_000).unwrap();
        assert_ne!(
            original.draft.digests().unwrap(),
            replacement.draft.digests().unwrap()
        );
        let mut value = serde_json::to_value(&terms).unwrap();
        value.as_object_mut().unwrap().remove("funders");
        assert!(serde_json::from_value::<RootFundingTerms>(value).is_err());
    }
}
