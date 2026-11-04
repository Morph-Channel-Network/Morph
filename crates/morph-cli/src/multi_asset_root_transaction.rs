//! Deterministic root construction from explicit per-wallet contributions.
//! Quantities use decimal strings; outputs and initial recovery are derived.
use crate::multi_asset_funding::{RootFundingDraft, funding_wallet_lock};
use crate::multi_asset_packages::{
    StoredMultiAssetCellDep, canonical_hex, decode_dependency_records, decode_hex,
};
use anyhow::{Result, anyhow, ensure};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder},
    packed,
    prelude::*,
};
use morph_core::*;
use morph_script_common::multi_asset as wire;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    pub funders: Vec<RootFunder>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootFunder {
    pub pubkey: String,
    pub inputs: Vec<RootInput>,
    /// Channel custody plus State carrier, excluding this wallet's fee share.
    pub ckb_contribution: String,
    pub fee_contribution: String,
    pub tokens: Vec<RootTokenContribution>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootInput {
    pub tx_hash: String,
    pub index: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTokenContribution {
    pub type_hash: String,
    pub amount: String,
}
#[derive(Debug, Clone)]
pub struct RootFundingCell {
    pub point: packed::OutPoint,
    pub output: packed::CellOutput,
    pub data: Bytes,
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

pub(crate) fn decimal_u64(value: &str) -> Result<u64> {
    let result = value.parse::<u64>()?;
    ensure!(
        result.to_string() == value,
        "quantity must be canonical unsigned decimal"
    );
    Ok(result)
}
fn decimal_u128(value: &str) -> Result<u128> {
    let result = value.parse::<u128>()?;
    ensure!(
        result.to_string() == value,
        "quantity must be canonical unsigned decimal"
    );
    Ok(result)
}
fn hash(value: &str) -> Result<Bytes32> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| anyhow!("hash must be 32 bytes"))
}
fn public(value: &str) -> Result<Vec<u8>> {
    let raw = decode_hex(value, 33)?;
    ensure!(raw.len() == 33, "compressed key must be 33 bytes");
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
        .map_err(|_| anyhow!("invalid compressed public key"))?;
    Ok(raw)
}

fn script(raw: &str) -> Result<Vec<u8>> {
    let raw = decode_hex(raw, wire::MULTI_ASSET_MAX_SCRIPT_LEN)?;
    packed::Script::from_slice(&raw)?;
    Ok(raw)
}
fn data1(code: &Bytes32, args: &[u8]) -> packed::Script {
    packed::Script::new_builder()
        .code_hash(code.pack())
        .hash_type(2u8)
        .args(args.pack())
        .build()
}
impl RootInput {
    pub fn point(&self) -> Result<packed::OutPoint> {
        let hash = hash(&self.tx_hash)?;
        ensure!(hash != [0; 32], "zero funding input hash");
        Ok(packed::OutPoint::new_builder()
            .tx_hash(hash.pack())
            .index(self.index)
            .build())
    }
}
impl RootFundingTerms {
    pub fn points(&self) -> Result<Vec<packed::OutPoint>> {
        ensure!(
            self.schema == "morph.multi_asset_root_terms.v1",
            "unsupported root terms schema"
        );
        ensure!(
            (1..=16).contains(&self.funders.len()),
            "root requires 1..=16 explicit funders"
        );
        ensure!(
            self.funders
                .windows(2)
                .all(|pair| pair[0].pubkey < pair[1].pubkey),
            "funders must be distinct and sorted by public key"
        );
        let mut points = Vec::new();
        let mut seen = BTreeSet::new();
        for funder in &self.funders {
            public(&funder.pubkey)?;
            ensure!(
                !funder.inputs.is_empty() && funder.inputs.len() <= 64,
                "funder requires bounded explicit inputs"
            );
            ensure!(
                funder
                    .inputs
                    .windows(2)
                    .all(|pair| (&pair[0].tx_hash, pair[0].index)
                        < (&pair[1].tx_hash, pair[1].index)),
                "funder inputs must be ordered"
            );
            decimal_u64(&funder.ckb_contribution)?;
            decimal_u64(&funder.fee_contribution)?;
            ensure!(
                funder.tokens.len() <= wire::MULTI_ASSET_MAX_VAULTS
                    && funder
                        .tokens
                        .windows(2)
                        .all(|pair| pair[0].type_hash < pair[1].type_hash),
                "token contributions must be bounded and ordered"
            );
            for token in &funder.tokens {
                hash(&token.type_hash)?;
                ensure!(decimal_u128(&token.amount)? > 0, "zero token contribution");
            }
            for input in &funder.inputs {
                let point = input.point()?;
                ensure!(
                    seen.insert(point.as_slice().to_vec()),
                    "duplicate funding input"
                );
                points.push(point);
            }
        }
        ensure!(points.len() <= 64, "too many root funding inputs");
        Ok(points)
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
        let keys = self.participants.each_ref().map(|key| public(key));
        let [first, second] = keys;
        let keys = [first?, second?];
        ensure!(
            keys[0] < keys[1],
            "participants must be distinct and ordered"
        );
        let blocks = decimal_u64(&self.challenge_blocks)?;
        ensure!(blocks > 0, "challenge blocks must be positive");
        let since = morph_script_common::relative_block_since(blocks)
            .map_err(|error| anyhow!("invalid challenge blocks: {error:?}"))?;
        let input = packed::CellInput::new_builder()
            .previous_output(points[0].clone())
            .build();
        let mut anchor = input.as_slice().to_vec();
        anchor.extend_from_slice(&0u64.to_le_bytes());
        let anchor = blake2b256(&anchor);
        let mut args = anchor.to_vec();
        args.extend_from_slice(&since.to_le_bytes());
        let state_type = data1(&authority.state_type, &args);
        let state_lock = data1(
            &authority.state_lock,
            state_type.calc_script_hash().as_slice(),
        );
        let vault_args = wire::encode_multi_asset_vault_args(
            &anchor,
            since,
            &state_type.calc_script_hash().unpack(),
            &state_lock.calc_script_hash().unpack(),
        )
        .map_err(|error| anyhow!("invalid Vault authority: {error:?}"))?;
        let vault_lock = data1(&authority.vault_lock, &vault_args);
        let settlement = MultiAssetSettlement::decode(&decode_hex(
            &self.descriptor_hex,
            wire::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
                + wire::MULTI_ASSET_MAX_VAULTS * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN,
        )?)?;
        let manifest = MultiAssetManifest {
            vaults: settlement
                .payouts
                .iter()
                .map(|payout| -> Result<_> {
                    let [a, b] = payout.values;
                    Ok(MultiAssetVault {
                        asset: payout.asset.clone(),
                        lock_hash: vault_lock.calc_script_hash().unpack(),
                        value: MultiAssetValue {
                            reserve: a
                                .reserve
                                .checked_add(b.reserve)
                                .ok_or_else(|| anyhow!("reserve overflow"))?,
                            business_ckb: a
                                .business_ckb
                                .checked_add(b.business_ckb)
                                .ok_or_else(|| anyhow!("business capacity overflow"))?,
                            amount: a
                                .amount
                                .checked_add(b.amount)
                                .ok_or_else(|| anyhow!("token amount overflow"))?,
                        },
                    })
                })
                .collect::<Result<_>>()?,
        };
        ensure!(
            self.type_scripts_hex.len() <= wire::MULTI_ASSET_MAX_VAULTS,
            "too many Type Scripts"
        );
        let type_scripts = self
            .type_scripts_hex
            .iter()
            .map(|raw| -> Result<_> {
                let raw = script(raw)?;
                Ok(MultiAssetTypeScript {
                    type_hash: blake2b256(&raw),
                    script: raw,
                })
            })
            .collect::<Result<_>>()?;
        let state_output = packed::CellOutput::new_builder()
            .lock(state_lock.clone())
            .type_(Some(state_type.clone()).pack())
            .build();
        let carrier = state_output
            .occupied_capacity(Capacity::bytes(wire::MULTI_ASSET_STATE_HEADER_LEN)?)?
            .as_u64();
        let mut channel = b"CKB_MORPH_CHANNEL_ID".to_vec();
        channel.extend_from_slice(&anchor);
        let mut challenge = b"CKB_MORPH_CHALLENGE_POLICY".to_vec();
        challenge.extend_from_slice(&since.to_le_bytes());
        let creation = MultiAssetRecoveryPackage {
            state: MultiAssetState {
                header: MultiAssetHeader {
                    protocol_version: 1,
                    chain_id,
                    signature_scheme_id: 1,
                    channel_id: blake2b256(&channel),
                    funding_epoch: 0,
                    funding_anchor: anchor,
                    state_number: 0,
                    mode: Mode::BilateralPlain,
                    phase: Phase::Active,
                    participants_commitment: participants_commitment(2, &[&keys[0], &keys[1]]),
                    asset_registry_commitment: asset_registry_commitment(&manifest.registry()?),
                    settlement_descriptor_commitment: settlement.commitment()?,
                    descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
                    challenge_policy_commitment: blake2b256(&challenge),
                    state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
                },
                vault_content_set_root: manifest.commitment()?,
                vault_outpoint_set_root: [0; 32],
                vault_count: manifest.vaults.len() as u16,
            },
            authorization: StateAuthorization {
                threshold: 2,
                signatures: vec![],
            },
            manifest,
            settlement,
            outpoints: vec![],
            state_carrier_capacity: carrier,
            scripts: MultiAssetRecoveryScripts {
                vault_lock: vault_lock.as_slice().to_vec(),
                state_type: state_type.as_slice().to_vec(),
                state_lock: state_lock.as_slice().to_vec(),
                participant_locks: [
                    script(&self.participant_locks_hex[0])?,
                    script(&self.participant_locks_hex[1])?,
                ],
                carrier_refund_lock: script(&self.carrier_refund_lock_hex)?,
                type_scripts,
            },
        };
        creation.validate_contents()?;
        Ok(creation)
    }
    pub fn build(
        &self,
        chain_id: Bytes32,
        authority: RootAuthorityHashes,
        cells: &[RootFundingCell],
        max_fee: u64,
    ) -> Result<PreparedRoot> {
        let creation = self.creation(chain_id, authority)?;
        let points = self.points()?;
        ensure!(
            points.len() == cells.len()
                && points
                    .iter()
                    .zip(cells)
                    .all(|(point, cell)| point.as_slice() == cell.point.as_slice()),
            "resolved funding inputs differ from exact terms"
        );
        let mut outputs = vec![
            packed::CellOutput::new_builder()
                .capacity(creation.state_carrier_capacity)
                .lock(packed::Script::from_slice(&creation.scripts.state_lock)?)
                .type_(Some(packed::Script::from_slice(&creation.scripts.state_type)?).pack())
                .build(),
        ];
        let mut data = vec![Bytes::from(creation.state.encode()?.to_vec())];
        let registered = creation
            .scripts
            .type_scripts
            .iter()
            .map(|entry| (entry.type_hash, entry.script.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let mut expected_tokens = BTreeMap::new();
        for vault in &creation.manifest.vaults {
            let ty = match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => {
                    expected_tokens.insert(hash, vault.value.amount);
                    Some(packed::Script::from_slice(
                        registered
                            .get(&hash)
                            .ok_or_else(|| anyhow!("missing registered Type Script"))?,
                    )?)
                }
            };
            outputs.push(
                packed::CellOutput::new_builder()
                    .capacity(vault.value.capacity()?)
                    .lock(packed::Script::from_slice(&creation.scripts.vault_lock)?)
                    .type_(ty.clone().pack())
                    .build(),
            );
            data.push(if ty.is_some() {
                Bytes::from(vault.value.amount.to_le_bytes().to_vec())
            } else {
                Bytes::new()
            });
        }
        let required_capacity = creation.manifest.vaults.iter().try_fold(
            creation.state_carrier_capacity,
            |sum, vault| -> Result<_> {
                sum.checked_add(vault.value.capacity()?)
                    .ok_or_else(|| anyhow!("root custody capacity overflow"))
            },
        )?;
        let mut contributed_capacity = 0u64;
        let mut fee = 0u64;
        let mut contributed_tokens = BTreeMap::<Bytes32, u128>::new();
        let mut offset = 0;
        for funder in &self.funders {
            let lock = funding_wallet_lock(&public(&funder.pubkey)?)?;
            let group = &cells[offset..offset + funder.inputs.len()];
            offset += group.len();
            let mut remaining = BTreeMap::<Bytes32, u128>::new();
            let mut capacity = 0u64;
            for cell in group {
                ensure!(
                    cell.output.lock() == lock,
                    "funding input is not owned by its declared funder"
                );
                capacity = capacity
                    .checked_add(u64::from(cell.output.capacity()))
                    .ok_or_else(|| anyhow!("input capacity overflow"))?;
                ensure!(
                    u64::from(cell.output.capacity())
                        >= cell
                            .output
                            .occupied_capacity(Capacity::bytes(cell.data.len())?)?
                            .as_u64(),
                    "funding input below occupied capacity"
                );
                if let Some(ty) = cell.output.type_().to_opt() {
                    let hash: Bytes32 = ty.calc_script_hash().unpack();
                    ensure!(
                        registered.contains_key(&hash),
                        "funding input has an unregistered asset"
                    );
                    let amount = u128::from_le_bytes(
                        cell.data
                            .as_ref()
                            .try_into()
                            .map_err(|_| anyhow!("funding token data must be 16 bytes"))?,
                    );
                    let sum = remaining.entry(hash).or_default();
                    *sum = sum
                        .checked_add(amount)
                        .ok_or_else(|| anyhow!("input token overflow"))?;
                } else {
                    ensure!(
                        cell.data.is_empty(),
                        "plain funding input has unexpected data"
                    );
                }
            }
            for token in &funder.tokens {
                let hash = hash(&token.type_hash)?;
                let amount = decimal_u128(&token.amount)?;
                ensure!(
                    registered.contains_key(&hash),
                    "token contribution is unregistered"
                );
                let available = remaining
                    .get_mut(&hash)
                    .ok_or_else(|| anyhow!("funder lacks pledged token input"))?;
                *available = available
                    .checked_sub(amount)
                    .ok_or_else(|| anyhow!("funder lacks pledged token quantity"))?;
                let total = contributed_tokens.entry(hash).or_default();
                *total = total
                    .checked_add(amount)
                    .ok_or_else(|| anyhow!("token contribution overflow"))?;
            }
            let contribution = decimal_u64(&funder.ckb_contribution)?;
            let fee_share = decimal_u64(&funder.fee_contribution)?;
            contributed_capacity = contributed_capacity
                .checked_add(contribution)
                .ok_or_else(|| anyhow!("CKB contribution overflow"))?;
            fee = fee
                .checked_add(fee_share)
                .ok_or_else(|| anyhow!("fee contribution overflow"))?;
            let mut change = capacity
                .checked_sub(contribution)
                .and_then(|value| value.checked_sub(fee_share))
                .ok_or_else(|| anyhow!("funder lacks pledged CKB capacity"))?;
            let first_change = outputs.len();
            for (hash, amount) in remaining {
                if amount == 0 {
                    continue;
                }
                let output = packed::CellOutput::new_builder()
                    .lock(lock.clone())
                    .type_(Some(packed::Script::from_slice(registered[&hash])?).pack())
                    .build();
                let occupied = output.occupied_capacity(Capacity::bytes(16)?)?.as_u64();
                change = change
                    .checked_sub(occupied)
                    .ok_or_else(|| anyhow!("funder cannot fund occupied token change"))?;
                outputs.push(output.as_builder().capacity(occupied).build());
                data.push(Bytes::from(amount.to_le_bytes().to_vec()));
            }
            if change > 0 {
                let plain = packed::CellOutput::new_builder().lock(lock).build();
                if change >= plain.occupied_capacity(Capacity::bytes(0)?)?.as_u64() {
                    outputs.push(plain.as_builder().capacity(change).build());
                    data.push(Bytes::new());
                } else if outputs.len() > first_change {
                    let capacity = u64::from(outputs[first_change].capacity())
                        .checked_add(change)
                        .ok_or_else(|| anyhow!("change capacity overflow"))?;
                    outputs[first_change] = outputs[first_change]
                        .clone()
                        .as_builder()
                        .capacity(capacity)
                        .build();
                } else {
                    return Err(anyhow!("funder plain change is below occupied capacity"));
                }
            }
        }
        ensure!(
            contributed_capacity == required_capacity,
            "CKB contributions must equal exact root custody plus State carrier: required {required_capacity}"
        );
        ensure!(
            contributed_tokens == expected_tokens,
            "per-Type contributions must equal exact root custody"
        );
        ensure!(
            fee > 0 && fee <= max_fee,
            "root fee is zero or exceeds max_fee"
        );
        let input_capacity = cells.iter().try_fold(0u64, |sum, cell| {
            sum.checked_add(u64::from(cell.output.capacity()))
                .ok_or_else(|| anyhow!("total input capacity overflow"))
        })?;
        let output_capacity = outputs.iter().try_fold(fee, |sum, output| {
            sum.checked_add(u64::from(output.capacity()))
                .ok_or_else(|| anyhow!("total output capacity overflow"))
        })?;
        ensure!(
            input_capacity == output_capacity,
            "root capacity accounting mismatch"
        );
        let evidence = encode_multi_asset_witness(
            &creation.manifest,
            &creation.settlement,
            &[],
            &creation.scripts,
        )?;
        let witness = packed::WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(evidence)).pack())
            .build();
        let mut tx = TransactionBuilder::default()
            .set_cell_deps(decode_dependency_records(&self.cell_deps)?);
        for point in points {
            tx = tx.input(
                packed::CellInput::new_builder()
                    .previous_output(point)
                    .build(),
            );
        }
        for (output, value) in outputs.into_iter().zip(data) {
            tx = tx.output(output).output_data(value.pack());
        }
        let transaction = tx.witness(witness.as_bytes()).build().data();
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
    pub(crate) fn fixture(
        count: usize,
        plain: bool,
    ) -> (
        RootFundingTerms,
        RootAuthorityHashes,
        Vec<RootFundingCell>,
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
            terms.funders.push(RootFunder {
                pubkey: canonical_hex(key.verifying_key().to_encoded_point(true).as_bytes()),
                inputs: (0..count.max(1))
                    .map(|j| RootInput {
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
                        RootTokenContribution {
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
                cells.push(RootFundingCell {
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
    fn assert_refunds(
        terms: &RootFundingTerms,
        cells: &[RootFundingCell],
        tx: &packed::Transaction,
    ) {
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
        let minimum = |cell: &RootFundingCell| {
            cell.output
                .occupied_capacity(Capacity::bytes(16).unwrap())
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
