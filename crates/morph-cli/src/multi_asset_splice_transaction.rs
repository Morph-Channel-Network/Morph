//! Exact, lossless splice drafts. Protocol signatures commit the raw CKB body;
//! witness signing can proceed separately without changing future OutPoints.
use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::*;
use morph_script_common::{multi_asset as wire, multi_asset_splice as splice};
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::{canonical_hex, decode_hex};

const SCHEMA: &str = "morph.multi_asset_splice_draft.v1";
const MAX_TRANSACTION_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpliceDraft {
    pub schema: String,
    pub base_state_digest: String,
    pub transaction_hex: String,
    pub new_witness_hex: String,
    pub flows_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpliceFundingExport {
    pub schema: String,
    pub transaction_hex: String,
    pub recovery_package: crate::multi_asset_packages::StoredMultiAssetPackage,
}

pub fn import_splice_funding(
    bundle: &std::path::Path,
    old_package: &std::path::Path,
    store_dir: &std::path::Path,
) -> Result<serde_json::Value> {
    let funding: SpliceFundingExport =
        crate::multi_asset_packages::read_bounded_json(bundle, 768 * 1024)?;
    ensure!(
        funding.schema == "morph.multi_asset_splice_funding.v1",
        "unsupported splice export schema"
    );
    let current = crate::multi_asset_packages::read_package(old_package)?.recovery()?;
    let recovery = funding.recovery_package.recovery()?;
    let transaction = packed::Transaction::from_slice(&decode_hex(
        &funding.transaction_hex,
        MAX_TRANSACTION_BYTES,
    )?)?;
    SpliceDraft::from_signed_transaction(&current, &recovery, &transaction)?;
    crate::multi_asset_packages::write_received_funding(
        store_dir,
        &funding.recovery_package,
        &transaction,
        TransactionKind::Splice,
    )
}

/// Unsigned value intent. Vault totals and authority scripts are derived;
/// quantities live only in canonical binary descriptor/flow encodings.
#[cfg(any(feature = "devnet", test))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpliceTerms {
    pub schema: String,
    pub descriptor_hex: String,
    pub flows_hex: String,
    pub new_type_scripts_hex: Vec<String>,
    pub withdrawal_lock_hex: String,
    pub cell_deps: Vec<crate::multi_asset_packages::StoredMultiAssetCellDep>,
}

#[cfg(any(feature = "devnet", test))]
impl SpliceTerms {
    pub fn funding(
        &self,
        current: &MultiAssetRecoveryPackage,
        old_state: &MultiAssetOutPoint,
    ) -> Result<MultiAssetRecoveryPackage> {
        use ckb_types::bytes::Bytes;
        current.validate()?;
        ensure!(
            self.schema == "morph.multi_asset_splice_terms.v1",
            "unsupported splice terms schema"
        );
        let settlement = MultiAssetSettlement::decode(&decode_hex(
            &self.descriptor_hex,
            wire::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
                + wire::MULTI_ASSET_MAX_VAULTS * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN,
        )?)?;
        ensure!(
            self.new_type_scripts_hex.len() <= wire::MULTI_ASSET_MAX_VAULTS,
            "too many Type Scripts"
        );
        let anchor = multi_asset_splice_funding_anchor(old_state);
        let mut scripts = current.scripts.clone();
        let since = wire::MultiAssetVaultArgs::parse(&scripts.vault_lock[53..])
            .map_err(invalid)?
            .finalise_since();
        let mut args = anchor.to_vec();
        let old_type = script(&current.scripts.state_type)?;
        let old_args = old_type.args().raw_data();
        args.extend_from_slice(&old_args[32..old_args.len() - 8]);
        args.extend_from_slice(&since.to_le_bytes());
        scripts.state_type = script(&scripts.state_type)?
            .as_builder()
            .args(Bytes::from(args).pack())
            .build()
            .as_slice()
            .to_vec();
        scripts.state_lock = script(&scripts.state_lock)?
            .as_builder()
            .args(Bytes::from(blake2b256(&scripts.state_type).to_vec()).pack())
            .build()
            .as_slice()
            .to_vec();
        scripts.vault_lock = script(&scripts.vault_lock)?
            .as_builder()
            .args(
                Bytes::from(
                    wire::encode_multi_asset_vault_args(
                        &anchor,
                        since,
                        &blake2b256(&scripts.state_type),
                        &blake2b256(&scripts.state_lock),
                    )
                    .map_err(invalid)?
                    .to_vec(),
                )
                .pack(),
            )
            .build()
            .as_slice()
            .to_vec();
        scripts.type_scripts = self
            .new_type_scripts_hex
            .iter()
            .map(|raw| -> Result<_> {
                let script = decode_hex(raw, wire::MULTI_ASSET_MAX_SCRIPT_LEN)?;
                Ok(MultiAssetTypeScript {
                    type_hash: blake2b256(&script),
                    script,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let vaults = settlement
            .payouts
            .iter()
            .map(|payout| -> Result<_> {
                let a = payout.values[0];
                let b = payout.values[1];
                Ok(MultiAssetVault {
                    asset: payout.asset.clone(),
                    lock_hash: blake2b256(&scripts.vault_lock),
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
            .collect::<Result<Vec<_>>>()?;
        let manifest = MultiAssetManifest { vaults };
        let mut state = current.state.clone();
        state.header.funding_epoch = state
            .header
            .funding_epoch
            .checked_add(1)
            .ok_or_else(|| anyhow!("funding epoch exhausted"))?;
        state.header.funding_anchor = anchor;
        state.header.phase = Phase::Active;
        state.header.state_number = 0;
        state.header.asset_registry_commitment = asset_registry_commitment(&manifest.registry()?);
        state.header.settlement_descriptor_commitment = settlement.commitment()?;
        state.vault_content_set_root = manifest.commitment()?;
        state.vault_outpoint_set_root = [0; 32];
        state.vault_count = manifest.vaults.len() as u16;
        let next = MultiAssetRecoveryPackage {
            state,
            authorization: StateAuthorization {
                threshold: 2,
                signatures: vec![],
            },
            manifest,
            settlement,
            scripts,
            outpoints: vec![],
            state_carrier_capacity: current.state_carrier_capacity,
        };
        next.validate_contents()?;
        Ok(next)
    }
}

fn invalid(error: morph_script_common::ScriptError) -> anyhow::Error {
    anyhow!("invalid splice evidence: {error:?}")
}
fn point(value: &packed::OutPoint) -> MultiAssetOutPoint {
    MultiAssetOutPoint {
        tx_hash: value.tx_hash().unpack(),
        index: value.index().unpack(),
    }
}
fn script(raw: &[u8]) -> Result<packed::Script> {
    packed::Script::from_slice(raw).map_err(Into::into)
}
fn allocation(value: wire::MultiAssetAllocation) -> MultiAssetValue {
    MultiAssetValue {
        reserve: value.reserve,
        business_ckb: value.business_ckb,
        amount: value.amount,
    }
}

impl SpliceDraft {
    #[cfg(feature = "devnet")]
    pub fn from_parts(
        current: &MultiAssetRecoveryPackage,
        transaction: &packed::Transaction,
        new_witness: &[u8],
        flows: &[u8],
    ) -> Result<Self> {
        let draft = Self {
            schema: SCHEMA.to_string(),
            base_state_digest: canonical_hex(&current.state.signing_digest()?),
            transaction_hex: canonical_hex(transaction.as_slice()),
            new_witness_hex: canonical_hex(new_witness),
            flows_hex: canonical_hex(flows),
        };
        draft.proposal(current)?;
        Ok(draft)
    }
    /// Reconstruct and verify every protocol authorization from an exported
    /// transaction, retaining the separately signed exact future exit package.
    pub fn from_signed_transaction(
        current: &MultiAssetRecoveryPackage,
        recovery: &MultiAssetRecoveryPackage,
        transaction: &packed::Transaction,
    ) -> Result<(Self, MultiAssetSpliceProposal)> {
        recovery.validate()?;
        let witness_bytes = transaction
            .witnesses()
            .get(0)
            .ok_or_else(|| anyhow!("missing Morph witness"))?
            .raw_data();
        let witness = packed::WitnessArgs::from_slice(&witness_bytes)?;
        ensure!(
            witness.lock().to_opt().is_none(),
            "unexpected Morph lock witness"
        );
        let bridge_bytes = witness
            .output_type()
            .to_opt()
            .ok_or_else(|| anyhow!("missing splice authorization"))?
            .raw_data();
        let bridge = splice::MultiAssetSpliceWitness::parse(&bridge_bytes).map_err(invalid)?;
        let creation_signatures = witness
            .input_type()
            .to_opt()
            .ok_or_else(|| anyhow!("missing creation signatures"))?
            .raw_data();
        let next = MultiAssetRecoveryPackage::decode(
            bridge.new_header().as_bytes(),
            bridge.new_evidence().as_bytes(),
            &creation_signatures,
            current.state_carrier_capacity,
        )?;
        let flows = (0..bridge.flows().count())
            .map(|index| -> Result<_> {
                let flow = bridge.flows().entry(index).map_err(invalid)?;
                Ok(MultiAssetSpliceFlow {
                    asset: if flow.asset.kind == 0 {
                        VaultAsset::Ckb
                    } else {
                        VaultAsset::Xudt(flow.asset.type_hash)
                    },
                    deposit: allocation(flow.deposit),
                    withdrawal: allocation(flow.withdrawal),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut witnesses = transaction.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[0] = ckb_types::bytes::Bytes::new().pack();
        let unsigned = transaction
            .clone()
            .as_builder()
            .witnesses(witnesses.pack())
            .build();
        let draft = Self {
            schema: SCHEMA.to_string(),
            base_state_digest: canonical_hex(&current.state.signing_digest()?),
            transaction_hex: canonical_hex(unsigned.as_slice()),
            new_witness_hex: canonical_hex(bridge.new_evidence().as_bytes()),
            flows_hex: canonical_hex(&encode_multi_asset_splice_flows(&flows)?),
        };
        let mut plan = draft.proposal(current)?;
        plan.new_state_authorization = next.authorization;
        plan.initial_recovery_authorization = recovery.authorization.clone();
        plan.validate(current)?;
        ensure!(
            plan.initial_recovery(current)? == *recovery,
            "future recovery package differs from exact splice body"
        );
        let signatures = bridge.signatures();
        let authorization = StateAuthorization {
            threshold: 2,
            signatures: (0..2)
                .map(|index| ParticipantSignature {
                    pubkey_sec1: signatures.pubkey(index).to_vec(),
                    signature: signatures.signature(index).to_vec(),
                })
                .collect(),
        };
        ensure!(
            plan.encode_witness(current, &authorization)? == bridge_bytes.as_ref(),
            "splice witness differs from signed intent"
        );
        Ok((draft, plan))
    }
    pub fn transaction(&self) -> Result<packed::Transaction> {
        ensure!(self.schema == SCHEMA, "unsupported splice draft schema");
        Ok(packed::Transaction::from_slice(&decode_hex(
            &self.transaction_hex,
            MAX_TRANSACTION_BYTES,
        )?)?)
    }
    pub fn proposal(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> Result<MultiAssetSpliceProposal> {
        current.validate()?;
        ensure!(
            self.base_state_digest == canonical_hex(&current.state.signing_digest()?),
            "splice draft extends another state"
        );
        let transaction = self.transaction()?;
        let raw = transaction.raw();
        ensure!(
            raw.inputs().len() > current.outpoints.len() && raw.inputs().len() <= 64,
            "invalid splice input count"
        );
        ensure!(
            raw.outputs().len() >= 2
                && raw.outputs().len() <= 64
                && raw.outputs().len() == raw.outputs_data().len(),
            "invalid splice output count"
        );
        ensure!(
            (1..=64).contains(&raw.cell_deps().len()) && raw.header_deps().len() <= 64,
            "splice dependency limit exceeded"
        );
        ensure!(
            u32::from(raw.version()) == 0,
            "unsupported transaction version"
        );
        let mut inputs = BTreeSet::new();
        for input in raw.inputs() {
            ensure!(
                inputs.insert(input.previous_output().as_slice().to_vec()),
                "duplicate splice input"
            );
        }
        let mut dependencies = BTreeSet::new();
        for dep in raw.cell_deps() {
            ensure!(
                dependencies.insert(dep.out_point().as_slice().to_vec()),
                "duplicate dependency OutPoint"
            );
            ensure!(
                matches!(u8::from(dep.dep_type()), 0 | 1),
                "unsupported dependency kind"
            );
            ensure!(
                !inputs.contains(dep.out_point().as_slice()),
                "splice consumes a recovery dependency"
            );
        }
        let input = raw
            .inputs()
            .get(0)
            .ok_or_else(|| anyhow!("missing old State input"))?;
        ensure!(
            u64::from(input.since()) == 0,
            "old State input since must be zero"
        );
        for (index, expected) in current.outpoints.iter().enumerate() {
            let input = raw
                .inputs()
                .get(index + 1)
                .ok_or_else(|| anyhow!("missing old Vault"))?;
            ensure!(
                point(&input.previous_output()) == *expected && u64::from(input.since()) == 0,
                "old Vault input order or since mismatch"
            );
        }
        let header = raw
            .outputs_data()
            .get(0)
            .ok_or_else(|| anyhow!("missing new State data"))?
            .raw_data();
        let evidence = decode_hex(&self.new_witness_hex, wire::MULTI_ASSET_MAX_WITNESS_LEN)?;
        let next = MultiAssetRecoveryPackage::decode_contents(
            &header,
            &evidence,
            current.state_carrier_capacity,
        )?;
        let encoded_flows = decode_hex(
            &self.flows_hex,
            4 + splice::MULTI_ASSET_SPLICE_MAX_FLOWS * splice::MULTI_ASSET_SPLICE_FLOW_LEN,
        )?;
        let table = splice::MultiAssetSpliceFlows::parse(&encoded_flows).map_err(invalid)?;
        let flows = (0..table.count())
            .map(|index| -> Result<_> {
                let flow = table.entry(index).map_err(invalid)?;
                Ok(MultiAssetSpliceFlow {
                    asset: if flow.asset.kind == 0 {
                        VaultAsset::Ckb
                    } else {
                        VaultAsset::Xudt(flow.asset.type_hash)
                    },
                    deposit: allocation(flow.deposit),
                    withdrawal: allocation(flow.withdrawal),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let withdrawal_lock = if table.has_withdrawals().map_err(invalid)? {
            raw.outputs()
                .get(1 + next.manifest.vaults.len())
                .ok_or_else(|| anyhow!("missing withdrawal output"))?
                .lock()
                .as_slice()
                .to_vec()
        } else {
            vec![]
        };
        let plan = MultiAssetSpliceProposal {
            base_state_digest: current.state.signing_digest()?,
            old_state_outpoint: point(&input.previous_output()),
            transaction_hash: transaction.calc_tx_hash().unpack(),
            new_state_authorization: next.authorization,
            initial_recovery_authorization: StateAuthorization {
                threshold: 2,
                signatures: vec![],
            },
            new_state: next.state,
            new_manifest: next.manifest,
            new_settlement: next.settlement,
            new_scripts: next.scripts,
            flows,
            withdrawal_lock,
        };
        plan.validate_contents(current)?;
        verify_outputs(&raw, current, &plan)?;
        // Witness zero belongs exclusively to Morph. Fee witnesses may already
        // be signed; no supplied witness can pre-empt participant authorization.
        ensure!(
            transaction.witnesses().len() <= raw.inputs().len(),
            "excess splice witnesses"
        );
        if let Some(witness) = transaction.witnesses().get(0) {
            ensure!(
                witness.raw_data().is_empty(),
                "draft Morph witness must be empty"
            );
        }
        Ok(plan)
    }
    pub fn validate_plan(
        &self,
        current: &MultiAssetRecoveryPackage,
        plan: &MultiAssetSpliceProposal,
    ) -> Result<()> {
        let mut expected = self.proposal(current)?;
        expected.new_state_authorization = plan.new_state_authorization.clone();
        expected.initial_recovery_authorization = plan.initial_recovery_authorization.clone();
        ensure!(
            expected == *plan,
            "stored splice intent differs from its exact transaction draft"
        );
        Ok(())
    }
}

/// Keep exported and fully fee-signed transactions in separate evidence
/// directories. Within each role, identical hashes cannot replace witnesses.
pub enum TransactionKind {
    Root,
    Splice,
}
pub fn write_transaction(
    dir: &std::path::Path,
    transaction: &packed::Transaction,
    kind: TransactionKind,
) -> Result<std::path::PathBuf> {
    let prefix = match kind {
        TransactionKind::Root => "funding",
        TransactionKind::Splice => "splice",
    };
    let path = dir.join(format!(
        "{prefix}-{}.tx",
        hex::encode(transaction.calc_tx_hash().as_slice())
    ));
    let _lock = crate::packages::try_lock_private_path(&path)?
        .ok_or_else(|| anyhow!("funding transaction artifact is busy"))?;
    if path.exists() {
        ensure!(
            std::fs::read(&path)? == transaction.as_slice(),
            "splice export path already holds different witnesses"
        );
        std::fs::File::open(&path)?.sync_all()?;
    } else {
        crate::packages::write_private_atomic(&path, transaction.as_slice())?;
    }
    Ok(path)
}

fn verify_outputs(
    raw: &packed::RawTransaction,
    current: &MultiAssetRecoveryPackage,
    plan: &MultiAssetSpliceProposal,
) -> Result<()> {
    let state = raw
        .outputs()
        .get(0)
        .ok_or_else(|| anyhow!("missing new State"))?;
    ensure!(
        u64::from(state.capacity()) == current.state_carrier_capacity
            && state.lock() == script(&plan.new_scripts.state_lock)?
            && state.type_().to_opt() == Some(script(&plan.new_scripts.state_type)?),
        "new State authority or carrier mismatch"
    );
    let mut expected = Vec::new();
    for vault in &plan.new_manifest.vaults {
        expected.push((
            &vault.asset,
            vault.value,
            plan.new_scripts.vault_lock.as_slice(),
        ));
    }
    for flow in &plan.flows {
        if flow.withdrawal != MultiAssetValue::default() {
            expected.push((
                &flow.asset,
                flow.withdrawal,
                plan.withdrawal_lock.as_slice(),
            ));
        }
    }
    ensure!(
        raw.outputs().len() > expected.len(),
        "incomplete splice outputs"
    );
    for (index, (asset, value, lock)) in expected.iter().enumerate() {
        let output = raw
            .outputs()
            .get(index + 1)
            .ok_or_else(|| anyhow!("missing splice value output"))?;
        let ty = if value.amount == 0 {
            None
        } else {
            let VaultAsset::Xudt(hash) = asset else {
                return Err(anyhow!("plain CKB cannot carry tokens"));
            };
            Some(script(
                &plan
                    .new_scripts
                    .type_scripts
                    .iter()
                    .chain(&current.scripts.type_scripts)
                    .find(|entry| entry.type_hash == *hash)
                    .ok_or_else(|| anyhow!("missing Type Script"))?
                    .script,
            )?)
        };
        let data = raw
            .outputs_data()
            .get(index + 1)
            .ok_or_else(|| anyhow!("missing splice output data"))?
            .raw_data();
        let expected_data = if ty.is_some() {
            value.amount.to_le_bytes().to_vec()
        } else {
            vec![]
        };
        ensure!(
            output.lock() == script(lock)?
                && output.type_().to_opt() == ty
                && u64::from(output.capacity()) == value.capacity()?
                && data.as_ref() == expected_data,
            "splice value output {index} differs from signed allocation"
        );
    }
    for (index, output) in raw.outputs().into_iter().enumerate().skip(1) {
        ensure!(
            output.lock().as_slice() != current.scripts.vault_lock,
            "splice recreates old Vault authority"
        );
        ensure!(
            output
                .type_()
                .to_opt()
                .is_none_or(|ty| ty.as_slice() != current.scripts.state_type
                    && ty.as_slice() != plan.new_scripts.state_type),
            "duplicate State authority"
        );
        if index > expected.len() {
            ensure!(
                output.lock().as_slice() != plan.new_scripts.vault_lock,
                "extra new Vault output"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture_draft(current: &MultiAssetRecoveryPackage) -> SpliceDraft {
    use ckb_types::{bytes::Bytes, core::TransactionBuilder};
    let old = MultiAssetOutPoint {
        tx_hash: [44; 32],
        index: 0,
    };
    let next = SpliceTerms {
        schema: "morph.multi_asset_splice_terms.v1".to_string(),
        descriptor_hex: canonical_hex(&current.settlement.encode().unwrap()),
        flows_hex: "0x".to_string(),
        new_type_scripts_hex: current
            .scripts
            .type_scripts
            .iter()
            .map(|entry| canonical_hex(&entry.script))
            .collect(),
        withdrawal_lock_hex: "0x".to_string(),
        cell_deps: vec![],
    }
    .funding(current, &old)
    .unwrap();
    let flows = current
        .manifest
        .vaults
        .iter()
        .map(|vault| MultiAssetSpliceFlow {
            asset: vault.asset.clone(),
            deposit: MultiAssetValue::default(),
            withdrawal: MultiAssetValue::default(),
        })
        .collect::<Vec<_>>();
    let mut tx = TransactionBuilder::default().cell_dep(
        packed::CellDep::new_builder()
            .out_point(
                packed::OutPoint::new_builder()
                    .tx_hash([77u8; 32].pack())
                    .build(),
            )
            .build(),
    );
    for point in std::iter::once(&old).chain(&current.outpoints) {
        tx = tx.input(
            packed::CellInput::new_builder()
                .previous_output(
                    packed::OutPoint::new_builder()
                        .tx_hash(point.tx_hash.pack())
                        .index(point.index)
                        .build(),
                )
                .build(),
        );
    }
    tx = tx
        .output(
            packed::CellOutput::new_builder()
                .capacity(current.state_carrier_capacity)
                .lock(script(&next.scripts.state_lock).unwrap())
                .type_(Some(script(&next.scripts.state_type).unwrap()).pack())
                .build(),
        )
        .output_data(Bytes::from(next.state.encode().unwrap().to_vec()).pack());
    for vault in &next.manifest.vaults {
        let ty = match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(
                script(
                    &next
                        .scripts
                        .type_scripts
                        .iter()
                        .find(|entry| entry.type_hash == hash)
                        .unwrap()
                        .script,
                )
                .unwrap(),
            ),
        };
        let data = if ty.is_some() {
            vault.value.amount.to_le_bytes().to_vec()
        } else {
            vec![]
        };
        tx = tx
            .output(
                packed::CellOutput::new_builder()
                    .capacity(vault.value.capacity().unwrap())
                    .lock(script(&next.scripts.vault_lock).unwrap())
                    .type_(ty.pack())
                    .build(),
            )
            .output_data(Bytes::from(data).pack());
    }
    SpliceDraft {
        schema: SCHEMA.to_string(),
        base_state_digest: canonical_hex(&current.state.signing_digest().unwrap()),
        transaction_hex: canonical_hex(tx.build().data().as_slice()),
        new_witness_hex: canonical_hex(
            &encode_multi_asset_witness(&next.manifest, &next.settlement, &[], &next.scripts)
                .unwrap(),
        ),
        flows_hex: canonical_hex(&encode_multi_asset_splice_flows(&flows).unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_types::bytes::Bytes;

    fn sdk_splice_fixture() -> serde_json::Value {
        use crate::multi_asset_funding::root_collection_tests::signed_receipts;
        use crate::multi_asset_packages::StoredMultiAssetPackage;
        let stored = crate::multi_asset_packages::fixture_package().unwrap();
        let current = stored.recovery().unwrap();
        let draft = fixture_draft(&current);
        let mut plan = draft.proposal(&current).unwrap();
        let participants = stored.validate().unwrap().signer_pubkeys;
        let creation_digest = plan.new_state.signing_digest().unwrap();
        let creation = signed_receipts(&creation_digest);
        let authorization =
            |digest: &Bytes32, receipts: &[crate::multi_asset_signatures::SignatureMessage]| {
                StateAuthorization {
                    threshold: 2,
                    signatures: receipts
                        .iter()
                        .map(|receipt| receipt.verify(digest, &participants).unwrap())
                        .collect(),
                }
            };
        plan.new_state_authorization = authorization(&creation_digest, &creation);
        let points = (0..plan.new_manifest.vaults.len())
            .map(|i| MultiAssetOutPoint {
                tx_hash: plan.transaction_hash,
                index: i as u32 + 1,
            })
            .collect::<Vec<_>>();
        let mut state = plan.new_state.clone();
        state.header.phase = Phase::Settling;
        state.header.state_number = 1;
        state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&plan.new_manifest, &points).unwrap();
        let recovery_digest = state.signing_digest().unwrap();
        let recovery = signed_receipts(&recovery_digest);
        plan.initial_recovery_authorization = authorization(&recovery_digest, &recovery);
        let bridge_digest = plan.signing_digest(&current).unwrap();
        let bridge = signed_receipts(&bridge_digest);
        let witness = packed::WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&plan.new_state_authorization)
                        .unwrap()
                        .to_vec(),
                ))
                .pack(),
            )
            .output_type(
                Some(Bytes::from(
                    plan.encode_witness(&current, &authorization(&bridge_digest, &bridge))
                        .unwrap(),
                ))
                .pack(),
            )
            .build();
        let transaction = draft
            .transaction()
            .unwrap()
            .as_builder()
            .witnesses(vec![witness.as_bytes().pack()].pack())
            .build();
        let exit = plan.initial_recovery(&current).unwrap();
        let recovery_package = StoredMultiAssetPackage::from_recovery(
            &exit,
            &transaction
                .raw()
                .cell_deps()
                .into_iter()
                .collect::<Vec<_>>(),
        )
        .unwrap();
        serde_json::json!({"current":stored,"draft":draft,"creation_digest":canonical_hex(&creation_digest),"recovery_digest":canonical_hex(&recovery_digest),"bridge_digest":canonical_hex(&bridge_digest),"creation_receipts":creation,"recovery_receipts":recovery,"bridge_receipts":bridge,"funding":{"schema":"morph.multi_asset_splice_funding.v1","transaction_hex":canonical_hex(transaction.as_slice()),"recovery_package":recovery_package}})
    }

    #[test]
    fn sdk_splice_fixture_matches_all_three_domains_and_exact_transaction() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/multi-asset-splice.json"
        ))
        .unwrap();
        assert_eq!(sdk_splice_fixture(), expected);
        // Recorded node transactions cover actual asset admission/removal and
        // withdrawal custody; revalidate their public evidence without RPC.
        let transitions: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/multi-asset-splice-transitions.json"
        ))
        .unwrap();
        for transition in transitions {
            let dir = std::env::temp_dir().join(format!(
                "morph-splice-import-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let bundle_path = dir.join("funding.json");
            let old_path = dir.join("old.json");
            std::fs::write(
                &bundle_path,
                serde_json::to_vec(&transition["funding"]).unwrap(),
            )
            .unwrap();
            std::fs::write(
                &old_path,
                serde_json::to_vec(&transition["current"]).unwrap(),
            )
            .unwrap();
            let current: crate::multi_asset_packages::StoredMultiAssetPackage =
                serde_json::from_value(transition["current"].clone()).unwrap();
            let recovery: crate::multi_asset_packages::StoredMultiAssetPackage =
                serde_json::from_value(transition["funding"]["recovery_package"].clone()).unwrap();
            let draft: SpliceDraft = serde_json::from_value(transition["draft"].clone()).unwrap();
            let tx = packed::Transaction::from_slice(
                &decode_hex(
                    transition["funding"]["transaction_hex"].as_str().unwrap(),
                    MAX_TRANSACTION_BYTES,
                )
                .unwrap(),
            )
            .unwrap();
            let current = current.recovery().unwrap();
            let recovery = recovery.recovery().unwrap();
            let (reconstructed, plan) =
                SpliceDraft::from_signed_transaction(&current, &recovery, &tx).unwrap();
            assert_eq!(
                reconstructed.transaction().unwrap().raw().as_slice(),
                draft.transaction().unwrap().raw().as_slice()
            );
            assert_eq!(reconstructed.new_witness_hex, draft.new_witness_hex);
            assert_eq!(reconstructed.flows_hex, draft.flows_hex);
            let participants = current
                .authorization
                .signatures
                .iter()
                .map(|signature| canonical_hex(&signature.pubkey_sec1))
                .collect::<Vec<_>>();
            let participants = [participants[0].clone(), participants[1].clone()];
            for (role, digest) in [
                ("creation", plan.new_state.signing_digest().unwrap()),
                ("recovery", recovery.state.signing_digest().unwrap()),
                ("bridge", plan.signing_digest(&current).unwrap()),
            ] {
                let receipts: Vec<crate::multi_asset_signatures::SignatureMessage> =
                    serde_json::from_value(transition[format!("{role}_receipts")].clone()).unwrap();
                assert_eq!(receipts.len(), 2);
                for receipt in receipts {
                    receipt.verify(&digest, &participants).unwrap();
                }
            }
            let store = dir.join("received");
            let imported = import_splice_funding(&bundle_path, &old_path, &store).unwrap();
            assert_eq!(
                std::fs::read(imported["transaction"].as_str().unwrap()).unwrap(),
                tx.as_slice()
            );
            assert_eq!(
                crate::multi_asset_packages::read_package(std::path::Path::new(
                    imported["recovery_package"].as_str().unwrap()
                ))
                .unwrap()
                .recovery()
                .unwrap(),
                recovery
            );
            assert_eq!(
                import_splice_funding(&bundle_path, &old_path, &store).unwrap(),
                imported
            );
            let mut invalid = transition["funding"].clone();
            invalid["recovery_package"] = transition["current"].clone();
            std::fs::write(&bundle_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            let rejected = dir.join("rejected");
            assert!(import_splice_funding(&bundle_path, &old_path, &rejected).is_err());
            assert!(!rejected.exists());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn exact_draft_rejects_authority_value_input_and_witness_tampering() {
        let current = crate::multi_asset_packages::fixture_package()
            .unwrap()
            .recovery()
            .unwrap();
        let good = fixture_draft(&current);
        let plan = good.proposal(&current).unwrap();
        for mutation in 0..8 {
            let mut draft = good.clone();
            let tx = draft.transaction().unwrap();
            let mut inputs = tx.raw().inputs().into_iter().collect::<Vec<_>>();
            let mut outputs = tx.raw().outputs().into_iter().collect::<Vec<_>>();
            let mut data = tx.raw().outputs_data().into_iter().collect::<Vec<_>>();
            match mutation {
                0 => inputs.swap(1, 2),
                1 => inputs.push(inputs[0].clone()),
                2 => {
                    outputs[0] = outputs[0]
                        .clone()
                        .as_builder()
                        .capacity(current.state_carrier_capacity - 1)
                        .build()
                }
                3 => {
                    outputs[1] = outputs[1]
                        .clone()
                        .as_builder()
                        .lock(script(&current.scripts.vault_lock).unwrap())
                        .build()
                }
                4 => {
                    outputs.push(outputs[1].clone());
                    data.push(data[1].clone());
                }
                5 => {
                    outputs[1] = outputs[1]
                        .clone()
                        .as_builder()
                        .type_(None::<packed::Script>.pack())
                        .build()
                }
                6 => {
                    outputs.pop();
                    data.pop();
                }
                _ => {}
            }
            let raw = tx
                .raw()
                .as_builder()
                .inputs(inputs.pack())
                .outputs(outputs.pack())
                .outputs_data(data.pack())
                .build();
            let mut tx = tx.as_builder().raw(raw).build();
            if mutation == 7 {
                tx = tx
                    .as_builder()
                    .witnesses(vec![Bytes::from_static(b"unreviewed").pack()].pack())
                    .build();
            }
            draft.transaction_hex = canonical_hex(tx.as_slice());
            assert!(draft.proposal(&current).is_err(), "mutation {mutation}");
        }
        let mut changed = good.clone();
        let tx = changed.transaction().unwrap();
        let mut inputs = tx.raw().inputs().into_iter().collect::<Vec<_>>();
        inputs.push(
            packed::CellInput::new_builder()
                .previous_output(
                    packed::OutPoint::new_builder()
                        .tx_hash([88u8; 32].pack())
                        .build(),
                )
                .build(),
        );
        let raw = tx.raw().as_builder().inputs(inputs.pack()).build();
        changed.transaction_hex = canonical_hex(tx.as_builder().raw(raw).build().as_slice());
        assert!(changed.proposal(&current).is_ok());
        assert!(changed.validate_plan(&current, &plan).is_err());
        let mut changed = good;
        changed.base_state_digest = canonical_hex(&[0; 32]);
        assert!(changed.validate_plan(&current, &plan).is_err());
    }
}
