//! Exact, lossless splice drafts. Protocol signatures commit the raw CKB body;
//! witness signing can proceed separately without changing future OutPoints.
use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::*;
use morph_script_common::{multi_asset as wire, multi_asset_splice as splice};
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::{canonical_hex, decode_hex};

pub const SCHEMA: &str = "morph.multi_asset_splice_draft.v1";
pub const MAX_TRANSACTION_BYTES: usize = 256 * 1024;

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
    let current = crate::multi_asset_packages::read_package(old_package)?.recovery()?;
    let (_, transaction) = funding.validated_draft(&current)?;
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
                + wire::MULTI_ASSET_MAX_VAULTS * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN
                + morph_script_common::multi_asset_conditional::MULTI_ASSET_CONDITIONAL_MAX_LEN,
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
        let manifest = settlement.custody_manifest(blake2b256(&scripts.vault_lock))?;
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

pub fn invalid(error: morph_script_common::ScriptError) -> anyhow::Error {
    anyhow!("invalid splice evidence: {error:?}")
}
pub fn point(value: &packed::OutPoint) -> MultiAssetOutPoint {
    MultiAssetOutPoint {
        tx_hash: value.tx_hash().unpack(),
        index: value.index().unpack(),
    }
}
pub fn script(raw: &[u8]) -> Result<packed::Script> {
    packed::Script::from_slice(raw).map_err(Into::into)
}
pub fn allocation(value: wire::MultiAssetAllocation) -> MultiAssetValue {
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
    ) -> Result<(Self, MultiAssetSpliceProposal, StateAuthorization)> {
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
        Ok((draft, plan, authorization))
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
    crate::persistence::write_private_immutable(&path, transaction.as_slice())?;
    Ok(path)
}

pub fn verify_outputs(
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

impl SpliceFundingExport {
    pub fn validated_draft(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> Result<(SpliceDraft, packed::Transaction)> {
        ensure!(
            self.schema == "morph.multi_asset_splice_funding.v1",
            "unsupported splice export schema"
        );
        let transaction = packed::Transaction::from_slice(&decode_hex(
            &self.transaction_hex,
            MAX_TRANSACTION_BYTES,
        )?)?;
        let (draft, _, _) = SpliceDraft::from_signed_transaction(
            current,
            &self.recovery_package.recovery()?,
            &transaction,
        )?;
        Ok((draft, transaction))
    }
}

impl SpliceDraft {
    pub fn authorized_transaction(
        &self,
        current: &MultiAssetRecoveryPackage,
        plan: &MultiAssetSpliceProposal,
        authorization: &StateAuthorization,
    ) -> Result<packed::Transaction> {
        use ckb_types::bytes::Bytes;
        let draft = self;
        draft.validate_plan(current, plan)?;
        let transaction = draft.transaction()?;
        let witness = packed::WitnessArgs::new_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(&plan.new_state_authorization)?.to_vec(),
                ))
                .pack(),
            )
            .output_type(Some(Bytes::from(plan.encode_witness(current, authorization)?)).pack())
            .build();
        let mut witnesses = transaction.witnesses().into_iter().collect::<Vec<_>>();
        if witnesses.is_empty() {
            witnesses.push(Bytes::new().pack());
        }
        witnesses[0] = witness.as_bytes().pack();
        Ok(transaction.as_builder().witnesses(witnesses.pack()).build())
    }
}
