//! Exact epoch-0 funding provenance. Creation signatures authenticate the
//! original unbound state; the current complete exit may have newer payouts.
use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use morph_core::*;
use morph_script_common::multi_asset as wire;

pub const SECP_TYPE_HASH: &str =
    "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
pub fn funding_wallet_lock(pubkey: &[u8]) -> Result<packed::Script> {
    ensure!(pubkey.len() == 33, "compressed key must be 33 bytes");
    Ok(packed::Script::new_builder()
        .code_hash(
            <[u8; 32]>::try_from(crate::multi_asset_packages::decode_hex(SECP_TYPE_HASH, 32)?)
                .map_err(|_| anyhow!("invalid standard secp type hash"))?
                .pack(),
        )
        .hash_type(1u8)
        .args(Bytes::copy_from_slice(&blake2b256(pubkey)[..20]).pack())
        .build())
}
pub const MAX_FUNDING_BYTES: usize = 256 * 1024;

pub fn script(raw: &[u8]) -> Result<packed::Script> {
    Ok(packed::Script::from_slice(raw)?)
}

pub fn validate_root_funding(
    current: &MultiAssetRecoveryPackage,
    transaction: &packed::Transaction,
) -> Result<()> {
    current.validate()?;
    validate_root_funding_contents(current, transaction)?;
    let witness = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding witness"))?
        .raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness)?;
    let signatures = witness
        .input_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing creation signatures"))?
        .raw_data();
    let (creation, _) = creation_contents(transaction)?;
    let header = creation.state.encode()?;
    wire::MultiAssetStateHeader::parse(&header)
        .map_err(|error| anyhow!("invalid creation: {error:?}"))?
        .verify_root_funding_signatures(
            &transaction.calc_tx_hash().unpack(),
            &morph_script_common::BilateralSignatureWitness::parse(&signatures)
                .map_err(|error| anyhow!("invalid root signatures: {error:?}"))?,
        )
        .map_err(|error| anyhow!("invalid root funding authorization: {error:?}"))?;
    Ok(())
}

/// Explicit unsigned review. This does not authorise creation or broadcast.
pub fn validate_root_funding_contents(
    current: &MultiAssetRecoveryPackage,
    transaction: &packed::Transaction,
) -> Result<()> {
    current.validate_contents()?;
    ensure!(
        current.state.header.funding_epoch == 0
            && current.state.header.phase == Phase::Settling
            && !current.outpoints.is_empty(),
        "root binding requires bound epoch-0 exit evidence"
    );
    ensure!(
        transaction.as_slice().len() <= MAX_FUNDING_BYTES,
        "root funding exceeds byte limit"
    );
    let raw = transaction.raw();
    ensure!(
        u32::from(raw.version()) == 0,
        "unsupported root transaction version"
    );
    ensure!(
        (1..=64).contains(&raw.inputs().len())
            && (1..=64).contains(&raw.outputs().len())
            && raw.outputs().len() == raw.outputs_data().len(),
        "invalid root funding cell count"
    );
    ensure!(
        (1..=64).contains(&raw.cell_deps().len()) && raw.header_deps().len() <= 64,
        "invalid root funding dependency count"
    );
    let mut input_points = BTreeSet::new();
    for input in raw.inputs() {
        let point = input.previous_output();
        ensure!(
            point.tx_hash().as_slice() != [0; 32] && input_points.insert(point.as_slice().to_vec()),
            "duplicate or invalid funding input"
        );
    }
    for (index, output) in raw.outputs().into_iter().enumerate() {
        let data = raw
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("missing root output data"))?
            .raw_data();
        ensure!(
            matches!(output.lock().hash_type().as_slice(), [0] | [1] | [2] | [4])
                && output
                    .type_()
                    .to_opt()
                    .is_none_or(|ty| matches!(ty.hash_type().as_slice(), [0] | [1] | [2] | [4])),
            "unknown root output Script hash type"
        );
        ensure!(
            u64::from(output.capacity())
                >= output
                    .occupied_capacity(ckb_types::core::Capacity::bytes(data.len())?)?
                    .as_u64(),
            "root output below occupied capacity"
        );
    }
    raw.outputs().into_iter().try_fold(0u64, |sum, output| {
        sum.checked_add(u64::from(output.capacity()))
            .ok_or_else(|| anyhow!("root output capacity overflow"))
    })?;
    let hash: [u8; 32] = transaction.calc_tx_hash().unpack();
    ensure!(
        current.outpoints.iter().all(|point| point.tx_hash == hash),
        "root Vaults are outside the funding transaction"
    );
    let state_type = script(&current.scripts.state_type)?;
    let states = raw
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, output)| output.type_().to_opt() == Some(state_type.clone()))
        .collect::<Vec<_>>();
    ensure!(
        states.len() == 1,
        "funding requires one authentic creation State"
    );
    let (index, output) = &states[0];
    ensure!(
        output.lock() == script(&current.scripts.state_lock)?
            && u64::from(output.capacity()) == current.state_carrier_capacity,
        "funding State authority or carrier mismatch"
    );
    let input = raw
        .inputs()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding anchor input"))?;
    let mut anchor = input.as_slice().to_vec();
    anchor.extend_from_slice(&(*index as u64).to_le_bytes());
    ensure!(
        blake2b256(&anchor) == current.state.header.funding_anchor,
        "funding State anchor does not derive from its actual output index"
    );
    let witness_bytes = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding witness zero"))?
        .raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness_bytes)?;
    let creation_data = raw
        .outputs_data()
        .get(*index)
        .ok_or_else(|| anyhow!("missing creation header"))?
        .raw_data();
    let evidence = witness
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing creation evidence"))?
        .raw_data();
    let mut creation = MultiAssetRecoveryPackage::decode_contents(
        &creation_data,
        &evidence,
        current.state_carrier_capacity,
    )?;
    ensure!(
        creation.state.header.funding_epoch == 0
            && creation.state.header.phase == Phase::Active
            && creation.state.header.state_number == 0
            && creation.outpoints.is_empty(),
        "funding witness is not the root unbound creation"
    );
    ensure!(
        creation.manifest == current.manifest && creation.scripts == current.scripts,
        "current recovery differs from authenticated root custody"
    );
    creation.outpoints = current.outpoints.clone();
    creation.state.vault_outpoint_set_root = current.state.vault_outpoint_set_root;
    // Never re-use the unbound creation signatures as an activation vote.
    creation.validate_contents()?;
    ensure!(
        creation.scripts.state_type.len() == 93,
        "direct root funding cannot use a Factory-origin State Type"
    );
    let before = creation.state.encode()?;
    let after = current.state.encode()?;
    ensure!(
        wire::MultiAssetStateHeader::parse(&before)
            .map_err(|error| anyhow!("invalid root header: {error:?}"))?
            .same_context_except_progress(
                &wire::MultiAssetStateHeader::parse(&after)
                    .map_err(|error| anyhow!("invalid current header: {error:?}"))?
            ),
        "root/current funding contexts differ"
    );
    let vault_lock = script(&current.scripts.vault_lock)?;
    let mut selected = BTreeSet::new();
    for (vault, point) in current.manifest.vaults.iter().zip(&current.outpoints) {
        let index = point.index as usize;
        ensure!(
            selected.insert(index) && index != states[0].0,
            "duplicate or aliased root Vault OutPoint"
        );
        let output = raw
            .outputs()
            .get(index)
            .ok_or_else(|| anyhow!("root Vault output missing"))?;
        let data = raw
            .outputs_data()
            .get(index)
            .ok_or_else(|| anyhow!("root Vault data missing"))?
            .raw_data();
        let ty = match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(script(
                &current
                    .scripts
                    .type_scripts
                    .iter()
                    .find(|entry| entry.type_hash == hash)
                    .ok_or_else(|| anyhow!("missing root Type Script"))?
                    .script,
            )?),
        };
        let expected_data = if ty.is_some() {
            vault.value.amount.to_le_bytes().to_vec()
        } else {
            vec![]
        };
        ensure!(
            output.lock() == vault_lock
                && output.type_().to_opt() == ty
                && u64::from(output.capacity()) == vault.value.capacity()?
                && data.as_ref() == expected_data,
            "root Vault physical contents mismatch"
        );
    }
    for (index, output) in raw.outputs().into_iter().enumerate() {
        ensure!(
            output.lock() != script(&current.scripts.state_lock)? || index == states[0].0,
            "unlisted StateLock in root funding transaction"
        );
        ensure!(
            output.lock() != vault_lock || selected.contains(&index),
            "unlisted Vault in root funding transaction"
        );
    }
    Ok(())
}

pub fn creation_contents(
    transaction: &packed::Transaction,
) -> Result<(MultiAssetRecoveryPackage, usize)> {
    ensure!(
        transaction.as_slice().len() <= MAX_FUNDING_BYTES,
        "root funding exceeds byte limit"
    );
    let witness = transaction
        .witnesses()
        .get(0)
        .ok_or_else(|| anyhow!("missing funding witness zero"))?
        .raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness)?;
    let evidence = witness
        .output_type()
        .to_opt()
        .ok_or_else(|| anyhow!("missing creation evidence"))?
        .raw_data();
    let parsed = wire::MultiAssetWitness::parse(&evidence)
        .map_err(|error| anyhow!("invalid creation evidence: {error:?}"))?;
    let ty = script(
        parsed
            .scripts()
            .script(4)
            .map_err(|error| anyhow!("missing StateType: {error:?}"))?,
    )?;
    let raw = transaction.raw();
    let indices = raw
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, output)| output.type_().to_opt() == Some(ty.clone()))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        indices.len() == 1,
        "funding requires one authentic creation State"
    );
    let index = indices[0];
    let carrier = u64::from(
        raw.outputs()
            .get(index)
            .ok_or_else(|| anyhow!("missing State"))?
            .capacity(),
    );
    let header = raw
        .outputs_data()
        .get(index)
        .ok_or_else(|| anyhow!("missing creation header"))?
        .raw_data();
    Ok((
        MultiAssetRecoveryPackage::decode_contents(&header, &evidence, carrier)?,
        index,
    ))
}

/// Public immutable funding proposal. Every amount and the initial exit are
/// derived from the packed transaction; no duplicate roots or amounts exist.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct RootFundingDraft {
    pub schema: String,
    pub transaction_hex: String,
    pub participants: [String; 2],
}
impl RootFundingDraft {
    pub fn transaction(&self) -> Result<packed::Transaction> {
        ensure!(
            self.schema == "morph.multi_asset_root_draft.v1",
            "unsupported root draft schema"
        );
        let bytes =
            crate::multi_asset_packages::decode_hex(&self.transaction_hex, MAX_FUNDING_BYTES)?;
        let tx = packed::Transaction::from_slice(&bytes)?;
        let raw = tx
            .witnesses()
            .get(0)
            .ok_or_else(|| anyhow!("missing draft witness"))?
            .raw_data();
        let args = packed::WitnessArgs::from_slice(&raw)?;
        ensure!(
            args.input_type().to_opt().is_none() && args.lock().to_opt().is_none(),
            "root draft must contain no creation or wallet signature in witness zero"
        );
        Ok(tx)
    }
    pub fn evidence(&self) -> Result<(MultiAssetRecoveryPackage, MultiAssetRecoveryPackage)> {
        let tx = self.transaction()?;
        let (creation, _) = creation_contents(&tx)?;
        let public = self
            .participants
            .each_ref()
            .map(|key| crate::multi_asset_packages::decode_hex(key, 33));
        let public = [
            public[0].as_ref().map_err(|error| anyhow!("{error}"))?,
            public[1].as_ref().map_err(|error| anyhow!("{error}"))?,
        ];
        ensure!(
            public[0].len() == 33 && public[1].len() == 33 && public[0] < public[1],
            "root participants must be sorted distinct compressed keys"
        );
        for key in public {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .map_err(|_| anyhow!("invalid compressed participant key"))?;
        }
        ensure!(
            participants_commitment(2, &[public[0], public[1]])
                == creation.state.header.participants_commitment,
            "root participant commitment mismatch"
        );
        let mut exit = creation.clone();
        let lock = script(&creation.scripts.vault_lock)?;
        let hash = tx.calc_tx_hash().unpack();
        for vault in &creation.manifest.vaults {
            let matches = tx
                .raw()
                .outputs()
                .into_iter()
                .enumerate()
                .filter(|(_, output)| {
                    output.lock() == lock
                        && match vault.asset {
                            VaultAsset::Ckb => output.type_().to_opt().is_none(),
                            VaultAsset::Xudt(hash) => output
                                .type_()
                                .to_opt()
                                .is_some_and(|ty| ty.calc_script_hash().as_slice() == hash),
                        }
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            ensure!(matches.len() == 1, "missing or duplicated root Vault");
            exit.outpoints.push(MultiAssetOutPoint {
                tx_hash: hash,
                index: matches[0] as u32,
            });
        }
        exit.state.vault_outpoint_set_root =
            multi_asset_outpoint_commitment(&exit.manifest, &exit.outpoints)?;
        exit.state.header.phase = Phase::Settling;
        exit.state.header.state_number = 1;
        validate_root_funding_contents(&exit, &tx)?;
        // Metadata is canonical even before any signature can be reserved.
        let dependencies = tx.raw().cell_deps().into_iter().collect::<Vec<_>>();
        crate::multi_asset_packages::decode_dependency_records(
            &crate::multi_asset_packages::dependency_records(&dependencies)?,
        )?;
        Ok((creation, exit))
    }
    pub fn digests(&self) -> Result<([u8; 32], [u8; 32])> {
        let (creation, exit) = self.evidence()?;
        Ok((
            creation
                .state
                .root_funding_signing_digest(&self.transaction()?.calc_tx_hash().unpack())?,
            exit.state.signing_digest()?,
        ))
    }
}

/// Public coordination state. It contains no signer authority or reservation.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct RootFundingCollection {
    pub schema: String,
    pub draft: RootFundingDraft,
    pub exit_signatures: Vec<crate::multi_asset_signatures::SignatureMessage>,
    pub creation_signatures: Vec<crate::multi_asset_signatures::SignatureMessage>,
}
#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, clap::ValueEnum, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RootFundingTarget {
    Exit,
    Creation,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RootFundingInspection {
    pub transaction_hash: String,
    pub chain_id: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub creation_digest: String,
    pub exit_digest: String,
    pub state_carrier_capacity: String,
    pub participants: [String; 2],
    pub participant_lock_hashes: [String; 2],
    pub vault_outpoints: Vec<RootFundingPoint>,
    pub assets: Vec<crate::multi_asset_packages::MultiAssetPackageBalance>,
    pub payouts: Vec<crate::summaries::PayoutSummary>,
    pub capability: crate::capability_summary::CapabilitySummary,
    pub input_count: usize,
    pub output_count: usize,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RootFundingPoint {
    pub tx_hash: String,
    pub index: u32,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RootCollectionSummary {
    #[serde(flatten)]
    pub root: RootFundingInspection,
    pub exit_signature_count: usize,
    pub creation_signature_count: usize,
    pub ready_to_export: bool,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootFundingExport {
    pub schema: String,
    pub transaction_hex: String,
    pub recovery_package: crate::multi_asset_packages::StoredMultiAssetPackage,
}
impl RootFundingDraft {
    pub fn inspection(&self) -> Result<RootFundingInspection> {
        use crate::multi_asset_packages::{MultiAssetPackageBalance, canonical_hex};
        let (creation, exit) = self.evidence()?;
        let tx = self.transaction()?;
        let (creation_digest, exit_digest) = self.digests()?;
        Ok(RootFundingInspection {
            transaction_hash: canonical_hex(tx.calc_tx_hash().as_slice()),
            chain_id: canonical_hex(&creation.state.header.chain_id),
            channel_id: canonical_hex(&creation.state.header.channel_id),
            funding_context_id: canonical_hex(&exit.state.funding_context_id()?),
            creation_digest: canonical_hex(&creation_digest),
            exit_digest: canonical_hex(&exit_digest),
            state_carrier_capacity: creation.state_carrier_capacity.to_string(),
            participants: self.participants.clone(),
            participant_lock_hashes: creation
                .settlement
                .participant_lock_hashes
                .map(|hash| canonical_hex(&hash)),
            vault_outpoints: exit
                .outpoints
                .iter()
                .map(|point| RootFundingPoint {
                    tx_hash: canonical_hex(&point.tx_hash),
                    index: point.index,
                })
                .collect(),
            assets: creation
                .manifest
                .vaults
                .iter()
                .map(|vault| MultiAssetPackageBalance {
                    type_hash: match vault.asset {
                        VaultAsset::Ckb => None,
                        VaultAsset::Xudt(hash) => Some(canonical_hex(&hash)),
                    },
                    reserve: vault.value.reserve.to_string(),
                    business_ckb: vault.value.business_ckb.to_string(),
                    amount: vault.value.amount.to_string(),
                })
                .collect(),
            payouts: crate::summaries::payout_summary(&creation.settlement),
            capability: crate::multi_asset_packages::capability_summary(
                &creation.settlement,
                &exit.state,
            )?,
            input_count: tx.raw().inputs().len(),
            output_count: tx.raw().outputs().len(),
        })
    }
}
impl RootFundingTarget {
    pub fn digest(self, draft: &RootFundingDraft) -> Result<Bytes32> {
        let (creation, exit) = draft.digests()?;
        Ok(match self {
            Self::Exit => exit,
            Self::Creation => creation,
        })
    }
}
impl RootFundingCollection {
    pub fn new(draft: RootFundingDraft) -> Result<Self> {
        let result = Self {
            schema: "morph.multi_asset_root_collection.v1".to_string(),
            draft,
            exit_signatures: vec![],
            creation_signatures: vec![],
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "morph.multi_asset_root_collection.v1",
            "unsupported root collection schema"
        );
        self.draft.evidence()?;
        for (target, receipts) in [
            (RootFundingTarget::Exit, &self.exit_signatures),
            (RootFundingTarget::Creation, &self.creation_signatures),
        ] {
            ensure!(
                receipts.len() <= 2
                    && receipts
                        .windows(2)
                        .all(|pair| pair[0].pubkey < pair[1].pubkey),
                "root receipts must be bounded, unique and ordered"
            );
            for receipt in receipts {
                receipt.verify(&target.digest(&self.draft)?, &self.draft.participants)?;
            }
        }
        if !self.creation_signatures.is_empty() {
            self.initial_exit()?.validate()?;
        }
        Ok(())
    }
    pub fn add(
        &mut self,
        target: RootFundingTarget,
        receipt: crate::multi_asset_signatures::SignatureMessage,
    ) -> Result<bool> {
        self.validate()?;
        if matches!(target, RootFundingTarget::Creation) {
            self.initial_exit()?.validate()?;
        }
        receipt.verify(&target.digest(&self.draft)?, &self.draft.participants)?;
        let receipts = match target {
            RootFundingTarget::Exit => &mut self.exit_signatures,
            RootFundingTarget::Creation => &mut self.creation_signatures,
        };
        if let Some(existing) = receipts
            .iter()
            .find(|existing| existing.pubkey == receipt.pubkey)
        {
            ensure!(*existing == receipt, "conflicting public signature receipt");
            return Ok(false);
        }
        receipts.push(receipt);
        receipts.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        Ok(true)
    }
    fn authorization(&self, target: RootFundingTarget) -> Result<StateAuthorization> {
        let receipts = match target {
            RootFundingTarget::Exit => &self.exit_signatures,
            RootFundingTarget::Creation => &self.creation_signatures,
        };
        let signatures = receipts
            .iter()
            .map(|receipt| receipt.verify(&target.digest(&self.draft)?, &self.draft.participants))
            .collect::<Result<_>>()?;
        Ok(StateAuthorization {
            threshold: 2,
            signatures,
        })
    }
    pub fn initial_exit(&self) -> Result<MultiAssetRecoveryPackage> {
        let (_, mut exit) = self.draft.evidence()?;
        exit.authorization = self.authorization(RootFundingTarget::Exit)?;
        Ok(exit)
    }
    pub fn summary(&self) -> Result<RootCollectionSummary> {
        self.validate()?;
        Ok(RootCollectionSummary {
            root: self.draft.inspection()?,
            exit_signature_count: self.exit_signatures.len(),
            creation_signature_count: self.creation_signatures.len(),
            ready_to_export: self.exit_signatures.len() == 2 && self.creation_signatures.len() == 2,
        })
    }
    pub fn export(&self) -> Result<RootFundingExport> {
        use crate::multi_asset_packages::{StoredMultiAssetPackage, canonical_hex};
        self.validate()?;
        let exit = self.initial_exit()?;
        exit.validate()?;
        let tx = self.draft.transaction()?;
        let raw = tx
            .witnesses()
            .get(0)
            .ok_or_else(|| anyhow!("missing root witness"))?
            .raw_data();
        let witness = packed::WitnessArgs::from_slice(&raw)?
            .as_builder()
            .input_type(
                Some(Bytes::from(
                    encode_multi_asset_signatures(
                        &self.authorization(RootFundingTarget::Creation)?,
                    )?
                    .to_vec(),
                ))
                .pack(),
            )
            .build();
        let mut witnesses = tx.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[0] = witness.as_bytes().pack();
        let signed = tx.as_builder().witnesses(witnesses.pack()).build();
        validate_root_funding(&exit, &signed)?;
        let recovery_package = StoredMultiAssetPackage::from_recovery(
            &exit,
            &signed.raw().cell_deps().into_iter().collect::<Vec<_>>(),
        )?;
        Ok(RootFundingExport {
            schema: "morph.multi_asset_root_funding.v1".to_string(),
            transaction_hex: canonical_hex(signed.as_slice()),
            recovery_package,
        })
    }
}

impl RootFundingExport {
    pub fn inspection(&self) -> Result<RootFundingInspection> {
        use crate::multi_asset_packages::{canonical_hex, decode_hex};
        ensure!(
            self.schema == "morph.multi_asset_root_funding.v1",
            "unsupported root funding export schema"
        );
        let tx = packed::Transaction::from_slice(&decode_hex(
            &self.transaction_hex,
            MAX_FUNDING_BYTES,
        )?)?;
        validate_root_funding(&self.recovery_package.recovery()?, &tx)?;
        let raw = tx
            .witnesses()
            .get(0)
            .ok_or_else(|| anyhow!("missing root funding witness"))?
            .raw_data();
        let args = packed::WitnessArgs::from_slice(&raw)?;
        let signature_bytes = args
            .input_type()
            .to_opt()
            .ok_or_else(|| anyhow!("missing root creation signatures"))?
            .raw_data();
        let signatures = morph_script_common::BilateralSignatureWitness::parse(&signature_bytes)
            .map_err(|error| anyhow!("invalid root signatures: {error:?}"))?;
        let participants = [
            canonical_hex(signatures.pubkey(0)),
            canonical_hex(signatures.pubkey(1)),
        ];
        let witness = args
            .as_builder()
            .lock(None::<Bytes>.pack())
            .input_type(None::<Bytes>.pack())
            .build();
        let mut witnesses = tx.witnesses().into_iter().collect::<Vec<_>>();
        witnesses[0] = witness.as_bytes().pack();
        let unsigned = tx.as_builder().witnesses(witnesses.pack()).build();
        RootFundingDraft {
            schema: "morph.multi_asset_root_draft.v1".to_string(),
            transaction_hex: canonical_hex(unsigned.as_slice()),
            participants,
        }
        .inspection()
    }
}
pub fn import_root_funding(
    path: &std::path::Path,
    store_dir: &std::path::Path,
) -> Result<serde_json::Value> {
    let funding: RootFundingExport =
        crate::multi_asset_packages::read_bounded_json(path, 768 * 1024)?;
    funding.inspection()?;
    let raw = crate::multi_asset_packages::decode_hex(&funding.transaction_hex, MAX_FUNDING_BYTES)?;
    let tx = packed::Transaction::from_slice(&raw)?;
    crate::multi_asset_packages::write_received_funding(
        store_dir,
        &funding.recovery_package,
        &tx,
        crate::multi_asset_splice_transaction::TransactionKind::Root,
    )
}
