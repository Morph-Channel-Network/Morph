#[cfg(unix)]
use crate::packages::sync_recovery_directories;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{
    core::{DepType, ScriptHashType},
    packed::{CellDep, OutPoint, Script},
    prelude::*,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use morph_core::*;
use morph_script_common::multi_asset as wire;
use morph_script_common::{BILATERAL_SIGNATURE_WITNESS_LEN, BilateralSignatureWitness};
use serde::{Deserialize, Serialize};

pub const MULTI_ASSET_PACKAGE_SCHEMA: &str = "morph.multi_asset_recovery_package.v1";
const MAX_PACKAGE_JSON_BYTES: usize = 128 * 1024;

/// Binary evidence is canonical hex. Every u64/u128 exposed to JavaScript is
/// a decimal string; JSON number rounding must never change signed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMultiAssetPackage {
    pub schema: String,
    pub header_hex: String,
    pub witness_hex: String,
    pub signature_witness_hex: String,
    pub state_carrier_capacity: String,
    pub cell_deps: Vec<StoredMultiAssetCellDep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMultiAssetCellDep {
    pub tx_hash: String,
    pub index: u32,
    pub dep_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiAssetPackageSummary {
    pub package_id: String,
    pub channel_id: String,
    pub funding_context_id: String,
    pub state_number: String,
    pub phase: String,
    pub vaults_bound: bool,
    pub vault_count: usize,
    pub witness_bytes: usize,
    pub dependency_count: usize,
    pub state_carrier_capacity: String,
    pub signer_pubkeys: [String; 2],
    pub assets: Vec<MultiAssetPackageBalance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiAssetPackageBalance {
    pub type_hash: Option<String>,
    pub reserve: String,
    pub business_ckb: String,
    pub amount: String,
}

pub(crate) struct DecodedMultiAssetPackage {
    pub header: Vec<u8>,
    pub witness: Vec<u8>,
    pub signatures: Vec<u8>,
    pub carrier_capacity: u64,
    pub cell_deps: Vec<CellDep>,
}

pub(crate) fn canonical_hex(raw: &[u8]) -> String {
    format!("0x{}", hex::encode(raw))
}

pub(crate) fn decode_hex(raw: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        raw.len() <= 2 + 2 * max,
        "multi-asset field exceeds its byte limit"
    );
    let bytes = hex::decode(
        raw.strip_prefix("0x")
            .ok_or_else(|| anyhow!("multi-asset hex requires 0x prefix"))?,
    )?;
    ensure!(
        canonical_hex(&bytes) == raw,
        "multi-asset hex must be canonical lowercase"
    );
    Ok(bytes)
}

fn wire_error(error: morph_script_common::ScriptError) -> anyhow::Error {
    anyhow!("invalid multi-asset evidence: {error:?}")
}

pub(crate) fn dependency_records(cell_deps: &[CellDep]) -> Result<Vec<StoredMultiAssetCellDep>> {
    let mut records = cell_deps
        .iter()
        .map(|dep| {
            Ok(StoredMultiAssetCellDep {
                tx_hash: canonical_hex(dep.out_point().tx_hash().as_slice()),
                index: dep.out_point().index().unpack(),
                dep_type: match dep.dep_type().as_slice()[0] {
                    0 => "code",
                    1 => "dep_group",
                    _ => return Err(anyhow!("unsupported dependency type")),
                }
                .to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    records.sort_by(|a, b| (&a.tx_hash, a.index).cmp(&(&b.tx_hash, b.index)));
    Ok(records)
}

pub(crate) fn decode_dependency_records(
    records: &[StoredMultiAssetCellDep],
) -> Result<Vec<CellDep>> {
    ensure!(
        (1..=64).contains(&records.len()),
        "recovery requires 1..=64 code dependencies"
    );
    ensure!(
        records
            .windows(2)
            .all(|pair| (&pair[0].tx_hash, pair[0].index) < (&pair[1].tx_hash, pair[1].index)),
        "dependency OutPoints must be unique and ordered"
    );
    let cell_deps = records
        .iter()
        .map(|dep| {
            let raw = decode_hex(&dep.tx_hash, 32)?;
            ensure!(
                raw.len() == 32 && raw.iter().any(|byte| *byte != 0),
                "invalid dependency transaction hash"
            );
            let mut hash = [0; 32];
            hash.copy_from_slice(&raw);
            let dep_type = match dep.dep_type.as_str() {
                "code" => DepType::Code,
                "dep_group" => DepType::DepGroup,
                _ => return Err(anyhow!("unsupported dependency type")),
            };
            Ok(CellDep::new_builder()
                .out_point(OutPoint::new(hash.pack(), dep.index))
                .dep_type(dep_type)
                .build())
        })
        .collect::<Result<_>>()?;
    Ok(cell_deps)
}

impl StoredMultiAssetPackage {
    pub fn recovery(&self) -> Result<MultiAssetRecoveryPackage> {
        let decoded = self.decode()?;
        Ok(MultiAssetRecoveryPackage::decode(
            &decoded.header,
            &decoded.witness,
            &decoded.signatures,
            decoded.carrier_capacity,
        )?)
    }

    pub fn value_subject(&self) -> Result<ValueSubject> {
        let summary = self.validate()?;
        let mut subject = ValueSubject::default();
        subject.add_ckb(u128::from(summary.state_carrier_capacity.parse::<u64>()?))?;
        for asset in summary.assets {
            subject.add_ckb(u128::from(asset.reserve.parse::<u64>()?))?;
            subject.add_ckb(u128::from(asset.business_ckb.parse::<u64>()?))?;
            if let Some(type_hash) = asset.type_hash {
                subject.add_xudt(&type_hash, asset.amount.parse::<u128>()?)?;
            }
        }
        Ok(subject)
    }
    pub fn from_recovery(
        package: &MultiAssetRecoveryPackage,
        cell_deps: &[CellDep],
    ) -> Result<Self> {
        let cell_deps = dependency_records(cell_deps)?;
        Self::with_dependency_records(package, cell_deps)
    }

    pub(crate) fn with_dependency_records(
        package: &MultiAssetRecoveryPackage,
        cell_deps: Vec<StoredMultiAssetCellDep>,
    ) -> Result<Self> {
        package.validate()?;
        let stored = Self {
            schema: MULTI_ASSET_PACKAGE_SCHEMA.to_string(),
            header_hex: canonical_hex(&package.state.encode()?),
            witness_hex: canonical_hex(&encode_multi_asset_witness(
                &package.manifest,
                &package.settlement,
                &package.outpoints,
                &package.scripts,
            )?),
            signature_witness_hex: canonical_hex(&encode_multi_asset_signatures(
                &package.authorization,
            )?),
            state_carrier_capacity: package.state_carrier_capacity.to_string(),
            cell_deps,
        };
        stored.validate()?;
        Ok(stored)
    }

    pub(crate) fn decode(&self) -> Result<DecodedMultiAssetPackage> {
        ensure!(
            self.schema == MULTI_ASSET_PACKAGE_SCHEMA,
            "unsupported multi-asset package schema"
        );
        let carrier_capacity = self
            .state_carrier_capacity
            .parse::<u64>()
            .context("invalid State carrier capacity")?;
        ensure!(
            carrier_capacity.to_string() == self.state_carrier_capacity,
            "State carrier capacity must be canonical unsigned decimal"
        );
        let header = decode_hex(&self.header_hex, wire::MULTI_ASSET_STATE_HEADER_LEN)?;
        let witness = decode_hex(&self.witness_hex, wire::MULTI_ASSET_MAX_WITNESS_LEN)?;
        let signatures = decode_hex(&self.signature_witness_hex, BILATERAL_SIGNATURE_WITNESS_LEN)?;
        let cell_deps = decode_dependency_records(&self.cell_deps)?;
        Ok(DecodedMultiAssetPackage {
            header,
            witness,
            signatures,
            carrier_capacity,
            cell_deps,
        })
    }

    pub fn validate(&self) -> Result<MultiAssetPackageSummary> {
        let decoded = self.decode()?;
        let header = wire::MultiAssetStateHeader::parse(&decoded.header).map_err(wire_error)?;
        let witness = wire::MultiAssetWitness::parse(&decoded.witness).map_err(wire_error)?;
        witness.validate_header(&header).map_err(wire_error)?;
        let signatures =
            BilateralSignatureWitness::parse(&decoded.signatures).map_err(wire_error)?;
        header.verify_signatures(&signatures).map_err(wire_error)?;
        let scripts = witness.scripts();
        ensure!(
            wire::multi_asset_occupied_capacity(scripts.script(2).map_err(wire_error)?, None, 0)
                .map_err(wire_error)?
                <= decoded.carrier_capacity,
            "State carrier cannot fund its refund output"
        );
        ensure!(
            wire::multi_asset_occupied_capacity(
                scripts.script(5).map_err(wire_error)?,
                Some(scripts.script(4).map_err(wire_error)?),
                wire::MULTI_ASSET_STATE_HEADER_LEN as u64
            )
            .map_err(wire_error)?
                <= decoded.carrier_capacity,
            "State carrier is below occupied capacity"
        );
        let base = header;
        let mut assets = Vec::new();
        for index in 0..witness.manifest().count() {
            let entry = witness.manifest().entry(index).map_err(wire_error)?;
            assets.push(MultiAssetPackageBalance {
                type_hash: (entry.asset.kind == 1).then(|| canonical_hex(&entry.asset.type_hash)),
                reserve: entry.allocation.reserve.to_string(),
                business_ckb: entry.allocation.business_ckb.to_string(),
                amount: entry.allocation.amount.to_string(),
            });
        }
        Ok(MultiAssetPackageSummary {
            package_id: canonical_hex(&header.signing_digest()),
            channel_id: canonical_hex(base.channel_id()),
            funding_context_id: canonical_hex(&header.funding_context_id().map_err(wire_error)?),
            state_number: base.state_number().to_string(),
            phase: if base.phase() == morph_script_common::PHASE_ACTIVE {
                "active"
            } else {
                "settling"
            }
            .to_string(),
            vaults_bound: header.vaults_are_bound(),
            vault_count: header.vault_count(),
            witness_bytes: decoded.witness.len(),
            dependency_count: decoded.cell_deps.len(),
            state_carrier_capacity: self.state_carrier_capacity.clone(),
            signer_pubkeys: [
                canonical_hex(signatures.pubkey(0)),
                canonical_hex(signatures.pubkey(1)),
            ],
            assets,
        })
    }
}

pub fn read_package(path: &Path) -> Result<StoredMultiAssetPackage> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PACKAGE_JSON_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_PACKAGE_JSON_BYTES,
        "multi-asset JSON package exceeds size limit"
    );
    let package: StoredMultiAssetPackage = serde_json::from_slice(&bytes)?;
    package.validate()?;
    Ok(package)
}

pub fn write_package(dir: &Path, package: &StoredMultiAssetPackage) -> Result<std::path::PathBuf> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let summary = package.validate()?;
    let parent = dir
        .join(summary.channel_id.trim_start_matches("0x"))
        .join(summary.funding_context_id.trim_start_matches("0x"));
    #[cfg(unix)]
    let existing_parent = parent
        .ancestors()
        .find(|path| path.is_dir())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    fs::create_dir_all(&parent)?;
    let path = parent.join(format!(
        "{:020}-{}.json",
        summary.state_number.parse::<u64>()?,
        summary.package_id.trim_start_matches("0x")
    ));
    if path.exists() {
        ensure!(
            read_package(&path)? == *package,
            "recovery package path already contains different evidence"
        );
        #[cfg(unix)]
        {
            File::open(&path)?.sync_all()?;
            sync_recovery_directories(&parent, &existing_parent)?;
        }
        return Ok(path);
    }
    let temporary = crate::packages::atomic_json_tmp_path(&path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(package)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    sync_recovery_directories(&parent, &existing_parent)?;
    Ok(path)
}

pub fn fixture_package() -> Result<StoredMultiAssetPackage> {
    fn script(code: u8, args: &[u8]) -> Script {
        Script::new_builder()
            .code_hash([code; 32].pack())
            .hash_type(ScriptHashType::Data1)
            .args(args.pack())
            .build()
    }
    let anchor = [4; 32];
    let since = morph_script_common::relative_block_since(6).map_err(wire_error)?;
    let mut state_args = anchor.to_vec();
    state_args.extend_from_slice(&since.to_le_bytes());
    let state_type = script(3, &state_args);
    let state_lock = script(2, state_type.calc_script_hash().as_slice());
    let vault_args = wire::encode_multi_asset_vault_args(
        &anchor,
        since,
        &state_type.calc_script_hash().unpack(),
        &state_lock.calc_script_hash().unpack(),
    )
    .map_err(wire_error)?;
    let vault_lock = script(1, &vault_args);
    let mut locks = [script(4, &[1; 20]), script(4, &[2; 20])];
    locks.sort_by_key(Script::calc_script_hash);
    let mut types = [script(5, &[1; 32]), script(5, &[2; 32])];
    types.sort_by_key(Script::calc_script_hash);
    let manifest = MultiAssetManifest {
        vaults: types
            .iter()
            .map(|script| MultiAssetVault {
                asset: VaultAsset::Xudt(script.calc_script_hash().unpack()),
                lock_hash: vault_lock.calc_script_hash().unpack(),
                value: MultiAssetValue {
                    reserve: 40_000_000_000,
                    business_ckb: 10_000_000_000,
                    amount: u128::MAX / 2,
                },
            })
            .collect(),
    };
    let settlement = MultiAssetSettlement {
        participant_lock_hashes: locks
            .each_ref()
            .map(|script| script.calc_script_hash().unpack()),
        carrier_refund_lock_hash: locks[0].calc_script_hash().unpack(),
        payouts: manifest
            .vaults
            .iter()
            .map(|vault| MultiAssetPayout {
                asset: vault.asset.clone(),
                values: [
                    MultiAssetValue {
                        reserve: 20_000_000_000,
                        business_ckb: 6_000_000_000,
                        amount: vault.value.amount - 7,
                    },
                    MultiAssetValue {
                        reserve: 20_000_000_000,
                        business_ckb: 4_000_000_000,
                        amount: 7,
                    },
                ],
            })
            .collect(),
    };
    let points = vec![
        MultiAssetOutPoint {
            tx_hash: [44; 32],
            index: 1,
        },
        MultiAssetOutPoint {
            tx_hash: [44; 32],
            index: 2,
        },
    ];
    let content = manifest.commitment()?;
    let mut keys = [
        SigningKey::from_slice(&[1; 32]).map_err(|_| anyhow!("invalid fixture signing key"))?,
        SigningKey::from_slice(&[2; 32]).map_err(|_| anyhow!("invalid fixture signing key"))?,
    ];
    keys.sort_by_key(|key| {
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    });
    let public = keys
        .each_ref()
        .map(|key| key.verifying_key().to_encoded_point(true));
    let state = MultiAssetState {
        header: MultiAssetHeader {
            protocol_version: 1,
            chain_id: [1; 32],
            signature_scheme_id: 1,
            channel_id: [2; 32],
            funding_epoch: 0,
            funding_anchor: anchor,
            state_number: 9,
            mode: Mode::BilateralPlain,
            phase: Phase::Settling,
            participants_commitment: participants_commitment(
                2,
                &[public[0].as_bytes(), public[1].as_bytes()],
            ),
            asset_registry_commitment: asset_registry_commitment(&manifest.registry()?),
            settlement_descriptor_commitment: settlement.commitment()?,
            descriptor_version: wire::MULTI_ASSET_DESCRIPTOR_VERSION,
            challenge_policy_commitment: [3; 32],
            state_layout_version: wire::MULTI_ASSET_STATE_LAYOUT_VERSION,
        },
        vault_content_set_root: content,
        vault_outpoint_set_root: multi_asset_outpoint_commitment(&manifest, &points)?,
        vault_count: 2,
    };
    let digest = state.signing_digest()?;
    let authorization = StateAuthorization {
        threshold: 2,
        signatures: keys
            .iter()
            .map(|key| {
                let signature: Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| anyhow!("fixture state signing failed"))?;
                Ok(ParticipantSignature {
                    pubkey_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                    signature: signature.to_bytes().to_vec(),
                })
            })
            .collect::<Result<_>>()?,
    };
    let fixture_deps = (1u8..=5)
        .map(|value| {
            CellDep::new_builder()
                .out_point(OutPoint::new([value; 32].pack(), 0))
                .build()
        })
        .collect::<Vec<_>>();
    StoredMultiAssetPackage::from_recovery(
        &MultiAssetRecoveryPackage {
            state,
            authorization,
            manifest,
            settlement,
            outpoints: points,
            state_carrier_capacity: 100_000_000_000,
            scripts: MultiAssetRecoveryScripts {
                vault_lock: vault_lock.as_slice().to_vec(),
                participant_locks: locks.each_ref().map(|script| script.as_slice().to_vec()),
                carrier_refund_lock: locks[0].as_slice().to_vec(),
                state_type: state_type.as_slice().to_vec(),
                state_lock: state_lock.as_slice().to_vec(),
                type_scripts: types
                    .iter()
                    .map(|script| MultiAssetTypeScript {
                        type_hash: script.calc_script_hash().unpack(),
                        script: script.as_slice().to_vec(),
                    })
                    .collect(),
            },
        },
        &fixture_deps,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multi_asset_package_keeps_u128_values_lossless() {
        let package = fixture_package().unwrap();
        let summary = package.validate().unwrap();
        assert_eq!(summary.assets[0].amount, (u128::MAX / 2).to_string());
        let raw = serde_json::to_string(&package).unwrap();
        let restored: StoredMultiAssetPackage = serde_json::from_str(&raw).unwrap();
        assert_eq!(restored.validate().unwrap(), summary);
        let shared: StoredMultiAssetPackage = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/multi-asset.json"
        ))
        .unwrap();
        assert_eq!(
            shared, package,
            "Rust and TypeScript must share the canonical signed fixture"
        );
        assert_eq!(
            serde_json::to_value(summary).unwrap(),
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../sdk/typescript/test/fixtures/multi-asset-summary.json"
            ))
            .unwrap()
        );
    }
    #[test]
    fn multi_asset_package_rejects_noncanonical_and_unsupported_evidence() {
        let package = fixture_package().unwrap();
        for mutation in 0..9 {
            let mut package = package.clone();
            match mutation {
                0 => package.schema.push('x'),
                1 => package.state_carrier_capacity.insert(0, '0'),
                2 => package.signature_witness_hex.push_str("00"),
                3 => package.witness_hex.replace_range(12..14, "FF"),
                4 => package.state_carrier_capacity = "1".to_string(),
                5 => package.cell_deps.clear(),
                6 => package.cell_deps.push(package.cell_deps[0].clone()),
                7 => package.cell_deps[0].dep_type = "unknown".to_string(),
                _ => package.cell_deps[0].tx_hash = format!("0x{}", "00".repeat(32)),
            }
            assert!(package.validate().is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn multi_asset_recovery_store_is_durable_idempotent_and_private() {
        let dir = std::env::temp_dir().join(format!(
            "morph-multi-asset-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let package = fixture_package().unwrap();
        let path = write_package(&dir, &package).unwrap();
        assert_eq!(read_package(&path).unwrap(), package);
        assert_eq!(write_package(&dir, &package).unwrap(), path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let mut changed = package.clone();
        changed.state_carrier_capacity = "200000000000".to_string();
        changed.validate().unwrap();
        assert!(write_package(&dir, &changed).is_err());
        assert_eq!(read_package(&path).unwrap(), package);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
