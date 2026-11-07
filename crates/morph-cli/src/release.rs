use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use morph_core::blake2b256;
use serde::{Deserialize, Serialize};

pub const CONTRACT_MANIFEST_SCHEMA: &str = "morph.contract_release_manifest";
pub const FACTORY_RELEASE_PROFILE: &str = "morph-current-custody";
pub const CONTRACT_RUST_TOOLCHAIN: &str = "1.95.0";
pub const CONTRACT_BUILD_TARGET: &str = "riscv64imac-unknown-none-elf";
pub const CONTRACT_BUILD_PROFILE: &str = "release";

const CONTRACTS: [ContractSpec; 8] = [
    ContractSpec::preproduction("morph-state-lock"),
    ContractSpec::preproduction("morph-state-type"),
    ContractSpec::preproduction("morph-factory-type"),
    ContractSpec::preproduction("morph-factory-vault-lock"),
    ContractSpec::preproduction("morph-vault-lock"),
    ContractSpec::preproduction("morph-batch-lock"),
    ContractSpec::preproduction("morph-sponsor-lock"),
    ContractSpec::devnet_only("morph-devnet-xudt"),
];

#[derive(Debug, Clone, Copy)]
struct ContractSpec {
    name: &'static str,
    deployment_scope: &'static str,
}

impl ContractSpec {
    const fn preproduction(name: &'static str) -> Self {
        Self {
            name,
            deployment_scope: "controlled_devnet",
        }
    }

    const fn devnet_only(name: &'static str) -> Self {
        Self {
            name,
            deployment_scope: "devnet_only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractReleaseManifest {
    pub schema: String,
    pub release_profile: String,
    pub rust_toolchain: String,
    pub target: String,
    pub build_profile: String,
    pub cargo_locked: bool,
    pub scripts: Vec<ContractArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractArtifact {
    pub name: String,
    pub file: String,
    pub deployment_scope: String,
    pub size_bytes: u64,
    pub ckb_data_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContractManifestVerification {
    pub schema: &'static str,
    pub manifest_path: String,
    pub contracts_dir: String,
    pub release_profile: String,
    pub target: String,
    pub script_count: usize,
    pub verified: bool,
    pub scripts: Vec<ContractArtifact>,
}

pub fn build_contract_manifest(contracts_dir: &Path) -> Result<ContractReleaseManifest> {
    let scripts = CONTRACTS
        .iter()
        .map(|spec| contract_artifact(contracts_dir, *spec))
        .collect::<Result<Vec<_>>>()?;
    Ok(ContractReleaseManifest {
        schema: CONTRACT_MANIFEST_SCHEMA.to_string(),
        release_profile: FACTORY_RELEASE_PROFILE.to_string(),
        rust_toolchain: CONTRACT_RUST_TOOLCHAIN.to_string(),
        target: CONTRACT_BUILD_TARGET.to_string(),
        build_profile: CONTRACT_BUILD_PROFILE.to_string(),
        cargo_locked: true,
        scripts,
    })
}

pub fn verify_contract_manifest(
    manifest_path: &Path,
    contracts_dir: &Path,
) -> Result<ContractManifestVerification> {
    let bytes = fs::read(manifest_path).with_context(|| {
        format!(
            "failed to read contract release manifest {}",
            manifest_path.display()
        )
    })?;
    let manifest: ContractReleaseManifest = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse contract release manifest {}",
            manifest_path.display()
        )
    })?;
    validate_manifest_metadata(&manifest)?;

    let actual = build_contract_manifest(contracts_dir)?;
    ensure!(
        manifest.scripts == actual.scripts,
        "built contract artefacts do not match {}; regenerate the reviewed manifest only after auditing the contract change",
        manifest_path.display()
    );

    Ok(ContractManifestVerification {
        schema: "morph.contract_release_manifest_verification",
        manifest_path: display_path(manifest_path),
        contracts_dir: display_path(contracts_dir),
        release_profile: manifest.release_profile,
        target: manifest.target,
        script_count: actual.scripts.len(),
        verified: true,
        scripts: actual.scripts,
    })
}

fn validate_manifest_metadata(manifest: &ContractReleaseManifest) -> Result<()> {
    ensure!(
        manifest.schema == CONTRACT_MANIFEST_SCHEMA,
        "unsupported contract manifest schema {}",
        manifest.schema
    );
    ensure!(
        manifest.release_profile == FACTORY_RELEASE_PROFILE,
        "contract manifest release profile must be {FACTORY_RELEASE_PROFILE}"
    );
    ensure!(
        manifest.rust_toolchain == CONTRACT_RUST_TOOLCHAIN,
        "contract manifest Rust toolchain must be {CONTRACT_RUST_TOOLCHAIN}"
    );
    ensure!(
        manifest.target == CONTRACT_BUILD_TARGET,
        "contract manifest target must be {CONTRACT_BUILD_TARGET}"
    );
    ensure!(
        manifest.build_profile == CONTRACT_BUILD_PROFILE,
        "contract manifest build profile must be {CONTRACT_BUILD_PROFILE}"
    );
    ensure!(
        manifest.cargo_locked,
        "contract manifest must attest a Cargo.lock-constrained build"
    );
    ensure!(
        manifest.scripts.len() == CONTRACTS.len(),
        "contract manifest must contain exactly {} scripts",
        CONTRACTS.len()
    );
    for (artifact, spec) in manifest.scripts.iter().zip(CONTRACTS) {
        ensure!(
            artifact.name == spec.name,
            "contract manifest script order/name mismatch: expected {}, got {}",
            spec.name,
            artifact.name
        );
        ensure!(
            artifact.file == spec.name,
            "contract manifest file for {} must be the bare ELF name",
            spec.name
        );
        ensure!(
            artifact.deployment_scope == spec.deployment_scope,
            "contract manifest deployment scope for {} must be {}",
            spec.name,
            spec.deployment_scope
        );
        ensure!(
            artifact.size_bytes > 0,
            "{} ELF must not be empty",
            spec.name
        );
        ensure!(
            is_canonical_hex32(&artifact.ckb_data_hash),
            "{} ckb_data_hash must be canonical 0x-prefixed hex32",
            spec.name
        );
    }
    Ok(())
}

fn contract_artifact(contracts_dir: &Path, spec: ContractSpec) -> Result<ContractArtifact> {
    let path = contracts_dir.join(spec.name);
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read built contract ELF {}", path.display()))?;
    ensure!(
        !bytes.is_empty(),
        "built contract ELF {} is empty",
        path.display()
    );
    Ok(ContractArtifact {
        name: spec.name.to_string(),
        file: spec.name.to_string(),
        deployment_scope: spec.deployment_scope.to_string(),
        size_bytes: u64::try_from(bytes.len()).context("contract ELF length does not fit u64")?,
        ckb_data_hash: format!("0x{}", hex::encode(blake2b256(&bytes))),
    })
}

fn is_canonical_hex32(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn display_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_requires_lowercase_prefixed_hex32() {
        assert!(is_canonical_hex32(&format!("0x{}", "ab".repeat(32))));
        assert!(!is_canonical_hex32(&"ab".repeat(32)));
        assert!(!is_canonical_hex32(&format!("0x{}", "AB".repeat(32))));
        assert!(!is_canonical_hex32("0x12"));
    }

    #[test]
    fn metadata_rejects_an_unlocked_build() {
        let mut manifest = ContractReleaseManifest {
            schema: CONTRACT_MANIFEST_SCHEMA.to_string(),
            release_profile: FACTORY_RELEASE_PROFILE.to_string(),
            rust_toolchain: CONTRACT_RUST_TOOLCHAIN.to_string(),
            target: CONTRACT_BUILD_TARGET.to_string(),
            build_profile: CONTRACT_BUILD_PROFILE.to_string(),
            cargo_locked: false,
            scripts: CONTRACTS
                .iter()
                .map(|spec| ContractArtifact {
                    name: spec.name.to_string(),
                    file: spec.name.to_string(),
                    deployment_scope: spec.deployment_scope.to_string(),
                    size_bytes: 1,
                    ckb_data_hash: format!("0x{}", "00".repeat(32)),
                })
                .collect(),
        };
        let error = validate_manifest_metadata(&manifest).unwrap_err();
        assert!(error.to_string().contains("Cargo.lock"));

        manifest.cargo_locked = true;
        validate_manifest_metadata(&manifest).unwrap();
    }
}
