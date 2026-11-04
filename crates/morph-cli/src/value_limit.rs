use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use morph_core::{
    VALUE_LIMIT_POLICY_SCHEMA, ValueLimitPolicy, ValueSubject, VaultAsset, VaultAssetAmount,
};

use crate::{factory_packages, multi_asset_packages, splice_packages};

const FACTORY_SPLICE_SCHEMA: &str = "morph.factory_splice_package";
const FACTORY_REDUCED_SPLICE_SCHEMA: &str = "morph.factory_reduced_splice_package";
const BILATERAL_SPLICE_SCHEMA: &str = "morph.splice_package";

pub fn read_value_limit_policy(path: &Path) -> Result<ValueLimitPolicy> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read value-limit policy {}", path.display()))?;
    let policy: ValueLimitPolicy = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse value-limit policy {}", path.display()))?;
    policy
        .validate()
        .with_context(|| format!("invalid value-limit policy {}", path.display()))?;
    Ok(policy)
}

pub fn fixture_value_limit_policy() -> Result<ValueLimitPolicy> {
    let policy = ValueLimitPolicy {
        schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
        created_unix_ms: now_unix_ms()?,
        max_channel_ckb_capacity: 10_000_000_000_000,
        max_xudt_amounts: BTreeMap::from([
            (format!("0x{}", "2a".repeat(32)), 1_000_000u128),
            (format!("0x{}", "42".repeat(32)), 1_000_000u128),
        ]),
    };
    policy.validate()?;
    Ok(policy)
}

/// Extracts peak committed channel holdings from a fully validated package.
/// Supported schemas are the bilateral and factory splice families and the
/// multi-asset recovery profile; unknown/malformed packages fail closed.
pub fn extract_value_subject(path: &Path) -> Result<(String, ValueSubject)> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read package {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse package {}", path.display()))?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("package {} carries no schema field", path.display()))?;
    match schema {
        multi_asset_packages::MULTI_ASSET_PACKAGE_SCHEMA => {
            let package = multi_asset_packages::read_package(path)?;
            Ok((
                multi_asset_packages::MULTI_ASSET_PACKAGE_SCHEMA.to_string(),
                package.value_subject()?,
            ))
        }
        BILATERAL_SPLICE_SCHEMA => {
            let package = splice_packages::read_splice_package(path)?;
            let transition = package.validate()?;
            Ok((
                BILATERAL_SPLICE_SCHEMA.to_string(),
                peak_vault_subject(&transition.old_vault.assets, &transition.new_vault.assets)?,
            ))
        }
        FACTORY_SPLICE_SCHEMA => {
            let package = factory_packages::read_factory_splice_package(path)?;
            let transition = package.validate()?;
            Ok((
                FACTORY_SPLICE_SCHEMA.to_string(),
                peak_vault_subject(&transition.old_vault.assets, &transition.new_vault.assets)?,
            ))
        }
        FACTORY_REDUCED_SPLICE_SCHEMA => {
            let package = factory_packages::read_factory_reduced_splice_package(path)?;
            let transition = package.validate()?;
            Ok((
                FACTORY_REDUCED_SPLICE_SCHEMA.to_string(),
                peak_vault_subject(&transition.old_vault.assets, &transition.new_vault.assets)?,
            ))
        }
        other => Err(anyhow::anyhow!(
            "package schema {other} in {} is not a value-bearing surface covered by value-limit checks; \
             supported schemas: {BILATERAL_SPLICE_SCHEMA}, {FACTORY_SPLICE_SCHEMA}, {FACTORY_REDUCED_SPLICE_SCHEMA}, {}",
            path.display(),
            multi_asset_packages::MULTI_ASSET_PACKAGE_SCHEMA
        )),
    }
}

fn peak_vault_subject(
    old_assets: &[VaultAssetAmount],
    new_assets: &[VaultAssetAmount],
) -> Result<ValueSubject> {
    let old = vault_subject(old_assets)?;
    let new = vault_subject(new_assets)?;
    let mut peak = ValueSubject::default();
    peak.include_peak(&old);
    peak.include_peak(&new);
    Ok(peak)
}

fn vault_subject(assets: &[VaultAssetAmount]) -> Result<ValueSubject> {
    let mut subject = ValueSubject::default();
    for amount in assets {
        match &amount.asset {
            VaultAsset::Ckb => subject.add_ckb(amount.amount)?,
            VaultAsset::Xudt(type_hash) => subject.add_xudt_raw(*type_hash, amount.amount)?,
        }
    }
    Ok(subject)
}

fn now_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before unix epoch")?
        .as_millis()
        .try_into()
        .context("unix time does not fit in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use morph_core::ValueLimitError;

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("morph-value-limit-{name}-{}", std::process::id()))
    }

    #[test]
    fn fixture_policy_passes_builtin_factory_splice_fixture() {
        let package = crate::factory_packages::fixture_factory_splice_package_with_kind(
            crate::factory_packages::FixtureFactorySpliceKind::CkbSpliceIn,
        )
        .unwrap();
        let transition = package.validate().unwrap();
        let subject =
            peak_vault_subject(&transition.old_vault.assets, &transition.new_vault.assets).unwrap();
        fixture_value_limit_policy()
            .unwrap()
            .enforce(&subject)
            .unwrap();
    }

    #[test]
    fn multi_asset_limits_include_all_types_reserve_business_and_state_carrier() {
        let package = multi_asset_packages::fixture_package().unwrap();
        let path = test_path("multi-asset");
        fs::write(&path, serde_json::to_vec(&package).unwrap()).unwrap();
        let (schema, subject) = extract_value_subject(&path).unwrap();
        assert_eq!(schema, multi_asset_packages::MULTI_ASSET_PACKAGE_SCHEMA);
        assert_eq!(subject.ckb_capacity, 200_000_000_000);
        assert_eq!(subject.xudt_amounts.len(), 2);
        assert!(
            subject
                .xudt_amounts
                .values()
                .all(|amount| *amount == u128::MAX / 2)
        );
        let mut policy = ValueLimitPolicy {
            schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
            created_unix_ms: 1,
            max_channel_ckb_capacity: 200_000_000_000,
            max_xudt_amounts: subject.xudt_amounts.clone(),
        };
        policy.enforce(&subject).unwrap();
        policy.max_xudt_amounts.pop_first();
        assert!(matches!(
            policy.enforce(&subject),
            Err(ValueLimitError::UnlistedXudt { .. })
        ));
        policy.max_xudt_amounts = subject.xudt_amounts.clone();
        policy.max_channel_ckb_capacity -= 1;
        assert!(matches!(
            policy.enforce(&subject),
            Err(ValueLimitError::CkbOverLimit { .. })
        ));
    }

    #[test]
    fn bilateral_extraction_uses_validated_old_and_expected_new_vaults() {
        let package = crate::splice_packages::fixture_package_with_kind(
            crate::splice_packages::FixtureSpliceKind::XudtSpliceIn,
        )
        .unwrap();
        let transition = package.validate().unwrap();
        let path = test_path("bilateral");
        fs::write(&path, serde_json::to_vec(&package).unwrap()).unwrap();

        let (schema, subject) = extract_value_subject(&path).unwrap();
        let expected =
            peak_vault_subject(&transition.old_vault.assets, &transition.new_vault.assets).unwrap();
        assert_eq!(schema, BILATERAL_SPLICE_SCHEMA);
        assert_eq!(subject, expected);
    }

    #[test]
    fn extraction_rejects_unknown_schemas() {
        let path = test_path("unknown");
        fs::write(
            &path,
            serde_json::json!({"schema": "morph.other_package"}).to_string(),
        )
        .unwrap();
        assert!(extract_value_subject(&path).is_err());
    }

    #[test]
    fn extraction_rejects_malformed_supported_schema() {
        let path = test_path("malformed-supported");
        fs::write(
            &path,
            serde_json::json!({"schema": BILATERAL_SPLICE_SCHEMA}).to_string(),
        )
        .unwrap();
        assert!(extract_value_subject(&path).is_err());
    }

    #[test]
    fn unlisted_xudt_fails_closed() {
        let mut policy = fixture_value_limit_policy().unwrap();
        policy.max_xudt_amounts.clear();
        let mut subject = ValueSubject::default();
        subject.add_xudt_raw([0x2au8; 32], 1).unwrap();
        assert!(matches!(
            policy.enforce(&subject).unwrap_err(),
            ValueLimitError::UnlistedXudt { .. }
        ));
    }
}
