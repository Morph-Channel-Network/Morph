use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{packed, prelude::*};
use morph_core::{MultiAssetManifest, VALUE_LIMIT_POLICY_SCHEMA, ValueLimitPolicy, ValueSubject};
use morph_script_common::factory_multi_asset::FactoryReducedReleaseWitness;

use crate::multi_asset_packages;

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

/// Extract validated current custody or a reviewed exact-body Factory request,
/// preserving component-wise peaks across
/// mutually exclusive transitions. Source-chain authority and live asset-code
/// qualification remain the native operator's separate RPC/VM obligations.
pub fn extract_value_subject(
    path: &Path,
    old_package: Option<&Path>,
) -> Result<(String, ValueSubject)> {
    let value: serde_json::Value =
        multi_asset_packages::read_bounded_json(path, crate::factory_packets::MAX_PACKET_BYTES)?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("package {} carries no schema field", path.display()))?;
    ensure!(
        old_package.is_none() || schema == "morph.multi_asset_splice_funding.v1",
        "--old-package applies only to a current signed splice funding bundle"
    );
    let subject = match schema {
        multi_asset_packages::MULTI_ASSET_PACKAGE_SCHEMA => {
            multi_asset_packages::read_package(path)?.value_subject()?
        }
        "morph.conditional_batch_package.v1" => {
            let package = crate::conditional_packages::read_package(path)?;
            package.source_package.value_subject()?
        }
        "morph.multi_asset_root_funding.v1" => {
            let package: crate::multi_asset_funding::RootFundingExport =
                serde_json::from_value(value.clone())?;
            let recovery = package.recovery_package.recovery()?;
            let tx = packed::Transaction::from_slice(&multi_asset_packages::decode_hex(
                &package.transaction_hex,
                crate::multi_asset_funding::MAX_FUNDING_BYTES,
            )?)?;
            crate::multi_asset_funding::validate_root_funding(&recovery, &tx)?;
            ValueSubject::from_manifest(&recovery.manifest, recovery.state_carrier_capacity)?
        }
        "morph.multi_asset_splice_funding.v1" => {
            let old_path = old_package.context("current splice policy checking requires --old-package with its signed source recovery")?;
            let old = multi_asset_packages::read_package(old_path)?.recovery()?;
            let package: crate::multi_asset_splice_transaction::SpliceFundingExport =
                serde_json::from_value(value.clone())?;
            let next = package.recovery_package.recovery()?;
            let tx = packed::Transaction::from_slice(&multi_asset_packages::decode_hex(
                &package.transaction_hex,
                256 * 1024,
            )?)?;
            crate::multi_asset_splice_transaction::SpliceDraft::from_signed_transaction(
                &old, &next, &tx,
            )?;
            let mut subject =
                ValueSubject::from_manifest(&old.manifest, old.state_carrier_capacity)?;
            subject.include_peak(&ValueSubject::from_manifest(
                &next.manifest,
                next.state_carrier_capacity,
            )?);
            subject
        }
        crate::factory_transition_packages::SCHEMA => {
            let package = crate::factory_transition_packages::read(path)?;
            factory_transition_subject(&package.witness()?)?
        }
        crate::factory_packets::REQUEST_SCHEMA => {
            let packet = crate::factory_packets::read_for_delivery_review(path)?;
            ValueSubject::from_factory_request(&packet.decode_for_delivery_review()?)?
        }
        other => {
            return Err(anyhow!(
                "unsupported current value-bearing package schema {other}; retired single-Vault/splice schemas are rejected"
            ));
        }
    };
    Ok((schema.to_string(), subject))
}

pub(crate) fn factory_transition_subject(
    frame: &FactoryReducedReleaseWitness<'_>,
) -> Result<ValueSubject> {
    frame
        .verify()
        .map_err(|error| anyhow!("invalid current Factory transition: {error:?}"))?;
    let mut peak = ValueSubject::from_manifest(
        &MultiAssetManifest::decode(frame.source().as_bytes())?,
        frame.carrier_capacity(),
    )?;
    let mut future = ValueSubject::from_manifest(
        &MultiAssetManifest::decode(frame.retained().as_bytes())?,
        frame.carrier_capacity(),
    )?;
    if let Some(intent) = frame.child_intent() {
        for index in 0..intent.child_count() {
            let child = intent
                .child(index)
                .map_err(|error| anyhow!("invalid Factory child: {error:?}"))?;
            future.add_manifest(
                &MultiAssetManifest::decode(child.evidence.manifest().as_bytes())?,
                child.carrier_capacity,
            )?;
        }
    }
    peak.include_peak(&future);
    Ok(peak)
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
    fn save(name: &str, value: &serde_json::Value) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "morph-current-value-{name}-{}-{}.json",
            std::process::id(),
            now_unix_ms().unwrap()
        ));
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
    #[test]
    fn current_recovery_limits_include_reserve_business_carrier_and_each_type() {
        let package = multi_asset_packages::fixture_package().unwrap();
        let path = save("recovery", &serde_json::to_value(&package).unwrap());
        let (schema, subject) = extract_value_subject(&path, None).unwrap();
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
        assert!(extract_value_subject(&path, Some(&path)).is_err());
    }
    #[test]
    fn conditional_limits_use_whole_signed_custody_including_pending_ckb() {
        let package = crate::conditional_packages::fixture_package().unwrap();
        let path = save("conditional", &serde_json::to_value(&package).unwrap());
        let (_, subject) = extract_value_subject(&path, None).unwrap();
        assert_eq!(subject.ckb_capacity, 200_000_000_000);
        assert_eq!(subject.xudt_amounts.len(), 1);
        assert_eq!(subject.xudt_amounts.values().next(), Some(&(u128::MAX / 2)));
        let mut json = serde_json::to_value(&package).unwrap();
        json["source_package"]["signature_witness_hex"] = serde_json::json!("0x00");
        let bad = save("conditional-bad", &json);
        assert!(extract_value_subject(&bad, None).is_err());
    }
    #[test]
    fn factory_request_policy_counts_simultaneous_children_and_external_carriers() {
        let fixture = crate::factory_packets::sdk_packet_fixture();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "reduced_child_delivered")
            .unwrap();
        let path = save("current-factory-child-request", &case["request"]);
        let (schema, subject) = extract_value_subject(&path, None).unwrap();
        assert_eq!(schema, crate::factory_packets::REQUEST_SCHEMA);
        // The source holds 2000 CKB plus one 1000-CKB carrier. Afterward,
        // retained and child custody coexist with two independent carriers.
        assert_eq!(subject.ckb_capacity, 400_000_000_000);
        assert_eq!(subject.xudt_amounts.len(), 1);
        let mut unsigned_shape = case["request"].clone();
        unsigned_shape["target_rights"] = serde_json::json!([]);
        assert!(
            extract_value_subject(
                &save("invalid-current-factory-rights", &unsigned_shape),
                None
            )
            .is_err()
        );
    }
    #[test]
    fn current_factory_policy_preserves_all_five_verified_transition_classes() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/factory-transitions.json"
        ))
        .unwrap();
        let cases = corpus["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 5);
        let mut operations = std::collections::BTreeSet::new();
        for (index, case) in cases.iter().enumerate() {
            operations.insert(case["operation"].as_str().unwrap());
            let path = save(&format!("factory-transition-{index}"), &case["package"]);
            let (schema, subject) = extract_value_subject(&path, None).unwrap();
            assert_eq!(schema, crate::factory_transition_packages::SCHEMA);
            let view = crate::factory_transition_packages::read(&path).unwrap();
            let frame = view.witness().unwrap();
            let old = ValueSubject::from_manifest(
                &MultiAssetManifest::decode(frame.source().as_bytes()).unwrap(),
                frame.carrier_capacity(),
            )
            .unwrap();
            assert!(subject.ckb_capacity >= old.ckb_capacity);
            for (asset, amount) in &old.xudt_amounts {
                assert!(
                    subject
                        .xudt_amounts
                        .get(asset)
                        .is_some_and(|maximum| maximum >= amount)
                );
            }
            if case["operation"] == "ReducedDeposit" {
                assert!(subject.ckb_capacity > old.ckb_capacity);
            }
            let mut bad = case["package"].clone();
            let transaction = view.transaction();
            let raw = transaction.raw();
            let mut outputs = raw.outputs().into_iter().collect::<Vec<_>>();
            outputs[0] = outputs[0]
                .clone()
                .as_builder()
                .capacity(u64::from(outputs[0].capacity()) + 1)
                .build();
            let modified = transaction
                .clone()
                .as_builder()
                .raw(raw.as_builder().outputs(outputs.pack()).build())
                .build();
            bad["transaction_hex"] =
                serde_json::json!(multi_asset_packages::canonical_hex(modified.as_slice()));
            assert!(
                extract_value_subject(
                    &save(&format!("factory-transition-bad-{index}"), &bad),
                    None
                )
                .is_err()
            );
            let mut detached = case["package"].clone();
            detached["transition_witness_hex"] = serde_json::json!("0x");
            assert!(
                extract_value_subject(
                    &save(&format!("factory-transition-extra-{index}"), &detached),
                    None
                )
                .is_err()
            );
        }
        assert_eq!(
            operations,
            std::collections::BTreeSet::from([
                "ReducedRelease",
                "ReducedRights",
                "ReducedDeposit",
                "FullCustody",
                "ReducedChild"
            ])
        );
    }
    #[test]
    fn root_policy_checks_exact_transaction_creation_authorization() {
        let fixture = crate::multi_asset_funding::root_collection_tests::fixture();
        let path = save("root", &fixture["funding"]);
        let (_, subject) = extract_value_subject(&path, None).unwrap();
        let package: crate::multi_asset_funding::RootFundingExport =
            serde_json::from_value(fixture["funding"].clone()).unwrap();
        assert_eq!(subject, package.recovery_package.value_subject().unwrap());
        let mut tx = packed::Transaction::from_slice(
            &multi_asset_packages::decode_hex(&package.transaction_hex, 256 * 1024).unwrap(),
        )
        .unwrap();
        let raw = tx.raw();
        let mut outputs = raw.outputs().into_iter().collect::<Vec<_>>();
        outputs[0] = outputs[0]
            .clone()
            .as_builder()
            .capacity(u64::from(outputs[0].capacity()) + 1)
            .build();
        tx = tx
            .as_builder()
            .raw(raw.as_builder().outputs(outputs.pack()).build())
            .build();
        let mut modified = fixture["funding"].clone();
        modified["transaction_hex"] =
            serde_json::json!(multi_asset_packages::canonical_hex(tx.as_slice()));
        assert!(
            extract_value_subject(&save("root-unauthorized-reprice", &modified), None).is_err()
        );
    }
    #[test]
    fn observed_current_splices_require_old_authority_and_preserve_removed_and_admitted_assets() {
        let transitions: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../sdk/typescript/test/fixtures/multi-asset-splice-transitions.json"
        ))
        .unwrap();
        for (index, transition) in transitions.into_iter().enumerate() {
            let path = save(&format!("splice-{index}"), &transition["funding"]);
            let source = save(&format!("source-{index}"), &transition["current"]);
            assert!(extract_value_subject(&path, None).is_err());
            let (_, subject) = extract_value_subject(&path, Some(&source)).unwrap();
            let before: multi_asset_packages::StoredMultiAssetPackage =
                serde_json::from_value(transition["current"].clone()).unwrap();
            let after: multi_asset_packages::StoredMultiAssetPackage =
                serde_json::from_value(transition["funding"]["recovery_package"].clone()).unwrap();
            let old = before.value_subject().unwrap();
            let new = after.value_subject().unwrap();
            assert_eq!(subject.ckb_capacity, old.ckb_capacity.max(new.ckb_capacity));
            let excluded = if transition["name"] == "remove" {
                old.xudt_amounts
                    .keys()
                    .find(|key| !new.xudt_amounts.contains_key(*key))
                    .unwrap()
            } else {
                new.xudt_amounts
                    .keys()
                    .find(|key| !old.xudt_amounts.contains_key(*key))
                    .unwrap()
            };
            let mut policy = ValueLimitPolicy {
                schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
                created_unix_ms: 1,
                max_channel_ckb_capacity: u64::MAX,
                max_xudt_amounts: subject.xudt_amounts.clone(),
            };
            policy.enforce(&subject).unwrap();
            policy.max_xudt_amounts.remove(excluded);
            assert!(matches!(
                policy.enforce(&subject),
                Err(ValueLimitError::UnlistedXudt { .. })
            ));
            let wrong = save(
                &format!("wrong-source-{index}"),
                &serde_json::to_value(multi_asset_packages::fixture_package().unwrap()).unwrap(),
            );
            assert!(extract_value_subject(&path, Some(&wrong)).is_err());
        }
    }
    #[test]
    fn all_retired_and_unknown_package_schemas_fail_closed() {
        for (index, schema) in [
            "morph.splice_package",
            "morph.factory_splice_package",
            "morph.factory_reduced_splice_package",
            "morph.factory_multi_asset_materialisation.v1",
            "morph.other_package",
        ]
        .into_iter()
        .enumerate()
        {
            let path = save(
                &format!("retired-{index}"),
                &serde_json::json!({"schema":schema}),
            );
            assert!(extract_value_subject(&path, None).is_err());
        }
        for (index, schema) in [
            "morph.multi_asset_root_funding.v1",
            "morph.multi_asset_splice_funding.v1",
            "morph.factory_transition_package.v1",
            "morph.factory_multi_asset_materialisation.v1",
        ]
        .into_iter()
        .enumerate()
        {
            let path = save(
                &format!("malformed-{index}"),
                &serde_json::json!({"schema":schema}),
            );
            assert!(extract_value_subject(&path, None).is_err());
        }
    }
}
