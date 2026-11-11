//! CLI entry points and baseline regression tests reuse the sole public Rust package implementation.
#[allow(unused_imports)]
pub use morph_packages::conditional_packages::*;

#[cfg(test)]
#[allow(unused_imports)]
use std::collections::BTreeMap;

#[cfg(test)]
#[allow(unused_imports)]
use std::path::Path;

#[cfg(test)]
#[allow(unused_imports)]
use anyhow::{Context, Result, anyhow, ensure};

#[cfg(test)]
#[allow(unused_imports)]
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

#[cfg(test)]
#[allow(unused_imports)]
use morph_core::{
    Bytes32, ConditionalBatch, ConditionalHashAlgorithm, ConditionalParticipant,
    ConditionalResolution, ConditionalTransferSpec, MultiAssetSettlementCapability,
    ParticipantSignature, StateAuthorization, VaultAsset, asset_registry_commitment,
    derive_conditional_payment_hash, multi_asset_outpoint_commitment,
};

#[cfg(test)]
#[allow(unused_imports)]
use morph_script_common::CONDITIONAL_BATCH_RESOLUTION_WITNESS_LEN;

#[cfg(test)]
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[allow(unused_imports)]
use crate::multi_asset_packages::{
    MultiAssetPackageSummary, StoredMultiAssetPackage, canonical_hex, decode_hex, read_bounded_json,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_is_linked_to_complete_signed_current_custody() {
        let package = fixture_package().unwrap();
        let summary = package.validate().unwrap();
        assert!(summary.source.capability.conditional().is_some());
        assert_eq!(summary.transfer_count, 1);
        assert_eq!(summary.total_capacity, "50000000000");
        assert_eq!(summary.resolved_capacities, ["24000000000", "26000000000"]);
        assert_eq!(
            summary.batch_lock_hash,
            summary
                .source
                .capability
                .conditional()
                .unwrap()
                .batch_lock_hash
        );
    }
    #[test]
    fn standalone_resolution_checks_preimages_refund_clock_and_complete_witness() {
        let source = fixture_source_package().unwrap();
        let refund = vec![StoredConditionalResolution::Refund {
            transfer_id: canonical_hex(&[33; 32]),
        }];
        assert!(
            StoredConditionalBatchPackage::from_source(source.clone(), refund.clone(), 499)
                .is_err()
        );
        let package = StoredConditionalBatchPackage::from_source(source, refund, 500).unwrap();
        assert_eq!(
            package.validate().unwrap().resolved_capacities,
            ["26000000000", "24000000000"]
        );
        let mut tampered = fixture_package().unwrap();
        tampered.resolution_witness_hex.replace_range(2..4, "ff");
        assert!(tampered.validate().is_err());
        assert!(
            StoredConditionalBatchPackage::from_source(
                fixture_source_package().unwrap(),
                vec![],
                0
            )
            .is_err()
        );
        let bad = vec![StoredConditionalResolution::Fulfill {
            transfer_id: canonical_hex(&[33; 32]),
            preimage: canonical_hex(&[36; 32]),
        }];
        assert!(
            StoredConditionalBatchPackage::from_source(fixture_source_package().unwrap(), bad, 0)
                .is_err()
        );
    }
    #[test]
    fn standalone_package_rejects_unsigned_detached_or_noncanonical_shapes() {
        let mut package = fixture_package().unwrap();
        package.source_package = crate::multi_asset_packages::fixture_package().unwrap();
        assert!(package.validate().is_err());
        let mut json = serde_json::to_value(fixture_package().unwrap()).unwrap();
        json["state_number"] = serde_json::json!(9);
        assert!(serde_json::from_value::<StoredConditionalBatchPackage>(json).is_err());
        let mut package = fixture_package().unwrap();
        package.input_since = "00".into();
        assert!(package.validate().is_err());
        let mut json = serde_json::to_value(fixture_package().unwrap()).unwrap();
        json["input_since"] = serde_json::json!(0);
        assert!(serde_json::from_value::<StoredConditionalBatchPackage>(json).is_err());
    }
}
