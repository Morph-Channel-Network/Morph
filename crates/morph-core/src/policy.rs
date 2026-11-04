//! Operator value-limit policy for the pre-real-assets gate.
//!
//! The policy is deliberately dumb and fail-closed: an operator declares a
//! maximum CKB capacity a channel may hold and, for every xUDT type the
//! deployment admits, a maximum base-unit amount. Any asset that is not
//! explicitly listed is rejected, and every value-bearing package must be
//! checked against the policy before broadcast. The policy is an operator
//! control only; the on-chain scripts remain the final boundary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::blake2b256;

pub const VALUE_LIMIT_POLICY_SCHEMA: &str = "morph.value_limit_policy";
pub const VALUE_LIMIT_POLICY_DIGEST_DOMAIN: &[u8] = b"CKB_MORPH_VALUE_LIMIT_POLICY";
const HEX_PREFIX: &str = "0x";
const HEX32_LEN: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValueLimitError {
    #[error("invalid current custody manifest: {0}")]
    InvalidCustody(String),
    #[error("unsupported value-limit policy schema {0}")]
    UnsupportedSchema(String),
    #[error("value-limit xUDT key {0} is not canonical 0x-prefixed 32-byte hex")]
    MalformedXudtKey(String),
    #[error("value-limit cap for {0} must be positive; omit the asset to forbid it")]
    ZeroCap(String),
    #[error("value-limit subject total overflowed for {asset}")]
    ValueOverflow { asset: String },
    #[error("channel CKB capacity {actual} exceeds the policy cap {cap}")]
    CkbOverLimit { actual: u128, cap: u64 },
    #[error("xUDT asset {asset} is not admitted by the value-limit policy")]
    UnlistedXudt { asset: String },
    #[error("xUDT asset {asset} amount {actual} exceeds the policy cap {cap}")]
    XudtOverLimit {
        asset: String,
        actual: u128,
        cap: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueLimitPolicy {
    pub schema: String,
    pub created_unix_ms: u64,
    pub max_channel_ckb_capacity: u64,
    /// Per-xUDT-type caps keyed by canonical `0x`-prefixed 32-byte hex.
    /// Assets absent from this map are rejected outright.
    pub max_xudt_amounts: BTreeMap<String, u128>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueSubject {
    pub ckb_capacity: u128,
    /// Per-xUDT-type amounts keyed by canonical `0x`-prefixed 32-byte hex.
    pub xudt_amounts: BTreeMap<String, u128>,
}

impl ValueSubject {
    /// One custody snapshot, including reserve, business CKB, every token Type
    /// and its separate State carrier. Multiple simultaneous custody bundles
    /// can be added; mutually exclusive before/after states use include_peak.
    pub fn add_manifest(
        &mut self,
        manifest: &crate::MultiAssetManifest,
        state_carrier_capacity: u64,
    ) -> Result<(), ValueLimitError> {
        manifest
            .encode()
            .map_err(|error| ValueLimitError::InvalidCustody(error.to_string()))?;
        self.add_ckb(u128::from(state_carrier_capacity))?;
        for vault in &manifest.vaults {
            self.add_ckb(u128::from(vault.value.reserve))?;
            self.add_ckb(u128::from(vault.value.business_ckb))?;
            if let crate::VaultAsset::Xudt(type_hash) = vault.asset {
                self.add_xudt_raw(type_hash, vault.value.amount)?;
            }
        }
        Ok(())
    }

    pub fn from_manifest(
        manifest: &crate::MultiAssetManifest,
        state_carrier_capacity: u64,
    ) -> Result<Self, ValueLimitError> {
        let mut subject = Self::default();
        subject.add_manifest(manifest, state_carrier_capacity)?;
        Ok(subject)
    }

    /// Offline Factory admission view. Claims are not added to physical
    /// custody, but every typed value right is admitted even when its current
    /// balance is zero. Child carriers are simultaneous future custody; the
    /// source and resulting custody are mutually exclusive snapshots.
    /// This review does not establish canonical-chain or signer authority.
    pub fn from_factory_request(
        request: &crate::FactorySigningRequest,
    ) -> Result<Self, ValueLimitError> {
        use morph_script_common::factory_multi_asset as factory;

        let invalid =
            |error: crate::FactoryBackendError| ValueLimitError::InvalidCustody(error.to_string());
        request
            .validate_for_review(&request.members().map_err(invalid)?)
            .map_err(invalid)?;
        let mut peak = if let Some(source) = &request.source {
            Self::from_manifest(&source.manifest, source.state_carrier_capacity)?
        } else {
            Self::default()
        };
        let mut future = if let Some(target) = &request.target {
            Self::from_manifest(&target.manifest, target.state_carrier_capacity)?
        } else {
            Self::default()
        };
        let mut add_children = |intent: &factory::FactoryMaterialisationIntent<'_>| {
            for index in 0..intent.child_count() {
                let child = intent
                    .child(index)
                    .map_err(|error| ValueLimitError::InvalidCustody(format!("{error:?}")))?;
                let manifest =
                    crate::MultiAssetManifest::decode(child.evidence.manifest().as_bytes())
                        .map_err(|error| ValueLimitError::InvalidCustody(error.to_string()))?;
                future.add_manifest(&manifest, child.carrier_capacity)?;
            }
            Ok::<_, ValueLimitError>(())
        };
        match request.role {
            crate::FactorySigningRole::Materialisation => {
                let frame = factory::FactoryMaterialisationWitness::parse(&request.witness)
                    .map_err(|error| ValueLimitError::InvalidCustody(format!("{error:?}")))?;
                add_children(frame.intent())?;
            }
            crate::FactorySigningRole::Transition => {
                let frame = factory::FactoryReducedReleaseWitness::parse(&request.witness)
                    .map_err(|error| ValueLimitError::InvalidCustody(format!("{error:?}")))?;
                if let Some(intent) = frame.child_intent() {
                    add_children(intent)?;
                }
            }
            _ => {}
        }
        peak.include_peak(&future);
        for right in &request.target_rights {
            if matches!(
                right.id.kind,
                crate::FactoryRightKind::Balance
                    | crate::FactoryRightKind::ReserveClaim
                    | crate::FactoryRightKind::SponsorBudgetClaim
            ) && let Some(asset) = right.id.asset_type
            {
                peak.add_xudt_raw(asset, 0)?;
            }
        }
        Ok(peak)
    }

    pub fn add_ckb(&mut self, amount: u128) -> Result<(), ValueLimitError> {
        self.ckb_capacity = self.ckb_capacity.checked_add(amount).ok_or_else(|| {
            ValueLimitError::ValueOverflow {
                asset: "ckb".to_string(),
            }
        })?;
        Ok(())
    }

    pub fn add_xudt(&mut self, asset: &str, amount: u128) -> Result<(), ValueLimitError> {
        let canonical = canonical_hex32(asset)?;
        let entry = self.xudt_amounts.entry(canonical.clone()).or_insert(0u128);
        *entry = entry
            .checked_add(amount)
            .ok_or(ValueLimitError::ValueOverflow { asset: canonical })?;
        Ok(())
    }

    pub fn add_xudt_raw(&mut self, asset: [u8; 32], amount: u128) -> Result<(), ValueLimitError> {
        let mut key = String::with_capacity(HEX_PREFIX.len() + HEX32_LEN);
        key.push_str(HEX_PREFIX);
        for byte in asset {
            key.push_str(&format!("{byte:02x}"));
        }
        let entry = self.xudt_amounts.entry(key.clone()).or_insert(0u128);
        *entry = entry
            .checked_add(amount)
            .ok_or(ValueLimitError::ValueOverflow { asset: key })?;
        Ok(())
    }

    /// Retains the component-wise peak observed across mutually exclusive
    /// channel states, such as the old and new vault descriptors of a splice.
    pub fn include_peak(&mut self, snapshot: &Self) {
        self.ckb_capacity = self.ckb_capacity.max(snapshot.ckb_capacity);
        for (asset, amount) in &snapshot.xudt_amounts {
            let peak = self.xudt_amounts.entry(asset.clone()).or_default();
            *peak = (*peak).max(*amount);
        }
    }
}

fn canonical_hex32(value: &str) -> Result<String, ValueLimitError> {
    let malformed = || ValueLimitError::MalformedXudtKey(value.to_string());
    let body = value
        .strip_prefix(HEX_PREFIX)
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(malformed)?;
    if body.len() != HEX32_LEN || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    Ok(format!("{HEX_PREFIX}{}", body.to_ascii_lowercase()))
}

impl ValueLimitPolicy {
    pub fn validate(&self) -> Result<(), ValueLimitError> {
        if self.schema != VALUE_LIMIT_POLICY_SCHEMA {
            return Err(ValueLimitError::UnsupportedSchema(self.schema.clone()));
        }
        for (asset, cap) in &self.max_xudt_amounts {
            let canonical = canonical_hex32(asset)?;
            if &canonical != asset {
                return Err(ValueLimitError::MalformedXudtKey(asset.clone()));
            }
            if *cap == 0 {
                return Err(ValueLimitError::ZeroCap(asset.clone()));
            }
        }
        Ok(())
    }

    /// Deterministic operator commitment over the declared caps.
    pub fn digest(&self) -> Result<[u8; 32], ValueLimitError> {
        self.validate()?;
        let mut body = String::new();
        body.push_str(VALUE_LIMIT_POLICY_SCHEMA);
        body.push_str(&self.max_channel_ckb_capacity.to_string());
        for (asset, cap) in &self.max_xudt_amounts {
            body.push_str(asset);
            body.push_str(&cap.to_string());
        }
        let mut bytes = Vec::with_capacity(VALUE_LIMIT_POLICY_DIGEST_DOMAIN.len() + body.len());
        bytes.extend_from_slice(VALUE_LIMIT_POLICY_DIGEST_DOMAIN);
        bytes.extend_from_slice(body.as_bytes());
        Ok(blake2b256(&bytes))
    }

    /// Fail-closed enforcement: every listed asset must be admitted, every
    /// amount must be within its cap, and the CKB capacity must be within the
    /// declared ceiling.
    pub fn enforce(&self, subject: &ValueSubject) -> Result<(), ValueLimitError> {
        self.validate()?;
        if subject.ckb_capacity > u128::from(self.max_channel_ckb_capacity) {
            return Err(ValueLimitError::CkbOverLimit {
                actual: subject.ckb_capacity,
                cap: self.max_channel_ckb_capacity,
            });
        }
        for (asset, amount) in &subject.xudt_amounts {
            let Some(cap) = self.max_xudt_amounts.get(asset) else {
                return Err(ValueLimitError::UnlistedXudt {
                    asset: asset.clone(),
                });
            };
            if amount > cap {
                return Err(ValueLimitError::XudtOverLimit {
                    asset: asset.clone(),
                    actual: *amount,
                    cap: *cap,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ValueLimitPolicy {
        ValueLimitPolicy {
            schema: VALUE_LIMIT_POLICY_SCHEMA.to_string(),
            created_unix_ms: 0,
            max_channel_ckb_capacity: 1_000_000,
            max_xudt_amounts: BTreeMap::from([(
                format!("{HEX_PREFIX}{}", "2a".repeat(32)),
                5_000u128,
            )]),
        }
    }

    fn subject(ckb: u128, xudt: u128) -> ValueSubject {
        let mut out = ValueSubject::default();
        out.add_ckb(ckb).unwrap();
        out.add_xudt_raw([0x2au8; 32], xudt).unwrap();
        out
    }

    #[test]
    fn policy_accepts_subjects_within_caps() {
        policy().enforce(&subject(1_000_000, 5_000)).unwrap();
    }

    #[test]
    fn policy_rejects_ckb_over_limit() {
        assert_eq!(
            policy().enforce(&subject(1_000_001, 1)).unwrap_err(),
            ValueLimitError::CkbOverLimit {
                actual: 1_000_001,
                cap: 1_000_000
            }
        );
    }

    #[test]
    fn policy_rejects_xudt_over_limit() {
        assert_eq!(
            policy().enforce(&subject(1, 5_001)).unwrap_err(),
            ValueLimitError::XudtOverLimit {
                asset: format!("{HEX_PREFIX}{}", "2a".repeat(32)),
                actual: 5_001,
                cap: 5_000
            }
        );
    }

    #[test]
    fn policy_rejects_unlisted_assets() {
        let mut subject = subject(1, 0);
        subject.add_xudt_raw([0x07u8; 32], 1).unwrap();
        assert_eq!(
            policy().enforce(&subject).unwrap_err(),
            ValueLimitError::UnlistedXudt {
                asset: format!("{HEX_PREFIX}{}", "07".repeat(32))
            }
        );
    }

    #[test]
    fn policy_rejects_malformed_keys_and_zero_caps() {
        let mut malformed = policy();
        malformed.max_xudt_amounts = BTreeMap::from([("0xzz".to_string(), 1u128)]);
        assert_eq!(
            malformed.validate().unwrap_err(),
            ValueLimitError::MalformedXudtKey("0xzz".to_string())
        );

        let mut zero_cap = policy();
        zero_cap.max_xudt_amounts = BTreeMap::from([("0x".to_string() + &"2a".repeat(32), 0u128)]);
        assert!(matches!(
            zero_cap.validate().unwrap_err(),
            ValueLimitError::ZeroCap(_)
        ));
    }

    #[test]
    fn policy_digest_is_deterministic_and_cap_sensitive() {
        let base = policy();
        let mut raised = base.clone();
        raised.max_channel_ckb_capacity += 1;
        assert_eq!(base.digest().unwrap(), policy().digest().unwrap());
        assert_ne!(base.digest().unwrap(), raised.digest().unwrap());
    }

    #[test]
    fn subject_keys_are_canonicalised() {
        let mut subject = ValueSubject::default();
        subject
            .add_xudt(&format!("0X{}", "2A".repeat(32)), 3)
            .unwrap();
        assert_eq!(
            subject.xudt_amounts,
            BTreeMap::from([(format!("{HEX_PREFIX}{}", "2a".repeat(32)), 3u128)])
        );
    }

    #[test]
    fn subject_addition_fails_closed_on_overflow() {
        let mut subject = ValueSubject::default();
        subject.add_ckb(u128::MAX).unwrap();
        assert!(matches!(
            subject.add_ckb(1).unwrap_err(),
            ValueLimitError::ValueOverflow { .. }
        ));

        let mut subject = ValueSubject::default();
        subject.add_xudt_raw([7u8; 32], u128::MAX).unwrap();
        assert!(matches!(
            subject.add_xudt_raw([7u8; 32], 1).unwrap_err(),
            ValueLimitError::ValueOverflow { .. }
        ));
    }

    #[test]
    fn subject_peak_is_component_wise() {
        let mut peak = subject(10, 100);
        let next = subject(20, 90);
        peak.include_peak(&next);
        assert_eq!(peak.ckb_capacity, 20);
        assert_eq!(
            peak.xudt_amounts[&format!("{HEX_PREFIX}{}", "2a".repeat(32))],
            100
        );
    }
}
