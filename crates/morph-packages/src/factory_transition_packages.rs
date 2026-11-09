//! Current exact Factory custody transactions. The canonical host view owns
//! frame, authorization and physical body validation; this module supplies only
//! the strict file wrapper. Canonical input cells and deployment approval still
//! require native RPC/VM qualification against an authenticated FactoryCustody.
use std::path::Path;

use anyhow::{Result, ensure};
use ckb_types::prelude::*;
use morph_core::FactoryTransactionView;
use serde::{Deserialize, Serialize};

use crate::multi_asset_packages::{decode_hex, read_bounded_json};

pub const SCHEMA: &str = "morph.factory_transition_package.v1";
pub const MAX_TRANSACTION_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFactoryTransitionPackage {
    pub schema: String,
    pub transaction_hex: String,
}

impl StoredFactoryTransitionPackage {
    pub fn validate(&self) -> Result<FactoryTransactionView> {
        ensure!(
            self.schema == SCHEMA,
            "unsupported Factory transition package schema"
        );
        Ok(FactoryTransactionView::parse(&decode_hex(
            &self.transaction_hex,
            MAX_TRANSACTION_BYTES,
        )?)?)
    }
}

pub fn read(path: &Path) -> Result<FactoryTransactionView> {
    let package: StoredFactoryTransitionPackage =
        read_bounded_json(path, 2 * MAX_TRANSACTION_BYTES + 1024)?;
    package.validate()
}

pub fn inspect(path: &Path, source: Option<&Path>) -> Result<serde_json::Value> {
    let view = read(path)?;
    if let Some(source) = source {
        view.validate_against(&crate::factory_packets::read_custody(source)?.decode()?)?;
    }
    let frame = view.witness()?;
    Ok(
        serde_json::json!({"schema":"morph.factory_transition_summary.v1",
        "validation_scope":"signed_frame_and_exact_body","canonical_source_verified":false,"source_bound":source.is_some(),
        "factory_id":crate::multi_asset_packages::canonical_hex(frame.before().factory_id()),
        "transaction_hash":crate::multi_asset_packages::canonical_hex(view.transaction().calc_tx_hash().as_slice()),
        "operation":format!("{:?}",frame.operation()),"operation_tag":frame.operation() as u16,
        "before_update_number":frame.before().update_number().to_string(),"after_update_number":frame.after().update_number().to_string(),
        "member_count":frame.member_count(),"signature_count":frame.signature_count(),"right_count":frame.right_count(),
        "source_vaults":frame.source().count(),"retained_vaults":frame.retained().count(),
        "transaction_bytes":view.transaction().as_slice().len(),"witness_bytes":frame.as_bytes().len()}),
    )
}
