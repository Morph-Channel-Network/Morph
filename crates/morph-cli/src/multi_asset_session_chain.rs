//! Persisted canonical evidence for signer context transitions. These fields
//! are explicit in the current snapshot; no migration supplies missing guards.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalInclusion {
    pub transaction_hash: String,
    pub block_number: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextChainEvidence {
    pub funding: CanonicalInclusion,
    pub state: CanonicalInclusion,
    pub state_out_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionOrigin {
    Root {
        funding_transaction_hex: String,
    },
    Splice {
        retired_journal: std::path::PathBuf,
        retired_journal_hash: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLineage {
    pub rpc_url: String,
    pub contracts_dir: std::path::PathBuf,
    pub min_confirmations: u64,
    pub evidence: ContextChainEvidence,
    pub origin: SessionOrigin,
}

pub fn rpc_endpoint(value: &str) -> anyhow::Result<url::Url> {
    let endpoint = url::Url::parse(value)?;
    anyhow::ensure!(
        matches!(endpoint.scheme(), "http" | "https")
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none(),
        "signer RPC endpoint must be HTTP(S) without embedded credentials"
    );
    Ok(endpoint)
}
