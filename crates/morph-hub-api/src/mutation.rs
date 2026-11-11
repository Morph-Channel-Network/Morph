//! Sole current Hub mutation contract. No missing-header compatibility mode.
use serde::{Deserialize, Serialize};

pub const API_VERSION: &str = "1";
pub const API_VERSION_HEADER: &str = "x-morph-api-version";
pub const IDEMPOTENCY_HEADER: &str = "idempotency-key";
pub const REVISION_HEADER: &str = "x-morph-expected-revision";
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiInfo {
    pub api_version: String,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub revision: u64,
}

/// This key is a public request identity, never signing material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MutationContext {
    pub idempotency_key: String,
    #[serde(with = "decimal")]
    #[schemars(schema_with = "decimal::schema")]
    pub expected_revision: u64,
}
impl MutationContext {
    pub fn valid(&self) -> bool {
        self.idempotency_key.len() == 32
            && self
                .idempotency_key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && self.expected_revision < i64::MAX as u64
    }
}

pub use morph_packages::public_encoding::{decimal, optional_decimal};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutation_context_has_one_explicit_bounded_encoding() {
        let context = MutationContext {
            idempotency_key: "12".repeat(16),
            expected_revision: 7,
        };
        assert!(context.valid());
        assert_eq!(
            serde_json::to_value(&context).unwrap()["expected_revision"],
            "7"
        );
        for value in ["01", "+1", " 1", "1.0", "18446744073709551616", ""] {
            assert!(decimal::parse(value).is_none());
        }
        assert!(
            serde_json::from_str::<MutationContext>(
                r#"{"idempotency_key":"a","expected_revision":7}"#
            )
            .is_err()
        );
        assert!(
            !MutationContext {
                idempotency_key: "ab".repeat(16),
                expected_revision: u64::MAX
            }
            .valid()
        );
    }
}
