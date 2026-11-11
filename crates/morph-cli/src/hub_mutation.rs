//! Durable API receipts contain only a request fingerprint and public response.
//! Raw requests can contain preimages and must never enter the plaintext Hub DB.
use anyhow::Result;
use morph_core::{Bytes32, blake2b256};
use morph_hub_api::{ApiErrorCode, MutationContext, mutation::*};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub(super) struct Failure {
    pub status: u16,
    pub code: ApiErrorCode,
    pub message: &'static str,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for Failure {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedResponse {
    pub schema: String,
    pub fingerprint: Bytes32,
    pub response: String,
}

pub(super) struct Mutation {
    pub context: MutationContext,
    pub fingerprint: Bytes32,
}
impl Mutation {
    pub fn parse(request: &super::hub::HttpRequest) -> Result<Self> {
        let invalid = || Failure {
            status: 400,
            code: ApiErrorCode::InvalidMutationContext,
            message: "mutation requires a canonical idempotency key and expected revision",
        };
        if request.header(API_VERSION_HEADER) != Some(API_VERSION) {
            return Err(Failure {
                status: 400,
                code: ApiErrorCode::UnsupportedApiVersion,
                message: "mutation requires the current explicit API version",
            }
            .into());
        }
        let context = MutationContext {
            idempotency_key: request
                .header(IDEMPOTENCY_HEADER)
                .ok_or_else(invalid)?
                .into(),
            expected_revision: request
                .header(REVISION_HEADER)
                .and_then(decimal::parse)
                .ok_or_else(invalid)?,
        };
        if !context.valid() {
            return Err(invalid().into());
        }
        let fingerprint = blake2b256(&serde_json::to_vec(&(
            "morph.hub.api_request.v1",
            API_VERSION,
            &request.method,
            &request.path,
            context.expected_revision,
            blake2b256(&request.body),
        ))?);
        Ok(Self {
            context,
            fingerprint,
        })
    }
    pub fn operation_id(&self) -> String {
        format!("hub-api:{}", self.context.idempotency_key)
    }
    pub fn saved_response(&self, response: Vec<u8>) -> Result<SavedResponse> {
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(Failure {
                status: 413,
                code: ApiErrorCode::ResponseLimit,
                message: "mutation response exceeds the supported size",
            }
            .into());
        }
        Ok(SavedResponse {
            schema: "morph.hub.api_response.v1".into(),
            fingerprint: self.fingerprint,
            response: String::from_utf8(response)?,
        })
    }
}
