use std::{collections::HashMap, str::FromStr, sync::Arc};

use biscuit_auth::{
    Biscuit, PrivateKey,
    builder::{AuthorizerBuilder, Term},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{derive_store_key, random_byte32};
use crate::protocol::hex32;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid Biscuit root private key")]
    InvalidPrivateKey,
    #[error("failed to build Biscuit credential: {0}")]
    Build(String),
    #[error("invalid or unauthorized Biscuit credential")]
    Unauthorized,
    #[error("credential expiry must be in the future")]
    InvalidExpiry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialClaims {
    pub credential_id: String,
    pub payment_hash: String,
    pub asset_id: String,
    pub amount: String,
    pub resource: String,
    pub operation: String,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct CredentialService {
    root: Arc<PrivateKey>,
}

impl CredentialService {
    pub fn generate() -> Self {
        Self {
            root: Arc::new(PrivateKey::new()),
        }
    }

    pub fn from_private_key(value: &str) -> Result<Self, CredentialError> {
        let private =
            PrivateKey::from_str(value).map_err(|_| CredentialError::InvalidPrivateKey)?;
        Ok(Self {
            root: Arc::new(private),
        })
    }

    pub fn private_key(&self) -> String {
        self.root.to_prefixed_string()
    }

    pub fn public_key(&self) -> String {
        self.root.public().to_string()
    }

    pub fn store_key(&self) -> [u8; 32] {
        derive_store_key(&self.root.to_bytes())
    }

    pub fn mint(&self, mut claims: CredentialClaims, now: u64) -> Result<String, CredentialError> {
        if claims.expires_at <= now {
            return Err(CredentialError::InvalidExpiry);
        }
        if claims.credential_id.is_empty() {
            claims.credential_id = hex32(&random_byte32());
        }
        let params = claims_params(&claims, Some(now));
        let biscuit = Biscuit::builder()
            .code_with_params(
                r#"
                    right({resource}, "access");
                    operation({operation});
                    payment_hash({payment_hash});
                    asset_id({asset_id});
                    amount({amount});
                    credential_id({credential_id});
                    expires_at({expires_at});
                    check if time($time), $time <= {expires_at};
                "#,
                params,
                HashMap::new(),
            )
            .map_err(|error| CredentialError::Build(error.to_string()))?
            .build(self.root.as_ref())
            .map_err(|error| CredentialError::Build(error.to_string()))?;
        biscuit
            .to_base64()
            .map_err(|error| CredentialError::Build(error.to_string()))
    }

    pub fn verify(
        &self,
        token: &str,
        expected: &CredentialClaims,
        now: u64,
    ) -> Result<(), CredentialError> {
        if expected.expires_at <= now {
            return Err(CredentialError::InvalidExpiry);
        }
        let biscuit = Biscuit::from_base64(token, self.root.public())
            .map_err(|_| CredentialError::Unauthorized)?;
        let params = claims_params(expected, Some(now));
        let mut authorizer = AuthorizerBuilder::new()
            .code_with_params(
                r#"
                    time({now});
                    allow if right({resource}, "access"),
                        payment_hash({payment_hash}),
                        asset_id({asset_id}),
                        amount({amount}),
                        credential_id({credential_id}),
                        operation({operation}),
                        expires_at({expires_at});
                "#,
                params,
                HashMap::new(),
            )
            .map_err(|_| CredentialError::Unauthorized)?
            .build(&biscuit)
            .map_err(|_| CredentialError::Unauthorized)?;
        authorizer
            .authorize()
            .map(|_| ())
            .map_err(|_| CredentialError::Unauthorized)
    }
}

fn claims_params(claims: &CredentialClaims, now: Option<u64>) -> HashMap<String, Term> {
    let mut params = HashMap::from([
        (
            "credential_id".to_string(),
            Term::Str(claims.credential_id.clone()),
        ),
        (
            "payment_hash".to_string(),
            Term::Str(claims.payment_hash.clone()),
        ),
        ("asset_id".to_string(), Term::Str(claims.asset_id.clone())),
        ("amount".to_string(), Term::Str(claims.amount.clone())),
        ("resource".to_string(), Term::Str(claims.resource.clone())),
        ("operation".to_string(), Term::Str(claims.operation.clone())),
        ("expires_at".to_string(), Term::Date(claims.expires_at)),
    ]);
    if let Some(now) = now {
        params.insert("now".to_string(), Term::Date(now));
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> CredentialClaims {
        CredentialClaims {
            credential_id: format!("0x{}", "11".repeat(32)),
            payment_hash: format!("0x{}", "22".repeat(32)),
            asset_id: "rgbpp:network:type".to_string(),
            amount: "1000".to_string(),
            resource: "/api/result".to_string(),
            operation: "GET".to_string(),
            expires_at: 200,
        }
    }

    #[test]
    fn token_is_bound_to_payment_asset_amount_and_resource() {
        let service = CredentialService::generate();
        let claims = claims();
        let token = service.mint(claims.clone(), 100).unwrap();
        service.verify(&token, &claims, 150).unwrap();

        let mut substituted = claims.clone();
        substituted.amount = "1001".to_string();
        assert!(service.verify(&token, &substituted, 150).is_err());
        assert!(service.verify(&token, &claims, 201).is_err());
    }

    #[test]
    fn both_biscuit_root_algorithms_enforce_credential_authority_and_claims() {
        for algorithm in ["ed25519", "secp256r1"] {
            let key = format!("{algorithm}-private/{}", "01".repeat(32));
            let service = CredentialService::from_private_key(&key).unwrap();
            let restored = CredentialService::from_private_key(&service.private_key()).unwrap();
            let claims = claims();
            let token = service.mint(claims.clone(), 100).unwrap();
            restored.verify(&token, &claims, 150).unwrap();
            assert_eq!(service.public_key(), restored.public_key());
            assert_eq!(service.store_key(), restored.store_key());

            let other_key = format!("{algorithm}-private/{}", "02".repeat(32));
            let other = CredentialService::from_private_key(&other_key).unwrap();
            assert!(other.verify(&token, &claims, 150).is_err());
            for field in 0..6 {
                let mut changed = claims.clone();
                match field {
                    0 => changed.payment_hash.push('0'),
                    1 => changed.asset_id.push('0'),
                    2 => changed.amount.push('0'),
                    3 => changed.resource.push('0'),
                    4 => changed.operation.push('0'),
                    _ => changed.credential_id.push('0'),
                }
                assert!(restored.verify(&token, &changed, 150).is_err());
            }
            assert!(restored.verify(&token, &claims, 201).is_err());
        }
    }

    #[test]
    fn private_key_round_trip_preserves_authority() {
        let first = CredentialService::generate();
        let restored = CredentialService::from_private_key(&first.private_key()).unwrap();
        assert_eq!(first.public_key(), restored.public_key());
        assert_eq!(first.store_key(), restored.store_key());
    }
}
