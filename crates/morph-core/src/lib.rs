#![forbid(unsafe_code)]

//! Core Morph Channel protocol objects and validation invariants.
//!
//! This crate is deliberately host-side Rust for now. It provides executable
//! protocol semantics for the no-std CKB script boundary, including fixed-layout
//! body schemas and current-envelope-carried factory authorisation.

pub mod agent;
pub mod backend;
pub mod bridge;
pub mod conditional;
pub mod hash;
pub mod multi_asset;
pub mod node;
pub mod policy;
pub mod rgbpp;
pub mod types;
pub mod validation;

pub use agent::*;
pub use backend::*;
pub use bridge::*;
pub use conditional::*;
pub use hash::{
    SigningBytes, asset_registry_commitment, blake2b256, factory_vault_delta_commitment,
    factory_vault_descriptor_commitment, funding_context_id, participants_commitment,
    splice_asset_delta_commitment, vault_descriptor_commitment, vault_outpoint_commitment,
};
pub use multi_asset::*;
pub use node::*;
pub use policy::*;
pub use rgbpp::*;
pub use types::*;
pub use validation::*;
