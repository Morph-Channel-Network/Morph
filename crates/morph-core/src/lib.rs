#![forbid(unsafe_code)]

//! Core Morph Channel protocol objects and validation invariants.
//!
//! This crate is deliberately host-side Rust. Canonical CKB packed types are
//! used for exact transaction-body checks, without an RPC or VM dependency.
//! It provides executable
//! protocol semantics for the no-std CKB script boundary, including fixed-layout
//! body schemas and role-separated Factory authorisation.

pub mod backend;
pub mod bridge;
pub mod conditional;
pub mod factory_backend;
pub mod factory_multi_asset;
pub mod factory_multi_asset_reduced;
pub mod hash;
pub mod multi_asset;
pub mod multi_asset_backend;
pub mod multi_asset_close;
pub mod multi_asset_splice;
pub mod node;
pub mod payment;
pub mod payment_gateway;
pub mod policy;
pub mod rgbpp;
pub mod types;
pub mod validation;

pub use backend::*;
pub use bridge::*;
pub use conditional::*;
pub use factory_backend::*;
pub use factory_multi_asset::*;
pub use factory_multi_asset_reduced::*;
pub use hash::{SigningBytes, asset_registry_commitment, blake2b256, participants_commitment};
pub use multi_asset::*;
pub use multi_asset_backend::*;
pub use multi_asset_close::*;
pub use multi_asset_splice::*;
pub use node::*;
pub use payment::*;
pub use payment_gateway::*;
pub use policy::*;
pub use rgbpp::*;
pub use types::*;
pub use validation::*;
