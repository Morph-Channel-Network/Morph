#![forbid(unsafe_code)]

//! Morph Payment Gateway is the application-layer payment and access gateway:
//! CKB/RGB++ payment processing, signed receipts, Biscuit authorization, and paid
//! API access. It talks to an unmodified Fiber node through JSON-RPC, following
//! the integration described in Fiber issue #1255.

pub mod client;
pub mod credential;
pub mod crypto;
pub mod fiber_rpc;
mod http_safety;
pub mod protocol;
pub mod service;
pub mod store;

pub use client::*;
pub use credential::*;
pub use crypto::*;
pub use fiber_rpc::*;
pub use protocol::*;
pub use service::*;
pub use store::*;
