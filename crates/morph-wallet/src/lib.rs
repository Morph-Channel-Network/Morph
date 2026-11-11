//! A local wallet is separate from channel signing journals and Hub record authority.
//! It signs exact reviewed CKB transactions, never arbitrary channel proposals.
#![forbid(unsafe_code)]
pub mod address;
pub mod keystore;
pub mod storage;

pub mod transaction;

pub mod rpc;

pub mod service;
