//! Private, bounded participant-signer IPC. The transport owns no private key or
//! journal. Integrators must durably reserve BEFORE calling it, and verify and
//! durably record the receipt BEFORE releasing it. No error permits unsealing.
//! A signer service must independently validate the canonical request, chain,
//! admission and monotonic authority before using a key. Decoding is not consent.
#![forbid(unsafe_code)]

pub use morph_packages::signer_protocol;

#[cfg(target_os = "linux")]
pub mod ipc;

#[cfg(target_os = "linux")]
pub mod files;

/// Public errors contain no peer-supplied JSON, keys, preimages or paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("signer protected file rejected")]
    ProtectedFile,
    #[error("invalid signer transport deadline")]
    InvalidDeadline,
    #[error("signer endpoint is not private and owner-controlled")]
    UntrustedEndpoint,
    #[error("signer endpoint is unavailable or busy")]
    Unavailable,
    #[error("signer transport deadline exceeded")]
    Deadline,
    #[error("invalid signer transport frame")]
    InvalidFrame,
    #[error("signer request encoding rejected")]
    InvalidRequest,
    #[error("signer response encoding or signature rejected")]
    InvalidResponse,
    #[error("signing outcome unknown; retain the original reservation")]
    OutcomeUnknown,
}
