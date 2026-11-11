//! Delivery is at least once. Neither these events nor their acknowledgements
//! are chain finality, signing authority, or protection from whole-store rollback.
#![forbid(unsafe_code)]
pub mod envelope;
pub mod queue;
pub mod webhook;
pub use envelope::*;
pub use morph_packages::events::*;
pub use queue::*;
pub use webhook::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid current event or delivery configuration")]
    Invalid,
    #[error("delivery store/source/endpoint policy mismatch")]
    Policy,
    #[error("delivery backlog or retained-history limit reached")]
    Full,
    #[error(
        "delivery generation is sealed, prepared, or requires archival; resume the bound handoff"
    )]
    ArchiveRequired,
    #[error("delivery state conflict; reload without sending")]
    Conflict,
    #[error("runtime event store: {0}")]
    Store(#[from] morph_runtime_store::StoreError),
}
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut output = [0; 32];
    let mut h = blake2b_rs::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    h.update(domain);
    h.update(bytes);
    h.finalize(&mut output);
    hex::encode(output)
}
pub(crate) fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests;

impl From<morph_packages::events::EventError> for Error {
    fn from(_: morph_packages::events::EventError) -> Self {
        Self::Invalid
    }
}
