//! Protected host-only private-key input shared by the two command-line binaries.
//! The CLI passes a path, never key material, to these value parsers. No raw-key
//! FromStr/serde parser is provided. Unsupported filesystem controls fail closed.
#![forbid(unsafe_code)]

use std::fmt;
use std::ops::Deref;
use std::path::Path;

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;
use zeroize::Zeroizing;

pub const MAX_SECRET_FILE_BYTES: usize = 256;

/// In-memory material; all explicit clones zeroize on drop and Debug is redacted.
/// This does not promise erasure of OS caches, swap, or upstream signer objects.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

/// Load a private, owner-controlled ordinary file through the opened descriptor.
/// NOFOLLOW rejects leaf symlinks; NONBLOCK prevents a FIFO from blocking before
/// the file-type check. The operator must also control the containing directory.
#[cfg(target_os = "linux")]
pub fn read_secret_file(path: &Path) -> Result<SecretString> {
    use rustix::fs::{Mode, OFlags, open};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| anyhow::anyhow!("cannot open protected private-key file"))?;
    let file = std::fs::File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("cannot inspect protected private-key file"))?;
    ensure!(
        metadata.is_file(),
        "private-key input must be a regular file"
    );
    ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw(),
        "private-key file must belong to the current user"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "private-key file must have no group or other permissions (use 0600 or 0400)"
    );
    ensure!(
        metadata.len() <= MAX_SECRET_FILE_BYTES as u64,
        "private-key file exceeds the 256-byte limit"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_FILE_BYTES + 1));
    file.take((MAX_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("cannot read protected private-key file"))?;
    ensure!(
        bytes.len() <= MAX_SECRET_FILE_BYTES,
        "private-key file exceeds the 256-byte limit"
    );
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("private-key file must contain one UTF-8 key"))?;
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    ensure!(
        !text.is_empty() && !text.chars().any(|c| c.is_whitespace() || c == '\0'),
        "private-key file must contain exactly one key"
    );
    Ok(SecretString::new(text.to_owned()))
}

#[cfg(not(target_os = "linux"))]
pub fn read_secret_file(_path: &Path) -> Result<SecretString> {
    anyhow::bail!("protected private-key file input is unsupported on this platform")
}

/// Clap value parser: its argument is a protected file path, not a key string.
pub fn secp256k1_file(path: &str) -> Result<SecretString, String> {
    let key = read_secret_file(Path::new(path)).map_err(|e| e.to_string())?;
    let hex = key.strip_prefix("0x").unwrap_or(&key);
    if hex.len() != 64 {
        return Err("private-key file must contain a 32-byte secp256k1 hex key".into());
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(hex, bytes.as_mut())
        .map_err(|_| "private-key file must contain a 32-byte secp256k1 hex key".to_owned())?;
    k256::ecdsa::SigningKey::from_slice(bytes.as_ref())
        .map_err(|_| "private-key file contains an invalid secp256k1 scalar".to_owned())?;
    Ok(key)
}

/// Biscuit has its own tagged key encoding; its authority validates that format.
pub fn biscuit_file(path: &str) -> Result<SecretString, String> {
    let key = read_secret_file(Path::new(path)).map_err(|e| e.to_string())?;
    let bytes = key
        .strip_prefix("ed25519-private/")
        .or_else(|| key.strip_prefix("secp256r1-private/"))
        .ok_or_else(|| "private-key file must contain a tagged Biscuit private key".to_owned())?;
    let mut decoded = Zeroizing::new([0u8; 32]);
    if bytes.len() != 64 || hex::decode_to_slice(bytes, decoded.as_mut()).is_err() {
        return Err("private-key file must contain a tagged 32-byte Biscuit key".into());
    }
    Ok(key)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(content: &[u8], mode: u32) -> Self {
            let path = std::env::temp_dir().join(format!(
                "morph-key-input-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut file, content).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            Self(path)
        }
        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn protected_file_accepts_valid_key_and_redacts_debug() {
        let f = Fixture::new(format!("0x{}\n", hex::encode([7; 32])).as_bytes(), 0o600);
        let key = secp256k1_file(f.path()).unwrap();
        assert_eq!(&*key, format!("0x{}", hex::encode([7; 32])));
        assert!(!format!("{key:?}").contains(&hex::encode([7; 32])));
        fs::set_permissions(&f.0, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(secp256k1_file(f.path()).is_ok());
    }

    #[test]
    fn rejects_exposed_symlink_directory_and_fifo_inputs() {
        let f = Fixture::new(hex::encode([7; 32]).as_bytes(), 0o644);
        assert!(
            secp256k1_file(f.path())
                .unwrap_err()
                .contains("permissions")
        );
        fs::set_permissions(&f.0, fs::Permissions::from_mode(0o600)).unwrap();
        let link = f.0.with_extension("link");
        symlink(&f.0, &link).unwrap();
        assert!(secp256k1_file(link.to_str().unwrap()).is_err());
        fs::remove_file(link).unwrap();
        assert!(secp256k1_file(std::env::temp_dir().to_str().unwrap()).is_err());
        let fifo = f.0.with_extension("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(
            secp256k1_file(fifo.to_str().unwrap())
                .unwrap_err()
                .contains("regular file")
        );
        fs::remove_file(fifo).unwrap();
    }

    #[test]
    fn rejects_oversize_multiple_tokens_and_invalid_scalars_without_echo() {
        for text in [
            "x".repeat(MAX_SECRET_FILE_BYTES + 1),
            format!("{} {}", hex::encode([7; 32]), hex::encode([8; 32])),
            "00".repeat(32),
            "ff".repeat(32),
            "TOP_SECRET_INVALID_HEX".into(),
            "\0".into(),
        ] {
            let f = Fixture::new(text.as_bytes(), 0o600);
            let err = secp256k1_file(f.path()).unwrap_err();
            assert!(!err.contains(&text));
        }
    }

    #[test]
    fn validates_biscuit_encoding_separately() {
        for prefix in ["ed25519-private/", "secp256r1-private/"] {
            let f = Fixture::new(
                format!("{prefix}{}\n", hex::encode([7; 32])).as_bytes(),
                0o600,
            );
            assert!(biscuit_file(f.path()).is_ok());
            assert!(secp256k1_file(f.path()).is_err());
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
#[test]
fn unsupported_platform_never_opens_a_private_key_file() {
    assert!(
        read_secret_file(Path::new("unused"))
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );
    assert!(
        secp256k1_file("unused")
            .unwrap_err()
            .contains("unsupported")
    );
    assert!(biscuit_file("unused").unwrap_err().contains("unsupported"));
}
