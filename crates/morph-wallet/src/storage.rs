//! Private, bounded, fsynced Linux files. The application owns the containing directory.
use anyhow::{Result, ensure};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
const MAX_BYTES: u64 = 4 * 1024 * 1024;
pub struct Storage {
    root: PathBuf,
    _guard: File,
}
impl Storage {
    #[cfg(target_os = "linux")]
    pub fn open(root: &Path) -> Result<Self> {
        if !root.exists() {
            fs::create_dir_all(root)?;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        let meta = fs::symlink_metadata(root)?;
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o077 == 0,
            "wallet.private_directory_required"
        );
        let fd = rustix::fs::open(
            root.join(".wallet.lock"),
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )?;
        let guard = File::from(fd);
        let lock_meta = guard.metadata()?;
        ensure!(
            lock_meta.is_file() && lock_meta.uid() == meta.uid() && lock_meta.mode() & 0o077 == 0,
            "wallet.invalid_private_file"
        );
        guard
            .try_lock()
            .map_err(|_| anyhow::anyhow!("wallet.already_open"))?;
        Ok(Self {
            root: root.to_owned(),
            _guard: guard,
        })
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                && !matches!(name, "." | ".."),
            "wallet.invalid_filename"
        );
        Ok(self.root.join(name))
    }
    #[cfg(target_os = "linux")]
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let fd = rustix::fs::open(
            self.path(name)?,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?;
        let file = File::from(fd);
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == rustix::process::geteuid().as_raw()
                && meta.mode() & 0o077 == 0
                && meta.len() <= MAX_BYTES,
            "wallet.invalid_private_file"
        );
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_BYTES as usize, "wallet.file_too_large");
        Ok(bytes)
    }
    /// Immutable creation: backups and signed transaction evidence are never overwritten.
    #[cfg(target_os = "linux")]
    pub fn create(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write(name, bytes, false)
    }
    /// Mutable metadata/keystore replacement, with the same private lock held throughout.
    pub fn replace(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write(name, bytes, true)
    }
    fn write(&self, name: &str, bytes: &[u8], replace: bool) -> Result<()> {
        ensure!(bytes.len() <= MAX_BYTES as usize, "wallet.file_too_large");
        let target = self.path(name)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| anyhow::anyhow!("wallet.random_unavailable"))?;
        let temporary = self.path(&format!(".pending-{}", hex::encode(random)))?;
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            if replace {
                if target.try_exists()? {
                    let _ = self.read(name)?;
                }
                fs::rename(&temporary, &target)?;
            } else {
                fs::hard_link(&temporary, &target)?;
                fs::remove_file(&temporary)?;
            }
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            ensure!(names.len() < 10000, "wallet.storage_limit");
            if let Some(name) = entry.file_name().to_str()
                && !name.starts_with('.')
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }
    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.path(name)?.try_exists()?)
    }
}

/// Export a complete ciphertext file without clobbering an existing backup or exposing a partial one.
pub fn export_encrypted(target: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_BYTES as usize, "wallet.file_too_large");
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| anyhow::anyhow!("wallet.random_unavailable"))?;
    let temporary = parent.join(format!(".morph-backup-{}", hex::encode(id)));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, target)?;
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_storage_is_single_owner_immutable_and_rejects_symlinks() {
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).unwrap();
        let path = std::env::temp_dir().join(format!("morph-wallet-test-{}", hex::encode(id)));
        let store = Storage::open(&path).unwrap();
        assert!(Storage::open(&path).is_err());
        store.create("key.json", b"original").unwrap();
        assert!(store.create("key.json", b"changed").is_err());
        assert_eq!(store.read("key.json").unwrap(), b"original");
        store.replace("key.json", b"updated").unwrap();
        assert_eq!(store.read("key.json").unwrap(), b"updated");
        std::os::unix::fs::symlink(path.join("key.json"), path.join("link.json")).unwrap();
        assert!(store.read("link.json").is_err());
        assert!(store.replace("link.json", b"attack").is_err());
        assert!(store.create("../escape", b"attack").is_err());
        assert_eq!(
            fs::metadata(path.join("key.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(store);
        fs::remove_dir_all(path).unwrap();
    }
}
