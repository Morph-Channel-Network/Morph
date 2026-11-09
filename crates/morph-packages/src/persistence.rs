//! Shared persistence for signing authority, recovery packages and observations.
//! No protocol codec or historical format belongs in this module.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// Create every missing directory with private permissions from its creation.
/// Existing parents may be shared and must never be chmodded by an artifact
/// writer. Return the already-existing ancestor for durable directory syncing.
pub fn create_private_directories(path: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let existing = path
            .ancestors()
            .find(|parent| parent.is_dir())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        Ok(existing)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        anyhow::bail!(
            "private artifact persistence requires Unix permission controls; platform ACL support is not implemented"
        )
    }
}

/// Private artifacts are not repaired by exposing their contents first.
/// Existing files with broader access must be secured by the operator before
/// an immutable replay or append can trust their storage boundary.
pub fn require_private_file(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "private artifact is not a regular file");
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "private artifact permissions must be 0600"
        );
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        anyhow::bail!(
            "private artifact persistence requires Unix permission controls; platform ACL support is not implemented"
        )
    }
}

/// A complete artifact is immutable at its published path, including witnesses.
/// Partial attempts must use separate paths and cannot replace a complete file.
pub fn write_private_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    let _lock = try_lock_private_path(path)?.ok_or_else(|| anyhow::anyhow!("artifact is busy"))?;
    if path.exists() {
        let file = fs::File::open(path)?;
        require_private_file(&file)?;
        ensure!(
            fs::read(path)? == bytes,
            "artifact path holds different contents"
        );
        file.sync_all()?;
    } else {
        write_private_atomic(path, bytes)?;
    }
    Ok(())
}

pub fn sync_recovery_directories(parent: &Path, existing_parent: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        for ancestor in parent.ancestors() {
            let directory = if ancestor.as_os_str().is_empty() {
                Path::new(".")
            } else {
                ancestor
            };
            fs::File::open(directory)?.sync_all()?;
            if directory == existing_parent {
                break;
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, existing_parent);
        anyhow::bail!(
            "private artifact persistence requires Unix permission controls; platform ACL support is not implemented"
        )
    }
}

/// Require an explicit value or null in persisted snapshots. Missing fields fail.
pub fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Keep the sidecar inode stable while snapshots are atomically replaced.
pub fn open_private_lock(path: &Path) -> Result<(fs::File, PathBuf, PathBuf)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing = create_private_directories(parent)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(PathBuf::from(name))?;
    require_private_file(&lock)?;
    Ok((lock, parent.to_path_buf(), existing))
}
pub fn sync_private_lock(lock: &fs::File, parent: &Path, existing: &Path) -> Result<()> {
    lock.sync_all()?;
    sync_recovery_directories(parent, existing)
}
pub fn lock_private_path(path: &Path) -> Result<fs::File> {
    let (lock, parent, existing) = open_private_lock(path)?;
    lock.lock()
        .context("failed to lock persistent state file")?;
    sync_private_lock(&lock, &parent, &existing)?;
    Ok(lock)
}
pub fn try_lock_private_path(path: &Path) -> Result<Option<fs::File>> {
    let (lock, parent, existing) = open_private_lock(path)?;
    match lock.try_lock() {
        Ok(()) => {
            sync_private_lock(&lock, &parent, &existing)?;
            Ok(Some(lock))
        }
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

pub fn append_private_jsonl<T: Serialize>(path: &Path, record: &T) -> Result<()> {
    use std::io::{BufRead, Read, Seek, SeekFrom, Write};
    const MAX_RECORD_BYTES: usize = 256 * 1024;
    #[derive(Deserialize)]
    struct Schema {
        schema: String,
    }
    let mut encoded = serde_json::to_vec(record)?;
    ensure!(
        encoded.len() < MAX_RECORD_BYTES,
        "persistent event exceeds byte limit"
    );
    let incoming: Schema = serde_json::from_slice(&encoded)?;
    encoded.push(b'\n');
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing_parent = create_private_directories(parent)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    require_private_file(&file)?;
    file.lock()
        .context("failed to lock persistent event stream")?;
    if file.metadata()?.len() > 0 {
        let mut last = [0; 1];
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut last)?;
        ensure!(
            last[0] == b'\n',
            "persistent event stream ends with an incomplete record"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut first = Vec::new();
        std::io::BufReader::new((&file).take(MAX_RECORD_BYTES as u64 + 1))
            .read_until(b'\n', &mut first)?;
        ensure!(
            first.len() <= MAX_RECORD_BYTES,
            "persistent event header exceeds byte limit"
        );
        let existing: Schema = serde_json::from_slice(&first)?;
        ensure!(
            existing.schema == incoming.schema,
            "persistent event stream has another schema"
        );
    }
    file.write_all(&encoded)?;
    file.sync_all()?;
    sync_recovery_directories(parent, &existing_parent)?;
    Ok(())
}

pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing_parent = create_private_directories(parent)?;
    let temporary = atomic_json_tmp_path(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    require_private_file(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_recovery_directories(parent, &existing_parent)?;
    Ok(())
}

pub fn atomic_json_tmp_path(final_path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    let parent = final_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = final_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "package.json".to_string());
    let tmp_name = format!(".{}.{}.{}.{}.tmp", file_name, pid, counter, nanos);
    parent.join(tmp_name)
}
