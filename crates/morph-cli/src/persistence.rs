//! Shared persistence for signing authority, recovery packages and observations.
//! No protocol codec or historical format belongs in this module.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// A complete artifact is immutable at its published path, including witnesses.
/// Partial attempts must use separate paths and cannot replace a complete file.
pub(crate) fn write_private_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    let _lock = try_lock_private_path(path)?.ok_or_else(|| anyhow::anyhow!("artifact is busy"))?;
    if path.exists() {
        ensure!(
            fs::read(path)? == bytes,
            "artifact path holds different contents"
        );
        fs::File::open(path)?.sync_all()?;
    } else {
        write_private_atomic(path, bytes)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_recovery_directories(parent: &Path, existing_parent: &Path) -> Result<()> {
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

/// Require an explicit value or null in persisted snapshots. Missing fields fail.
pub(crate) fn required_option<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Keep the sidecar inode stable while snapshots are atomically replaced.
fn open_private_lock(path: &Path) -> Result<(fs::File, PathBuf, PathBuf)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing = parent
        .ancestors()
        .find(|p| p.is_dir())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    fs::create_dir_all(parent)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok((
        options.open(PathBuf::from(name))?,
        parent.to_path_buf(),
        existing,
    ))
}
fn sync_private_lock(lock: &fs::File, parent: &Path, existing: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        lock.sync_all()?;
        sync_recovery_directories(parent, existing)?;
    }
    #[cfg(not(unix))]
    {
        let _ = (lock, parent, existing);
    }
    Ok(())
}
pub(crate) fn lock_private_path(path: &Path) -> Result<fs::File> {
    let (lock, parent, existing) = open_private_lock(path)?;
    lock.lock()
        .context("failed to lock persistent state file")?;
    sync_private_lock(&lock, &parent, &existing)?;
    Ok(lock)
}
pub(crate) fn try_lock_private_path(path: &Path) -> Result<Option<fs::File>> {
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

pub(crate) fn append_private_jsonl<T: Serialize>(path: &Path, record: &T) -> Result<()> {
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
    fs::create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&encoded)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing_parent = parent
        .ancestors()
        .find(|p| p.is_dir())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    fs::create_dir_all(parent)?;
    let temporary = atomic_json_tmp_path(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> PathBuf {
        let path = atomic_json_tmp_path(&std::env::temp_dir().join(name));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn sidecar_lock_survives_atomic_snapshot_replacement() {
        let dir = directory("morph-shared-persistence");
        let path = dir.join("nested/session.json");
        let authority = lock_private_path(&path).unwrap();
        assert!(try_lock_private_path(&path).unwrap().is_none());
        write_private_atomic(&path, b"first").unwrap();
        write_private_atomic(&path, b"second").unwrap();
        assert!(try_lock_private_path(&path).unwrap().is_none());
        assert_eq!(fs::read(&path).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.with_extension("json.lock"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(authority);
        assert!(try_lock_private_path(&path).unwrap().is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn append_rejects_partial_history_and_schema_switch_without_mutating_evidence() {
        let dir = directory("morph-shared-events");
        let path = dir.join("events.jsonl");
        let event = serde_json::json!({"schema":"current", "sequence":1});
        fs::write(&path, b"{\"schema\":\"current\"}").unwrap();
        let partial = fs::read(&path).unwrap();
        assert!(append_private_jsonl(&path, &event).is_err());
        assert_eq!(fs::read(&path).unwrap(), partial);
        fs::remove_file(&path).unwrap();
        append_private_jsonl(&path, &event).unwrap();
        let complete = fs::read(&path).unwrap();
        let other = serde_json::json!({"schema":"other", "sequence":2});
        assert!(append_private_jsonl(&path, &other).is_err());
        assert_eq!(fs::read(&path).unwrap(), complete);
        append_private_jsonl(&path, &event).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
}
