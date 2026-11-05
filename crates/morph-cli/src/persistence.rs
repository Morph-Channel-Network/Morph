//! Shared persistence for signing authority, recovery packages and observations.
//! No protocol codec or historical format belongs in this module.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// Create every missing directory with private permissions from its creation.
/// Existing parents may be shared and must never be chmodded by an artifact
/// writer. Return the already-existing ancestor for durable directory syncing.
pub(crate) fn create_private_directories(path: &Path) -> Result<PathBuf> {
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
pub(crate) fn require_private_file(file: &fs::File) -> Result<()> {
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
pub(crate) fn write_private_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
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

pub(crate) fn sync_recovery_directories(parent: &Path, existing_parent: &Path) -> Result<()> {
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
fn sync_private_lock(lock: &fs::File, parent: &Path, existing: &Path) -> Result<()> {
    lock.sync_all()?;
    sync_recovery_directories(parent, existing)
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

pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
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

    #[cfg(unix)]
    #[test]
    fn private_writers_create_restricted_trees_without_chmodding_existing_parents() {
        use std::os::unix::fs::PermissionsExt;

        let dir = directory("morph-private-directories");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let atomic = dir.join("atomic/nested/state.json");
        write_private_atomic(&atomic, b"private state").unwrap();
        let locked = dir.join("locked/nested/state.json");
        let lock = lock_private_path(&locked).unwrap();
        write_private_atomic(&locked, b"locked state").unwrap();
        let immutable = dir.join("immutable/nested/exit.json");
        write_private_immutable(&immutable, b"complete exit").unwrap();
        let events = dir.join("events/nested/events.jsonl");
        append_private_jsonl(&events, &serde_json::json!({"schema":"current"})).unwrap();

        for path in [&atomic, &locked, &immutable, &events] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            for parent in path.parent().unwrap().ancestors().take_while(|p| *p != dir) {
                assert_eq!(
                    fs::metadata(parent).unwrap().permissions().mode() & 0o777,
                    0o700,
                    "{}",
                    parent.display()
                );
            }
        }
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(try_lock_private_path(&locked).unwrap().is_none());
        drop(lock);
        assert!(try_lock_private_path(&locked).unwrap().is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_replay_append_and_locks_reject_broad_existing_files_without_repair() {
        use std::os::unix::fs::PermissionsExt;

        let dir = directory("morph-private-existing");
        let immutable = dir.join("exit.json");
        fs::write(&immutable, b"complete exit").unwrap();
        fs::set_permissions(&immutable, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(write_private_immutable(&immutable, b"complete exit").is_err());
        assert_eq!(fs::read(&immutable).unwrap(), b"complete exit");
        assert_eq!(
            fs::metadata(&immutable).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::set_permissions(&immutable, fs::Permissions::from_mode(0o600)).unwrap();
        write_private_immutable(&immutable, b"complete exit").unwrap();

        let events = dir.join("events.jsonl");
        let event = serde_json::json!({"schema":"current"});
        let original = b"{\"schema\":\"current\"}\n";
        fs::write(&events, original).unwrap();
        fs::set_permissions(&events, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(append_private_jsonl(&events, &event).is_err());
        assert_eq!(fs::read(&events).unwrap(), original);
        fs::set_permissions(&events, fs::Permissions::from_mode(0o600)).unwrap();
        append_private_jsonl(&events, &event).unwrap();

        let authority = dir.join("session.json");
        let sidecar = authority.with_extension("json.lock");
        fs::write(&sidecar, b"").unwrap();
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(try_lock_private_path(&authority).is_err());
        assert!(!authority.exists());
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(try_lock_private_path(&authority).unwrap().is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn private_storage_fails_closed_without_supported_permission_controls() {
        let dir = atomic_json_tmp_path(&std::env::temp_dir().join("morph-private-platform"));
        assert!(create_private_directories(&dir).is_err());
        assert!(write_private_atomic(&dir.join("secret.json"), b"private").is_err());
        assert!(!dir.exists());
    }

    #[test]
    fn append_rejects_partial_history_and_schema_switch_without_mutating_evidence() {
        let dir = directory("morph-shared-events");
        let path = dir.join("events.jsonl");
        let event = serde_json::json!({"schema":"current", "sequence":1});
        write_private_atomic(&path, b"{\"schema\":\"current\"}").unwrap();
        let partial = fs::read(&path).unwrap();
        assert!(
            append_private_jsonl(&path, &event)
                .unwrap_err()
                .to_string()
                .contains("incomplete record")
        );
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
