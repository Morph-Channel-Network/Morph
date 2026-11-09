//! CLI entry points and baseline regression tests reuse the sole public Rust package implementation.
#[allow(unused_imports)]
pub use morph_packages::persistence::*;

#[cfg(test)]
#[allow(unused_imports)]
use std::fs;

#[cfg(test)]
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

#[cfg(test)]
#[allow(unused_imports)]
use anyhow::{Context, Result, ensure};

#[cfg(test)]
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

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
