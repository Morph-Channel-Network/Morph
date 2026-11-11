use crate::{Result, StoreError, sql_error};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

#[cfg(target_os = "linux")]
pub(crate) fn open(path: &Path, read_only: bool) -> Result<(Connection, bool)> {
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path.file_name().is_none() {
        return Err(StoreError::Invalid);
    }
    let mut missing = Vec::new();
    let mut ancestor = parent;
    while !ancestor.exists() {
        missing.push(ancestor.to_path_buf());
        ancestor = ancestor
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
    }
    if !read_only {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|_| StoreError::Io)?;
        for created in missing.iter().rev() {
            sync_parent(created)?;
        }
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| StoreError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(StoreError::Permissions);
    }
    let absolute = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| StoreError::Io)?
            .join(parent)
    };
    if absolute
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(StoreError::Permissions);
    }
    // An exposed ancestor could let a different user rename the private leaf
    // between our checks and SQLite's own open. A root-owned sticky /tmp is safe
    // for an owner-controlled child; arbitrary shared writable parents are not.
    for ancestor in absolute.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| StoreError::Io)?;
        let owner = meta.uid();
        let trusted = owner == 0 || owner == rustix::process::geteuid().as_raw();
        let sticky_root = owner == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir() || !trusted || (meta.mode() & 0o022 != 0 && !sticky_root) {
            return Err(StoreError::Permissions);
        }
    }
    // The containing directory is private. Same-user concurrent path replacement
    // is outside this boundary; it can also replace the process and its key files.
    let mut created = false;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !read_only => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| StoreError::Io)?;
            file.sync_all().map_err(|_| StoreError::Io)?;
            created = true;
            file
        }
        Err(_) => return Err(StoreError::Io),
    };
    require_private(&file)?;
    if file.metadata().map_err(|_| StoreError::Io)?.len() > crate::MAX_DATABASE_BYTES {
        return Err(StoreError::Full);
    }
    if !created && file.metadata().map_err(|_| StoreError::Io)?.len() == 0 {
        return Err(StoreError::Corrupt);
    }
    // SQLite may read a hot rollback journal on open. Refuse linked or exposed
    // sidecars before handing the path to SQLite; never unlink a live journal.
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let side = std::path::PathBuf::from(name);
        match fs::symlink_metadata(&side) {
            Ok(_) => {
                let f = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                    )
                    .open(side)
                    .map_err(|_| StoreError::Permissions)?;
                require_private(&f)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(StoreError::Io),
        }
    }
    let flags = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let connection = Connection::open_with_flags(
        path,
        flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(sql_error)?;
    Ok((connection, created))
}

#[cfg(target_os = "linux")]
fn require_private(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().map_err(|_| StoreError::Io)?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err(StoreError::Permissions);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| StoreError::Io)
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn open(_: &Path, _: bool) -> Result<(Connection, bool)> {
    Err(StoreError::UnsupportedPlatform)
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn sync_parent(_: &Path) -> Result<()> {
    Err(StoreError::UnsupportedPlatform)
}
