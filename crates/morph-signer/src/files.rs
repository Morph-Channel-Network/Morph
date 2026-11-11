//! Bounded read of an owner-controlled configuration or atomic journal snapshot.
//! Does not lock, write, recover or create signing authority.
use crate::Error;
use rustix::fs::{Mode, OFlags, open};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;

pub fn read(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    crate::ipc::private_parent(path).map_err(|_| Error::ProtectedFile)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| Error::ProtectedFile)?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| Error::ProtectedFile)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > limit as u64
    {
        return Err(Error::ProtectedFile);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit as u64).checked_add(1).ok_or(Error::ProtectedFile)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::ProtectedFile)?;
    if bytes.len() > limit {
        return Err(Error::ProtectedFile);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
    #[test]
    fn protected_reader_rejects_aliases_broad_modes_special_files_and_size() {
        let dir = std::env::temp_dir().join(format!("morph-signer-file-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("authority.json");
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::fs::write(&path, b"private snapshot").unwrap();
        assert_eq!(read(&path, 64).unwrap().as_slice(), b"private snapshot");
        assert!(read(&path, 4).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path, 64).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(read(&alias, 64).is_err());
        let hardlink = dir.join("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(read(&path, 64).is_err());
        let fifo = dir.join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
        assert!(read(&fifo, 64).is_err());
        assert!(read(&dir, 64).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
