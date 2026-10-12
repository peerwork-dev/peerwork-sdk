//! Protected native secure-agent state. The file holds opaque exact wire JSON
//! bytes; semantic transitions and verification belong to `peerwork-core`.
//! An old TypeScript state file is never rewritten without explicit migration.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MAGIC: &[u8] = b"PEERWORK-NATIVE-SECURE-STATE\n1\n";
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum SecureStateError {
    #[error("protected secure-state directory or file required")]
    Protection,
    #[error("unsupported platform for protected local state")]
    UnsupportedPlatform,
    #[error("another process owns the secure-agent state")]
    Busy,
    #[error("secure-agent state handle belongs to another process")]
    ForeignProcess,
    #[error("incompatible secure-agent state; migration required")]
    MigrationRequired,
    #[error("secure-agent state exceeds size limit")]
    TooLarge,
    #[error("native secure-agent state is incomplete")]
    Corrupt,
    #[error("local secure-agent state operation failed")]
    Io(#[from] std::io::Error),
}

/// Exclusive process-local handle. The OS lock remains held until this value
/// is dropped, including across an atomic replacement of the state file.
pub struct SecureStateStore {
    path: PathBuf,
    _lock: ExclusiveLock,
}

struct ExclusiveLock {
    file: File,
    owner_pid: u32,
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // Unlock before close so an unrelated child briefly inheriting
            // this descriptor during process creation cannot keep our lock.
            if self.owner_pid == process_id() {
                unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
            }
        }
    }
}

impl SecureStateStore {
    pub fn open(path: &Path) -> Result<Self, SecureStateError> {
        check_private_parent(path)?;
        let lock_path = path.with_extension(format!(
            "{}.lock",
            path.extension().and_then(|s| s.to_str()).unwrap_or("state")
        ));
        let mut lock_options = OpenOptions::new();
        lock_options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = lock_options.open(&lock_path)?;
        check_private_file(&lock_path)?;
        lock_exclusive(&lock)?;
        let lock = ExclusiveLock {
            file: lock,
            owner_pid: process_id(),
        };
        if state_exists(path)? {
            check_private_file(path)?;
            let mut file = open_state_read(path)?;
            let mut magic = vec![0; MAGIC.len()];
            if file.read_exact(&mut magic).is_err() || magic != MAGIC {
                return Err(SecureStateError::MigrationRequired);
            }
            if file.metadata()?.len() <= MAGIC.len() as u64 {
                return Err(SecureStateError::Corrupt);
            }
        }
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
        })
    }

    /// Returns exact saved JSON wire bytes for internal replay. This is not a
    /// public DTO and must never be surfaced through a language binding.
    pub fn read_exact(&self) -> Result<Option<Vec<u8>>, SecureStateError> {
        self.ensure_owner()?;
        if !state_exists(&self.path)? {
            return Ok(None);
        }
        check_private_file(&self.path)?;
        let mut file = open_state_read(&self.path)?;
        let len = file.metadata()?.len();
        if len <= MAGIC.len() as u64 {
            return Err(SecureStateError::Corrupt);
        }
        if len > MAX_STATE_BYTES + MAGIC.len() as u64 {
            return Err(SecureStateError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(len as usize);
        file.read_to_end(&mut bytes)?;
        if !bytes.starts_with(MAGIC) {
            return Err(SecureStateError::MigrationRequired);
        }
        Ok(Some(bytes[MAGIC.len()..].to_vec()))
    }

    /// Atomically replaces native state with exact bytes after the caller has
    /// completed semantic validation. Empty/oversize state fails closed.
    pub fn write_exact(&self, bytes: &[u8]) -> Result<(), SecureStateError> {
        self.ensure_owner()?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(SecureStateError::TooLarge);
        }
        if state_exists(&self.path)? {
            check_private_file(&self.path)?;
            let mut file = open_state_read(&self.path)?;
            let mut magic = vec![0; MAGIC.len()];
            if file.read_exact(&mut magic).is_err() || magic != MAGIC {
                return Err(SecureStateError::MigrationRequired);
            }
            if file.metadata()?.len() <= MAGIC.len() as u64 {
                return Err(SecureStateError::Corrupt);
            }
        }
        let parent = self.path.parent().ok_or(SecureStateError::Protection)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".peerwork-state-")
            .tempfile_in(parent)?;
        temporary.as_file_mut().write_all(MAGIC)?;
        temporary.as_file_mut().write_all(bytes)?;
        temporary.as_file_mut().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| SecureStateError::Io(error.error))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn ensure_owner(&self) -> Result<(), SecureStateError> {
        if self._lock.owner_pid != process_id() {
            Err(SecureStateError::ForeignProcess)
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn process_id() -> u32 {
    unsafe { libc::getpid() as u32 }
}

#[cfg(not(unix))]
fn process_id() -> u32 {
    std::process::id()
}

fn state_exists(path: &Path) -> Result<bool, SecureStateError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SecureStateError::Io(error)),
    }
}

fn open_state_read(path: &Path) -> Result<File, SecureStateError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

#[cfg(unix)]
fn check_private_parent(path: &Path) -> Result<(), SecureStateError> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(SecureStateError::Protection);
    }
    let parent = path.parent().ok_or(SecureStateError::Protection)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| SecureStateError::Protection)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
        || fs::canonicalize(parent).map_err(|_| SecureStateError::Protection)? != parent
    {
        return Err(SecureStateError::Protection);
    }
    Ok(())
}

#[cfg(unix)]
fn check_private_file(path: &Path) -> Result<(), SecureStateError> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).map_err(|_| SecureStateError::Protection)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.len() > MAX_STATE_BYTES + MAGIC.len() as u64
    {
        return Err(SecureStateError::Protection);
    }
    Ok(())
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<(), SecureStateError> {
    use std::os::fd::AsRawFd;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Err(SecureStateError::Busy)
    } else {
        Err(SecureStateError::Io(error))
    }
}

#[cfg(not(unix))]
fn check_private_parent(_: &Path) -> Result<(), SecureStateError> {
    Err(SecureStateError::UnsupportedPlatform)
}
#[cfg(not(unix))]
fn check_private_file(_: &Path) -> Result<(), SecureStateError> {
    Err(SecureStateError::UnsupportedPlatform)
}
#[cfg(not(unix))]
fn lock_exclusive(_: &File) -> Result<(), SecureStateError> {
    Err(SecureStateError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn exact_state_survives_atomic_replace_and_reopen() {
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        let first = b"{\"signed\":\"\\ud800\"}";
        let second = b"{\"signed\":\"\\udc00\"}";
        {
            let store = SecureStateStore::open(&path).unwrap();
            assert_eq!(store.read_exact().unwrap(), None);
            store.write_exact(first).unwrap();
            assert_eq!(store.read_exact().unwrap(), Some(first.to_vec()));
            store.write_exact(second).unwrap();
        }
        let reopened = SecureStateStore::open(&path).unwrap();
        assert_eq!(reopened.read_exact().unwrap(), Some(second.to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_state_and_unprotected_paths_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        fs::write(&path, b"{\"v\":1}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            SecureStateStore::open(&path),
            Err(SecureStateError::MigrationRequired)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"{\"v\":1}");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            SecureStateStore::open(&path),
            Err(SecureStateError::Protection)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_state_is_refused_even_when_target_is_missing() {
        use std::os::unix::fs::symlink;
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        symlink(dir.path().join("absent"), &path).unwrap();
        assert!(matches!(
            SecureStateStore::open(&path),
            Err(SecureStateError::Protection)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lock_blocks_second_writer_and_releases_on_drop() {
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        let first = SecureStateStore::open(&path).unwrap();
        assert!(matches!(
            SecureStateStore::open(&path),
            Err(SecureStateError::Busy)
        ));
        drop(first);
        SecureStateStore::open(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn duplicated_descriptor_cannot_extend_guard_lifetime() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        let store = SecureStateStore::open(&path).unwrap();
        // A forked process temporarily shares this open file description.
        // `dup` makes that lifetime deterministic without a scheduling race.
        let inherited_fd = unsafe { libc::dup(store._lock.file.as_raw_fd()) };
        assert!(inherited_fd >= 0);
        let inherited = unsafe { File::from_raw_fd(inherited_fd) };
        drop(store);
        let reopened = SecureStateStore::open(&path).unwrap();
        drop(reopened);
        drop(inherited);
    }

    #[cfg(unix)]
    #[test]
    fn forked_child_drop_cannot_release_parent_lock() {
        use std::process::Command;
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        let store = SecureStateStore::open(&path).unwrap();
        store.write_exact(b"{\"parent\":true}").unwrap();

        // The child inherits the same open file description. Its destructor
        // must close that descriptor without unlocking the parent's guard.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            if !matches!(store.read_exact(), Err(SecureStateError::ForeignProcess))
                || !matches!(
                    store.write_exact(b"{\"child\":true}"),
                    Err(SecureStateError::ForeignProcess)
                )
            {
                unsafe { libc::_exit(2) };
            }
            drop(store);
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);

        let probe = || {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "secure_state::tests::child_lock_probe",
                    "--nocapture",
                ])
                .env("PEERWORK_TEST_SECURE_STATE_PATH", &path)
                .output()
                .unwrap()
        };
        let blocked = probe();
        assert!(blocked.status.success());
        assert!(String::from_utf8_lossy(&blocked.stdout).contains("PEERWORK_SECURE_BUSY"));
        assert_eq!(
            store.read_exact().unwrap(),
            Some(b"{\"parent\":true}".to_vec())
        );
        drop(store);
        let acquired = probe();
        assert!(acquired.status.success());
        assert!(String::from_utf8_lossy(&acquired.stdout).contains("PEERWORK_SECURE_ACQUIRED"));
    }

    #[cfg(unix)]
    #[test]
    fn child_lock_probe() {
        let Ok(path) = std::env::var("PEERWORK_TEST_SECURE_STATE_PATH") else {
            return;
        };
        match SecureStateStore::open(Path::new(&path)) {
            Err(SecureStateError::Busy) => println!("PEERWORK_SECURE_BUSY"),
            Ok(_) => println!("PEERWORK_SECURE_ACQUIRED"),
            Err(error) => panic!("unexpected secure-state lock error: {error}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn cross_process_lock_excludes_then_releases() {
        use std::process::Command;
        let dir = private_dir();
        let path = dir.path().join("agent.state");
        let probe = || {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "secure_state::tests::child_lock_probe",
                    "--nocapture",
                ])
                .env("PEERWORK_TEST_SECURE_STATE_PATH", &path)
                .output()
                .unwrap()
        };
        let first = SecureStateStore::open(&path).unwrap();
        let blocked = probe();
        assert!(blocked.status.success());
        assert!(String::from_utf8_lossy(&blocked.stdout).contains("PEERWORK_SECURE_BUSY"));
        drop(first);
        let acquired = probe();
        assert!(acquired.status.success());
        assert!(String::from_utf8_lossy(&acquired.stdout).contains("PEERWORK_SECURE_ACQUIRED"));
    }
}
