//! Files owned by explicit local onboarding. Public project ancestors need not
//! be private, but no writable/symlink ancestor may redirect generated outputs.
use crate::participant::{ParticipantError, Result};
use std::path::{Component, Path};
#[cfg(windows)]
#[path = "onboarding_windows.rs"]
mod windows;
fn error() -> ParticipantError {
    ParticipantError::local("ONBOARDING_PATH_UNSAFE", "LOCAL_CONFIGURATION")
}
pub(crate) fn directory(path: &Path, private: bool) -> Result<()> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(error());
    }
    let parent = path.parent().ok_or_else(error)?;
    check_directory(parent, false)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(if private { 0o700 } else { 0o755 })
                    .create(path)
                    .map_err(|_| error())?;
            }
            #[cfg(windows)]
            crate::windows_fs::create_private_directory(path).map_err(|_| error())?;
            #[cfg(not(any(unix, windows)))]
            return Err(error());
        }
        Err(_) => return Err(error()),
    }
    check_directory(path, private)
}
pub(crate) fn check_directory(path: &Path, private: bool) -> Result<()> {
    let m = std::fs::symlink_metadata(path).map_err(|_| error())?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::canonicalize(path).map_err(|_| error())? != path {
            return Err(error());
        }
        if m.uid() != unsafe { libc::geteuid() }
            || m.mode() & if private { 0o077 } else { 0o022 } != 0
        {
            return Err(error());
        }
        for ancestor in path.ancestors().skip(1) {
            let parent = std::fs::symlink_metadata(ancestor).map_err(|_| error())?;
            let trusted_owner = parent.uid() == 0 || parent.uid() == unsafe { libc::geteuid() };
            let sticky_root = parent.uid() == 0 && parent.mode() & 0o1000 != 0;
            if !parent.is_dir()
                || parent.file_type().is_symlink()
                || !trusted_owner
                || (parent.mode() & 0o022 != 0 && !sticky_root)
            {
                return Err(error());
            }
        }
    }
    #[cfg(windows)]
    {
        windows::directory(path)?;
        if private {
            crate::secure_state::check_private_directory(path).map_err(|_| error())?;
        }
    }
    Ok(())
}
pub(crate) fn read_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    read_file(path, limit, true)
}
pub(crate) fn read_public_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    read_file(path, limit, false)
}
fn read_file(path: &Path, limit: usize, private: bool) -> Result<Option<Vec<u8>>> {
    check_directory(path.parent().ok_or_else(error)?, false)?;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(error()),
        Ok(m) => {
            if !m.is_file() || m.file_type().is_symlink() || m.len() > limit as u64 {
                return Err(error());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if m.uid() != unsafe { libc::geteuid() }
                    || m.nlink() != 1
                    || m.mode() & if private { 0o077 } else { 0o022 } != 0
                {
                    return Err(error());
                }
            }
        }
    }
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(windows))]
    let mut f = options.open(path).map_err(|_| error())?;
    #[cfg(windows)]
    let mut f = windows::read(path, private)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = f.metadata().map_err(|_| error())?;
        let named = std::fs::symlink_metadata(path).map_err(|_| error())?;
        if opened.ino() != named.ino() || opened.dev() != named.dev() {
            return Err(error());
        }
    }
    let mut bytes = Vec::new();
    f.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error())?;
    if bytes.len() > limit {
        return Err(error());
    }
    Ok(Some(bytes))
}
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let expected = read_public_optional(path, 256 * 1024)?;
    replace_if_unchanged(path, expected.as_deref(), bytes)
}
fn unchanged(path: &Path, expected: Option<&[u8]>) -> Result<()> {
    if read_public_optional(path, 256 * 1024)?.as_deref() != expected {
        return Err(ParticipantError::local(
            "HOST_CONFIGURATION_CONCURRENTLY_CHANGED",
            "LOCAL_CONFIGURATION",
        ));
    }
    Ok(())
}
pub(crate) fn replace_if_unchanged(
    path: &Path,
    expected: Option<&[u8]>,
    bytes: &[u8],
) -> Result<()> {
    unchanged(path, expected)?;
    #[cfg(windows)]
    {
        windows::replace(path, expected, bytes)?;
    }
    #[cfg(not(windows))]
    {
        use std::io::Write;
        let parent = path.parent().ok_or_else(error)?;
        let mut f = tempfile::Builder::new()
            .prefix(".peerwork-install-")
            .tempfile_in(parent)
            .map_err(|_| error())?;
        f.write_all(bytes)
            .and_then(|_| f.as_file().sync_all())
            .map_err(|_| error())?;
        // No filesystem operation follows this comparison before rename.
        // Uncooperative same-user editors can still race that final boundary;
        // the project lock coordinates Peerwork writers, not arbitrary editors.
        unchanged(path, expected)?;
        f.persist(path).map_err(|_| error())?;
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| error())?;
    }
    Ok(())
}

pub(crate) fn remove_if_unchanged(path: &Path, expected: &[u8]) -> Result<()> {
    if read_public_optional(path, 256 * 1024)?.as_deref() != Some(expected) {
        return Err(ParticipantError::local(
            "HOST_CONFIGURATION_CONCURRENTLY_CHANGED",
            "LOCAL_CONFIGURATION",
        ));
    }
    std::fs::remove_file(path).map_err(|_| error())?;
    #[cfg(unix)]
    std::fs::File::open(path.parent().ok_or_else(error)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| error())?;
    Ok(())
}
