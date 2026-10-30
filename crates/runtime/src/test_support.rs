//! Protected temporary parents for tests of durable native state.

use std::path::{Path, PathBuf};

pub(crate) struct ProtectedTestDir {
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl ProtectedTestDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn protected_test_dir() -> ProtectedTestDir {
    let root = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let path = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // macOS exposes its temporary parent through /var, a system alias
        // for /private/var. Native state deliberately rejects alias paths;
        // canonicalize our newly created test root instead of relaxing it.
        std::fs::canonicalize(root.path()).unwrap()
    };
    #[cfg(windows)]
    let path = {
        let path = root.path().join("state");
        crate::windows_fs::create_private_directory(&path).unwrap();
        path
    };
    #[cfg(not(any(unix, windows)))]
    let path = root.path().to_owned();
    ProtectedTestDir { _root: root, path }
}
