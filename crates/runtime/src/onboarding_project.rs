//! Project configuration is not a private state root. Unix operations stay
//! relative to opened directory handles; project hints never authorize a signer.
use crate::participant::{ParticipantError, Result};
use std::path::{Component, Path};

fn conflict() -> ParticipantError {
    ParticipantError::local("HOST_CONFIGURATION_CONCURRENTLY_CHANGED", "LOCAL_CONFIGURATION")
}
fn failure(path: &Path, operation: &str, reason: &str) -> ParticipantError {
    crate::onboarding_files::path_error(path, "PROJECT_CONFIGURATION", operation, reason)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{ffi::{CString, OsStr, OsString}, fs::File, io::{Read, Write},
        os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}},
        path::PathBuf, sync::Arc};

    #[derive(Clone, Copy)]
    enum Policy { Namespace, Configuration, Private }
    struct Node {
        file: File, path: PathBuf, parent: Option<Arc<Node>>, name: OsString, policy: Policy,
    }
    #[derive(Clone)]
    pub(crate) struct Directory(Arc<Node>);
    pub(crate) struct StateLock { file:File, pid:u32 }
    impl StateLock {pub(crate) fn is_owner(&self)->bool{self.pid==std::process::id()}}
    impl Drop for StateLock {
        fn drop(&mut self) {if self.pid==std::process::id(){unsafe{libc::flock(self.file.as_raw_fd(),libc::LOCK_UN)};}}
    }
    fn name(value: &OsStr, path: &Path) -> Result<CString> {
        if !matches!(Path::new(value).components().collect::<Vec<_>>().as_slice(), [Component::Normal(_)]) {
            return Err(failure(path, "OPEN", "INVALID_COMPONENT"));
        }
        CString::new(value.as_bytes()).map_err(|_| failure(path, "OPEN", "INVALID_COMPONENT"))
    }
    fn io_error(path: &Path, operation: &str, e: &std::io::Error) -> ParticipantError {
        failure(path, operation, match e.raw_os_error() {
            Some(libc::ELOOP) => "SYMLINK",
            Some(libc::EACCES | libc::EPERM) => "PERMISSION_DENIED",
            Some(libc::ENOENT) => "NOT_FOUND",
            Some(libc::ENOTDIR) => "NOT_DIRECTORY_OR_SYMLINK",
            _ => "FILESYSTEM_ERROR",
        })
    }
    fn raw(file: i32, path: &Path, operation: &str) -> Result<File> {
        if file < 0 { return Err(io_error(path, operation, &std::io::Error::last_os_error())); }
        Ok(unsafe { File::from_raw_fd(file) })
    }
    fn metadata(node: &Node) -> Result<std::fs::Metadata> {
        let m = node.file.metadata().map_err(|e| io_error(&node.path, "STAT", &e))?;
        if !m.is_dir() { return Err(failure(&node.path, "STAT", "NOT_DIRECTORY")); }
        if !matches!(node.policy, Policy::Namespace) {
            if m.uid() != unsafe { libc::geteuid() } { return Err(failure(&node.path, "STAT", "OWNER_MISMATCH")); }
            let mask = if matches!(node.policy, Policy::Private) { 0o077 } else { 0o022 };
            if m.mode() & mask != 0 { return Err(failure(&node.path, "STAT", "CONFIGURATION_PERMISSIONS")); }
        }
        Ok(m)
    }
    fn stat_at(parent: &File, name: &CString, path: &Path) -> Result<Option<libc::stat>> {
        let mut out = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), out.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::NotFound { Ok(None) } else { Err(io_error(path, "STAT", &e)) };
        }
        Ok(Some(unsafe { out.assume_init() }))
    }
    impl Directory {
        pub(crate) fn open(path: &Path) -> Result<Self> {
            if !path.is_absolute() || path.components().any(|p| matches!(p, Component::ParentDir | Component::CurDir)) {
                return Err(failure(path, "OPEN", "ABSOLUTE_CANONICAL_PATH_REQUIRED"));
            }
            let root = raw(unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) }, Path::new("/"), "OPEN")?;
            let mut node = Arc::new(Node { file: root, path: "/".into(), parent: None, name: OsString::new(), policy: Policy::Namespace });
            let parts: Vec<_> = path.components().filter_map(|c| if let Component::Normal(n) = c { Some(n) } else { None }).collect();
            for (i, part) in parts.iter().enumerate() {
                let next = node.path.join(part); let n = name(part, &next)?;
                let mut flags = libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
                #[cfg(target_os = "linux")]
                { flags |= if i + 1 == parts.len() { libc::O_RDONLY } else { libc::O_PATH }; }
                #[cfg(target_os = "macos")]
                { flags |= if i + 1 == parts.len() { libc::O_RDONLY } else { libc::O_SEARCH }; }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                { flags |= libc::O_RDONLY; }
                let file = raw(unsafe { libc::openat(node.file.as_raw_fd(), n.as_ptr(), flags) }, &next, "OPEN")?;
                node = Arc::new(Node { file, path: next, parent: Some(node), name: (*part).into(), policy: Policy::Namespace });
            }
            let result = Self(node); result.verify()?; Ok(result)
        }
        pub(crate) fn path(&self) -> &Path { &self.0.path }
        pub(crate) fn private(path:&Path)->Result<Self>{
            let mut result=Self::open(path)?;
            Arc::get_mut(&mut result.0).expect("fresh directory handle").policy=Policy::Private;
            result.verify()?;Ok(result)
        }
        pub(crate) fn kind(&self,value:&str)->Result<Option<&'static str>> {
            self.verify()?;let n=name(OsStr::new(value),self.path())?;
            Ok(stat_at(&self.0.file,&n,&self.path().join(value))?.map(|s|match s.st_mode & libc::S_IFMT {libc::S_IFDIR=>"DIRECTORY",libc::S_IFREG=>"FILE",_=>"OTHER"}))
        }
        pub(crate) fn lock(&self,value:&str)->Result<StateLock>{
            self.verify()?;let parent=metadata(&self.0)?;
            if parent.uid()!=unsafe{libc::geteuid()} || parent.mode() & 0o077!=0{return Err(failure(self.path(),"LOCK","PRIVATE_PARENT_REQUIRED"))}
            let path=self.path().join(value);let n=name(OsStr::new(value),&path)?;
            let file=raw(unsafe{libc::openat(self.0.file.as_raw_fd(),n.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK,0o600)},&path,"LOCK")?;
            let m=file.metadata().map_err(|e|io_error(&path,"LOCK",&e))?;
            if !m.is_file() || m.uid()!=unsafe{libc::geteuid()} || m.mode() & 0o077!=0 || m.nlink()!=1{return Err(failure(&path,"LOCK","PRIVATE_FILE_REQUIRED"))}
            if unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{return Err(ParticipantError::local("HOST_INSTALLATION_ALREADY_OWNED_OR_UNSAFE","LOCAL_CONFIGURATION"))}
            let result=StateLock{file,pid:std::process::id()};
            let named=stat_at(&self.0.file,&n,&path)?.ok_or_else(||failure(&path,"LOCK","PATH_CHANGED"))?;
            if named.st_dev as u64!=m.dev() || named.st_ino as u64!=m.ino(){return Err(failure(&path,"LOCK","PATH_CHANGED"))}
            self.verify()?;Ok(result)
        }
        pub(crate) fn identity(&self) -> Result<serde_json::Value> {
            self.verify()?; let m = metadata(&self.0)?;
            Ok(serde_json::json!({"path":self.path(),"device":m.dev(),"inode":m.ino()}))
        }
        pub(crate) fn verify(&self) -> Result<()> {
            let mut current = Some(&self.0);
            while let Some(node) = current {
                let m = metadata(node)?;
                if let Some(parent) = &node.parent {
                    let n = name(&node.name, &node.path)?;
                    let named = stat_at(&parent.file, &n, &node.path)?.ok_or_else(|| failure(&node.path, "VERIFY", "PATH_CHANGED"))?;
                    if named.st_dev as u64 != m.dev() || named.st_ino as u64 != m.ino() || named.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(failure(&node.path, "VERIFY", "PATH_CHANGED"));
                    }
                }
                current = node.parent.as_ref();
            }
            Ok(())
        }
        pub(crate) fn child(&self, value: &str, create: bool, private: bool) -> Result<Option<Self>> {
            self.verify()?; let path = self.path().join(value); let n = name(OsStr::new(value), &path)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
            let mut fd = unsafe { libc::openat(self.0.file.as_raw_fd(), n.as_ptr(), flags) };
            if fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                if !create { return Ok(None); }
                if unsafe { libc::mkdirat(self.0.file.as_raw_fd(), n.as_ptr(), if private { 0o700 } else { 0o755 }) } != 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(io_error(&path, "MKDIR", &std::io::Error::last_os_error()));
                }
                fd = unsafe { libc::openat(self.0.file.as_raw_fd(), n.as_ptr(), flags) };
            }
            let file = raw(fd, &path, "OPEN")?;
            let result = Self(Arc::new(Node { file, path, parent: Some(self.0.clone()), name: value.into(), policy: if private { Policy::Private } else { Policy::Configuration } }));
            result.verify()?; Ok(Some(result))
        }
        pub(crate) fn read(&self, value: &str, limit: usize, private: bool) -> Result<Option<Vec<u8>>> {
            use std::os::unix::fs::FileTypeExt;
            self.verify()?;
            if private {
                let m = metadata(&self.0)?;
                if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 { return Err(failure(self.path(), "READ", "PRIVATE_PARENT_REQUIRED")); }
            }
            let path = self.path().join(value); let n = name(OsStr::new(value), &path)?;
            let Some(before) = stat_at(&self.0.file, &n, &path)? else { return Ok(None); };
            let fd = unsafe { libc::openat(self.0.file.as_raw_fd(), n.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) };
            let mut file = raw(fd, &path, "READ")?; let opened = file.metadata().map_err(|e| io_error(&path, "READ", &e))?;
            if opened.file_type().is_symlink() || !opened.is_file() || opened.file_type().is_fifo() { return Err(failure(&path, "READ", "REGULAR_FILE_REQUIRED")); }
            if opened.uid() != unsafe { libc::geteuid() } { return Err(failure(&path, "READ", "OWNER_MISMATCH")); }
            if opened.nlink() != 1 { return Err(failure(&path, "READ", "HARDLINK")); }
            if opened.mode() & if private { 0o077 } else { 0o022 } != 0 { return Err(failure(&path, "READ", "FILE_PERMISSIONS")); }
            if opened.len() > limit as u64 { return Err(failure(&path, "READ", "FILE_TOO_LARGE")); }
            if before.st_dev as u64 != opened.dev() || before.st_ino as u64 != opened.ino() { return Err(failure(&path, "READ", "PATH_CHANGED")); }
            let mut bytes = Vec::new(); (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|e| io_error(&path, "READ", &e))?;
            let after = file.metadata().map_err(|e| io_error(&path, "READ", &e))?;
            let named = stat_at(&self.0.file, &n, &path)?.ok_or_else(|| failure(&path, "READ", "PATH_CHANGED"))?;
            if bytes.len() > limit || after.len() != opened.len() || after.mtime() != opened.mtime() || after.mtime_nsec() != opened.mtime_nsec()
                || named.st_dev as u64 != opened.dev() || named.st_ino as u64 != opened.ino() || after.uid() != opened.uid() || after.mode() != opened.mode() || after.nlink() != 1 {
                return Err(failure(&path, "READ", "PATH_OR_CONTENT_CHANGED"));
            }
            self.verify()?; Ok(Some(bytes))
        }
        pub(crate) fn replace(&self, value: &str, expected: Option<&[u8]>, bytes: &[u8]) -> Result<()> {
            self.replace_with(value, expected, bytes, || {})
        }
        pub(crate) fn replace_private(&self,value:&str,expected:Option<&[u8]>,bytes:&[u8])->Result<()> {self.replace_inner(value,expected,bytes,64*1024*1024+128,true,||{})}
        fn replace_with(&self,value:&str,expected:Option<&[u8]>,bytes:&[u8],before_rename:impl FnOnce())->Result<()>{self.replace_inner(value,expected,bytes,256*1024,false,before_rename)}
        fn replace_inner(&self, value: &str, expected: Option<&[u8]>, bytes: &[u8], limit:usize,private:bool,before_rename: impl FnOnce()) -> Result<()> {
            if self.read(value, limit, private)?.as_deref() != expected { return Err(conflict()); }
            use rand_core::RngCore;
            let mut random = [0u8;16]; rand_core::OsRng.try_fill_bytes(&mut random).map_err(|_| failure(self.path(), "WRITE", "RANDOM_UNAVAILABLE"))?;
            let stage = format!(".peerwork-install-{}", random.iter().map(|v|format!("{v:02x}")).collect::<String>());
            let temporary = name(OsStr::new(&stage), self.path())?; let target = name(OsStr::new(value), self.path())?;
            let fd = unsafe { libc::openat(self.0.file.as_raw_fd(), temporary.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0o600) };
            let mut file = raw(fd, &self.path().join(&stage), "WRITE")?;
            let result = (|| {
                file.write_all(bytes).and_then(|_|file.sync_all()).map_err(|e|io_error(self.path(), "WRITE", &e))?;
                if self.read(value, limit, private)?.as_deref() != expected { return Err(conflict()); }
                self.verify()?; before_rename();
                if unsafe { libc::renameat(self.0.file.as_raw_fd(), temporary.as_ptr(), self.0.file.as_raw_fd(), target.as_ptr()) } != 0 {
                    return Err(io_error(self.path(), "RENAME", &std::io::Error::last_os_error()));
                }
                self.0.file.sync_all().map_err(|e|io_error(self.path(), "SYNC", &e))?; self.verify()
            })();
            // Relative cleanup cannot follow a replaced project pathname.
            unsafe { libc::unlinkat(self.0.file.as_raw_fd(), temporary.as_ptr(), 0) }; result
        }
        pub(crate) fn remove(&self, value: &str, expected: &[u8]) -> Result<()> {
            if self.read(value, 256 * 1024, false)?.as_deref() != Some(expected) { return Err(conflict()); }
            self.verify()?; let n = name(OsStr::new(value), self.path())?;
            if unsafe { libc::unlinkat(self.0.file.as_raw_fd(), n.as_ptr(), 0) } != 0 { return Err(io_error(self.path(), "UNLINK", &std::io::Error::last_os_error())); }
            self.0.file.sync_all().map_err(|e|io_error(self.path(), "SYNC", &e))?; self.verify()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};
        #[test]
        fn shared_ancestor_is_context_not_private_authority() {
            let t=crate::test_support::protected_test_dir(); let shared=t.path().join("shared"); std::fs::create_dir(&shared).unwrap(); std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o775)).unwrap();
            let project=shared.join("repo"); std::fs::create_dir(&project).unwrap();
            let root=Directory::open(&project).unwrap(); let config=root.child(".codex",true,false).unwrap().unwrap();
            config.replace("config.toml",None,b"safe").unwrap(); assert_eq!(config.read("config.toml",32,false).unwrap(),Some(b"safe".to_vec()));
            assert!(crate::onboarding_files::check_directory(&project,false).is_err());
            assert_eq!(std::fs::metadata(shared).unwrap().mode() & 0o777,0o775);
        }
        #[test]
        fn ancestor_swap_at_commit_does_not_redirect_write_or_cleanup() {
            let t=crate::test_support::protected_test_dir(); let project=t.path().join("repo"); std::fs::create_dir(&project).unwrap();
            let root=Directory::open(&project).unwrap();let config=root.child(".codex",true,false).unwrap().unwrap();config.replace("config.toml",None,b"old").unwrap();
            let moved=t.path().join("moved");
            let result=config.replace_with("config.toml",Some(b"old"),b"ours",||{
                std::fs::rename(&project,&moved).unwrap(); std::fs::create_dir(&project).unwrap();std::fs::create_dir(project.join(".codex")).unwrap();std::fs::write(project.join(".codex/config.toml"),b"do not touch").unwrap();
            });
            assert!(result.is_err()); assert_eq!(std::fs::read(project.join(".codex/config.toml")).unwrap(),b"do not touch");
            assert_eq!(std::fs::read(moved.join(".codex/config.toml")).unwrap(),b"ours"); assert_eq!(std::fs::read_dir(moved.join(".codex")).unwrap().count(),1);
            assert!(config.read("config.toml",32,false).is_err());
        }
        #[test]
        fn link_and_configuration_conflict_do_not_modify_targets() {
            let t=crate::test_support::protected_test_dir();let root=Directory::open(t.path()).unwrap();let config=root.child("config",true,false).unwrap().unwrap();config.replace("a",None,b"original").unwrap();
            assert!(config.replace("a",Some(b"stale"),b"bad").is_err()); assert_eq!(config.read("a",32,false).unwrap().unwrap(),b"original");
            symlink(config.path().join("a"),config.path().join("alias")).unwrap();assert!(config.read("alias",32,false).is_err());
            std::fs::hard_link(config.path().join("a"),config.path().join("hard")).unwrap();assert!(config.read("a",32,false).is_err());
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::path::PathBuf;
    // Keep the established Windows ACL/reparse validation. Namespace handles
    // additionally prevent ancestor rename while a project operation is active.
    #[derive(Clone)]
    pub(crate) struct Directory { path: PathBuf, _pins: std::sync::Arc<Vec<std::fs::File>> }
    pub(crate) struct StateLock { file:std::fs::File,pid:u32 }
    impl StateLock {pub(crate) fn is_owner(&self)->bool{self.pid==std::process::id()}}
    impl Drop for StateLock {fn drop(&mut self){if self.is_owner(){let _=self.file.unlock();}}}
    impl Directory {
        pub(crate) fn open(path:&Path)->Result<Self>{Ok(Self{path:path.into(),_pins:std::sync::Arc::new(crate::onboarding_files::windows::pin_directory(path)?)})}
        pub(crate) fn path(&self)->&Path{&self.path}
        pub(crate) fn private(path:&Path)->Result<Self>{crate::secure_state::check_private_directory(path).map_err(|_|failure(path,"OPEN","PRIVATE_PARENT_REQUIRED"))?;Self::open(path)}
        pub(crate) fn kind(&self,name:&str)->Result<Option<&'static str>>{self.verify()?;match std::fs::symlink_metadata(self.path.join(name)){Ok(m)=>Ok(Some(if m.file_type().is_symlink(){"OTHER"}else if m.is_dir(){"DIRECTORY"}else if m.is_file(){"FILE"}else{"OTHER"})),Err(e)if e.kind()==std::io::ErrorKind::NotFound=>Ok(None),Err(_)=>Err(failure(&self.path,"STAT","PERMISSION_DENIED"))}}
        pub(crate) fn lock(&self,name:&str)->Result<StateLock>{self.verify()?;let file=crate::windows_fs::open_private_lock(&self.path.join(name)).map_err(|_|failure(&self.path,"LOCK","PRIVATE_FILE_REQUIRED"))?;file.try_lock().map_err(|_|ParticipantError::local("HOST_INSTALLATION_ALREADY_OWNED_OR_UNSAFE","LOCAL_CONFIGURATION"))?;Ok(StateLock{file,pid:std::process::id()})}
        pub(crate) fn verify(&self)->Result<()>{crate::onboarding_files::windows::directory(&self.path)}
        pub(crate) fn identity(&self)->Result<serde_json::Value>{self.verify()?;crate::onboarding_files::windows::directory_identity(&self.path)}
        pub(crate) fn child(&self,name:&str,create:bool,private:bool)->Result<Option<Self>>{
            if !matches!(Path::new(name).components().collect::<Vec<_>>().as_slice(),[Component::Normal(_)]){return Err(failure(&self.path,"OPEN","INVALID_COMPONENT"));}
            self.verify()?;let p=self.path.join(name);if !p.exists()&&!create{return Ok(None)}
            if create{crate::onboarding_files::directory(&p,private)?;}else{crate::onboarding_files::check_directory(&p,private)?;}Self::open(&p).map(Some)
        }
        pub(crate) fn read(&self,name:&str,max:usize,private:bool)->Result<Option<Vec<u8>>>{self.verify()?;if private{crate::onboarding_files::read_optional(&self.path.join(name),max)}else{crate::onboarding_files::read_public_optional(&self.path.join(name),max)}}
        pub(crate) fn replace(&self,name:&str,old:Option<&[u8]>,bytes:&[u8])->Result<()>{self.verify()?;crate::onboarding_files::replace_if_unchanged(&self.path.join(name),old,bytes)}
        pub(crate) fn replace_private(&self,name:&str,old:Option<&[u8]>,bytes:&[u8])->Result<()>{self.verify()?;crate::onboarding_files::replace_if_unchanged(&self.path.join(name),old,bytes)}
        pub(crate) fn remove(&self,name:&str,old:&[u8])->Result<()>{self.verify()?;crate::onboarding_files::remove_if_unchanged(&self.path.join(name),old)}
    }
}
pub(crate) use platform::{Directory,StateLock};

pub(crate) fn read_private_source(path:&Path,limit:usize)->Result<Option<Vec<u8>>>{
    let parent=path.parent().ok_or_else(||failure(path,"READ","PARENT_REQUIRED"))?;
    let name=path.file_name().and_then(|n|n.to_str()).ok_or_else(||failure(path,"READ","INVALID_COMPONENT"))?;
    Directory::open(parent)?.read(name,limit,true)
}
