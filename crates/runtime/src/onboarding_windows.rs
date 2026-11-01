//! Windows project configuration checks. Unlike identity stores, a project may
//! be readable by others. Its owner and every effective writer must remain the
//! selected user or a trusted local system principal. Existing directory ACLs
//! are never changed; generated replacement files have private current-user ACLs.
use super::{error, Result};
use std::{
    ffi::c_void,
    fs::{self, File},
    io::{self, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_SUCCESS, INVALID_HANDLE_VALUE},
    Security::{
        AclSizeInformation,
        Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, GetAclInformation, GetTokenInformation, LookupAccountNameW, TokenUser,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, MoveFileExW, BY_HANDLE_FILE_INFORMATION, DELETE,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
        WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "project path or effective write authority is unsafe",
    )
}
fn current_user() -> io::Result<Vec<u8>> {
    let mut raw = INVALID_HANDLE_VALUE;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // An owned File also closes a token handle; no file operations are used.
    let token = unsafe { File::from_raw_handle(raw) };
    let mut length = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length) };
    if !(size_of::<TOKEN_USER>() as u32..=65536).contains(&length) {
        return Err(denied());
    }
    let mut data = vec![0u64; (length as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let length = unsafe { windows_sys::Win32::Security::GetLengthSid(user.User.Sid) } as usize;
    if !(1..=256).contains(&length) {
        return Err(denied());
    }
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length) }.to_vec())
}
fn sid_text(sid: PSID) -> io::Result<String> {
    let mut raw = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = Descriptor(raw.cast());
    let mut length = 0;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
        if length > 256 {
            return Err(denied());
        }
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, length) });
    drop(descriptor);
    Ok(value)
}
fn installer_sid() -> Option<Vec<u8>> {
    // Resolve the local Windows servicing principal rather than accepting an
    // arbitrary service SID or relying on a machine/account-specific value.
    let name: Vec<u16> = "NT SERVICE\\TrustedInstaller"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let (mut length, mut domain_length, mut usage) = (0, 0, 0);
    unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            null_mut(),
            &mut length,
            null_mut(),
            &mut domain_length,
            &mut usage,
        )
    };
    if length == 0 || length > 256 || domain_length > 65536 {
        return None;
    }
    let mut sid = vec![0u8; length as usize];
    let mut domain = vec![0u16; domain_length as usize];
    (unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut length,
            domain.as_mut_ptr(),
            &mut domain_length,
            &mut usage,
        )
    } != 0)
        .then_some(sid)
}
struct Trust {
    current: Vec<u8>,
    installer: Option<Vec<u8>>,
}
impl Trust {
    fn open() -> io::Result<Self> {
        Ok(Self {
            current: current_user()?,
            installer: installer_sid(),
        })
    }
    fn current(&self, sid: PSID) -> bool {
        !sid.is_null() && unsafe { EqualSid(sid, self.current.as_ptr().cast_mut().cast()) } != 0
    }
    fn system(&self, sid: PSID) -> bool {
        if self.current(sid) {
            return true;
        }
        if self
            .installer
            .as_ref()
            .is_some_and(|value| unsafe { EqualSid(sid, value.as_ptr().cast_mut().cast()) } != 0)
        {
            return true;
        }
        // SYSTEM and local Administrators are the Windows equivalent of the
        // root-owned ancestors accepted on Unix, not delegated Agent authority.
        sid_text(sid).is_ok_and(|value| matches!(value.as_str(), "S-1-5-18" | "S-1-5-32-544"))
    }
}
fn open(path: &Path, directory: bool, data: u32) -> io::Result<File> {
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | data,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn inspect(file: &File, directory: bool, selected: bool, trust: &Trust) -> io::Result<()> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(denied());
    }
    let (mut owner, mut dacl, mut descriptor): (PSID, *mut ACL, *mut c_void) =
        (null_mut(), null_mut(), null_mut());
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let _descriptor = Descriptor(descriptor);
    if owner.is_null()
        || dacl.is_null()
        || if selected {
            !trust.current(owner)
        } else {
            !trust.system(owner)
        }
    {
        return Err(denied());
    }
    let mut acl: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || acl.AceCount > 4096
    {
        return Err(denied());
    }
    // Adding an unrelated sibling under a system ancestor is harmless. Replacing
    // our ancestor/child or changing its ACL is not. Selected project/file nodes
    // reject all untrusted writes, including inherited effective ACEs.
    const GENERIC_ALL: u32 = 0x10000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    let mut write = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    if selected {
        write |= FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | GENERIC_WRITE;
    }
    for index in 0..acl.AceCount {
        let mut raw = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(denied());
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 || header.AceType == 1 {
            continue;
        }
        if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(denied());
        }
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if ace.Mask & write != 0 && !trust.system(sid) {
            return Err(denied());
        }
    }
    Ok(())
}
fn components(path: &Path) -> io::Result<()> {
    let mut parts = path.components();
    if !path.is_absolute()
        || !matches!(parts.next(),Some(Component::Prefix(p))if matches!(p.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_)))
        || parts.any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(denied());
    }
    Ok(())
}
pub(super) fn directory(path: &Path) -> Result<()> {
    components(path).map_err(|_| error())?;
    let trust = Trust::open().map_err(|_| error())?;
    for (index, node) in path.ancestors().enumerate() {
        let handle = open(node, true, 0).map_err(|_| error())?;
        inspect(&handle, true, index == 0, &trust).map_err(|_| error())?;
    }
    Ok(())
}
pub(super) fn read(path: &Path, private: bool) -> Result<File> {
    directory(path.parent().ok_or_else(error)?)?;
    if private {
        return crate::windows_fs::open_private_read(path).map_err(|_| error());
    }
    let handle = open(path, false, FILE_READ_DATA).map_err(|_| error())?;
    inspect(&handle, false, true, &Trust::open().map_err(|_| error())?).map_err(|_| error())?;
    Ok(handle)
}
struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("prepared"));
        let _ = fs::remove_dir(&self.0);
    }
}
pub(super) fn replace(path: &Path, expected: Option<&[u8]>, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(error)?;
    directory(parent)?;
    use rand_core::RngCore;
    let mut random = [0u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| error())?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let stage = Stage(parent.join(format!(".peerwork-install-{suffix}")));
    crate::windows_fs::create_private_directory(&stage.0).map_err(|_| error())?;
    let prepared = stage.0.join("prepared");
    crate::windows_fs::create_or_check_file(&prepared).map_err(|_| error())?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&prepared)
            .map_err(|_| error())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| error())?;
    }
    super::unchanged(path, expected)?;
    if unsafe {
        MoveFileExW(
            wide(&prepared).as_ptr(),
            wide(path).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(error());
    }
    crate::windows_fs::private_file(path).map_err(|_| error())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{CreateDirectoryW, CREATE_NEW},
    };
    fn descriptor(other: &str) -> Descriptor {
        let current = sid_text(Trust::open().unwrap().current.as_ptr().cast_mut().cast()).unwrap();
        let sddl: Vec<u16> = format!("O:{current}D:P(A;OICI;FA;;;{current})(A;OICI;{other};;;WD)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut raw = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut raw,
                    null_mut(),
                )
            },
            0
        );
        Descriptor(raw)
    }
    fn attributes(value: &Descriptor) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: value.0,
            bInheritHandle: 0,
        }
    }
    fn project(parent: &Path, name: &str, other: &str) -> PathBuf {
        let path = parent.join(name);
        let acl = descriptor(other);
        let attributes = attributes(&acl);
        assert_ne!(
            unsafe { CreateDirectoryW(wide(&path).as_ptr(), &attributes) },
            0
        );
        path
    }
    fn file(path: &Path, other: &str) {
        let acl = descriptor(other);
        let attributes = attributes(&acl);
        let raw = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                FILE_WRITE_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE);
        let mut file = unsafe { File::from_raw_handle(raw) };
        file.write_all(b"user configuration").unwrap();
        file.sync_all().unwrap();
    }
    #[test]
    fn ordinary_drive_path_accepts_readers_and_rejects_other_project_writers() {
        let root = crate::test_support::protected_test_dir();
        let good = project(root.path(), "readable", "FR");
        let spelling = good.to_string_lossy();
        let ordinary = PathBuf::from(spelling.strip_prefix(r"\\?\").unwrap_or(&spelling));
        directory(&ordinary).unwrap();
        let config = ordinary.join("config.json");
        file(&config, "FR");
        let mut input = String::new();
        use std::io::Read;
        read(&config, false)
            .unwrap()
            .read_to_string(&mut input)
            .unwrap();
        assert_eq!(input, "user configuration");
        let writable = project(root.path(), "writable", "FW");
        assert!(directory(&writable).is_err());
        let bad = ordinary.join("writable.json");
        file(&bad, "FW");
        assert!(read(&bad, false).is_err());
    }
    #[test]
    fn readable_project_rejects_hardlinked_files_and_reparse_ancestors() {
        let root = crate::test_support::protected_test_dir();
        let project = project(root.path(), "readable", "FR");
        let config = project.join("config.json");
        file(&config, "FR");
        fs::hard_link(&config, project.join("linked.json")).unwrap();
        assert!(read(&config, false).is_err());
        let alias = root.path().join("alias");
        if std::os::windows::fs::symlink_dir(&project, &alias).is_ok() {
            assert!(directory(&alias).is_err());
        }
    }
    #[test]
    fn project_replacement_preserves_concurrent_edit_and_publishes_private_output() {
        let root = crate::test_support::protected_test_dir();
        let project = project(root.path(), "readable", "FR");
        let config = project.join("config.json");
        file(&config, "FR");
        fs::write(&config, b"user changed").unwrap();
        assert!(super::super::replace_if_unchanged(
            &config,
            Some(b"user configuration"),
            b"generated"
        )
        .is_err());
        assert_eq!(fs::read(&config).unwrap(), b"user changed");
        super::super::replace_if_unchanged(&config, Some(b"user changed"), b"generated").unwrap();
        assert_eq!(fs::read(&config).unwrap(), b"generated");
        crate::windows_fs::private_file(&config).unwrap();
        assert!(fs::read_dir(&project).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".peerwork-install-")));
    }
}
