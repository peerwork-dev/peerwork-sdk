//! Current-user protected Windows files shared by both durable stores.
//! All checks inspect opened handles, including reparse-point and hard-link
//! checks. A private directory is required before either store can open.

use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, Prefix};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACL,
    ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE,
    INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW,
    BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_DATA, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
    READ_CONTROL, WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "protected current-user state required",
    )
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

struct Handle(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn current_user_sid() -> io::Result<Vec<u8>> {
    let mut token = INVALID_HANDLE_VALUE;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
    if size < size_of::<TOKEN_USER>() as u32 || size > 65536 {
        return Err(denied());
    }
    let mut buffer = vec![0_u64; (size as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let len = unsafe { GetLengthSid(user.User.Sid) } as usize;
    if len == 0 || len > 256 {
        return Err(denied());
    }
    let mut sid = vec![0_u8; len];
    unsafe { std::ptr::copy_nonoverlapping(user.User.Sid.cast::<u8>(), sid.as_mut_ptr(), len) };
    Ok(sid)
}

fn inspect(file: &File, directory: bool) -> io::Result<()> {
    let handle = file.as_raw_handle();
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(denied());
    }

    let current = current_user_sid()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _descriptor = Descriptor(descriptor);
    if owner.is_null()
        || dacl.is_null()
        || unsafe { EqualSid(owner, current.as_ptr().cast_mut().cast()) } == 0
    {
        return Err(denied());
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || (directory && control & SE_DACL_PROTECTED == 0)
    {
        return Err(denied());
    }
    let mut acl_info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || acl_info.AceCount != 1
    {
        return Err(denied());
    }
    let mut ace: *mut c_void = null_mut();
    if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
        return Err(denied());
    }
    let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
    // ACCESS_ALLOWED_ACE_TYPE = 0. The private directory grants only the
    // current user full access; no administrator or Everyone ACE is accepted.
    if allowed.Header.AceType != 0
        || allowed.Header.AceFlags & INHERIT_ONLY_ACE as u8 != 0
        || allowed.Header.AceFlags
            & !((OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE) as u8)
            != 0
        || allowed.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
        || unsafe {
            EqualSid(
                (&allowed.SidStart as *const u32).cast_mut().cast(),
                current.as_ptr().cast_mut().cast(),
            )
        } == 0
    {
        return Err(denied());
    }
    Ok(())
}

fn set_current_user_owner(path: &Path, file: &File) -> io::Result<()> {
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            WRITE_OWNER | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let owner_handle = unsafe { File::from_raw_handle(handle) };
    let mut expected: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let mut actual: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut expected) } == 0
        || unsafe { GetFileInformationByHandle(owner_handle.as_raw_handle(), &mut actual) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if expected.dwVolumeSerialNumber != actual.dwVolumeSerialNumber
        || expected.nFileIndexHigh != actual.nFileIndexHigh
        || expected.nFileIndexLow != actual.nFileIndexLow
        || actual.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    let current = current_user_sid()?;
    let result = unsafe {
        SetSecurityInfo(
            owner_handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            current.as_ptr().cast_mut().cast(),
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    inspect(file, false)
}

fn open_nofollow(
    path: &Path,
    directory: bool,
    data_access: u32,
    share_delete: bool,
) -> io::Result<File> {
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | data_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 },
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    inspect(&file, directory)?;
    Ok(file)
}

fn reject_reparse_ancestors(path: &Path) -> io::Result<()> {
    let mut parts = path.components();
    if !matches!(parts.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || parts.any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(denied());
    }
    for ancestor in path.ancestors().skip(1) {
        let handle = unsafe {
            CreateFileW(
                wide(ancestor).as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(denied());
        }
    }
    Ok(())
}

pub(crate) fn private_parent(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(denied());
    }
    let parent = path.parent().ok_or_else(denied)?;
    create_private_directory(parent)
}

/// Validate an existing protected parent without creating missing directories.
pub(crate) fn private_existing_parent(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(denied());
    }
    let parent = path.parent().ok_or_else(denied)?;
    reject_reparse_ancestors(parent)?;
    let _parent = open_nofollow(parent, true, 0, true)?;
    Ok(())
}

/// Creates a dedicated state directory with a protected current-user DACL.
/// Existing directories must pass the same handle-based review.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(denied());
    }
    reject_reparse_ancestors(path)?;
    match open_nofollow(path, true, 0, true) {
        Ok(_) => return Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32) =>
            {}
        Err(error) => return Err(error),
    }
    let sid = current_user_sid()?;
    let mut sid_string = null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut sid_string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_text = unsafe {
        let mut len = 0;
        while *sid_string.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len));
        LocalFree(sid_string.cast());
        text
    };
    let sddl: Vec<u16> = format!("O:{sid_text}D:P(A;OICI;FA;;;{sid_text})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _descriptor_guard = Descriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    open_nofollow(path, true, 0, true).map(|_| ())
}

pub(crate) fn private_file(path: &Path) -> io::Result<()> {
    open_nofollow(path, false, 0, true).map(|_| ())
}

pub(crate) fn private_file_if_exists(path: &Path) -> io::Result<bool> {
    match open_nofollow(path, false, 0, true) {
        Ok(_) => Ok(true),
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32) => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn create_or_check_file(path: &Path) -> io::Result<()> {
    private_parent(path)?;
    // Creation inherits exactly the protected parent DACL. Existing files
    // must independently pass the handle-based ACL and link checks.
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => {
            set_current_user_owner(path, &file)?;
            inspect(&file, false)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    private_file(path)
}

pub(crate) fn open_private_read(path: &Path) -> io::Result<File> {
    open_nofollow(path, false, FILE_READ_DATA, true)
}

pub(crate) fn open_private_lock(path: &Path) -> io::Result<File> {
    create_or_check_file(path)?;
    // The lock pathname must not be moved or replaced while this handle
    // lives; otherwise a second process could lock a different file there.
    open_nofollow(path, false, FILE_READ_DATA | FILE_WRITE_DATA, false)
}

pub(crate) fn atomic_replace(path: &Path, magic: &[u8], bytes: &[u8]) -> io::Result<()> {
    private_parent(path)?;
    let parent = path.parent().ok_or_else(denied)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".peerwork-state-")
        .tempfile_in(parent)?;
    set_current_user_owner(temporary.path(), temporary.as_file())?;
    inspect(temporary.as_file(), false)?;
    temporary.as_file_mut().write_all(magic)?;
    temporary.as_file_mut().write_all(bytes)?;
    temporary.as_file_mut().sync_all()?;
    // tempfile persist uses Windows replacement on the same volume. The
    // replacement inherits the temporary file's verified private ACL.
    let source = temporary.into_temp_path();
    if unsafe {
        MoveFileExW(
            wide(source.as_ref()).as_ptr(),
            wide(path).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    private_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherit_only_ace_is_not_an_effective_private_directory_grant() {
        let outer = tempfile::tempdir().unwrap();
        let path = outer.path().join("inherit-only");
        let sid = current_user_sid().unwrap();
        let mut sid_ptr = null_mut();
        assert_ne!(
            unsafe { ConvertSidToStringSidW(sid.as_ptr().cast_mut().cast(), &mut sid_ptr) },
            0
        );
        let sid_text = unsafe {
            let mut len = 0;
            while *sid_ptr.add(len) != 0 {
                len += 1;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid_ptr, len));
            LocalFree(sid_ptr.cast());
            text
        };
        let sddl: Vec<u16> = format!("D:P(A;OICIIO;FA;;;{sid_text})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let _guard = Descriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        assert_ne!(
            unsafe { CreateDirectoryW(wide(&path).as_ptr(), &attributes) },
            0
        );
        assert!(create_private_directory(&path).is_err());
    }

    #[test]
    fn protected_directory_and_files_reject_broad_and_reparse_paths() {
        let outer = tempfile::tempdir().unwrap();
        let state_dir = outer.path().join("protected");
        create_private_directory(&state_dir).unwrap();
        create_private_directory(&state_dir).unwrap();
        let file = state_dir.join("state.bin");
        create_or_check_file(&file).unwrap();
        assert!(private_file(&file).is_ok());
        assert!(private_parent(&file).is_ok());
        // The ordinary temp directory is not an acceptable state parent.
        assert!(private_parent(&outer.path().join("broad.bin")).is_err());
        let linked = state_dir.join("linked.bin");
        fs::hard_link(&file, &linked).unwrap();
        assert!(private_file(&file).is_err());
        assert!(private_file(&linked).is_err());
        let reparse = state_dir.join("reparse.bin");
        if std::os::windows::fs::symlink_file(&file, &reparse).is_ok() {
            assert!(private_file(&reparse).is_err());
        }
        let nested = state_dir.join("nested");
        create_private_directory(&nested).unwrap();
        let alias = outer.path().join("alias");
        if std::os::windows::fs::symlink_dir(&state_dir, &alias).is_ok() {
            assert!(private_parent(&alias.join("nested").join("state.bin")).is_err());
        }
    }

    #[test]
    fn atomic_replace_preserves_private_acl_and_exact_bytes() {
        let outer = tempfile::tempdir().unwrap();
        let state_dir = outer.path().join("protected");
        create_private_directory(&state_dir).unwrap();
        let path = state_dir.join("state.bin");
        atomic_replace(&path, b"header", b"first").unwrap();
        atomic_replace(&path, b"header", b"second").unwrap();
        let mut bytes = Vec::new();
        use std::io::Read;
        open_private_read(&path)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"headersecond");
    }
}
