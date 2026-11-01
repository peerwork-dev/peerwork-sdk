//! Local process birth observations, never business time or authority. A missing
//! observation is not proof of death; callers retain unknown launch ownership.
#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {}

pub(crate) fn token(pid: u32) -> Option<String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()?
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .nth(19)
            .map(str::to_owned)
    }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        if unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        } != size
        {
            return None;
        }
        Some(format!(
            "macos:{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, FILETIME},
            System::Threading::{
                GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut created: FILETIME = std::mem::zeroed();
            let mut exited = created;
            let mut kernel = created;
            let mut user = created;
            let mut state = 0;
            let ok = GetExitCodeProcess(handle, &mut state) != 0
                && state == 259
                && GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) != 0;
            CloseHandle(handle);
            ok.then(|| {
                format!(
                    "windows:{:08x}{:08x}",
                    created.dwHighDateTime, created.dwLowDateTime
                )
            })
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}
/// Conservative liveness. True without a birth-token match means only that
/// death could not be established, not that the original process was verified.
pub(crate) fn alive(pid: u32, expected: Option<&str>) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    if let (Some(expected), Some(actual)) = (expected, token(pid)) {
        return expected == actual;
    }
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return std::io::Error::last_os_error().raw_os_error() != Some(87);
            }
            let mut state = 0;
            let ok = GetExitCodeProcess(handle, &mut state);
            CloseHandle(handle);
            ok == 0 || state == 259
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_process_birth_token_is_stable_and_a_different_process_cannot_match() {
        let pid = std::process::id();
        let current = token(pid).expect("supported platform process identity");
        assert_eq!(token(pid).as_ref(), Some(&current));
        assert!(alive(pid, Some(&current)));
        assert!(!alive(pid, Some("different-process")));
        assert!(!alive(0, None));
        assert!(token(0).is_none());
    }
}
