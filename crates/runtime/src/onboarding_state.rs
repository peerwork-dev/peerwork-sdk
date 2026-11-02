//! User-owned onboarding bookkeeping, separate from shared project contents.
use crate::{onboarding_files as files, participant::{ParticipantError, Result}};
use std::path::{Path, PathBuf};

fn invalid(path:&Path,reason:&str)->ParticipantError { files::path_error(path,"PRIVATE_STATE_ROOT","SELECT",reason) }
fn create_tree(path:&Path)->Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => files::check_directory(path,false),
        Err(e) if e.kind()==std::io::ErrorKind::NotFound => {
            let parent=path.parent().ok_or_else(||invalid(path,"PARENT_REQUIRED"))?;
            create_tree(parent)?; files::directory(path,true)
        },
        Err(_) => Err(invalid(path,"PERMISSION_DENIED")),
    }
}
fn base()->Result<PathBuf> {
    #[cfg(windows)]
    let candidate=std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or_else(||invalid(Path::new("LOCALAPPDATA"),"OS_USER_STATE_ROOT_UNAVAILABLE"))?;
    #[cfg(target_os="macos")]
    let candidate=std::env::var_os("HOME").map(|p|PathBuf::from(p).join("Library/Application Support")).ok_or_else(||invalid(Path::new("HOME"),"OS_USER_STATE_ROOT_UNAVAILABLE"))?;
    #[cfg(all(unix,not(target_os="macos")))]
    let candidate=if let Some(value)=std::env::var_os("XDG_STATE_HOME") {PathBuf::from(value)}else{
        std::env::var_os("HOME").map(|p|PathBuf::from(p).join(".local/state")).ok_or_else(||invalid(Path::new("HOME"),"OS_USER_STATE_ROOT_UNAVAILABLE"))?
    };
    if !candidate.is_absolute() || candidate.components().any(|c|matches!(c,std::path::Component::ParentDir)) {return Err(invalid(&candidate,"ABSOLUTE_STATE_ROOT_REQUIRED"));}
    Ok(candidate.join("peerwork"))
}
pub(crate) fn root(create:bool)->Result<Option<PathBuf>> {
    let path=base()?;
    if !create && !path.try_exists().map_err(|_|invalid(&path,"PERMISSION_DENIED"))? {return Ok(None)}
    if create {create_tree(&path)?;}
    files::check_directory(&path,true)?;Ok(Some(path))
}
pub(crate) fn project(project:&Path,kind:&str,create:bool)->Result<Option<PathBuf>> {
    let Some(root)=root(create)? else{return Ok(None)};
    let path=root.join(kind);
    if create {files::directory(&path,true)?;}else if !path.try_exists().map_err(|_|invalid(&path,"PERMISSION_DENIED"))? {return Ok(None)}
    files::check_directory(&path,true)?;
    let spelling=project.to_str().ok_or_else(||invalid(project,"UTF8_PATH_REQUIRED"))?;
    let key=peerwork_core::crypto::sha256_hex(spelling.as_bytes());
    let selected=path.join(key);
    if create {files::directory(&selected,true)?;}else if !selected.try_exists().map_err(|_|invalid(&selected,"PERMISSION_DENIED"))? {return Ok(None)}
    files::check_directory(&selected,true)?;Ok(Some(selected))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_first_use_creates_one_valid_private_tree(){
        let t=crate::test_support::protected_test_dir();let path=t.path().join("first/nested/user-state");let barrier=std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers:Vec<_>=(0..8).map(|_|{let b=barrier.clone();let p=path.clone();std::thread::spawn(move||{b.wait();create_tree(&p)})}).collect();
        for worker in workers {worker.join().unwrap().unwrap();}files::check_directory(&path,true).unwrap();
    }
}
