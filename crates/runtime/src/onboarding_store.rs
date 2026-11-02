//! The two onboarding bookkeeping consumers share the existing secure-state
//! envelope/lock. Legacy project-local stores keep their original files.
use crate::{onboarding_project::{Directory,StateLock},participant::{ParticipantError,Result},secure_state::SecureStateStore};
use std::path::Path;
pub(crate) enum Store {
    Protected(SecureStateStore),
    Anchored {directory:Directory,name:String,_lock:StateLock},
}
fn invalid()->ParticipantError{ParticipantError::local("LOCAL_STATE_RECOVERY_REQUIRED","LOCAL_CONFIGURATION")}
impl Store {
    fn ensure_owner(&self)->Result<()>{if matches!(self,Self::Anchored{_lock,..}if !_lock.is_owner()){return Err(ParticipantError::local("LOCAL_STATE_FOREIGN_PROCESS","LOCAL_CONFIGURATION"))}Ok(())}
    pub(crate) fn protected(path:&Path)->Result<Self>{SecureStateStore::open(path).map(Self::Protected).map_err(|_|ParticipantError::local("LOCAL_STATE_OWNED_OR_UNSAFE","LOCAL_CONFIGURATION"))}
    pub(crate) fn anchored(directory:Directory,name:&str,allow_missing:bool)->Result<Self>{
        let lock=directory.lock(&format!("{name}.lock"))?;
        let result=Self::Anchored{directory,name:name.into(),_lock:lock};
        if result.read_exact()?.is_none()&&!allow_missing{return Err(invalid())} Ok(result)
    }
    pub(crate) fn read_exact(&self)->Result<Option<Vec<u8>>>{
        self.ensure_owner()?;
        match self {
            Self::Protected(s)=>s.read_exact().map_err(|_|invalid()),
            Self::Anchored{directory,name,..}=>directory.read(name,64*1024*1024+128,true)?.map(|b|SecureStateStore::snapshot_payload(&b,64*1024*1024).map(|v|v.to_vec()).map_err(|_|invalid())).transpose(),
        }
    }
    pub(crate) fn write_exact(&self,bytes:&[u8])->Result<()>{
        self.ensure_owner()?;
        match self {
            Self::Protected(s)=>s.write_exact(bytes).map_err(|_|invalid()),
            Self::Anchored{directory,name,..}=>{let old=directory.read(name,64*1024*1024+128,true)?;let wire=SecureStateStore::snapshot_wire(bytes).map_err(|_|invalid())?;directory.replace_private(name,old.as_deref(),&wire)},
        }
    }
}

#[cfg(all(test,unix))]
mod tests{
    use super::*;
    #[test]
    fn fork_cannot_read_write_or_release_original_anchored_owner(){
        let t=crate::test_support::protected_test_dir();let dir=Directory::private(t.path()).unwrap();let store=Store::anchored(dir.clone(),"ownership.state",true).unwrap();store.write_exact(b"{\"parent\":true}").unwrap();
        let child=unsafe{libc::fork()};assert!(child>=0);
        if child==0{
            let failed_read=matches!(store.read_exact(),Err(e)if e.code=="LOCAL_STATE_FOREIGN_PROCESS");let failed_write=matches!(store.write_exact(b"{\"child\":true}"),Err(e)if e.code=="LOCAL_STATE_FOREIGN_PROCESS");
            drop(store);unsafe{libc::_exit(if failed_read&&failed_write{0}else{2})};
        }
        let mut status=0;assert_eq!(unsafe{libc::waitpid(child,&mut status,0)},child);assert_eq!(status,0);
        assert!(Store::anchored(dir.clone(),"ownership.state",false).is_err());assert_eq!(store.read_exact().unwrap().unwrap(),b"{\"parent\":true}");drop(store);
        assert!(Store::anchored(dir,"ownership.state",false).is_ok());
    }
}
