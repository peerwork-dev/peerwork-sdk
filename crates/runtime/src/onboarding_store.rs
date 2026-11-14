//! The two onboarding bookkeeping consumers share the existing secure-state
//! envelope/lock. Legacy project-local stores keep their original files.
use crate::{onboarding_project::{Directory,StateLock},participant::{ParticipantError,Result},secure_state::{SecureStateError,SecureStateStore}};
use std::path::Path;
pub(crate) enum Store {
    Protected(SecureStateStore),
    Anchored {directory:Directory,name:String,_lock:StateLock},
}
fn invalid()->ParticipantError{ParticipantError::local("LOCAL_STATE_RECOVERY_REQUIRED","LOCAL_CONFIGURATION")}
impl Store {
    fn ensure_owner(&self,operation:&'static str)->Result<()>{if matches!(self,Self::Anchored{_lock,..}if !_lock.is_owner()){return Err(SecureStateError::ForeignProcess.diagnose(ParticipantError::local("LOCAL_STATE_FOREIGN_PROCESS","LOCAL_CONFIGURATION"),operation))}Ok(())}
    pub(crate) fn protected(path:&Path)->Result<Self>{SecureStateStore::open(path).map(Self::Protected).map_err(|e|e.diagnose(ParticipantError::local("LOCAL_STATE_OWNED_OR_UNSAFE","LOCAL_CONFIGURATION"),"OPEN"))}
    pub(crate) fn anchored(directory:Directory,name:&str,allow_missing:bool)->Result<Self>{
        let lock=directory.lock(&format!("{name}.lock"))?;
        let result=Self::Anchored{directory,name:name.into(),_lock:lock};
        if result.read_exact()?.is_none()&&!allow_missing{return Err(invalid())} Ok(result)
    }
    pub(crate) fn read_exact(&self)->Result<Option<Vec<u8>>>{
        self.ensure_owner("READ")?;
        match self {
            Self::Protected(s)=>s.read_exact().map_err(|e|e.diagnose(invalid(),"READ")),
            Self::Anchored{directory,name,..}=>directory.read(name,64*1024*1024+128,true)?.map(|b|SecureStateStore::snapshot_payload(&b,64*1024*1024).map(|v|v.to_vec()).map_err(|e|e.diagnose(invalid(),"READ"))).transpose(),
        }
    }
    pub(crate) fn write_exact(&self,bytes:&[u8])->Result<()>{
        self.ensure_owner("WRITE")?;
        match self {
            Self::Protected(s)=>s.write_exact(bytes).map_err(|e|e.diagnose(invalid(),"WRITE")),
            Self::Anchored{directory,name,..}=>{let old=directory.read(name,64*1024*1024+128,true)?;let wire=SecureStateStore::snapshot_wire(bytes).map_err(|e|e.diagnose(invalid(),"WRITE"))?;directory.replace_private(name,old.as_deref(),&wire)},
        }
    }
}

#[cfg(all(test,unix))]
mod tests{
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_bytes(path:&Path,bytes:&[u8]) {
        std::fs::write(path,bytes).unwrap();
        std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn diagnostic(error:ParticipantError,cause:&str,operation:&str,path:&Path) {
        assert_eq!(error.phase,"LOCAL_CONFIGURATION");
        assert_eq!(error.effect_certainty,"NOT_SUBMITTED");
        assert!(error.operation_id.is_none());
        let details=error.details.as_ref().unwrap();
        assert_eq!(details["local_state"]["cause"],cause);
        assert_eq!(details["local_state"]["operation"],operation);
        assert_eq!(details["local_state"]["next_action"],error.recovery);
        let wire=serde_json::to_string(&error).unwrap();
        assert!(!wire.contains(path.to_str().unwrap()));
        assert!(!wire.contains("private-payload"));
    }
    #[test]
    fn protected_open_distinguishes_contention_protection_io_and_state_envelopes() {
        let t=crate::test_support::protected_test_dir();let path=t.path().join("original.state");
        let store=Store::protected(&path).unwrap();store.write_exact(b"private-payload").unwrap();
        let original=std::fs::read(&path).unwrap();
        let busy=Store::protected(&path).err().unwrap();
        assert_eq!(busy.code,"LOCAL_STATE_OWNED_OR_UNSAFE");
        assert_eq!(busy.details.as_ref().unwrap()["local_state"]["owner_observation"],"NOT_OBSERVED");
        diagnostic(busy,"BUSY","OPEN",&path);drop(store);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();
        diagnostic(Store::protected(&path).err().unwrap(),"PROTECTION","OPEN",&path);
        assert_eq!(std::fs::read(&path).unwrap(),original);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        let incompatible=b"legacy private-payload without native state envelope";
        private_bytes(&path,incompatible);
        diagnostic(Store::protected(&path).err().unwrap(),"MIGRATION_REQUIRED","OPEN",&path);
        assert_eq!(std::fs::read(&path).unwrap(),incompatible);
        let mut corrupt=SecureStateStore::snapshot_wire(b"x").unwrap();corrupt.pop();private_bytes(&path,&corrupt);
        diagnostic(Store::protected(&path).err().unwrap(),"CORRUPT","OPEN",&path);
        assert_eq!(std::fs::read(&path).unwrap(),corrupt);
        let io_path=t.path().join("unavailable.state");let lock=io_path.with_extension("state.lock");std::fs::create_dir(&lock).unwrap();
        diagnostic(Store::protected(&io_path).err().unwrap(),"IO","OPEN",&io_path);
        assert!(lock.is_dir());assert!(!io_path.exists());
    }
    #[test]
    fn protected_read_write_diagnostics_preserve_the_original_bytes() {
        let t=crate::test_support::protected_test_dir();let path=t.path().join("original.state");
        let store=Store::protected(&path).unwrap();store.write_exact(b"private-payload").unwrap();
        let original=std::fs::read(&path).unwrap();
        diagnostic(store.write_exact(b"").unwrap_err(),"TOO_LARGE","WRITE",&path);
        assert_eq!(std::fs::read(&path).unwrap(),original);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();
        diagnostic(store.read_exact().unwrap_err(),"PROTECTION","READ",&path);
        diagnostic(store.write_exact(b"replacement").unwrap_err(),"PROTECTION","WRITE",&path);
        assert_eq!(std::fs::read(&path).unwrap(),original);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        for (bytes,cause) in [(b"legacy private-payload without native state envelope".as_slice(),"MIGRATION_REQUIRED"),(b"x".as_slice(),"CORRUPT")] {
            // Magic-only state is corrupt on both read and write.
            let mut corrupt=SecureStateStore::snapshot_wire(b"x").unwrap();corrupt.pop();
            let bytes=if cause=="CORRUPT"{corrupt.as_slice()}else{bytes};private_bytes(&path,bytes);
            diagnostic(store.read_exact().unwrap_err(),cause,"READ",&path);
            diagnostic(store.write_exact(b"replacement").unwrap_err(),cause,"WRITE",&path);
            assert_eq!(std::fs::read(&path).unwrap(),bytes);
        }
    }
    #[test]
    fn protected_read_write_io_failure_keeps_the_original_directory() {
        let t=crate::test_support::protected_test_dir();let directory=t.path().join("store");
        crate::secure_state::create_private_state_directory(&directory).unwrap();let path=directory.join("original.state");
        let store=Store::protected(&path).unwrap();store.write_exact(b"private-payload").unwrap();
        let original=std::fs::read(&path).unwrap();let moved=t.path().join("preserved-original");
        std::fs::rename(&directory,&moved).unwrap();private_bytes(&directory,b"blocked directory entry");
        diagnostic(store.read_exact().unwrap_err(),"IO","READ",&path);
        diagnostic(store.write_exact(b"replacement").unwrap_err(),"IO","WRITE",&path);
        assert_eq!(std::fs::read(moved.join("original.state")).unwrap(),original);
        assert_eq!(std::fs::read(directory).unwrap(),b"blocked directory entry");
    }
    #[test]
    fn inherited_protected_store_reports_foreign_process_without_releasing_owner() {
        let t=crate::test_support::protected_test_dir();let path=t.path().join("original.state");
        let store=Store::protected(&path).unwrap();store.write_exact(b"private-payload").unwrap();let original=std::fs::read(&path).unwrap();
        let child=unsafe{libc::fork()};assert!(child>=0);
        if child==0 {
            let foreign=|error:ParticipantError|error.details.as_ref().unwrap()["local_state"]["cause"]=="FOREIGN_PROCESS";
            let failed=foreign(store.read_exact().unwrap_err())&&foreign(store.write_exact(b"replacement").unwrap_err());
            drop(store);unsafe{libc::_exit(if failed{0}else{2})};
        }
        let mut status=0;assert_eq!(unsafe{libc::waitpid(child,&mut status,0)},child);assert_eq!(status,0);
        diagnostic(Store::protected(&path).err().unwrap(),"BUSY","OPEN",&path);
        assert_eq!(std::fs::read(&path).unwrap(),original);drop(store);assert!(Store::protected(&path).is_ok());
    }
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
