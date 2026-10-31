//! Local operation storage shared with the published Agent tools. No network
//! operation or host call runs while a SQLite transaction is held.
use crate::secure_state::{create_private_state_directory, read_private_file_bounded};
use peerwork_core::crypto::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

pub(crate) type Result<T> = std::result::Result<T, &'static str>;
pub(crate) fn digest(value: &Value) -> String { sha256_hex(value.to_string().as_bytes()) }
pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
pub(crate) fn private_json(path: &Path, limit: usize) -> Result<Value> {
    let bytes = read_private_file_bounded(path, limit).map_err(|_| "TOOLS_FILE_NOT_PRIVATE")?;
    peerwork_core::strict_json::parse_strict_json(&bytes).map_err(|_| "TOOLS_JSON_INVALID")
}
pub(crate) fn database(directory: &Path, name: &str) -> Result<Connection> {
    create_private_state_directory(directory).map_err(|_| "TOOLS_STATE_NOT_PRIVATE")?;
    let path = directory.join(name);
    if !path.exists() { crate::communication_host::write_private(&path, b"")?; }
    // Check ownership, mode, canonical parent and link identity before SQLite.
    crate::secure_state::validate_private_file(&path).map_err(|_| "TOOLS_STATE_NOT_PRIVATE")?;
    let db = Connection::open(path).map_err(|_| "TOOLS_STATE_FAILED")?;
    db.busy_timeout(Duration::from_secs(3)).map_err(|_| "TOOLS_STATE_FAILED")?;
    db.execute_batch("PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;").map_err(|_| "TOOLS_STATE_FAILED")?;
    Ok(db)
}
/// Native indexes have one engine owner and live on a local filesystem. Keep
/// FULL commit durability while avoiding a new rollback journal/directory sync
/// for every short admission, scheduling and inbox transaction.
pub(crate) fn single_owner_database(directory:&Path,name:&str)->Result<Connection>{
    create_private_state_directory(directory).map_err(|_|"TOOLS_STATE_NOT_PRIVATE")?;
    let sidecars=[directory.join(format!("{name}-wal")),directory.join(format!("{name}-shm")),directory.join(format!("{name}-journal"))];
    let check=||->Result<()>{
        for path in &sidecars{
            match std::fs::symlink_metadata(path){
                Ok(_)=>crate::secure_state::validate_private_file(path).map_err(|_|"TOOLS_STATE_NOT_PRIVATE")?,
                Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
                Err(_)=>return Err("TOOLS_STATE_NOT_PRIVATE"),
            }
        }Ok(())
    };
    check()?;
    #[cfg(windows)]
    for path in &sidecars[..2]{crate::windows_fs::create_or_check_file(path).map_err(|_|"TOOLS_STATE_NOT_PRIVATE")?;}
    let db=database(directory,name)?;
    let mode:String=db.pragma_query_value(None,"journal_mode",|r|r.get(0)).map_err(|_|"TOOLS_STATE_FAILED")?;
    if mode!="wal"{db.pragma_update(None,"journal_mode","WAL").map_err(|_|"TOOLS_STATE_FAILED")?;}
    let mode:String=db.pragma_query_value(None,"journal_mode",|r|r.get(0)).map_err(|_|"TOOLS_STATE_FAILED")?;
    if mode!="wal"{return Err("TOOLS_STATE_FAILED");}
    check()?;Ok(db)
}

#[cfg(test)]
mod native_database_tests{
    use super::*;
    #[test]
    fn owned_wal_preserves_full_durability_reopen_and_private_sidecars(){
        let root=crate::test_support::protected_test_dir();let directory=root.path().join("indexes");
        let db=single_owner_database(&directory,"owned.sqlite").unwrap();
        assert_eq!(db.pragma_query_value(None,"synchronous",|r|r.get::<_,i64>(0)).unwrap(),2);
        db.execute_batch("CREATE TABLE durable(value INTEGER); INSERT INTO durable VALUES(7);").unwrap();
        for suffix in ["-wal","-shm"]{crate::secure_state::validate_private_file(&directory.join(format!("owned.sqlite{suffix}"))).unwrap();}
        drop(db);
        let db=single_owner_database(&directory,"owned.sqlite").unwrap();
        assert_eq!(db.query_row("SELECT value FROM durable",[],|r|r.get::<_,u64>(0)).unwrap(),7);drop(db);
        #[cfg(unix)]{
            let other=root.path().join("unrelated");crate::communication_host::write_private(&other,b"must stay unchanged").unwrap();
            std::os::unix::fs::symlink(&other,directory.join("owned.sqlite-wal")).unwrap();
            assert!(matches!(single_owner_database(&directory,"owned.sqlite"),Err("TOOLS_STATE_NOT_PRIVATE")));
            assert_eq!(std::fs::read(other).unwrap(),b"must stay unchanged");
        }
    }
}
pub(crate) struct ToolStore { pub db: Connection }
impl ToolStore {
    pub fn open(profile: &Value) -> Result<Self> {
        let directory = profile["state_directory"].as_str().ok_or("TOOLS_PROFILE_INVALID")?;
        let db = database(Path::new(directory), "agent-tools.sqlite")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
            input TEXT, prepared TEXT, outcome TEXT, phase TEXT NOT NULL, pid INTEGER, process_token TEXT);")
            .map_err(|_| "TOOLS_STATE_FAILED")?;
        let pin = digest(&json!({"binding":profile["binding"],"identityPath":profile["kernel"]["identityPath"],
            "journalPath":profile["kernel"]["journalPath"],"authority":profile["kernel"]["authority"]}));
        db.execute("INSERT OR IGNORE INTO meta VALUES('binding',?1)", [&pin]).map_err(|_| "TOOLS_STATE_FAILED")?;
        let old: String = db.query_row("SELECT value FROM meta WHERE key='binding'", [], |r| r.get(0)).map_err(|_| "TOOLS_STATE_FAILED")?;
        if old != pin { return Err("TOOLS_PROFILE_MISMATCH"); }
        Ok(Self { db })
    }
    pub fn get(&self, key: &str) -> Result<Option<Value>> {
        let value: Option<String> = self.db.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .optional().map_err(|_| "TOOLS_STATE_FAILED")?;
        value.map(|v| serde_json::from_str(&v).map_err(|_| "TOOLS_STATE_INVALID")).transpose()
    }
    pub fn set(&self, key: &str, value: &Value) -> Result<()> {
        self.db.execute("INSERT INTO meta VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,value.to_string()])
            .map_err(|_| "TOOLS_STATE_FAILED")?; Ok(())
    }
    pub fn row(&self, id: &str) -> Result<Value> {
        self.db.query_row("SELECT input,prepared,outcome,phase,pid,process_token,request_hash FROM operations WHERE id=?1", [id], |r| {
            Ok((r.get::<_,Option<String>>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Option<String>>(2)?,
                r.get::<_,String>(3)?,r.get::<_,Option<u32>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,String>(6)?))
        }).optional().map_err(|_| "TOOLS_STATE_FAILED")?.ok_or("TOOLS_OPERATION_NOT_FOUND")
        .and_then(|(input,prepared,outcome,phase,pid,token,hash)| {
            let decode = |value: Option<String>| -> Result<Value> { value.map(|v|serde_json::from_str(&v).map_err(|_|"TOOLS_STATE_INVALID")).transpose().map(|v|v.unwrap_or(Value::Null)) };
            Ok(json!({"id":id,"input":decode(input)?,"prepared":decode(prepared)?,"outcome":decode(outcome)?,
                "phase":phase,"pid":pid,"process_token":token,"request_hash":hash}))
        })
    }
    pub fn reserve(&self, id: &str, input: &Value) -> Result<()> {
        let hash = digest(input);
        self.db.execute("INSERT OR IGNORE INTO operations(id,request_hash,input,phase) VALUES(?1,?2,?3,'PREPARING')", params![id,hash,input.to_string()])
            .map_err(|_| "TOOLS_STATE_FAILED")?;
        if self.row(id)?["request_hash"] != hash { return Err("TOOLS_OPERATION_INPUT_CONFLICT"); }
        Ok(())
    }
    pub fn claim(&self, id: &str) -> Result<()> {
        self.db.execute_batch("BEGIN IMMEDIATE").map_err(|_| "TOOLS_STATE_FAILED")?;
        let result = (|| {
            let row = self.row(id)?;
            if let Some(pid) = row["pid"].as_u64() {
                if process_alive(pid as u32, row["process_token"].as_str()) { return Err("TOOLS_OPERATION_BUSY"); }
            }
            self.db.execute("UPDATE operations SET pid=?1,process_token=?2 WHERE id=?3",params![std::process::id(),process_token(std::process::id()),id])
                .map_err(|_|"TOOLS_STATE_FAILED")?; Ok(())
        })();
        if result.is_ok() { self.db.execute_batch("COMMIT").map_err(|_|"TOOLS_STATE_FAILED")?; }
        else { let _ = self.db.execute_batch("ROLLBACK"); }
        result
    }
    pub fn release(&self, id: &str) {
        let _ = self.db.execute("UPDATE operations SET pid=NULL,process_token=NULL WHERE id=?1 AND pid=?2",params![id,std::process::id()]);
    }
    pub fn prepare(&self, id: &str, value: &Value) -> Result<()> {
        self.db.execute("UPDATE operations SET prepared=?1,phase='PREPARED' WHERE id=?2",params![value.to_string(),id]).map_err(|_|"TOOLS_STATE_FAILED")?; Ok(())
    }
    pub fn submitting(&self, id: &str) -> Result<()> {
        self.db.execute("UPDATE operations SET phase='SUBMITTING' WHERE id=?1",[id]).map_err(|_|"TOOLS_STATE_FAILED")?; Ok(())
    }
    pub fn finish(&self, id: &str, outcome: &Value) -> Result<()> {
        let terminal = matches!(outcome["state"].as_str(),Some("ACCEPTED"|"COMPLETED"|"REJECTED"));
        self.db.execute("UPDATE operations SET outcome=?1,phase=?2,input=CASE WHEN ?3 THEN NULL ELSE input END,
            prepared=CASE WHEN ?3 THEN NULL ELSE prepared END WHERE id=?4",params![outcome.to_string(),outcome["state"].as_str().unwrap_or("PENDING"),terminal,id])
            .map_err(|_|"TOOLS_STATE_FAILED")?; Ok(())
    }
    pub fn page(&self, after: &str, limit: u64) -> Result<Value> {
        if !(1..=32).contains(&limit) { return Err("TOOLS_PAGE_INVALID"); }
        let mut stmt=self.db.prepare("SELECT id,phase FROM operations WHERE id>?1 ORDER BY id LIMIT ?2").map_err(|_|"TOOLS_STATE_FAILED")?;
        let mut rows=stmt.query(params![after,limit+1]).map_err(|_|"TOOLS_STATE_FAILED")?;
        let mut items=Vec::new();
        while let Some(row)=rows.next().map_err(|_|"TOOLS_STATE_FAILED")? { items.push(json!({"operation_id":row.get::<_,String>(0).map_err(|_|"TOOLS_STATE_FAILED")?,"phase":row.get::<_,String>(1).map_err(|_|"TOOLS_STATE_FAILED")?})); }
        let next=if items.len()>limit as usize {Some(items[limit as usize-1]["operation_id"].clone())}else{None};
        items.truncate(limit as usize); Ok(json!({"items":items,"next_after":next}))
    }
}
pub(crate) fn output(row: &Value) -> Value {
    let mut out = if row["outcome"].is_object() {row["outcome"].clone()} else {json!({"state":if row["phase"]=="SUBMITTING"{"PENDING"}else{"NOT_SUBMITTED"},"phase":row["phase"],"effect_certainty":if row["phase"]=="SUBMITTING"{"UNKNOWN"}else{"NOT_SUBMITTED"},"recovery":"RESUME_SAME_INTENT","target":row["input"]["target"]})};
    out["operation_id"]=row["id"].clone(); out["audience"]=json!("WORKSPACE_INSTANCE_SHARED");
    out["model_response"]=json!("NOT_ATTESTED"); out["observation"]=json!("LOCAL_CACHED"); out
}
pub(crate) fn process_token(pid: u32) -> Option<String> {
    #[cfg(target_os="linux")]
    { std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?.rsplit_once(") ")?.1.split_whitespace().nth(19).map(str::to_owned) }
    #[cfg(not(target_os="linux"))] { let _=pid; None }
}
pub(crate) fn process_alive(pid: u32, token: Option<&str>) -> bool {
    if let (Some(expected),Some(actual))=(token,process_token(pid)) {return expected==actual;}
    #[cfg(unix)] { unsafe {libc::kill(pid as i32,0)==0 || std::io::Error::last_os_error().raw_os_error()==Some(libc::EPERM)} }
    #[cfg(windows)] { // Unknown ownership is deliberately not force-reclaimed.
        use windows_sys::Win32::{Foundation::CloseHandle,System::Threading::{OpenProcess,GetExitCodeProcess,PROCESS_QUERY_LIMITED_INFORMATION}};
        unsafe { let handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid); if handle.is_null(){return std::io::Error::last_os_error().raw_os_error()!=Some(87);}
            let mut code=0; let ok=GetExitCodeProcess(handle,&mut code);CloseHandle(handle);ok==0||code==259 }
    }
    #[cfg(not(any(unix,windows)))] {true}
}
