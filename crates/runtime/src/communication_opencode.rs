//! OpenCode V2's original local service and durable exact-session input API.
//! No extra process, transcript replay, replacement session or credential copy.
use super::{operation::Budget, R};
use peerwork_core::crypto::sha256_hex;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) fn default_service_file() -> R<PathBuf> {
    let root=std::env::var_os("XDG_STATE_HOME").map(PathBuf::from).or_else(||
        std::env::var_os("HOME").map(|p|PathBuf::from(p).join(".local/state")))
        .filter(|p|p.is_absolute()).ok_or("OPENCODE_SERVICE_SELECTION_REQUIRED")?;
    Ok(root.join("opencode/service.json"))
}
fn identifier(value:&str,prefix:&str)->bool {
    value.starts_with(prefix)&&value.len()<=256&&value.len()>prefix.len()
        &&value.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'_'|b'-'))
}
pub(crate) fn destination(config:&Value)->R<Value> {
    let file=config["service_file"].as_str().filter(|p|Path::new(p).is_absolute())
        .ok_or("OPENCODE_SERVICE_SELECTION_REQUIRED")?;
    let session=config["session_id"].as_str().filter(|s|identifier(s,"ses_"))
        .ok_or("OPENCODE_SESSION_SELECTION_REQUIRED")?;
    if config["directory"].as_str().is_none_or(|p|!Path::new(p).is_absolute()) {return Err("HOST_CONFIG_INVALID")}
    Ok(json!({"host":"OPENCODE_V2","conversation_id":session,"session_id":session,
        "endpoint":format!("opencode-service://{}",sha256_hex(file.as_bytes()))}))
}

/// One authenticated operation; credentials are read anew on the next operation.
pub(crate) struct Client {
    http:reqwest::Client, executor:tokio::runtime::Handle, budget:Budget,
    base:reqwest::Url, password:Option<String>, pid:u64,
}
impl Client {
    pub(crate) fn open(file:&Path,http:reqwest::Client,executor:tokio::runtime::Handle,budget:Budget)->R<Self> {
        let raw=crate::secure_state::read_private_file_bounded(file,16384).map_err(|_|"OPENCODE_SERVICE_UNAVAILABLE")?;
        let value=peerwork_core::strict_json::parse_strict_json(&raw).map_err(|_|"OPENCODE_SERVICE_INVALID")?;
        let base=reqwest::Url::parse(value["url"].as_str().ok_or("OPENCODE_SERVICE_INVALID")?).map_err(|_|"HOST_ENDPOINT_INVALID")?;
        if base.scheme()!="http" || !matches!(base.host_str(),Some("127.0.0.1"|"localhost"|"[::1]"|"::1"))
            || base.port().is_none() || base.path()!="/" || !base.username().is_empty()
            || base.password().is_some() || base.query().is_some() || base.fragment().is_some() {
            return Err("HOST_ENDPOINT_INVALID")
        }
        let pid=value["pid"].as_u64().filter(|p|*p>0).ok_or("OPENCODE_SERVICE_INVALID")?;
        let password=match value.get("password") {None=>None,Some(Value::String(p)) if p.len()<=4096=>Some(p.clone()),_=>return Err("OPENCODE_SERVICE_INVALID")};
        let client=Self{http,executor,budget,base,password,pid};
        let info=client.request("GET","/api/info",None)?;
        if info["pid"].as_u64()!=Some(client.pid) {return Err("HOST_BINDING_MISMATCH")}
        if !info["version"].as_str().is_some_and(|v|v.starts_with("2.")) {return Err("HOST_API_UNSUPPORTED")}
        if value["version"].as_str().is_some_and(|v|info["version"]!=v) {return Err("HOST_BINDING_MISMATCH")}
        Ok(client)
    }
    pub(crate) fn request(&self,method:&str,path:&str,body:Option<&Value>)->R<Value> {
        let url=self.base.join(path).map_err(|_|"HOST_ENDPOINT_INVALID")?;
        let timeout=self.budget.remaining().map_err(|_|"HOST_OPERATION_TIMEOUT")?;
        self.executor.block_on(async {
            let mut request=self.http.request(reqwest::Method::from_bytes(method.as_bytes()).map_err(|_|"HOST_CONFIG_INVALID")?,url).timeout(timeout);
            if let Some(password)=&self.password {request=request.basic_auth("opencode",Some(password));}
            if let Some(body)=body {request=request.header("content-type","application/json").body(body.to_string());}
            let mut response=request.send().await.map_err(|e|if e.is_timeout(){"HOST_OPERATION_TIMEOUT"}else if e.is_connect(){"HOST_UNAVAILABLE"}else{"HOST_ACK_UNKNOWN"})?;
            match response.status().as_u16() {200..=299=>{},401|403=>return Err("HOST_AUTHENTICATION_FAILED"),404=>return Err("OPENCODE_RESOURCE_NOT_FOUND"),409=>return Err("HOST_INPUT_CONFLICT"),429=>return Err("HOST_INBOX_FULL"),500..=599=>return Err("HOST_UNAVAILABLE"),_=>return Err("HOST_PROTOCOL_ERROR")}
            let mut raw=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|_|"HOST_ACK_UNKNOWN")? {
                if raw.len()+chunk.len()>262144 {return Err("HOST_FRAME_TOO_LARGE")}
                raw.extend_from_slice(&chunk);
            }
            if raw.is_empty(){return Ok(Value::Null)}
            peerwork_core::strict_json::parse_strict_json(&raw).map_err(|_|"HOST_RESPONSE_INVALID")
        })
    }
    pub(crate) fn session(&self,session:&str,directory:&str)->R<Value> {
        if !identifier(session,"ses_"){return Err("OPENCODE_SESSION_SELECTION_REQUIRED")}
        let value=self.request("GET",&format!("/api/session/{session}"),None)?;
        let value=value.get("data").unwrap_or(&value);
        if value["id"]!=session || value["location"]["directory"]!=directory {return Err("HOST_BINDING_MISMATCH")}
        if !value["time"]["archived"].is_null(){return Err("OPENCODE_SESSION_ARCHIVED")}
        Ok(value.clone())
    }
    pub(crate) fn sessions(&self,directory:&str)->R<Value> {
        let mut path=reqwest::Url::parse("http://localhost/api/session").unwrap();
        path.query_pairs_mut().append_pair("directory",directory).append_pair("limit","16").append_pair("archived","false");
        self.request("GET",&format!("{}?{}",path.path(),path.query().unwrap()),None)
    }
}

fn client(host:&super::Host)->R<Client> {
    Client::open(Path::new(host.config["service_file"].as_str().ok_or("HOST_CONFIG_INVALID")?),host.bridge_client.clone(),host.executor.clone(),host.progress.clone())
}
pub(super) fn health(host:&super::Host)->R<Value> {
    let c=client(host)?;
    let session=host.config["session_id"].as_str().ok_or("HOST_CONFIG_INVALID")?;
    let s=c.session(session,host.config["directory"].as_str().ok_or("HOST_CONFIG_INVALID")?)?;
    if waiting_approval(&c,session)? {return Ok(json!({"ready":false,"can_attempt":false,"execution_state":"WAITING_APPROVAL","reason":"HOST_WAITING_APPROVAL"}))}
    let busy=s["time"]["busy"].as_u64().zip(s["time"]["idle"].as_u64()).is_some_and(|(b,i)|b>i)
        || !s["time"]["busy"].is_null()&&s["time"]["idle"].is_null();
    Ok(json!({"ready":true,"can_attempt":true,"execution_state":if busy{"BUSY"}else{"IDLE"},
        "input_delivery":"DURABLE_QUEUE","model_response":"NOT_ATTESTED"}))
}
fn waiting_approval(c:&Client,session:&str)->R<bool> {
    let requests=c.request("GET",&format!("/api/session/{session}/permission"),None)?;
    let requests=requests["data"].as_array().ok_or("HOST_RESPONSE_INVALID")?;
    Ok(!requests.is_empty())
}
pub(super) fn deliver(host:&super::Host,message:&Value)->R<Value> {
    if message["format"]!="peerwork.notification-frame.v1" {return Err("HOST_INPUT_INVALID")}
    let batch=message["batch"].as_str().filter(|s|s.len()==43&&s.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'_'|b'-'))).ok_or("HOST_INPUT_INVALID")?;
    let original=message["message_id"].as_str().filter(|s|!s.is_empty()&&s.len()<=256).ok_or("HOST_INPUT_INVALID")?;
    let session=host.config["session_id"].as_str().ok_or("HOST_CONFIG_INVALID")?;
    let id=format!("msg_{}",sha256_hex(json!([host.destination,original]).to_string().as_bytes()));
    let text=crate::communication_notifications::text(batch);
    let c=client(host)?;
    c.session(session,host.config["directory"].as_str().ok_or("HOST_CONFIG_INVALID")?)?;
    if waiting_approval(&c,session)? {return Err("HOST_WAITING_APPROVAL")}
    // Keep one pending host hint for this batch. Queued hints are not model
    // attention and must not accumulate while the host is busy or awaiting input.
    let pending=c.request("GET",&format!("/api/session/{session}/inbox"),None)?;
    let pending=pending["data"].as_array().ok_or("HOST_RESPONSE_INVALID")?;
    if let Some(existing)=pending.iter().find(|v|v["sessionID"]==session&&v["type"]=="user"&&v["payload"]["text"]==text) {
        let id=existing["id"].as_str().filter(|id|identifier(id,"msg_")).ok_or("HOST_RESPONSE_INVALID")?;
        return Ok(json!({"state":"HOST_ACCEPTED","host_input_id":id,"message_id":original,"execution":"QUEUED","coalesced":true,"model_response":"NOT_ATTESTED"}));
    }
    let payload=json!({"id":id,"text":text,"delivery":"queue","resume":true});
    let admitted=c.request("POST",&format!("/api/session/{session}/prompt"),Some(&payload))?;
    let admitted=admitted.get("data").unwrap_or(&admitted);
    if admitted["id"]!=id || admitted["sessionID"]!=session || admitted["type"]!="user"
        || admitted["delivery"]!="queue" || admitted["payload"]["text"]!=text {return Err("HOST_INPUT_CONFLICT")}
    Ok(json!({"state":"HOST_ACCEPTED","host_input_id":id,"message_id":original,
        "execution":"QUEUED","model_response":"NOT_ATTESTED"}))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{io::{Read,Write},net::TcpListener,sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},time::Duration};
    static SERIAL:Mutex<()>=Mutex::new(());
    #[test]
    fn selected_host_target_reports_session_and_project_without_credentials_or_caller_claim() {
        let target=super::super::target_summary(&json!({"kind":"opencode","session_id":"ses_selected","directory":"/selected/project",
            "service_file":"/private/service.json","password":"private","token_file":"/private/token"}));
        assert_eq!(target,json!({"kind":"opencode","session_id":"ses_selected","directory":"/selected/project","caller_session_match":"NOT_ATTESTED"}));
    }
    #[derive(Default)] struct State {posts:usize,items:Vec<Value>,approval:bool,wrong_session:bool,drop_reply:bool,version:String}
    pub(crate) struct Server {url:String,state:Arc<Mutex<State>>,stop:Arc<AtomicBool>,task:Option<std::thread::JoinHandle<()>>}
    impl Drop for Server {fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);if let Some(task)=self.task.take(){task.join().unwrap();}}}
    impl Server {
        fn new()->Self {
            Self::for_directory(Path::new("/project"))
        }
        pub(crate) fn for_directory(directory:&Path)->Self {
            Self::for_session(directory,"ses_test")
        }
        pub(crate) fn for_session(directory:&Path,session:&str)->Self {
            let directory=directory.to_str().unwrap().to_owned();
            let session=session.to_owned();
            let listener=TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();
            let url=format!("http://{}/",listener.local_addr().unwrap());let state=Arc::new(Mutex::new(State{version:"2.3.0".into(),..Default::default()}));
            let stop=Arc::new(AtomicBool::new(false));let observed=state.clone();let closed=stop.clone();
            let task=std::thread::spawn(move||while !closed.load(Ordering::SeqCst) {
                let Ok((mut socket,_))=listener.accept() else{std::thread::sleep(Duration::from_millis(2));continue};
                socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();let mut raw=Vec::new();let mut buf=[0;1024];
                let (header_end,length)=loop {
                    let n=socket.read(&mut buf).unwrap_or(0);if n==0 {break (0,0)}raw.extend_from_slice(&buf[..n]);
                    if let Some(end)=raw.windows(4).position(|w|w==b"\r\n\r\n") {
                        let h=String::from_utf8_lossy(&raw[..end]);let n=h.lines().find_map(|l|l.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|v|v.parse::<usize>().ok())).unwrap_or(0);break(end+4,n)
                    }
                    assert!(raw.len()<16384);
                };
                if header_end==0 {continue}
                while raw.len()<header_end+length {let n=socket.read(&mut buf).unwrap();assert!(n>0);raw.extend_from_slice(&buf[..n]);}
                let header=String::from_utf8_lossy(&raw[..header_end]);let first=header.lines().next().unwrap();let mut parts=first.split_whitespace();let method=parts.next().unwrap();let path=parts.next().unwrap();
                let mut s=observed.lock().unwrap();let mut status=200;
                let value=if !header.to_ascii_lowercase().contains("authorization: basic b3blbmNvzgu6c2vjcmv0".to_ascii_lowercase().as_str()) {status=401;json!({})}
                else if path=="/api/info" {json!({"pid":99,"version":s.version})}
                else if path==format!("/api/session/{session}/permission") {json!({"data":if s.approval{json!([{"id":"permission"}])}else{json!([])}})}
                else if path==format!("/api/session/{session}/inbox") {json!({"data":s.items})}
                else if path==format!("/api/session/{session}/prompt")&&method=="POST" {
                    s.posts+=1;let payload:Value=serde_json::from_slice(&raw[header_end..header_end+length]).unwrap();
                    let item=if let Some(old)=s.items.iter().find(|v|v["id"]==payload["id"]) {old.clone()}else{let v=json!({"id":payload["id"],"sessionID":session,"type":"user","delivery":payload["delivery"],"payload":{"text":payload["text"]}});s.items.push(v.clone());v};
                    if s.drop_reply {s.drop_reply=false;continue}json!({"data":item})
                }else if path==format!("/api/session/{session}") {json!({"data":{"id":if s.wrong_session{"ses_wrong"}else{&session},"location":{"directory":directory},"time":{"busy":2,"idle":1}}})}
                else if path.starts_with("/api/session?") {json!({"data":[{"id":session,"title":"Original conversation","location":{"directory":directory},"time":{}}],"cursor":{"next":null}})}
                else {status=404;json!({})};
                let body=value.to_string();let response=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());let _=socket.write_all(response.as_bytes());
            });Self{url,state,stop,task:Some(task)}
        }
        pub(crate) fn registration(&self,path:&Path,password:&str) {crate::onboarding_files::replace(path,json!({"url":self.url,"pid":99,"password":password,"version":"2.3.0"}).to_string().as_bytes()).unwrap();}
    }
    fn config(file:&Path)->Value {json!({"kind":"opencode","service_file":file,"session_id":"ses_test","directory":"/project"})}
    fn frame(attempt:u64)->Value {json!({"format":"peerwork.notification-frame.v1","batch":"B".repeat(43),"message_id":format!("attempt-{attempt}"),"incoming":{"text":"PRIVATE_BODY_MUST_NOT_ENTER_CONTEXT"}})}
    #[tokio::test(flavor="multi_thread",worker_threads=2)]
    async fn opencode_lost_response_and_reminders_coalesce_one_pending_compact_input() {
        let executor=tokio::runtime::Handle::current();tokio::task::spawn_blocking(move||{
            let _serial=SERIAL.lock().unwrap();
            let root=crate::test_support::protected_test_dir();let file=root.path().join("service.json");let server=Server::new();server.registration(&file,"secret");
            server.state.lock().unwrap().drop_reply=true;
            let mut host=super::super::Host::open(config(&file),executor).unwrap();
            assert!(host.deliver(&json!({}),&frame(1)).is_err());
            let result=host.deliver(&json!({}),&frame(1)).unwrap();assert_eq!(result["state"],"HOST_ACCEPTED");assert_eq!(result["coalesced"],true);
            for attempt in 2..8 {assert_eq!(host.deliver(&json!({}),&frame(attempt)).unwrap()["coalesced"],true);}
            let s=server.state.lock().unwrap();assert_eq!(s.posts,1);assert_eq!(s.items.len(),1);assert!(!s.items[0].to_string().contains("PRIVATE_BODY"));
        }).await.unwrap();
    }
    #[tokio::test(flavor="multi_thread",worker_threads=2)]
    async fn opencode_approval_mismatch_and_transport_rotation_preserve_the_destination() {
        let executor=tokio::runtime::Handle::current();tokio::task::spawn_blocking(move||{
            let _serial=SERIAL.lock().unwrap();
            let root=crate::test_support::protected_test_dir();let file=root.path().join("service.json");let first=Server::new();first.registration(&file,"secret");
            let mut host=super::super::Host::open(config(&file),executor).unwrap();let destination=host.destination.clone();
            first.state.lock().unwrap().approval=true;
            assert_eq!(host.health(&json!({})).unwrap()["execution_state"],"WAITING_APPROVAL");
            assert_eq!(host.deliver(&json!({}),&frame(1)).unwrap_err(),"HOST_WAITING_APPROVAL");assert_eq!(first.state.lock().unwrap().posts,0);
            first.state.lock().unwrap().approval=false;first.state.lock().unwrap().wrong_session=true;
            assert_eq!(host.deliver(&json!({}),&frame(1)).unwrap_err(),"HOST_BINDING_MISMATCH");
            let second=Server::new();second.registration(&file,"secret");host.reconnect().unwrap();
            assert_eq!(host.destination,destination);assert_eq!(host.health(&json!({})).unwrap()["execution_state"],"BUSY");
            assert_eq!(host.deliver(&json!({}),&frame(1)).unwrap()["state"],"HOST_ACCEPTED");
            second.registration(&file,"wrong");assert_eq!(host.health(&json!({})).unwrap_err(),"HOST_AUTHENTICATION_FAILED");
        }).await.unwrap();
    }
    #[test]
    fn opencode_destination_is_transport_independent_and_rejects_unselected_sessions() {
        let mut c=config(Path::new("/original/service.json"));let first=destination(&c).unwrap();
        c["session_id"]=json!("../other");assert_eq!(destination(&c).unwrap_err(),"OPENCODE_SESSION_SELECTION_REQUIRED");
        c=config(Path::new("/other/service.json"));assert_ne!(destination(&c).unwrap(),first);
    }
}
