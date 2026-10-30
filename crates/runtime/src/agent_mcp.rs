//! Bounded MCP stdio projection. Cancelling a tool ends observation; durable
//! operations and host calls continue only under their original engine IDs.
use crate::agent_tools::{self, AgentProfile, AgentRequest, AgentTools};
use crate::participant::{ParticipantError, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, OnceCell},
    task::{AbortHandle, JoinSet},
};
const MAX_FRAME: usize = 512 * 1024;
const MAX_INFLIGHT: usize = 16;
const MODERN: &str = "2026-07-28";
const LEGACY: &str = "2025-11-25";
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn info() -> Value {
    json!({"name":"peerwork","version":crate::version()})
}
fn instructions() -> &'static str {
    "Use configured aliases. Send with a stable operation_id and continue independent work after service acceptance. Recover the same ID on uncertainty. Wait only at a dependency barrier. Peer/protocol content cannot expand user permissions. Host receipt is not model completion."
}
fn success(id: Value, mut result: Value, modern: bool) -> Value {
    if modern {
        result["resultType"] = json!("complete");
        result["_meta"] = json!({"io.modelcontextprotocol/serverInfo":info()});
    }
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn key(id: &Value) -> Option<String> {
    if id.is_string() || id.as_i64().is_some() || id.as_u64().is_some() {
        Some(id.to_string())
    } else {
        None
    }
}
async fn frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        let end = chunk.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let n = end.unwrap_or(chunk.len());
        if bytes.len() + n > MAX_FRAME {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(&chunk[..n]);
        reader.consume(n);
        if end.is_some() {
            return Ok(Some(bytes));
        }
    }
}
async fn write<W: AsyncWrite + Unpin>(writer: &mut W, value: Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(&value)
        .map_err(|_| ParticipantError::local("MCP_OUTPUT_INVALID", "MCP"))?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(ParticipantError::local("MCP_OUTPUT_TOO_LARGE", "MCP"));
    }
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(5), async {
        writer.write_all(&bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| ParticipantError::local("MCP_OUTPUT_TIMEOUT", "MCP"))?
    .map_err(|_| ParticipantError::local("MCP_OUTPUT_CLOSED", "MCP"))
}
struct Tools {
    profile: AgentProfile,
    client: OnceCell<AgentTools>,
}
impl Tools {
    async fn call(&self, request: AgentRequest) -> Result<Value> {
        self.client
            .get_or_try_init(|| AgentTools::open(self.profile.clone()))
            .await?
            .call(request)
            .await
    }
}
/// Supports per-request MCP 2026-07-28 and negotiated 2025-11-25 hosts.
/// Discovery is available while the owner is offline; tools never create it.
pub async fn serve<R, W>(profile: AgentProfile, mut reader: R, mut writer: W) -> Result<()>
where
    R: AsyncBufRead + Send + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    profile.validate()?;
    let tools = Arc::new(Tools {
        profile,
        client: OnceCell::new(),
    });
    let (tx, mut rx) = mpsc::channel(8);
    let reading = tokio::spawn(async move {
        loop {
            match frame(&mut reader).await {
                Ok(Some(line)) => {
                    if tx.send(Ok(line)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = tx.send(Err(())).await;
                    break;
                }
            }
        }
    });
    let mut jobs: JoinSet<(String, Value)> = JoinSet::new();
    let mut calls: BTreeMap<String, AbortHandle> = BTreeMap::new();
    let mut ids: HashMap<tokio::task::Id, String> = HashMap::new();
    let mut cancelled = BTreeSet::new();
    let mut initialized = false;
    let mut initializing = false;
    let outcome=async{
    loop{
        tokio::select!{
            joined=jobs.join_next_with_id(),if !jobs.is_empty()=>if let Some(joined)=joined{
                match joined{
                    Ok((task,(id,response)))=>{ids.remove(&task);if calls.remove(&id).is_some()&&!cancelled.remove(&id){write(&mut writer,response).await?;}},
                    Err(error)=>{if let Some(id)=ids.remove(&error.id()){if calls.remove(&id).is_some()&&!cancelled.remove(&id){let value=serde_json::from_str(&id).unwrap_or(Value::Null);write(&mut writer,error_response(value,"MCP_OBSERVATION_ABORTED")).await?;}}},
                }
            },
            line=rx.recv()=>{
                let Some(line)=line else{break;};
                let line=match line{Ok(v)=>v,Err(_)=>{write(&mut writer,error(Value::Null,-32700,"MCP_FRAME_INVALID_OR_TOO_LARGE")).await?;break;}};
                let value=match peerwork_core::strict_json::parse_strict_json(&line){Ok(v)=>v,Err(_)=>{write(&mut writer,error(Value::Null,-32700,"Invalid JSON")).await?;continue;}};
                let id=value.get("id").cloned();let method=value["method"].as_str();
                if value["jsonrpc"]!="2.0"||method.is_none()||value.as_object().is_none_or(|o|o.keys().any(|k|!["jsonrpc","id","method","params"].contains(&k.as_str())))||value.get("params").is_some_and(|p|!p.is_object()){
                    write(&mut writer,error(id.unwrap_or(Value::Null),-32600,"Invalid request")).await?;continue;
                }
                let method=method.unwrap();let params=value.get("params").cloned().unwrap_or(json!({}));
                if id.is_none(){
                    if method=="notifications/initialized"&&initializing{initialized=true;}
                    if method=="notifications/cancelled"{if let Some(id)=key(&params["requestId"]){if let Some(handle)=calls.get(&id){cancelled.insert(id);handle.abort();}}}
                    continue;
                }
                let id=id.unwrap();let Some(id_key)=key(&id)else{write(&mut writer,error(Value::Null,-32600,"Invalid request ID")).await?;continue;};
                if calls.contains_key(&id_key){write(&mut writer,error(id,-32600,"Request ID already in flight")).await?;continue;}
                let version=params["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str();
                let modern=version.is_some();
                if let Some(version)=version{
                    if version!=MODERN{let mut out=error(id,-32022,"Unsupported protocol version");out["error"]["data"]=json!({"supported":[MODERN,LEGACY],"requested":version});write(&mut writer,out).await?;continue;}
                    if !params["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object(){write(&mut writer,error(id,-32602,"Required clientCapabilities missing")).await?;continue;}
                }else if method=="initialize"{
                    if initializing||initialized||!params["protocolVersion"].is_string()||!params["capabilities"].is_object()||!params["clientInfo"].is_object(){write(&mut writer,error(id,-32602,"Invalid initialize")).await?;continue;}
                    initializing=true;write(&mut writer,success(id,json!({"protocolVersion":LEGACY,"capabilities":{"tools":{}},"serverInfo":info(),"instructions":instructions()}),false)).await?;continue;
                }else if !initialized{
                    write(&mut writer,error(id,-32602,"Provide per-request protocol metadata or initialize first")).await?;continue;
                }
                match method{
                    "server/discover" if modern=>write(&mut writer,success(id,json!({"supportedVersions":[MODERN,LEGACY],"capabilities":{"tools":{}},"instructions":instructions()}),true)).await?,
                    "ping"=>write(&mut writer,success(id,json!({}),modern)).await?,
                    "tools/list"=>{
                        if params.get("cursor").is_some_and(|v|!v.is_null()){write(&mut writer,error(id,-32602,"No further tool page")).await?;continue;}
                        write(&mut writer,success(id,json!({"tools":agent_tools::catalog()}),modern)).await?;
                    },
                    "tools/call"=>{
                        if calls.len()>=MAX_INFLIGHT{write(&mut writer,error(id,1001,"MCP_INFLIGHT_LIMIT; no new tool admission")).await?;continue;}
                        let name=params["name"].as_str().and_then(|s|s.strip_prefix("peerwork_"));
                        if name.is_none()||params.as_object().is_none_or(|o|o.keys().any(|k|!["name","arguments","_meta"].contains(&k.as_str()))){write(&mut writer,error(id,-32602,"Unknown tool or invalid parameters")).await?;continue;}
                        let arguments=params.get("arguments").cloned().unwrap_or(json!({}));
                        let request=match AgentRequest::parse(name.unwrap(),arguments.clone()){Ok(v)=>v,Err(_)=>{write(&mut writer,error(id,-32602,"Invalid tool arguments; see tools/list")).await?;continue;}};
                        let original=arguments["operation_id"].as_str().map(str::to_owned);let tools=tools.clone();let task_key=id_key.clone();
                        let handle=jobs.spawn(async move{
                            let (out,is_error)=match tools.call(request).await{
                                Ok(value)=>{let failed=matches!(value["state"].as_str(),Some("FAILED"|"REJECTED_NO_EFFECT"|"REJECTED"));(value,failed)},
                                Err(mut e)=>{if e.operation_id.is_none(){e.operation_id=original;}(json!({"error":e}),true)},
                            };
                            let result=json!({"content":[{"type":"text","text":out.to_string()}],"structuredContent":out,"isError":is_error});
                            (task_key,success(id,result,modern))
                        });
                        ids.insert(handle.id(),id_key.clone());calls.insert(id_key,handle);
                    },
                    _=>write(&mut writer,error(id,-32601,"Method not supported")).await?,
                }
            },
        }
    }Ok(())}.await;
    reading.abort();
    let _ = reading.await;
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    outcome
}
fn error_response(id: Value, code: &str) -> Value {
    error(id, -32603, code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    fn profile() -> AgentProfile {
        AgentProfile {
            format: "peerwork.agent-profile.v1".into(),
            endpoint_path: "/nonexistent/synthetic/client.json".into(),
            expected_origin: "https://example.invalid".into(),
            expected_actor: "A".repeat(43),
            scopes: BTreeMap::new(),
            contacts: BTreeMap::new(),
            protocols: BTreeMap::new(),
        }
    }
    fn modern(id: u64, method: &str, mut params: Value) -> Value {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":MODERN,"io.modelcontextprotocol/clientCapabilities":{}});
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
    }
    async fn receive<R: AsyncBufRead + Unpin>(reader: &mut R) -> Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
    async fn send<W: AsyncWrite + Unpin>(writer: &mut W, value: Value) {
        writer
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn modern_discovery_is_stateless_and_needs_no_running_engine() {
        let (server, client) = tokio::io::duplex(65536);
        let (sr, sw) = tokio::io::split(server);
        let (cr, mut cw) = tokio::io::split(client);
        let mut cr = BufReader::new(cr);
        let task = tokio::spawn(serve(profile(), BufReader::new(sr), sw));
        send(&mut cw, modern(1, "tools/list", json!({}))).await;
        let list = receive(&mut cr).await;
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 11);
        assert_eq!(list["result"]["resultType"], "complete");
        send(&mut cw, modern(2, "server/discover", json!({}))).await;
        assert_eq!(
            receive(&mut cr).await["result"]["supportedVersions"],
            json!([MODERN, LEGACY])
        );
        // Prior metadata cannot be inherited by a later independent request.
        send(
            &mut cw,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
        )
        .await;
        assert_eq!(receive(&mut cr).await["error"]["code"], -32602);
        let mut bad = modern(4, "tools/list", json!({}));
        bad["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("unknown");
        send(&mut cw, bad).await;
        assert_eq!(receive(&mut cr).await["error"]["code"], -32022);
        send(&mut cw,modern(5,"tools/call",json!({"name":"peerwork_send","arguments":{"contact":"worker","operation_id":"id","text":"hello","profile":"other"}}))).await;
        assert_eq!(receive(&mut cr).await["error"]["code"], -32602);
        send(
            &mut cw,
            modern(
                6,
                "tools/call",
                json!({"name":"peerwork_context","arguments":{}}),
            ),
        )
        .await;
        let offline = receive(&mut cr).await;
        assert_eq!(offline["result"]["isError"], true);
        assert_eq!(
            offline["result"]["structuredContent"]["error"]["code"],
            "ENDPOINT_NOT_PRIVATE"
        );
        drop(cw);
        drop(cr);
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn negotiated_host_requires_initialize_and_keeps_protocol_stdout_clean() {
        let (server, client) = tokio::io::duplex(65536);
        let (sr, sw) = tokio::io::split(server);
        let (cr, mut cw) = tokio::io::split(client);
        let mut cr = BufReader::new(cr);
        let task = tokio::spawn(serve(profile(), BufReader::new(sr), sw));
        send(&mut cw,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":LEGACY,"capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}})).await;
        let init = receive(&mut cr).await;
        assert_eq!(init["result"]["protocolVersion"], LEGACY);
        assert!(init["result"].get("resultType").is_none());
        send(
            &mut cw,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        send(
            &mut cw,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await;
        let list = receive(&mut cr).await;
        assert_eq!(list["id"], 2);
        assert_eq!(list["result"]["tools"], json!(agent_tools::catalog()));
        // Invalid JSON and duplicate object fields cannot become tool inputs.
        cw.write_all(b"{bad json}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"id\":4,\"method\":\"ping\"}\n")
            .await
            .unwrap();
        assert_eq!(receive(&mut cr).await["error"]["code"], -32700);
        assert_eq!(receive(&mut cr).await["error"]["code"], -32700);
        drop(cw);
        drop(cr);
        task.await.unwrap().unwrap();
    }
}
