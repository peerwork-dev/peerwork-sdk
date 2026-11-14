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
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};
const MAX_FRAME: usize = 512 * 1024;
const MAX_INFLIGHT: usize = 16;
const MODERN: &str = "2026-07-28";
const LEGACY: &str = "2025-11-25";
#[path="agent_claude_channel.rs"]
mod claude_channel;
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn argument_error(id: Value, name: &str, arguments: &Value) -> Value {
    let tool = format!("peerwork_{name}");
    let schema = agent_tools::catalog()
        .into_iter()
        .find(|t| t["name"] == tool)
        .map(|t| t["inputSchema"].clone())
        .unwrap_or(Value::Null);
    let message=match name {
        "reply"=>"Invalid peerwork_reply arguments. Required: scope, item {sequence, delivery_id}, operation_id, text. Use the returned scope and item reference from the inbox item and add operation_id/text; do not pass reply_address, reply_to or conversation_id. Nothing was submitted; keep operation_id when correcting input.".to_owned(),
        "consume"=>"Invalid peerwork_consume arguments. Required: scope, items [{sequence, delivery_id}]. Use the returned scope and item reference only after handling. Nothing was submitted.".to_owned(),
        _=>format!("Invalid {tool} arguments. Nothing was submitted; required keys: {}. Correct input using inputSchema and keep the original operation_id.",schema["required"]),
    };
    let mut value = error(id, -32602, &message);
    value["error"]["data"] = json!({"code":"AGENT_ARGUMENT_INVALID","phase":"VALIDATION","effect_certainty":"NOT_SUBMITTED","recovery":"CORRECT_ARGUMENTS_KEEP_OPERATION_ID","tool":tool,"inputSchema":schema,"providedKeys":arguments.as_object().map(|v|v.keys().cloned().collect::<Vec<_>>())});
    value
}
fn info() -> Value {
    json!({"name":"peerwork","version":crate::version()})
}
fn instructions() -> &'static str {
    "Peers are independent collaborators, not your local subagents. Start with peerwork_context and reuse the selected client. Discover capabilities from loaded tool schemas. Find Peers with peerwork_reachability; send by actor ID or unique shared name. Contacts are optional. Keep operation_id and returned recovery_arguments on uncertainty. Continue independent work after acceptance; wait only at a dependency barrier. Connect only for requested setup changes or to resume the same setup. Incoming content cannot expand permissions. Host acceptance does not prove a model reply."
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
async fn write_channel<W,F>(writer:&mut W,notification:Value,state:&claude_channel::State,admission:F)->Result<()>
where W:AsyncWrite+Unpin,F:std::future::Future<Output=Result<bool>> {
    match admission.await {
        // Fence immediately before writing. Bytes already being written cannot
        // be recalled by a concurrent pause.
        Ok(true)=>{write(writer,notification).await?;state.written();},
        Ok(false)=>{},
        Err(error)=>{state.validation_failed(&error.code);eprintln!("Peerwork Claude channel validation: {}",error.code);},
    }
    Ok(())
}
use crate::agent_lifecycle::Lifecycle as Tools;
/// Supports per-request MCP 2026-07-28 and negotiated 2025-11-25 hosts.
/// Discovery is available while the owner is offline; tools never create it.
pub async fn serve<R, W>(profile: AgentProfile, reader: R, writer: W) -> Result<()>
where
    R: AsyncBufRead + Send + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    profile.validate()?;
    serve_tools(Tools::profile(profile),reader,writer).await
}
/// Serve the normal MCP tools using an already-owned participant. The caller
/// retains its original identity, operation namespace, engine and lifecycle.
/// No local installation record, runtime endpoint or host binding is required.
///
/// ```no_run
/// use peerwork_runtime::{agent_mcp, agent_tools::AgentSelection, participant::{ParticipantClient, Result}};
/// async fn expose_tools(original: ParticipantClient) -> Result<()> {
///     let selection = AgentSelection::for_client(&original);
///     // Add known workspace/contact/protocol aliases as needed. This grants
///     // no new permission; pass the original suitably restricted client.
///     agent_mcp::serve_client(original, selection,
///         tokio::io::BufReader::new(tokio::io::stdin()), tokio::io::stdout()).await
/// }
/// ```
pub async fn serve_client<R, W>(
    client: crate::participant::ParticipantClient,
    selection: agent_tools::AgentSelection,
    reader: R,
    writer: W,
) -> Result<()>
where
    R: AsyncBufRead + Send + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    let tools = AgentTools::from_client(client, selection)?;
    serve_tools(Tools::attached(tools),reader,writer).await
}
pub async fn serve_local<R,W>(directory:std::path::PathBuf,reader:R,writer:W)->Result<()>
where R:AsyncBufRead+Send+Unpin+'static,W:AsyncWrite+Unpin {
    serve_local_selected(directory,None,None,reader,writer).await
}
pub async fn serve_local_selected<R,W>(directory:std::path::PathBuf,handle:Option<String>,workspace:Option<String>,reader:R,writer:W)->Result<()>
where R:AsyncBufRead+Send+Unpin+'static,W:AsyncWrite+Unpin {
    // The directory itself was explicitly selected by the host owner. Missing
    // identity handles expose discovery only, never secret scanning/bootstrap.
    if directory.exists(){crate::participant_connect::Connect::inspect(&directory)?;}
    else{drop(crate::participant_connect::Connect::open(&directory)?);}
    serve_tools(Tools::local(directory,handle,workspace),reader,writer).await
}
/// Claude Code's opt-in Channels transport over the same native tools and inbox.
/// A successful notification write is never recorded as host acceptance.
pub async fn serve_claude<R,W>(profile:AgentProfile,reader:R,writer:W)->Result<()>
where R:AsyncBufRead+Send+Unpin+'static,W:AsyncWrite+Unpin {
    profile.validate()?;
    serve_tools_mode(Tools::profile(profile),reader,writer,true).await
}
pub async fn serve_claude_local<R,W>(directory:std::path::PathBuf,handle:Option<String>,workspace:Option<String>,reader:R,writer:W)->Result<()>
where R:AsyncBufRead+Send+Unpin+'static,W:AsyncWrite+Unpin {
    if directory.exists(){crate::participant_connect::Connect::inspect(&directory)?;}else{drop(crate::participant_connect::Connect::open(&directory)?);}
    serve_tools_mode(Tools::local(directory,handle,workspace),reader,writer,true).await
}
async fn serve_tools<R,W>(tools:Tools,reader:R,writer:W)->Result<()>
where R:AsyncBufRead+Send+Unpin+'static,W:AsyncWrite+Unpin {
    serve_tools_mode(tools,reader,writer,false).await
}
async fn serve_tools_mode<R,W>(tools:Tools,mut reader:R,mut writer:W,claude:bool)->Result<()>
where R:AsyncBufRead+Send+Unpin+'static,W:AsyncWrite+Unpin {
    let tools = Arc::new(tools);
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
    let mut channel_task:Option<tokio::task::JoinHandle<()>>=None;
    let (channel_tx,mut channel_rx)=mpsc::channel::<Value>(8);
    let channel_state=claude_channel::State::default();
    let capabilities=if claude {json!({"tools":{},"experimental":{"claude/channel":{}}})}else{json!({"tools":{}})};
    let guidance=if claude {format!("{} {}",instructions(),claude_channel::INSTRUCTIONS)}else{instructions().to_owned()};
    let outcome=async{
    loop{
        tokio::select!{
            notification=channel_rx.recv(),if channel_task.is_some()=>if let Some(notification)=notification {
                let meta=&notification["params"]["meta"];
                let allowed=match (meta["batch"].as_str(),meta["revision"].as_u64()) {
                    (Some(batch),Some(revision))=>tools.notification_allowed(batch,revision).await,
                    _=>Err(ParticipantError::local("CLAUDE_CHANNEL_BATCH_INVALID","CLAUDE_CHANNEL")),
                };
                write_channel(&mut writer,notification,&channel_state,async {allowed}).await?;
            },
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
                    if method=="notifications/initialized"&&initializing{
                        initialized=true;
                        if claude && channel_task.is_none(){channel_task=Some(tokio::spawn(claude_channel::watch(tools.clone(),channel_tx.clone(),channel_state.clone())));}
                    }
                    if method=="notifications/cancelled"{if let Some(id)=key(&params["requestId"]){if let Some(handle)=calls.get(&id){cancelled.insert(id);handle.abort();}}}
                    continue;
                }
                let id=id.unwrap();let Some(id_key)=key(&id)else{write(&mut writer,error(Value::Null,-32600,"Invalid request ID")).await?;continue;};
                if calls.contains_key(&id_key){write(&mut writer,error(id,-32600,"Request ID already in flight")).await?;continue;}
                // Claude Channels use the initialized stdio protocol. Match the
                // official Channel SDK's unsupported-method probe response so
                // the host selects that handshake without a global override.
                if claude && method=="server/discover"{
                    write(&mut writer,error(id,-32601,"Method not found")).await?;continue;
                }
                let version=params["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str();
                let modern=version.is_some();
                if let Some(version)=version{
                    if claude||version!=MODERN{let mut out=error(id,-32022,"Unsupported protocol version");out["error"]["data"]=json!({"supported":if claude{json!([LEGACY])}else{json!([MODERN,LEGACY])},"requested":version});write(&mut writer,out).await?;continue;}
                    if !params["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object(){write(&mut writer,error(id,-32602,"Required clientCapabilities missing")).await?;continue;}
                }else if method=="initialize"{
                    if initializing||initialized||!params["protocolVersion"].is_string()||!params["capabilities"].is_object()||!params["clientInfo"].is_object(){write(&mut writer,error(id,-32602,"Invalid initialize")).await?;continue;}
                    let requested=params["protocolVersion"].as_str().unwrap();
                    let negotiated=if ["2025-03-26","2025-06-18",LEGACY].contains(&requested){requested}else{LEGACY};
                    initializing=true;write(&mut writer,success(id,json!({"protocolVersion":negotiated,"capabilities":capabilities,"serverInfo":info(),"instructions":guidance}),false)).await?;continue;
                }else if !initialized{
                    write(&mut writer,error(id,-32602,"Provide per-request protocol metadata or initialize first")).await?;continue;
                }
                match method{
                    "server/discover" if modern=>{
                        write(&mut writer,success(id,json!({"supportedVersions":[MODERN,LEGACY],"capabilities":capabilities,"instructions":guidance}),true)).await?;
                    },
                    "ping"=>write(&mut writer,success(id,json!({}),modern)).await?,
                    "tools/list"=>{
                        if params.get("cursor").is_some_and(|v|!v.is_null()){write(&mut writer,error(id,-32602,"No further tool page")).await?;continue;}
                        match tools.catalog(){Ok(catalog)=>write(&mut writer,success(id,json!({"tools":catalog}),modern)).await?,Err(e)=>write(&mut writer,error_response(id,&e.code)).await?};
                    },
                    "tools/call"=>{
                        if calls.len()>=MAX_INFLIGHT{write(&mut writer,error(id,1001,"MCP_INFLIGHT_LIMIT; no new tool admission")).await?;continue;}
                        let name=params["name"].as_str().and_then(|s|s.strip_prefix("peerwork_"));
                        if name.is_none()||params.as_object().is_none_or(|o|o.keys().any(|k|!["name","arguments","_meta"].contains(&k.as_str()))){write(&mut writer,error(id,-32602,"Unknown tool or invalid parameters")).await?;continue;}
                        let arguments=params.get("arguments").cloned().unwrap_or(json!({}));
                        let request=match AgentRequest::parse(name.unwrap(),arguments.clone()){Ok(v)=>v,Err(_)=>{write(&mut writer,argument_error(id,name.unwrap(),&arguments)).await?;continue;}};
                        let context=claude&&matches!(request,AgentRequest::Context);
                        let consume=claude&&matches!(request,AgentRequest::Consume{..});
                        let channel_state=channel_state.clone();
                        let original=arguments["operation_id"].as_str().map(str::to_owned);let tools=tools.clone();let task_key=id_key.clone();
                        let handle=jobs.spawn(async move{
                            let (out,is_error)=match tools.call(request).await{
                                Ok(mut value)=>{if context{value["host_channel"]=channel_state.status();}let failed=matches!(value["state"].as_str(),Some("FAILED"|"REJECTED_NO_EFFECT"|"REJECTED"));if consume&&!failed{channel_state.consumed();}(value,failed)},
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
    if let Some(task)=channel_task {task.abort();let _=task.await;}
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
    #[tokio::test]
    async fn queued_channel_notice_is_suppressed_when_final_admission_is_paused_or_stale() {
        let state=super::claude_channel::State::default();let mut wire=Vec::new();
        let notice=serde_json::json!({"method":"notifications/claude/channel","params":{"meta":{"batch":"queued","revision":1}}});
        super::write_channel(&mut wire,notice.clone(),&state,async {Ok(false)}).await.unwrap();
        assert!(wire.is_empty());assert_eq!(state.status()["notifications_written"],0);
        super::write_channel(&mut wire,notice.clone(),&state,async {Err(crate::participant::ParticipantError::local("SYNTHETIC_VALIDATION_UNAVAILABLE","TEST"))}).await.unwrap();
        assert!(wire.is_empty());assert_eq!(state.status()["validation_error"],"SYNTHETIC_VALIDATION_UNAVAILABLE");
        super::write_channel(&mut wire,notice,&state,async {Ok(true)}).await.unwrap();
        assert!(!wire.is_empty());assert_eq!(state.status()["notifications_written"],1);
    }
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    #[tokio::test]
    async fn ambiguous_unconfigured_frontend_still_lists_tools_and_identity_choices() {
        let root=crate::test_support::protected_test_dir();let directory=root.path().join("local");
        drop(crate::participant_connect::Connect::open(&directory).unwrap());
        let owner=crate::secure_state::SecureStateStore::open(&directory.join("connect.state")).unwrap();
        let registrations=json!({"participants":{
            "a":{"actor_id":"A".repeat(43),"origin":"https://example.invalid/","endpoint_path":root.path().join("a.json")},
            "b":{"actor_id":"B".repeat(43),"origin":"https://example.invalid/","endpoint_path":root.path().join("b.json")}},
            "setups":{},"active":null});
        owner.write_exact(&serde_json::to_vec(&registrations).unwrap()).unwrap();drop(owner);
        let tools=Tools::local(directory,None,None);
        let catalog=tools.catalog().unwrap();assert!(catalog.iter().any(|v|v["name"]=="peerwork_connect"));
        let context=tools.call(AgentRequest::Context).await.unwrap();assert_eq!(context["participants"].as_array().unwrap().len(),2);
        let request=AgentRequest::parse("connect",json!({"request":{"workspace_id":"W".repeat(43)}})).unwrap();
        let result=tools.call(request).await.unwrap();assert_eq!(result["blocker"]["code"],"IDENTITY_SELECTION_REQUIRED");
        assert_eq!(result["discovery"]["candidates"].as_array().unwrap().len(),2);
        assert!(!result.to_string().contains(&root.path().to_string_lossy().to_string()));
        let bad=crate::participant_connect::Connect::open(tools.local.as_ref().unwrap()).unwrap()
            .connect_selected(serde_json::from_value(json!({"participant":"b","workspace_id":"W".repeat(43)})).unwrap(),Some("a"),None).await.unwrap_err();
        assert_eq!(bad.code,"FRONTEND_IDENTITY_PIN_MISMATCH");
    }
    fn profile() -> AgentProfile {
        AgentProfile { recovery_views:Default::default(), protocol_views: Default::default(), management_views: Default::default(),
            workspaces: Default::default(), directory_endpoints: Default::default(), protocol_endpoints: Default::default(),
            send_scopes: Default::default(), receive_endpoint_path: None,
            format: "peerwork.agent-profile.v1".into(),
            endpoint_path: std::env::current_dir().unwrap().join("__peerwork_nonexistent_synthetic__/client.json"),
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
    async fn claude_negotiates_mcp_and_exposes_tools_without_claiming_a_channel_is_accepted() {
        let root=crate::test_support::protected_test_dir();let directory=root.path().join("local");
        drop(crate::participant_connect::Connect::open(&directory).unwrap());
        let (server,client)=tokio::io::duplex(65536);let (sr,sw)=tokio::io::split(server);let (cr,mut cw)=tokio::io::split(client);let mut cr=BufReader::new(cr);
        let task=tokio::spawn(serve_claude_local(directory,None,None,BufReader::new(sr),sw));
        send(&mut cw,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code-qualification","version":"synthetic"}}})).await;
        let init=receive(&mut cr).await;assert_eq!(init["result"]["protocolVersion"],"2025-03-26");
        assert_eq!(init["result"]["capabilities"]["experimental"]["claude/channel"],json!({}));
        assert!(init["result"]["capabilities"]["experimental"].get("claude/channel/permission").is_none());
        send(&mut cw,json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await;
        send(&mut cw,json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await;
        assert_eq!(receive(&mut cr).await["result"]["tools"].as_array().unwrap().len(),2);
        send(&mut cw,json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"peerwork_context","arguments":{}}})).await;
        let context=receive(&mut cr).await;assert_eq!(context["result"]["structuredContent"]["state"],"NOT_CONFIGURED");
        assert_eq!(context["result"]["structuredContent"]["host_channel"]["host_acceptance"],"NOT_ATTESTED");
        drop(cw);drop(cr);assert!(tokio::time::timeout(Duration::from_secs(2),task).await.unwrap().unwrap().is_ok());
    }
    #[tokio::test]
    async fn claude_probe_falls_back_then_tools_and_channel_share_the_initialized_connection() {
        let root=crate::test_support::protected_test_dir();let directory=root.path().join("local");
        drop(crate::participant_connect::Connect::open(&directory).unwrap());
        let (server,client)=tokio::io::duplex(65536);let (sr,sw)=tokio::io::split(server);let (cr,mut cw)=tokio::io::split(client);let mut cr=BufReader::new(cr);
        let task=tokio::spawn(serve_claude_local(directory,None,None,BufReader::new(sr),sw));
        // The modern probe must not advertise a Channel the host cannot use.
        send(&mut cw,modern(1,"server/discover",json!({}))).await;
        let probe=receive(&mut cr).await;
        assert_eq!(probe["error"]["code"],-32601);assert!(probe.get("result").is_none());
        send(&mut cw,modern(2,"tools/call",json!({"name":"peerwork_context","arguments":{}}))).await;
        let rejected=receive(&mut cr).await;
        assert_eq!(rejected["error"]["code"],-32022);assert_eq!(rejected["error"]["data"]["supported"],json!([LEGACY]));
        send(&mut cw,json!({"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":MODERN,"capabilities":{},"clientInfo":{"name":"claude-code-qualification","version":"synthetic"}}})).await;
        let init=receive(&mut cr).await;
        assert_eq!(init["result"]["protocolVersion"],LEGACY);
        assert_eq!(init["result"]["capabilities"]["experimental"]["claude/channel"],json!({}));
        send(&mut cw,json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}})).await;
        assert_eq!(receive(&mut cr).await["error"]["code"],-32602);
        send(&mut cw,json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await;
        send(&mut cw,json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}})).await;
        assert_eq!(receive(&mut cr).await["result"]["tools"].as_array().unwrap().len(),2);
        send(&mut cw,json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"peerwork_context","arguments":{}}})).await;
        let context=receive(&mut cr).await;
        assert_eq!(context["result"]["structuredContent"]["host_channel"]["transport"],"MCP_STDIO_CHANNEL");
        assert_eq!(context["result"]["structuredContent"]["host_channel"]["notifications_written"],0);
        assert_eq!(context["result"]["structuredContent"]["host_channel"]["host_acceptance"],"NOT_ATTESTED");
        drop(cw);drop(cr);assert!(tokio::time::timeout(Duration::from_secs(2),task).await.unwrap().unwrap().is_ok());
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
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), agent_tools::catalog().len());
        assert!(list["result"]["tools"].as_array().unwrap().iter().any(|v| v["name"] == "peerwork_connect"));
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
    async fn unconfigured_mcp_exposes_connect_without_a_profile_or_identity() {
        let temp=crate::test_support::protected_test_dir();
        let directory=temp.path().join("local");
        let _setup_writer=crate::participant_connect::Connect::open(&directory).unwrap();
        let (server,client)=tokio::io::duplex(65536);
        let (sr,sw)=tokio::io::split(server);let(cr,mut cw)=tokio::io::split(client);
        let mut cr=BufReader::new(cr);
        let task=tokio::spawn(serve_local(directory.clone(),BufReader::new(sr),sw));
        send(&mut cw,modern(1,"tools/list",json!({}))).await;
        let list=receive(&mut cr).await;
        let names:Vec<_>=list["result"]["tools"].as_array().unwrap().iter().map(|v|v["name"].as_str().unwrap()).collect();
        assert_eq!(names,vec!["peerwork_context","peerwork_connect"]);
        send(&mut cw,modern(2,"tools/call",json!({"name":"peerwork_context","arguments":{}}))).await;
        let context=receive(&mut cr).await;
        assert_eq!(context["result"]["structuredContent"]["state"],"NOT_CONFIGURED");
        send(&mut cw,modern(3,"tools/call",json!({"name":"peerwork_connect","arguments":{"request":{"setup_id":"first","participant":"existing","workspace_id":"W".repeat(43),"receive":true}}}))).await;
        assert_eq!(receive(&mut cr).await["result"]["structuredContent"]["blocker"]["code"],"LOCAL_SELECTION_REQUIRED");
        send(&mut cw,modern(4,"tools/call",json!({"name":"peerwork_connect","arguments":{"request":{"setup_id":"first","participant":"existing","workspace_id":"W".repeat(43),"receive":true,"identity_path":"/unselected"}}}))).await;
        assert_eq!(receive(&mut cr).await["error"]["code"],-32602);
        assert!(!directory.join("connect.state").exists(),"discovery cannot create a trusted identity binding");
        drop(cw);drop(cr);task.await.unwrap().unwrap();
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
        let tools = list["result"]["tools"].as_array().unwrap();
        let expected: Vec<_> = agent_tools::catalog().into_iter().collect();
        assert_eq!(tools, &expected);
        assert!(tools.iter().all(|tool| tool["_meta"]["antigravity/alwaysLoad"] == true));
        // Setup tools remain visible on every transport. Bound the same ordinary
        // collaboration catalog as agent_tools, independently of setup schemas.
        let operational: Vec<_> = tools.iter().filter(|tool| !matches!(
            tool["name"].as_str(), Some("peerwork_connect" | "peerwork_connect_approve")
        )).collect();
        let bytes = serde_json::to_vec(&operational).unwrap().len();
        assert!(bytes <= 16 * 1024,
            "operational eager entry points must stay within 16 KiB, not expand into per-protocol action catalogs: {bytes} bytes");
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
