//! Explicit backend-execution Context. Opening is offline and does not require
//! an Owner migration, lifecycle keyring, journal replay or directory creation.
//! The configured HTTPS origin is the initial trust input. Online operations
//! use Kernel's durable discovery pin and core-verified author/service proofs.
use super::{canonical, error, identity, origin, path, runtime_error, Result};
use crate::{kernel_access::{KernelAccess, KernelPublicError}, kernel_client::StructureIntentOutcome,
    secure_state::check_private_directory, transport::TransportOptions};
use peerwork_core::{crypto::sha256_hex, structure_execution::{is_structure_action, PROFILE},
    wire_json::{parse_wire_json_bounded, WireValue}};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::{Path, PathBuf}};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String, execution_profile: String, service_id: String, origin: String,
    identity_path: PathBuf, kernel_journal_path: PathBuf, workspaces: Vec<String>,
    #[serde(default)] allow_loopback_http: bool,
    #[serde(default)] required_features: Vec<String>,
    #[serde(default)] authority: Option<String>,
    #[serde(default)] transport: TransportOptions,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    expected_fingerprint: Option<String>, workspace_id: String,
    intent: Option<Value>, operation_id: Option<String>, command_id: Option<String>,
    query: Option<Value>,
}
fn valid_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn failure(e: crate::kernel_access::KernelAccessError) -> super::Error {
    public_failure(KernelPublicError::from(e))
}
fn public_failure(public:KernelPublicError)->super::Error{
    if let Some(detail)=public.details.as_ref(){return runtime_error(public.code,json!({"stage":detail["phase"],"server_code":detail["server_code"],"effect_certainty":detail["effect_certainty"],"http_status":detail["http_status"],"retryability":if detail["retryable"]==true{"reconcile_only"}else{"correct_input"},"recovery_hints":[{"action":detail["recovery"]}],"continuation":if detail["command_id"].is_string(){json!({"operation":"recover","workspace_id":detail["workspace_id"],"command_id":detail["command_id"]})}else{Value::Null}}).to_string());}
    if matches!(public.code,"IDENTITY_MISSING"|"IDENTITY_STATE"|"CONFIG_INVALID"|"AUTHORITY_MISMATCH"|"COMMAND_INVALID"|"STATE_CONFLICT"|"NOT_FOUND"|"DISCOVERY_CHANGED"|"DISCOVERY_FAILED"|"CAPABILITY_UNAVAILABLE"|"CONTENT_KEY_MISSING"|"CONTENT_KEY_ROTATION_REQUIRED"|"CONTENT_KEY_ROLLBACK"|"CONTENT_KEY_CONFLICT"|"CONTENT_TOO_LARGE"|"CONTENT_AUTHENTICATION_FAILED"|"CONTENT_KEY_STATE"|"ACCESS_REQUEST_INVALID"|"ACCESS_REQUEST_EXPIRED"|"ACCESS_STATE_INVALID"|"ACCESS_KEY_AUTHENTICATION_FAILED") {
        error(public.code, public.message)
    }else{runtime_error(public.code, public.message.into())}
}
fn request_intent(workspace: &str, input: Value) -> Result<Value> {
    let mut intent=input.as_object().cloned().ok_or_else(||error("REQUEST_INVALID","structure intent must be an object"))?;
    if intent.get("workspace_id").is_some_and(|v| v.as_str()!=Some(workspace)) {
        return Err(error("CONTEXT_BINDING","intent targets a different workspace"));
    }
    let action=intent.get("action").and_then(Value::as_str).ok_or_else(||error("REQUEST_INVALID","structure action is required"))?;
    if !is_structure_action(action) || action=="structure.workspace.create" {
        return Err(error("UNSUPPORTED_PRODUCER","selected workspace requires a backend structure action"));
    }
    intent.insert("workspace_id".into(),json!(workspace));
    Ok(Value::Object(intent))
}
fn read(action: &str, body: Value) -> Value { json!({"action":action,"body":body}) }
fn follow_continuation(workspace:&str,intent:Option<&Value>)->Value{
    let empty=Value::Null;let i=intent.unwrap_or(&empty);
    let selector=|v:&Value|v.as_str().filter(|s|valid_token(s)).map(|s|json!(s)).unwrap_or(Value::Null);
    json!({"operation":"follow.operation","workspace_id":workspace,"intent":{"action":"structure.maintenance.get",
        "instance_id":selector(&i["instance_id"]),"protocol_digest":selector(&i["protocol_digest"]),"body":{"job_id":selector(&i["body"]["job_id"])}}})
}
pub(super) fn follow_error_continuation(request:&Value)->Value{
    follow_continuation(request["workspace_id"].as_str().unwrap_or(""),request.get("intent"))
}

pub(super) fn bind(target: &Path, actor: &str, service: &str, wire: Option<&str>, cancel: &CancellationToken) -> Result<Value> {
    let wire=wire.filter(|s|s.len()<=64*1024).ok_or_else(||error("REQUEST_LIMIT","bounded backend configuration required"))?;
    let cwd=std::env::current_dir().map_err(|_|error("CONTEXT_PATH","current directory unavailable"))?;
    let target=path(target,&cwd)?;let parent=target.parent().ok_or_else(||error("CONTEXT_PATH","context parent missing"))?;
    check_private_directory(parent).map_err(|_|error("CONTEXT_STATE","context parent must already exist and be protected"))?;
    if std::fs::symlink_metadata(&target).is_ok(){return Err(error("CONTEXT_EXISTS","context already exists; reopen it explicitly"));}
    let mut result=execute("open",&target,wire.as_bytes(),actor,service,None,cancel)?;
    super::persist_context(&target,parent,wire.as_bytes(),cancel)?;
    result["status"]=json!("bound");result["local_only"]=json!(true);Ok(result)
}

pub(super) fn execute(operation: &str, selected: &Path, config_wire: &[u8], actor: &str,
    service: &str, request_wire: Option<&str>, cancel: &CancellationToken) -> Result<Value> {
    let mut config:Config=serde_json::from_slice(config_wire).map_err(|_|error("CONTEXT_CONFIG","invalid backend context configuration"))?;
    if config.schema!="peerwork.agent-context.v2" || config.execution_profile!=PROFILE {
        return Err(error("CONTEXT_CONFIG","unsupported backend context profile"));
    }
    if service.is_empty() || service!=config.service_id {return Err(error("CONTEXT_SERVICE","selected service differs from expected service"));}
    let parent=selected.parent().ok_or_else(||error("CONTEXT_PATH","context parent missing"))?;
    let normalized_origin=origin(&config.origin,config.allow_loopback_http)?;
    let identity_path=path(&config.identity_path,parent)?;
    let (selected_actor,key)=identity(&identity_path)?;
    if actor.is_empty() || actor!=selected_actor {return Err(error("CONTEXT_ACTOR","selected identity differs from expected actor"));}
    let journal_path=path(&config.kernel_journal_path,parent)?;
    if journal_path==identity_path || journal_path==selected {return Err(error("CONTEXT_BINDING","journal must have its own protected path"));}
    check_private_directory(journal_path.parent().ok_or_else(||error("CONTEXT_PATH","journal parent missing"))?)
        .map_err(|_|error("CONTEXT_STATE","journal parent must already exist and be protected"))?;
    config.transport.validate().map_err(|_|error("CONTEXT_CONFIG","invalid transport configuration"))?;
    for root in &mut config.transport.additional_root_pem_files {*root=path(root,parent)?;}
    let spaces:BTreeSet<_>=config.workspaces.iter().collect();
    if config.workspaces.len()>128 || spaces.len()!=config.workspaces.len() || spaces.iter().any(|s|!valid_token(s))
        || config.required_features.len()>64 || config.required_features.iter().any(|s|s.is_empty()||s.len()>128)
        || config.authority.as_ref().is_some_and(|s|s.len()!=64||!s.bytes().all(|b|b.is_ascii_digit()||matches!(b,b'a'..=b'f'))) {
        return Err(error("CONTEXT_CONFIG","invalid bounded workspace, feature or authority selectors"));
    }
    let mut descriptor=json!({"schema":config.schema,"service_id":service,"origin":normalized_origin,
        "execution_profile":PROFILE,"actor_id":actor,"key_id":key,"workspaces":spaces,
        "trust":"configured_origin_then_discovery_continuity","assurance":"BACKEND_CURRENT_STATE",
        "events":{"source":"backend_structural_events","sync":"bounded_keyset","incremental":true,"default_start":"NOW","delivery":"at_least_once","task_completion":false},
        "producers":["protocol.action","structure.intent"],"discovery":{"execution":"backend","verification":"service_and_author_signatures"}});
    let binding=json!({"descriptor":descriptor,"context_path":selected,"identity_path":identity_path,
        "journal_path":journal_path,"authority":config.authority,"required_features":config.required_features,
        "allow_loopback_http":config.allow_loopback_http,"transport":config.transport});
    descriptor["fingerprint"]=json!(sha256_hex(canonical(&binding).as_bytes()));
    let mut out=json!({"schema":"peerwork.agent-result.v1","context":descriptor,"status":"ready"});
    if operation=="open" {return Ok(out);}
    if !matches!(operation,"execute.structure"|"operate"|"recover"|"inspect"|"discover"|"describe"|"operations"|"follow.operation"|"request.access"|"publish.record"|"authorize.access"|"accept.keys"|"rotate.key"|"coordinate.keys") {
        return Err(error("UNSUPPORTED_PRODUCER","use executeStructureIntent for bounded backend records, members and events; legacy replay operations are unavailable in v2"));
    }
    let wire=request_wire.filter(|s|s.len()<=peerwork_core::structure_content::MAX_BODY_REQUEST_BYTES).ok_or_else(||error("REQUEST_LIMIT","bounded workspace request required"))?;
    parse_wire_json_bounded(wire.as_bytes(),40,peerwork_core::structure_content::MAX_BODY_REQUEST_BYTES).map_err(|_|error("REQUEST_INVALID","invalid or duplicate JSON request fields"))?;
    let r:Request=serde_json::from_str(wire).map_err(|_|error("REQUEST_INVALID","invalid backend workspace request"))?;
    if r.expected_fingerprint.as_deref().is_some_and(|v|Some(v)!=out["context"]["fingerprint"].as_str()) {
        return Err(error("CONTEXT_CHANGED","selected context bindings changed; explicitly reopen before proceeding"));
    }
    if !spaces.contains(&r.workspace_id) {return Err(error("CONTEXT_WORKSPACE","workspace is not selected"));}
    let access=KernelAccess::new(&normalized_origin,&journal_path,&identity_path,&config.required_features,config.allow_loopback_http)
        .with_authority(config.authority).with_transport_options(config.transport);
    let access_selection=||->Result<Value>{
        if r.intent.is_some()||r.operation_id.is_some()||r.command_id.is_some(){return Err(error("REQUEST_INVALID","access methods accept only scoped options"));}
        let mut query=r.query.as_ref().and_then(Value::as_object).cloned().ok_or_else(||error("REQUEST_INVALID","access options required"))?;
        if query.get("workspace_id").is_some_and(|v|v.as_str()!=Some(r.workspace_id.as_str())){return Err(error("CONTEXT_WORKSPACE","access options target a different workspace"));}
        query.insert("workspace_id".into(),json!(r.workspace_id));Ok(Value::Object(query))
    };
    if matches!(operation,"request.access"|"accept.keys"){
        let selected=access_selection()?.to_string();
        let value=if operation=="request.access"{access.request_access_json(&selected,cancel)}else{access.accept_content_keys_json(&selected,cancel)}
            .map_err(public_failure)?;
        out["workspace_id"]=json!(r.workspace_id);out["status"]=json!(if operation=="request.access"{"waiting"}else{"verified"});out["result"]=value;
        if operation=="request.access"{out["continuation"]=json!({"operation":"inspect","workspace_id":r.workspace_id});}
        return Ok(out);
    }
    let outcome=if operation=="coordinate.keys"{
        access.coordinate_content_keys_json(&access_selection()?.to_string(),cancel).map_err(public_failure)?
    }else if operation=="rotate.key"{
        access.rotate_content_key_json(&access_selection()?.to_string(),cancel).map_err(public_failure)?
    }else if operation=="publish.record"{
        access.publish_selected_record_with_cancel(access_selection()?.to_string().as_bytes(),cancel).map_err(failure)?
    }else if operation=="authorize.access"{
        access.authorize_access_with_cancel(access_selection()?.to_string().as_bytes(),cancel).map_err(failure)?
    }else if operation=="follow.operation" {
        if r.query.is_some()||r.command_id.is_some()||r.operation_id.is_some(){return Err(error("REQUEST_INVALID","follow requires a selected backend operation only"));}
        let intent=request_intent(&r.workspace_id,r.intent.clone().ok_or_else(||error("REQUEST_INVALID","operation selector required"))?)?;
        access.follow_structure_operation_with_cancel(intent.to_string().as_bytes(),cancel).map_err(failure)?
    }else if operation=="recover" {
        if r.intent.is_some()||r.query.is_some()||r.operation_id.is_some()==r.command_id.is_some() {
            return Err(error("REQUEST_INVALID","recover requires exactly one saved command_id or operation_id"));
        }
        let id=if let Some(id)=r.command_id.as_ref(){
            if !valid_token(id){return Err(error("REQUEST_INVALID","invalid saved command id"));} id.clone()
        }else{
            let key:Vec<u16>=r.operation_id.as_ref().unwrap().encode_utf16().collect();
            crate::kernel_client::structure_keyed_command_id(&normalized_origin,actor,WireValue::String(r.workspace_id.encode_utf16().collect()),&key)
                .map_err(|_|error("REQUEST_INVALID","invalid operation id"))?
        };
        access.resume_structure_intent_scoped_with_cancel(&id,&r.workspace_id,cancel).map_err(failure)?
    }else{
        if r.command_id.is_some(){return Err(error("REQUEST_INVALID","command_id is only valid in recover; select it inside an explicit structure intent"));}
        let input=match operation {
            "operations"=>{
                #[derive(Deserialize,Default)] #[serde(deny_unknown_fields)] struct Query{after:Option<String>,limit:Option<u8>,scope:Option<String>,view:Option<String>}
                if r.intent.is_some()||r.operation_id.is_some(){return Err(error("REQUEST_INVALID","operations requires a bounded query"));}
                let q:Query=serde_json::from_value(r.query.clone().unwrap_or(json!({}))).map_err(|_|error("REQUEST_INVALID","invalid operation page query"))?;
                if q.scope.as_deref().is_some_and(|s|!matches!(s,"MINE"|"WORKSPACE"))||q.view.as_deref().is_some_and(|s|!matches!(s,"OPEN"|"HISTORY"))||q.limit.is_some_and(|n|n==0||n>32){return Err(error("REQUEST_INVALID","invalid operation selectors or page limit"));}
                let mut body=json!({});if let Some(cursor)=q.after{body["cursor"]=json!(cursor);}if let Some(limit)=q.limit{body["limit"]=json!(limit);}
                if let Some(scope)=q.scope{body["scope"]=json!(scope);}if let Some(view)=q.view{body["view"]=json!(view);}
                read("structure.operations.read",body)
            },
            "inspect"=>{if r.intent.is_some()||r.query.is_some()||r.operation_id.is_some(){return Err(error("REQUEST_INVALID","inspect accepts only the selected workspace"));}read("structure.workspace.get",json!({}))},
            "discover"=>{
                #[derive(Deserialize,Default)] #[serde(deny_unknown_fields)] struct Query{after:Option<String>,limit:Option<u8>}
                if r.intent.is_some()||r.operation_id.is_some(){return Err(error("REQUEST_INVALID","discover requires a bounded query"));}
                let q:Query=serde_json::from_value(r.query.clone().unwrap_or(json!({}))).map_err(|_|error("REQUEST_INVALID","invalid backend page query"))?;
                let mut body=json!({});if let Some(cursor)=q.after{body["cursor"]=json!(cursor);}if let Some(limit)=q.limit{body["limit"]=json!(limit);}
                read("structure.instances.read",body)
            },
            "describe"=>{
                #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Query{instance_id:String,protocol_digest:String,record_id:Option<String>,revision:Option<u64>}
                if r.intent.is_some()||r.operation_id.is_some(){return Err(error("REQUEST_INVALID","describe requires an exact selector"));}
                let q:Query=serde_json::from_value(r.query.clone().unwrap_or(Value::Null)).map_err(|_|error("REQUEST_INVALID","backend describe requires instance_id and protocol_digest from discover"))?;
                if q.record_id.is_some()!=q.revision.is_some(){return Err(error("REQUEST_INVALID","record_id and revision must be selected together"));}
                let mut intent=if let Some(id)=q.record_id{read("structure.record.get",json!({"record_id":id,"revision":q.revision}))}else{read("structure.instance.get",json!({}))};
                intent["instance_id"]=json!(q.instance_id);intent["protocol_digest"]=json!(q.protocol_digest);intent
            },
            "execute.structure"=>{if r.query.is_some()||r.operation_id.is_some(){return Err(error("REQUEST_INVALID","execute accepts only a structure intent"));}r.intent.clone().ok_or_else(||error("REQUEST_INVALID","structure intent required"))?},
            "operate"=>{
                if r.query.is_some(){return Err(error("REQUEST_INVALID","operate does not accept a discovery query"));}
                let input=r.intent.as_ref().ok_or_else(||error("REQUEST_INVALID","business intent required"))?;
                let mut intent=match input.get("kind").and_then(Value::as_str) {
                    Some("structure.intent")=>{
                        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Intent{kind:String,request:Value}
                        let i:Intent=serde_json::from_value(input.clone()).map_err(|_|error("REQUEST_INVALID","invalid structure intent wrapper"))?;let _=i.kind;i.request
                    },
                    Some("protocol.action")=>{
                        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Intent{kind:String,instance_id:String,protocol_digest:String,expected_instance_revision:u64,action_id:String,values:Value,#[serde(default)]refs:Vec<Value>,#[serde(default)]contents:Vec<Value>,#[serde(default)]plaintext_contents:Vec<Value>,#[serde(default)]document_times:Vec<Value>}
                        let i:Intent=serde_json::from_value(input.clone()).map_err(|_|error("REQUEST_INVALID","backend action requires protocol_digest and expected_instance_revision"))?;let _=i.kind;
                        let mut request=json!({"action":"structure.action","instance_id":i.instance_id,"protocol_digest":i.protocol_digest,"expected_instance_revision":i.expected_instance_revision,"exact_input_refs":i.refs,"body":{"action_id":i.action_id,"structure":i.values,"contents":i.contents}});
                        if !i.plaintext_contents.is_empty(){request["plaintext_contents"]=json!(i.plaintext_contents);}if !i.document_times.is_empty(){request["body"]["document_times"]=json!(i.document_times);}request
                    },
                    _=>return Err(error("UNSUPPORTED_PRODUCER","backend context supports protocol.action and structure.intent")),
                };
                if intent.get("command_id").is_some()||intent.get("idempotency_key").is_some(){return Err(error("REQUEST_INVALID","operate owns the operation idempotency key"));}
                intent.as_object_mut().ok_or_else(||error("REQUEST_INVALID","structure intent must be an object"))?.insert("idempotency_key".into(),
                    json!(r.operation_id.as_ref().filter(|s|!s.is_empty()&&s.encode_utf16().count()<=128).ok_or_else(||error("REQUEST_INVALID","bounded operation_id required"))?));intent
            },
            _=>unreachable!(),
        };
        let intent=request_intent(&r.workspace_id,input)?;
        access.execute_structure_intent_with_cancel(intent.to_string().as_bytes(),cancel).map_err(failure)?
    };
    out["workspace_id"]=json!(r.workspace_id);out["operation_id"]=json!(r.operation_id);
    match outcome {
        StructureIntentOutcome::Completed{command_id,result}=>{
            let structure:Value=serde_json::from_str(result.structure_result_json.as_deref().ok_or_else(||runtime_error("VERIFICATION_FAILED","backend operation observation missing".into()))?)
                .map_err(|_|runtime_error("RESULT_ENCODING","invalid verified backend operation observation".into()))?;
            out["status"]=json!(match structure["delivery"]["status"].as_str().or_else(||structure["maintenance"]["status"].as_str()).or_else(||structure["deletion"]["status"].as_str()){Some("APPLIED"|"COMPLETE")=>"verified",Some("REJECTED_NO_EFFECT")=>"rejected",_=>"blocked"});
            let author_verified=structure["maintenance"]["source"].is_object()||structure["deletion"]["source"].is_object();
            out["command_id"]=json!(command_id);out["observation_command_id"]=json!(result.command_id);out["result"]=structure;
            out["evidence"]=json!({"verification":if author_verified{"service_progress_and_original_intent"}else{"service_progress"},"assurance":"BACKEND_CURRENT_STATE"});
        },
        StructureIntentOutcome::Accepted(result)=>{
            if let Some(reference)=result.browser_approval_reference(){out["browser_approval_reference"]=json!(reference);}
            if let Some(contents)=result.opened_contents {out["opened_contents"]=json!(contents);}
            let structure:Value=serde_json::from_str(result.structure_result_json.as_deref().ok_or_else(||runtime_error("VERIFICATION_FAILED","backend structure evidence missing".into()))?)
                .map_err(|_|runtime_error("RESULT_ENCODING","invalid verified structure result".into()))?;
            // A service-signed deterministic rejection is a definite outcome,
            // distinct from acceptance of business effects or unknown delivery.
            out["status"]=json!(match structure["status"].as_str(){Some("REJECTED_NO_EFFECT")=>"rejected",Some("COMMITTED_RESULT_UNAVAILABLE")=>"committed",_=>"verified"});
            if structure["status"]=="COMMITTED_RESULT_UNAVAILABLE"{
                let command_id=result.command_id.clone();
                out["continuation"]=json!({"operation":"recover","workspace_id":r.workspace_id,"command_id":command_id,"precondition":"WORKSPACE_ACCESS_RESTORED"});
            }
            out["command_id"]=json!(result.command_id);out["result"]=structure;
            if let Some(history)=result.key_history{out["key_history"]=json!(history);}
            out["evidence"]=json!({"verification":"service_and_author_signatures","assurance":"BACKEND_CURRENT_STATE"});
        },
        StructureIntentOutcome::Pending{command_id,code,phase,retryable,recovery}=>{
            out["status"]=json!("pending");out["command_id"]=json!(command_id);
            out["continuation"]=if matches!(operation,"rotate.key"|"coordinate.keys"){json!({"operation":operation,"workspace_id":r.workspace_id,"query":r.query})}
                else if recovery=="OBSERVE_SAME_OPERATION"{follow_continuation(&r.workspace_id,r.intent.as_ref())}
                else if recovery=="NEW_READ"{json!({"operation":"NEW_READ","workspace_id":r.workspace_id})}
                else{json!({"operation":"recover","workspace_id":r.workspace_id,"command_id":command_id})};
            out["result"]=json!({"code":code,"phase":phase,"retryable":retryable,"recovery":recovery,"effect_certainty":if phase=="KEY_DELIVERY"{"COMMITTED"}else if phase=="PREPARATION"{"NOT_SUBMITTED"}else{"UNKNOWN"}});
        },
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agent_context::agent_context_json,kernel_identity::KernelIdentity,test_support::protected_test_dir};
    fn write(path:&Path,value:&Value){
        #[cfg(windows)] crate::windows_fs::create_or_check_file(path).unwrap();
        std::fs::write(path,value.to_string()).unwrap();
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o600)).unwrap();}
    }
    fn config(origin:&str,workspaces:Value)->Value{json!({"schema":"peerwork.agent-context.v2","execution_profile":PROFILE,"service_id":"selected-service",
        "origin":origin,"identity_path":"identity.state","kernel_journal_path":"operations.sqlite","workspaces":workspaces})}
    fn call(operation:&str,profile:&Path,actor:&str,request:Option<Value>)->Value{
        serde_json::from_str(&agent_context_json(operation,profile,actor,"selected-service",request.as_ref().map(Value::to_string).as_deref(),&CancellationToken::new())).unwrap()
    }
    #[test]
    fn backend_context_open_is_offline_redacted_and_requires_no_legacy_state(){
        let root=protected_test_dir();let actor=KernelIdentity::create(&root.path().join("identity.state")).unwrap().actor_id().to_owned();let profile=root.path().join("context.json");
        write(&profile,&config("https://example.invalid",json!(["spaceA","spaceB"])));
        let before=std::fs::read_dir(root.path()).unwrap().count();let opened=call("open",&profile,&actor,None);
        assert_eq!(opened["ok"],true);let descriptor=&opened["value"]["context"];
        assert_eq!(descriptor["execution_profile"],PROFILE);assert_eq!(descriptor["events"]["sync"],"bounded_keyset");
        assert!(!opened.to_string().contains(root.path().to_str().unwrap()));assert_eq!(opened,call("open",&profile,&actor,None));
        assert_eq!(before,std::fs::read_dir(root.path()).unwrap().count());assert!(!root.path().join("operations.sqlite").exists());
        assert_eq!(call("open",&profile,"wrong-actor",None)["code"],"CONTEXT_ACTOR");
    }
    #[test]
    fn backend_context_binding_validates_before_persistence_and_never_overwrites(){
        let root=protected_test_dir();let actor=KernelIdentity::create(&root.path().join("identity.state")).unwrap().actor_id().to_owned();let target=root.path().join("context.json");
        let mut cfg=config("https://example.invalid",json!(["spaceA"]));cfg["identity_path"]=json!("missing.state");
        assert_eq!(call("bind.structure",&target,&actor,Some(cfg))["code"],"IDENTITY_STATE");assert!(!target.exists());
        let cfg=config("https://example.invalid",json!(["spaceA"]));let bound=call("bind.structure",&target,&actor,Some(cfg.clone()));
        assert_eq!(bound["ok"],true,"{bound}");assert_eq!(bound["value"]["status"],"bound");
        let original=std::fs::read(&target).unwrap();assert_eq!(call("bind.structure",&target,&actor,Some(cfg))["code"],"CONTEXT_EXISTS");
        assert_eq!(std::fs::read(&target).unwrap(),original);assert!(!root.path().join("operations.sqlite").exists());
        assert_eq!(bound["value"]["context"]["fingerprint"],call("open",&target,&actor,None)["value"]["context"]["fingerprint"]);
    }
    #[test]
    fn backend_context_rejects_changed_bindings_and_cross_workspace_intents_before_network(){
        let root=protected_test_dir();let actor=KernelIdentity::create(&root.path().join("identity.state")).unwrap().actor_id().to_owned();let profile=root.path().join("context.json");
        write(&profile,&config("https://example.invalid",json!(["spaceA"])));
        assert_eq!(call("inspect",&profile,&actor,Some(json!({"workspace_id":"spaceB"})))["code"],"CONTEXT_WORKSPACE");
        assert_eq!(call("execute.structure",&profile,&actor,Some(json!({"workspace_id":"spaceA","intent":{"action":"structure.workspace.get","workspace_id":"spaceB","body":{}}})))["code"],"CONTEXT_BINDING");
        assert_eq!(call("inspect",&profile,&actor,Some(json!({"workspace_id":"spaceA","expected_fingerprint":"old-binding"})))["code"],"CONTEXT_CHANGED");
        assert_eq!(call("events.sync",&profile,&actor,Some(json!({"workspace_id":"spaceA"})))["code"],"UNSUPPORTED_PRODUCER");
        let duplicate="{\"workspace_id\":\"spaceA\",\"workspace_id\":\"spaceB\"}";
        let rejected:Value=serde_json::from_str(&agent_context_json("inspect",&profile,&actor,"selected-service",Some(duplicate),&CancellationToken::new())).unwrap();
        assert_eq!(rejected["code"],"REQUEST_INVALID");assert!(!root.path().join("operations.sqlite").exists());
    }

    #[cfg(unix)]
    #[test]
    #[ignore="requires a frozen candidate service and synthetic loopback HTTP"]
    fn backend_context_executes_discovers_reads_and_recovers_without_history_or_owner_migration(){
        use std::{io::{BufRead,BufReader},process::{Child,Command,Stdio}};
        struct Server(Child);impl Drop for Server{fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
        let state=protected_test_dir();let fixture=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/structure-profile-service.mjs");
        let mut server=Server(Command::new(std::env::var("PEERWORK_TEST_NODE").expect("test Node required")).arg(fixture)
            .env("PEERWORK_TEST_STATE",state.path()).env("PEERWORK_STRUCTURE_TEST_DROPS","2")
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
        let mut line=String::new();BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let origin=serde_json::from_str::<Value>(&line).unwrap()["origin"].as_str().unwrap().to_owned();
        let identity_path=state.path().join("identity.state");let actor=KernelIdentity::create(&identity_path).unwrap().actor_id().to_owned();
        let access=KernelAccess::new(&origin,state.path().join("operations.sqlite"),&identity_path,&[],true);
        let create=|key:&str| match access.execute_structure_intent_with_cancel(json!({"action":"structure.workspace.create","idempotency_key":key,"body":{"name":key}}).to_string().as_bytes(),&CancellationToken::new()).unwrap(){StructureIntentOutcome::Accepted(result)=>result.workspace_id.unwrap(),other=>panic!("unexpected creation: {other:?}")};
        let a=create("workspaceA");let b=create("workspaceB");let profile=state.path().join("context.json");let mut cfg=config(&origin,json!([a,b]));cfg["allow_loopback_http"]=json!(true);write(&profile,&cfg);
        let opened=call("open",&profile,&actor,None);assert_eq!(opened["ok"],true);
        let manifest=json!({"name":"context-claim","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"initial_state":{"count":0},
            "record_schemas":{"change":{"type":"object","fields":{"count":"integer"},"required":["count"],"max_bytes":256}},
            "actions":[{"id":"advance","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},
                "variants":[{"when":[{"op":"eq","left":{"from":"state","path":["count"]},"right":{"from":"literal","value":0}}],"effects":[
                    {"op":"set","path":["count"],"value":{"from":"literal","value":1}},
                    {"op":"append","schema":"change","value":{"from":"literal","value":{"count":1}},"relations":[]}]}]}]});
        let adopted=call("operate",&profile,&actor,Some(json!({"workspace_id":a,"operation_id":"adopt-v1","intent":{"kind":"structure.intent","request":{"action":"structure.adopt","body":{"manifest":manifest,"bootstrap_grant":{"actions":["advance"]}}}}})));
        assert_eq!(adopted["ok"],true,"{adopted}");let instance=adopted["value"]["result"]["instance_id"].clone();let protocol=adopted["value"]["result"]["protocol_digest"].clone();
        let page=call("discover",&profile,&actor,Some(json!({"workspace_id":a,"query":{"limit":1}})));assert_eq!(page["value"]["result"]["instances"][0]["instance_id"],instance);
        let content_key=access.ensure_local_content_key_with_cancel(&a,&CancellationToken::new()).unwrap();
        let intent=json!({"workspace_id":a,"operation_id":"advance-once","intent":{"kind":"protocol.action","instance_id":instance,"protocol_digest":protocol,"expected_instance_revision":1,"action_id":"advance","values":{},"plaintext_contents":[{"record_index":0,"text":"private body from one SDK call"}]}});
        let pending=call("operate",&profile,&actor,Some(intent.clone()));assert_eq!(pending["value"]["status"],"pending","{pending}");
        let command=pending["value"]["command_id"].clone();
        let local=access.pending_page_json_with_cancel("{}",&CancellationToken::new()).unwrap();
        assert_eq!(local["items"].as_array().unwrap().len(),1);assert_eq!(local["items"][0]["command_id"],command);
        // Scope validation occurs before resubmitting the saved A operation.
        let wrong=call("recover",&profile,&actor,Some(json!({"workspace_id":b,"command_id":command})));assert_eq!(wrong["code"],"COMMAND_INVALID");
        let restored=call("recover",&profile,&actor,Some(json!({"workspace_id":a,"operation_id":"advance-once"})));assert_eq!(restored["value"]["status"],"verified","{restored}");
        assert_eq!(restored["value"]["command_id"],command);assert_eq!(restored["value"]["result"]["state"]["count"],1);
        assert!(access.pending().unwrap().is_empty(),"verified acceptance removes only the selected unresolved entry");
        assert_eq!(call("operate",&profile,&actor,Some(intent.clone()))["value"]["command_id"],command);
        let read=call("describe",&profile,&actor,Some(json!({"workspace_id":a,"query":{"instance_id":instance,"protocol_digest":protocol}})));
        assert_eq!(read["value"]["result"]["revision"],2);assert_eq!(read["value"]["result"]["state"]["count"],1);
        let records=call("execute.structure",&profile,&actor,Some(json!({"workspace_id":a,"intent":{"action":"structure.records.read","instance_id":instance,"protocol_digest":protocol,"body":{"limit":1}}})));
        assert_eq!(records["value"]["result"]["records"].as_array().unwrap().len(),1);
        assert!(!records["value"]["result"].to_string().contains("private body from one SDK call"),"service result and original author packet contain ciphertext only");
        assert_eq!(records["value"]["opened_contents"][0]["text"],"private body from one SDK call");
        assert_eq!(records["value"]["opened_contents"][0]["assurance"],"AUTHOR_SIGNATURE_AND_AEAD");
        let record=&records["value"]["result"]["records"][0];let source=&records["value"]["result"]["sources"][record["source_key"].as_str().unwrap()];
        let journal=crate::kernel_intents::KernelIntentJournal::open(&state.path().join("operations.sqlite")).unwrap();
        let discovery=journal.pinned_discovery(&origin).unwrap();
        let author=peerwork_core::prepared_command::verify_structure_author_intent(source["author_intent"].as_str().unwrap(),discovery.audience_utf16()).unwrap();
        let mut transport=crate::transport::TransportConfig::new(&origin);transport.allow_loopback_http=true;
        let mut keys=crate::kernel_intents::StructureContentKeys::open(&access.content_key_path_for_origin(&origin),transport).unwrap();
        let local=KernelIdentity::open(&identity_path).unwrap();
        assert_eq!(&**keys.open_authored_body(local.key_id(),&author,0).unwrap(),b"private body from one SDK call");
        let replacement=state.path().join("synthetic-new-body.key");std::fs::write(&replacement,[42u8;32]).unwrap();
        {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&replacement,std::fs::Permissions::from_mode(0o600)).unwrap();}
        keys.import_current_from_file(local.key_id(),&a,&replacement,&peerwork_core::structure_content::structure_content_key_id(&[42;32]),Some(&content_key.key_id)).unwrap();
        assert_eq!(call("operate",&profile,&actor,Some(intent.clone()))["value"]["command_id"],command,"retry retains original ciphertext after local active-key change");
        let mut changed=intent;changed["intent"]["plaintext_contents"][0]["text"]=json!("changed private body");
        let conflict=call("operate",&profile,&actor,Some(changed));assert_eq!(conflict["code"],"STATE_CONFLICT");
        assert!(!conflict.to_string().contains("changed private body"),"error continuations never retain plaintext");
        let body_db=rusqlite::Connection::open(access.content_key_path_for_origin(&origin)).unwrap();
        let retained_secret=zeroize::Zeroizing::new(body_db.query_row("SELECT secret FROM content_keys WHERE local_key_id=?1 AND workspace_id=?2 AND key_id=?3",
            rusqlite::params![local.key_id(),a,content_key.key_id],|r|r.get::<_,Vec<u8>>(0)).unwrap());
        let read_bodies=||call("execute.structure",&profile,&actor,Some(json!({"workspace_id":a,"intent":{"action":"structure.records.read","instance_id":instance,"protocol_digest":protocol,"body":{"limit":1}}})));
        body_db.execute("UPDATE content_keys SET secret=?1 WHERE local_key_id=?2 AND workspace_id=?3 AND key_id=?4",rusqlite::params![&[0u8;32][..],local.key_id(),a,content_key.key_id]).unwrap();
        let damaged=read_bodies();assert_eq!(damaged["value"]["status"],"verified");assert_eq!(damaged["value"]["opened_contents"][0]["state"],"KEY_STATE_INVALID");
        body_db.execute("DELETE FROM content_keys WHERE local_key_id=?1 AND workspace_id=?2 AND key_id=?3",rusqlite::params![local.key_id(),a,content_key.key_id]).unwrap();
        let missing=read_bodies();assert_eq!(missing["value"]["status"],"verified");assert_eq!(missing["value"]["opened_contents"][0]["state"],"KEY_UNAVAILABLE");
        body_db.execute("INSERT INTO content_keys VALUES(?1,?2,?3,?4)",rusqlite::params![local.key_id(),a,content_key.key_id,&retained_secret[..]]).unwrap();
        let rebuilt=call("operate",&profile,&actor,Some(json!({"workspace_id":a,"operation_id":"repair-current","intent":{"kind":"structure.intent","request":{
            "action":"structure.maintenance.rebuild","instance_id":instance,"protocol_digest":protocol,"expected_instance_revision":read["value"]["result"]["revision"],
            "body":{"expected_event_revision":read["value"]["result"]["event_revision"]}}}})));
        assert_eq!(rebuilt["value"]["status"],"verified","{rebuilt}");assert_eq!(rebuilt["value"]["result"]["maintenance"]["status"],"APPLIED");
        assert_ne!(rebuilt["value"]["command_id"],rebuilt["value"]["observation_command_id"]);
        let fresh_profile=state.path().join("fresh-context.json");let mut fresh=config(&origin,json!([a]));fresh["allow_loopback_http"]=json!(true);fresh["kernel_journal_path"]=json!("fresh-observations.sqlite");
        assert_eq!(call("bind.structure",&fresh_profile,&actor,Some(fresh))["ok"],true);
        let discovered=call("operations",&fresh_profile,&actor,Some(json!({"workspace_id":a,"query":{"view":"HISTORY","limit":1}})));
        assert_eq!(discovered["ok"],true,"{discovered}");let selected=&discovered["value"]["result"]["operations"][0];assert_eq!(selected["job_id"],rebuilt["value"]["result"]["maintenance"]["job_id"]);
        let followed=call("follow.operation",&fresh_profile,&actor,Some(json!({"workspace_id":a,"intent":{"action":"structure.maintenance.get","instance_id":selected["instance_id"],"protocol_digest":selected["protocol_digest"],"body":{"job_id":selected["job_id"]}}})));
        assert_eq!(followed["value"]["status"],"verified","{followed}");assert_eq!(followed["value"]["command_id"],rebuilt["value"]["command_id"]);
        let fresh_bodies=call("execute.structure",&fresh_profile,&actor,Some(json!({"workspace_id":a,"intent":{"action":"structure.records.read","instance_id":instance,"protocol_digest":protocol,"body":{"limit":1}}})));
        assert_eq!(fresh_bodies["value"]["opened_contents"][0]["text"],"private body from one SDK call","same identity/service reuses keys across Context and journal changes");
        let fresh_db=rusqlite::Connection::open(state.path().join("fresh-observations.sqlite")).unwrap();
        assert_eq!(fresh_db.query_row("SELECT count(*) FROM kernel_intents",[],|row|row.get::<_,i64>(0)).unwrap(),0,"a fresh device follows backend work without importing or replaying the original outbox");
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let counts:Value=runtime.block_on(async{serde_json::from_slice(&reqwest::get(format!("{origin}__test/counts")).await.unwrap().bytes().await.unwrap()).unwrap()});
        assert_eq!(counts,json!({"records":1,"dropped":2,"journal_reads":0}));
        let db=rusqlite::Connection::open(state.path().join("operations.sqlite")).unwrap();
        assert_eq!(db.query_row("SELECT count(*) FROM kernel_intents",[],|row|row.get::<_,i64>(0)).unwrap(),5,"two creations, adoption, one action and one maintenance intent; no read snapshots");
    }
}
