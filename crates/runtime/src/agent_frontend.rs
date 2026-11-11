//! Native CLI and stdio MCP entrypoints over the same scoped tool projection.
use crate::{
    agent_tools::{self, AgentProfile, AgentRequest, AgentTools},
    participant::{ParticipantError, Result},
};
use serde_json::{json, Value};
use std::{io::Read, path::Path};
fn invalid() -> ParticipantError {
    ParticipantError::local("AGENT_ARGUMENT_INVALID_SEE_HELP", "AGENT_CLI")
}
pub fn help() -> Value {
    json!({"state":"HELP","maturity":"EXPERIMENTAL","runtime_dependencies":[],"usage":[
"peerwork agent tools",
"peerwork connect --help",
"peerwork agent --local PROTECTED_DIRECTORY context|mcp",
"peerwork agent --profile PROFILE.json context",
"peerwork agent --profile PROFILE.json reachability [--workspace WORKSPACE]",
"peerwork agent --profile PROFILE.json send --to MEMBER --id OPERATION_ID [--text-file FILE] < message.txt",
"peerwork agent --profile PROFILE.json reply SCOPE SEQUENCE/DELIVERY_ID --id OPERATION_ID [--text-file FILE] < reply.txt",
"peerwork agent --profile PROFILE.json inbox SCOPE",
"peerwork agent --profile PROFILE.json status|recover OPERATION_ID",
"peerwork agent --profile PROFILE.json call TOOL ARGUMENTS_JSON",
"peerwork agent --profile PROFILE.json manage [describe OPERATION]",
"peerwork agent --local ORIGINAL_REGISTRY call manage - < BUSINESS_REQUEST.json",
"peerwork agent --profile PROFILE.json mcp"],"tools":agent_tools::catalog(),"identity":"Protected profile pins a scoped client endpoint, actor and Origin. This frontend never starts an engine or a model.","recovery":"Keep the operation_id. Unknown means recover the original intent, not send a replacement.","terminology":"A Peer is an independently identified Agent or program in a Workspace, not a local subagent.","scheduling":"Service acceptance does not wait for a Peer reply. Continue independent work; use wait only for a real dependency."})
}
fn text(args: &[String]) -> Result<String> {
    let mut bytes = Vec::new();
    match args {
        [] => {
            std::io::stdin()
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid())?;
        }
        [flag, path] if flag == "--text-file" => {
            std::fs::File::open(path)
                .map_err(|_| invalid())?
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid())?;
        }
        _ => return Err(invalid()),
    }
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(ParticipantError::local("MESSAGE_TEXT_LIMIT", "AGENT_CLI"));
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
fn selection(args: &[String]) -> Result<AgentRequest> {
    let (name, body) = match args {
        [command] if command == "context" => ("context", json!({})),
        [command] if command == "manage" => ("manage", json!({"mode":"catalog"})),
        [command, mode, operation] if command=="manage"&&mode=="describe" => ("manage",json!({"mode":"describe","operation":operation})),
        [command, scope] if command == "inbox" => ("inbox", json!({"scope":scope})),
        [command] if command == "reachability" => ("reachability", json!({})),
        [command, scope] if command == "reachability" => ("reachability", json!({"scope":scope})),
        [command, flag, workspace] if command == "reachability"&&flag=="--workspace" => ("reachability", json!({"workspace":workspace})),
        [command, id] if ["status", "recover"].contains(&command.as_str()) => {
            (command.as_str(), json!({"operation_id":id}))
        }
        [command, selector, target, flag, id, rest @ ..] if command == "send"&&selector=="--to"&&flag=="--id" => (
            "send",json!({"to":target,"operation_id":id,"text":text(rest)?}),
        ),
        [command, target, flag, id, rest @ ..] if command == "send" && flag == "--id" => (
            "send",
            json!({"contact":target,"operation_id":id,"text":text(rest)?}),
        ),
        [command, scope, item, flag, id, rest @ ..] if command == "reply" && flag == "--id" => {
            let (sequence, delivery) = item.split_once('/').ok_or_else(invalid)?;
            let sequence = sequence.parse::<u64>().map_err(|_| invalid())?;
            (
                "reply",
                json!({"scope":scope,"item":{"sequence":sequence,"delivery_id":delivery},"operation_id":id,"text":text(rest)?}),
            )
        }
        [command, tool, body] if command == "call" => (
            tool.as_str().strip_prefix("peerwork_").unwrap_or(tool),
            peerwork_core::strict_json::parse_strict_json(if body=="-" {
                let mut wire=Vec::new();std::io::stdin().take(512*1024+1).read_to_end(&mut wire).map_err(|_|invalid())?;
                if wire.len()>512*1024{return Err(invalid());}wire
            }else{body.as_bytes().to_vec()}.as_slice())
                .map_err(|_| invalid())?,
        ),
        _ => return Err(invalid()),
    };
    AgentRequest::parse(name, body)
}
pub fn cli(args: &[String]) -> Value {
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        return help();
    }
    if args == ["tools"] {
        return json!({"tools":agent_tools::catalog(),"maturity":"EXPERIMENTAL"});
    }
    let run = || -> Result<Value> {
        let [flag, path, rest @ ..] = args else {
            return Err(invalid());
        };
        if flag != "--profile" && flag != "--local" {
            return Err(invalid());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| invalid())?;
        if flag == "--local" {
            let path=std::path::absolute(path).map_err(|_|invalid())?;
            let (handle,rest)=match rest {
                [selected,value,tail @ ..] if selected=="--participant"=>(Some(value.clone()),tail),
                _=>(None,rest),
            };
            let (workspace,rest)=match rest {
                [selected,value,tail @ ..] if selected=="--workspace"=>(Some(value.clone()),tail),
                _=>(None,rest),
            };
            if rest == ["mcp"] || rest == ["mcp","--claude-channel"] {
                if rest.len()==2 {runtime.block_on(crate::agent_mcp::serve_claude_local(path,handle,workspace,tokio::io::BufReader::new(tokio::io::stdin()),tokio::io::stdout()))?;}
                else {runtime.block_on(crate::agent_mcp::serve_local_selected(path,handle,workspace,tokio::io::BufReader::new(tokio::io::stdin()),tokio::io::stdout()))?;}
                return Ok(Value::Null);
            }
            let request=selection(rest)?;
            return runtime.block_on(async {
                if !path.exists(){drop(crate::participant_connect::Connect::open(&path)?);}
                if let AgentRequest::Connect{request}=request {return crate::participant_connect::Connect::open(&path)?.connect_selected(request,handle.as_deref(),workspace.as_deref()).await;}
                if let AgentRequest::ConnectApprove{participant,approval_id,request}=request {return crate::participant_connect::Connect::open(&path)?.approve(&participant,&approval_id,request).await;}
                let connect=crate::participant_connect::Connect::inspect(&path)?;
                let profile=connect.profile_for_scope(handle.as_deref(),workspace.as_deref())?;
                if let Some(profile)=profile {
                    let is_context=matches!(request,AgentRequest::Context);let context=connect.context_for(handle.as_deref(),workspace.as_deref());drop(connect);
                    let alias=agent_tools::protocol_request_alias(&request).map(str::to_owned);let retry=request.clone();
                    let result=AgentTools::open(profile).await?.call(request).await;
                    let mut value=match result {
                        Err(error)if agent_tools::refresh_workspace_error(&error).is_some()=>{
                            let selected=agent_tools::refresh_workspace_error(&error).unwrap();
                            if !crate::participant_connect::Connect::open(&path)?.refresh_workspace_profile(handle.as_deref(),selected).await? {return Err(error);}
                            let next=crate::participant_connect::Connect::inspect(&path)?.profile_for_scope(handle.as_deref(),workspace.as_deref())?.ok_or_else(||ParticipantError::local("LOCAL_SELECTION_REQUIRED","CONNECT"))?;
                            AgentTools::open(next).await?.call(retry).await?
                        },
                        Err(error)if alias.is_some()&&error.code=="PROTOCOL_OPERATION_ROUTE_EXISTS"=>{
                            let next=crate::participant_connect::Connect::inspect(&path)?.profile_for_scope(handle.as_deref(),workspace.as_deref())?.ok_or_else(||ParticipantError::local("LOCAL_SELECTION_REQUIRED","CONNECT"))?;
                            AgentTools::open(next).await?.call(retry).await?
                        },
                        Err(error)if alias.is_some()&&agent_tools::refresh_protocol_error(&error)=>{
                            if let Err(error)=crate::participant_connect::Connect::open(&path)?.refresh_protocol_alias(handle.as_deref(),workspace.as_deref(),alias.as_deref().unwrap(),error.details.as_ref()).await{if !agent_tools::refresh_nonblocking(&error,&retry){return Err(error);}}
                            let next=crate::participant_connect::Connect::inspect(&path)?.profile_for_scope(handle.as_deref(),workspace.as_deref())?.ok_or_else(||ParticipantError::local("LOCAL_SELECTION_REQUIRED","CONNECT"))?;
                            AgentTools::open(next).await?.call(retry).await?
                        },other=>other?,
                    };
                    if is_context {value["onboarding"]=context;}return Ok(value);
                }
                if matches!(request,AgentRequest::Context) {return Ok(connect.context());}
                Err(ParticipantError::local("LOCAL_SELECTION_REQUIRED_USE_CONNECT","CONNECT"))
            });
        }
        let profile = AgentProfile::load(Path::new(path))?;
        if rest == ["mcp"] || rest == ["mcp","--claude-channel"] {
            if rest.len()==2 {runtime.block_on(crate::agent_mcp::serve_claude(profile,tokio::io::BufReader::new(tokio::io::stdin()),tokio::io::stdout()))?;}
            else {runtime.block_on(crate::agent_mcp::serve(
                profile,
                tokio::io::BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
            ))?;}
            return Ok(Value::Null);
        }
        let request = selection(rest)?;
        runtime.block_on(async { AgentTools::open(profile).await?.call(request).await })
    };
    match run() {
        Ok(v) => v,
        Err(error) => json!({"state":"FAILED","error":error}),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn member_target_is_explicit_and_never_reinterprets_a_contact(){
        let temp=crate::test_support::protected_test_dir();let file=temp.path().join("message");std::fs::write(&file,"Hello").unwrap();let path=file.to_str().unwrap();
        let legacy=selection(&["send","worker","--id","same","--text-file",path].map(str::to_owned)).unwrap();
        assert!(matches!(legacy,AgentRequest::Send{contact,to:None,..}if contact=="worker"));
        let member=selection(&["send","--to","worker","--id","same","--text-file",path].map(str::to_owned)).unwrap();
        assert!(matches!(member,AgentRequest::Send{contact,to:Some(to),..}if contact.is_empty()&&to=="worker"));
    }
    #[test]
    fn fixed_cli_rejects_guessed_flags_and_authority_selection() {
        assert!(selection(&["send", "worker", "--json", "{}"].map(str::to_owned)).is_err());
        assert!(selection(
            &[
                "call",
                "send",
                r#"{"contact":"worker","operation_id":"id","text":"hello","profile":"other"}"#
            ]
            .map(str::to_owned)
        )
        .is_err());
        assert!(selection(
            &["reply", "project", "bad-reference", "--id", "same"].map(str::to_owned)
        )
        .is_err());
        assert!(selection(&["status", "original"].map(str::to_owned)).is_ok());
    }
}
