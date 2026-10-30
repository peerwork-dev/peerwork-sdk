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
    json!({"state":"HELP","availability":"UNRELEASED_CANDIDATE","runtime_dependencies":[],"usage":[
"peerwork agent tools",
"peerwork agent --profile PROFILE.json context",
"peerwork agent --profile PROFILE.json send CONTACT --id OPERATION_ID [--text-file FILE] < message.txt",
"peerwork agent --profile PROFILE.json reply SCOPE SEQUENCE/DELIVERY_ID --id OPERATION_ID [--text-file FILE] < reply.txt",
"peerwork agent --profile PROFILE.json inbox SCOPE",
"peerwork agent --profile PROFILE.json status|recover OPERATION_ID",
"peerwork agent --profile PROFILE.json call TOOL ARGUMENTS_JSON",
"peerwork agent --profile PROFILE.json mcp"],"tools":agent_tools::catalog(),"identity":"Protected profile pins a scoped client endpoint, actor and Origin. This frontend never starts an engine or a model.","recovery":"Keep the operation_id. Unknown means recover the original intent, not send a replacement.","scheduling":"Service acceptance does not wait for a Worker reply. Continue independent work; use wait only for a real dependency."})
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
        [command, scope] if command == "inbox" => ("inbox", json!({"scope":scope})),
        [command, id] if ["status", "recover"].contains(&command.as_str()) => {
            (command.as_str(), json!({"operation_id":id}))
        }
        [command, contact, flag, id, rest @ ..] if command == "send" && flag == "--id" => (
            "send",
            json!({"contact":contact,"operation_id":id,"text":text(rest)?}),
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
            peerwork_core::strict_json::parse_strict_json(body.as_bytes())
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
        return json!({"tools":agent_tools::catalog(),"availability":"UNRELEASED_CANDIDATE"});
    }
    let run = || -> Result<Value> {
        let [flag, path, rest @ ..] = args else {
            return Err(invalid());
        };
        if flag != "--profile" {
            return Err(invalid());
        }
        let profile = AgentProfile::load(Path::new(path))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| invalid())?;
        if rest == ["mcp"] {
            runtime.block_on(crate::agent_mcp::serve(
                profile,
                tokio::io::BufReader::new(tokio::io::stdin()),
                tokio::io::stdout(),
            ))?;
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
