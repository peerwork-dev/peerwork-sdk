//! ACP wire events for an explicitly owned, single-session AGY process.
use super::{json, Path, Value, R};

pub(super) const INITIALIZE: u64 = 1;
pub(super) const RESUME: u64 = 2;

#[derive(Debug)]
pub(super) enum Event {
    Initialized(R<()>),
    Resumed(R<()>),
    TurnEnd(u64, bool),
    TurnUpdate,
    Request { id: Value, action: Request },
    Ignore,
}

#[derive(Debug)]
pub(super) enum Request {
    Permission(Option<String>),
    Unsupported,
}

pub(super) struct Session {
    conversation: String,
    working_directory: String,
    mcp: Value,
    exact_tools: Vec<String>,
}

impl Session {
    pub(super) fn new(config: &Value, conversation: &str, working: &str) -> R<Self> {
        let mut mcp = json!([]);
        let mut exact_tools = Vec::new();
        if let Some(client) = config.get("acp_client") {
            let registry = super::text(client, "registry")?;
            let participant = super::text(client, "participant")?;
            let workspace = super::text(client, "workspace")?;
            if !client.as_object().is_some_and(|value| value.len() == 3)
                || !Path::new(registry).is_absolute()
                || !crate::communication_store::identifier(participant)
                || !crate::communication_store::identifier(workspace)
            {
                return Err("HOST_CONFIG_INVALID");
            }
            let suffix = super::mcp_server(config)?.ok_or("HOST_CONFIG_INVALID")?;
            let name = format!("peerwork_{suffix}");
            let executable = std::env::current_exe().map_err(|_| "HOST_CONFIG_INVALID")?;
            mcp = json!([{"name":name,"command":executable,
                "args":["agent","--local",registry,"--participant",participant,"--workspace",workspace,"mcp"],
                "env":[]}]);
            exact_tools = crate::agent_tools::catalog()
                .iter()
                .filter_map(|tool| {
                    let name = tool["name"].as_str()?;
                    let ordinary_read = tool["annotations"]["readOnlyHint"] == true
                        && !matches!(name, "peerwork_listen" | "peerwork_wait");
                    let ordinary_work = matches!(name,
                        "peerwork_send" | "peerwork_reply" | "peerwork_consume" | "peerwork_post"
                        | "peerwork_act" | "peerwork_availability" | "peerwork_member_name"
                        | "peerwork_subscriptions" | "peerwork_recover");
                    (ordinary_read || ordinary_work).then_some(name)
                })
                .map(|tool| format!("mcp_{name}_{tool}"))
                .collect();
        } else if config.get("mcp_server").is_some() {
            return Err("HOST_CONFIG_INVALID");
        }
        Ok(Self { conversation: conversation.into(), working_directory: working.into(), mcp, exact_tools })
    }

    pub(super) fn initialize(&self) -> Value {
        json!({"jsonrpc":"2.0","id":INITIALIZE,"method":"initialize","params":{
            "protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"peerwork","version":env!("CARGO_PKG_VERSION")}
        }})
    }

    pub(super) fn resume(&self) -> Value {
        json!({"jsonrpc":"2.0","id":RESUME,"method":"session/resume","params":{
            "sessionId":self.conversation,"cwd":self.working_directory,"mcpServers":self.mcp
        }})
    }

    pub(super) fn prompt(&self, id: u64, rendered: &str) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":"session/prompt","params":{
            "sessionId":self.conversation,"prompt":[{"type":"text","text":rendered}]
        }})
    }

    pub(super) fn event(&self, value: &Value) -> R<Event> {
        if value["jsonrpc"] != "2.0" {
            return Err("HOST_RESPONSE_INVALID");
        }
        let params = &value["params"];
        if let Some(method) = value["method"].as_str() {
            if let Some(id) = value.get("id") {
                if !(id.is_number() || id.as_str().is_some_and(|id| id.len() <= 128)) {
                    return Err("HOST_RESPONSE_INVALID");
                }
                let action = if method == "session/request_permission" {
                    // The executable and tools come from the selected original
                    // local installation, never from a prompt or display title.
                    let selected = if params["sessionId"] == self.conversation
                        && params["toolCall"]["name"].as_str().is_some_and(|name|
                            self.exact_tools.iter().any(|tool| tool == name))
                    {
                        params["options"].as_array().and_then(|choices| choices.iter().find_map(|option| {
                            (option["kind"] == "allow_once").then(|| option["optionId"].as_str())
                                .flatten().filter(|value| !value.is_empty() && value.len() <= 128).map(str::to_owned)
                        }))
                    } else {
                        None
                    };
                    Request::Permission(selected)
                } else {
                    Request::Unsupported
                };
                return Ok(Event::Request { id: id.clone(), action });
            }
            if method == "session/update" && params["sessionId"] == self.conversation
                && matches!(params["update"]["sessionUpdate"].as_str(),
                    Some("agent_message_chunk" | "agent_thought_chunk" | "tool_call" | "tool_call_update"))
            {
                return Ok(Event::TurnUpdate);
            }
            return Ok(Event::Ignore);
        }
        let id = value["id"].as_u64().ok_or("HOST_RESPONSE_INVALID")?;
        let result = &value["result"];
        let success = value.get("error").is_none() && result.is_object();
        Ok(match id {
            INITIALIZE => Event::Initialized(if success && result["protocolVersion"] == 1
                && result["agentCapabilities"]["sessionCapabilities"]["resume"].is_object() {
                Ok(())
            } else {
                Err(rejection(value, "AGY_ACP_RESUME_UNSUPPORTED"))
            }),
            RESUME => Event::Resumed(if success && result.get("sessionId")
                .is_none_or(|session| session == &self.conversation) {
                Ok(())
            } else {
                Err(rejection(value, "AGY_ACP_ORIGINAL_SESSION_UNAVAILABLE"))
            }),
            _ => Event::TurnEnd(id, success && matches!(result["stopReason"].as_str(),
                Some("end_turn" | "max_tokens" | "max_turn_requests" | "refusal"))),
        })
    }
}

fn rejection(value: &Value, default: &'static str) -> &'static str {
    let error = &value["error"];
    let classified = crate::host_recovery_policy::rpc_error(error);
    if classified == "HOST_AUTHENTICATION_FAILED" || error["message"].as_str().is_some_and(|message|
        message.eq_ignore_ascii_case("Authentication required")) {
        "HOST_AUTHENTICATION_FAILED"
    } else if classified == "HOST_SESSION_OWNERSHIP_CONFLICT" {
        "AGY_STDIO_SESSION_ALREADY_OWNED"
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bound_native_tool_gets_once_permission_during_an_active_turn() {
        let root = crate::test_support::protected_test_dir();
        let config = json!({"mcp_server":"peerwork-1234567890abcdef", "acp_client":{
            "registry":root.path(),"participant":"original-peer","workspace":"W".repeat(43)
        }});
        let session = Session::new(&config, "original-session", root.path().to_str().unwrap()).unwrap();
        let request = |session_id: &str, name: &str, active| {
            let event = session.event(&json!({"jsonrpc":"2.0","id":"permission-1",
                "method":"session/request_permission","params":{"sessionId":session_id,
                "toolCall":{"name":name,"title":"mcp_peerwork_1234567890abcdef_peerwork_inbox"},
                "options":[{"kind":"allow_always","optionId":"all"},{"kind":"allow_once","optionId":"once"}]}})).unwrap();
            let Event::Request {id,action} = event else { panic!("expected request"); };
            action.respond(id, active)["result"]["outcome"].clone()
        };
        let inbox = "mcp_peerwork_1234567890abcdef_peerwork_inbox";
        assert_eq!(request("original-session", inbox, true), json!({"outcome":"selected","optionId":"once"}));
        assert_eq!(request("another-session", inbox, true), json!({"outcome":"cancelled"}));
        assert_eq!(request("original-session", "run_command", true), json!({"outcome":"cancelled"}));
        for action in ["connect", "connect_approve", "delivery", "manage", "listen"] {
            let name = format!("mcp_peerwork_1234567890abcdef_peerwork_{action}");
            assert_eq!(request("original-session", &name, true), json!({"outcome":"cancelled"}));
        }
        assert_eq!(request("original-session", inbox, false), json!({"outcome":"cancelled"}));
        assert_eq!(session.resume()["params"]["mcpServers"][0]["args"][4], "original-peer");
    }
}

impl Request {
    pub(super) fn respond(self, id: Value, active_turn: bool) -> Value {
        match self {
            Self::Permission(selection) => {
                let outcome = match selection.filter(|_| active_turn) {
                    Some(option) => json!({"outcome":"selected","optionId":option}),
                    None => json!({"outcome":"cancelled"}),
                };
                json!({"jsonrpc":"2.0","id":id,"result":{"outcome":outcome}})
            }
            Self::Unsupported => json!({"jsonrpc":"2.0","id":id,
                "error":{"code":-32601,"message":"Unsupported Peerwork ACP client method"}}),
        }
    }
}
