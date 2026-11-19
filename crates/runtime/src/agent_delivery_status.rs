//! Read-only projection of selected current observations and saved setup intent.
use serde_json::{json, Value};

pub(crate) fn binding(context: &Value, scope: &Value) -> Value {
    json!({"actor_id":context["actor_id"],"origin":context["origin"],
        "workspace_id":scope["workspace_id"],"mailbox_id":scope["mailbox_id"],
        "membership_id":scope["membership_id"],
        "client_generation":context["receiving_binding"]["client_generation"],
        "client_name":context["receiving_binding"]["client_name"],
        "engine_digest":context["receiving_binding"]["engine_digest"],
        "state_binding":context["receiving_binding"]["state_binding"],
        "namespace":context["receiving_binding"]["namespace"]})
}
fn same_scope(a: &Value, b: &Value) -> bool {
    ["workspace_id", "mailbox_id", "membership_id"].iter()
        .all(|key| a[*key].is_string() && a[*key] == b[*key])
}
fn current(at: &Value, now: i64) -> bool {
    at.as_i64().is_some_and(|at| at <= now && now.saturating_sub(at) < 10_000)
}

pub(crate) fn refresh(context: &mut Value) {
    refresh_at(context, crate::participant_store::now());
}
fn refresh_at(context: &mut Value, now: i64) {
    let mut scopes = serde_json::Map::new();
    if let Some(selected) = context["scopes"].as_object() {
        for (alias, scope) in selected {
            let expected = binding(context, scope);
            let observations = context["delivery_observations"]["observations"].as_array();
            let observation = observations.and_then(|items| items.iter().find(|v| same_scope(&v["binding"], scope)
                && context["bindings"].as_array().is_some_and(|bindings|bindings.iter().any(|b|b==&v["binding"]))
                && (v["receiving_binding"].is_null() || ["client_name","client_generation","namespace","engine_digest","state_binding"].iter().all(|key|v["receiving_binding"][*key]==context["receiving_binding"][*key]))));
            let source = observation.filter(|v| context["receiving_status"].is_null() && current(&v["observed_at_ms"], now));
            let receiver = source.map(|v|v["receiver"].clone()).unwrap_or_else(||json!({"state":"UNKNOWN"}));
            let notification = source.map(|v|v["notification"].clone()).unwrap_or(Value::Null);
            let candidate = &context["host_channel"]["scopes"][alias];
            let channel_matches = candidate["binding"] == expected;
            let channel = if channel_matches && candidate["observation_age_ms"].as_u64().is_some_and(|age|age<10_000) {
                json!({"state":candidate["state"],"code":candidate["code"],"observation_age_ms":candidate["observation_age_ms"],"session_receiving":candidate["session_receiving"],
                    "retry_at_ms":candidate["retry_at_ms"],"failure":candidate["failure"]})
            } else { json!({"state":"UNKNOWN","reason":if candidate.is_null(){"NOT_OBSERVED"}else if !channel_matches{"BINDING_MISMATCH"}else{"STALE_OBSERVATION"}}) };
            let selected_binding=observation.map(|v|v["binding"].clone()).unwrap_or(Value::Null);
            let hosts=context["host_status"]["hosts"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            let selected_host=crate::delivery_health::selected_host(&selected_binding,hosts,context["receiving_binding"]["client_name"].as_str().unwrap_or_default(),context["receiving_binding"]["client_generation"].as_u64());
            let mut host=selected_host.clone().unwrap_or_else(||json!({"state":"UNKNOWN","reason":"EXACT_HOST_NOT_OBSERVED"}));
            host["observation"]=if host["host_observation"]["observation_age_ms"].as_u64().is_some_and(|age|age<crate::delivery_health::FRESH_MS){host["host_observation"].clone()}else{json!({"state":"UNKNOWN","reason":"FRESH_OBSERVATION_UNAVAILABLE"})};
            let transport=if selected_binding["host_destination"].is_string(){"HOST_PUSH"}
                else if channel_matches || source.is_some_and(|v|v["transport"]=="MCP_STDIO_CHANNEL"){"MCP_STDIO_CHANNEL"}else{"NATIVE_INBOX"};
            let health=if transport=="MCP_STDIO_CHANNEL"&&!candidate.is_null(){channel.clone()}
                else if let Some(host)=selected_host.as_ref(){crate::delivery_health::host_observation(host)}
                else{source.map(|v|v["transport_health"].clone()).unwrap_or_else(||json!({"state":"UNKNOWN"}))};
            let mut current=crate::delivery_health::evaluate(&receiver,&notification,transport,&health);
            if transport=="NATIVE_INBOX" && current["state"]=="READY"{current["state"]=json!("RECEIVING");}
            let state=current["state"].clone();
            scopes.insert(alias.clone(), json!({"binding":expected,"state":state,"transport":transport,
                "observed_at_ms":observation.map(|v|&v["observed_at_ms"]),
                "receiver":receiver,"channel":channel,"target":host["target"],"host":host,
                "next_action":current["next_action"],"code":current["code"],"current_delivery":current,
                "delivery_control":notification.get("control_state").unwrap_or(&notification["state"]),
                "automatic_receiving":current["automatic_receiving"],
                "last_verified_at":notification["last_verified_at"],
                "model_response":"NOT_ATTESTED"}));
        }
    }
    let setups = context["onboarding"]["setups"].as_array().into_iter().flatten().map(|setup| {
        let matched = setup["actor_id"]==context["actor_id"] && setup["origin"]==context["origin"]
            && setup["receiving_scopes"].as_object().is_some_and(|saved|!saved.is_empty() && saved.iter().all(|(alias,scope)|
                scopes.get(alias).is_some_and(|v|same_scope(scope,&v["binding"]))));
        json!({"setup_id":setup["setup_id"],"saved_state":setup["state"],"blocker":setup["blocker"],
            "requested_objectives":setup["requested_objectives"],"receiving_scope":if matched{"MATCHED"}else{"UNKNOWN_OR_DIFFERENT"},
            "requested_host":setup["requested_host"],"host_objective":"NOT_RECONCILED_FROM_SCOPE_MATCH",
            "objectives_complete":setup["state"]=="LOCAL_CONFIGURED"})
    }).collect::<Vec<_>>();
    context["delivery_status"] = json!({"basis":"CURRENT_SELECTED_LOCAL_OBSERVATIONS","scopes":scopes,
        "setups":setups,"setup_state_changed":false,"model_response":"NOT_ATTESTED"});
}

/// The Claude frontend can refine the runtime's local polling observation with
/// its exact selected Channel projection. No extra runtime or service request.
pub(crate) fn refresh_delivery(value:&mut Value, channel:&Value) {
    let identity=json!({"actor_id":value["actor_id"],"origin":value["origin"]});
    if let Some(observations)=value["observations"].as_array_mut(){for observation in observations {
        if observation["transport"]=="HOST_PUSH"{continue;}
        let projects=channel["scopes"].as_object().is_some_and(|scopes|scopes.values().any(|candidate|same_scope(&candidate["binding"],&observation["binding"])));
        if observation["transport"]!="MCP_STDIO_CHANNEL"&&!projects{continue;}
        observation["transport"]=json!("MCP_STDIO_CHANNEL");
        let mut context=identity.clone();context["receiving_binding"]=observation["receiving_binding"].clone();
        let expected=binding(&context,&observation["binding"]);
        let candidate=channel["scopes"].as_object().and_then(|scopes|scopes.values().find(|candidate|candidate["binding"]==expected));
        let health=candidate.cloned().unwrap_or_else(||json!({"state":"UNKNOWN","reason":"CHANNEL_SOURCE_NOT_OBSERVED"}));
        let current=crate::delivery_health::evaluate(&observation["receiver"],&observation["notification"],"MCP_STDIO_CHANNEL",&health);
        observation["current_delivery"]=current.clone();observation["transport_health"]=health;
        crate::delivery_health::annotate_notification(&mut observation["notification"],&current);
    }}
    // Keep destination control and current readiness separate, but coherent.
    if let Some(destinations)=value["destinations"].as_array().cloned(){
        value["destinations"]=json!(destinations.into_iter().map(|mut destination|{
            let current=value["observations"].as_array().into_iter().flatten().filter(|observation|
                observation["binding"]["host_destination"].as_str().unwrap_or("CLAUDE_CHANNEL")==destination["destination_digest"].as_str().unwrap_or_default())
                .map(|v|v["current_delivery"].clone()).min_by_key(|v|if v["state"]=="READY"{2}else if v["state"]=="BLOCKED"{0}else{1});
            if let Some(current)=current{crate::delivery_health::annotate_notification(&mut destination,&current);}
            destination
        }).collect::<Vec<_>>());
    }
    crate::delivery_health::summarize(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Value {
        let scope=json!({"workspace_id":"w","mailbox_id":"m","membership_id":"g"});
        json!({"actor_id":"a","origin":"https://example.invalid/","scopes":{"space":scope},"bindings":[scope],
            "receiving_binding":{"client_generation":2,"client_name":"original"},
            "delivery_observations":{"observations":[{"binding":scope,"observed_at_ms":1000,
                "receiver":{"state":"RECEIVER_LINK_VERIFIED","receiver_link_verified":true,"presence":{"key_current":true,"body_key":{"state":"READY"}}},
                "transport":"MCP_STDIO_CHANNEL","transport_health":{"state":"POLLING","observation_age_ms":0},
                "notification":{"state":"RUNNING","automatic_receiving":"VERIFIED"}}]},
            "onboarding":{"setups":[{"setup_id":"pending","actor_id":"a","origin":"https://example.invalid/",
                "receiving_scopes":{"space":scope},"state":"PENDING","blocker":{"code":"ROLE_APPROVAL_REQUIRED"},
                "requested_objectives":{"receive":true,"protocol_roles":["worker"]}}]}})
    }
    #[test]
    fn current_receiving_does_not_complete_pending_setup_or_attest_channel_wake() {
        let mut value=context(); let saved=value["onboarding"].clone();
        let bound=binding(&value,&value["scopes"]["space"]);
        value["host_channel"]=json!({"notifications_written":8,"scopes":{"space":{"binding":bound,"state":"WAITING_READ","observation_age_ms":5,"session_receiving":"VERIFIED"}}});
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"READY");
        assert_eq!(value["delivery_status"]["scopes"]["space"]["transport"],"MCP_STDIO_CHANNEL");
        assert_eq!(value["delivery_status"]["setups"][0]["objectives_complete"],false);
        assert_eq!(value["delivery_status"]["setups"][0]["receiving_scope"],"MATCHED");
        assert_eq!(value["delivery_status"]["model_response"],"NOT_ATTESTED");assert_eq!(value["onboarding"],saved);
    }
    #[test]
    fn changed_binding_stale_unknown_and_pause_remain_distinct() {
        let mut value=context();let mut bound=binding(&value,&value["scopes"]["space"]);bound["client_generation"]=json!(1);
        value["host_channel"]=json!({"scopes":{"space":{"binding":bound,"state":"READY","observation_age_ms":0}}});
        value["onboarding"]["setups"][0]["receiving_scopes"]["space"]["membership_id"]=json!("old");
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["channel"]["reason"],"BINDING_MISMATCH");
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"UNKNOWN","a different Channel generation cannot borrow runtime polling health");
        assert_eq!(value["delivery_status"]["setups"][0]["receiving_scope"],"UNKNOWN_OR_DIFFERENT");
        value["delivery_observations"]["observations"][0]["notification"]["state"]=json!("PAUSED");refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"PAUSED");
        refresh_at(&mut value,11000);assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"UNKNOWN");
        value["delivery_observations"]=Value::Null;refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"UNKNOWN");
    }
    #[test]
    fn stopped_receiver_and_stale_channel_never_turn_into_ready_setup() {
        let mut value=context();let bound=binding(&value,&value["scopes"]["space"]);
        value["host_channel"]=json!({"scopes":{"space":{"binding":bound,"state":"WAITING_READ","observation_age_ms":10000}}});
        value["delivery_observations"]["observations"][0]["receiver"]["state"]=json!("LOCAL_STOPPED");
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"STOPPED");
        assert_eq!(value["delivery_status"]["scopes"]["space"]["channel"]["reason"],"STALE_OBSERVATION");
        assert_eq!(value["delivery_status"]["setups"][0]["objectives_complete"],false);
        value["delivery_observations"]["observations"][0]["binding"]["host_destination"]=json!("different");
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"UNKNOWN");
    }

    #[test]
    fn host_status_cannot_cross_client_generation() {
        let mut value=context();let scope=value["scopes"]["space"].clone();
        value["host_status"]=json!({"hosts":[{"state":"RUNNING","selection_id":"selected-session",
            "host_observation":{"ready":true,"observation_age_ms":1},
            "source_bindings":[{"watch":scope,"client":"original","client_generation":1}]}]});
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["state"],"UNKNOWN");
        value["host_status"]["hosts"][0]["source_bindings"][0]["client_generation"]=json!(2);
        value["host_status"]["hosts"][0]["target"]=json!({"kind":"opencode","session_id":"ses_selected","directory":"/original/project","caller_session_match":"NOT_ATTESTED"});
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["selection_id"],"selected-session");
        assert_eq!(value["delivery_status"]["scopes"]["space"]["target"]["session_id"],"ses_selected");
        assert_eq!(value["delivery_status"]["scopes"]["space"]["target"]["caller_session_match"],"NOT_ATTESTED");
        value["host_status"]["hosts"][0]["source_bindings"][0]["watch"]["host_destination"]=json!("other-host");
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["state"],"UNKNOWN");
        value["host_status"]["hosts"][0]["source_bindings"][0]["watch"]=value["scopes"]["space"].clone();
        value["host_status"]["hosts"][0]["host_observation"]["observation_age_ms"]=json!(10000);
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["observation"]["state"],"UNKNOWN");
        value["bindings"][0]["host_destination"]=json!("selected-digest");
        value["delivery_observations"]["observations"][0]["binding"]=value["bindings"][0].clone();
        value["host_status"]["hosts"][0]["destination_digest"]=json!("selected-digest");
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["selection_id"],"selected-session","sanitized runtime status retains the verified physical destination digest");
    }

    #[test]
    fn delivery_status_cannot_reuse_another_channel_generation() {
        let context=context();let mut old=binding(&context,&context["scopes"]["space"]);old["client_generation"]=json!(1);
        let mut delivery=json!({"actor_id":context["actor_id"],"origin":context["origin"],"observations":context["delivery_observations"]["observations"]});
        delivery["observations"][0]["receiving_binding"]=context["receiving_binding"].clone();
        refresh_delivery(&mut delivery,&json!({"scopes":{"space":{"binding":old,"state":"WAITING_READ","observation_age_ms":0}}}));
        assert_eq!(delivery["state"],"UNKNOWN");assert_eq!(delivery["observations"][0]["transport_health"]["reason"],"CHANNEL_SOURCE_NOT_OBSERVED");
        delivery["observations"][0]["transport"]=json!("NATIVE_INBOX");
        refresh_delivery(&mut delivery,&json!({"scopes":{"space":{"binding":binding(&context,&context["scopes"]["space"]),"state":"STARTING","observation_age_ms":0}}}));
        assert_eq!(delivery["state"],"UNKNOWN");assert_eq!(delivery["observations"][0]["transport"],"MCP_STDIO_CHANNEL");
    }

}
