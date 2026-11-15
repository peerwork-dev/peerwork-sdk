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
                && context["bindings"].as_array().is_some_and(|bindings|bindings.iter().any(|b|b==&v["binding"]))));
            let source = observation.filter(|v| context["receiving_status"].is_null() && current(&v["observed_at_ms"], now));
            let receiver = source.map(|v|v["receiver"].clone()).unwrap_or_else(||json!({"state":"UNKNOWN"}));
            let notification = source.map(|v|v["notification"].clone()).unwrap_or(Value::Null);
            let candidate = &context["host_channel"]["scopes"][alias];
            let channel_matches = candidate["binding"] == expected;
            let channel = if channel_matches && candidate["observation_age_ms"].as_u64().is_some_and(|age|age<10_000) {
                json!({"state":candidate["state"],"code":candidate["code"],"observation_age_ms":candidate["observation_age_ms"]})
            } else { json!({"state":"UNKNOWN","reason":if candidate.is_null(){"NOT_OBSERVED"}else if !channel_matches{"BINDING_MISMATCH"}else{"STALE_OBSERVATION"}}) };
            let host = context["host_status"]["hosts"].as_array().and_then(|hosts|hosts.iter().find(|host|
                host["source_bindings"].as_array().is_some_and(|sources|sources.iter().any(|source|
                    same_scope(&source["watch"],scope) && source["client"].is_string()
                    && context["bindings"].as_array().is_some_and(|bindings|bindings.iter().any(|b|b==&source["watch"]))
                    && source["client_generation"]==context["receiving_binding"]["client_generation"]
                    && source["client"]==context["receiving_binding"]["client_name"]))));
            let host = host.map(|host|json!({"state":host["state"],"code":host["code"],
                "selection_id":host["selection_id"],"dispatcher_running":host["dispatcher_running"],
                "observation":if host["host_observation"]["observation_age_ms"].as_u64().is_some_and(|age|age<10_000){host["host_observation"].clone()}else{json!({"state":"UNKNOWN","reason":"FRESH_OBSERVATION_UNAVAILABLE"})},
                "model_response":"NOT_ATTESTED"})).unwrap_or_else(||json!({"state":"UNKNOWN","reason":"EXACT_HOST_NOT_OBSERVED"}));
            let bound = context["bindings"].as_array().is_some_and(|items|items.iter().any(|v|same_scope(v,scope)));
            let state = if !bound || source.is_none() {"UNKNOWN"}
                else if notification["state"]=="PAUSED" {"PAUSED"}
                else if receiver["state"]=="LOCAL_STOPPED" {"STOPPED"}
                else if !receiver["verification_failure"].is_null() || receiver["state"]=="BLOCKED" {"BLOCKED"}
                else if receiver["receiver_link_verified"]==true && receiver["state"]=="RECEIVER_LINK_VERIFIED" {"RECEIVING"}
                else {"PENDING"};
            let transport = if context["bindings"].as_array().is_some_and(|items|items.iter().any(|v|same_scope(v,scope)&&v["host_destination"].is_string())) {"HOST_PUSH"}
                else if channel_matches {"MCP_STDIO_CHANNEL"} else {"NATIVE_INBOX"};
            scopes.insert(alias.clone(), json!({"binding":expected,"state":state,"transport":transport,
                "observed_at_ms":observation.map(|v|&v["observed_at_ms"]),
                "receiver":receiver,"channel":channel,"host":host,
                "next_action":match state {"RECEIVING"=>"CONTINUE_COLLABORATION","PAUSED"=>"RESUME_WHEN_REQUESTED","STOPPED"=>"RESTART_ORIGINAL_RECEIVER_WHEN_REQUESTED","BLOCKED"=>"INSPECT_CURRENT_BLOCKER",_=>"REOBSERVE_ORIGINAL_BINDING"},
                "delivery_control":notification["state"],
                "automatic_receiving":notification["automatic_receiving"],
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

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Value {
        let scope=json!({"workspace_id":"w","mailbox_id":"m","membership_id":"g"});
        json!({"actor_id":"a","origin":"https://example.invalid/","scopes":{"space":scope},"bindings":[scope],
            "receiving_binding":{"client_generation":2,"client_name":"original"},
            "delivery_observations":{"observations":[{"binding":scope,"observed_at_ms":1000,
                "receiver":{"state":"RECEIVER_LINK_VERIFIED","receiver_link_verified":true,"presence":{"key_current":true}},
                "notification":{"state":"RUNNING","automatic_receiving":"VERIFIED"}}]},
            "onboarding":{"setups":[{"setup_id":"pending","actor_id":"a","origin":"https://example.invalid/",
                "receiving_scopes":{"space":scope},"state":"PENDING","blocker":{"code":"ROLE_APPROVAL_REQUIRED"},
                "requested_objectives":{"receive":true,"protocol_roles":["worker"]}}]}})
    }
    #[test]
    fn current_receiving_does_not_complete_pending_setup_or_attest_channel_wake() {
        let mut value=context(); let saved=value["onboarding"].clone();
        let bound=binding(&value,&value["scopes"]["space"]);
        value["host_channel"]=json!({"notifications_written":8,"scopes":{"space":{"binding":bound,"state":"WAITING_READ","observation_age_ms":5}}});
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["state"],"RECEIVING");
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
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["selection_id"],"selected-session");
        value["host_status"]["hosts"][0]["source_bindings"][0]["watch"]["host_destination"]=json!("other-host");
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["state"],"UNKNOWN");
        value["host_status"]["hosts"][0]["source_bindings"][0]["watch"]=value["scopes"]["space"].clone();
        value["host_status"]["hosts"][0]["host_observation"]["observation_age_ms"]=json!(10000);
        refresh_at(&mut value,1001);
        assert_eq!(value["delivery_status"]["scopes"]["space"]["host"]["observation"]["state"],"UNKNOWN");
    }

}
