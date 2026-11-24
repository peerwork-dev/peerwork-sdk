//! One interpretation of current receiving and automatic-delivery evidence.
use serde_json::{json, Value};
pub(crate) const FRESH_MS: u64 = 10_000;
pub(crate) const PRESENTATION_PRESENCE_FEATURE: &str = "verified-presentation-presence-v1";
pub(crate) const PRESENTATION_WAIT_MS: u64 = 7_000;

/// Publish queue acceptance independently of the session's ability to run.
/// Current host health alone does not establish a successful live wake.
pub(crate) fn host_presence(health: &Value, delivery: &Value) -> Value {
    let queued = health["mode"] == "QUEUED_ONLY" || health["input_delivery"] == "DURABLE_QUEUE";
    let ready = delivery["state"] == "RUNNING" && if queued {
        health["can_attempt"] == true || health["ready"] == true
    } else {
        health["ready"] == true && delivery["automatic_receiving"] == "VERIFIED"
    };
    json!({
        "mode": if queued { "QUEUED_ONLY" } else { "LIVE" },
        "ready": ready,
        "execution_state": health["execution_state"],
    })
}

pub(crate) fn mcp_transport(transport: &str) -> bool {
    matches!(transport, "MCP_STDIO_CHANNEL" | "MCP_BACKGROUND_TOOL")
}

pub(crate) fn evaluate(receiver: &Value, notification: &Value, transport: &str, health: &Value) -> Value {
    let linked=receiver["receiver_link_verified"]==true && receiver["state"]=="RECEIVER_LINK_VERIFIED" && receiver["verification_failure"].is_null();
    let body=&receiver["presence"];let keys=body["key_current"]==true && matches!(body["body_key"]["state"].as_str(),Some("READY"|"NOT_REQUIRED"));
    let automatic=transport!="NATIVE_INBOX";
    let control=notification["control_state"].as_str().or_else(||notification["state"].as_str());
    let verified=control==Some("RUNNING") && (notification["historical_verification"]["state"]=="VERIFIED" || notification["automatic_receiving"]=="VERIFIED");
    let age=health["observation_age_ms"].as_u64().map(|age|age.saturating_add(health["coordinator_age_ms"].as_u64().unwrap_or(0)));
    let fresh=age.is_some_and(|age|age<FRESH_MS);
    let host_code=health["code"].as_str().or_else(||health["reason"].as_str());
    let blocked=matches!(health["state"].as_str(),Some("BLOCKED"|"FAILED"|"STOPPED"|"RECONNECTING")) || health["ready"]==false && health["can_attempt"]!=true;
    let background = transport == "MCP_BACKGROUND_TOOL";
    let waiting_read = background && health["notification_read_pending"] == true;
    let needs_listener = background && health["code"] == "BACKGROUND_LISTEN_NOT_ARMED";
    let capable=if mcp_transport(transport) {
        fresh && !waiting_read && !needs_listener
            && !matches!(health["state"].as_str(),None|Some("UNKNOWN"|"BLOCKED"|"STARTING"|"STOPPED"|"RECOVERING"|"WAITING_HOST"))
    } else { fresh && (health["ready"]==true || health["can_attempt"]==true) };
    let (state,code)=if receiver["state"]=="LOCAL_STOPPED" {("STOPPED","RECEIVER_STOPPED")}
        else if automatic && control==Some("PAUSED") {("PAUSED","DELIVERY_PAUSED")}
        else if !receiver["verification_failure"].is_null() || receiver["state"]=="BLOCKED" {("BLOCKED",receiver["code"].as_str().unwrap_or("RECEIVER_NOT_VERIFIED"))}
        else if receiver["state"]=="RECONNECTING" {("RECOVERING",receiver["code"].as_str().unwrap_or("RECEIVER_RECONNECTING"))}
        else if !linked {("UNKNOWN",receiver["code"].as_str().unwrap_or("RECEIVER_NOT_VERIFIED"))}
        else if !automatic {("READY","READY")}
        else if !keys {("BLOCKED","BODY_KEYS_NOT_READY")}
        else if health["state"]=="RECOVERING" {("RECOVERING",host_code.unwrap_or("HOST_RECONNECTING"))}
        else if health["state"]=="WAITING_HOST" {("WAITING_HOST",host_code.unwrap_or("HOST_NOT_READY"))}
        else if blocked {("BLOCKED",host_code.unwrap_or("HOST_NOT_READY"))}
        else if waiting_read {("WAITING_HOST","BACKGROUND_NOTIFICATION_READ_PENDING")}
        else if needs_listener {("WAITING_HOST","BACKGROUND_LISTEN_NOT_ARMED")}
        else if !capable {("UNKNOWN",host_code.unwrap_or("CURRENT_TRANSPORT_OBSERVATION_UNAVAILABLE"))}
        // Only the active Channel frontend can qualify its own session. Native
        // setup observations still describe their original local inbox proof.
        else if mcp_transport(transport) && health.get("session_receiving").is_some() && health["session_receiving"]!="VERIFIED" {("VERIFYING","CURRENT_CHANNEL_READ_NOT_OBSERVED")}
        else if !verified {("VERIFYING","DELIVERY_SELF_TEST_PENDING")}
        else {("READY","READY")};
    json!({"state":state,"code":code,"receiver_link_verified":linked,"body_keys_ready":keys,
        "transport":transport,"transport_ready":capable&&!blocked,
        "retry_at_ms":health["retry_at_ms"],"failure":health["failure"],"phase":health["phase"],"observation_age_ms":age,
        "automatic_receiving":if !automatic{"NOT_CONFIGURED"}else if state=="READY"{"VERIFIED"}else{state},
        "last_verified_at":notification["last_verified_at"],"verification_evidence":"BOUND_LOCAL_INBOX_READ",
        "verification_scope":"HISTORICAL_SELECTED_DESTINATION","acceptance":if !automatic{"LOCAL_INBOX"}else if background{"BACKGROUND_TOOL_OUTPUT"}else if transport=="MCP_STDIO_CHANNEL"{"CHANNEL_OUTPUT"}else if health["can_attempt"]==true && health["ready"]!=true{"QUEUED_ONLY"}else{"HOST_INPUT_CAPABILITY"},"model_response":"NOT_ATTESTED",
        "recovery":if matches!(state,"BLOCKED"|"RECOVERING"|"WAITING_HOST"){crate::host_recovery_policy::diagnostic(code)}else{Value::Null},
        "next_action":match state {"READY"=>"CONTINUE_COLLABORATION","PAUSED"=>"RESUME_WHEN_REQUESTED","STOPPED"=>"RESTART_ORIGINAL_RECEIVER_WHEN_REQUESTED","VERIFYING" if code=="CURRENT_CHANNEL_READ_NOT_OBSERVED"=>"OBSERVE_CURRENT_CHANNEL_BATCH_OR_RUN_DELIVERY_SELF_TEST","VERIFYING"=>"OBSERVE_EXISTING_SELF_TEST",_=>crate::host_recovery_policy::action(code)}})
}

/// A source configured without a destination adopts the verified destination,
/// never another scope or generation. Keep full WatchOptions equality.
pub(crate) fn source_matches(source: &Value, binding: &Value, host: &Value) -> bool {
    let mut expected=source.clone();
    if expected["host_destination"].is_null() && binding["host_destination"].is_string() {
        expected["host_destination"]=if host["destination_digest"].is_string(){host["destination_digest"].clone()}
            else{let Ok(destination)=crate::participant_inbox::HostBinding::new(host["destination"].clone()) else{return false;};json!(destination.digest)};
    }
    expected==*binding
}

pub(crate) fn host_observation(host: &Value) -> Value {
    let mut value=host["host_observation"].clone();
    if !value.is_object(){value=json!({});}
    if matches!(host["state"].as_str(),Some("BLOCKED"|"FAILED"|"STOPPED"|"RECONNECTING"|"RECOVERING"|"WAITING_HOST")) {
        value["state"]=host["state"].clone();value["code"]=host["code"].clone();value["ready"]=json!(false);
    }
    value["phase"]=host["diagnostic"]["failure_phase"].clone();
    value
}

#[cfg(test)] mod tests {
    use super::*;
    fn receiver()->Value{json!({"state":"RECEIVER_LINK_VERIFIED","receiver_link_verified":true,"presence":{"key_current":true,"body_key":{"state":"READY"}}})}
    fn verified()->Value{json!({"state":"RUNNING","automatic_receiving":"VERIFIED","last_verified_at":123})}
    #[test]
    fn member_presence_separates_live_host_proof_from_known_queue_acceptance() {
        let live = json!({"mode":"LIVE","ready":true,"execution_state":"IDLE"});
        let queued = json!({"mode":"LIVE","ready":false,"can_attempt":true,
            "input_delivery":"DURABLE_QUEUE","execution_state":"UNKNOWN"});
        let app = json!({"mode":"QUEUED_ONLY","ready":false,"can_attempt":true,"execution_state":"UNKNOWN"});
        let wrong_codex = json!({"mode":"LIVE","ready":false,"reason":"HOST_SESSION_NOT_LOADED","execution_state":"UNKNOWN"});
        assert_eq!(host_presence(&live, &verified())["ready"], true);
        assert_eq!(host_presence(&live, &json!({"state":"RUNNING","automatic_receiving":"VERIFYING"}))["ready"], false);
        assert_eq!(host_presence(&wrong_codex, &verified())["ready"], false);
        for health in [queued, app] {
            assert_eq!(host_presence(&health, &verified())["mode"], "QUEUED_ONLY");
            assert_eq!(host_presence(&health, &verified())["ready"], true);
            assert_eq!(host_presence(&health, &json!({"state":"PAUSED"}))["ready"], false);
        }
    }
    #[test] fn historical_success_cannot_override_current_host_failure_or_stale_health() {
        let r=receiver();let n=verified();
        let ready=json!({"ready":true,"observation_age_ms":0});
        assert_eq!(evaluate(&r,&n,"HOST_PUSH",&ready)["state"],"READY");
        let failed=json!({"state":"BLOCKED","ready":false,"code":"HOST_SESSION_OWNERSHIP_CONFLICT"});
        let v=evaluate(&r,&n,"HOST_PUSH",&failed);assert_eq!(v["state"],"BLOCKED");assert_eq!(v["last_verified_at"],123);assert_eq!(v["next_action"],"VERIFY_SELECTED_CODEX_ROUTE_AND_ORIGINAL_SESSION_OWNER");
        assert_eq!(v["recovery"]["exit_required"],"NOT_DETERMINED");
        let stale=json!({"ready":true,"observation_age_ms":10_000});assert_eq!(evaluate(&r,&n,"HOST_PUSH",&stale)["state"],"UNKNOWN");
        assert_eq!(evaluate(&r,&n,"NATIVE_INBOX",&failed)["state"],"READY");
    }
    #[test] fn channel_and_queued_contracts_do_not_require_a_codex_host_or_attest_model_wake() {
        let channel=json!({"state":"WAITING_READ","observation_age_ms":2,"session_receiving":"VERIFIED"});
        let v=evaluate(&receiver(),&verified(),"MCP_STDIO_CHANNEL",&channel);assert_eq!(v["state"],"READY");assert_eq!(v["model_response"],"NOT_ATTESTED");
        let mut restarted=channel.clone();restarted["session_receiving"]=Value::Null;
        assert_eq!(evaluate(&receiver(),&verified(),"MCP_STDIO_CHANNEL",&restarted)["code"],"CURRENT_CHANNEL_READ_NOT_OBSERVED");
        let queued=json!({"ready":false,"can_attempt":true,"observation_age_ms":0});assert_eq!(evaluate(&receiver(),&verified(),"HOST_PUSH",&queued)["state"],"READY");
        for state in ["STOPPED","RECONNECTING","BLOCKED","FAILED"] {
            let mut unavailable=queued.clone();unavailable["state"]=json!(state);
            let current=evaluate(&receiver(),&verified(),"HOST_PUSH",&unavailable);
            assert_eq!(current["state"],"BLOCKED");assert_eq!(current["transport_ready"],false);
        }
    }
}

/// Match the exact source, client generation and physical destination.
pub(crate) fn selected_host(binding:&Value, hosts:&[Value], name:&str, generation:Option<u64>)->Option<Value> {
    hosts.iter().find(|host|host["source_bindings"].as_array().is_some_and(|sources|sources.iter().any(|source|
        source["client"]==name && source["client_generation"]==json!(generation) && source_matches(&source["watch"],binding,host)))).cloned()
}
pub(crate) fn annotate_notification(value:&mut Value, current:&Value) {
    if !value.is_object(){return;}
    if value["historical_verification"].is_null(){value["historical_verification"]=json!({"state":if value["last_verified_at"].is_number(){"VERIFIED"}else{"UNCONFIRMED"},"at":value["last_verified_at"],"evidence":"BOUND_LOCAL_INBOX_READ"});}
    if value["control_state"].is_null(){value["control_state"]=value["state"].clone();}
    value["state"]=current["state"].clone();
    value["automatic_receiving"]=current["automatic_receiving"].clone();
    value["current_delivery"]=current.clone();
}

pub(crate) fn summarize(value:&mut Value){
    if let Some(observations)=value["observations"].as_array(){
        if let Some(current)=observations.iter().map(|v|&v["current_delivery"]).filter(|v|v.is_object()).min_by_key(|v|match v["state"].as_str(){Some("BLOCKED")=>0,Some("PAUSED"|"STOPPED")=>1,Some("UNKNOWN"|"VERIFYING")=>2,_=>3}).cloned(){
            value["state"]=current["state"].clone();value["code"]=current["code"].clone();value["next_action"]=current["next_action"].clone();
        }
    }
}
