//! OpenCode V2 selection uses its original service, not a replacement server.
use super::*;

pub(super) async fn select(connect:&Connect,participant:&str,workspace:&str,project:&Path,values:&BTreeMap<String,String>)->Result<Option<Value>> {
    let explicit=values.contains_key("--opencode-session")||values.contains_key("--opencode-service");
    if explicit && (values.contains_key("--tools-only") || values.contains_key("--no-receive") || values.contains_key("--program")
        || values.contains_key("--host") || values.get("--receive-mode").is_some_and(|m|m!="push")) {return Err(local("SELECT_ONE_HOST_ADAPTER"))}
    if !explicit && (values.contains_key("--host") || values.contains_key("--tools-only") || values.contains_key("--no-receive")
        || values.contains_key("--program") || values.get("--receive-mode").is_some_and(|m|m=="inbox")) {return Ok(None)}
    let original=connect.registry.active_by_scope.get(&format!("{participant}:{workspace}")).and_then(|id|connect.registry.setups.get(id));
    if !explicit && original.is_some() {return Ok(None)}
    if !explicit && connect.registry.setups.values().any(|s|s.desired.participant==participant
        && s.desired.workspace_id==workspace && s.result["state"]=="PENDING" && s.desired.host.is_some()) {return Ok(None)}
    let file=match values.get("--opencode-service") {
        Some(path)=>std::path::absolute(path).map_err(|_|local("OPENCODE_SERVICE_SELECTION_REQUIRED"))?,
        None=>crate::communication_host::opencode::default_service_file().map_err(local)?,
    };
    let file=std::fs::canonicalize(&file).map_err(|_|local("OPENCODE_SERVICE_UNAVAILABLE"))?;
    let directory=std::fs::canonicalize(project).map_err(|_|local("PROJECT_CONTEXT_INVALID"))?;
    let directory=directory.to_str().ok_or_else(||local("PROJECT_CONTEXT_INVALID"))?.to_owned();
    let selected=values.get("--opencode-session").cloned();
    let observed_file=file.clone();let observed_directory=directory.clone();
    let executor=tokio::runtime::Handle::current();
    let observation=tokio::task::spawn_blocking(move|| {
        let budget=crate::communication_host::operation::Budget::new(std::time::Duration::from_secs(10));
        let http=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().map_err(|_|"HOST_CONFIG_INVALID")?;
        let client=crate::communication_host::opencode::Client::open(&observed_file,http,executor,budget)?;
        if let Some(id)=selected {client.session(&id,&observed_directory).map(|_|json!({"selected":id}))}
        else{client.sessions(&observed_directory)}
    }).await.map_err(|_|local("HOST_TASK_FAILED"))?.map_err(local)?;
    if let Some(session)=observation["selected"].as_str() {
        return Ok(Some(json!({"kind":"opencode","service_file":file,"session_id":session,"directory":directory})))
    }
    let data=observation.get("data").unwrap_or(&observation);
    let sessions=data.as_array().or_else(||data["items"].as_array()).or_else(||data["sessions"].as_array()).ok_or_else(||local("HOST_RESPONSE_INVALID"))?;
    let candidates=sessions.iter().take(16).filter(|s|s["location"]["directory"]==directory&&s["time"]["archived"].is_null()).filter_map(|s| {
        let id=s["id"].as_str()?;
        let mut argv=vec![json!("peerwork"),json!("connect"),json!("--local"),json!(connect.directory),json!("--participant"),json!(participant),json!("--project"),json!(directory),json!("--workspace"),json!(workspace),json!("--install"),json!("opencode"),json!("--opencode-service"),json!(file),json!("--opencode-session"),json!(id)];
        if values.contains_key("--new"){argv.push(json!("--new"));}
        Some(json!({"session_id":id,"title":s["title"],"continuation_argv":argv}))
    }).collect::<Vec<_>>();
    let mut error=local("OPENCODE_SESSION_SELECTION_REQUIRED");
    error.recovery="SELECT_EXACT_EXISTING_OPENCODE_SESSION".into();
    error.details=Some(json!({"candidates":candidates,"next_action":"SELECT_EXACT_EXISTING_SESSION","creates_session":false,"bounded":true,"more":!observation["cursor"]["next"].is_null()}));
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn opencode_saved_pending_host_and_explicit_manual_intent_do_not_rediscover_or_replace_the_host() {
        let root=crate::test_support::protected_test_dir();
        let mut connect=Connect::open(root.path()).unwrap();let workspace="W".repeat(43);
        let saved:Setup=serde_json::from_value(json!({"desired":{"setup_id":"pending","participant":"peer","workspace_id":workspace,"host":"original"},
            "registration":{"origin":"http://127.0.0.1:1","actor_id":"A".repeat(43),"endpoint_path":root.path().join("original.json")},
            "digest":"a".repeat(64),"profile":null,"result":{"state":"PENDING"}})).unwrap();
        connect.registry.setups.insert("pending".into(),saved);
        let mut values=BTreeMap::from([("--install".into(),"opencode".into())]);
        assert!(select(&connect,"peer",&workspace,root.path(),&values).await.unwrap().is_none());
        values.insert("--tools-only".into(),String::new());
        assert!(select(&connect,"peer",&workspace,root.path(),&values).await.unwrap().is_none());
        values.insert("--opencode-session".into(),"ses_selected".into());
        assert_eq!(select(&connect,"peer",&workspace,root.path(),&values).await.unwrap_err().code,"SELECT_ONE_HOST_ADAPTER");
        assert_eq!(connect.registry.setups.len(),1);
    }
}
