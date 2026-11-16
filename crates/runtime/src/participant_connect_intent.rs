//! Ordinary connection intent selects original saved work; transaction IDs stay internal.
use super::*;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectIntent {
    #[serde(default)] pub participant: Option<String>,
    #[serde(default)] pub workspace_id: Option<String>,
    #[serde(default, rename="new")] pub new_peer: bool,
    #[serde(default)] pub host: Option<String>,
    #[serde(default)] pub send: Option<bool>,
    #[serde(default)] pub receive: Option<bool>,
    #[serde(default)] pub receive_mode: Option<ReceiveMode>,
    #[serde(default)] pub require_body_keys: Option<bool>,
    #[serde(default)] pub request_membership: Option<bool>,
}

impl ConnectIntent {
    fn matches(&self, request:&ConnectRequest)->bool {
        self.host.as_ref().is_none_or(|host|request.host.as_ref()==Some(host))
            && self.send.is_none_or(|v|v==request.send)
            && self.receive.is_none_or(|v|v==request.receive)
            && self.receive_mode.is_none_or(|v|Some(v)==request.receive_mode)
            && self.require_body_keys.is_none_or(|v|v==request.require_body_keys)
            && self.request_membership.is_none_or(|v|v==request.request_membership)
    }
    fn matches_selected(&self, request:&ConnectRequest, selected:Option<&ConnectRequest>)->bool {
        self.matches(request) && selected.is_none_or(|current|
            (self.send.is_some() || request.send==current.send)
            && (self.receive.is_some() || request.receive==current.receive)
            && (self.receive_mode.is_some() || request.receive_mode==current.receive_mode)
            && (self.host.is_some() || request.host==current.host)
            && (self.require_body_keys.is_some() || request.require_body_keys==current.require_body_keys)
            && (self.request_membership.is_some() || request.request_membership==current.request_membership)
            && request.alias==current.alias && request.protocols==current.protocols
            && request.management==current.management && request.contacts==current.contacts)
    }
}

impl Connect {
    pub fn resolve_input_selected(&self, input:ConnectInput, participant:Option<&str>, workspace:Option<&str>)->Result<(ConnectRequest,bool)> {
        match input {
            ConnectInput::Intent(mut intent)=>{
                if participant.is_some_and(|pin|intent.participant.as_deref().is_some_and(|p|p!=pin)){return Err(local("FRONTEND_IDENTITY_PIN_MISMATCH"));}
                if workspace.is_some_and(|pin|intent.workspace_id.as_deref().is_some_and(|w|w!=pin)){return Err(local("FRONTEND_WORKSPACE_PIN_MISMATCH"));}
                if let Some(pin)=participant{intent.participant=Some(pin.into());}
                if let Some(pin)=workspace{intent.workspace_id=Some(pin.into());}
                self.resolve_intent(intent, true)
            },
            other=>self.resolve_input(other),
        }
    }
    pub(super) fn resolve_intent(&self, intent:ConnectIntent, agent:bool)->Result<(ConnectRequest,bool)> {
        if intent.new_peer {
            let mut argv=vec![json!("peerwork"),json!("connect"),json!("--new")];
            if let Some(workspace)=&intent.workspace_id {if !token(workspace){return Err(local("CONNECT_ARGUMENT_INVALID"));}argv.extend([json!("--workspace"),json!(workspace)]);}
            let mut error=local("NEW_PEER_LOCAL_OWNER_REQUIRED");
            error.recovery="RUN_NATIVE_CONNECT_NEW".into();
            error.details=Some(json!({"next_actor":"LOCAL_RUNTIME_OWNER","argv":argv,"required_inputs":if intent.workspace_id.is_none(){json!(["workspace"])}else{json!([])},"service":"SELECTED_OR_HOSTED_DEFAULT","existing_identity_preserved":true,"owner_approval_required":false}));
            return Err(error);
        }
        let participant=match intent.participant.as_deref() {
            Some(handle)=>self.original_handle(Some(handle))?,
            None=>match self.selected_handle(None)? {Some(handle)=>Some(handle),None=>self.original_handle(None)?},
        }.ok_or_else(||local("LOCAL_SELECTION_REQUIRED"))?;
        let workspace=if let Some(workspace)=&intent.workspace_id {workspace.clone()}else{
            let spaces=self.registry.setups.values().filter(|s|s.desired.participant==participant)
                .map(|s|s.desired.workspace_id.clone()).chain(self.saved_codex_workspaces(&participant))
                .collect::<std::collections::BTreeSet<_>>();
            if spaces.len()!=1{return Err(local("WORKSPACE_SELECTION_REQUIRED"));}
            spaces.into_iter().next().unwrap()
        };
        if !token(&workspace){return Err(local("CONNECT_ARGUMENT_INVALID"));}
        if let Some(request)=self.saved_codex_intent(&participant,&workspace) {
            if intent.matches(&request){return Ok((request,true));}
            if self.codex_attachment_pending(&participant,&workspace){return Err(local("CODEX_ATTACHMENT_PENDING_RESUME_ORIGINAL_CHAT"));}
        }
        let active=self.registry.active_by_scope.get(&format!("{participant}:{workspace}")).and_then(|id|self.registry.setups.get(id));
        let matching_scope=|s:&&Setup|s.desired.participant==participant&&s.desired.workspace_id==workspace;
        let pending=self.registry.setups.values().filter(matching_scope)
            .filter(|s|s.result["state"]=="PENDING" && intent.matches_selected(&s.desired,active.map(|s|&s.desired)))
            .collect::<Vec<_>>();
        if pending.len()>1 {
            let mut error=local("CONNECT_PENDING_SELECTION_REQUIRED");error.recovery="SELECT_ORIGINAL_PENDING_CONNECTION".into();
            error.details=Some(json!({"candidates":pending.iter().map(|s|json!({"setup_id":s.desired.setup_id,"blocker":s.result["blocker"],"resume":{"request":{"resume_setup_id":s.desired.setup_id}}})).collect::<Vec<_>>() }));
            return Err(error);
        }
        if let Some(saved)=pending.first(){return Ok((saved.desired.clone(),true));}
        if let Some(saved)=active.filter(|s|intent.matches(&s.desired)){return Ok((saved.desired.clone(),true));}
        // Explicit changed fields amend a new intent, never overwrite its old transaction.
        // Omitted fields inherit deliberate restrictions on the selected installation.
        let mut request=active.map(|s|s.desired.clone()).unwrap_or_else(||ConnectRequest{
            setup_id:String::new(),participant:participant.clone(),workspace_id:workspace.clone(),alias:default_alias(),
            send:true,receive:true,receive_mode:None,require_body_keys:true,request_membership:true,
            protocols:vec![],management:vec![],contacts:vec![],host:None,
        });
        request.setup_id.clear();
        if let Some(value)=intent.send{request.send=value;}
        if let Some(value)=intent.receive{request.receive=value;if !value{request.receive_mode=None;request.host=None;}}
        if let Some(value)=intent.receive_mode{request.receive_mode=Some(value);}
        if let Some(value)=intent.require_body_keys{request.require_body_keys=value;}
        if let Some(value)=intent.request_membership{request.request_membership=value;}
        if let Some(value)=intent.host{request.host=Some(value);}
        let request=if agent{self.normalize_agent_request(request)?}else{self.normalize_request(request)?};
        Ok((request,false))
    }
}

#[cfg(test)]
#[path="participant_connect_intent_native_tests.rs"]
mod native_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn selected(root:&Path)->Connect {
        let mut connect=Connect::open(root).unwrap();
        connect.registry.participants.insert("peer".into(),Registration{origin:"https://example.invalid/".into(),actor_id:"A".repeat(43),endpoint_path:root.join("original.json")});
        connect.save().unwrap();connect
    }
    fn saved(connect:&mut Connect,id:&str,send:bool,receive:bool,state:&str)->ConnectRequest {
        let request:ConnectRequest=serde_json::from_value(json!({"setup_id":id,"participant":"peer","workspace_id":"W".repeat(43),"send":send,"receive":receive,"receive_mode":if receive{json!("INBOX")}else{Value::Null}})).unwrap();
        connect.begin_setup(&request,connect.registry.participants["peer"].clone(),false,None).unwrap();
        connect.registry.setups.get_mut(id).unwrap().result["state"]=json!(state);
        connect.registry.active_by_scope.insert(format!("peer:{}",request.workspace_id),id.into());connect.registry.active=Some(id.into());connect.save().unwrap();request
    }
    #[test]
    fn ordinary_wire_uses_intent_but_explicit_legacy_and_recovery_remain_exact() {
        for value in [json!({}),json!({"workspace_id":"W".repeat(43)}),json!({"new":true,"workspace_id":"W".repeat(43)})] {
            assert!(matches!(serde_json::from_value::<ConnectInput>(value).unwrap(),ConnectInput::Intent(_)));
        }
        assert!(matches!(serde_json::from_value::<ConnectInput>(json!({"setup_id":"saved","participant":"peer","workspace_id":"W".repeat(43)})).unwrap(),ConnectInput::Configure(_)));
        assert!(matches!(serde_json::from_value::<ConnectInput>(json!({"workspace_id":"W".repeat(43),"alias":"tasks"})).unwrap(),ConnectInput::Configure(_)));
        assert!(matches!(serde_json::from_value::<ConnectInput>(json!({"resume_setup_id":"saved"})).unwrap(),ConnectInput::Resume(_)));
        assert!(serde_json::from_value::<ConnectInput>(json!({"resume_setup_id":"saved","send":true})).is_err());
    }
    #[test]
    fn repeat_omits_flags_without_enlarging_manual_or_tools_only_selection() {
        for receive in [false,true] {
            let root=crate::test_support::protected_test_dir();let mut connect=selected(root.path());
            let original=saved(&mut connect,"original",false,receive,"LOCAL_CONFIGURED");
            let before=std::fs::read(root.path().join("connect.state")).unwrap();
            let (resolved,resume)=connect.resolve_input(serde_json::from_value(json!({})).unwrap()).unwrap();
            assert!(resume);assert!(resolved==original);
            assert_eq!(std::fs::read(root.path().join("connect.state")).unwrap(),before);
            let (changed,resume)=connect.resolve_input(serde_json::from_value(json!({"send":true})).unwrap()).unwrap();
            assert!(!resume);assert!(changed.send);assert_eq!(changed.receive,receive);assert!(changed.receive_mode==original.receive_mode);
            assert!(!changed.request_membership);assert!(!changed.require_body_keys);assert_ne!(changed.setup_id,original.setup_id);
            assert!(connect.registry.setups["original"].desired==original);
        }
    }
    #[test]
    fn new_scope_infers_collaboration_and_pending_selection_is_bounded_and_explicit() {
        let root=crate::test_support::protected_test_dir();let mut connect=selected(root.path());
        let (request,resume)=connect.resolve_input(serde_json::from_value(json!({"workspace_id":"W".repeat(43)})).unwrap()).unwrap();
        assert!(!resume);assert!(request.send&&request.receive&&request.require_body_keys&&request.request_membership);
        let first=saved(&mut connect,"first",false,true,"PENDING");
        let (resolved,resume)=connect.resolve_input(serde_json::from_value(json!({})).unwrap()).unwrap();assert!(resume);assert!(resolved==first);
        saved(&mut connect,"second",false,true,"PENDING");
        let error=connect.resolve_input(serde_json::from_value(json!({})).unwrap()).err().unwrap();
        assert_eq!(error.code,"CONNECT_PENDING_SELECTION_REQUIRED");assert_eq!(error.details.unwrap()["candidates"].as_array().unwrap().len(),2);
    }
    #[test]
    fn old_pending_objective_does_not_widen_current_deliberate_selection() {
        let root=crate::test_support::protected_test_dir();let mut connect=selected(root.path());
        saved(&mut connect,"historical-broad",true,true,"PENDING");
        let current=saved(&mut connect,"selected-tools-only",false,false,"LOCAL_CONFIGURED");
        let (request,resume)=connect.resolve_input(serde_json::from_value(json!({})).unwrap()).unwrap();
        assert!(resume);assert!(request==current);
        let (changed,resume)=connect.resolve_input(serde_json::from_value(json!({"send":true})).unwrap()).unwrap();
        assert!(!resume);assert!(changed.send);assert!(!changed.receive);assert!(!changed.require_body_keys);
    }
    #[test]
    fn original_identity_and_frontend_scope_pins_are_preserved() {
        let root=crate::test_support::protected_test_dir();let mut connect=selected(root.path());saved(&mut connect,"original",false,false,"LOCAL_CONFIGURED");
        let mut same_actor=connect.registry.participants["peer"].clone();same_actor.endpoint_path=root.path().join("different-journal.json");connect.registry.participants.insert("other".into(),same_actor);
        assert_eq!(connect.resolve_input(serde_json::from_value(json!({})).unwrap()).err().unwrap().code,"MULTIPLE_IDENTITIES_SELECT_FRONTEND_PARTICIPANT");
        connect.registry.selected_source=Some("peer".into());
        let (request,resume)=connect.resolve_input_selected(serde_json::from_value(json!({})).unwrap(),Some("peer"),Some(&"W".repeat(43))).unwrap();assert!(resume);assert_eq!(request.participant,"peer");
        assert_eq!(connect.resolve_input_selected(serde_json::from_value(json!({"participant":"other"})).unwrap(),Some("peer"),None).err().unwrap().code,"FRONTEND_IDENTITY_PIN_MISMATCH");
        assert_eq!(connect.resolve_input_selected(serde_json::from_value(json!({"workspace_id":"X".repeat(43)})).unwrap(),Some("peer"),Some(&"W".repeat(43))).err().unwrap().code,"FRONTEND_WORKSPACE_PIN_MISMATCH");
    }
    #[test]
    fn ordinary_profile_reads_materialize_no_file_and_context_omits_history() {
        let root=crate::test_support::protected_test_dir();let mut connect=selected(root.path());saved(&mut connect,"old",false,false,"LOCAL_CONFIGURED");saved(&mut connect,"current",false,false,"LOCAL_CONFIGURED");
        let profile:AgentProfile=serde_json::from_value(json!({"format":"peerwork.agent-profile.v1","endpoint_path":root.path().join("original.json"),"expected_origin":"https://example.invalid/","expected_actor":"A".repeat(43),"scopes":{},"workspaces":{"space":"W".repeat(43)}})).unwrap();
        connect.registry.setups.get_mut("current").unwrap().profile=Some(profile);connect.save().unwrap();
        let reader=Connect::inspect(root.path()).unwrap();assert!(reader.profile_for_scope(Some("peer"),None).unwrap().is_some());
        assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry|entry.unwrap().file_name().to_string_lossy().starts_with("profile-")));
        assert_eq!(reader.context_for(Some("peer"),None)["setups"].as_array().unwrap().len(),1);
        assert_eq!(reader.context()["setups"].as_array().unwrap().len(),2);
    }
    #[test]
    fn mcp_new_peer_returns_owner_command_without_changing_original_state() {
        let root=crate::test_support::protected_test_dir();let connect=selected(root.path());let before=std::fs::read(root.path().join("connect.state")).unwrap();
        let error=connect.resolve_input(serde_json::from_value(json!({"new":true,"workspace_id":"W".repeat(43)})).unwrap()).err().unwrap();
        assert_eq!(error.code,"NEW_PEER_LOCAL_OWNER_REQUIRED");let detail=error.details.unwrap();assert_eq!(detail["argv"],json!(["peerwork","connect","--new","--workspace","W".repeat(43)]));assert_eq!(detail["owner_approval_required"],false);
        assert_eq!(std::fs::read(root.path().join("connect.state")).unwrap(),before);assert!(!root.path().join("new-peer-peer").exists());
    }
    #[test]
    fn native_new_peer_retains_identity_and_original_service_across_interruption() {
        let root=crate::test_support::protected_test_dir();let connect=Connect::open(root.path()).unwrap();
        let values=BTreeMap::from([("--new".into(),"true".into()),("--workspace".into(),"W".repeat(43)),("--origin".into(),"http://127.0.0.1:9999".into()),("--allow-loopback-http".into(),"true".into())]);
        let (handle,engine)=bootstrap::new_peer(&connect,&values).unwrap();assert_eq!(handle,"peer");
        let bytes=std::fs::read(&engine.identity_path).unwrap();
        let mut repeat=values.clone();repeat.remove("--origin");repeat.remove("--allow-loopback-http");
        let (_,again)=bootstrap::new_peer(&connect,&repeat).unwrap();assert_eq!(again.expected_actor,engine.expected_actor);assert_eq!(again.origin,engine.origin);assert!(again.allow_loopback_http);assert_eq!(std::fs::read(&engine.identity_path).unwrap(),bytes);
        std::fs::remove_file(&engine.identity_path).unwrap();assert_eq!(bootstrap::new_peer(&connect,&repeat).err().unwrap().code,"IDENTITY_RECOVERY_REQUIRED");assert!(!engine.identity_path.exists());
    }
    #[test]
    fn new_peer_never_replaces_registered_identity_and_hosted_default_needs_no_paths() {
        let root=crate::test_support::protected_test_dir();let connect=selected(root.path());let values=BTreeMap::from([("--new".into(),"true".into()),("--workspace".into(),"W".repeat(43))]);
        assert_eq!(bootstrap::new_peer(&connect,&values).err().unwrap().code,"NEW_PEER_HANDLE_EXISTS_CHOOSE_NEW_NAME");assert!(!root.path().join("new-peer-peer").exists());
        let fresh=crate::test_support::protected_test_dir();let connect=Connect::open(fresh.path()).unwrap();let (_,engine)=bootstrap::new_peer(&connect,&values).unwrap();
        assert_eq!(engine.origin,"https://api.peerwork.dev/");assert!(engine.identity_path.starts_with(fresh.path()));assert!(engine.journal_path.unwrap().starts_with(fresh.path()));
    }
}
