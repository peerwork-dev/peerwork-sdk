//! Discoverable administration over the existing participant engine. The table
//! selects native operations; it is neither a second signer nor a grant system.
use super::*;
use peerwork_core::structure_execution::StructureOperationKind;

pub(super) struct Operation {
    name: &'static str,
    action: &'static str,
    scope: &'static str,
    description: &'static str,
    required: &'static [&'static str],
    example: Value,
}
fn operations()->Vec<Operation> {
    fn op(name:&'static str,action:&'static str,scope:&'static str,description:&'static str,required:&'static [&'static str],example:Value)->Operation {
        Operation{name,action,scope,description,required,example}
    }
    vec![
        op("workspace.get","structure.workspace.get","workspace","Read current workspace and membership.",&[],json!({})),
        op("workspace.delete","structure.workspace.delete","workspace","Delete only the explicitly confirmed workspace using its current revision. This is destructive and must be requested by the user.",&["confirm_workspace_id"],json!({"confirm_workspace_id":"EXACT_SELECTED_WORKSPACE_ID"})),
        op("workspace.create","structure.workspace.create","identity","Create a PRIVATE workspace with the selected identity.",&["name"],json!({"name":"Project"})),
        op("instances.read","structure.instances.read","workspace","Read one bounded current instance page.",&[],json!({"limit":8})),
        op("protocol.register","structure.protocol.register","workspace","Register an inspected immutable protocol bundle, without adoption or publication.",&["bundle"],json!({"bundle":"REPLACE_WITH_AUTHORED_BUNDLE_OBJECT"})),
        op("protocol.adopt","structure.adopt","workspace","Create an instance using an explicitly selected bundle or registered package. Existing instances remain pinned. Choose bootstrap_grant explicitly, including an empty actions list if no writes are intended.",&["bootstrap_grant"],json!({"package_digest":"EXACT_REGISTERED_PACKAGE_DIGEST","bootstrap_grant":{"actions":[],"protocol_roles":[],"capabilities":[]}})),
        op("protocol.bind","structure.protocol.bind","workspace","Attach a first role bundle with exactly matching execution rules to an existing instance.",&["instance_id","protocol_digest"],json!({"instance_id":"EXACT_INSTANCE_ID","protocol_digest":"EXACT_EXECUTION_DIGEST","package_digest":"EXACT_REGISTERED_PACKAGE_DIGEST"})),
        op("protocol.upgrade","participant.protocol.upgrade","workspace","Upgrade an existing instance using a target package digest or authored bundle. The SDK freezes verified current binding CAS once. New execution requires explicit bounded writer grants or read_only:true; recovery retains the original plan.",&["instance_id"],json!({"instance_id":"EXACT_INSTANCE_ID","target_package_digest":"EXACT_REGISTERED_PACKAGE_DIGEST","grants":[{"actor_id":"EXACT_TARGET_ACTOR_ID","actions":["EXPLICIT_TARGET_CREATE_ACTION"],"protocol_roles":["EXPLICIT_TARGET_ROLE"],"capabilities":["EXPLICIT_TARGET_CAPABILITY"],"expires_at":null}]})),
        op("instance.records.read","structure.instance.records.read","workspace","Read one bounded instance-wide container page across execution contexts; each record retains its own protocol and original author evidence.",&["instance_id"],json!({"instance_id":"EXACT_INSTANCE_ID","limit":8})),
        op("context.records.read","structure.records.read","protocol","Read one explicitly selected execution context. Omitted execution_context_id retains legacy meaning.",&[],json!({"limit":8})),
        op("instance.inspect","structure.instance.get","protocol","Read the selected execution state without a business write grant.",&[],json!({})),
        op("record.inspect","structure.record.get","protocol","Read one exact original record and its authenticated body.",&["record_id","revision"],json!({"record_id":"EXACT_RECORD_ID","revision":1})),
        op("protocol.inspect","structure.protocol.resolve","protocol","Resolve the selected execution's role/schema before using it.",&[],json!({"view":"inspect","include_resources":false})),
        op("protocol.resource","structure.protocol.resource.get","protocol","Read one selected package resource.",&["path"],json!({"path":"roles/worker.md"})),
        op("grant.get","structure.grant.get","protocol","Read selected member's grant for the configured instance.",&["actor_id"],json!({"actor_id":"EXACT_ACTOR_ID"})),
        op("grant.revoke","structure.grant.revoke","protocol","Revoke the exact current member grant, retaining signed historical attribution.",&["actor_id","expected_grant_revision"],json!({"actor_id":"EXACT_ACTOR_ID","expected_grant_revision":1})),
        op("grant.set","structure.grant.set","protocol","Set explicitly selected actions, roles and capabilities for the exact current membership.",&["actor_id","membership_id","expected_grant_revision","actions","protocol_roles","capabilities","expires_at"],json!({"actor_id":"EXACT_ACTOR_ID","membership_id":"EXACT_MEMBERSHIP_ID","expected_grant_revision":null,"actions":["claim"],"protocol_roles":["WORKER"],"capabilities":[],"expires_at":null})),
        op("event.progress","structure.communication.event.get","workspace","Read one event's frozen audience, receiver/host facts and undelivered reasons. Storage alone does not mean Agent host delivery.",&["event_sequence"],json!({"event_sequence":1,"limit":8})),
        op("workspace.collaboration","structure.workspace.collaboration.set","workspace","Change the Workspace shared-status visibility policy using its current collaboration revision. Ordinary collaboration requires no extra communication grant.",&["expected_revision","show_presence"],json!({"expected_revision":1,"show_presence":true})),
        op("communication.get","structure.communication.grant.get","workspace","Read one member's communication grant; local aliases do not substitute for membership.",&["actor_id"],json!({"actor_id":"EXACT_ACTOR_ID"})),
        op("communication.set","structure.communication.grant.set","workspace","Explicitly set communication rights for the exact current membership. Ordinary connect uses the consolidated approval path.",&["actor_id","membership_id","expected_revision","send","receive"],json!({"actor_id":"EXACT_ACTOR_ID","membership_id":"EXACT_MEMBERSHIP_ID","expected_revision":null,"send":true,"receive":true})),
        op("member.set","structure.member.set","workspace","Change an explicitly selected member's state using the current workspace revision.",&["actor_id","state","expected_membership_id"],json!({"actor_id":"EXACT_ACTOR_ID","state":"ACTIVE","expected_membership_id":null})),
        op("access.request","participant.access.request","workspace","Prepare a signed access request; does not approve it.",&["label"],json!({"label":"Project worker"})),
        op("access.approve","participant.access.approve","workspace","Approve the exact signed Agent/browser request. Verify workspace/device and requested rights; future/history keys require explicit consent.",&["request_jws"],json!({"request_jws":"EXACT_SIGNED_REQUEST","ttl_ms":86400000,"include_history":false,"follow_current_key":false})),
        op("keys.prepare","participant.keys.prepare","workspace","Prepare only the selected workspace's authorized current body keys.",&[],json!({})),
        op("keys.status","participant.keys.status","workspace","Inspect selected body-key availability locally; this is not a remote grant.",&["key_ids"],json!({"key_ids":["EXACT_BODY_KEY_ID"]})),
        op("keys.accept","participant.keys.accept","workspace","Accept the exact authorized key deliveries from the selected Owner. Current writing-key selection is explicit.",&["owner_id","key_ids"],json!({"owner_id":"EXACT_OWNER_ID","key_ids":["EXACT_BODY_KEY_ID"]})),
        op("keys.rotate","participant.keys.rotate","workspace","Explicit Owner rotation using one durable original operation.",&[],json!({})),
        op("keys.coordinate","participant.keys.coordinate","workspace","Advance authorized Owner key deliveries without altering grants.",&[],json!({})),
        op("archive.sources","participant.archive.sources","workspace","List configured migration source handles; no local secret paths are accepted.",&[],json!({})),
        op("archive.migrate","participant.archive.migrate","workspace","Migrate the selected archived workspace using an already configured source handle. Preserve identity and original operation.",&["source_id"],json!({"source_id":"CONFIGURED_SOURCE_DIGEST"})),
        op("operations.read","structure.operations.read","workspace","Read one bounded page of admitted backend operations, independent of local unsubmitted intents.",&[],json!({"limit":8})),
        op("maintenance.cancel","structure.maintenance.cancel","protocol","Explicit Owner cancellation of one maintenance job; cancellation does not undo an activated generation.",&["job_id"],json!({"job_id":"EXACT_JOB_ID"})),
        op("maintenance.get","structure.maintenance.get","protocol","Read one admitted backend maintenance job.",&["job_id"],json!({"job_id":"EXACT_JOB_ID"})),
        op("maintenance.rebuild","structure.maintenance.rebuild","protocol","Request explicit backend maintenance; ordinary reads never require it.",&["expected_event_revision"],json!({"expected_event_revision":1,"ttl_ms":60000})),
        op("publication.publish","participant.publication.publish","protocol","Publish exactly selected content with explicit disclosure consent; never inferred from a PRIVATE record.",&["record_id","revision","title","disclosure","body"],json!({"record_id":"EXACT_RECORD_ID","revision":1,"title":"Release notes","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"RECORD"}})),
        op("protocol.offline","participant.protocol.offline","identity","Run fixture, simulate, compatibility or plan locally. No legacy online export/apply and no network evidence.",&["operation","input"],json!({"operation":"fixture","input":{"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"counter","manifest":{"name":"example.counter","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{"count":0},"actions":[{"id":"set","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}}]}]}]}}]}})),
    ]
}
pub(super) fn names()->Vec<&'static str>{operations().into_iter().map(|spec|spec.name).collect()}
pub(crate) fn workspace_names()->Vec<&'static str>{operations().into_iter().filter(|spec|spec.scope!="identity").map(|spec|spec.name).collect()}
pub(crate) fn is_workspace_action(action:&str)->bool{operations().iter().any(|spec|spec.scope!="identity"&&spec.action==action)}
pub(crate) fn workspace_actions(names:&[String])->Result<std::collections::BTreeSet<String>> {
    let mut seen=std::collections::BTreeSet::new();let mut actions=std::collections::BTreeSet::new();
    for name in names {
        let spec=operations().into_iter().find(|spec|spec.name==name).ok_or_else(||invalid("MANAGEMENT_OPERATION_UNKNOWN"))?;
        if spec.scope=="identity" {return Err(invalid("IDENTITY_MANAGEMENT_NOT_SUPPORTED_BY_WORKSPACE_CONNECT"));}
        if !seen.insert(name){return Err(invalid("MANAGEMENT_OPERATION_DUPLICATE"));}
        actions.insert(spec.action.to_owned());
    }
    Ok(actions)
}
fn enable_hint(spec:&Operation,workspace:Option<&str>)->Value {
    json!({"next_actor":"LOCAL_RUNTIME_OWNER","next_action":"SELECT_ORIGINAL_CLIENT_OR_REVIEW_EXPLICIT_DELEGATION","action":spec.action,"workspace_id":workspace,"remote_grants_changed":false,"existing_credentials_widened":false})
}
fn enable_error(mut error:ParticipantError,spec:&Operation,workspace:Option<&str>,view:Option<&str>)->ParticipantError {
    if error.code=="LOCAL_SCOPE_DENIED"&&view.is_none() {
        error.details.get_or_insert_with(||json!({}))["management_enable"]=enable_hint(spec,workspace);
    }
    error
}
pub(super) fn read_enable_error(error:ParticipantError,action:&str,workspace:Option<&str>)->ParticipantError {
    match operations().into_iter().find(|spec|spec.action==action){Some(spec)=>enable_error(error,&spec,workspace,None),None=>error}
}
fn native_kind(spec:&Operation)->StructureOperationKind {
    crate::participant_actions::kind(spec.action).expect("management catalog uses existing native operations")
}
impl AgentTools {
    pub(super) async fn manage(&self,mode:&str,operation:Option<&str>,workspace:Option<&str>,protocol:Option<&str>,instance_id:Option<&str>,protocol_digest:Option<&str>,id:Option<&str>,body:Option<Value>,expected_workspace:Option<u64>,expected_instance:Option<u64>,wait_ms:u64)->Result<Value> {
        if !["catalog","describe","read","request","invoke"].contains(&mode) {return Err(invalid("MANAGEMENT_MODE_INVALID"));}
        if instance_id.is_some()!=protocol_digest.is_some(){return Err(invalid("MANAGEMENT_INSTANCE_TARGET_PAIR_REQUIRED"));}
        if protocol.is_some()&&(workspace.is_some()||instance_id.is_some()){return Err(invalid("MANAGEMENT_SCOPE_SELECTION_INVALID"));}
        if instance_id.is_some_and(|id|!token(id))||protocol_digest.is_some_and(|digest|!crate::participant_migration::digest(digest)){return Err(invalid("MANAGEMENT_INSTANCE_TARGET_INVALID"));}
        if matches!(mode,"catalog"|"describe") {
            if mode=="describe"&&operation.is_none(){return Err(invalid("MANAGEMENT_OPERATION_REQUIRED"));}
            if id.is_some()||body.is_some()||expected_workspace.is_some()||expected_instance.is_some(){return Err(invalid("DISCOVERY_DOES_NOT_ACCEPT_MUTATION_INPUT"));}
            let selected_workspace=if let Some(alias)=protocol{self.protocol(alias)?.workspace_id}else{self.selected_workspace(workspace).ok()};
            let client=selected_workspace.as_deref().map(|ws|self.directory_client(ws)).unwrap_or(&self.client);
            let caps=client.call(json!({"method":"capabilities"})).await?;
            let cap:crate::participant::Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|invalid("LOCAL_CEILING_INVALID"))?;
            let list=operations().into_iter().filter(|spec|operation.is_none_or(|name|spec.name==name)).map(|spec|{
                let kind=native_kind(&spec);
                let view:Option<&str>=None;
                let selected_cap=&cap;
                let mut item=json!({"operation":spec.name,"native_action":spec.action,"scope":spec.scope,"description":spec.description,
                    "mode":match kind{StructureOperationKind::Read=>"read",StructureOperationKind::Control=>"request",StructureOperationKind::Mutation=>"invoke"},
                    "local_operation_listed":selected_cap.operations.contains(spec.action),"management_view":view,"local_scope_checked":false,"remote_permission":"NOT_ATTESTED"});
                if !selected_cap.operations.contains(spec.action){item["management_enable"]=enable_hint(&spec,selected_workspace.as_deref());}
                if mode=="describe" {
                    item["required_body_fields"]=json!(spec.required);item["body_example"]=spec.example;
                    item["revision_input"]=json!(if matches!(spec.name,"member.set"|"workspace.delete"){"expected_workspace_revision"}else if spec.name=="maintenance.rebuild"{"expected_revision"}else{"SEE_SELECTED_OPERATION"});
                    if spec.name=="protocol.upgrade"{item["revision_input"]=json!("SDK_VERIFIED_AND_FROZEN_ONCE");item["selection"]=json!({"instance":"protocol alias or body.instance_id","target":"body.target_package_digest OR body.bundle","old_work":"optional body.record_id selects the original work context before role-only upgrade","authority":"explicit grants[] for a new writable execution; existing grants are never widened implicitly","automatic_metadata":"SDK verifies and freezes current membership_id, grant CAS, package and binding CAS; caller selects meaningful target actions, roles and capabilities","role_only":"same-execution instruction update needs no additional grant","read_only":"optional read_only:true intentionally activates a new execution without writer authority"});}
                    item["scope_inputs"]=match spec.scope {
                        "identity"=>json!({"selectors":[],"workspace_connect_management":"NOT_SUPPORTED"}),
                        "protocol"=>json!({"choose_one":[["protocol"],["workspace","instance_id","protocol_digest"]],"source":"EXACT_VERIFIED_INSTANCES_READ_RESULT","business_role_required":false}),
                        _=>json!({"selectors":["workspace"]}),
                    };
                }
                item
            }).collect::<Vec<_>>();
            if list.is_empty(){return Err(invalid("MANAGEMENT_OPERATION_UNKNOWN"));}
            return Ok(json!({"operations":list,"identity":self.client.actor_id(),"origin":self.client.origin(),"source":"NATIVE_OPERATION_CATALOG",
                "instructions":"Use business fields from the selected operation. Existing local/remote permissions remain enforced. Copy recovery_arguments for an uncertain invoke; examples contain placeholders, never inferred authority."}));
        }
        let name=operation.ok_or_else(||invalid("MANAGEMENT_OPERATION_REQUIRED"))?;
        let spec=operations().into_iter().find(|s|s.name==name).ok_or_else(||invalid("MANAGEMENT_OPERATION_UNKNOWN"))?;
        let kind=native_kind(&spec);
        let expected_mode=match kind{StructureOperationKind::Read=>"read",StructureOperationKind::Control=>"request",StructureOperationKind::Mutation=>"invoke"};
        if mode!=expected_mode{return Err(invalid("MANAGEMENT_OPERATION_MODE_MISMATCH"));}
        if mode!="invoke"&&id.is_some(){return Err(invalid("READ_DOES_NOT_ACCEPT_MUTATION_ID"));}
        if wait_ms>5000{return Err(invalid("WAIT_BUDGET_INVALID"));}
        let mut body=body.unwrap_or(json!({}));
        let object=body.as_object_mut().ok_or_else(||invalid("MANAGEMENT_BODY_INVALID"))?;
        if object.contains_key("workspace_id")||object.contains_key("idempotency_key")||object.contains_key("command_id") {return Err(invalid("MANAGEMENT_SCOPE_MUST_USE_SELECTED_CLIENT"));}
        if name=="protocol.upgrade" {
            if let Some(alias)=protocol {
                let selected=self.protocol(alias)?;let instance=selected.instance_id.ok_or_else(||invalid("MANAGEMENT_PROTOCOL_SELECTION_REQUIRED"))?;
                if object.get("instance_id").is_some_and(|id|id!=&json!(instance)){return Err(invalid("MANAGEMENT_SCOPE_SELECTION_INVALID"));}
                object.insert("instance_id".into(),json!(instance));
            }
        }
        if name=="grant.read"&&!object.contains_key("view"){object.insert("view".into(),json!("SUMMARY"));}
        for field in spec.required {if !object.contains_key(*field){let mut e=invalid("MANAGEMENT_FIELD_REQUIRED");e.details=Some(json!({"operation":name,"field":field,"next_action":"DESCRIBE_SELECTED_OPERATION"}));return Err(e);}}
        let (fallback,scope)=match spec.scope {
            "identity" if workspace.is_none()&&protocol.is_none()&&instance_id.is_none()=>(&self.client,Scope::default()),
            "workspace" if name=="protocol.upgrade"&&protocol.is_some()&&instance_id.is_none()=>{let ws=self.protocol(protocol.unwrap())?.workspace_id.ok_or_else(||invalid("WORKSPACE_ALIAS_UNKNOWN"))?;(self.directory_client(&ws),Scope{workspace_id:Some(ws),..Default::default()})},
            "workspace" if protocol.is_none()&&instance_id.is_none()=>{let ws=self.selected_workspace(workspace)?;(self.directory_client(&ws),Scope{workspace_id:Some(ws),..Default::default()})},
            "protocol" if protocol.is_some()&&instance_id.is_none()=>{let selected=self.protocol(protocol.unwrap())?;let ws=selected.workspace_id.as_deref().ok_or_else(||invalid("WORKSPACE_ALIAS_UNKNOWN"))?;(self.directory_client(ws),selected)},
            "protocol" if protocol.is_none()&&instance_id.is_some()=>{let ws=self.selected_workspace(workspace)?;(self.directory_client(&ws),Scope{workspace_id:Some(ws),instance_id:instance_id.map(str::to_owned),protocol_digest:protocol_digest.map(str::to_owned)})},
            "protocol"=>return Err(invalid("MANAGEMENT_PROTOCOL_SELECTION_REQUIRED")),
            _=>return Err(invalid("MANAGEMENT_SCOPE_SELECTION_INVALID")),
        };
        // Historical views are exact recovery routes, never permission fallbacks.
        let view:Option<&str>=None;
        let client=fallback;
        if let Some(bundle)=body.get("bundle") {peerwork_core::protocol_bundle::inspect(bundle).map_err(|_|invalid("PROTOCOL_BUNDLE_INVALID"))?;}
        if mode!="invoke" {
            if expected_workspace.is_some()||expected_instance.is_some(){return Err(invalid("READ_DOES_NOT_ACCEPT_MUTATION_REVISION"));}
            if mode=="read"{return self.read_client(client,spec.action,scope.clone(),body).await.map_err(|error|enable_error(error,&spec,scope.workspace_id.as_deref(),view));}
            return client.call(json!({"method":"request","request":Invoke::new("agent-management-control",spec.action,scope.clone(),body)})).await.map_err(|error|enable_error(error,&spec,scope.workspace_id.as_deref(),view));
        }
        let id=id.ok_or_else(||invalid("MANAGEMENT_OPERATION_ID_REQUIRED"))?;
        let mut recovery=json!({"operation_id":id});
        if let Some(view)=view {recovery["management"]=json!(view);}else if let Some(protocol)=protocol {recovery["protocol"]=json!(protocol);}else if scope.workspace_id.is_some() {recovery["workspace"]=json!(scope.workspace_id);}
        if matches!(name,"member.set"|"workspace.delete")&&expected_workspace.is_none(){return Err(invalid("EXPECTED_WORKSPACE_REVISION_REQUIRED"));}
        if name=="maintenance.rebuild"&&expected_instance.is_none(){return Err(invalid("EXPECTED_INSTANCE_REVISION_REQUIRED"));}
        let mut request=Invoke::new(id,spec.action,scope.clone(),body);
        request.expected_workspace_revision=expected_workspace;request.expected_instance_revision=expected_instance;
        let mut result=match self.invoke_client(client,request,wait_ms).await {Ok(result)=>result,Err(error)=>{let mut error=enable_error(error,&spec,scope.workspace_id.as_deref(),view);error.details.get_or_insert_with(||json!({}))["recovery_arguments"]=recovery;return Err(error);}};
        result["recovery_arguments"]=recovery;Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn management_discovery_and_offline_execution_reuse_original_client_without_network() {
        use crate::{kernel_identity::KernelIdentity,participant::{ParticipantClient,ParticipantConfig,Capability}};
        let root=crate::test_support::protected_test_dir();
        let identity_path=root.path().join("identity.state");let identity=KernelIdentity::create(&identity_path).unwrap();
        let mut config=ParticipantConfig::new("http://127.0.0.1:1",identity.actor_id(),identity_path,root.path().join("engine"));config.allow_loopback_http=true;
        let client=ParticipantClient::open(config).await.unwrap();
        let tools=AgentTools::from_client(client.clone(),AgentSelection::for_client(&client)).unwrap();
        let catalog=tools.call(AgentRequest::parse("manage",json!({})).unwrap()).await.unwrap();
        assert!(catalog["operations"].as_array().unwrap().iter().any(|o|o["operation"]=="access.approve"));
        assert!(catalog["operations"].as_array().unwrap().iter().all(|o|o["remote_permission"]=="NOT_ATTESTED"));
        let described=tools.call(AgentRequest::parse("manage",json!({"mode":"describe","operation":"protocol.offline"})).unwrap()).await.unwrap();
        let fixture=tools.call(AgentRequest::parse("manage",json!({"mode":"request","operation":"protocol.offline","body":described["operations"][0]["body_example"]})).unwrap()).await.unwrap();
        assert_eq!(fixture["result"]["ok"],true,"{fixture}");
        let simulated=tools.call(AgentRequest::parse("manage",json!({"mode":"request","operation":"protocol.offline","body":{"operation":"simulate","input":{"schema":"peerwork.protocol-simulation.v1","fixture":fixture["result"]["value"],"steps":[{"instance_id":"counter","action_id":"set"}]}}})).unwrap()).await.unwrap();
        assert_eq!(simulated["result"]["value"]["steps"][0]["output_state"]["count"],1,"{simulated}");
        for request in [
            json!({"mode":"read","operation":"workspace.create","body":{"name":"wrong"}}),
            json!({"mode":"invoke","operation":"workspace.create","operation_id":"blocked","body":{"name":"wrong","workspace_id":"other"}}),
            json!({"mode":"describe","operation":"workspace.create","operation_id":"must-not-submit"}),
        ] {assert!(tools.call(AgentRequest::parse("manage",request).unwrap()).await.is_err());}
        let mut ceiling=Capability::owner();ceiling.operations.remove("structure.workspace.create");
        let restricted=client.restrict("restricted",ceiling).unwrap();
        let limited=AgentTools::from_client(restricted.clone(),AgentSelection::for_client(&restricted)).unwrap();
        let description=limited.call(AgentRequest::parse("manage",json!({"mode":"describe","operation":"workspace.create"})).unwrap()).await.unwrap();
        assert_eq!(description["operations"][0]["local_operation_listed"],false);
        assert_eq!(limited.call(AgentRequest::parse("manage",json!({"mode":"invoke","operation":"workspace.create","operation_id":"forbidden","body":{"name":"forbidden"}})).unwrap()).await.unwrap_err().code,"LOCAL_SCOPE_DENIED");
        assert_eq!(client.operations("",32).await.unwrap()["items"].as_array().unwrap().len(),0,"offline/control/discovery cannot create a mutation intent");
        client.close().await.unwrap();
    }
}
