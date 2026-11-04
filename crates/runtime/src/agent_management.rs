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
        op("grant.get","structure.grant.get","protocol","Read selected member's grant for the configured instance.",&["actor_id"],json!({"actor_id":"EXACT_ACTOR_ID"})),
        op("grant.set","structure.grant.set","protocol","Set explicitly selected actions, roles and capabilities for the exact current membership.",&["actor_id","membership_id","expected_grant_revision","actions","protocol_roles","capabilities","expires_at"],json!({"actor_id":"EXACT_ACTOR_ID","membership_id":"EXACT_MEMBERSHIP_ID","expected_grant_revision":null,"actions":["claim"],"protocol_roles":["WORKER"],"capabilities":[],"expires_at":null})),
        op("member.set","structure.member.set","workspace","Change an explicitly selected member's state using the current workspace revision.",&["actor_id","state","expected_membership_id"],json!({"actor_id":"EXACT_ACTOR_ID","state":"ACTIVE","expected_membership_id":null})),
        op("access.request","participant.access.request","workspace","Prepare a signed access request; does not approve it.",&["label"],json!({"label":"Project worker"})),
        op("access.approve","participant.access.approve","workspace","Approve the exact signed Agent/browser request. Verify workspace/device and requested rights; future/history keys require explicit consent.",&["request_jws"],json!({"request_jws":"EXACT_SIGNED_REQUEST","ttl_ms":86400000,"include_history":false,"follow_current_key":false})),
        op("keys.prepare","participant.keys.prepare","workspace","Prepare only the selected workspace's authorized current body keys.",&[],json!({})),
        op("keys.rotate","participant.keys.rotate","workspace","Explicit Owner rotation using one durable original operation.",&[],json!({})),
        op("keys.coordinate","participant.keys.coordinate","workspace","Advance authorized Owner key deliveries without altering grants.",&[],json!({})),
        op("archive.sources","participant.archive.sources","workspace","List configured migration source handles; no local secret paths are accepted.",&[],json!({})),
        op("archive.migrate","participant.archive.migrate","workspace","Migrate the selected archived workspace using an already configured source handle. Preserve identity and original operation.",&["source_id"],json!({"source_id":"CONFIGURED_SOURCE_DIGEST"})),
        op("maintenance.get","structure.maintenance.get","protocol","Read one admitted backend maintenance job.",&["job_id"],json!({"job_id":"EXACT_JOB_ID"})),
        op("maintenance.rebuild","structure.maintenance.rebuild","protocol","Request explicit backend maintenance; ordinary reads never require it.",&["expected_event_revision"],json!({"expected_event_revision":1,"ttl_ms":60000})),
        op("publication.publish","participant.publication.publish","protocol","Publish exactly selected content with explicit disclosure consent; never inferred from a PRIVATE record.",&["record_id","revision","title","disclosure","body"],json!({"record_id":"EXACT_RECORD_ID","revision":1,"title":"Release notes","disclosure":"PUBLISH_SELECTED_CONTENT","body":{"from":"RECORD"}})),
        op("protocol.offline","participant.protocol.offline","identity","Run fixture, simulate, compatibility or plan locally. No legacy online export/apply and no network evidence.",&["operation","input"],json!({"operation":"fixture","input":{"schema":"peerwork.protocol-fixture.v1","protocols":[]}})),
    ]
}
fn native_kind(spec:&Operation)->StructureOperationKind {
    crate::participant_actions::kind(spec.action).expect("management catalog uses existing native operations")
}
impl AgentTools {
    pub(super) async fn manage(&self,mode:&str,operation:Option<&str>,workspace:Option<&str>,protocol:Option<&str>,id:Option<&str>,body:Option<Value>,expected_workspace:Option<u64>,expected_instance:Option<u64>,wait_ms:u64)->Result<Value> {
        if !["catalog","describe","read","request","invoke"].contains(&mode) {return Err(invalid("MANAGEMENT_MODE_INVALID"));}
        if matches!(mode,"catalog"|"describe") {
            if id.is_some()||body.is_some()||expected_workspace.is_some()||expected_instance.is_some(){return Err(invalid("DISCOVERY_DOES_NOT_ACCEPT_MUTATION_INPUT"));}
            let client=self.operation_client(protocol,workspace)?;
            let caps=client.call(json!({"method":"capabilities"})).await?;
            let cap:crate::participant::Capability=serde_json::from_value(caps["capability"].clone()).map_err(|_|invalid("LOCAL_CEILING_INVALID"))?;
            let list=operations().into_iter().filter(|spec|operation.is_none_or(|name|spec.name==name)).map(|spec|{
                let kind=native_kind(&spec);
                json!({"operation":spec.name,"native_action":spec.action,"scope":spec.scope,"description":spec.description,
                    "mode":match kind{StructureOperationKind::Read=>"read",StructureOperationKind::Control=>"request",StructureOperationKind::Mutation=>"invoke"},"required_body_fields":spec.required,"body_example":spec.example,
                    "local_operation_listed":cap.operations.contains(spec.action),"local_scope_checked":false,"remote_permission":"NOT_ATTESTED",
                    "revision_input":if spec.name=="member.set"{"expected_workspace_revision"}else if spec.name=="maintenance.rebuild"{"expected_revision"}else{"SEE_SELECTED_OPERATION"}})
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
        for field in spec.required {if !object.contains_key(*field){let mut e=invalid("MANAGEMENT_FIELD_REQUIRED");e.details=Some(json!({"operation":name,"field":field,"next_action":"DESCRIBE_SELECTED_OPERATION"}));return Err(e);}}
        let (client,scope)=match spec.scope {
            "identity" if workspace.is_none()&&protocol.is_none()=>(&self.client,Scope::default()),
            "workspace" if protocol.is_none()=>{let ws=self.selected_workspace(workspace)?;(self.directory_client(&ws),Scope{workspace_id:Some(ws),..Default::default()})},
            "protocol" if workspace.is_none()=>{let alias=protocol.ok_or_else(||invalid("MANAGEMENT_PROTOCOL_SELECTION_REQUIRED"))?;(self.protocol_client(alias)?,self.protocol(alias)?)},
            _=>return Err(invalid("MANAGEMENT_SCOPE_SELECTION_INVALID")),
        };
        if let Some(bundle)=body.get("bundle") {peerwork_core::protocol_bundle::inspect(bundle).map_err(|_|invalid("PROTOCOL_BUNDLE_INVALID"))?;}
        if mode!="invoke" {
            if expected_workspace.is_some()||expected_instance.is_some(){return Err(invalid("READ_DOES_NOT_ACCEPT_MUTATION_REVISION"));}
            if mode=="read"{return self.read_client(client,spec.action,scope,body).await;}
            return client.call(json!({"method":"request","request":Invoke::new("agent-management-control",spec.action,scope,body)})).await;
        }
        let id=id.ok_or_else(||invalid("MANAGEMENT_OPERATION_ID_REQUIRED"))?;
        let mut recovery=json!({"operation_id":id});
        if spec.scope=="protocol" {recovery["protocol"]=json!(protocol);}else if spec.scope=="workspace" {recovery["workspace"]=json!(scope.workspace_id);}
        let mut request=Invoke::new(id,spec.action,scope,body);
        request.expected_workspace_revision=expected_workspace;request.expected_instance_revision=expected_instance;
        let mut result=match self.invoke_client(client,request,wait_ms).await {Ok(result)=>result,Err(mut error)=>{error.details.get_or_insert_with(||json!({}))["recovery_arguments"]=recovery;return Err(error);}};
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
        let manifest=json!({"name":"test.counter","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{"count":0},"actions":[{"id":"set","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}}]}]}]});
        let fixture=tools.call(AgentRequest::parse("manage",json!({"mode":"request","operation":"protocol.offline","body":{"operation":"fixture","input":{"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"counter","manifest":manifest}]}}})).unwrap()).await.unwrap();
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
