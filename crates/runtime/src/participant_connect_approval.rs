//! Owner-side continuation of one explicit permission request. Prepared child
//! intents are frozen before submission; retries never rebuild an unknown write.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Delta {
    Membership,
    CommunicationSend,
    CommunicationReceive,
    BusinessRole {
        instance_id: String,
        protocol_digest: String,
        #[serde(default, skip_serializing_if="Option::is_none")]
        execution_context_id: Option<String>,
        #[serde(default)]
        role: String,
        actions: Vec<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub format: String,
    pub setup_id: String,
    pub origin: String,
    pub workspace_id: String,
    pub actor_id: String,
    pub membership_id: String,
    pub owner_id: String,
    pub missing: Vec<Delta>,
    pub body_keys_required: bool,
    /// Explicitly requested lease for this approval. Omission preserves an
    /// existing finite lease; it never silently renews or makes it permanent.
    #[serde(default)]
    pub grant_expires_at: Option<u64>,
    #[serde(default)]
    pub follow_current_key: bool,
    #[serde(default)]
    pub key_request: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approval {
    participant: String,
    digest: String,
    steps: Vec<Invoke>,
    results: Vec<Value>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    continuation: Option<AuthorizationRequest>,
}
impl AuthorizationRequest {
    /// Portable public permission request. This carries no local endpoint,
    /// private signing key or authority to grant the requested rights.
    pub fn to_code(&self) -> Result<String> {
        self.validate()?;
        let wire=serde_json::to_vec(self).map_err(|_|local("AUTHORIZATION_REQUEST_INVALID"))?;
        if wire.len()>32768 {return Err(local("AUTHORIZATION_REQUEST_TOO_LARGE"));}
        Ok(format!("PW-AUTH-1.{}",peerwork_core::crypto::base64url(&wire)))
    }
    pub fn from_input(input:Value)->Result<Self> {
        let value=if let Some(code)=input.as_str() {
            if code.len()>43705 {return Err(local("AUTHORIZATION_REQUEST_TOO_LARGE"));}
            let encoded=code.strip_prefix("PW-AUTH-1.").ok_or_else(||local("AUTHORIZATION_REQUEST_INVALID"))?;
            let wire=peerwork_core::crypto::decode_base64url(encoded).map_err(|_|local("AUTHORIZATION_REQUEST_INVALID"))?;
            if wire.len()>32768 {return Err(local("AUTHORIZATION_REQUEST_TOO_LARGE"));}
            peerwork_core::strict_json::parse_strict_json(&wire).map_err(|_|local("AUTHORIZATION_REQUEST_INVALID"))?
        }else{input};
        let request:Self=serde_json::from_value(value).map_err(|_|local("AUTHORIZATION_REQUEST_INVALID"))?;
        request.validate()?;
        Ok(request)
    }
    fn validate(&self) -> Result<()> {
        let admission=self.missing.iter().any(|v|matches!(v,Delta::Membership));
        if (if admission{self.format!="peerwork.connect-authorization-request.v2"}else{self.format!="peerwork.connect-authorization-request.v1"})
            || !identifier(&self.setup_id)
            || ![
                &self.workspace_id,
                &self.actor_id,
            ]
            .iter()
            .all(|v| token(v))
            || (!admission&&(!token(&self.membership_id)||!token(&self.owner_id)))
            || (admission&&(!self.membership_id.is_empty()||!self.owner_id.is_empty()))
            || self.missing.len() > if admission{11}else{10}
            || self.missing.iter().filter(|v|matches!(v,Delta::Membership)).count()>1
            || (self.follow_current_key && !self.body_keys_required)
        {
            return Err(local("AUTHORIZATION_REQUEST_INVALID"));
        }
        for delta in &self.missing {
            if let Delta::BusinessRole {
                instance_id,
                protocol_digest,
                execution_context_id,
                role,
                actions,
            } = delta
            {
                if !token(instance_id)
                    || !(crate::participant_migration::digest(protocol_digest)||(admission&&protocol_digest.is_empty()))
                    || execution_context_id.as_ref().is_some_and(|id|!token(id))
                    || (role.is_empty() && actions.is_empty())
                    || role.len() > 128
                    || actions.len() > 64
                    || actions.iter().any(|s| s.is_empty() || s.len() > 128)
                {
                    return Err(local("AUTHORIZATION_REQUEST_INVALID"));
                }
            }
        }
        if self.body_keys_required {
            let request = self
                .key_request
                .as_ref()
                .ok_or_else(|| local("SIGNED_KEY_REQUEST_REQUIRED"))?;
            let jws = request["request_jws"]
                .as_str()
                .filter(|s| s.len() <= 12000)
                .ok_or_else(|| local("SIGNED_KEY_REQUEST_REQUIRED"))?;
            let payload = jws
                .split('.')
                .nth(1)
                .ok_or_else(|| local("SIGNED_KEY_REQUEST_REQUIRED"))?;
            let bytes = peerwork_core::crypto::decode_base64url(payload)
                .map_err(|_| local("SIGNED_KEY_REQUEST_REQUIRED"))?;
            let claims = peerwork_core::strict_json::parse_strict_json(&bytes)
                .map_err(|_| local("SIGNED_KEY_REQUEST_REQUIRED"))?;
            // These comparisons bind the requested delivery to the approved
            // participant. Signature/time/certificate validation is performed by
            // the existing native access-approval producer before submission.
            if claims["actor_id"] != self.actor_id || claims["workspace_id"] != self.workspace_id {
                return Err(local("SIGNED_KEY_REQUEST_BINDING_MISMATCH"));
            }
        }
        Ok(())
    }
}
pub fn deserialize_input<'de,D:serde::Deserializer<'de>>(deserializer:D)->std::result::Result<AuthorizationRequest,D::Error>{
    AuthorizationRequest::from_input(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
pub(super) fn effective(grant: &Value, now: u64) -> bool {
    grant.is_object()
        && (grant["expires_at"].is_null() || grant["expires_at"].as_u64().is_some_and(|t| t > now))
}
fn approved_expiry(grant: &Value, requested: Option<u64>, now: u64) -> Result<Value> {
    let expiry = requested.or_else(|| grant["expires_at"].as_u64());
    if expiry.is_some_and(|t| t <= now) {
        return Err(local(
            "AUTHORIZATION_LEASE_EXPIRED_EXPLICIT_RENEWAL_REQUIRED",
        ));
    }
    Ok(json!(expiry))
}
impl Connect {
    #[cfg(test)]
    pub(crate) fn interrupt_after_admission_once(&mut self){self.interrupt_after_admission=true;}
    /// One public approval continues admission and its dependent grants. The
    /// parent persists the original request and pins resolved protocol scopes;
    /// every internal write retains its own original operation/recovery ID.
    async fn approve_admission(&mut self,participant:&str,id:&str,request:AuthorizationRequest,owner:&str,client:RuntimeClient,digest:String)->Result<Value>{
        if let Some(prior)=self.registry.approvals.get(id){
            if prior.digest!=digest||prior.participant!=participant{return Err(local("APPROVAL_ID_CONFLICT_RESUME_ORIGINAL"));}
        }else{
            if self.registry.approvals.len()>=63{return Err(local("APPROVAL_LIMIT"));}
            let scope=Scope{workspace_id:Some(request.workspace_id.clone()),..Default::default()};
            let workspace=read(&client,"structure.workspace.get",scope.clone(),json!({})).await?;
            if workspace["membership"]["role"]!="OWNER"||workspace["owner_id"]!=owner{return Err(local("OWNER_APPROVAL_REQUIRED"));}
            let mut continuation=request.clone();
            continuation.format="peerwork.connect-authorization-request.v1".into();
            continuation.owner_id=owner.into();
            continuation.missing.retain(|d|!matches!(d,Delta::Membership));
            // Resolve and validate requested role scopes before any admission.
            // A malformed role request must not leave a new membership behind.
            for delta in &mut continuation.missing {
                if let Delta::BusinessRole{instance_id,protocol_digest,execution_context_id,role,actions}=delta {
                    let mut query=json!({"instance_id":instance_id});
                    if let Some(context)=execution_context_id.as_ref(){query["execution_context_id"]=json!(context);}
                    let resolved=read(&client,"structure.instance.resolve",scope.clone(),query).await?;
                    let binding=&resolved[if execution_context_id.is_some(){"binding"}else{"default_binding"}];
                    let actual=binding["protocol_digest"].as_str().or_else(||resolved["instance"]["protocol_digest"].as_str()).ok_or_else(||local("PROTOCOL_RESOLUTION_FAILED"))?;
                    if !protocol_digest.is_empty()&&protocol_digest!=actual{return Err(local("PROTOCOL_RESOLUTION_FAILED"));}
                    *protocol_digest=actual.into();
                    let selected=Scope{workspace_id:scope.workspace_id.clone(),instance_id:Some(instance_id.clone()),protocol_digest:Some(protocol_digest.clone())};
                    let mut query=json!({"view":"inspect","include_resources":false});
                    if let Some(context)=execution_context_id.as_ref(){query["execution_context_id"]=json!(context);}
                    let bound=read(&client,"structure.protocol.resolve",selected,query).await?;
                    let declared:std::collections::BTreeSet<String>=if role.is_empty(){
                        bound["bundle_header"]["manifest"]["actions"].as_array().into_iter().flatten().filter_map(|action|action["id"].as_str().map(str::to_owned)).collect()
                    }else{
                        let definition=&bound["bundle_header"]["roles"][role.as_str()];
                        if !definition.is_object(){return Err(local("PROTOCOL_ROLE_NOT_FOUND"));}
                        definition["tools"].as_array().into_iter().flatten().filter_map(|t|t["action"].as_str().map(str::to_owned)).collect()
                    };
                    if actions.is_empty(){*actions=declared.into_iter().collect();}
                    else if actions.iter().any(|a|!declared.contains(a)){return Err(local("ACTION_NOT_DECLARED_FOR_ROLE"));}
                }
            }
            let active=read(&client,"structure.members.read",scope.clone(),json!({"actor_id":request.actor_id,"state":"ACTIVE","limit":1})).await?;
            let mut steps=Vec::new();
            if let Some(member)=active["members"].as_array().and_then(|m|m.first()){
                if member["access_active"]!=true{return Err(local("EXPIRED_SESSION_REQUIRES_EXPLICIT_ADMISSION"));}
                continuation.membership_id=member["membership_id"].as_str().ok_or_else(||local("MEMBERSHIP_OBSERVATION_INVALID"))?.into();
            }else{
                let revoked=read(&client,"structure.members.read",scope.clone(),json!({"actor_id":request.actor_id,"state":"REVOKED","limit":1})).await?;
                let expected=revoked["members"].as_array().and_then(|m|m.first()).map(|m|m["membership_id"].clone()).unwrap_or(Value::Null);
                let mut step=Invoke::new(format!("approve-{id}-membership"),"structure.member.set",scope,
                    json!({"actor_id":request.actor_id,"state":"ACTIVE","expected_membership_id":expected}));
                step.expected_workspace_revision=workspace["workspace_revision"].as_u64();
                steps.push(step);
            }
            self.registry.approvals.insert(id.into(),Approval{participant:participant.into(),digest,steps,results:Vec::new(),continuation:Some(continuation)});
            self.save()?;
        }
        let parent=&self.registry.approvals[id];
        if parent.results.len()<parent.steps.len(){
            let step=parent.steps[parent.results.len()].clone();
            let mut value=client.call(json!({"method":"invoke","request":step,"wait_ms":1000})).await?;
            if value["state"]=="PENDING"{value=client.call(json!({"method":"recover","operation_id":step.operation_id})).await?;}
            if value["state"]!="ACCEPTED"{
                let terminal=matches!(value["state"].as_str(),Some("REJECTED_NO_EFFECT"|"FAILED"|"REJECTED"));
                return Ok(json!({"state":if terminal{"REJECTED_NO_EFFECT"}else{"PENDING"},"approval_id":id,"setup_id":request.setup_id,"phase":"ADMISSION_SUBMISSION",
                    "original_operation":crate::agent_tools::operation_view(value),"next_action":if terminal{"CORRECT_REQUEST_NEW_APPROVAL_ID"}else{"RESUME_SAME_APPROVAL_ID"},"partial_success_preserved":true}));
            }
            #[cfg(test)]
            if self.interrupt_after_admission {
                self.interrupt_after_admission=false;
                return Err(local("SYNTHETIC_INTERRUPT_AFTER_ADMISSION"));
            }
            let membership=value["outcome"]["result"]["structure"]["membership_id"].as_str().filter(|s|token(s)).ok_or_else(||local("MEMBERSHIP_OBSERVATION_INVALID"))?.to_owned();
            let parent=self.registry.approvals.get_mut(id).unwrap();
            parent.continuation.as_mut().ok_or_else(||local("APPROVAL_STATE_INVALID"))?.membership_id=membership;
            parent.results.push(json!({"operation_id":value["operation_id"],"command_id":value["command_id"],"state":"ACCEPTED","effect_certainty":value["effect_certainty"]}));
            self.save()?;
        }
        let continuation=self.registry.approvals[id].continuation.clone().ok_or_else(||local("APPROVAL_STATE_INVALID"))?;
        let child_id=format!("rights-{}",&sha256_hex(json!([id,&self.registry.approvals[id].digest]).to_string().as_bytes())[..32]);
        let mut result=Box::pin(self.approve(participant,&child_id,continuation)).await?;
        result["approval_id"]=json!(id);
        result["setup_id"]=json!(request.setup_id);
        result["admission_operations"]=json!(self.registry.approvals[id].results);
        result["next_action"]=if result["state"]=="APPROVED"{json!("RESUME_ORIGINAL_CONNECT_SETUP")}else if result["state"]=="PENDING"{json!("RESUME_SAME_APPROVAL_ID")}else{json!("CORRECT_REQUEST_NEW_APPROVAL_ID")};
        Ok(result)
    }
    pub async fn approve(
        &mut self,
        participant: &str,
        approval_id: &str,
        request: AuthorizationRequest,
    ) -> Result<Value> {
        self.require_writer()?;
        request.validate()?;
        if !identifier(approval_id) || approval_id.len() > 64 {
            return Err(local("APPROVAL_ID_INVALID"));
        }
        let selected = self
            .registry
            .participants
            .get(participant)
            .cloned()
            .ok_or_else(|| local("LOCAL_SELECTION_REQUIRED"))?;
        let admission=request.missing.iter().any(|v|matches!(v,Delta::Membership));
        let business_only = !request.body_keys_required && !request.missing.is_empty()
            && request.missing.iter().all(|delta|matches!(delta,Delta::BusinessRole{..}));
        if (!admission&&!business_only&&selected.actor_id != request.owner_id) || selected.origin != request.origin {
            return Err(local("APPROVER_IDENTITY_OR_ORIGIN_MISMATCH"));
        }
        let client =
            RuntimeClient::connect(selected.endpoint_path, &selected.origin, &selected.actor_id)
                .await?;
        let missing =
            missing_runtime_features(&client.call(json!({"method":"capabilities"})).await?);
        if !missing.is_empty() {
            return Ok(
                json!({"state":"PENDING","approval_id":approval_id,"blocker":{"stage":"LOCAL_RUNTIME","code":"LOCAL_RUNTIME_UPGRADE_REQUIRED","next_actor":"LOCAL_RUNTIME_OWNER","next_action":"UPGRADE_SELECTED_RUNTIME_PRESERVING_ORIGINAL_STATE","missing_features":missing},"remote_changes_submitted":false,"original_operations_retained":true}),
            );
        }
        let digest = sha256_hex(
            serde_json::to_vec(&request)
                .map_err(|_| local("AUTHORIZATION_REQUEST_INVALID"))?
                .as_slice(),
        );
        if admission {return self.approve_admission(participant,approval_id,request,&selected.actor_id,client,digest).await;}
        if let Some(prior) = self.registry.approvals.get(approval_id) {
            if prior.digest != digest || prior.participant != participant {
                return Err(local("APPROVAL_ID_CONFLICT_RESUME_ORIGINAL"));
            }
        } else {
            if self.registry.approvals.len() >= 64 {
                return Err(local("APPROVAL_LIMIT"));
            }
            let scope = Scope {
                workspace_id: Some(request.workspace_id.clone()),
                ..Scope::default()
            };
            let now = trusted_time(&client, &scope).await?;
            let workspace =
                read(&client, "structure.workspace.get", scope.clone(), json!({})).await?;
            if !business_only && workspace["membership"]["role"] != "OWNER" {
                return Err(local("OWNER_APPROVAL_REQUIRED"));
            }
            let mut steps = Vec::new();
            let send = request
                .missing
                .iter()
                .any(|v| matches!(v, Delta::CommunicationSend));
            let receive = request
                .missing
                .iter()
                .any(|v| matches!(v, Delta::CommunicationReceive));
            if send || receive {
                let old = read(
                    &client,
                    "structure.communication.grant.get",
                    scope.clone(),
                    json!({"actor_id":request.actor_id}),
                )
                .await?;
                let grant = &old["grant"];
                if grant.is_object() && grant["membership_id"] != request.membership_id {
                    return Err(local("MEMBERSHIP_CHANGED_NEW_REQUEST_REQUIRED"));
                }
                let expiry = approved_expiry(grant, request.grant_expires_at, now)?;
                let effective = effective(grant, now);
                steps.push(Invoke::new(format!("approve-{approval_id}-communication"),"structure.communication.grant.set",scope.clone(),
                    json!({"actor_id":request.actor_id,"membership_id":request.membership_id,"expected_revision":grant["revision"],
                        "send":send||(effective&&grant["can_send"]==true),"receive":receive||(effective&&grant["can_receive"]==true),"expires_at":expiry})));
            }
            let mut groups: BTreeMap<
                (String, String, Option<String>),
                (
                    std::collections::BTreeSet<String>,
                    std::collections::BTreeSet<String>,
                ),
            > = BTreeMap::new();
            for delta in &request.missing {
                if let Delta::BusinessRole {
                    instance_id,
                    protocol_digest,
                    execution_context_id,
                    role,
                    actions,
                } = delta
                {
                    let group = groups
                        .entry((instance_id.clone(), protocol_digest.clone(), execution_context_id.clone()))
                        .or_default();
                    if !role.is_empty(){group.0.insert(role.clone());}
                    group.1.extend(actions.iter().cloned());
                }
            }
            for (index, ((instance_id, protocol_digest, execution_context_id), (requested_roles, requested_actions))) in
                groups.into_iter().enumerate()
            {
                let s = Scope {
                    workspace_id: Some(request.workspace_id.clone()),
                    instance_id: Some(instance_id.clone()),
                    protocol_digest: Some(protocol_digest.clone()),
                };
                let mut query=json!({"actor_id":request.actor_id,"view":"SUMMARY"});
                if let Some(context)=&execution_context_id {query["execution_context_id"]=json!(context);}
                let old = read(
                    &client,
                    "structure.grant.get",
                    s.clone(),
                    query,
                )
                .await?;
                let grant = &old["grant"];
                if grant.is_object() && grant["membership_id"] != request.membership_id {
                    return Err(local("MEMBERSHIP_CHANGED_NEW_REQUEST_REQUIRED"));
                }
                let expiry = approved_expiry(grant, request.grant_expires_at, now)?;
                let effective = grant["effective"] == true && effective(grant, now);
                let mut roles: std::collections::BTreeSet<String> = if effective {
                    serde_json::from_value(grant["protocol_roles"].clone()).unwrap_or_default()
                } else {
                    Default::default()
                };
                roles.extend(requested_roles);
                let mut allowed: std::collections::BTreeSet<String> = if effective {
                    serde_json::from_value(grant["actions"].clone()).unwrap_or_default()
                } else {
                    Default::default()
                };
                allowed.extend(requested_actions);
                let mut body=json!({"actor_id":request.actor_id,"membership_id":request.membership_id,"expected_grant_revision":grant["grant_revision"],
                    "actions":allowed,"protocol_roles":roles,"capabilities":if effective{grant["capabilities"].as_array().cloned().unwrap_or_default()}else{Vec::new()},"expires_at":expiry});
                if let Some(context)=execution_context_id {body["execution_context_id"]=json!(context);}
                steps.push(Invoke::new(format!("approve-{approval_id}-role-{index}"),"structure.grant.set",s,body));
            }
            if request.body_keys_required {
                steps.push(Invoke::new(format!("approve-{approval_id}-keys"),"participant.access.approve",scope,
                    json!({"request_jws":request.key_request.as_ref().unwrap()["request_jws"],"mode":"KEYS_ONLY","follow_current_key":request.follow_current_key})));
            }
            // The request and exact commands are committed before first remote
            // mutation. Partial application is retained rather than rolled back.
            self.registry.approvals.insert(
                approval_id.into(),
                Approval {
                    participant: participant.into(),
                    digest,
                    steps,
                    results: Vec::new(),
                    continuation: None,
                },
            );
            self.save()?;
        }
        loop {
            let approval = &self.registry.approvals[approval_id];
            let index = approval.results.len();
            if index == approval.steps.len() {
                return Ok(
                    json!({"state":"APPROVED","approval_id":approval_id,"setup_id":request.setup_id,
                "results":approval.results,"next_actor":request.actor_id,"next_action":"RESUME_ORIGINAL_CONNECT_SETUP"}),
                );
            }
            let step = approval.steps[index].clone();
            let mut value = client
                .call(json!({"method":"invoke","request":step,"wait_ms":1000}))
                .await?;
            if value["state"] == "PENDING" {
                value = client
                    .call(json!({"method":"recover","operation_id":step.operation_id}))
                    .await?;
            }
            if value["state"] == "ACCEPTED" {
                self.registry.approvals.get_mut(approval_id).unwrap().results.push(json!({"operation_id":value["operation_id"],"command_id":value["command_id"],"state":value["state"],"effect_certainty":value["effect_certainty"]}));
                self.save()?;
            } else {
                let terminal = matches!(
                    value["state"].as_str(),
                    Some("REJECTED_NO_EFFECT" | "FAILED" | "REJECTED")
                );
                return Ok(
                    json!({"state":if terminal{"REJECTED_NO_EFFECT"}else{"PENDING"},"approval_id":approval_id,"setup_id":request.setup_id,"phase":"AUTHORIZATION_SUBMISSION",
                    "original_operation":crate::agent_tools::operation_view(value),"completed_steps":index,
                    "next_action":if terminal{"CORRECT_REQUEST_NEW_APPROVAL_ID"}else{"RESUME_SAME_APPROVAL_ID"},"partial_success_preserved":true}),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn business_action_request_retains_exact_context_without_inventing_a_role() {
        let mut input=json!({"format":"peerwork.connect-authorization-request.v1","setup_id":"browser-action",
            "origin":"https://example.invalid/","workspace_id":"W".repeat(43),"actor_id":"A".repeat(43),
            "membership_id":"M".repeat(43),"owner_id":"O".repeat(43),"body_keys_required":false,
            "missing":[{"kind":"BUSINESS_ROLE","instance_id":"I".repeat(43),"protocol_digest":"a".repeat(64),
                "execution_context_id":"C".repeat(43),"actions":["review"]}]});
        let request=AuthorizationRequest::from_input(input.clone()).unwrap();
        let restored=AuthorizationRequest::from_input(json!(request.to_code().unwrap())).unwrap();
        let encoded=serde_json::to_value(restored).unwrap();
        assert_eq!(encoded["missing"][0]["execution_context_id"],"C".repeat(43));
        assert_eq!(encoded["missing"][0]["role"],"");
        input["missing"][0]["execution_context_id"]=json!("invalid-context");
        assert!(AuthorizationRequest::from_input(input.clone()).is_err());
        input["missing"][0]["execution_context_id"]=json!("C".repeat(43));
        input["missing"][0]["actions"]=json!([]);
        assert!(AuthorizationRequest::from_input(input).is_err());
    }
    #[test]
    fn public_request_code_roundtrips_and_is_not_an_authorization() {
        let input=json!({"format":"peerwork.connect-authorization-request.v2","setup_id":"join-worker",
            "origin":"https://example.invalid/","workspace_id":"W".repeat(43),"actor_id":"A".repeat(43),
            "membership_id":"","owner_id":"","missing":[{"kind":"MEMBERSHIP"},{"kind":"COMMUNICATION_SEND"}],"body_keys_required":false});
        let request=AuthorizationRequest::from_input(input).unwrap();
        let code=request.to_code().unwrap();
        let restored=AuthorizationRequest::from_input(json!(code)).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(),serde_json::to_value(restored).unwrap());
        let tool=crate::agent_tools::AgentRequest::parse("connect_approve",json!({"participant":"owner","approval_id":"approve-once","request":code}));
        assert!(matches!(tool,Ok(crate::agent_tools::AgentRequest::ConnectApprove{..})));
        assert!(AuthorizationRequest::from_input(json!("PW-AUTH-1.invalid+padding=")).is_err());
        let invalid=format!("PW-AUTH-1.{}",peerwork_core::crypto::base64url(br#"{"format":"x","format":"y"}"#));
        assert!(AuthorizationRequest::from_input(json!(invalid)).is_err());
        assert!(AuthorizationRequest::from_input(json!("x".repeat(43706))).is_err());
        let mut v=serde_json::to_value(&request).unwrap();v["missing"]=json!([{"kind":"COMMUNICATION_SEND"}]);
        assert!(AuthorizationRequest::from_input(v).is_err(),"v2 cannot omit its explicit admission request");
    }
    #[test]
    fn approval_preserves_finite_lease_and_requires_explicit_expired_renewal() {
        let grant = json!({"expires_at":2000});
        assert!(effective(&grant, 1000));
        assert_eq!(approved_expiry(&grant, None, 1000).unwrap(), 2000);
        assert!(!effective(&grant, 2000));
        assert_eq!(
            approved_expiry(&grant, None, 2000).unwrap_err().code,
            "AUTHORIZATION_LEASE_EXPIRED_EXPLICIT_RENEWAL_REQUIRED"
        );
        assert_eq!(approved_expiry(&grant, Some(3000), 2000).unwrap(), 3000);
        assert!(!effective(&Value::Null, 1000));
        assert!(approved_expiry(&Value::Null, None, 1000).unwrap().is_null());
        assert!(effective(&json!({"expires_at":null}), 1000));
    }
    #[test]
    fn future_key_follow_requires_explicit_body_authorization() {
        let mut request:AuthorizationRequest=serde_json::from_value(json!({
            "format":"peerwork.connect-authorization-request.v1","setup_id":"new-worker",
            "origin":"https://example.invalid/","workspace_id":"W".repeat(43),"actor_id":"A".repeat(43),
            "membership_id":"M".repeat(43),"owner_id":"O".repeat(43),"missing":[{"kind":"COMMUNICATION_SEND"}],
            "body_keys_required":false})).unwrap();
        request.validate().unwrap();
        assert!(!request.follow_current_key);
        request.follow_current_key = true;
        assert_eq!(
            request.validate().unwrap_err().code,
            "AUTHORIZATION_REQUEST_INVALID"
        );
    }
}
