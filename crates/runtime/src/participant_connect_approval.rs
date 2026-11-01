//! Owner-side continuation of one explicit permission request. Prepared child
//! intents are frozen before submission; retries never rebuild an unknown write.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Delta {
    CommunicationSend,
    CommunicationReceive,
    BusinessRole {
        instance_id: String,
        protocol_digest: String,
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
}
impl AuthorizationRequest {
    fn validate(&self) -> Result<()> {
        if self.format != "peerwork.connect-authorization-request.v1"
            || !identifier(&self.setup_id)
            || ![
                &self.workspace_id,
                &self.actor_id,
                &self.membership_id,
                &self.owner_id,
            ]
            .iter()
            .all(|v| token(v))
            || self.missing.len() > 10
            || (self.follow_current_key && !self.body_keys_required)
        {
            return Err(local("AUTHORIZATION_REQUEST_INVALID"));
        }
        for delta in &self.missing {
            if let Delta::BusinessRole {
                instance_id,
                protocol_digest,
                role,
                actions,
            } = delta
            {
                if !token(instance_id)
                    || !crate::participant_migration::digest(protocol_digest)
                    || role.is_empty()
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
        if selected.actor_id != request.owner_id || selected.origin != request.origin {
            return Err(local("APPROVER_IDENTITY_OR_ORIGIN_MISMATCH"));
        }
        let client =
            RuntimeClient::connect(selected.endpoint_path, &selected.origin, &selected.actor_id)
                .await?;
        let digest = sha256_hex(
            serde_json::to_vec(&request)
                .map_err(|_| local("AUTHORIZATION_REQUEST_INVALID"))?
                .as_slice(),
        );
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
            if workspace["membership"]["role"] != "OWNER" {
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
                (String, String),
                (
                    std::collections::BTreeSet<String>,
                    std::collections::BTreeSet<String>,
                ),
            > = BTreeMap::new();
            for delta in &request.missing {
                if let Delta::BusinessRole {
                    instance_id,
                    protocol_digest,
                    role,
                    actions,
                } = delta
                {
                    let group = groups
                        .entry((instance_id.clone(), protocol_digest.clone()))
                        .or_default();
                    group.0.insert(role.clone());
                    group.1.extend(actions.iter().cloned());
                }
            }
            for (index, ((instance_id, protocol_digest), (requested_roles, requested_actions))) in
                groups.into_iter().enumerate()
            {
                let s = Scope {
                    workspace_id: Some(request.workspace_id.clone()),
                    instance_id: Some(instance_id.clone()),
                    protocol_digest: Some(protocol_digest.clone()),
                };
                let old = read(
                    &client,
                    "structure.grant.get",
                    s.clone(),
                    json!({"actor_id":request.actor_id}),
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
                steps.push(Invoke::new(format!("approve-{approval_id}-role-{index}"),"structure.grant.set",s,
                        json!({"actor_id":request.actor_id,"membership_id":request.membership_id,"expected_grant_revision":grant["grant_revision"],
                            "actions":allowed,"protocol_roles":roles,"capabilities":if effective{grant["capabilities"].as_array().cloned().unwrap_or_default()}else{Vec::new()},"expires_at":expiry})));
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
