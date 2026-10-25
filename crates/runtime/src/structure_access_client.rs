//! Bounded device admission and body-key handoff over the selected service.
//! Key material remains in protected native storage; language bindings receive
//! public requests, operation results and key IDs only.
use super::*;
use crate::{
    kernel_intents::StructureContentKeys,
    secure_recipient_state::{RecipientState, RecipientStateError},
};
use peerwork_core::{
    canonical::{canonical, Path as CanonicalPath},
    crypto::{base64url, sha256, sha256_hex},
    prepared_command::verify_structure_author_intent,
    structure_access::{
        create_access_request, open_owner_access_keys, verify_access_request, AccessKind,
        AccessRequestOptions, AccessWrite, OpenedAccessKeys,
    },
    structure_context::{verify_structure_context, VerifiedStructureContext},
    structure_execution::PROFILE,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureAccessRequest {
    pub workspace_id: String,
    pub label: String,
    #[serde(default = "agent")]
    pub kind: AccessKind,
    #[serde(default)]
    pub write: Option<AccessWrite>,
}
fn agent() -> AccessKind {
    AccessKind::Agent
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessMode {
    Session,
    KeysOnly,
}
fn session() -> AccessMode {
    AccessMode::Session
}
fn is_false(value:&bool)->bool{!*value}
fn yes() -> bool {
    true
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureAccessWrite {
    pub instance_id: String,
    pub protocol_digest: String,
    pub action_id: String,
    #[serde(default)]
    pub protocol_roles: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureAccessApproval {
    pub workspace_id: String,
    pub request_jws: String,
    #[serde(default = "session")]
    pub mode: AccessMode,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default = "yes")]
    pub deliver_content_keys: bool,
    #[serde(default,skip_serializing_if = "is_false")]
    pub follow_current_key: bool,
    #[serde(default,skip_serializing_if = "is_false")]
    pub include_history: bool,
    #[serde(default)]
    pub key_ids: Vec<String>,
    #[serde(default)]
    pub selected_write: Option<StructureAccessWrite>,
    #[serde(default)]
    pub expected_workspace_revision: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructureKeyAcceptance {
    pub workspace_id: String,
    pub owner_id: String,
    pub key_ids: Vec<String>,
    #[serde(default)]
    pub current_key_id: Option<String>,
    #[serde(default)]
    pub expected_current_key_id: Option<String>,
}
pub(super) fn data(result: &KernelAcceptedResult) -> Result<Value, KernelClientError> {
    if result.outcome_state()=="REJECTED"{return Err(KernelClientError::OperationRefused(Box::new(crate::kernel_client::OperationRefusal::from_verified(result)?)));}
    serde_json::from_str(
        result
            .structure_result_json
            .as_deref()
            .ok_or(KernelClientError::InvalidResult)?,
    )
    .map_err(|_| KernelClientError::InvalidResult)
}
fn selected_ids(ids: &[String]) -> bool {
    !ids.is_empty()
        && ids.len() <= 32
        && ids.iter().all(|v| {
            v.len() == 43 && peerwork_core::crypto::decode_base64url(v).is_ok_and(|b| b.len() == 32)
        })
        && ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len()
}
impl KernelClient {
    fn access_content_config(&self) -> TransportConfig {
        let mut config = TransportConfig::new(self.origin());
        config.allow_loopback_http = self.origin().starts_with("http://");
        config
    }

    pub(super) async fn access_context(
        &self,
        cancel: &CancellationToken,
    ) -> Result<(String, Vec<u8>, VerifiedStructureContext), KernelClientError> {
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| KernelClientError::InvalidCommand)?;
        let nonce = base64url(&nonce);
        let started = Instant::now();
        let response = self.transport.structure_context(&nonce, cancel).await?;
        if !(200..300).contains(&response.status) {
            return Err(KernelClientError::ServerRejected(response.status));
        }
        if started.elapsed() > Duration::from_secs(30) {
            return Err(TransportError::Timeout.into());
        }
        let context = verify_structure_context(
            &response.wire,
            &nonce,
            self.discovery.audience_utf16(),
            self.discovery.receipt_public_key(),
        )
        .map_err(|_| JournalError::InvalidReceipt)?;
        Ok((nonce, response.wire, context))
    }
    pub(crate) async fn request_structure_access(
        &self,
        identity: &KernelIdentity,
        recipient_path: &Path,
        selection: StructureAccessRequest,
        cancel: &CancellationToken,
    ) -> Result<Value, KernelClientError> {
        let (nonce, wire, context) = self.access_context(cancel).await?;
        let recipient = match RecipientState::open(recipient_path, identity) {
            Ok(v) => v,
            Err(RecipientStateError::NotFound) => {
                RecipientState::create(recipient_path, identity, context.server_time_ms())?
            }
            Err(e) => return Err(e.into()),
        };
        let request = create_access_request(
            identity.signing_key(),
            recipient.recipient(),
            AccessRequestOptions {
                workspace_id: &selection.workspace_id,
                nonce: &nonce,
                kind: selection.kind,
                label: &selection.label,
                write: selection.write,
                context_wire: &wire,
                audience_utf16: self.discovery.audience_utf16(),
                service_key: self.discovery.receipt_public_key(),
            },
        )?;
        Ok(
            json!({"profile":PROFILE,"workspace_id":request.request().workspace_id,"actor_id":identity.actor_id(),"request_id":request.request().request_id,"recipient_key_id":request.recipient_key_id(),"expires_at":request.deadline_ms(),"request_jws":request.jws(),"state":"AWAITING_OWNER_APPROVAL"}),
        )
    }
    pub(super) fn normalize_structure_access(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        mut selection: StructureAccessApproval,
    ) -> Result<(StructureAccessApproval,String), KernelClientError> {
        if !self.discovery.protocol_features().contains(&"owner-approved-key-floor-v1".encode_utf16().collect::<Vec<_>>()){return Err(KernelClientError::UnsupportedStructureProfile);}
        if selection.follow_current_key{self.require_current_key_delivery()?;}
        if selection.include_history{self.require_retained_key_delivery()?;}
        if selection.request_jws.len() > 12000
            || selection.key_ids.len() > 32
            || selection.expected_workspace_revision == Some(0)
        {
            return Err(KernelClientError::InvalidCommand);
        }
        if selection.mode == AccessMode::KeysOnly {
            if selection.ttl_ms.is_some() || selection.selected_write.is_some() {
                return Err(KernelClientError::InvalidCommand);
            }
        } else {
            selection.ttl_ms = Some(selection.ttl_ms.unwrap_or(86400000));
            if !(1..=31 * 86400000).contains(&selection.ttl_ms.unwrap()) {
                return Err(KernelClientError::InvalidCommand);
            }
        }
        if !selection.deliver_content_keys && (selection.include_history || selection.follow_current_key || !selection.key_ids.is_empty()) {
            return Err(KernelClientError::InvalidCommand);
        }
        selection.key_ids.sort();
        if selection.key_ids.windows(2).any(|v| v[0] == v[1]) {
            return Err(KernelClientError::InvalidCommand);
        }
        // The public selection determines an immutable operation before random HPKE
        // encryption or CAS discovery. Repetition resumes the saved exact packet,
        // even after its original ten-minute human approval window has ended.
        let plan=canonical(&json!({"domain":"peerwork.structure-access-operation.v1","origin":self.origin(),"actor_id":identity.actor_id(),"authority":authority,"selection":selection}),CanonicalPath::COMMAND).map_err(|_|KernelClientError::InvalidCommand)?;
        let command_id = base64url(&sha256(plan.as_bytes()));
        Ok((selection,command_id))
    }
    pub(super) async fn authorize_structure_access_prepared(
        &mut self,identity:&KernelIdentity,authority:&str,selection:StructureAccessApproval,cancel:&CancellationToken,
    )->Result<StructureIntentOutcome,KernelClientError>{
        let (selection,command_id)=self.normalize_structure_access(identity,authority,selection)?;
        if self
            .journal
            .verified_pending(
                &command_id,
                identity.key_id(),
                self.discovery.audience_utf16(),
            )?
            .is_some()
        {
            return self
                .resume_saved_structure_intent(
                    identity,
                    authority,
                    &command_id,
                    Some(&selection.workspace_id),
                    cancel,
                )
                .await;
        }
        let (_, _, context) = self.access_context(cancel).await?;
        let request = verify_access_request(
            &selection.request_jws,
            &selection.workspace_id,
            self.discovery.audience_utf16(),
            self.discovery.receipt_public_key(),
            context.server_time_ms(),
        )?;
        if matches!(request.request().kind,peerwork_core::structure_access::AccessKind::Browser)
            && !self.discovery.protocol_features().contains(&"owner-pinned-browser-access-v1".encode_utf16().collect::<Vec<_>>()) {return Err(KernelClientError::UnsupportedStructureProfile);}
        let current=self.execute_structure_intent(identity,authority,serde_json::to_string(&json!({"action":"structure.workspace.get","workspace_id":selection.workspace_id,"body":{}})).unwrap().as_bytes(),cancel).await?;
        let StructureIntentOutcome::Accepted(current) = current else {
            return Err(KernelClientError::InvalidResult);
        };
        let mut current = data(&current)?;
        if current["membership"]["role"] != "OWNER" || current["owner_id"] != identity.actor_id() {
            return Err(KernelClientError::InvalidCommand);
        }
        let content_key_epoch=if selection.deliver_content_keys {
            current=Box::pin(self.ensure_structure_content_ready(identity,authority,&selection.workspace_id,cancel)).await?;
            current["content_key_head"]["epoch"].as_u64().ok_or(KernelClientError::InvalidResult)?
        }else{
            self.observe_head(identity,&current,&selection.workspace_id)?;
            current["content_key_head"]["epoch"].as_u64().unwrap_or(0)
        };
        let revision = selection
            .expected_workspace_revision
            .or_else(|| current["workspace_revision"].as_u64())
            .ok_or(KernelClientError::InvalidResult)?;
        let expires = if let Some(ttl) = selection.ttl_ms {
            let expires = context
                .server_time_ms()
                .checked_add(ttl)
                .ok_or(KernelClientError::InvalidCommand)?;
            if request.request().certificate.payload["expires_at"]
                .as_u64()
                .is_none_or(|t| expires > t)
            {
                return Err(KernelClientError::InvalidCommand);
            }
            Some(expires)
        } else {
            None
        };
        let grant = if selection.deliver_content_keys {
            let mut keys = StructureContentKeys::open(
                &self.content_key_store_path(),
                self.access_content_config(),
            )?;
            keys.ensure_current(identity.key_id(), &selection.workspace_id)?;
            Some(
                keys.package_access_keys(
                    identity.key_id(),
                    &selection.workspace_id,
                    &request,
                    &String::from_utf16(self.discovery.audience_utf16())
                        .map_err(|_| KernelClientError::InvalidCommand)?,
                    identity.actor_id(),
                    &selection.key_ids,
                )?,
            )
        } else {
            None
        };
        let mut intent = json!({"action":"structure.access.authorize","command_id":command_id,"workspace_id":selection.workspace_id,"expected_workspace_revision":revision,"body":{"request_jws":selection.request_jws,"mode":selection.mode,"expires_at":expires,"content_grant":grant,"content_key_epoch":content_key_epoch,"follow_current_key":selection.follow_current_key,"selected_write":selection.selected_write}});
        if selection.include_history{intent["body"]["retained_key_epoch_ceiling"]=json!(content_key_epoch);}
        match self
            .execute_structure_intent_prepared(identity, authority, intent.to_string().as_bytes(), cancel)
            .await
        {
            Err(KernelClientError::Store(JournalError::IntentConflict)) => {
                self.resume_saved_structure_intent(
                    identity,
                    authority,
                    &command_id,
                    Some(&selection.workspace_id),
                    cancel,
                )
                .await
            }
            result => result,
        }
    }
    /// A selected read can fetch its missing recipient-bound keys without
    /// making the Agent manage a second protocol or replay any history.
    pub(crate) async fn populate_selected_body_keys(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        recipient_path: &Path,
        outcome: &mut StructureIntentOutcome,
        cancel: &CancellationToken,
    ) {
        let StructureIntentOutcome::Accepted(result) = outcome else {
            return;
        };
        let Some(opened) = result.opened_contents.as_ref() else {
            return;
        };
        let ids: Vec<String> = opened
            .iter()
            .filter(|b| b.state == "KEY_UNAVAILABLE")
            .filter_map(|b| b.key_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if ids.is_empty() || !recipient_path.is_file() {
            return;
        }
        let Some(workspace) = result.workspace_id.clone() else {
            return;
        };
        let attempted = tokio::time::timeout(Duration::from_secs(10), async {
            let query =
                json!({"action":"structure.workspace.get","workspace_id":workspace,"body":{}});
            let metadata = self
                .execute_structure_intent(identity, authority, query.to_string().as_bytes(), cancel)
                .await?;
            let StructureIntentOutcome::Accepted(metadata) = metadata else {
                return Err(KernelClientError::InvalidResult);
            };
            let owner = data(&metadata)?["owner_id"]
                .as_str()
                .ok_or(KernelClientError::InvalidResult)?
                .to_owned();
            self.accept_structure_keys_mode(
                identity,
                authority,
                recipient_path,
                StructureKeyAcceptance {
                    workspace_id: workspace,
                    owner_id: owner,
                    key_ids: ids,
                    current_key_id: None,
                    expected_current_key_id: None,
                },
                cancel,
                true,
            )
            .await
        })
        .await;
        match attempted {
            Ok(Ok(_)) => {
                let action = if data(result).is_ok_and(|v| v.get("records").is_some()) {
                    "structure.records.read"
                } else {
                    "structure.record.get"
                };
                let previous = result.opened_contents.take();
                if self
                    .open_selected_structure_bodies(result, action, identity.key_id())
                    .is_err()
                {
                    result.opened_contents = previous;
                    if let Some(opened) = result.opened_contents.as_mut() {
                        for body in opened.iter_mut().filter(|b| b.state == "KEY_UNAVAILABLE") {
                            body.state = "KEY_STATE_INVALID";
                        }
                    }
                }
            }
            error => {
                let state = if matches!(
                    error,
                    Ok(Err(KernelClientError::Access(_)
                        | KernelClientError::InvalidResult
                        | KernelClientError::Store(JournalError::InvalidReceipt)))
                ) {
                    "KEY_GRANT_INVALID"
                } else {
                    "KEY_DELIVERY_UNAVAILABLE"
                };
                if let Some(opened) = result.opened_contents.as_mut() {
                    for body in opened.iter_mut().filter(|b| b.state == "KEY_UNAVAILABLE") {
                        body.state = state;
                    }
                }
            }
        }
    }
    pub(crate) async fn accept_structure_keys(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        recipient_path: &Path,
        selection: StructureKeyAcceptance,
        cancel: &CancellationToken,
    ) -> Result<Value, KernelClientError> {
        self.accept_structure_keys_mode(
            identity,
            authority,
            recipient_path,
            selection,
            cancel,
            false,
        )
        .await
    }
    pub(crate) async fn accept_structure_keys_mode(
        &mut self,
        identity: &KernelIdentity,
        authority: &str,
        recipient_path: &Path,
        selection: StructureKeyAcceptance,
        cancel: &CancellationToken,
        allow_missing: bool,
    ) -> Result<Value, KernelClientError> {
        if !selected_ids(&selection.key_ids)
            || selection
                .current_key_id
                .as_ref()
                .is_some_and(|id| !selection.key_ids.contains(id))
            || selection.current_key_id.is_none() && selection.expected_current_key_id.is_some()
        {
            return Err(KernelClientError::InvalidCommand);
        }
        let recipient = RecipientState::open(recipient_path, identity)?;
        let mut remaining = selection.key_ids.clone();
        let mut imported = std::collections::BTreeMap::new();
        let mut source_count = 0;
        let mut unavailable = std::collections::BTreeSet::new();
        let audience = String::from_utf16(self.discovery.audience_utf16())
            .map_err(|_| KernelClientError::InvalidResult)?;
        // This loop follows only explicit selected-ID deferrals. It is bounded by
        // 32 keys, never workspace history. No key is persisted until all required
        // signatures and commitments have passed.
        for _ in 0..32 {
            let query = json!({"action":"structure.content-keys.read","workspace_id":selection.workspace_id,"body":{"recipient_key_id":recipient.recipient().encryption_key_id(),"key_ids":remaining}});
            let response = self
                .execute_structure_intent(identity, authority, query.to_string().as_bytes(), cancel)
                .await?;
            let StructureIntentOutcome::Accepted(response) = response else {
                return Err(KernelClientError::InvalidResult);
            };
            let response = data(&response)?;
            let rows = response["keys"]
                .as_array()
                .ok_or(KernelClientError::InvalidResult)?;
            let sources = response["sources"]
                .as_object()
                .ok_or(KernelClientError::InvalidResult)?;
            if rows.len() > 32 || sources.len() > 32 {
                return Err(crate::kernel_intents::ContentKeyError::Missing.into());
            }
            let missing: Vec<String> = serde_json::from_value(response["missing_key_ids"].clone())
                .map_err(|_| KernelClientError::InvalidResult)?;
            if !missing.is_empty() {
                if !allow_missing {
                    return Err(crate::kernel_intents::ContentKeyError::Missing.into());
                }
                if !selected_ids(&missing) || missing.iter().any(|id| !remaining.contains(id)) {
                    return Err(KernelClientError::InvalidResult);
                }
                unavailable.extend(missing.iter().cloned());
            }
            let mut used = std::collections::BTreeSet::new();
            let mut opened_sources = std::collections::BTreeSet::new();
            for row in rows {
                let id = row["key_id"]
                    .as_str()
                    .ok_or(KernelClientError::InvalidResult)?;
                let source_key = row["source_key"]
                    .as_str()
                    .ok_or(KernelClientError::InvalidResult)?;
                if !remaining.iter().any(|s| s == id)
                    || row["recipient_key_id"] != recipient.recipient().encryption_key_id()
                    || !used.insert(id.to_owned())
                {
                    return Err(KernelClientError::InvalidResult);
                }
                let source = sources
                    .get(source_key)
                    .ok_or(KernelClientError::InvalidResult)?;
                let jws = source["author_intent"]
                    .as_str()
                    .ok_or(KernelClientError::InvalidResult)?;
                if source["intent_digest"] != sha256_hex(jws.as_bytes()) {
                    return Err(KernelClientError::InvalidResult);
                }
                let author = verify_structure_author_intent(jws, self.discovery.audience_utf16())
                    .map_err(|_| JournalError::InvalidReceipt)?;
                if source_key != format!("{}:{}", author.actor_id(), author.command_id())
                    || source["actor_id"] != author.actor_id()
                    || source["command_id"] != author.command_id()
                {
                    return Err(KernelClientError::InvalidResult);
                }
                if opened_sources.insert(source_key) {
                    let bundle = open_owner_access_keys(
                        &author,
                        &selection.owner_id,
                        identity.actor_id(),
                        recipient.recipient(),
                        &selection.workspace_id,
                        &audience,
                        self.discovery.receipt_public_key(),
                    )?;
                    source_count += 1;
                    for key in bundle.keys {
                        if selection.key_ids.iter().any(|id| id == key.key_id()) {
                            imported.insert(key.key_id().to_owned(), key);
                        }
                    }
                }
                if !imported.contains_key(id) {
                    return Err(KernelClientError::InvalidResult);
                }
            }
            if opened_sources.len() != sources.len() {
                return Err(KernelClientError::InvalidResult);
            }
            let deferred: Vec<String> =
                serde_json::from_value(response["deferred_key_ids"].clone())
                    .map_err(|_| KernelClientError::InvalidResult)?;
            if !deferred.is_empty()
                && (!selected_ids(&deferred)
                    || deferred.len() >= remaining.len()
                    || deferred.iter().any(|id| {
                        !remaining.contains(id) || used.contains(id) || missing.contains(id)
                    }))
            {
                return Err(KernelClientError::InvalidResult);
            }
            if used.len() + deferred.len() + missing.len() != remaining.len() {
                return Err(KernelClientError::InvalidResult);
            }
            remaining = deferred;
            if remaining.is_empty() {
                break;
            }
        }
        if !remaining.is_empty() || imported.len() + unavailable.len() != selection.key_ids.len() {
            return Err(KernelClientError::InvalidResult);
        }
        if imported.is_empty() {
            return Ok(
                json!({"profile":PROFILE,"workspace_id":selection.workspace_id,"state":"NO_KEYS_AVAILABLE","key_ids":[],"unavailable_key_ids":unavailable,"current_key_id":null,"source_count":source_count}),
            );
        }
        let head = selection
            .current_key_id
            .clone()
            .unwrap_or_else(|| imported.keys().next().unwrap().clone());
        let opened = OpenedAccessKeys {
            keys: imported.into_values().collect(),
            current_key_id: head,
        };
        let mut keys = StructureContentKeys::open(
            &self.content_key_store_path(),
            self.access_content_config(),
        )?;
        let imported = keys.retain_access_keys(
            identity.key_id(),
            &selection.workspace_id,
            &opened,
            selection.current_key_id.is_some(),
            selection.expected_current_key_id.as_deref(),
        )?;
        Ok(
            json!({"profile":PROFILE,"workspace_id":selection.workspace_id,"state":"IMPORTED","key_ids":imported.iter().map(|k|k.key_id.as_str()).collect::<Vec<_>>(),"current_key_id":selection.current_key_id,"source_count":source_count,"unavailable_key_ids":unavailable}),
        )
    }
}
